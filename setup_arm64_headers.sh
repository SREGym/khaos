#!/bin/bash

# Script to set up kernel headers for ARM64 BPF compilation
#
# This script attempts to:
# 1. Install necessary packages.
# 2. Clean up potentially problematic existing /usr/include/asm symlinks/directories.
# 3. Create the correct symlink for /usr/include/asm to point to ARM64 headers.

# --- Configuration ---
KERNEL_VERSION=$(uname -r)
KERNEL_HEADERS_ROOT="/usr/src/linux-headers-${KERNEL_VERSION}"
ARM64_MULTIARCH_ASM_DIR="/usr/include/aarch64-linux-gnu/asm"
ARM64_KERNEL_UAPI_ASM_DIR="${KERNEL_HEADERS_ROOT}/arch/arm64/include/uapi/asm"
ARM64_KERNEL_ASM_DIR="${KERNEL_HEADERS_ROOT}/arch/arm64/include/asm"
TARGET_ASM_LINK="/usr/include/asm"

# --- Helper Functions ---
echoinfo() {
    echo "[INFO] $1"
}

echowarn() {
    echo "[WARN] $1"
}

echoerror() {
    echo "[ERROR] $1" >&2
}

# --- Main Script ---

echoinfo "Starting ARM64 header setup for BPF compilation..."

# 1. Ensure Necessary Packages are Installed
echoinfo "Ensuring necessary packages are installed (linux-headers, libc6-dev, build-essential)..."
if ! sudo apt-get update; then
    echoerror "Failed to update package lists. Please check your internet connection and repositories."
    exit 1
fi
if ! sudo apt-get install -y "linux-headers-${KERNEL_VERSION}" libc6-dev build-essential; then
    echoerror "Failed to install required packages. Please check apt output for errors."
    exit 1
fi
echoinfo "Required packages should now be installed."

# 2. Clean Up Previous Symlink Attempts
echoinfo "Cleaning up previous symlink attempts for ${TARGET_ASM_LINK}..."

# Remove potentially problematic nested link /usr/include/asm/asm
if [ -e "${TARGET_ASM_LINK}/asm" ]; then
    echoinfo "Removing problematic nested link/file: ${TARGET_ASM_LINK}/asm"
    if ! sudo rm -rf "${TARGET_ASM_LINK}/asm"; then
        echoerror "Failed to remove ${TARGET_ASM_LINK}/asm. Please check permissions or remove manually."
        # Continue if it fails, as the main link is more critical
    fi
fi

# Handle the main /usr/include/asm
if [ -L "${TARGET_ASM_LINK}" ]; then # If it's a symlink
    CURRENT_LINK_TARGET=$(readlink -f "${TARGET_ASM_LINK}")
    echoinfo "${TARGET_ASM_LINK} is currently a symlink to: ${CURRENT_LINK_TARGET}"
    echoinfo "Removing this symlink..."
    if ! sudo unlink "${TARGET_ASM_LINK}"; then
        echoerror "Failed to unlink ${TARGET_ASM_LINK}. Please check permissions or remove manually."
        exit 1
    fi
elif [ -d "${TARGET_ASM_LINK}" ]; then # If it's a directory
    echoinfo "${TARGET_ASM_LINK} is currently a directory."
    # Avoid removing system-critical directories if they are not what we expect
    if [[ "${TARGET_ASM_LINK}" != "${ARM64_MULTIARCH_ASM_DIR}"* ]]; then # Check if it's not the standard multiarch path
        BACKUP_DIR="/usr/include/asm_backup_$(date +%F_%T)"
        echowarn "${TARGET_ASM_LINK} is a directory and not the expected multiarch path. Backing it up to ${BACKUP_DIR}."
        if ! sudo mv "${TARGET_ASM_LINK}" "${BACKUP_DIR}"; then
            echoerror "Failed to backup ${TARGET_ASM_LINK}. Please check permissions or handle manually."
            exit 1
        fi
    else
        echoinfo "${TARGET_ASM_LINK} appears to be the standard multiarch directory. Leaving it as is for now, will attempt to link if necessary."
        # If it's the multiarch dir, we don't want to remove it, but we might re-link /usr/include/asm if it's not already pointing there.
        # This case is less likely if /usr/include/asm is a directory AND the multiarch one.
    fi
elif [ -f "${TARGET_ASM_LINK}" ]; then # If it's a file
    echoinfo "${TARGET_ASM_LINK} is currently a regular file."
    echoinfo "Removing this file..."
    if ! sudo rm "${TARGET_ASM_LINK}"; then
        echoerror "Failed to remove file ${TARGET_ASM_LINK}. Please check permissions or remove manually."
        exit 1
    fi
else
    echoinfo "${TARGET_ASM_LINK} does not exist or is not a type we explicitly handle for cleanup. Proceeding to link creation."
fi

# 3. Create the Correct Symlink for /usr/include/asm
echoinfo "Attempting to create the correct symlink for ${TARGET_ASM_LINK}..."

SYMLINK_TARGET=""

if [ -d "${ARM64_MULTIARCH_ASM_DIR}" ] && [ -f "${ARM64_MULTIARCH_ASM_DIR}/bitsperlong.h" ]; then
    echoinfo "Found bitsperlong.h in multiarch directory: ${ARM64_MULTIARCH_ASM_DIR}"
    SYMLINK_TARGET="${ARM64_MULTIARCH_ASM_DIR}"
elif [ -d "${ARM64_KERNEL_UAPI_ASM_DIR}" ] && [ -f "${ARM64_KERNEL_UAPI_ASM_DIR}/bitsperlong.h" ]; then
    echoinfo "Found bitsperlong.h in kernel uapi headers: ${ARM64_KERNEL_UAPI_ASM_DIR}"
    SYMLINK_TARGET="${ARM64_KERNEL_UAPI_ASM_DIR}"
elif [ -d "${ARM64_KERNEL_ASM_DIR}" ] && [ -f "${ARM64_KERNEL_ASM_DIR}/bitsperlong.h" ]; then
    echoinfo "Found bitsperlong.h in kernel asm headers: ${ARM64_KERNEL_ASM_DIR}"
    SYMLINK_TARGET="${ARM64_KERNEL_ASM_DIR}"
else
    echoerror "Could not find a suitable source for arm64 bitsperlong.h in common locations:"
    echoerror "  - ${ARM64_MULTIARCH_ASM_DIR}"
    echoerror "  - ${ARM64_KERNEL_UAPI_ASM_DIR}"
    echoerror "  - ${ARM64_KERNEL_ASM_DIR}"
    echoerror "Please ensure linux-headers-${KERNEL_VERSION} are correctly installed and contain these files for arm64."
    echoerror "You might also need to install architecture-specific development packages like 'libc6-dev-arm64-cross' if cross-compiling from x86."
    exit 1
fi

if [ -n "${SYMLINK_TARGET}" ]; then
    echoinfo "Creating symlink: ${TARGET_ASM_LINK} -> ${SYMLINK_TARGET}"
    if ! sudo ln -s "${SYMLINK_TARGET}" "${TARGET_ASM_LINK}"; then
        echoerror "Failed to create symlink ${TARGET_ASM_LINK} -> ${SYMLINK_TARGET}. Please check for errors."
        exit 1
    fi
else
    # This case should ideally be caught by the checks above
    echoerror "No suitable symlink target was determined. This should not happen."
    exit 1
fi

# 4. Verify the Symlink
echoinfo "Verifying the symlink..."
if [ -L "${TARGET_ASM_LINK}" ] && [ -e "${TARGET_ASM_LINK}/bitsperlong.h" ]; then
    echoinfo "Symlink successfully created and ${TARGET_ASM_LINK}/bitsperlong.h is accessible."
    echoinfo "${TARGET_ASM_LINK} now points to: $(readlink -f "${TARGET_ASM_LINK}")"
else
    echoerror "Symlink verification failed. ${TARGET_ASM_LINK} might not be pointing correctly or bitsperlong.h is not accessible through it."
    ls -ld "${TARGET_ASM_LINK}"
    ls -l "${TARGET_ASM_LINK}/" # List contents if it's a directory link
    exit 1
fi

echoinfo "ARM64 header setup script completed successfully."

exit 0
