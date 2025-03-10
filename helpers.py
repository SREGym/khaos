'''Helper functions to make finding PIDs easier'''

import subprocess

def get_pids_by_name(search_term):
    """
    Get a list of PIDs for processes whose command exactly matches the given search term.

    :param search_term: The exact name of the process (case-sensitive).
    :return: A list of PIDs (integers) matching exactly the search term.
    """
    try:
        result = subprocess.run(
            ["ps", "-e", "-o", "pid,comm"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if result.returncode != 0:
            raise RuntimeError(f"Error running ps command: {result.stderr.strip()}")

        # Filter output for exact match of process name
        matching_pids = []
        for line in result.stdout.splitlines():
            parts = line.split(maxsplit=1)
            if len(parts) == 2:  # Ensure we have both PID and command
                pid, command = parts
                if command == search_term:  # Exact match
                    if pid.isdigit():
                        matching_pids.append(int(pid))

        return matching_pids

    except Exception as e:
        print(f"Error: {e}")
        return []

def get_pids_by_name_contain(search_term):
    """
    Get a list of PIDs for processes whose command contains the given search term.

    :param search_term: A substring of the process name (case-sensitive).
    :return: A list of PIDs (integers) where the command contains search_term.
    """
    try:
        result = subprocess.run(
            ["ps", "-e", "-o", "pid,comm"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if result.returncode != 0:
            raise RuntimeError(f"Error running ps command: {result.stderr.strip()}")

        # Filter output for processes that contain search_term
        matching_pids = []
        for line in result.stdout.splitlines():
            if search_term in line:
                parts = line.split(maxsplit=1)
                if parts and parts[0].isdigit():  # Ensure we have at least a PID
                    matching_pids.append(int(parts[0]))

        return matching_pids

    except Exception as e:
        print(f"Error: {e}")
        return []

if __name__ == "__main__":
    search_term = "bash"  # Example usage
    pids = get_pids_by_name(search_term)
    print(f"Processes named '{search_term}': {pids}")

    search_term_contain = "python"
    pids_contain = get_pids_by_name_contain(search_term_contain)
    print(f"Processes containing '{search_term_contain}': {pids_contain}")
