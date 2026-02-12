#!/bin/bash

# Demo script for testing latent sector error fault injection
# This script demonstrates how to use the latent_sector_error fault with different error rates

echo "=== Latent Sector Error Demo ==="
echo "This demo shows percentage-based read failures that simulate storage sector errors"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This demo must be run as root (use sudo)"
    echo "Usage: sudo $0"
    exit 1
fi

# Check if khaos binary exists
if [ ! -f "../../khaos" ]; then
    echo "ERROR: khaos binary not found. Please run 'make' in the project root first."
    exit 1
fi

# Check if test binary exists
if [ ! -f "../bin/test_programs/test_latent_sector_error" ]; then
    echo "ERROR: test_latent_sector_error binary not found. Please build it first."
    echo "Run: make tests"
    exit 1
fi

echo "Starting test program in background..."
../bin/test_programs/test_latent_sector_error 300 &  # Run for 5 minutes
TEST_PID=$!
echo "Test program started with PID: $TEST_PID"

sleep 2  # Give the test program time to start

echo
echo "=== Phase 1: Testing with 25% error rate ==="
echo "Injecting latent_sector_error with 25% failure rate into PID $TEST_PID"
../../khaos latent_sector_error $TEST_PID 25

echo "Letting test run for 10 seconds..."
sleep 10

echo "Recovering from fault..."
../../khaos --recover latent_sector_error $TEST_PID

sleep 2

echo
echo "=== Phase 2: Testing with 75% error rate ==="
echo "Injecting latent_sector_error with 75% failure rate into PID $TEST_PID"
../../khaos latent_sector_error $TEST_PID 75

echo "Letting test run for 10 seconds..."
sleep 10

echo "Recovering from fault..."
../../khaos --recover latent_sector_error $TEST_PID

sleep 2

echo
echo "=== Phase 3: Testing with 50% error rate (default) ==="
echo "Injecting latent_sector_error with default 50% failure rate into PID $TEST_PID"
../../khaos latent_sector_error $TEST_PID

echo "Letting test run for 10 seconds..."
sleep 10

echo "Recovering from fault..."
../../khaos --recover latent_sector_error $TEST_PID

echo
echo "=== Demo Complete ==="
echo "Stopping test program..."
kill $TEST_PID
wait $TEST_PID 2>/dev/null

echo "Check the output above to see the different error rates in action!"
echo "You should observe:"
echo "  - Phase 1: ~25% of reads failing with EIO errors"
echo "  - Phase 2: ~75% of reads failing with EIO errors"
echo "  - Phase 3: ~50% of reads failing with EIO errors"
echo "  - Between phases: 0% failures (normal operation)"