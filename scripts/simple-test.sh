#!/bin/bash

echo "Simple Application Test"
echo "======================"

# Use a random port to avoid conflicts
TEST_PORT=$(( 5000 + RANDOM % 1000 ))
echo "Using port: $TEST_PORT"

# Start application
echo "Starting application..."
cd src
PORT=$TEST_PORT python app.py &
APP_PID=$!

# Give it time to start
sleep 3

# Check if process is running
if ! ps -p $APP_PID > /dev/null; then
    echo "ERROR: Application failed to start"
    exit 1
fi

echo "Application started with PID: $APP_PID"

# Test endpoints with timeout
test_endpoint() {
    local url=$1
    local name=$2
    if curl -s --max-time 5 "$url" > /dev/null; then
        echo "✅ $name is accessible"
        return 0
    else
        echo "❌ $name failed"
        return 1
    fi
}

# Test endpoints
test_endpoint "http://localhost:$TEST_PORT" "Homepage"
test_endpoint "http://localhost:$TEST_PORT/challenges" "Challenges page"
test_endpoint "http://localhost:$TEST_PORT/health" "Health endpoint"

# Stop application
echo "Stopping application..."
pkill -P $APP_PID 2>/dev/null || true
kill $APP_PID 2>/dev/null || true
sleep 1

echo "Test completed"
