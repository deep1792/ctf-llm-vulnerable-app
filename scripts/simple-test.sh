#!/bin/bash

echo "Final Application Test"
echo "====================="

# Use dynamic port
TEST_PORT=$(( 5000 + RANDOM % 1000 ))
echo "Testing on port: $TEST_PORT"

# Clean up any existing processes
pkill -f "python app.py" || true
sleep 2

# Start application
echo "Starting application..."
cd src
PORT=$TEST_PORT python app.py &
APP_PID=$!

# Wait for startup
sleep 5

# Check if running
if ! ps -p $APP_PID > /dev/null; then
    echo "Application failed to start"
    exit 1
fi

echo "✅ Application started with PID: $APP_PID"

# Test function
test_endpoint() {
    local name=$1
    local path=$2
    local expected=$3
    
    echo "Testing $name..."
    if curl -s --max-time 10 "http://localhost:$TEST_PORT$path" | grep -q "$expected"; then
        echo "$name: PASS"
        return 0
    else
        echo "$name: FAIL"
        return 1
    fi
}

# Run tests
test_endpoint "Homepage" "/" "CTF"
HOME_TEST=$?

test_endpoint "Challenges Page" "/challenges" "Challenges"  
CHALLENGES_TEST=$?

test_endpoint "Health Endpoint" "/health" "healthy"
HEALTH_TEST=$?

test_endpoint "LLM01 Challenge" "/challenge/llm01" "Prompt Injection"
LLM01_TEST=$?

# Stop application
echo "Stopping application..."
pkill -f "python app.py" || true
sleep 2

# Check results
if [ $HOME_TEST -eq 0 ] && [ $CHALLENGES_TEST -eq 0 ] && [ $HEALTH_TEST -eq 0 ] && [ $LLM01_TEST -eq 0 ]; then
    echo "ALL TESTS PASSED"
    exit 0
else
    echo "SOME TESTS FAILED"
    exit 1
fi
