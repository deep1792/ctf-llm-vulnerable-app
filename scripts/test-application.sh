#!/bin/bash

echo "Testing CTF Application Startup and Functionality"

# Use a unique port to avoid conflicts
TEST_PORT=5123

# Clean up any existing processes on the test port
echo "Cleaning up any existing processes on port $TEST_PORT"
pkill -f "python app.py" || true
sleep 2

# Start the application in background on specific port
echo "Starting application on port $TEST_PORT"
cd src
PORT=$TEST_PORT python app.py &
APP_PID=$!

# Wait for application to start
echo "Waiting for application to start..."
sleep 5

# Check if application is running
if ps -p $APP_PID > /dev/null; then
    echo "Application started successfully with PID: $APP_PID on port $TEST_PORT"
    
    # Test homepage
    echo "Testing homepage..."
    if curl -s --retry 3 --retry-delay 2 http://localhost:$TEST_PORT/ | grep -q "CTF"; then
        echo "Homepage loaded successfully"
        HOME_STATUS=0
    else
        echo "Homepage failed to load"
        HOME_STATUS=1
    fi
    
    # Test challenges page
    echo "Testing challenges page..."
    if curl -s --retry 3 --retry-delay 2 http://localhost:$TEST_PORT/challenges | grep -q "Challenges"; then
        echo "Challenges page loaded successfully"
        CHALLENGE_STATUS=0
    else
        echo "Challenges page failed to load"
        CHALLENGE_STATUS=1
    fi
    
    # Test health endpoint
    echo "Testing health endpoint..."
    if curl -s http://localhost:$TEST_PORT/health | grep -q "healthy"; then
        echo "Health endpoint working"
        HEALTH_STATUS=0
    else
        echo "Health endpoint failed"
        HEALTH_STATUS=1
    fi
    
    # Test specific challenge endpoints
    echo "Testing challenge endpoints..."
    if curl -s http://localhost:$TEST_PORT/challenge/llm01 | grep -q "Prompt Injection"; then
        echo "LLM01 challenge page accessible"
        LLM01_STATUS=0
    else
        echo "LLM01 challenge page failed"
        LLM01_STATUS=1
    fi
    
    # Stop the application
    echo "Stopping application..."
    kill $APP_PID 2>/dev/null || true
    sleep 2
    
    # Force kill if still running
    if ps -p $APP_PID > /dev/null; then
        echo "Application still running, forcing kill..."
        kill -9 $APP_PID 2>/dev/null || true
    fi
    
    wait $APP_PID 2>/dev/null || true
    echo "Application stopped"
    
    # Determine overall test status
    if [ $HOME_STATUS -eq 0 ] && [ $CHALLENGE_STATUS -eq 0 ] && [ $HEALTH_STATUS -eq 0 ] && [ $LLM01_STATUS -eq 0 ]; then
        echo "All application tests passed"
        exit 0
    else
        echo "Some application tests failed"
        exit 1
    fi
    
else
    echo " Application failed to start"
    exit 1
fi
