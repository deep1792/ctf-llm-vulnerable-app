#!/bin/bash

echo "Testing CTF Application Startup"

# Start the application in background
cd src
python app.py &
APP_PID=$!

# Wait for application to start
sleep 5

# Check if application is running
if ps -p $APP_PID > /dev/null; then
    echo "Application started successfully with PID: $APP_PID"
    
    # Test homepage
    echo "Testing homepage..."
    if curl -s --retry 3 --retry-delay 2 http://localhost:5000/ | grep -q "CTF"; then
        echo "Homepage loaded successfully"
    else
        echo "Homepage failed to load"
    fi
    
    # Test challenges page
    echo "Testing challenges page..."
    if curl -s --retry 3 --retry-delay 2 http://localhost:5000/challenges | grep -q "Challenges"; then
        echo "Challenges page loaded successfully"
    else
        echo "Challenges page failed to load"
    fi
    
    # Stop the application
    kill $APP_PID
    wait $APP_PID 2>/dev/null
    echo "Application stopped"
else
    echo "Application failed to start"
    exit 1
fi
