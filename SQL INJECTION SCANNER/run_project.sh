#!/bin/bash
echo "==================================================="
echo "  SQL Injection Detector - Full Project Launcher"
echo "==================================================="

echo "[1/3] Initializing Database..."
python database/init_db.py
if [ $? -ne 0 ]; then
    echo "Error initializing database!"
    exit 1
fi
echo "Database initialized successfully."

echo "[2/3] Starting Backend Server..."
# Check if python or python3 is available
if command -v python3 &>/dev/null; then
    PYTHON_CMD=python3
else
    PYTHON_CMD=python
fi

$PYTHON_CMD backend/main.py &
SERVER_PID=$!
echo "Backend server started (PID: $SERVER_PID)."

echo "[3/3] Opening Frontend..."
sleep 3

# Open browser based on OS
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    start frontend/login.html
elif [[ "$OSTYPE" == "darwin"* ]]; then
    open frontend/login.html
elif command -v xdg-open &>/dev/null; then
    xdg-open frontend/login.html
else
    echo "Could not detect web browser. Please open frontend/login.html manually."
fi

echo ""
echo "==================================================="
echo "  Project is running!"
echo "  Backend: http://localhost:8000"
echo "  Frontend: Opened in your default browser"
echo "  Press CTRL+C to stop the backend server"
echo "==================================================="

# Wait for user to quit
wait $SERVER_PID
