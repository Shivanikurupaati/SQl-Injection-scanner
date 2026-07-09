@echo off
echo ===================================================
echo   SQL Injection Detector - Full Project Launcher
echo ===================================================

echo [1/3] Initializing Database...
python database/init_db.py
if %errorlevel% neq 0 (
    echo Error initializing database!
    pause
    exit /b %errorlevel%
)
echo Database initialized successfully.

echo [2/3] Starting Backend Server...
echo Starting server in a new window...
start "SQL Injection Detector Backend" cmd /k "python backend/main.py"

echo [3/3] Opening Frontend...
echo Waiting for server to start...
timeout /t 3 >nul
echo Opening login page...
start frontend/login.html

echo.
echo ===================================================
echo   Project is running!
echo   Backend: http://localhost:8000
echo   Frontend: Opened in your default browser
echo ===================================================
echo.
echo You can close this window now, or keep it open.
echo The backend server is running in a separate window.
pause
