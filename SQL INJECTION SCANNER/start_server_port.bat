@echo off
if "%1"=="" (
    set PORT=8001
) else (
    set PORT=%1
)
echo Starting SQL Injection Detector API Server on port %PORT%...
echo.
echo Server will be available at http://localhost:%PORT%
echo Press CTRL+C to stop the server
echo.
set PORT=%PORT%
python backend/main.py


