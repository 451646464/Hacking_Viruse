@echo off
echo ========================================
echo   Malware Analysis System Launcher
echo ========================================
echo.

REM Activate virtual environment
echo [1/3] Activating virtual environment...
call .venv\Scripts\activate.bat
echo.

REM Add API key column if not exists
echo [2/3] Checking database schema...
python add_api_key_column.py
echo.

REM Run Flask application
echo [3/3] Starting Flask application...
echo.
echo ========================================
echo   Application is running!
echo   Open browser: http://localhost:5000
echo   Press Ctrl+C to stop
echo ========================================
echo.

python -m flask run --host=0.0.0.0 --port=5000
