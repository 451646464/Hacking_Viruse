Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Malware Analysis System Launcher" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Activate virtual environment
Write-Host "[1/3] Activating virtual environment..." -ForegroundColor Yellow
& .venv\Scripts\Activate.ps1
Write-Host ""

# Add API key column if not exists
Write-Host "[2/3] Checking database schema..." -ForegroundColor Yellow
python add_api_key_column.py
Write-Host ""

# Run Flask application
Write-Host "[3/3] Starting Flask application..." -ForegroundColor Yellow
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Application is running!" -ForegroundColor Green
Write-Host "  Open browser: http://localhost:5000" -ForegroundColor Green
Write-Host "  Press Ctrl+C to stop" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

python -m flask run --host=0.0.0.0 --port=5000
