@echo off
echo ========================================
echo SOC DASHBOARD ENTERPRISE EDITION
echo Phase 6 - Production Ready
echo ========================================
echo.

echo [1/2] Starting Backend Service...
start cmd /k "run_backend.bat"

timeout /t 3 /nobreak >nul

echo [2/2] Starting Dashboard UI...
start cmd /k "run_dashboard.bat"

echo.
echo ✅ Both services started successfully!
echo 📊 Backend: main.py
echo 🖥️  Dashboard: http://localhost:8050
echo.
echo Press any key to close this window...
pause >nul