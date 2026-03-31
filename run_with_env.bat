@echo off
REM run_with_env.bat - Run with environment variables for Windows CMD

echo ========================================
echo Security Monitor - Windows Environment
echo ========================================

REM Set environment variables
set SMTP_PASSWORD=your-smtp-password
set DASH_AUTH_PASSWORD=your-dashboard-password
set SMS__APP__NAME=Security Monitor Enterprise
set SMS__DASHBOARD__PORT=8050

echo.
echo Running Security Monitor with environment variables...
echo.

REM Run the main application
python main.py

REM Clean up (optional)
set SMTP_PASSWORD=
set DASH_AUTH_PASSWORD=
set SMS__APP__NAME=
set SMS__DASHBOARD__PORT=