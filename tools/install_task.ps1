# tools/install_task.ps1
<#
.SYNOPSIS
    Script to install Suspicious Tracker components as Windows Scheduled Tasks
.DESCRIPTION
    Creates three scheduled tasks that run at system startup:
    - SuspiciousTracker_Backend: Runs main.py
    - SuspiciousTracker_Dashboard: Runs dashboard/app.py
    - SuspiciousTracker_Dispatcher: Runs integrations/dispatcher.py
.NOTES
    Must be run as Administrator
#>

# Check for Administrator privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-NOT $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Please close this window and open PowerShell as Administrator." -ForegroundColor Yellow
    exit 1
}

# Get paths
$ProjectDir = (Get-Location).Path
$PythonPath = (Get-Command python).Source

if (-not $PythonPath) {
    Write-Host "ERROR: Python not found in PATH!" -ForegroundColor Red
    exit 1
}

Write-Host "============================================================"
Write-Host "Suspicious Tracker - Scheduled Task Installer" -ForegroundColor Cyan
Write-Host "============================================================"
Write-Host "Project Path: $ProjectDir"
Write-Host "Python Path:  $PythonPath"
Write-Host ""

# Function to create a scheduled task
function Create-ScheduledTask {
    param(
        [string]$TaskName,
        [string]$ScriptPath,
        [string]$Description
    )

    Write-Host "Creating task: $TaskName" -ForegroundColor Yellow
    Write-Host "  Script: $ScriptPath"
    Write-Host "  Description: $Description"

    # Delete existing task if any (ignore errors)
    schtasks /Delete /TN $TaskName /F 2>$null

    # بناء الأمر بشكل صحيح مع علامات اقتباس مزدوجة للمسارات التي تحتوي على مسافات
    $FullScriptPath = Join-Path -Path $ProjectDir -ChildPath $ScriptPath
    $CommandLine = "`"$PythonPath`" `"$FullScriptPath`""
    
    # استخدام schtasks مع علامات اقتباس للأمر بالكامل
    $Result = schtasks /Create /TN $TaskName /TR "$CommandLine" /SC ONSTART /RL HIGHEST /F 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✅ Task created successfully" -ForegroundColor Green
        return $true
    } else {
        Write-Host "  ❌ Failed to create task" -ForegroundColor Red
        Write-Host "  Error: $Result"
        return $false
    }
}

# Create the three tasks
$successCount = 0

Write-Host ""
if (Create-ScheduledTask -TaskName "SuspiciousTracker_Backend" -ScriptPath "main.py" -Description "Suspicious Tracker Backend Engine") {
    $successCount++
}

Write-Host ""
if (Create-ScheduledTask -TaskName "SuspiciousTracker_Dashboard" -ScriptPath "dashboard\app.py" -Description "Suspicious Tracker Web Dashboard") {
    $successCount++
}

Write-Host ""
if (Create-ScheduledTask -TaskName "SuspiciousTracker_Dispatcher" -ScriptPath "integrations\dispatcher.py" -Description "Suspicious Tracker Integration Dispatcher") {
    $successCount++
}

Write-Host ""
Write-Host "============================================================"

if ($successCount -eq 3) {
    Write-Host "SUCCESS: All 3 tasks created successfully!" -ForegroundColor Green
} else {
    Write-Host "WARNING: $successCount of 3 tasks created." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "To start the tasks immediately, run:" -ForegroundColor Cyan
Write-Host "  Start-ScheduledTask -TaskName 'SuspiciousTracker_Backend'"
Write-Host "  Start-ScheduledTask -TaskName 'SuspiciousTracker_Dashboard'"
Write-Host "  Start-ScheduledTask -TaskName 'SuspiciousTracker_Dispatcher'"
Write-Host ""
Write-Host "To check task status:" -ForegroundColor Cyan
Write-Host "  Get-ScheduledTask -TaskName 'SuspiciousTracker_*' | Format-Table TaskName, State"
Write-Host ""
Write-Host "To stop tasks:" -ForegroundColor Cyan
Write-Host "  Stop-ScheduledTask -TaskName 'SuspiciousTracker_Backend'"
Write-Host "  Stop-ScheduledTask -TaskName 'SuspiciousTracker_Dashboard'"  
Write-Host "  Stop-ScheduledTask -TaskName 'SuspiciousTracker_Dispatcher'"
Write-Host ""
Write-Host "============================================================"