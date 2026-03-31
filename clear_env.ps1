# clear_env.ps1 - Clear environment variables

Write-Host "Clearing Security Monitor Environment Variables" -ForegroundColor Yellow

$variables = @(
    "SMTP_PASSWORD",
    "DASH_AUTH_PASSWORD",
    "SMS__APP__NAME",
    "SMS__DASHBOARD__PORT",
    "SMS__DASHBOARD__DEBUG",
    "SMS__ALERTING__EMAIL_ENABLED"
)

foreach ($var in $variables) {
    if (Test-Path "env:$var") {
        Remove-Item "env:$var"
        Write-Host "  Removed: $var" -ForegroundColor Red
    }
}

Write-Host "`nEnvironment variables cleared." -ForegroundColor Green