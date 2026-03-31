# security_env.psm1 - PowerShell module for Security Monitor

function Set-SecurityEnv {
    <#
    .SYNOPSIS
    Set environment variables for Security Monitor
    
    .EXAMPLE
    Set-SecurityEnv -SmtpPassword "pass123" -DashboardPassword "admin456"
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SmtpPassword,
        
        [Parameter(Mandatory=$true)]
        [string]$DashboardPassword,
        
        [string]$AppName = "Security Monitor",
        
        [int]$DashboardPort = 8050
    )
    
    $env:SMTP_PASSWORD = $SmtpPassword
    $env:DASH_AUTH_PASSWORD = $DashboardPassword
    $env:SMS__APP__NAME = $AppName
    $env:SMS__DASHBOARD__PORT = $DashboardPort.ToString()
    
    Write-Host "✅ Environment variables set:" -ForegroundColor Green
    Write-Host "   SMTP_PASSWORD = [SET]" -ForegroundColor Yellow
    Write-Host "   DASH_AUTH_PASSWORD = [SET]" -ForegroundColor Yellow
    Write-Host "   SMS__APP__NAME = $AppName" -ForegroundColor Yellow
    Write-Host "   SMS__DASHBOARD__PORT = $DashboardPort" -ForegroundColor Yellow
}

function Clear-SecurityEnv {
    <#
    .SYNOPSIS
    Clear Security Monitor environment variables
    #>
    
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
            Write-Host "Removed: $var" -ForegroundColor Red
        }
    }
    
    Write-Host "✅ Security Monitor environment cleared" -ForegroundColor Green
}

function Show-SecurityEnv {
    <#
    .SYNOPSIS
    Show current Security Monitor environment variables
    #>
    
    Write-Host "Current Security Monitor Environment:" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    
    $variables = @(
        "SMTP_PASSWORD",
        "DASH_AUTH_PASSWORD",
        "SMS__APP__NAME",
        "SMS__DASHBOARD__PORT"
    )
    
    foreach ($var in $variables) {
        $value = [Environment]::GetEnvironmentVariable($var, "Process")
        if ($value) {
            if ($var -like "*PASSWORD") {
                Write-Host "  $var = [SET]" -ForegroundColor Green
            } else {
                Write-Host "  $var = $value" -ForegroundColor Green
            }
        } else {
            Write-Host "  $var = [NOT SET]" -ForegroundColor Red
        }
    }
}

Export-ModuleMember -Function Set-SecurityEnv, Clear-SecurityEnv, Show-SecurityEnv