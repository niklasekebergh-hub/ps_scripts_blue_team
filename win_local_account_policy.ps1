param(
    [string]$OutputDir = "C:\WRCCDC\logs",
    [int]$MinLength = 12,
    [int]$MaxAgeDays = 30,
    [int]$LockoutThreshold = 3,
    [int]$LockoutDurationMinutes = 30,
    [int]$LockoutWindowMinutes = 30
)

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$hostname  = $env:COMPUTERNAME
$null = New-Item -Path $OutputDir -ItemType Directory -Force
$logFile = Join-Path $OutputDir "$hostname-account-policy-$timestamp.txt"

function Write-Section {
    param([string]$Title)
    Add-Content -Path $logFile -Value ""
    Add-Content -Path $logFile -Value "==== $Title ===="
}

Write-Section "Current net accounts"
(net accounts | Out-String) | Add-Content -Path $logFile

Write-Section "Applying new settings"
$cmd = "net accounts /minpwlen:$MinLength /maxpwage:$MaxAgeDays /lockoutthreshold:$LockoutThreshold /lockoutduration:$LockoutDurationMinutes /lockoutwindow:$LockoutWindowMinutes"
$cmd | Add-Content -Path $logFile
Invoke-Expression $cmd | Out-String | Add-Content -Path $logFile

Write-Section "New net accounts"
(net accounts | Out-String) | Add-Content -Path $logFile
