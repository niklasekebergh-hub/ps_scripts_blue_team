param(
    [string]$OutputDir = "C:\WRCCDC\logs"
)

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$hostname  = $env:COMPUTERNAME
$null = New-Item -Path $OutputDir -ItemType Directory -Force
$logFile = Join-Path $OutputDir "$hostname-inventory-$timestamp.txt"

function Write-Section {
    param([string]$Title)
    Add-Content -Path $logFile -Value ""
    Add-Content -Path $logFile -Value "==== $Title ===="
}

Write-Section "Host Info (systeminfo)"
systeminfo | Out-String | Add-Content -Path $logFile

Write-Section "IP Config"
ipconfig /all | Out-String | Add-Content -Path $logFile

Write-Section "Disks / Volumes"
Get-Volume | Format-Table -AutoSize | Out-String | Add-Content -Path $logFile

Write-Section "Installed Hotfixes"
Get-HotFix | Sort-Object InstalledOn | Format-Table -AutoSize | Out-String | Add-Content -Path $logFile

Write-Section "Installed Software (64-bit HKLM)"
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' |
    Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Sort-Object DisplayName |
    Format-Table -AutoSize | Out-String | Add-Content -Path $logFile

Write-Section "Installed Software (32-bit HKLM)"
Get-ItemProperty 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
    Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Sort-Object DisplayName |
    Format-Table -AutoSize | Out-String | Add-Content -Path $logFile
