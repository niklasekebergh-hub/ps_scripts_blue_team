param(
    [string]$OutputDir = "C:\WRCCDC\logs"
)

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$hostname  = $env:COMPUTERNAME
$null = New-Item -Path $OutputDir -ItemType Directory -Force
$logFile = Join-Path $OutputDir "$hostname-users-groups-$timestamp.txt"

function Write-Section {
    param([string]$Title)
    Add-Content -Path $logFile -Value ""
    Add-Content -Path $logFile -Value "==== $Title ===="
}

Write-Section "Local Users"
Get-LocalUser |
    Select-Object Name, Enabled, LastLogon, PasswordLastSet |
    Sort-Object Name |
    Format-Table -AutoSize | Out-String | Add-Content -Path $logFile

Write-Section "Local Groups"
Get-LocalGroup |
    Select-Object Name, Description |
    Sort-Object Name |
    Format-Table -AutoSize | Out-String | Add-Content -Path $logFile

Write-Section "Administrators Group Members"
try {
    Get-LocalGroupMember -Group 'Administrators' |
        Select-Object Name, ObjectClass, PrincipalSource |
        Sort-Object Name |
        Format-Table -AutoSize | Out-String | Add-Content -Path $logFile
} catch {
    Add-Content -Path $logFile -Value "Failed to query Administrators group: $_"
}

Write-Section "Remote Desktop Users Group Members"
try {
    Get-LocalGroupMember -Group 'Remote Desktop Users' |
        Select-Object Name, ObjectClass, PrincipalSource |
        Sort-Object Name |
        Format-Table -AutoSize | Out-String | Add-Content -Path $logFile
} catch {
    Add-Content -Path $logFile -Value "Failed to query Remote Desktop Users group: $_"
}

Write-Section "RDP Configuration (fDenyTSConnections)"
try {
    $tsKey = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
    $val = Get-ItemProperty -Path $tsKey -Name 'fDenyTSConnections' -ErrorAction Stop
    Add-Content -Path $logFile -Value ("fDenyTSConnections = {0}" -f $val.fDenyTSConnections)
} catch {
    Add-Content -Path $logFile -Value "Failed to query RDP registry key: $_"
}
