param(
    [string]$OutputDir = "C:\WRCCDC\logs"
)

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$hostname  = $env:COMPUTERNAME
$null = New-Item -Path $OutputDir -ItemType Directory -Force
$logFile = Join-Path $OutputDir "$hostname-network-$timestamp.txt"

function Write-Section {
    param([string]$Title)
    Add-Content -Path $logFile -Value ""
    Add-Content -Path $logFile -Value "==== $Title ===="
}

Write-Section "IP Config"
ipconfig /all | Out-String | Add-Content -Path $logFile

Write-Section "Routing Table"
route print | Out-String | Add-Content -Path $logFile

Write-Section "TCP Connections (Get-NetTCPConnection)"
Get-NetTCPConnection |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
    Sort-Object LocalPort, RemoteAddress |
    Format-Table -AutoSize | Out-String | Add-Content -Path $logFile

Write-Section "UDP Endpoints (Get-NetUDPEndpoint)"
Get-NetUDPEndpoint |
    Select-Object LocalAddress, LocalPort, OwningProcess |
    Sort-Object LocalPort |
    Format-Table -AutoSize | Out-String | Add-Content -Path $logFile

Write-Section "DNS Client Server Addresses"
Get-DnsClientServerAddress |
    Select-Object InterfaceAlias, AddressFamily, ServerAddresses |
    Format-Table -AutoSize | Out-String | Add-Content -Path $logFile

Write-Section "Enabled Firewall Rules"
Get-NetFirewallRule -Enabled True |
    Select-Object DisplayName, Direction, Action, Profile |
    Sort-Object DisplayName |
    Format-Table -AutoSize | Out-String | Add-Content -Path $logFile
