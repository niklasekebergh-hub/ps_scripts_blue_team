param(
    [string[]]$Profiles = @('Domain','Private','Public')
)

$profilesJoined = $Profiles -join ','

Set-NetFirewallProfile -Profile $Profiles -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow

if (-not (Get-NetFirewallRule -DisplayName 'Allow_RDP_3389' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName 'Allow_RDP_3389' `
        -Direction Inbound -Protocol TCP -LocalPort 3389 `
        -Action Allow -Profile $Profiles
}

if (-not (Get-NetFirewallRule -DisplayName 'Allow_Ping_ICMPv4' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName 'Allow_Ping_ICMPv4' `
        -Protocol ICMPv4 -IcmpType 8 -Direction Inbound `
        -Action Allow -Profile $Profiles
}

if (-not (Get-NetFirewallRule -DisplayName 'Allow_Windows_FileAndPrinter_Sharing' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName 'Allow_Windows_FileAndPrinter_Sharing' `
        -Direction Inbound -Protocol TCP -LocalPort 445 `
        -Action Allow -Profile $Profiles
}

Write-Host "Firewall hardened for profiles: $profilesJoined"
