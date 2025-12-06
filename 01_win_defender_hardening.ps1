param(
    [switch]$QuickScanOnly
)

try {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
    Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue
    Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
} catch {}

try {
    Update-MpSignature -ErrorAction SilentlyContinue
} catch {}

if ($QuickScanOnly) {
    Start-MpScan -ScanType QuickScan
} else {
    Start-MpScan -ScanType QuickScan
}
