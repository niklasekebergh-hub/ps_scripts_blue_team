$svcToDisable = @(
    'RemoteRegistry',
    'SSDPSRV',
    'upnphost',
    'TrkWks'
)

foreach ($name in $svcToDisable) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc) {
        try {
            if ($svc.Status -ne 'Stopped') {
                Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
            }
            Set-Service -Name $name -StartupType Disabled
            Write-Host "Disabled service: $name"
        } catch {
            Write-Host "Failed to disable service $name : $_"
        }
    }
}
