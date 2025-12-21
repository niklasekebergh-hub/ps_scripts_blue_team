param(
    [string]$OutputDir = "C:\WRCCDC\logs",
    [int]$RecentMinutes = 45
)

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$hostname  = $env:COMPUTERNAME
$null = New-Item -Path $OutputDir -ItemType Directory -Force
$logFile = Join-Path $OutputDir "$hostname-threathunt-$timestamp.txt"

function Write-Section {
    param([string]$Title)
    Add-Content -Path $logFile -Value ""
    Add-Content -Path $logFile -Value "==== $Title ===="
}

$cutoff = (Get-Date).AddMinutes(-1 * $RecentMinutes)

Write-Section "Processes Started in Last $RecentMinutes Minutes"
$recentProcs = @()
Get-Process | ForEach-Object {
    $p = $_
    $start = $null
    try { $start = $p.StartTime } catch {}
    if ($start -ne $null -and $start -gt $cutoff) {
        $path = $null
        try { $path = $p.MainModule.FileName } catch {}
        $recentProcs += [PSCustomObject]@{
            Name      = $p.Name
            Id        = $p.Id
            StartTime = $start
            Path      = $path
        }
    }
}

$recentProcs |
    Sort-Object StartTime |
    Format-Table -AutoSize | Out-String | Add-Content -Path $logFile

Write-Section "Suspicious Network Connections (non-local, non-common ports)"
$tcp = Get-NetTCPConnection |
    Where-Object {
        $_.RemoteAddress -ne '::' -and
        $_.RemoteAddress -ne '0.0.0.0' -and
        $_.RemoteAddress -ne '127.0.0.1' -and
        $_.RemoteAddress -notlike 'fe80*' -and
        $_.RemotePort -notin 80,443,53,3389
    }

$tcp |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
    Sort-Object RemoteAddress, RemotePort |
    Format-Table -AutoSize | Out-String | Add-Content -Path $logFile

Write-Section "Auto Services Not Running"
Get-WmiObject Win32_Service |
    Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' } |
    Select-Object Name, DisplayName, StartMode, State, StartName |
    Format-Table -AutoSize | Out-String | Add-Content -Path $logFile

Write-Section "Local Administrators (for quick check)"
try {
    Get-LocalGroupMember -Group 'Administrators' |
        Select-Object Name, ObjectClass, PrincipalSource |
        Sort-Object Name |
        Format-Table -AutoSize | Out-String | Add-Content -Path $logFile
} catch {
    Add-Content -Path $logFile -Value "Failed to query Administrators group: $_"
}
