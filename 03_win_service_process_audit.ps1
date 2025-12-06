param(
    [string]$OutputDir = "C:\WRCCDC\logs"
)

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$hostname  = $env:COMPUTERNAME
$null = New-Item -Path $OutputDir -ItemType Directory -Force
$logFile = Join-Path $OutputDir "$hostname-services-procs-$timestamp.txt"

function Write-Section {
    param([string]$Title)
    Add-Content -Path $logFile -Value ""
    Add-Content -Path $logFile -Value "==== $Title ===="
}

Write-Section "All Services (from Win32_Service)"
$services = Get-WmiObject Win32_Service
$services |
    Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
    Sort-Object Name |
    Format-Table -AutoSize | Out-String | Add-Content -Path $logFile

Write-Section "Suspicious Running Services (non-standard paths)"
$services |
    Where-Object {
        $_.State -eq 'Running' -and
        $_.PathName -ne $null -and
        $_.PathName -notmatch '^(?i)c:\\windows\\|c:\\program files'
    } |
    Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
    Format-Table -AutoSize | Out-String | Add-Content -Path $logFile

Write-Section "Top Processes by CPU"
$procList = @()
Get-Process | ForEach-Object {
    $p = $_
    $path = $null
    $start = $null
    try { $path = $p.MainModule.FileName } catch {}
    try { $start = $p.StartTime } catch {}
    $procList += [PSCustomObject]@{
        Name      = $p.Name
        Id        = $p.Id
        CPU       = $p.CPU
        StartTime = $start
        Path      = $path
    }
}

$procList |
    Sort-Object CPU -Descending |
    Select-Object -First 40 |
    Format-Table -AutoSize | Out-String | Add-Content -Path $logFile
