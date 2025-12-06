param(
    [string]$OutputDir = "C:\WRCCDC\logs",
    [int]$RecentMinutes = 60
)

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$hostname  = $env:COMPUTERNAME
$null = New-Item -Path $OutputDir -ItemType Directory -Force
$logFile = Join-Path $OutputDir "$hostname-suspicious-files-$timestamp.txt"

function Write-Section {
    param([string]$Title)
    Add-Content -Path $logFile -Value ""
    Add-Content -Path $logFile -Value "==== $Title ===="
}

$cutoff = (Get-Date).AddMinutes(-1 * $RecentMinutes)
$extensions = @(".ps1",".psm1",".bat",".cmd",".vbs",".js",".exe",".dll",".scr",".hta",".jar",".py",".rb")

$paths = @(
    "C:\Users",
    "C:\ProgramData",
    "C:\"
)

Write-Section "Suspicious files modified since $cutoff"

foreach ($p in $paths) {
    if (-not (Test-Path $p)) { continue }
    Add-Content -Path $logFile -Value ""
    Add-Content -Path $logFile -Value "Path: $p"

    Get-ChildItem -Path $p -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object {
            -not $_.PSIsContainer -and
            $_.LastWriteTime -gt $cutoff -and
            $_.DirectoryName -notmatch '^C:\\Windows' -and
            $_.DirectoryName -notmatch '^C:\\Program Files' -and
            $_.Extension -ne $null -and
            $extensions -contains $_.Extension.ToLower()
        } |
        Select-Object FullName, Extension, Length, LastWriteTime |
        Sort-Object LastWriteTime |
        Format-Table -AutoSize | Out-String | Add-Content -Path $logFile
}
