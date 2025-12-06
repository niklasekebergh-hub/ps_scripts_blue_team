param(
    [string]$OutputDir = "C:\WRCCDC\logs"
)

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$hostname  = $env:COMPUTERNAME
$null = New-Item -Path $OutputDir -ItemType Directory -Force
$logFile = Join-Path $OutputDir "$hostname-tasks-autoruns-$timestamp.txt"

function Write-Section {
    param([string]$Title)
    Add-Content -Path $logFile -Value ""
    Add-Content -Path $logFile -Value "==== $Title ===="
}

Write-Section "Scheduled Tasks"
Get-ScheduledTask |
    Sort-Object TaskName |
    ForEach-Object {
        $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath
        [PSCustomObject]@{
            TaskName   = $_.TaskName
            TaskPath   = $_.TaskPath
            State      = $info.State
            LastRun    = $info.LastRunTime
            NextRun    = $info.NextRunTime
            Author     = $_.Author
            Actions    = ($_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; "
            Triggers   = ($_.Triggers | ForEach-Object { $_.StartBoundary + " " + $_.ScheduleType }) -join "; "
        }
    } |
    Format-Table -AutoSize | Out-String | Add-Content -Path $logFile

Write-Section "Run / RunOnce Registry Keys"
$runKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)

foreach ($key in $runKeys) {
    Add-Content -Path $logFile -Value ""
    Add-Content -Path $logFile -Value "Key: $key"
    try {
        Get-ItemProperty -Path $key |
            Select-Object * |
            Format-List | Out-String | Add-Content -Path $logFile
    } catch {
        Add-Content -Path $logFile -Value "Failed to read key: $key - $_"
    }
}

Write-Section "Startup Folders"
$startupDirs = @(
    "$Env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
    "$Env:AppData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($dir in $startupDirs) {
    Add-Content -Path $logFile -Value ""
    Add-Content -Path $logFile -Value "Directory: $dir"
    if (Test-Path $dir) {
        Get-ChildItem -Path $dir -Force |
            Select-Object Name, FullName, LastWriteTime |
            Format-Table -AutoSize | Out-String | Add-Content -Path $logFile
    } else {
        Add-Content -Path $logFile -Value "Not found."
    }
}
