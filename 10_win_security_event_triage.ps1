param(
    [string]$OutputDir = "C:\WRCCDC\logs",
    [int]$RecentMinutes = 45
)

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$hostname  = $env:COMPUTERNAME
$null = New-Item -Path $OutputDir -ItemType Directory -Force
$logFile = Join-Path $OutputDir "$hostname-security-events-$timestamp.txt"

function Write-Section {
    param([string]$Title)
    Add-Content -Path $logFile -Value ""
    Add-Content -Path $logFile -Value "==== $Title ===="
}

$since = (Get-Date).AddMinutes(-1 * $RecentMinutes)

$eventIds = @{
    "4624_SuccessfulLogon"     = 4624
    "4625_FailedLogon"         = 4625
    "4672_PrivLogon"           = 4672
    "4720_UserCreated"         = 4720
    "4722_UserEnabled"         = 4722
    "4723_PwdChangeAttempt"    = 4723
    "4724_PwdResetAttempt"     = 4724
    "4728_AddedToGlobalGroup"  = 4728
    "4732_AddedToLocalGroup"   = 4732
    "4735_GroupChanged"        = 4735
}

foreach ($label in $eventIds.Keys) {
    $id = $eventIds[$label]
    Write-Section "EventID $id ($label) since $since"
    try {
        Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$id; StartTime=$since} -ErrorAction Stop |
            Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
            Sort-Object TimeCreated |
            Format-Table -AutoSize | Out-String | Add-Content -Path $logFile
    } catch {
        Add-Content -Path $logFile -Value "No events or error for ID $id : $_"
    }
}
