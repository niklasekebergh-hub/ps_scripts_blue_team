param(
    [string]$BaseDir = "C:\WRCCDC",
    [switch]$EnableFirewall,
    [switch]$EnableDefender,
    [switch]$EnableServiceHardening,
    [switch]$RollLocalPasswords,
    [switch]$TightenAccountPolicy
)

$ErrorActionPreference = 'Stop'

$hostname = $env:COMPUTERNAME
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

$logRoot    = Join-Path $BaseDir "logs"
$passRoot   = Join-Path $BaseDir "passwords"
$runLogFile = Join-Path $logRoot "$hostname-master-launcher-$timestamp.txt"

$null = New-Item -Path $logRoot  -ItemType Directory -Force
$null = New-Item -Path $passRoot -ItemType Directory -Force

function Write-RunLog {
    param([string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message
    Write-Host $line
    Add-Content -Path $runLogFile -Value $line
}

function Invoke-LocalScript {
    param(
        [string]$ScriptName
    )
    $scriptPath = Join-Path $PSScriptRoot $ScriptName
    if (-not (Test-Path $scriptPath)) {
        Write-RunLog "MISS: $ScriptName not found in $PSScriptRoot"
        return
    }

    Write-RunLog "RUN : $ScriptName"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $scriptPath
        $sw.Stop()
        Write-RunLog (" OK : {0} completed in {1:n1}s" -f $ScriptName, $sw.Elapsed.TotalSeconds)
    } catch {
        $sw.Stop()
        Write-RunLog ("FAIL: {0} error: {1}" -f $ScriptName, $_.Exception.Message)
    }
}

Write-RunLog "==== MASTER LAUNCHER START: $hostname $timestamp ===="
Write-RunLog "BaseDir: $BaseDir"
Write-RunLog ("Options: Firewall={0}, Defender={1}, ServiceHardening={2}, RollLocalPasswords={3}, TightenAccountPolicy={4}" -f `
    ($EnableFirewall.IsPresent), ($EnableDefender.IsPresent), ($EnableServiceHardening.IsPresent), ($RollLocalPasswords.IsPresent), ($TightenAccountPolicy.IsPresent))

# --- SAFE BASELINE / LOGGING / HUNTING ---

Invoke-LocalScript "01_win_init_inventory.ps1"
Invoke-LocalScript "02_win_user_group_audit.ps1"
Invoke-LocalScript "03_win_service_process_audit.ps1"
Invoke-LocalScript "04_win_schtask_autoruns_audit.ps1"
Invoke-LocalScript "05_win_network_snapshot.ps1"
Invoke-LocalScript "09_win_logging_hardening.ps1"
Invoke-LocalScript "08_win_quick_threathunt.ps1"
Invoke-LocalScript "10_win_security_event_triage.ps1"
Invoke-LocalScript "11_win_suspicious_file_scan.ps1"

# --- OPTIONAL HARDENING / HIGH-IMPACT ACTIONS ---

if ($EnableDefender) {
    Invoke-LocalScript "07_win_defender_hardening.ps1"
} else {
    Write-RunLog "SKIP: Defender hardening (use -EnableDefender to run)"
}

if ($EnableFirewall) {
    Invoke-LocalScript "06_win_firewall_hardening.ps1"
} else {
    Write-RunLog "SKIP: Firewall hardening (use -EnableFirewall to run, beware scoring ports)"
}

if ($EnableServiceHardening) {
    Invoke-LocalScript "12_win_safe_service_hardening.ps1"
} else {
    Write-RunLog "SKIP: Service hardening (use -EnableServiceHardening to run)"
}

if ($RollLocalPasswords) {
    Invoke-LocalScript "14_win_roll_local_passwords.ps1"
} else {
    Write-RunLog "SKIP: Rolling local passwords (use -RollLocalPasswords to run)"
}

if ($TightenAccountPolicy) {
    Invoke-LocalScript "13_win_local_account_policy.ps1"
} else {
    Write-RunLog "SKIP: Local account policy hardening (use -TightenAccountPolicy to run)"
}

Write-RunLog "==== MASTER LAUNCHER END ===="
Write-Host ""
Write-Host "Master launcher log: $runLogFile"
