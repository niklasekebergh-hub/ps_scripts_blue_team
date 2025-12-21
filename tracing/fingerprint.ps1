param(
  [int]$DurationSeconds = 20,
  [double]$IntervalSeconds = 0.5,
  [int]$Top = 15,
  [int]$Port = 0,  # optional focus: only show flows involving this port
  [ValidateSet("TCP","UDP","ANY")] [string]$Protocol = "TCP",
  [string]$OutDir = "C:\ccdc"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

function Write-Info($msg){ Write-Host "[*] $msg" }
function Write-Warn($msg){ Write-Host "[!] $msg" }
function Write-Err ($msg){ Write-Host "[X] $msg" }

function Test-IsAdmin {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

function Get-OSVersionString {
  try {
    $os = Get-CimInstance Win32_OperatingSystem
    return "$($os.Caption) ($($os.Version))"
  } catch {
    return [System.Environment]::OSVersion.VersionString
  }
}

function Get-ProcName([int]$pid) {
  if ($pid -le 0) { return "?" }
  try { return (Get-Process -Id $pid -ErrorAction Stop).ProcessName } catch { return "pid:$pid" }
}

function Ensure-Dir($p){ New-Item -ItemType Directory -Force -Path $p | Out-Null }

function Try-NetshScenario([string]$scenarioName) {
  # Quick probe: does netsh trace exist and list scenarios?
  $out = & netsh trace show scenarios 2>&1
  if ($LASTEXITCODE -ne 0) { return $false }
  return ($out -match [regex]::Escape($scenarioName))
}

function Parse-NetshCsvOrFail($csvPath, [int]$Port, [string]$Protocol) {
  $rows = Import-Csv $csvPath
  if (-not $rows -or $rows.Count -eq 0) { throw "CSV is empty." }

  # Schema sanity check (this is what usually becomes “finicky”)
  $props = ($rows | Select-Object -First 1 | Get-Member -MemberType NoteProperty).Name
  $need = @("Protocol","LocalPort","RemoteAddress","RemotePort","Direction")
  foreach ($n in $need) {
    if ($props -notcontains $n) {
      throw "CSV schema mismatch: missing column '$n'. Present: $($props -join ', ')"
    }
  }

  # Filter
  $filtered = $rows
  if ($Protocol -ne "ANY") {
    $filtered = $filtered | Where-Object { $_.Protocol -eq $Protocol }
  }
  if ($Port -gt 0) {
    $filtered = $filtered | Where-Object { $_.LocalPort -eq "$Port" }
  }

  # If still nothing, throw so we fall back automatically.
  if (-not $filtered -or $filtered.Count -eq 0) {
    throw "No matching rows after filtering (Protocol=$Protocol, LocalPort=$Port)."
  }

  # INBOUND: recv
  $in = $filtered | Where-Object { $_.Direction -like "*recv*" }
  # OUTBOUND: send
  $out = $filtered | Where-Object { $_.Direction -like "*send*" }

  return [pscustomobject]@{
    Inbound  = $in
    Outbound = $out
  }
}

function Run-FallbackSampler([int]$DurationSeconds, [double]$IntervalSeconds, [int]$Top, [int]$Port, [string]$Protocol) {
  Write-Warn "Using fallback sampler (TCP connection truth). This is stable, but it won't show pure UDP flows."

  # Listener port set to infer IN vs OUT for TCP
  $listenerPorts = @{}
  if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    Get-NetTCPConnection -State Listen | ForEach-Object { $listenerPorts[[int]$_.LocalPort] = $true }
  } else {
    (netstat -ano -p tcp | Select-String "LISTENING") | ForEach-Object {
      $p = (($_ -replace '\s+',' ').Trim().Split(' '))[1].Split(':')[-1]
      if ($p -match '^\d+$') { $listenerPorts[[int]$p] = $true }
    }
  }

  $agg = @{}  # key -> object

  function Touch([string]$dir, [int]$lport, [string]$rip, [int]$rport, [int]$pid, [string]$state) {
    if ($Port -gt 0 -and $lport -ne $Port -and $rport -ne $Port) { return }
    $key = "$dir|L:$lport|R:$rip:$rport"
    if (-not $agg.ContainsKey($key)) {
      $agg[$key] = [pscustomobject]@{
        Dir=$dir; LocalPort=$lport; RemoteIP=$rip; RemotePort=$rport;
        Count=0; Pids = New-Object System.Collections.Generic.HashSet[int]
        States = New-Object System.Collections.Generic.HashSet[string]
      }
    }
    $o = $agg[$key]
    $o.Count++
    [void]$o.Pids.Add($pid)
    if ($state) { [void]$o.States.Add($state) }
  }

  $steps = [int][Math]::Ceiling($DurationSeconds / $IntervalSeconds)
  for ($i=0; $i -lt $steps; $i++) {
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
      Get-NetTCPConnection |
        Where-Object { $_.RemoteAddress -and $_.RemotePort -and $_.State -ne "Listen" } |
        ForEach-Object {
          $lport = [int]$_.LocalPort
          $rport = [int]$_.RemotePort
          $rip   = [string]$_.RemoteAddress
          $pid   = [int]$_.OwningProcess
          $state = [string]$_.State
          $dir   = $listenerPorts.ContainsKey($lport) ? "IN" : "OUT"
          Touch $dir $lport $rip $rport $pid $state
        }
    } else {
      (netstat -ano -p tcp | Select-String "^ *TCP") | ForEach-Object {
        $parts = (($_ -replace '\s+',' ').Trim().Split(' '))
        if ($parts.Count -lt 5) { return }
        $local = $parts[1]; $remote = $parts[2]; $state = $parts[3]; $pid = [int]$parts[4]
        $lport = [int]($local.Split(':')[-1])
        $rport = [int]($remote.Split(':')[-1])
        $rip   = ($remote -split ':')[0]
        $dir   = $listenerPorts.ContainsKey($lport) ? "IN" : "OUT"
        Touch $dir $lport $rip $rport $pid $state
      }
    }
    Start-Sleep -Seconds $IntervalSeconds
  }

  $rows = foreach ($k in $agg.Keys) {
    $o = $agg[$k]
    $pids = ($o.Pids | Sort-Object)
    [pscustomobject]@{
      Dir=$o.Dir; LocalPort=$o.LocalPort; RemoteIP=$o.RemoteIP; RemotePort=$o.RemotePort;
      Count=$o.Count;
      PIDs=($pids -join ";");
      Processes=(($pids | ForEach-Object { Get-ProcName $_ } | Sort-Object -Unique) -join ";");
      States=(($o.States | Sort-Object) -join ";")
    }
  } | Sort-Object Count -Descending

  Write-Host ""
  Write-Host "=== INBOUND (clients hitting your listening ports) ==="
  $rows | Where-Object { $_.Dir -eq "IN" } | Select-Object -First $Top |
    Format-Table -AutoSize Dir,LocalPort,RemoteIP,RemotePort,Count,Processes,States

  Write-Host ""
  Write-Host "=== OUTBOUND (dependencies: what this host calls) ==="
  $rows | Where-Object { $_.Dir -eq "OUT" } | Select-Object -First $Top |
    Format-Table -AutoSize Dir,LocalPort,RemoteIP,RemotePort,Count,Processes,States
}

# Main
Ensure-Dir $OutDir
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
Write-Info "OS: $(Get-OSVersionString)"
Write-Info "Duration: ${DurationSeconds}s (fallback sampler interval: ${IntervalSeconds}s)"
if ($Port -gt 0) { Write-Info "Port focus: $Port" }
Write-Info "Protocol filter (netsh parsing only): $Protocol"
Write-Host ""

$netshOk = $false
$netshWhy = ""
$etl = Join-Path $OutDir "scoreprobe-$stamp.etl"
$csv = Join-Path $OutDir "scoreprobe-$stamp.csv"

# Try netsh first by default
$haveNetsh = [bool](Get-Command netsh -ErrorAction SilentlyContinue)
$haveTracerpt = [bool](Get-Command tracerpt -ErrorAction SilentlyContinue)
$isAdmin = Test-IsAdmin

if (-not $haveNetsh) {
  $netshWhy = "netsh not found on PATH (weird box)."
} elseif (-not $isAdmin) {
  $netshWhy = "not running as Administrator (netsh trace requires elevation)."
} elseif (-not (Try-NetshScenario "NetConnection")) {
  $netshWhy = "netsh trace scenario 'NetConnection' not available on this OS / image."
} elseif (-not $haveTracerpt) {
  $netshWhy = "tracerpt not available (can't convert ETL -> CSV)."
} else {
  Write-Info "Attempting netsh trace capture -> $etl"
  $startOut = & netsh trace start capture=yes scenario=NetConnection tracefile="$etl" report=no persistent=no maxsize=100 filemode=circular 2>&1
  $startCode = $LASTEXITCODE

  if ($startCode -ne 0 -or ($startOut -match "(requires elevation|Access is denied|The command you entered is not valid|not found|already in progress)")) {
    # Try to extract a human reason
    if ($startOut -match "already in progress") {
      $netshWhy = "netsh trace session already running. (Someone started it earlier.)"
    } elseif ($startOut -match "requires elevation|Access is denied") {
      $netshWhy = "netsh trace start denied (admin/elevation issue despite check)."
    } elseif ($startOut -match "not valid|not found") {
      $netshWhy = "netsh trace not supported / invalid command on this image."
    } else {
      $netshWhy = "netsh trace start failed (exit=$startCode): $($startOut | Select-Object -First 1)"
    }
  } else {
    $netshOk = $true
    Start-Sleep -Seconds $DurationSeconds
    Write-Info "Stopping netsh trace"
    & netsh trace stop 2>&1 | Out-Null

    Write-Info "Converting ETL -> CSV via tracerpt -> $csv"
    $trOut = & tracerpt "$etl" -o "$csv" -of CSV 2>&1
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $csv)) {
      $netshOk = $false
      $netshWhy = "tracerpt conversion failed: $($trOut | Select-Object -First 1)"
    } else {
      # Try parsing; if schema mismatch, treat as failure and fall back
      try {
        $parsed = Parse-NetshCsvOrFail $csv $Port $Protocol

        Write-Host ""
        Write-Host "=== NETSH PARSE: INBOUND (recv) top talkers ==="
        ($parsed.Inbound | Group-Object RemoteAddress | Sort-Object Count -Descending | Select-Object -First $Top) |
          ForEach-Object { "{0,6}  {1}" -f $_.Count, $_.Name }

        Write-Host ""
        Write-Host "=== NETSH PARSE: OUTBOUND (send) dependencies ==="
        ($parsed.Outbound | Group-Object RemoteAddress,RemotePort | Sort-Object Count -Descending | Select-Object -First $Top) |
          ForEach-Object { "{0,6}  {1}" -f $_.Count, $_.Name }

        Write-Host ""
        Write-Info "Artifacts:"
        Write-Info "  ETL: $etl"
        Write-Info "  CSV: $csv"
        exit 0
      } catch {
        $netshOk = $false
        $netshWhy = "netsh capture worked but CSV parsing is not reliable here: $($_.Exception.Message)"
      }
    }
  }
}

# If we got here: netsh path failed; explain and fall back
Write-Warn "Netsh primary path FAILED: $netshWhy"
Write-Warn "Falling back now."
Run-FallbackSampler -DurationSeconds $DurationSeconds -IntervalSeconds $IntervalSeconds -Top $Top -Port $Port -Protocol $Protocol
