[CmdletBinding()]
param(
  [int]$ServicePort = 0,                 # 0 = no port filter, show global top talkers
  [ValidateSet("TCP","UDP","ANY")]
  [string]$Protocol = "TCP",
  [ValidateSet("recv","send","any")]
  [string]$Direction = "recv",           # :contentReference[oaicite:3]{index=3}
  [int]$DurationSeconds = 20,            # capture time (15-30s is typical) :contentReference[oaicite:4]{index=4}
  [int]$Top = 10,
  [string]$OutDir = "C:\ccdc",
  [switch]$NoCapture,                    # analyze existing ETL/CSV instead of capturing
  [string]$EtlPath,
  [string]$CsvPath,
  [switch]$NoisyMode                     # groups by RemoteAddress,RemotePort like playbook's noisy option :contentReference[oaicite:5]{index=5}
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-Admin {
  $wp = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Dir([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path | Out-Null
  }
}

function Run-NetshTrace([string]$EtlOut, [int]$Seconds) {
  Write-Host "[*] Starting capture for $Seconds seconds..."
  # Prefer tracefile= (common on Windows); fall back to traceroute= (as written in playbook). :contentReference[oaicite:6]{index=6}
  $started = $false

  $cmd1 = "netsh trace start capture=yes scenario=NetConnection tracefile=`"$EtlOut`""
  $cmd2 = "netsh trace start capture=yes scenario=NetConnection traceroute=`"$EtlOut`""

  try {
    cmd.exe /c $cmd1 | Out-Null
    $started = $true
  } catch {
    try {
      cmd.exe /c $cmd2 | Out-Null
      $started = $true
    } catch {
      throw "netsh trace start failed with both tracefile= and traceroute=. Are you Admin? Is netsh trace supported here?"
    }
  }

  Start-Sleep -Seconds $Seconds
  Write-Host "[*] Stopping capture..."
  cmd.exe /c "netsh trace stop" | Out-Null
  if (-not (Test-Path -LiteralPath $EtlOut)) {
    throw "ETL was not created at $EtlOut"
  }
}

function Convert-EtlToCsv([string]$EtlIn, [string]$CsvOut) {
  Write-Host "[*] Converting ETL -> CSV via tracerpt..."
  # Matches playbook: tracerpt c:\scoring.etl -o c:\scoring.csv -of CSV :contentReference[oaicite:7]{index=7}
  cmd.exe /c "tracerpt `"$EtlIn`" -o `"$CsvOut`" -of CSV -y" | Out-Null
  if (-not (Test-Path -LiteralPath $CsvOut)) {
    throw "CSV was not created at $CsvOut"
  }
}

function Get-Prop([object]$Row, [string]$Name) {
  if ($Row.PSObject.Properties.Name -contains $Name) { return $Row.$Name }
  return $null
}

function Is-PrivateIp([string]$Ip) {
  try {
    $addr = [System.Net.IPAddress]::Parse($Ip)
    # IPv4 RFC1918 quick checks
    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
      $b = $addr.GetAddressBytes()
      if ($b[0] -eq 10) { return $true }
      if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $true }
      if ($b[0] -eq 192 -and $b[1] -eq 168) { return $true }
      return $false
    }
    # Treat IPv6 ULA (fc00::/7) as private-ish
    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
      $b = $addr.GetAddressBytes()
      return (($b[0] -band 0xFE) -eq 0xFC)
    }
    return $false
  } catch { return $false }
}

# --- Main ---
if (-not (Test-Admin)) {
  throw "Run this in an elevated PowerShell (Admin). netsh trace requires it."
}

Ensure-Dir $OutDir

$ts = Get-Date -Format "yyyyMMdd_HHmmss"
if (-not $EtlPath) { $EtlPath = Join-Path $OutDir "scoring_$ts.etl" }
if (-not $CsvPath) { $CsvPath = Join-Path $OutDir "scoring_$ts.csv" }

if (-not $NoCapture) {
  Run-NetshTrace -EtlOut $EtlPath -Seconds $DurationSeconds
  Convert-EtlToCsv -EtlIn $EtlPath -CsvOut $CsvPath
} else {
  if (-not $CsvPath -and -not $EtlPath) {
    throw "-NoCapture requires -CsvPath or -EtlPath."
  }
  if (-not (Test-Path -LiteralPath $CsvPath)) {
    if (-not (Test-Path -LiteralPath $EtlPath)) {
      throw "Could not find CSV ($CsvPath) or ETL ($EtlPath)."
    }
    Convert-EtlToCsv -EtlIn $EtlPath -CsvOut $CsvPath
  }
}

Write-Host "[*] Loading $CsvPath ..."
$rows = Import-Csv -LiteralPath $CsvPath

if (-not $rows -or $rows.Count -eq 0) {
  throw "CSV has no rows. Capture might have been too short or tracerpt output isn’t the format expected."
}

# Basic schema sanity check (playbook relies on these column names) :contentReference[oaicite:8]{index=8}
$need = @("LocalPort","RemotePort","RemoteAddress","Protocol","Direction")
$missing = $need | Where-Object { -not ($rows[0].PSObject.Properties.Name -contains $_) }
if ($missing.Count -gt 0) {
  Write-Warning "CSV is missing expected columns: $($missing -join ', '). Output may be unreliable."
}

function Filter-Rows([object[]]$InputRows, [int]$Port) {
  $f = $InputRows

  if ($Port -gt 0) {
    $f = $f | Where-Object { (Get-Prop $_ "LocalPort") -eq "$Port" }
  }

  if ($Protocol -ne "ANY") {
    $f = $f | Where-Object { (Get-Prop $_ "Protocol") -eq $Protocol }
  }

  if ($Direction -ne "any") {
    $f = $f | Where-Object { ((Get-Prop $_ "Direction") + "") -like "*$Direction*" }
  }

  return $f
}

# --- Output mode A: no ServicePort -> global top talkers ---
if ($ServicePort -le 0) {
  Write-Host ""
  Write-Host "=== Global Top Talkers (RemoteAddress) ==="
  $global = Filter-Rows -InputRows $rows -Port 0

  $global |
    Where-Object { (Get-Prop $_ "RemoteAddress") } |
    Group-Object RemoteAddress |
    Sort-Object Count -Descending |
    Select-Object -First $Top |
    ForEach-Object {
      $ip = $_.Name
      [pscustomobject]@{
        Count        = $_.Count
        RemoteAddress= $ip
        PrivateIP    = (Is-PrivateIp $ip)
      }
    } | Format-Table -AutoSize

  Write-Host ""
  Write-Host "[*] Files:"
  Write-Host "    ETL: $EtlPath"
  Write-Host "    CSV: $CsvPath"
  exit 0
}

# --- Output mode B: ServicePort specified -> scoring + dependencies ---
Write-Host ""
Write-Host "=== Service-Port View (LocalPort=$ServicePort, Protocol=$Protocol, Direction=$Direction) ==="

$filtered = Filter-Rows -InputRows $rows -Port $ServicePort

if (-not $filtered -or $filtered.Count -eq 0) {
  Write-Warning "No rows matched LocalPort=$ServicePort. Wrong port, wrong protocol, or too short/noisy capture."
} else {
  if (-not $NoisyMode) {
    $grouped = $filtered |
      Where-Object { (Get-Prop $_ "RemoteAddress") } |
      Group-Object RemoteAddress |
      Sort-Object Count -Descending
  } else {
    # Playbook “noisy” option groups by RemoteAddress,RemotePort :contentReference[oaicite:9]{index=9}
    $grouped = $filtered |
      Where-Object { (Get-Prop $_ "RemoteAddress") -and (Get-Prop $_ "RemotePort") } |
      Group-Object RemoteAddress,RemotePort |
      Sort-Object Count -Descending
  }

  $topList = $grouped | Select-Object -First $Top
  if ($topList.Count -eq 0) {
    Write-Warning "No usable remote talkers found after grouping."
  } else {
    $scoringCandidate = $topList[0].Name.Split(",")[0].Trim()

    Write-Host ""
    Write-Host "Top talkers on the suspected scoring port (top one is your likely scoring IP):"
    $topList | ForEach-Object {
      $name = $_.Name
      $ip = $name.Split(",")[0].Trim()
      $rp = if ($name -like "*,*") { $name.Split(",")[1].Trim() } else { "" }
      [pscustomobject]@{
        Count         = $_.Count
        RemoteAddress = $ip
        RemotePort    = $rp
        PrivateIP     = (Is-PrivateIp $ip)
        LikelyScoring = ($ip -eq $scoringCandidate)
      }
    } | Format-Table -AutoSize

    Write-Host ""
    Write-Host "=== Dependency Candidates (other heavy RemoteAddress talkers, excluding the top scoring IP) ==="
    # “Dependencies” view: everything else that talks to you a lot (all ports, both directions), excluding scoring IP.
    $deps = $rows |
      Where-Object { (Get-Prop $_ "RemoteAddress") -and ((Get-Prop $_ "RemoteAddress") -ne $scoringCandidate) } |
      Group-Object RemoteAddress |
      Sort-Object Count -Descending |
      Select-Object -First $Top |
      ForEach-Object {
        $ip = $_.Name
        [pscustomobject]@{
          Count        = $_.Count
          RemoteAddress= $ip
          PrivateIP    = (Is-PrivateIp $ip)
        }
      }

    $deps | Format-Table -AutoSize

    Write-Host ""
    Write-Host "[*] Likely scoring IP (best guess): $scoringCandidate"
    Write-Host "[*] Reality check: if your service starts failing, rerun—scoring IP can change. :contentReference[oaicite:10]{index=10}"
  }
}

Write-Host ""
Write-Host "[*] Files:"
Write-Host "    ETL: $EtlPath"
Write-Host "    CSV: $CsvPath"
