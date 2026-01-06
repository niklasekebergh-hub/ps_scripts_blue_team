[CmdletBinding()]
param(
  [int]$ServicePort = 0,                 # 0 = no port filter, show global top talkers
  [ValidateSet("TCP","UDP","ANY")]
  [string]$Protocol = "TCP",
  [ValidateSet("recv","send","any")]
  [string]$Direction = "recv",
  [int]$DurationSeconds = 20,            # capture time (15-30s is typical)
  [int]$Top = 10,
  [string]$OutDir = "C:\ccdc",
  [switch]$NoCapture,                    # analyze existing ETL/CSV instead of capturing
  [string]$EtlPath,
  [string]$CsvPath,
  [switch]$NoisyMode                     # group by RemoteAddress,RemotePort
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

function Invoke-Native {
  param(
    [Parameter(Mandatory)][string]$FilePath,
    [Parameter()][string[]]$ArgumentList
  )
  $output = & $FilePath @ArgumentList 2>&1
  $code = $LASTEXITCODE
  if ($code -ne 0) {
    $msg = ($output | Out-String).Trim()
    if (-not $msg) { $msg = "<no output>" }
    throw "$FilePath failed (exit $code): $($ArgumentList -join ' ')`n$msg"
  }
  return $output
}

function Run-NetshTrace([string]$EtlOut, [int]$Seconds) {
  Write-Host "[*] Starting capture for $Seconds seconds..."

  # netsh trace uses tracefile= . "traceroute=" is NOT valid.
  $startArgs = @('trace','start','capture=yes','scenario=NetConnection',("tracefile=$EtlOut"))
  $stopArgs  = @('trace','stop')

  try {
    Invoke-Native -FilePath 'netsh' -ArgumentList $startArgs | Out-Null
    Start-Sleep -Seconds $Seconds
  }
  finally {
    Write-Host "[*] Stopping capture..."
    try {
      Invoke-Native -FilePath 'netsh' -ArgumentList $stopArgs | Out-Null
    } catch {
      Write-Warning "netsh trace stop failed (trace may still be running): $($_.Exception.Message)"
    }
  }

  if (-not (Test-Path -LiteralPath $EtlOut)) {
    throw "ETL was not created at $EtlOut"
  }
}

function Convert-EtlToCsv([string]$EtlIn, [string]$CsvOut) {
  Write-Host "[*] Converting ETL -> CSV via tracerpt..."
  Invoke-Native -FilePath 'tracerpt' -ArgumentList @($EtlIn,'-o',$CsvOut,'-of','CSV','-y') | Out-Null

  if (-not (Test-Path -LiteralPath $CsvOut)) {
    throw "CSV was not created at $CsvOut"
  }
}

function Import-TracerptCsv([string]$Path) {
  # tracerpt CSVs sometimes have non-table lines before the header.
  $lines = Get-Content -LiteralPath $Path -ErrorAction Stop

  $match = $lines | Select-String -Pattern '^"?(LocalPort|Local Port)"?,' -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($match) {
    $start = [Math]::Max(0, $match.LineNumber - 1)
    $csvText = $lines[$start..($lines.Count - 1)] -join "`r`n"
    return @($csvText | ConvertFrom-Csv)
  }

  return @(Import-Csv -LiteralPath $Path)
}

function Try-ParseInt([object]$v) {
  if ($null -eq $v) { return $null }
  $s = ($v.ToString()).Trim()
  $i = 0
  if ([int]::TryParse($s, [ref]$i)) { return $i }
  return $null
}

function Normalize-Protocol([object]$v) {
  $s = (($v + '').ToString()).Trim()
  switch -Regex ($s) {
    '^(6|tcp)$'  { return 'TCP' }
    '^(17|udp)$' { return 'UDP' }
    default      { return $s.ToUpperInvariant() }
  }
}

function Test-DirectionMatch([object]$val, [string]$want) {
  if ($want -ieq 'any') { return $true }
  $s = (($val + '').ToString()).ToLowerInvariant()

  switch ($want.ToLowerInvariant()) {
    'recv' { return ($s -match 'recv|receive|inbound|in') }
    'send' { return ($s -match 'send|sent|outbound|out') }
    default { return $true }
  }
}

function Resolve-ColumnMap([object]$SampleRow) {
  $props = @($SampleRow.PSObject.Properties.Name)

  function Pick([string[]]$cands) {
    foreach ($c in $cands) {
      $hit = $props | Where-Object { $_ -ieq $c } | Select-Object -First 1
      if ($hit) { return $hit }
    }
    foreach ($c in $cands) {
      $hit = $props | Where-Object { $_ -imatch [regex]::Escape($c) } | Select-Object -First 1
      if ($hit) { return $hit }
    }
    return $null
  }

  [pscustomobject]@{
    LocalPort     = Pick @('LocalPort','Local Port','SrcPort','SourcePort')
    RemotePort    = Pick @('RemotePort','Remote Port','DstPort','DestPort','DestinationPort')
    RemoteAddress = Pick @('RemoteAddress','Remote Address','DstAddr','DestAddr','DestinationAddress','RemoteIP')
    Protocol      = Pick @('Protocol','IPProtocol','IP Protocol','TransportProtocol')
    Direction     = Pick @('Direction','Dir','TrafficDirection')
  }
}

# Will be set after CSV import
$script:ColMap = $null

function Get-Field([object]$Row, [string]$Canonical) {
  $actual = $script:ColMap.$Canonical
  if ($actual -and $Row.PSObject.Properties[$actual]) {
    return $Row.PSObject.Properties[$actual].Value
  }

  # fall back if the canonical exists literally
  if ($Row.PSObject.Properties[$Canonical]) {
    return $Row.PSObject.Properties[$Canonical].Value
  }

  return $null
}

function Is-PrivateIp([string]$Ip) {
  try {
    $addr = [System.Net.IPAddress]::Parse($Ip)

    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
      $b = $addr.GetAddressBytes()
      if ($b[0] -eq 10) { return $true }
      if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $true }
      if ($b[0] -eq 192 -and $b[1] -eq 168) { return $true }
      return $false
    }

    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
      $b = $addr.GetAddressBytes()
      return (($b[0] -band 0xFE) -eq 0xFC)  # fc00::/7
    }

    return $false
  } catch { return $false }
}

function Filter-Rows([object[]]$InputRows, [int]$Port) {
  $f = $InputRows

  if ($Port -gt 0) {
    $f = $f | Where-Object { (Try-ParseInt (Get-Field $_ 'LocalPort')) -eq $Port }
  }

  if ($Protocol -ne "ANY") {
    $f = $f | Where-Object { (Normalize-Protocol (Get-Field $_ 'Protocol')) -eq $Protocol }
  }

  if ($Direction -ne "any") {
    $f = $f | Where-Object { Test-DirectionMatch -val (Get-Field $_ 'Direction') -want $Direction }
  }

  return $f
}

# --- Main ---

Ensure-Dir $OutDir

if (-not $NoCapture) {
  if (-not (Test-Admin)) {
    throw "Run this in an elevated PowerShell (Admin). netsh trace requires it."
  }

  $ts = Get-Date -Format "yyyyMMdd_HHmmss"
  if (-not $EtlPath) { $EtlPath = Join-Path $OutDir "scoring_$ts.etl" }
  if (-not $CsvPath) { $CsvPath = Join-Path $OutDir "scoring_$ts.csv" }

  Run-NetshTrace -EtlOut $EtlPath -Seconds $DurationSeconds
  Convert-EtlToCsv -EtlIn $EtlPath -CsvOut $CsvPath
}
else {
  # In NoCapture mode, DO NOT auto-invent paths and pretend they exist.
  if (-not $CsvPath -and -not $EtlPath) {
    throw "-NoCapture requires -CsvPath or -EtlPath."
  }

  if (-not $CsvPath -and $EtlPath) {
    $CsvPath = [System.IO.Path]::ChangeExtension($EtlPath, ".csv")
  }

  if ($CsvPath -and (Test-Path -LiteralPath $CsvPath)) {
    # ok
  }
  elseif ($EtlPath -and (Test-Path -LiteralPath $EtlPath)) {
    Convert-EtlToCsv -EtlIn $EtlPath -CsvOut $CsvPath
  }
  else {
    throw "Could not find CSV ($CsvPath) or ETL ($EtlPath)."
  }

  # If user didn't provide EtlPath in NoCapture mode, keep it blank.
}

Write-Host "[*] Loading $CsvPath ..."
$rows = @(Import-TracerptCsv -Path $CsvPath)

if ($rows.Count -eq 0) {
  throw "CSV has no rows. Capture might have been too short or tracerpt output isn’t the format expected."
}

$script:ColMap = Resolve-ColumnMap -SampleRow $rows[0]

# Basic schema sanity check
$need = @("LocalPort","RemotePort","RemoteAddress","Protocol","Direction")
$missing = $need | Where-Object { -not $script:ColMap.$_ }
if (@($missing).Count -gt 0) {
  Write-Warning "CSV is missing/unknown expected columns: $($missing -join ', '). Output may be unreliable."
}

# --- Output mode A: no ServicePort -> global top talkers ---
if ($ServicePort -le 0) {
  Write-Host ""
  Write-Host "=== Global Top Talkers (RemoteAddress) ==="

  $global = Filter-Rows -InputRows $rows -Port 0

  $global |
    Where-Object { (Get-Field $_ 'RemoteAddress') } |
    Group-Object -Property { ((Get-Field $_ 'RemoteAddress') + '').Trim() } |
    Sort-Object Count -Descending |
    Select-Object -First $Top |
    ForEach-Object {
      $ip = $_.Name
      [pscustomobject]@{
        Count         = $_.Count
        RemoteAddress = $ip
        PrivateIP     = (Is-PrivateIp $ip)
      }
    } | Format-Table -AutoSize

  Write-Host ""
  Write-Host "[*] Files:"
  if ($EtlPath) { Write-Host "    ETL: $EtlPath" }
  Write-Host "    CSV: $CsvPath"
  return
}

# --- Output mode B: ServicePort specified -> scoring + dependencies ---
Write-Host ""
Write-Host "=== Service-Port View (LocalPort=$ServicePort, Protocol=$Protocol, Direction=$Direction) ==="

$filtered = @(Filter-Rows -InputRows $rows -Port $ServicePort)

if ($filtered.Count -eq 0) {
  Write-Warning "No rows matched LocalPort=$ServicePort. Wrong port, wrong protocol, wrong direction, or too short/noisy capture."
}
else {
  if (-not $NoisyMode) {
    $grouped = $filtered |
      Where-Object { (Get-Field $_ 'RemoteAddress') } |
      Group-Object -Property { ((Get-Field $_ 'RemoteAddress') + '').Trim() } |
      Sort-Object Count -Descending
  }
  else {
    $grouped = $filtered |
      Where-Object { (Get-Field $_ 'RemoteAddress') -and (Get-Field $_ 'RemotePort') } |
      Group-Object -Property {
        $ip = ((Get-Field $_ 'RemoteAddress') + '').Trim()
        $rp = (Try-ParseInt (Get-Field $_ 'RemotePort'))
        "$ip,$rp"
      } |
      Sort-Object Count -Descending
  }

  $topList = @($grouped | Select-Object -First $Top)

  if ($topList.Count -eq 0) {
    Write-Warning "No usable remote talkers found after grouping."
  }
  else {
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

    $deps = $rows |
      Where-Object {
        $ra = (Get-Field $_ 'RemoteAddress')
        $ra -and (($ra + '').Trim() -ne $scoringCandidate)
      } |
      Group-Object -Property { ((Get-Field $_ 'RemoteAddress') + '').Trim() } |
      Sort-Object Count -Descending |
      Select-Object -First $Top |
      ForEach-Object {
        $ip = $_.Name
        [pscustomobject]@{
          Count         = $_.Count
          RemoteAddress = $ip
          PrivateIP     = (Is-PrivateIp $ip)
        }
      }

    $deps | Format-Table -AutoSize

    Write-Host ""
    Write-Host "[*] Likely scoring IP (best guess): $scoringCandidate"
    Write-Host "[*] Reality check: if your service starts failing, rerun—scoring IP can change."
  }
}

Write-Host ""
Write-Host "[*] Files:"
if ($EtlPath) { Write-Host "    ETL: $EtlPath" }
Write-Host "    CSV: $CsvPath"

