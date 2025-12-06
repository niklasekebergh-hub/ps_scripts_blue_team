param(
    [string]$OutputDir = "C:\WRCCDC\passwords",
    [int]$Length = 16,
    [switch]$IncludeDisabled,
    [switch]$EchoToScreen
)

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$hostname  = $env:COMPUTERNAME
$null = New-Item -Path $OutputDir -ItemType Directory -Force
$outputFile = Join-Path $OutputDir "$hostname-local-passwords-$timestamp.txt"

$chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*?'

function New-RandomPassword {
    param([int]$Length = 16)
    $bytes = New-Object 'System.Byte[]' ($Length * 2)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Length; $i++) {
        $idx = $bytes[$i] % $chars.Length
        [void]$sb.Append($chars[$idx])
    }
    $sb.ToString()
}

try {
    $acl = Get-Acl $OutputDir
    $admin = New-Object System.Security.Principal.NTAccount("Administrators")
    $system = New-Object System.Security.Principal.NTAccount("SYSTEM")
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
    $rule1 = New-Object System.Security.AccessControl.FileSystemAccessRule($admin, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule($system, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($rule1)
    $acl.AddAccessRule($rule2)
    Set-Acl -Path $OutputDir -AclObject $acl
} catch {}

$users = Get-LocalUser | Where-Object {
    $_.Name -notin 'DefaultAccount','WDAGUtilityAccount','Guest' -and
    ($IncludeDisabled -or $_.Enabled) -and
    ($_.Name -notmatch '(?i)svc|service|sql|iis|msol_')
}

foreach ($u in $users) {
    $pwd = New-RandomPassword -Length $Length
    $secure = ConvertTo-SecureString $pwd -AsPlainText -Force
    try {
        Set-LocalUser -Name $u.Name -Password $secure
        $line = "{0},{1}" -f $u.Name, $pwd
        Add-Content -Path $outputFile -Value $line
        if ($EchoToScreen) { Write-Host $line }
    } catch {
        Add-Content -Path $outputFile -Value "FAILED:$($u.Name):$_"
    }
}

Write-Host "Local passwords written to $outputFile"
