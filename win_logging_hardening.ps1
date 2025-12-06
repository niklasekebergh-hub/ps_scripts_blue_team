param(
    [string]$OutputDir = "C:\WRCCDC\logs"
)

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$hostname  = $env:COMPUTERNAME
$null = New-Item -Path $OutputDir -ItemType Directory -Force
$logFile = Join-Path $OutputDir "$hostname-logging-hardening-$timestamp.txt"

function Write-Section {
    param([string]$Title)
    Add-Content -Path $logFile -Value ""
    Add-Content -Path $logFile -Value "==== $Title ===="
}

Write-Section "Increase Event Log Sizes"
"Security log size -> 192MB"    | Add-Content -Path $logFile
wevtutil sl Security /ms:196608 | Out-Null
"System log size -> 192MB"      | Add-Content -Path $logFile
wevtutil sl System /ms:196608   | Out-Null
"Application log size -> 192MB" | Add-Content -Path $logFile
wevtutil sl Application /ms:196608 | Out-Null

Write-Section "Enable Key Audit Categories"
AuditPol /set /subcategory:"Logon" /success:enable /failure:enable       | Out-String | Add-Content -Path $logFile
AuditPol /set /subcategory:"Account Lockout" /success:enable /failure:enable | Out-String | Add-Content -Path $logFile
AuditPol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-String | Add-Content -Path $logFile
AuditPol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable | Out-String | Add-Content -Path $logFile

Write-Section "Enable Process Command Line Logging"
$sysPol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
New-Item -Path $sysPol -Force | Out-Null
New-ItemProperty -Path $sysPol -Name "ProcessCreationIncludeCmdLine_Enabled" -PropertyType DWord -Value 1 -Force | Out-Null
"ProcessCreationIncludeCmdLine_Enabled = 1" | Add-Content -Path $logFile

Write-Section "Enable PowerShell ScriptBlock Logging"
$psPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $psPol -Force | Out-Null
New-ItemProperty -Path $psPol -Name "EnableScriptBlockLogging" -PropertyType DWord -Value 1 -Force | Out-Null
"ScriptBlockLogging enabled" | Add-Content -Path $logFile

Write-Section "Enable PowerShell Transcription"
$psTrans = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
New-Item -Path $psTrans -Force | Out-Null
New-ItemProperty -Path $psTrans -Name "EnableTranscripting" -PropertyType DWord -Value 1 -Force | Out-Null
New-ItemProperty -Path $psTrans -Name "OutputDirectory" -PropertyType String -Value $OutputDir -Force | Out-Null
"Transcription enabled to $OutputDir" | Add-Content -Path $logFile
