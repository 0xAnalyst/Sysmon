<#
.SYNOPSIS
  Deploys the incident-response Sysmon config and the Windows logging an investigation needs.

.DESCRIPTION
  Safe to run more than once: later runs reapply the config and settings but keep the backups
  taken on the first run, so Remove-SysmonIR.ps1 can always restore the client's original state.

  On the first run it:
    - records what is already there: an existing Sysmon (standalone or the built-in Windows
      feature), its config (registry export) and its existing event log (exported to .evtx)
    - installs Sysmon, or applies the IR config to the Sysmon already installed
    - raises the size of the Sysmon, Security, PowerShell, RDP, Task Scheduler and Defender logs
      (never lowers them) and enables the Task Scheduler log
    - enables the audit subcategories behind the Windows events the reports rely on (logons
      4624/4625, process creation with command line 4688, services 4697, tasks 4698, Kerberos
      4768/4769, share access 5140, account changes, DCSync 4662 on domain controllers) and
      PowerShell script block logging (4104). The previous audit policy is backed up first.
    - checks that Sysmon is running and logging

  State and backups are kept in -StateDir (default C:\ProgramData\SysmonIR).

.PARAMETER ConfigPath
  Sysmon config to apply. Default: ..\windows-ir.xml next to this script.

.PARAMETER SysmonExe
  Path to Sysmon64.exe (or Sysmon64a.exe on ARM64). Default: the binary next to this script.

.PARAMETER Download
  Download Sysmon from Sysinternals when no binary is found, and check its Microsoft signature.

.PARAMETER DetailedFileShare
  Also audit Detailed File Share (5145). Very noisy on file servers and domain controllers.

.EXAMPLE
  .\Deploy-SysmonIR.ps1 -SysmonExe \\share\tools\Sysmon64.exe
.EXAMPLE
  .\Deploy-SysmonIR.ps1 -ConfigPath .\sysmon-client.xml -Download
#>
[CmdletBinding()]
param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot '..\windows-ir.xml'),
  [string]$SysmonExe,
  [switch]$Download,
  [int]$SysmonLogSizeMB = 2048,
  [switch]$SkipAuditPolicy,
  [switch]$SkipLogSizes,
  [switch]$DetailedFileShare,
  [string]$StateDir = (Join-Path $env:ProgramData 'SysmonIR')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

function Write-Step($msg) { Write-Host "[SysmonIR] $msg" }

# Windows PowerShell 5.1 turns a native program's redirected stderr into a terminating error when
# $ErrorActionPreference is Stop (Sysmon prints its banner to stderr). Run native commands with
# Continue and return their output, stderr included, as plain text lines; check $LASTEXITCODE after.
function Invoke-Native([scriptblock]$Block) {
  $eap = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try { & $Block 2>&1 | ForEach-Object { "$_" } } finally { $ErrorActionPreference = $eap }
}

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell (Administrator).'
  }
}

# Runs a Sysmon command and fails on a non-zero exit code or error text in its output.
function Invoke-Sysmon([string]$exe, [string[]]$arguments) {
  $out = Invoke-Native { & $exe @arguments } | Out-String
  $code = $LASTEXITCODE
  if ($code -ne 0 -or $out -match '(?i)\b(error|invalid|failed)\b') {
    throw "Sysmon $($arguments -join ' ') failed (exit $code):`n$out"
  }
  return $out
}

# Finds an installed Sysmon service, whatever it was renamed to.
function Get-SysmonInstall {
  foreach ($svc in Get-CimInstance Win32_Service) {
    if (-not $svc.PathName) { continue }
    $path = $svc.PathName.Trim('"')
    if ($path -notmatch '\.exe$' -or -not (Test-Path -LiteralPath $path)) { continue }
    $info = (Get-Item -LiteralPath $path).VersionInfo
    if ($info.FileDescription -like 'System activity monitor*' -or $info.OriginalFilename -like 'Sysmon*') {
      # The minifilter driver uses Sysmon's registered altitude, 385201.
      $driver = $null
      foreach ($line in (Invoke-Native { & fltmc.exe filters })) {
        if ($line -match '^\s*(\S+)\s+\d+\s+385201\b') { $driver = $Matches[1] }
      }
      return [pscustomobject]@{ ServiceName = $svc.Name; Exe = $path; Version = $info.FileVersion; Driver = $driver; State = $svc.State }
    }
  }
  return $null
}

function Resolve-SysmonBinary {
  $name = switch ($env:PROCESSOR_ARCHITECTURE) { 'ARM64' { 'Sysmon64a.exe' } 'x86' { 'Sysmon.exe' } default { 'Sysmon64.exe' } }
  $candidates = @()
  if ($SysmonExe) { $candidates += $SysmonExe }
  $candidates += (Join-Path $PSScriptRoot $name)
  foreach ($c in $candidates) { if (Test-Path -LiteralPath $c) { return (Resolve-Path -LiteralPath $c).Path } }
  if (-not $Download) { throw "Sysmon binary not found. Pass -SysmonExe <path to $name>, put $name next to this script, or use -Download." }

  $bin = Join-Path $StateDir 'bin'
  New-Item -ItemType Directory -Force -Path $bin | Out-Null
  $zip = Join-Path $bin 'Sysmon.zip'
  Write-Step 'Downloading Sysmon from Sysinternals'
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -UseBasicParsing -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip
  Expand-Archive -Path $zip -DestinationPath $bin -Force
  $exe = Join-Path $bin $name
  $sig = Get-AuthenticodeSignature -FilePath $exe
  if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
    throw "Downloaded $name does not carry a valid Microsoft signature ($($sig.Status))."
  }
  return $exe
}

# Event logs to keep bigger during the engagement: name -> minimum size in MB.
$LogTargets = [ordered]@{
  'Microsoft-Windows-Sysmon/Operational'                              = $SysmonLogSizeMB
  'Security'                                                          = 1024
  'System'                                                            = 256
  'Microsoft-Windows-PowerShell/Operational'                          = 512
  'Windows PowerShell'                                                = 256
  'Microsoft-Windows-TaskScheduler/Operational'                       = 128
  'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' = 128
  'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' = 128
  'Microsoft-Windows-Windows Defender/Operational'                    = 128
  'Microsoft-Windows-WMI-Activity/Operational'                        = 64
  'Microsoft-Windows-Bits-Client/Operational'                         = 64
}

# Audit subcategories by GUID, so the script works on any Windows display language.
$AuditSubcategories = [ordered]@{
  '{0CCE922B-69AE-11D9-BED3-505054503030}' = 'Process Creation (4688)'
  '{0CCE9215-69AE-11D9-BED3-505054503030}' = 'Logon (4624/4625)'
  '{0CCE9216-69AE-11D9-BED3-505054503030}' = 'Logoff (4634)'
  '{0CCE921B-69AE-11D9-BED3-505054503030}' = 'Special Logon (4672)'
  '{0CCE921C-69AE-11D9-BED3-505054503030}' = 'Other Logon/Logoff Events (4778/4779 RDP reconnects)'
  '{0CCE923F-69AE-11D9-BED3-505054503030}' = 'Credential Validation (4776)'
  '{0CCE9242-69AE-11D9-BED3-505054503030}' = 'Kerberos Authentication Service (4768)'
  '{0CCE9240-69AE-11D9-BED3-505054503030}' = 'Kerberos Service Ticket Operations (4769, Kerberoasting)'
  '{0CCE9235-69AE-11D9-BED3-505054503030}' = 'User Account Management (4720)'
  '{0CCE9237-69AE-11D9-BED3-505054503030}' = 'Security Group Management (4728/4732)'
  '{0CCE9211-69AE-11D9-BED3-505054503030}' = 'Security System Extension (4697 services)'
  '{0CCE9227-69AE-11D9-BED3-505054503030}' = 'Other Object Access Events (4698 scheduled tasks)'
  '{0CCE9224-69AE-11D9-BED3-505054503030}' = 'File Share (5140)'
  '{0CCE923B-69AE-11D9-BED3-505054503030}' = 'Directory Service Access (4662, DCSync on DCs)'
  '{0CCE922F-69AE-11D9-BED3-505054503030}' = 'Audit Policy Change (4719)'
  '{0CCE9210-69AE-11D9-BED3-505054503030}' = 'Security State Change'
}
if ($DetailedFileShare) { $AuditSubcategories['{0CCE9244-69AE-11D9-BED3-505054503030}'] = 'Detailed File Share (5145)' }

# Registry values set for logging: path, name, value.
$RegistrySettings = @(
  @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit', 'ProcessCreationIncludeCmdLine_Enabled', 1),
  @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 'EnableScriptBlockLogging', 1),
  # Make subcategory settings win over legacy category settings.
  @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'SCENoApplyLegacyAuditPolicy', 1)
)

# ---------------------------------------------------------------------------------------------

Assert-Admin
$ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
$backup = Join-Path $StateDir 'backup'
$statePath = Join-Path $StateDir 'state.json'
New-Item -ItemType Directory -Force -Path $backup | Out-Null

$firstRun = -not (Test-Path -LiteralPath $statePath)
if ($firstRun) {
  $os = Get-CimInstance Win32_OperatingSystem
  $state = [pscustomobject][ordered]@{
    deployedAt = (Get-Date).ToUniversalTime().ToString('o')
    host = $env:COMPUTERNAME
    os = "$($os.Caption) $($os.Version)"
    sysmon = $null
    configPath = $null
    configSha256 = $null
    archiveDirectory = $null
    logs = [pscustomobject]@{}
    audit = [pscustomobject]@{ backup = $null; registry = @() }
    collections = @()
  }
  Write-Step "First deployment on $($state.host) ($($state.os))"
} else {
  $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
  Write-Step "Already deployed on $($state.deployedAt); reapplying and keeping the original backups"
}

# --- Sysmon -----------------------------------------------------------------------------------
$existing = Get-SysmonInstall
if ($firstRun) {
  $native = $false
  try { $native = (Get-WindowsOptionalFeature -Online -FeatureName 'Sysmon' -ErrorAction Stop).State -eq 'Enabled' } catch { }
  if ($existing) {
    Write-Step "Sysmon $($existing.Version) already installed as service '$($existing.ServiceName)' (driver '$($existing.Driver)')$(if ($native) { ', built-in Windows feature' })"
    $evtx = Join-Path $backup 'sysmon-log-before.evtx'
    if (-not (Test-Path $evtx)) { Invoke-Native { & wevtutil.exe epl 'Microsoft-Windows-Sysmon/Operational' $evtx } | Out-Null }
    Invoke-Native { & $existing.Exe -c } | Out-File -Encoding utf8 (Join-Path $backup 'sysmon-config-before.txt')
    if ($existing.Driver) {
      Invoke-Native { & reg.exe export "HKLM\SYSTEM\CurrentControlSet\Services\$($existing.Driver)\Parameters" (Join-Path $backup 'sysmon-parameters-before.reg') /y } | Out-Null
    }
  }
  $state.sysmon = [pscustomobject][ordered]@{
    preExisting = [bool]$existing
    nativeFeature = $native
    serviceName = $(if ($existing) { $existing.ServiceName } else { $null })
    driver = $(if ($existing) { $existing.Driver } else { $null })
    exe = $(if ($existing) { $existing.Exe } else { $null })
    versionBefore = $(if ($existing) { $existing.Version } else { $null })
  }
}

if ($existing) {
  Write-Step "Applying $ConfigPath to the installed Sysmon"
  Invoke-Sysmon $existing.Exe @('-c', $ConfigPath) | Out-Null
} else {
  $exe = Resolve-SysmonBinary
  Write-Step "Installing Sysmon from $exe"
  Invoke-Sysmon $exe @('-accepteula', '-i', $ConfigPath) | Out-Null
  $existing = Get-SysmonInstall
  if (-not $existing) { throw 'Sysmon installed but its service was not found.' }
}
$state.sysmon.exe = $existing.Exe
$state.sysmon.serviceName = $existing.ServiceName
$state.sysmon.driver = $existing.Driver
$state.configSha256 = (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash
$state.configPath = $ConfigPath
$archiveNode = ([xml](Get-Content -LiteralPath $ConfigPath -Raw)).SelectSingleNode('/Sysmon/ArchiveDirectory')
$state.archiveDirectory = $(if ($archiveNode -and $archiveNode.InnerText) { $archiveNode.InnerText.Trim() } else { 'Sysmon' })

# --- Event log sizes -------------------------------------------------------------------------
if (-not $SkipLogSizes) {
  foreach ($name in $LogTargets.Keys) {
    $log = Get-WinEvent -ListLog $name -ErrorAction SilentlyContinue
    if (-not $log) { continue }
    $want = [int64]$LogTargets[$name] * 1MB
    # Remember the original size only once, so a re-run never records our own values as "before".
    if ($null -eq $state.logs.PSObject.Properties[$name]) {
      $state.logs | Add-Member -NotePropertyName $name -NotePropertyValue ([pscustomobject]@{ maxBytesBefore = $log.MaximumSizeInBytes; enabledBefore = $log.IsEnabled })
    }
    if ($log.MaximumSizeInBytes -lt $want) { Invoke-Native { & wevtutil.exe sl $name "/ms:$want" } | Out-Null }
    if (-not $log.IsEnabled) { Invoke-Native { & wevtutil.exe sl $name /e:true } | Out-Null }
  }
  Write-Step ("Event log sizes raised (Sysmon log: {0} MB)" -f $SysmonLogSizeMB)
}

# --- Audit policy and logging registry values ------------------------------------------------
if (-not $SkipAuditPolicy) {
  $auditBackup = Join-Path $backup 'auditpol-before.csv'
  if ($firstRun -or -not (Test-Path $auditBackup)) {
    Invoke-Native { & auditpol.exe /backup "/file:$auditBackup" } | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'auditpol /backup failed.' }
    $state.audit.backup = $auditBackup
    $saved = @()
    foreach ($s in $RegistrySettings) {
      $cur = Get-ItemProperty -LiteralPath $s[0] -Name $s[1] -ErrorAction SilentlyContinue
      $saved += [pscustomobject]@{ path = $s[0]; name = $s[1]; existed = [bool]$cur; value = $(if ($cur) { $cur.($s[1]) } else { $null }) }
    }
    $state.audit.registry = $saved
  }
  foreach ($guid in $AuditSubcategories.Keys) {
    Invoke-Native { & auditpol.exe /set "/subcategory:$guid" /success:enable /failure:enable } | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning "Could not enable audit subcategory $($AuditSubcategories[$guid])" }
  }
  foreach ($s in $RegistrySettings) {
    if (-not (Test-Path -LiteralPath $s[0])) { New-Item -Path $s[0] -Force | Out-Null }
    New-ItemProperty -LiteralPath $s[0] -Name $s[1] -Value $s[2] -PropertyType DWord -Force | Out-Null
  }
  Write-Step "Enabled $($AuditSubcategories.Count) audit subcategories, command lines in 4688 and PowerShell script block logging"
  Write-Step 'Note: a domain GPO that sets advanced audit policy can override these at the next refresh. Check with: auditpol /get /category:*'
}

# --- Verify -----------------------------------------------------------------------------------
$svc = Get-Service -Name $existing.ServiceName
if ($svc.Status -ne 'Running') { throw "Sysmon service '$($existing.ServiceName)' is $($svc.Status)." }
$marker = "SysmonIR-selftest-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
& cmd.exe /c "echo $marker" | Out-Null
$seen = $false
for ($i = 0; $i -lt 15 -and -not $seen; $i++) {
  Start-Sleep -Seconds 2
  $seen = [bool](Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1; StartTime = (Get-Date).AddMinutes(-2) } -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match $marker } | Select-Object -First 1)
}
if (-not $seen) { throw 'Sysmon is running but the self-test process was not logged. Check the config and the event log.' }
Write-Step 'Self-test passed: Sysmon is logging process creation'

$state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $statePath -Encoding UTF8
Write-Step "Done. State and backups: $StateDir"
Write-Step 'Next: forward or collect logs regularly (Collect-SysmonIR.ps1), and run Remove-SysmonIR.ps1 at the end of the engagement.'
