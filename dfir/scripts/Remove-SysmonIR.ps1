<#
.SYNOPSIS
  Ends the engagement on a host: restores the client's original Sysmon, logging and audit settings.

.DESCRIPTION
  Uses the state and backups written by Deploy-SysmonIR.ps1:
    - Sysmon that was already installed: its original config is restored from the registry backup.
      Sysmon we installed: uninstalled.
    - Event log sizes and the enabled state of logs are put back.
    - The audit policy and logging registry values are restored from backup.
    - The deleted-file archive is left in place unless -RemoveArchive is given.
  Refuses to run until Collect-SysmonIR.ps1 has produced at least one collection, unless -Force.
  Collections stored under the state folder are kept.

.EXAMPLE
  .\Remove-SysmonIR.ps1
.EXAMPLE
  .\Remove-SysmonIR.ps1 -RemoveArchive
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [string]$StateDir = (Join-Path $env:ProgramData 'SysmonIR'),
  [switch]$Force,
  [switch]$KeepAuditPolicy,
  [switch]$RemoveArchive
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
function Write-Step($msg) { Write-Host "[SysmonIR] $msg" }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this script from an elevated PowerShell (Administrator).'
}
$statePath = Join-Path $StateDir 'state.json'
if (-not (Test-Path -LiteralPath $statePath)) { throw "No deployment state found in $StateDir." }
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
if (-not @($state.collections | Where-Object { $_ }).Count -and -not $Force) {
  throw 'No collection has been made on this host. Run Collect-SysmonIR.ps1 first, or pass -Force to remove anyway.'
}
$backup = Join-Path $StateDir 'backup'

# --- Sysmon -----------------------------------------------------------------------------------
$exe = $state.sysmon.exe
if ($state.sysmon.preExisting) {
  $reg = Join-Path $backup 'sysmon-parameters-before.reg'
  if (Test-Path -LiteralPath $reg) {
    # Sysmon reloads its rules when the Parameters key changes.
    & reg.exe import $reg 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not restore the original Sysmon config from $reg." }
    Write-Step "Restored the client's original Sysmon config (service '$($state.sysmon.serviceName)')"
  } else {
    Write-Warning "Sysmon was already installed but no config backup exists; it is left running with the IR config. Reapply the client's own config manually."
  }
} elseif ($exe -and (Test-Path -LiteralPath $exe)) {
  if ($PSCmdlet.ShouldProcess($exe, 'Uninstall Sysmon')) {
    $out = & $exe -u force 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "Sysmon uninstall failed:`n$out" }
    Write-Step 'Uninstalled Sysmon'
  }
} else {
  Write-Warning "Sysmon binary $exe not found; it may already be uninstalled."
}

# --- Event logs -------------------------------------------------------------------------------
if ($state.logs) {
  foreach ($p in $state.logs.PSObject.Properties) {
    $log = Get-WinEvent -ListLog $p.Name -ErrorAction SilentlyContinue
    if (-not $log) { continue }
    # Windows applies a smaller size only after the log is next cleared; nothing is lost now.
    if ($log.MaximumSizeInBytes -ne $p.Value.maxBytesBefore) { & wevtutil.exe sl $p.Name "/ms:$($p.Value.maxBytesBefore)" | Out-Null }
    if ($log.IsEnabled -and -not $p.Value.enabledBefore) { & wevtutil.exe sl $p.Name /e:false | Out-Null }
  }
  Write-Step 'Event log sizes restored'
}

# --- Audit policy -----------------------------------------------------------------------------
if (-not $KeepAuditPolicy -and $state.audit -and $state.audit.backup) {
  if (Test-Path -LiteralPath $state.audit.backup) {
    & auditpol.exe /restore "/file:$($state.audit.backup)" | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning 'auditpol /restore failed; check the audit policy manually.' } else { Write-Step 'Audit policy restored' }
  }
  foreach ($r in @($state.audit.registry)) {
    if ($r.existed) {
      New-ItemProperty -LiteralPath $r.path -Name $r.name -Value $r.value -PropertyType DWord -Force | Out-Null
    } else {
      Remove-ItemProperty -LiteralPath $r.path -Name $r.name -ErrorAction SilentlyContinue
    }
  }
  Write-Step 'Logging registry values restored'
}

# --- Deleted-file archive ---------------------------------------------------------------------
$archiveName = $state.archiveDirectory
foreach ($drive in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3') {
  $dir = "$($drive.DeviceID)\$archiveName"
  if (-not $archiveName -or -not (Test-Path -LiteralPath $dir)) { continue }
  if ($RemoveArchive) {
    & takeown.exe /f $dir /r /d y 2>&1 | Out-Null
    & icacls.exe $dir /grant '*S-1-5-32-544:(OI)(CI)F' /t /c /q 2>&1 | Out-Null
    Remove-Item -LiteralPath $dir -Recurse -Force
    Write-Step "Removed $dir"
  } else {
    Write-Step "Left $dir in place (pass -RemoveArchive to delete it after it has been collected)"
  }
}

# --- State ------------------------------------------------------------------------------------
$collections = Join-Path $StateDir 'collections'
Get-ChildItem -LiteralPath $StateDir -Force | Where-Object { $_.FullName -ne $collections } | Remove-Item -Recurse -Force
if (Test-Path -LiteralPath $collections) {
  Write-Step "Kept collections in $collections. Move them to evidence storage, then delete the folder."
} else {
  Remove-Item -LiteralPath $StateDir -Force -Recurse
}
Write-Step 'Removal complete'
