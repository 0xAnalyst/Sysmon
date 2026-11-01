<#
.SYNOPSIS
  Collects the evidence gathered during the engagement into one hashed zip.

.DESCRIPTION
  Exports the Sysmon log and the Windows logs an investigation needs, copies the files Sysmon kept
  when they were deleted (the archive folder at each volume root), adds the backups taken by
  Deploy-SysmonIR.ps1 (including any Sysmon log that existed before deployment), and writes a
  SHA256 manifest. The zip's own SHA256 is written next to it for chain of custody.

  Safe to run as often as needed while Sysmon keeps logging. Exported logs can be triaged with
  Hayabusa or Chainsaw; rule names carry ATT&CK technique IDs.

.PARAMETER OutputDir
  Where the collection folder and zip are written. Default: C:\ProgramData\SysmonIR\collections.

.PARAMETER NoArchive
  Skip the deleted-file archive (it can be large).

.EXAMPLE
  .\Collect-SysmonIR.ps1 -OutputDir \\evidence-server\case-1234\
#>
[CmdletBinding()]
param(
  [string]$OutputDir,
  [string]$StateDir = (Join-Path $env:ProgramData 'SysmonIR'),
  [switch]$NoArchive
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
function Write-Step($msg) { Write-Host "[SysmonIR] $msg" }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this script from an elevated PowerShell (Administrator).'
}

$statePath = Join-Path $StateDir 'state.json'
$state = $null
if (Test-Path -LiteralPath $statePath) { $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json }
else { Write-Warning "No deployment state in $StateDir; collecting logs anyway." }

if (-not $OutputDir) { $OutputDir = Join-Path $StateDir 'collections' }
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') + 'Z'
$name = "$($env:COMPUTERNAME)_SysmonIR_$stamp"
$dest = Join-Path $OutputDir $name
New-Item -ItemType Directory -Force -Path (Join-Path $dest 'logs') | Out-Null

# --- Event logs ------------------------------------------------------------------------------
$channels = @(
  'Microsoft-Windows-Sysmon/Operational', 'Security', 'System', 'Application',
  'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell',
  'Microsoft-Windows-TaskScheduler/Operational',
  'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
  'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
  'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational',
  'Microsoft-Windows-Windows Defender/Operational',
  'Microsoft-Windows-WMI-Activity/Operational',
  'Microsoft-Windows-Bits-Client/Operational',
  'Microsoft-Windows-SMBServer/Security',
  'Microsoft-Windows-WinRM/Operational'
)
$exported = 0
foreach ($ch in $channels) {
  if (-not (Get-WinEvent -ListLog $ch -ErrorAction SilentlyContinue)) { continue }
  $file = Join-Path $dest ('logs\' + ($ch -replace '[\\/]', '%4') + '.evtx')
  & wevtutil.exe epl $ch $file 2>$null
  if ($LASTEXITCODE -eq 0) { $exported++ } else { Write-Warning "Could not export $ch" }
}
Write-Step "Exported $exported event logs"

# --- Sysmon config and deployment backups ----------------------------------------------------
if ($state -and $state.sysmon -and $state.sysmon.exe -and (Test-Path -LiteralPath $state.sysmon.exe)) {
  & $state.sysmon.exe -c 2>&1 | Out-File -Encoding utf8 (Join-Path $dest 'sysmon-config-active.txt')
}
if ($state -and $state.configPath -and (Test-Path -LiteralPath $state.configPath)) {
  Copy-Item -LiteralPath $state.configPath -Destination (Join-Path $dest 'sysmon-config-deployed.xml')
}
$backup = Join-Path $StateDir 'backup'
if (Test-Path -LiteralPath $backup) {
  Copy-Item -LiteralPath $backup -Destination (Join-Path $dest 'deployment-backup') -Recurse
}
if (Test-Path -LiteralPath $statePath) { Copy-Item -LiteralPath $statePath -Destination (Join-Path $dest 'deployment-state.json') }

# --- Deleted files kept by Sysmon ------------------------------------------------------------
$archiveName = $(if ($state -and $state.archiveDirectory) { $state.archiveDirectory } else { 'SysmonIRArchive' })
$archived = 0
if (-not $NoArchive) {
  foreach ($drive in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3') {
    $src = "$($drive.DeviceID)\$archiveName"
    if (-not (Test-Path -LiteralPath $src)) { continue }
    $to = Join-Path $dest ("deleted-files\" + $drive.DeviceID.TrimEnd(':'))
    # The archive has a SYSTEM-only ACL; backup mode (/B) reads it with the administrator's backup privilege.
    & robocopy.exe $src $to /E /B /COPY:DT /R:1 /W:1 /NP /NFL /NDL /NJH /NJS | Out-Null
    if ($LASTEXITCODE -ge 8) { Write-Warning "robocopy could not copy $src (exit $LASTEXITCODE)" }
    $archived += @(Get-ChildItem -LiteralPath $to -Recurse -File -ErrorAction SilentlyContinue).Count
  }
  Write-Step "Copied $archived deleted file(s) kept by Sysmon"
}

# --- Host details ----------------------------------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
[pscustomobject][ordered]@{
  host = $env:COMPUTERNAME
  domain = (Get-CimInstance Win32_ComputerSystem).Domain
  os = "$($os.Caption) $($os.Version)"
  collectedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
  timeZone = (Get-TimeZone).Id
  lastBootUtc = $os.LastBootUpTime.ToUniversalTime().ToString('o')
  ipAddresses = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { $_.IPAddress } | Where-Object { $_ })
  collectedBy = $id.Name
} | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $dest 'host.json') -Encoding UTF8

# --- Manifest and zip ------------------------------------------------------------------------
Get-ChildItem -LiteralPath $dest -Recurse -File | ForEach-Object {
  [pscustomobject]@{ Path = $_.FullName.Substring($dest.Length + 1); Bytes = $_.Length; SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
} | Export-Csv -LiteralPath (Join-Path $dest 'manifest-sha256.csv') -NoTypeInformation -Encoding UTF8

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = "$dest.zip"
[IO.Compression.ZipFile]::CreateFromDirectory($dest, $zip, [IO.Compression.CompressionLevel]::Optimal, $false)
$zipHash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
"$zipHash  $(Split-Path $zip -Leaf)" | Set-Content -LiteralPath "$zip.sha256" -Encoding ASCII
Remove-Item -LiteralPath $dest -Recurse -Force

if ($state) {
  $entry = [pscustomobject]@{ atUtc = (Get-Date).ToUniversalTime().ToString('o'); zip = $zip; sha256 = $zipHash }
  $state.collections = @(@($state.collections | Where-Object { $_ }) + $entry)
  $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $statePath -Encoding UTF8
}
Write-Step "Collection: $zip"
Write-Step "SHA256: $zipHash"
