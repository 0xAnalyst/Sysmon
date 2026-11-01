<#
.SYNOPSIS
  Lab check for a host where Deploy-SysmonIR.ps1 has run: performs harmless actions that mirror
  common intrusion steps and confirms Sysmon logged each one.

.DESCRIPTION
  Actions: run a copied binary from C:\PerfLogs, write a script to ProgramData, delete the copied
  binary (Sysmon should keep a copy), look up and fetch a web address, add and remove a Run key,
  create a named pipe, and open a handle to LSASS (no memory is read). Nothing is left behind.
  Run it in a lab or on a test host before an engagement, not on evidence hosts.
  Exits 1 if any expected event is missing.
#>
[CmdletBinding()]
param([int]$WaitSeconds = 15)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$tag = 'sysmonir' + [guid]::NewGuid().ToString('N').Substring(0, 6)
$start = (Get-Date).AddSeconds(-5)
$results = New-Object System.Collections.Generic.List[object]

# Marker-named copies so events can be matched exactly.
$exe = "C:\PerfLogs\$tag.exe"
$ps1 = "C:\ProgramData\$tag.ps1"
New-Item -ItemType Directory -Force -Path 'C:\PerfLogs' | Out-Null
Copy-Item "$env:SystemRoot\System32\whoami.exe" $exe
& $exe | Out-Null
Set-Content -LiteralPath $ps1 -Value "# $tag"
Remove-Item -LiteralPath $ps1
Start-Sleep -Seconds 1
Remove-Item -LiteralPath $exe

Resolve-DnsName -Name 'example.com' -Type A -ErrorAction SilentlyContinue | Out-Null
try { Invoke-WebRequest -UseBasicParsing -Uri 'https://example.com' -TimeoutSec 15 | Out-Null } catch { Write-Warning "Web request failed: $_" }

$run = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$createdRun = -not (Test-Path $run)   # fresh profiles may not have the key yet
if ($createdRun) { New-Item -Path $run -Force | Out-Null }
New-ItemProperty -Path $run -Name $tag -Value 'C:\Windows\System32\calc.exe' -PropertyType String -Force | Out-Null
Remove-ItemProperty -Path $run -Name $tag
if ($createdRun) { Remove-Item -Path $run }

$pipe = New-Object System.IO.Pipes.NamedPipeServerStream($tag)
$pipe.Dispose()

$lsassOpened = $false
try {
  Add-Type -Namespace SysmonIR -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)] public static extern System.IntPtr OpenProcess(uint access, bool inherit, int pid);
[DllImport("kernel32.dll")] public static extern bool CloseHandle(System.IntPtr h);
'@
  # PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ: the rights a dumper asks for. No memory is read.
  $h = [SysmonIR.Native]::OpenProcess(0x1010, $false, (Get-Process lsass).Id)
  if ($h -ne [IntPtr]::Zero) { $lsassOpened = $true; [SysmonIR.Native]::CloseHandle($h) | Out-Null }
} catch { }

Start-Sleep -Seconds $WaitSeconds
$events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; StartTime = $start } -ErrorAction SilentlyContinue)

# A delete matched by both FileDelete (23) and FileDeleteDetected (26) rules is logged as one of them.
function Check([int[]]$ids, $what, $pattern, [switch]$Optional) {
  $hit = $events | Where-Object { $ids -contains $_.Id -and $_.Message -match $pattern } | Select-Object -First 1
  $results.Add([pscustomobject]@{ Event = ($ids -join '/'); Check = $what; Logged = [bool]$hit; Optional = [bool]$Optional })
}
$t = [regex]::Escape($tag)
Check 1  'Process started from C:\PerfLogs'             "Image: C:\\PerfLogs\\$t\.exe"
Check 29 'New executable written to C:\PerfLogs'        "TargetFilename: C:\\PerfLogs\\$t\.exe"
Check 11 'Script written to ProgramData'                "TargetFilename: C:\\ProgramData\\$t\.ps1"
Check 23,26 'Deleted executable logged'                "TargetFilename: C:\\PerfLogs\\$t\.exe"
Check 23,26 'Deleted script logged'                    "TargetFilename: C:\\ProgramData\\$t\.ps1"
Check 22 'DNS query'                                    'QueryName: example\.com'
Check 3  'Network connection from PowerShell'           'Image: .*\\powershell\.exe'
Check 13 'Run key set'                                  "TargetObject: .*\\CurrentVersion\\Run\\$t"
Check 17 'Named pipe created'                           "PipeName: \\$t"
Check 10 'Handle to LSASS with memory-read rights'      'TargetImage: .*\\lsass\.exe' -Optional:(-not $lsassOpened)

$results | Format-Table -AutoSize | Out-String -Width 160 | Write-Host
$missing = @($results | Where-Object { -not $_.Logged -and -not $_.Optional })
if ($missing.Count) {
  Write-Host "Missing: $(($missing | ForEach-Object { "event $($_.Event) ($($_.Check))" }) -join '; ')"
  exit 1
}
Write-Host "All required events logged ($($results.Count) checks)."
