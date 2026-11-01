// Deployment script generators. Every script is idempotent: it installs Sysmon when missing,
// reinstalls when the binary changed, and reapplies the config only when its content changed.

export const TARGETS = [
  { id: 'gpo-bat', platform: 'windows', label: 'GPO startup script (batch)', file: 'startupscript.bat',
    help: 'Computer startup script reading Sysmon64.exe and the config from a share. Domain computers need read access to the share.' },
  { id: 'gpo-ps1', platform: 'windows', label: 'GPO / scheduled task (PowerShell)', file: 'Deploy-Sysmon.ps1',
    help: 'Same logic as the batch script in PowerShell, with logging to the Application event log.' },
  { id: 'intune-detect', platform: 'windows', label: 'Intune remediation: detection', file: 'Detect-Sysmon.ps1',
    help: 'Exits 1 when Sysmon is missing or the deployed config differs from this one. Pair with the remediation script.' },
  { id: 'intune-remediate', platform: 'windows', label: 'Intune remediation: remediation', file: 'Remediate-Sysmon.ps1',
    help: 'Downloads Sysmon from Microsoft if needed and applies the embedded config. No file share required.' },
  { id: 'linux-sh', platform: 'linux', label: 'Linux shell script', file: 'deploy-sysmon.sh',
    help: 'Installs sysmonforlinux from packages.microsoft.com and applies the embedded config. Run as root.' },
  { id: 'ansible', platform: 'linux', label: 'Ansible playbook', file: 'sysmon.yml',
    help: 'Installs Sysmon for Linux and applies sysmonconfig-linux.xml (place it next to the playbook).' },
];

const psStr = s => `'${String(s).replace(/'/g, "''")}'`;

function b64utf8(text) {
  const bytes = new TextEncoder().encode(text);
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
function wrap(s, n = 100) {
  return s.match(new RegExp(`.{1,${n}}`, 'g')).join('\n');
}

export function generate(target, { xml, hash, share = '\\\\UNCPATH\\Sysmon', exe = 'Sysmon64.exe', configName = 'sysmonconfig.xml' }) {
  const svc = exe.replace(/\.exe$/i, '');
  switch (target) {
    case 'gpo-bat': return `@echo off
setlocal EnableExtensions
REM Sysmon deployment: GPO computer startup script.
REM Installs Sysmon when missing, reinstalls when the binary on the share changes, and
REM reapplies the config whenever the copy on the share changes (compared by SHA256).

set "SHARE=${share}"
set "EXE=${exe}"
set "CFG=${configName}"
set "DEST=%SystemRoot%"

if not exist "%SHARE%\\%EXE%" exit /b 1
if not exist "%SHARE%\\%CFG%" exit /b 1

call :hash "%SHARE%\\%EXE%" NEW_EXE
call :hash "%DEST%\\%EXE%" OLD_EXE
call :hash "%SHARE%\\%CFG%" NEW_CFG
call :hash "%DEST%\\%CFG%" OLD_CFG

sc query "${svc}" >nul 2>&1
if errorlevel 1 goto install

if /i not "%NEW_EXE%"=="%OLD_EXE%" (
  "%DEST%\\%EXE%" -u force
  goto install
)

if /i not "%NEW_CFG%"=="%OLD_CFG%" (
  REM Apply from the share first, keep the local copy only if Sysmon accepted it.
  "%DEST%\\%EXE%" -c "%SHARE%\\%CFG%" && copy /y "%SHARE%\\%CFG%" "%DEST%\\%CFG%" >nul
)
exit /b 0

:install
copy /y "%SHARE%\\%EXE%" "%DEST%\\%EXE%" >nul
copy /y "%SHARE%\\%CFG%" "%DEST%\\%CFG%" >nul
"%DEST%\\%EXE%" -accepteula -i "%DEST%\\%CFG%"
exit /b %errorlevel%

:hash
set "%~2="
if not exist "%~1" exit /b 0
for /f "delims=" %%H in ('certutil -hashfile "%~1" SHA256 ^| findstr /v /c:":"') do set "%~2=%%H"
exit /b 0
`.replace(/\n/g, '\r\n');

    case 'gpo-ps1': return `#Requires -RunAsAdministrator
<#
  Sysmon deployment from a file share. Installs when missing, reinstalls when the binary
  changes, reapplies the config when it changes. Safe to run on every boot.
#>
param(
  [string]$Share = ${psStr(share)},
  [string]$Exe = ${psStr(exe)},
  [string]$Config = ${psStr(configName)}
)
$ErrorActionPreference = 'Stop'
$dest = $env:SystemRoot
$srcExe = Join-Path $Share $Exe;  $dstExe = Join-Path $dest $Exe
$srcCfg = Join-Path $Share $Config; $dstCfg = Join-Path $dest $Config
$source = 'SysmonDeploy'
if (-not [Diagnostics.EventLog]::SourceExists($source)) { New-EventLog -LogName Application -Source $source }
function Log($msg, $type = 'Information') { Write-EventLog -LogName Application -Source $source -EventId 1 -EntryType $type -Message $msg }
function Hash($p) { if (Test-Path $p) { (Get-FileHash $p -Algorithm SHA256).Hash } }

function Install-Sysmon {
  Copy-Item $srcExe $dstExe -Force
  Copy-Item $srcCfg $dstCfg -Force
  & $dstExe -accepteula -i $dstCfg | Out-Null
  if ($LASTEXITCODE) { Log "Sysmon install failed ($LASTEXITCODE)" 'Error'; exit $LASTEXITCODE }
  Log "Sysmon installed with config hash $(Hash $dstCfg)"
}

if (-not (Get-Service -Name ${psStr(svc)} -ErrorAction SilentlyContinue)) { Install-Sysmon; exit 0 }

if ((Hash $srcExe) -ne (Hash $dstExe)) {
  & $dstExe -u force | Out-Null
  Install-Sysmon
  exit 0
}

if ((Hash $srcCfg) -ne (Hash $dstCfg)) {
  & $dstExe -c $srcCfg | Out-Null
  if ($LASTEXITCODE) { Log "Sysmon rejected $srcCfg ($LASTEXITCODE); keeping the current config" 'Error'; exit $LASTEXITCODE }
  Copy-Item $srcCfg $dstCfg -Force
  Log "Sysmon config updated to hash $(Hash $dstCfg)"
}
`;

    case 'intune-detect': return `<#
  Intune remediation detection. Exit 0 = compliant, exit 1 = run remediation.
  Expected config SHA256: ${hash}
#>
$expected = ${psStr(hash)}
$cfg = Join-Path $env:SystemRoot ${psStr(configName)}
if (-not (Get-Service -Name ${psStr(svc)} -ErrorAction SilentlyContinue)) { Write-Output 'Sysmon not installed'; exit 1 }
if (-not (Test-Path $cfg)) { Write-Output 'Config missing'; exit 1 }
if ((Get-FileHash $cfg -Algorithm SHA256).Hash -ne $expected) { Write-Output 'Config outdated'; exit 1 }
Write-Output 'Sysmon config current'
exit 0
`;

    case 'intune-remediate': return `<#
  Intune remediation. Installs Sysmon from download.sysinternals.com when missing and
  applies the embedded config (SHA256 ${hash}).
#>
$ErrorActionPreference = 'Stop'
$cfgPath = Join-Path $env:SystemRoot ${psStr(configName)}
$exePath = Join-Path $env:SystemRoot ${psStr(exe)}
$config = @'
${wrap(b64utf8(xml))}
'@
$tmp = Join-Path $env:TEMP 'sysmonconfig.new.xml'
[IO.File]::WriteAllBytes($tmp, [Convert]::FromBase64String(($config -replace '\\s', '')))

if (-not (Get-Service -Name ${psStr(svc)} -ErrorAction SilentlyContinue)) {
  $zip = Join-Path $env:TEMP 'Sysmon.zip'
  Invoke-WebRequest -UseBasicParsing 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip
  Expand-Archive $zip -DestinationPath (Join-Path $env:TEMP 'Sysmon') -Force
  $downloaded = Join-Path $env:TEMP ('Sysmon\\' + ${psStr(exe)})
  $sig = Get-AuthenticodeSignature $downloaded
  if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft') { throw "Unexpected signature on $downloaded" }
  Copy-Item $downloaded $exePath -Force
  & $exePath -accepteula -i $tmp
} else {
  & $exePath -c $tmp
}
if ($LASTEXITCODE) { throw "Sysmon returned $LASTEXITCODE" }
Move-Item $tmp $cfgPath -Force
Write-Output 'Sysmon config applied'
`;

    case 'linux-sh': return `#!/usr/bin/env bash
# Installs Sysmon for Linux (packages.microsoft.com) and applies the config below when it changed.
# Config SHA256: ${hash}
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run as root" >&2; exit 1; }

CONFIG=/opt/sysmon/sysmonconfig.xml
NEW=$(mktemp)
trap 'rm -f "$NEW"' EXIT
cat > "$NEW" <<'SYSMON_CONFIG_EOF'
${xml.trimEnd()}
SYSMON_CONFIG_EOF

if ! command -v sysmon >/dev/null 2>&1; then
  . /etc/os-release
  case "$ID" in
    ubuntu|debian)
      curl -fsSL "https://packages.microsoft.com/config/$ID/$VERSION_ID/packages-microsoft-prod.deb" -o /tmp/packages-microsoft-prod.deb
      dpkg -i /tmp/packages-microsoft-prod.deb
      apt-get update -q && apt-get install -y sysmonforlinux ;;
    rhel|centos|rocky|almalinux|ol)
      rpm --import https://packages.microsoft.com/keys/microsoft.asc
      rpm -Uvh "https://packages.microsoft.com/config/rhel/\${VERSION_ID%%.*}/packages-microsoft-prod.rpm" || true
      (dnf install -y sysmonforlinux || yum install -y sysmonforlinux) ;;
    *) echo "Unsupported distribution $ID: install sysmonforlinux manually" >&2; exit 1 ;;
  esac
fi

mkdir -p /opt/sysmon
if [ -f "$CONFIG" ] && cmp -s "$NEW" "$CONFIG" && systemctl is-active --quiet sysmon; then
  echo "Sysmon config is current"; exit 0
fi
if systemctl is-active --quiet sysmon; then
  sysmon -c "$NEW"
else
  sysmon -accepteula -i "$NEW"
fi
install -m 600 "$NEW" "$CONFIG"
echo "Sysmon config applied"
`;

    case 'ansible': return `# Deploys Sysmon for Linux. Put sysmonconfig-linux.xml next to this playbook.
# Config SHA256: ${hash}
- name: Deploy Sysmon for Linux
  hosts: all
  become: true
  vars:
    sysmon_config_src: sysmonconfig-linux.xml
    sysmon_config_path: /opt/sysmon/sysmonconfig.xml
  tasks:
    - name: Add Microsoft package repository (Debian/Ubuntu)
      ansible.builtin.apt:
        deb: "https://packages.microsoft.com/config/{{ ansible_distribution | lower }}/{{ ansible_distribution_version }}/packages-microsoft-prod.deb"
      when: ansible_os_family == "Debian"

    - name: Import Microsoft signing key (RHEL family)
      ansible.builtin.rpm_key:
        key: https://packages.microsoft.com/keys/microsoft.asc
      when: ansible_os_family == "RedHat"

    - name: Add Microsoft package repository (RHEL family)
      ansible.builtin.dnf:
        name: "https://packages.microsoft.com/config/rhel/{{ ansible_distribution_major_version }}/packages-microsoft-prod.rpm"
      when: ansible_os_family == "RedHat"

    - name: Install Sysmon for Linux (Debian/Ubuntu)
      ansible.builtin.apt:
        name: sysmonforlinux
        update_cache: true
      when: ansible_os_family == "Debian"

    - name: Install Sysmon for Linux (RHEL family)
      ansible.builtin.dnf:
        name: sysmonforlinux
      when: ansible_os_family == "RedHat"

    - name: Copy Sysmon config
      ansible.builtin.copy:
        src: "{{ sysmon_config_src }}"
        dest: "{{ sysmon_config_path }}"
        mode: "0600"
      register: sysmon_config

    - name: Check Sysmon service
      ansible.builtin.command: systemctl is-active sysmon
      register: sysmon_service
      changed_when: false
      failed_when: false

    - name: Install Sysmon with the config
      ansible.builtin.command: sysmon -accepteula -i {{ sysmon_config_path }}
      when: sysmon_service.rc != 0

    - name: Apply the updated config
      ansible.builtin.command: sysmon -c {{ sysmon_config_path }}
      when: sysmon_service.rc == 0 and sysmon_config.changed
`;
  }
  return '';
}
