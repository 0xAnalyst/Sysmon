// Toggleable detection modules. Each adds tagged include rules; turning a module off removes
// exactly the rules it added (tracked by item.module while you edit in the builder).

import { newCond, newRule } from './config.js';

const tn = (id, name) => `technique_id=${id},technique_name=${name}`;
const c = (field, condition, value, extra) => newCond(field, condition, value, extra);
const and = (name, ...conds) => { const r = newRule('and', name); r.conds = conds; return r; };

export const MODULES = [
  {
    id: 'c2-pipes', platform: 'windows', title: 'C2 & lateral movement named pipes',
    desc: 'Default pipe names of Cobalt Strike, Metasploit, PsExec-style tools and credential dumpers.',
    rules: [{ event: 'PipeEvent', items: () => {
      const n = tn('T1570', 'Lateral Tool Transfer');
      return [
        ['\\msagent_', 'Cobalt Strike SMB beacon default'], ['\\MSSE-', 'Cobalt Strike default'], ['\\postex_', 'Cobalt Strike post-exploitation'],
        ['\\status_', 'Cobalt Strike default'], ['\\mojo.5688.8052.', 'Cobalt Strike malleable default'],
        ['\\PSEXESVC', 'PsExec'], ['\\RemCom_communicaton', 'RemCom'], ['\\paexec', 'PAExec'], ['\\csexec', 'CSExec'],
        ['\\lsadump', 'Credential dumping tools'], ['\\cachedump', 'Credential dumping tools'], ['\\wceservicepipe', 'Windows Credential Editor'],
        ['\\isapi_http', 'Equation Group / DoublePulsar'], ['\\sdlrpc', 'Cobra/Turla'], ['\\ahexec', 'Turla'], ['\\winsession', 'Wild Neutron'],
      ].map(([v, note]) => c('PipeName', 'contains', v, { name: n, comment: note }));
    } }],
  },
  {
    id: 'lolbin-network', platform: 'windows', title: 'LOLBins making network connections',
    desc: 'Built-in Windows binaries that attackers use to download payloads or proxy execution.',
    rules: [{ event: 'NetworkConnect', items: () => {
      const n = tn('T1218', 'System Binary Proxy Execution');
      return ['certutil.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'msbuild.exe', 'installutil.exe', 'regasm.exe', 'regsvcs.exe',
        'cmstp.exe', 'msiexec.exe', 'odbcconf.exe', 'hh.exe', 'wscript.exe', 'cscript.exe', 'finger.exe', 'curl.exe', 'bitsadmin.exe',
        'powershell.exe', 'pwsh.exe', 'notepad.exe', 'calc.exe', 'esentutl.exe', 'expand.exe', 'mavinject.exe', 'presentationhost.exe']
        .map(img => c('Image', 'image', img, { name: n }));
    } }],
  },
  {
    id: 'lsass-access', platform: 'windows', title: 'LSASS credential dumping',
    desc: 'Process access to lsass.exe with dumping access masks, MiniDump via comsvcs.dll, and .dmp files of LSASS.',
    rules: [
      { event: 'ProcessAccess', items: () => [
        and(tn('T1003.001', 'LSASS Memory'),
          c('TargetImage', 'end with', '\\lsass.exe'),
          c('GrantedAccess', 'is any', '0x1010;0x1410;0x1438;0x143a;0x1fffff;0x1f1fff;0x1f2fff;0x1f3fff;0x40')),
      ] },
      { event: 'ProcessCreate', items: () => [
        and(tn('T1003.001', 'LSASS Memory'), c('CommandLine', 'contains all', 'comsvcs;MiniDump')),
        and(tn('T1003.001', 'LSASS Memory'), c('CommandLine', 'contains all', 'procdump;lsass')),
      ] },
      { event: 'FileCreate', items: () => [
        c('TargetFilename', 'contains', 'lsass', { name: tn('T1003.001', 'LSASS Memory'), comment: 'Dump files named after LSASS' }),
        c('TargetFilename', 'end with', '.dmp', { name: tn('T1003', 'OS Credential Dumping') }),
      ] },
    ],
  },
  {
    id: 'registry-persistence', platform: 'windows', title: 'Registry persistence',
    desc: 'Run keys, Winlogon, IFEO debuggers, SilentProcessExit, LSA packages, Netsh helpers, Office test DLL and COM hijacks.',
    rules: [{ event: 'RegistryEvent', items: () => [
      c('TargetObject', 'contains', '\\CurrentVersion\\Run', { name: tn('T1547.001', 'Registry Run Keys / Startup Folder') }),
      c('TargetObject', 'contains', '\\Policies\\Explorer\\Run', { name: tn('T1547.001', 'Registry Run Keys / Startup Folder') }),
      c('TargetObject', 'contains', '\\Windows NT\\CurrentVersion\\Winlogon\\', { name: tn('T1547.004', 'Winlogon Helper DLL') }),
      c('TargetObject', 'contains', '\\Image File Execution Options\\', { name: tn('T1546.012', 'Image File Execution Options Injection') }),
      c('TargetObject', 'contains', '\\SilentProcessExit\\', { name: tn('T1546.012', 'Image File Execution Options Injection') }),
      c('TargetObject', 'contains', '\\Control\\Lsa\\Security Packages', { name: tn('T1547.005', 'Security Support Provider') }),
      c('TargetObject', 'contains', '\\Control\\Lsa\\Notification Packages', { name: tn('T1556.002', 'Password Filter DLL') }),
      c('TargetObject', 'contains', '\\Control\\Session Manager\\BootExecute', { name: tn('T1547.001', 'Registry Run Keys / Startup Folder') }),
      c('TargetObject', 'contains', '\\Control\\Print\\Monitors\\', { name: tn('T1547.010', 'Port Monitors') }),
      c('TargetObject', 'contains', '\\Microsoft\\NetSh\\', { name: tn('T1546.007', 'Netsh Helper DLL') }),
      c('TargetObject', 'contains', '\\Software\\Microsoft\\Office test\\Special\\Perf', { name: tn('T1137.002', 'Office Test') }),
      c('TargetObject', 'contains', '\\Windows\\CurrentVersion\\Windows\\AppInit_DLLs', { name: tn('T1546.010', 'AppInit DLLs') }),
      and(tn('T1546.015', 'Component Object Model Hijacking'), c('TargetObject', 'begin with', 'HKU\\'), c('TargetObject', 'contains', '\\InprocServer32')),
      c('TargetObject', 'end with', '\\ImagePath', { name: tn('T1543.003', 'Windows Service') }),
      c('TargetObject', 'end with', '\\ServiceDll', { name: tn('T1543.003', 'Windows Service') }),
    ] }],
  },
  {
    id: 'defense-evasion', platform: 'windows', title: 'Log tampering, backups and Defender changes',
    desc: 'Clearing event logs, deleting shadow copies and backups, and weakening Microsoft Defender: typical ransomware prep.',
    rules: [{ event: 'ProcessCreate', items: () => [
      and(tn('T1070.001', 'Clear Windows Event Logs'), c('Image', 'image', 'wevtutil.exe'), c('CommandLine', 'contains any', ' cl ;clear-log')),
      and(tn('T1490', 'Inhibit System Recovery'), c('CommandLine', 'contains all', 'vssadmin;delete;shadows')),
      and(tn('T1490', 'Inhibit System Recovery'), c('CommandLine', 'contains all', 'shadowcopy;delete')),
      and(tn('T1490', 'Inhibit System Recovery'), c('CommandLine', 'contains all', 'bcdedit;recoveryenabled;no')),
      and(tn('T1490', 'Inhibit System Recovery'), c('CommandLine', 'contains all', 'wbadmin;delete;catalog')),
      and(tn('T1070', 'Indicator Removal'), c('CommandLine', 'contains all', 'fsutil;usn;deletejournal')),
      and(tn('T1562.001', 'Disable or Modify Tools'), c('CommandLine', 'contains any', 'DisableRealtimeMonitoring;Add-MpPreference;DisableBehaviorMonitoring;DisableIOAVProtection')),
      and(tn('T1562.004', 'Disable or Modify System Firewall'), c('CommandLine', 'contains all', 'netsh;advfirewall;state off')),
    ] }],
  },
  {
    id: 'startup-drops', platform: 'windows', title: 'Files dropped in autostart and staging locations',
    desc: 'Startup folders, scheduled task files, and scripts or executables written to user temp folders.',
    rules: [{ event: 'FileCreate', items: () => [
      c('TargetFilename', 'contains', '\\Start Menu\\Programs\\Startup\\', { name: tn('T1547.001', 'Registry Run Keys / Startup Folder') }),
      c('TargetFilename', 'begin with', 'C:\\Windows\\System32\\Tasks\\', { name: tn('T1053.005', 'Scheduled Task') }),
      c('TargetFilename', 'begin with', 'C:\\Windows\\System32\\GroupPolicy\\', { name: tn('T1484.001', 'Group Policy Modification') }),
      and(tn('T1105', 'Ingress Tool Transfer'), c('TargetFilename', 'contains', '\\AppData\\Local\\Temp\\'),
        c('TargetFilename', 'end with', '.exe')),
      ...['.hta', '.js', '.jse', '.vbs', '.vbe', '.wsf', '.scr', '.iso', '.img', '.vhd', '.lnk']
        .map(ext => and(tn('T1204.002', 'Malicious File'), c('TargetFilename', 'begin with', 'C:\\Users\\'), c('TargetFilename', 'end with', ext))),
    ] }],
  },
  {
    id: 'dns-abuse', platform: 'windows', title: 'Tunnels, paste sites and dynamic DNS',
    desc: 'DNS queries for services commonly used for C2, staging and exfiltration.',
    rules: [{ event: 'DnsQuery', items: () => {
      const n = tn('T1102', 'Web Service');
      return ['.ngrok.io', '.ngrok-free.app', '.trycloudflare.com', '.workers.dev', 'pastebin.com', 'paste.ee', 'transfer.sh',
        'api.telegram.org', 'cdn.discordapp.com', '.duckdns.org', '.no-ip.org', '.ddns.net', 'tmpfiles.org', 'file.io', '.onion']
        .map(d => c('QueryName', 'end with', d, { name: n }));
    } }],
  },
  {
    id: 'linux-persistence', platform: 'linux', title: 'Linux persistence files',
    desc: 'Cron, systemd units, SSH keys, shell profiles, sudoers and ld.so.preload.',
    rules: [{ event: 'FileCreate', items: () => [
      c('TargetFilename', 'begin with', '/etc/cron', { name: tn('T1053.003', 'Cron') }),
      c('TargetFilename', 'begin with', '/var/spool/cron', { name: tn('T1053.003', 'Cron') }),
      c('TargetFilename', 'begin with', '/etc/systemd/system/', { name: tn('T1543.002', 'Systemd Service') }),
      c('TargetFilename', 'begin with', '/usr/lib/systemd/system/', { name: tn('T1543.002', 'Systemd Service') }),
      c('TargetFilename', 'contains', '/.ssh/authorized_keys', { name: tn('T1098.004', 'SSH Authorized Keys') }),
      c('TargetFilename', 'begin with', '/etc/profile.d/', { name: tn('T1546.004', 'Unix Shell Configuration Modification') }),
      c('TargetFilename', 'end with', '/.bashrc', { name: tn('T1546.004', 'Unix Shell Configuration Modification') }),
      c('TargetFilename', 'is', '/etc/ld.so.preload', { name: tn('T1574.006', 'Dynamic Linker Hijacking') }),
      c('TargetFilename', 'begin with', '/etc/sudoers', { name: tn('T1548.003', 'Sudo and Sudo Caching') }),
      c('TargetFilename', 'is', '/etc/rc.local', { name: tn('T1037.004', 'RC Scripts') }),
      c('TargetFilename', 'begin with', '/etc/init.d/', { name: tn('T1037.004', 'RC Scripts') }),
    ] }],
  },
];

// Include rules would *narrow* an event that already logs everything (Log all, or only excludes).
export function includeWouldNarrow(ev) {
  const live = l => l.filter(i => i.enabled !== false).length;
  return ev.mode === 'all' || (ev.mode === 'filtered' && !live(ev.include) && live(ev.exclude) > 0);
}
