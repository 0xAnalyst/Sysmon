// Presets, starter rules for newer events, and common exclusion targets.

import { newCond } from './config.js';

export const PRESETS = [
  // `files` are tried in order: the deployed site copies the configs into presets/,
  // and a local server started at the repo root finds them one level up.
  { id: 'windows', label: '0xAnalyst Windows (MITRE / JPCERT)', files: ['presets/windows.xml', '../sysmonv9.xml'],
    note: 'Windows config from github.com/0xAnalyst/Sysmon, upgraded to the latest schema.' },
  { id: 'windows-ir', label: '0xAnalyst Windows DFIR (incident response)', files: ['presets/windows-ir.xml', '../dfir/windows-ir.xml'],
    note: 'Incident-response config from github.com/0xAnalyst/Sysmon (dfir/). Logs far more than the production config; add client exclusions as an overlay.' },
  { id: 'linux', label: '0xAnalyst Linux (MSTIC + Sigma + GTFOBins)', files: ['presets/linux.xml', '../SysmonForLinux/config.xml'],
    note: 'Sysmon for Linux config from github.com/0xAnalyst/Sysmon.' },
  { id: 'blank-windows', label: 'Blank Windows config', platform: 'windows' },
  { id: 'blank-linux', label: 'Blank Linux config', platform: 'linux' },
];

// One-click starting points for events added after the original configs were written.
export const STARTERS = {
  DnsQuery: {
    mode: 'filtered',
    desc: 'Log all DNS queries except common high-volume Microsoft and local lookups.',
    exclude: () => [
      newCond('QueryName', 'end with', '.arpa.', { comment: 'Reverse lookups' }),
      newCond('QueryName', 'end with', '.arpa', { comment: 'Reverse lookups' }),
      newCond('QueryName', 'end with', '.msftncsi.com', { comment: 'Network connectivity checks' }),
      newCond('QueryName', 'is', 'localhost'),
      newCond('QueryName', 'end with', '.windowsupdate.com', { comment: 'Windows Update' }),
      newCond('QueryName', 'end with', '.delivery.mp.microsoft.com', { comment: 'Windows Update delivery' }),
      newCond('Image', 'is', 'C:\\Windows\\System32\\svchost.exe', { name: '', comment: 'Optional: very noisy, remove if you need svchost DNS' }),
    ],
  },
  ProcessTampering: {
    mode: 'all',
    desc: 'Log all process tampering (hollowing / herpaderping). Low volume, high value.',
  },
  FileExecutableDetected: {
    mode: 'filtered',
    desc: 'Log new executables written to user-writable locations.',
    include: () => [
      newCond('TargetFilename', 'begin with', 'C:\\Users\\', { name: 'technique_id=T1105,technique_name=Ingress Tool Transfer' }),
      newCond('TargetFilename', 'begin with', 'C:\\ProgramData\\'),
      newCond('TargetFilename', 'begin with', 'C:\\Windows\\Temp\\'),
      newCond('TargetFilename', 'begin with', 'C:\\PerfLogs\\'),
    ],
  },
  FileDeleteDetected: {
    mode: 'filtered',
    desc: 'Log deletion of executables and scripts (indicator removal), without archiving.',
    include: () => [
      newCond('TargetFilename', 'end with', '.exe', { name: 'technique_id=T1070.004,technique_name=File Deletion' }),
      newCond('TargetFilename', 'end with', '.dll'),
      newCond('TargetFilename', 'end with', '.ps1'),
      newCond('TargetFilename', 'end with', '.bat'),
      newCond('TargetFilename', 'end with', '.vbs'),
      newCond('TargetFilename', 'end with', '.hta'),
    ],
  },
  FileDelete: { mode: 'off', desc: 'Keep archiving off (disk usage). Use FileDeleteDetected instead.' },
  ClipboardChange: { mode: 'off', desc: 'Off by default: clipboard capture can collect sensitive data.' },
  FileBlockExecutable: { mode: 'off', desc: 'Off by default: include rules block file creation.' },
  FileBlockShredding: { mode: 'off', desc: 'Off by default: include rules block shredding tools.' },
};

// Security products that commonly need excluding. Paths are default install folders.
export const PRODUCTS = [
  { label: 'Microsoft Defender', paths: ['C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\', 'C:\\Program Files\\Windows Defender\\'] },
  { label: 'Defender for Endpoint (Sense)', paths: ['C:\\Program Files\\Windows Defender Advanced Threat Protection\\'] },
  { label: 'CrowdStrike Falcon', paths: ['C:\\Program Files\\CrowdStrike\\'] },
  { label: 'SentinelOne', paths: ['C:\\Program Files\\SentinelOne\\'] },
  { label: 'Sophos', paths: ['C:\\Program Files\\Sophos\\', 'C:\\Program Files (x86)\\Sophos\\'] },
  { label: 'Trellix / McAfee', paths: ['C:\\Program Files\\McAfee\\', 'C:\\Program Files\\Common Files\\McAfee\\'] },
  { label: 'Trend Micro', paths: ['C:\\Program Files\\Trend Micro\\', 'C:\\Program Files (x86)\\Trend Micro\\'] },
  { label: 'Splunk Universal Forwarder', paths: ['C:\\Program Files\\SplunkUniversalForwarder\\bin\\'] },
  { label: 'Elastic Agent', paths: ['C:\\Program Files\\Elastic\\'] },
  { label: 'Wazuh agent', paths: ['C:\\Program Files (x86)\\ossec-agent\\'] },
  { label: 'Velociraptor', paths: ['C:\\Program Files\\Velociraptor\\'] },
];
