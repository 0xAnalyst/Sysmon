// Sysmon configuration schema knowledge.
// Source: Sysinternals Sysmon docs (v15.x, schema 4.90) and `sysmon -s` output.

export const LATEST = {
  windows: { sysmon: '15.x', schema: '4.90' },
  linux: { sysmon: '1.x (Linux)', schema: '4.81' },
};

// Schema versions a user can target, oldest first. `events` lists the event IDs
// that became filterable in that release.
export const SCHEMA_VERSIONS = [
  { schema: '4.00', sysmon: '8.0', events: [1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21] },
  { schema: '4.21', sysmon: '10.0', events: [22] },
  { schema: '4.22', sysmon: '10.4', events: [] },
  { schema: '4.30', sysmon: '11.0', events: [23] },
  { schema: '4.40', sysmon: '12.0', events: [24] },
  { schema: '4.50', sysmon: '13.0', events: [25] },
  { schema: '4.60', sysmon: '13.10', events: [26] },
  { schema: '4.81', sysmon: '13.30', events: [] },
  { schema: '4.82', sysmon: '14.0', events: [27] },
  { schema: '4.83', sysmon: '14.1', events: [28] },
  { schema: '4.90', sysmon: '15.0+', events: [29] },
];

export function minSchemaForEvent(id) {
  for (const v of SCHEMA_VERSIONS) if (v.events.includes(id)) return v.schema;
  return '4.00';
}

export const CONDITIONS = [
  { name: 'is', help: 'Exact match (default)' },
  { name: 'is not', help: 'Value is different' },
  { name: 'is any', help: 'Equals one of the ;-separated values', multi: true },
  { name: 'contains', help: 'Field contains the value' },
  { name: 'contains any', help: 'Contains any of the ;-separated values', multi: true },
  { name: 'contains all', help: 'Contains all of the ;-separated values', multi: true },
  { name: 'excludes', help: 'Field does not contain the value' },
  { name: 'excludes any', help: 'Does not contain one or more of the ;-separated values', multi: true },
  { name: 'excludes all', help: 'Contains none of the ;-separated values', multi: true },
  { name: 'begin with', help: 'Field begins with the value' },
  { name: 'not begin with', help: 'Field does not begin with the value' },
  { name: 'end with', help: 'Field ends with the value' },
  { name: 'not end with', help: 'Field does not end with the value' },
  { name: 'less than', help: 'Lexicographically less than' },
  { name: 'more than', help: 'Lexicographically more than' },
  { name: 'image', help: 'Image path or bare image name (lsass.exe matches C:\\Windows\\System32\\lsass.exe)' },
];
export const CONDITION_NAMES = CONDITIONS.map(c => c.name);

const P = ['RuleName', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'User'];

// Filterable events. `ids` are the event IDs the tag covers.
export const EVENTS = [
  { tag: 'ProcessCreate', ids: [1], title: 'Process creation', platforms: ['windows', 'linux'],
    fields: ['RuleName', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'FileVersion', 'Description', 'Product', 'Company', 'OriginalFileName', 'CommandLine', 'CurrentDirectory', 'User', 'LogonGuid', 'LogonId', 'TerminalSessionId', 'IntegrityLevel', 'Hashes', 'ParentProcessGuid', 'ParentProcessId', 'ParentImage', 'ParentCommandLine', 'ParentUser'],
    help: 'Every new process with full command line and parent. The backbone of most detections.' },
  { tag: 'FileCreateTime', ids: [2], title: 'File creation time changed', platforms: ['windows'],
    fields: [...P, 'TargetFilename', 'CreationUtcTime', 'PreviousCreationUtcTime'],
    help: 'A process changed a file creation timestamp (timestomping).' },
  { tag: 'NetworkConnect', ids: [3], title: 'Network connection', platforms: ['windows', 'linux'],
    fields: [...P, 'Protocol', 'Initiated', 'SourceIsIpv6', 'SourceIp', 'SourceHostname', 'SourcePort', 'SourcePortName', 'DestinationIsIpv6', 'DestinationIp', 'DestinationHostname', 'DestinationPort', 'DestinationPortName'],
    help: 'TCP/UDP connections. Very noisy if logged without filters.' },
  { tag: 'ProcessTerminate', ids: [5], title: 'Process terminated', platforms: ['windows', 'linux'],
    fields: P, help: 'Process exit.' },
  { tag: 'DriverLoad', ids: [6], title: 'Driver loaded', platforms: ['windows'],
    fields: ['RuleName', 'UtcTime', 'ImageLoaded', 'Hashes', 'Signed', 'Signature', 'SignatureStatus'],
    help: 'Kernel driver loads with signature info.' },
  { tag: 'ImageLoad', ids: [7], title: 'Image (DLL) loaded', platforms: ['windows'],
    fields: ['RuleName', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'ImageLoaded', 'FileVersion', 'Description', 'Product', 'Company', 'OriginalFileName', 'Hashes', 'Signed', 'Signature', 'SignatureStatus', 'User'],
    help: 'Module loads. Extremely high volume; always filter.' },
  { tag: 'CreateRemoteThread', ids: [8], title: 'CreateRemoteThread', platforms: ['windows'],
    fields: ['RuleName', 'UtcTime', 'SourceProcessGuid', 'SourceProcessId', 'SourceImage', 'TargetProcessGuid', 'TargetProcessId', 'TargetImage', 'NewThreadId', 'StartAddress', 'StartModule', 'StartFunction', 'SourceUser', 'TargetUser'],
    help: 'A process created a thread in another process (injection).' },
  { tag: 'RawAccessRead', ids: [9], title: 'Raw disk access read', platforms: ['windows', 'linux'],
    fields: [...P, 'Device'], help: 'Reads from a drive via \\\\.\\ (bypassing file locks).' },
  { tag: 'ProcessAccess', ids: [10], title: 'Process accessed', platforms: ['windows'],
    fields: ['RuleName', 'UtcTime', 'SourceProcessGUID', 'SourceProcessId', 'SourceThreadId', 'SourceImage', 'TargetProcessGUID', 'TargetProcessId', 'TargetImage', 'GrantedAccess', 'CallTrace', 'SourceUser', 'TargetUser'],
    help: 'OpenProcess calls, e.g. LSASS credential dumping.' },
  { tag: 'FileCreate', ids: [11], title: 'File created', platforms: ['windows', 'linux'],
    fields: [...P, 'TargetFilename', 'CreationUtcTime'], help: 'File created or overwritten.' },
  { tag: 'RegistryEvent', ids: [12, 13, 14], title: 'Registry events', platforms: ['windows'],
    fields: ['RuleName', 'EventType', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'TargetObject', 'Details', 'NewName', 'User'],
    help: 'Key/value create, delete, set and rename.' },
  { tag: 'FileCreateStreamHash', ids: [15], title: 'File stream created', platforms: ['windows'],
    fields: [...P, 'TargetFilename', 'CreationUtcTime', 'Hash', 'Contents'], help: 'Alternate data streams such as Zone.Identifier (mark of the web).' },
  { tag: 'PipeEvent', ids: [17, 18], title: 'Named pipe created / connected', platforms: ['windows'],
    fields: ['RuleName', 'EventType', 'UtcTime', 'ProcessGuid', 'ProcessId', 'PipeName', 'Image', 'User'],
    help: 'Named pipes, used by many C2 frameworks for lateral movement.' },
  { tag: 'WmiEvent', ids: [19, 20, 21], title: 'WMI event filter / consumer / binding', platforms: ['windows'],
    fields: ['RuleName', 'EventType', 'UtcTime', 'Operation', 'User', 'EventNamespace', 'Name', 'Query', 'Type', 'Destination', 'Consumer', 'Filter'],
    help: 'WMI persistence.' },
  { tag: 'DnsQuery', ids: [22], title: 'DNS query', platforms: ['windows'],
    fields: ['RuleName', 'UtcTime', 'ProcessGuid', 'ProcessId', 'QueryName', 'QueryStatus', 'QueryResults', 'Image', 'User'],
    help: 'DNS queries made by processes (Windows 8.1+).' },
  { tag: 'FileDelete', ids: [23], title: 'File delete (archived)', platforms: ['windows', 'linux'],
    fields: [...P, 'TargetFilename', 'Hashes', 'IsExecutable', 'Archived'],
    help: 'Deleted files are copied to ArchiveDirectory. Can consume a lot of disk.' },
  { tag: 'ClipboardChange', ids: [24], title: 'Clipboard change', platforms: ['windows'],
    fields: [...P, 'Session', 'ClientInfo', 'Hashes', 'Archived'], help: 'Clipboard content changes (needs CaptureClipboard).' },
  { tag: 'ProcessTampering', ids: [25], title: 'Process tampering', platforms: ['windows'],
    fields: [...P, 'Type'], help: 'Process hollowing / herpaderping detection.' },
  { tag: 'FileDeleteDetected', ids: [26], title: 'File delete (logged only)', platforms: ['windows'],
    fields: [...P, 'TargetFilename', 'Hashes', 'IsExecutable'], help: 'Like FileDelete, without archiving the file.' },
  { tag: 'FileBlockExecutable', ids: [27], title: 'Block executable creation', platforms: ['windows'],
    fields: [...P, 'TargetFilename', 'Hashes'], help: 'BLOCKS creation of PE files matching the include rules. Use with care.' },
  { tag: 'FileBlockShredding', ids: [28], title: 'Block file shredding', platforms: ['windows'],
    fields: [...P, 'TargetFilename', 'Hashes', 'IsExecutable'], help: 'BLOCKS shredding tools like SDelete.' },
  { tag: 'FileExecutableDetected', ids: [29], title: 'Executable file detected', platforms: ['windows'],
    fields: [...P, 'TargetFilename', 'Hashes'], help: 'A new PE file was created.' },
];
export const EVENT_BY_TAG = Object.fromEntries(EVENTS.map(e => [e.tag, e]));

// Fields that hold a process image path, used by the exclusion wizard.
export function imageFieldFor(tag) {
  const e = EVENT_BY_TAG[tag];
  if (!e) return null;
  if (e.fields.includes('Image')) return 'Image';
  if (e.fields.includes('SourceImage')) return 'SourceImage';
  if (e.fields.includes('ImageLoaded')) return 'ImageLoaded';
  return null;
}

// Top-level configuration entries (children of <Sysmon>).
export const OPTIONS = [
  { tag: 'HashAlgorithms', type: 'hashes', platforms: ['windows'], help: 'Hashes computed for images: MD5, SHA1, SHA256, IMPHASH or * for all.' },
  { tag: 'CheckRevocation', type: 'bool', platforms: ['windows'], help: 'Check signature revocation. Default: True.' },
  { tag: 'DnsLookup', type: 'bool', platforms: ['windows'], help: 'Reverse DNS lookup for network events. Default: True.' },
  { tag: 'ArchiveDirectory', type: 'text', platforms: ['windows'], placeholder: 'Sysmon', help: 'Folder at volume roots for copy-on-delete files (FileDelete, ClipboardChange).' },
  { tag: 'CopyOnDeletePE', type: 'bool', platforms: ['windows'], help: 'Preserve deleted executable images. Default: False.' },
  { tag: 'CopyOnDeleteSIDs', type: 'text', platforms: ['windows'], placeholder: 'S-1-5-18,S-1-5-19', help: 'Comma-separated account SIDs whose deletes are preserved.' },
  { tag: 'CopyOnDeleteExtensions', type: 'text', platforms: ['windows'], placeholder: '.exe,.dll,.ps1', help: 'Extensions preserved on delete.' },
  { tag: 'CopyOnDeleteProcesses', type: 'text', platforms: ['windows'], placeholder: 'cmd.exe', help: 'Processes whose deletes are preserved.' },
  { tag: 'CaptureClipboard', type: 'flag', platforms: ['windows'], help: 'Enable ClipboardChange (event 24) content capture.' },
  { tag: 'DriverName', type: 'text', platforms: ['windows'], placeholder: 'SysmonDrv', help: 'Custom driver/service name (light obfuscation only).' },
  { tag: 'FieldSizes', type: 'text', platforms: ['windows', 'linux'], placeholder: 'CommandLine:1024,Image:256', help: 'Truncate field sizes, e.g. CommandLine:1024.' },
];
export const OPTION_TAGS = OPTIONS.map(o => o.tag);
