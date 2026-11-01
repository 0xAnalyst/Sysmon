// Turn named include rules into SIEM queries and Sigma rules.
//
// Sysmon writes the name of the include rule that matched into the event's RuleName field,
// so the SIEM queries simply search for that RuleName. Sigma rules are rebuilt from the
// conditions themselves so they also work on data that did not come through this config.

import { EVENTS, EVENT_BY_TAG } from './schema.js';
import { techniqueIds, TECH_BY_ID } from './attack.js';

// Named include rules grouped by event and name: [{ tag, name, items }]
export function namedRules(cfg) {
  const groups = new Map();
  for (const e of EVENTS) {
    if (!e.platforms.includes(cfg.platform)) continue;
    const ev = cfg.events[e.tag];
    if (!ev || ev.mode !== 'filtered') continue;
    for (const item of ev.include) {
      if (item.enabled === false) continue;
      const name = item.name || (item.kind === 'cond' ? '' : '');
      if (!name) continue;
      const key = `${e.tag}\u0000${name}`;
      if (!groups.has(key)) groups.set(key, { tag: e.tag, name, items: [] });
      groups.get(key).items.push(item);
    }
  }
  return [...groups.values()];
}

const kqlStr = s => `@"${String(s).replace(/"/g, '""')}"`;
const splStr = s => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
const luceneStr = s => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

export function splunk(cfg, r) {
  const ids = EVENT_BY_TAG[r.tag].ids;
  const src = cfg.platform === 'linux' ? 'sourcetype="sysmon:linux"' : 'source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"';
  return `${src} EventCode IN (${ids.join(', ')}) RuleName=${splStr(r.name)}\n| stats count min(_time) as first max(_time) as last values(Image) as Image by host, RuleName`;
}

export function sentinel(cfg, r) {
  const ids = EVENT_BY_TAG[r.tag].ids;
  if (cfg.platform === 'linux') {
    return `Syslog\n| where ProcessName == "sysmon" and SyslogMessage has ${kqlStr(r.name)}\n| extend EventID = toint(extract(@"<EventID>(\\d+)</EventID>", 1, SyslogMessage))\n| where EventID in (${ids.join(', ')})`;
  }
  return `Event\n| where Source == "Microsoft-Windows-Sysmon" and EventID in (${ids.join(', ')})\n` +
    `| extend RuleName = extract(@'<Data Name="RuleName">([^<]*)</Data>', 1, EventData)\n` +
    `| where RuleName == ${kqlStr(r.name)}\n| summarize count(), min(TimeGenerated), max(TimeGenerated) by Computer, RuleName`;
}

export function elastic(cfg, r) {
  const ids = EVENT_BY_TAG[r.tag].ids;
  return `event.code:(${ids.map(i => `"${i}"`).join(' or ')}) and rule.name:${luceneStr(r.name)}\n` +
    `// Winlogbeat / Elastic Agent Sysmon integration. Raw field: winlog.event_data.RuleName`;
}

// ------------------------------------------------------------------ Sigma

const CATEGORY = {
  ProcessCreate: 'process_creation', FileCreateTime: 'file_change', NetworkConnect: 'network_connection',
  ProcessTerminate: 'process_termination', DriverLoad: 'driver_load', ImageLoad: 'image_load',
  CreateRemoteThread: 'create_remote_thread', RawAccessRead: 'raw_access_thread', ProcessAccess: 'process_access',
  FileCreate: 'file_event', RegistryEvent: 'registry_event', FileCreateStreamHash: 'create_stream_hash',
  PipeEvent: 'pipe_created', WmiEvent: 'wmi_event', DnsQuery: 'dns_query', FileDelete: 'file_delete',
  ClipboardChange: 'clipboard_change', ProcessTampering: 'process_tampering', FileDeleteDetected: 'file_delete',
  FileBlockExecutable: 'file_block_executable', FileBlockShredding: 'file_block_shredding', FileExecutableDetected: 'file_executable_detected',
};

const yq = s => `'${String(s).replace(/'/g, "''")}'`;
const sigmaEscape = v => String(v).replace(/([*?])/g, '\\$1');
const multi = v => v.split(';').filter(Boolean);

// One condition -> { field: 'Image|endswith', values: [...], negate, all, unsupported }
function sigmaTerm(c) {
  const v = c.value;
  switch (c.condition) {
    case 'is': return { key: c.field, values: [v] };
    case 'is any': return { key: c.field, values: multi(v) };
    case 'contains': return { key: `${c.field}|contains`, values: [v] };
    case 'contains any': return { key: `${c.field}|contains`, values: multi(v) };
    case 'contains all': return { key: `${c.field}|contains|all`, values: multi(v) };
    case 'begin with': return { key: `${c.field}|startswith`, values: [v] };
    case 'end with': return { key: `${c.field}|endswith`, values: [v] };
    case 'image': return /[\\/]/.test(v) ? { key: c.field, values: [v] } : { key: `${c.field}|endswith`, values: ['\\' + v] };
    case 'is not': return { key: c.field, values: [v], negate: true };
    case 'excludes': return { key: `${c.field}|contains`, values: [v], negate: true };
    case 'excludes all': return { key: `${c.field}|contains`, values: multi(v), negate: true };
    case 'excludes any': return { key: `${c.field}|contains|all`, values: multi(v), negate: true };
    case 'not begin with': return { key: `${c.field}|startswith`, values: [v], negate: true };
    case 'not end with': return { key: `${c.field}|endswith`, values: [v], negate: true };
    default: return { unsupported: `${c.field} ${c.condition} ${v}` };
  }
}

export function sigma(cfg, r, date = new Date()) {
  const blocks = [];      // [name, [[key, values]]]
  const expr = [];
  const notes = [];
  let n = 0;
  // Plain single conditions on the same field collapse into one list (OR).
  const simple = new Map();
  for (const item of r.items) {
    if (item.kind === 'cond') {
      const t = sigmaTerm(item);
      if (!t.unsupported && !t.negate && !t.key.endsWith('|all')) {
        (simple.get(t.key) || simple.set(t.key, []).get(t.key)).push(...t.values);
        continue;
      }
    }
    const conds = item.kind === 'cond' ? [item] : item.conds.filter(c => c.enabled !== false);
    const terms = conds.map(sigmaTerm);
    terms.filter(t => t.unsupported).forEach(t => notes.push(`not expressible in Sigma: ${t.unsupported}`));
    const usable = terms.filter(t => !t.unsupported);
    if (!usable.length) continue;
    if (item.kind === 'rule' && item.relation === 'or') {
      // OR rule: each condition becomes its own alternative.
      for (const t of usable) {
        const id = `selection_${++n}`;
        blocks.push([id, [[t.key, t.values]]]);
        expr.push(t.negate ? `not ${id}` : id);
      }
      continue;
    }
    const pos = usable.filter(t => !t.negate), neg = usable.filter(t => t.negate);
    const parts = [];
    // Same key twice in one AND map is not allowed in YAML; split those into extra blocks.
    const groups = [];
    for (const t of pos) {
      let g = groups.find(g => !g.some(([k]) => k === t.key));
      if (!g) groups.push(g = []);
      g.push([t.key, t.values]);
    }
    for (const g of groups) { const id = `selection_${++n}`; blocks.push([id, g]); parts.push(id); }
    for (const t of neg) { const id = `filter_${++n}`; blocks.push([id, [[t.key, t.values]]]); parts.push(`not ${id}`); }
    expr.push(parts.length > 1 ? `(${parts.join(' and ')})` : parts[0]);
  }
  for (const [key, values] of simple) {
    const id = `selection_${++n}`;
    blocks.push([id, [[key, [...new Set(values)]]]]);
    expr.push(id);
  }
  if (!expr.length) return `# ${r.name}: no conditions could be expressed in Sigma\n`;

  const techs = techniqueIds(r.name);
  const tags = new Set();
  for (const t of techs) {
    tags.add(`attack.${t.toLowerCase()}`);
    for (const tac of TECH_BY_ID.get(t)?.tactics || []) tags.add(`attack.${tac}`);
  }
  const title = techs.length ? `${techs.map(t => TECH_BY_ID.get(t)?.name || t).join(', ')} (${r.tag})` : r.name;
  const lines = [
    `title: ${yq(title)}`,
    `id: ${crypto.randomUUID()}`,
    'status: experimental',
    `description: ${yq(`Generated from the Sysmon config rule "${r.name}" (${r.tag}). Review before use.`)}`,
    'author: Sysmon Config Builder',
    `date: ${date.toISOString().slice(0, 10).replace(/-/g, '/')}`,
  ];
  if (tags.size) lines.push('tags:', ...[...tags].map(t => `    - ${t}`));
  lines.push('logsource:', `    product: ${cfg.platform}`, `    category: ${CATEGORY[r.tag] || r.tag}`, 'detection:');
  for (const [id, pairs] of blocks) {
    lines.push(`    ${id}:`);
    for (const [k, vals] of pairs) {
      if (vals.length === 1) lines.push(`        ${k}: ${yq(sigmaEscape(vals[0]))}`);
      else lines.push(`        ${k}:`, ...vals.map(v => `            - ${yq(sigmaEscape(v))}`));
    }
  }
  const condition = expr.length === 1 ? expr[0] : expr.every(x => /^selection_\d+$/.test(x)) ? '1 of selection_*' : expr.join(' or ');
  lines.push(`    condition: ${condition}`);
  lines.push('falsepositives:', '    - Legitimate administrative activity', 'level: medium');
  return (notes.length ? notes.map(x => `# ${x}`).join('\n') + '\n' : '') + lines.join('\n') + '\n';
}
