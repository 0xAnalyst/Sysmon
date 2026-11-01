// Config validation. Returns a list of { level: 'error'|'warn'|'info', event, itemId, msg }.

import { EVENTS, EVENT_BY_TAG, CONDITIONS, CONDITION_NAMES, OPTIONS, minSchemaForEvent } from './schema.js';
import { revokedIds } from './attack.js';

// Locations a standard user can write to. Excluding by path there lets malware hide.
export const WRITABLE = [
  /^c:\\users\b/i, /\\appdata\\/i, /(?<!\\driverstore)\\temp\\?/i, /\\downloads\\?/i, /^c:\\perflogs/i,
  /^c:\\windows\\tasks/i, /^c:\\windows\\tracing/i, /^\/tmp\b/, /^\/var\/tmp\b/, /^\/dev\/shm\b/, /^\/home\b/,
];
const PATH_FIELDS = ['Image', 'ParentImage', 'SourceImage', 'TargetImage', 'ImageLoaded', 'TargetFilename'];

// IR profile: for configs used in incident response (dfir/). These events must log everything
// (exclusions allowed), because attackers run inside processes no allow-list anticipates.
export const IR_LOG_ALL = ['ProcessCreate', 'NetworkConnect', 'DnsQuery', 'CreateRemoteThread', 'DriverLoad',
  'RawAccessRead', 'PipeEvent', 'WmiEvent', 'ProcessTampering', 'FileExecutableDetected'];

// opts.profile: 'ir' applies the stricter incident-response rules.
export function validate(cfg, opts = {}) {
  const ir = opts.profile === 'ir';
  const issues = [];
  const add = (level, event, itemId, msg) => issues.push({ level, event, itemId, msg });
  const target = parseFloat(cfg.schemaversion);

  for (const e of EVENTS) {
    const ev = cfg.events[e.tag];
    if (!ev || ev.mode === 'unset') continue;
    if (!e.platforms.includes(cfg.platform)) {
      if (ev.mode !== 'off') add('warn', e.tag, null, `${e.tag} is not supported on ${cfg.platform}; it is left out of the output.`);
      continue;
    }
    const min = minSchemaForEvent(e.ids[0]);
    if (parseFloat(min) > target) add('error', e.tag, null, `${e.tag} needs schema ${min} or newer (target is ${cfg.schemaversion}).`);
    if (ev.mode === 'all' && ['ImageLoad', 'FileCreate', 'RegistryEvent', 'ProcessAccess', 'FileDelete'].includes(e.tag)) {
      add('warn', e.tag, null, `Logging every ${e.tag} event produces very high volume.`);
    }
    if (ev.mode === 'all' && e.tag === 'FileDelete') add('warn', e.tag, null, 'FileDelete archives every deleted file to disk. Prefer FileDeleteDetected (26) unless you need copies.');
    if (ev.mode !== 'filtered') continue;

    if ((e.tag === 'FileBlockExecutable' || e.tag === 'FileBlockShredding') && ev.include.some(i => i.enabled)) {
      add('info', e.tag, null, `${e.tag} include rules BLOCK the operation, not just log it. Test before rolling out.`);
    }

    const keys = { include: new Map(), exclude: new Map() };
    for (const onmatch of ['include', 'exclude']) {
      for (const item of ev[onmatch]) {
        if (!item.enabled) continue;
        const conds = item.kind === 'rule' ? item.conds.filter(c => c.enabled) : [item];
        if (item.kind === 'rule') {
          if (!conds.length) add('error', e.tag, item.id, `Rule "${item.name || '(unnamed)'}" has no active conditions.`);
          if (item.relation !== 'and' && item.relation !== 'or') add('error', e.tag, item.id, `Rule relation must be "and" or "or".`);
        }
        for (const c of conds) checkCond(e, c, onmatch, item, add, ir);
        for (const n of new Set([item.name, ...conds.map(c => c.name)].filter(Boolean))) {
          const old = revokedIds(n);
          if (old.length) add('info', e.tag, item.id, `Rule name uses revoked ATT&CK ID${old.length > 1 ? 's' : ''} ${old.map(([a, b]) => `${a} (now ${b})`).join(', ')}.`);
        }
        if (item.kind === 'cond') {
          const k = `${item.field}|${item.condition}|${item.value.toLowerCase()}`;
          if (keys[onmatch].has(k)) add('warn', e.tag, item.id, `Duplicate ${onmatch} rule: ${item.field} ${item.condition} "${item.value}".`);
          keys[onmatch].set(k, item.id);
        }
      }
    }
    for (const [k, id] of keys.include) {
      if (keys.exclude.has(k)) add('warn', e.tag, id, `Same rule is both included and excluded (exclude wins): ${k.split('|').join(' ')}.`);
    }
  }

  for (const o of OPTIONS) {
    if (cfg.options[o.tag] !== undefined && cfg.options[o.tag] !== '' && !o.platforms.includes(cfg.platform)) {
      add('info', null, null, `${o.tag} is ignored on ${cfg.platform} and left out of the output.`);
    }
  }
  const h = cfg.options.HashAlgorithms;
  if (h && cfg.platform === 'windows') {
    const bad = h.split(',').map(s => s.trim()).filter(s => s && !/^(md5|sha1|sha256|imphash|\*)$/i.test(s));
    if (bad.length) add('error', null, null, `Unknown hash algorithm(s): ${bad.join(', ')}.`);
  }
  if (cfg.events.ClipboardChange?.mode !== 'unset' && cfg.events.ClipboardChange?.mode !== 'off' && !cfg.options.CaptureClipboard) {
    add('info', 'ClipboardChange', null, 'ClipboardChange content is only archived when CaptureClipboard is set.');
  }
  if (ir) checkIr(cfg, add);
  return issues;
}

function checkIr(cfg, add) {
  if (cfg.platform !== 'windows') return;
  for (const tag of IR_LOG_ALL) {
    const ev = cfg.events[tag];
    const logAll = ev && (ev.mode === 'all' || (ev.mode === 'filtered' && !ev.include.some(i => i.enabled)));
    if (!logAll) add('error', tag, null, `IR profile: ${tag} must log everything (Log all, or exclusions only). An include list misses activity inside injected or renamed processes.`);
  }
  const pa = cfg.events.ProcessAccess;
  const lsass = pa && (pa.mode === 'all' || (pa.mode === 'filtered' && (!pa.include.some(i => i.enabled) ||
    pa.include.some(i => i.enabled && i.kind === 'cond' && i.field === 'TargetImage' && /lsass\.exe$/i.test(i.value)))));
  if (!lsass) add('error', 'ProcessAccess', null, 'IR profile: ProcessAccess must include every access to lsass.exe.');
  if (['all', 'filtered'].includes(cfg.events.ClipboardChange?.mode)) add('warn', 'ClipboardChange', null, 'IR profile: clipboard capture records user data. Enable it only with written client approval.');
  for (const tag of ['FileBlockExecutable', 'FileBlockShredding']) {
    const ev = cfg.events[tag];
    if (ev && (ev.mode === 'all' || (ev.mode === 'filtered' && ev.include.some(i => i.enabled)))) add('warn', tag, null, `IR profile: ${tag} blocks activity on the hosts under investigation. Use it only for agreed containment.`);
  }
}

function checkCond(e, c, onmatch, item, add, ir = false) {
  const where = item.kind === 'rule' ? ` (in rule "${item.name || 'unnamed'}")` : '';
  if (!e.fields.includes(c.field)) add('error', e.tag, item.id, `${c.field} is not a field of ${e.tag}${where}.`);
  if (!CONDITION_NAMES.includes(c.condition)) add('error', e.tag, item.id, `Unknown condition "${c.condition}"${where}.`);
  if (c.value === '') add('warn', e.tag, item.id, `${c.field} has an empty value${where}.`);
  const def = CONDITIONS.find(x => x.name === c.condition);
  if (def?.multi && !c.value.includes(';')) add('info', e.tag, item.id, `"${c.condition}" expects ;-separated values; "${c.value}" is a single value${where}.`);
  // A leading space is almost always a typo. A trailing one can be deliberate ("Intel ").
  if (c.value !== c.value.trimStart()) add('warn', e.tag, item.id, `Value "${c.value}" starts with a space, so it will rarely match${where}.`);
  else if (c.value !== c.value.trimEnd()) add('info', e.tag, item.id, `Value "${c.value}" ends with a space; check that it is intended${where}.`);

  // Broad exclusions are an easy way for an attacker to stay invisible.
  if (onmatch === 'exclude' && item.kind === 'cond' && PATH_FIELDS.includes(c.field)) {
    const v = c.value.trim();
    if (['begin with', 'contains', 'end with'].includes(c.condition) && WRITABLE.some(r => r.test(v))) {
      add(ir ? 'error' : 'warn', e.tag, item.id, `Excludes ${c.field} ${c.condition} "${v}", a user-writable location. Malware placed there will not be logged.`);
    } else if (c.condition === 'image' || (c.condition === 'end with' && !v.includes('\\') && !v.includes('/'))) {
      add(ir ? 'error' : 'info', e.tag, item.id, `Excludes any binary named "${v}" anywhere on disk. A full path is harder to spoof.`);
    } else if (c.condition === 'contains' && v.length < 5) {
      add('warn', e.tag, item.id, `Very broad exclusion: ${c.field} contains "${v}".`);
    }
  }
}

export { EVENT_BY_TAG };
