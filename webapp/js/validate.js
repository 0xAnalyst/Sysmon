// Config validation. Returns a list of { level: 'error'|'warn'|'info', event, itemId, msg }.

import { EVENTS, EVENT_BY_TAG, CONDITIONS, CONDITION_NAMES, OPTIONS, minSchemaForEvent } from './schema.js';

// Locations a standard user can write to. Excluding by path there lets malware hide.
const WRITABLE = [
  /^c:\\users\b/i, /\\appdata\\/i, /\\temp\\?/i, /\\downloads\\?/i, /^c:\\perflogs/i,
  /^c:\\windows\\tasks/i, /^c:\\windows\\tracing/i, /^\/tmp\b/, /^\/var\/tmp\b/, /^\/dev\/shm\b/, /^\/home\b/,
];
const PATH_FIELDS = ['Image', 'ParentImage', 'SourceImage', 'TargetImage', 'ImageLoaded', 'TargetFilename'];

export function validate(cfg) {
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
        for (const c of conds) checkCond(e, c, onmatch, item, add);
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
  return issues;
}

function checkCond(e, c, onmatch, item, add) {
  const where = item.kind === 'rule' ? ` (in rule "${item.name || 'unnamed'}")` : '';
  if (!e.fields.includes(c.field)) add('error', e.tag, item.id, `${c.field} is not a field of ${e.tag}${where}.`);
  if (!CONDITION_NAMES.includes(c.condition)) add('error', e.tag, item.id, `Unknown condition "${c.condition}"${where}.`);
  if (c.value === '') add('warn', e.tag, item.id, `${c.field} has an empty value${where}.`);
  const def = CONDITIONS.find(x => x.name === c.condition);
  if (def?.multi && !c.value.includes(';')) add('info', e.tag, item.id, `"${c.condition}" expects ;-separated values; "${c.value}" is a single value${where}.`);
  if (c.value !== c.value.trim()) add('warn', e.tag, item.id, `Value "${c.value}" has leading/trailing spaces, so it will rarely match${where}.`);

  // Broad exclusions are an easy way for an attacker to stay invisible.
  if (onmatch === 'exclude' && item.kind === 'cond' && PATH_FIELDS.includes(c.field)) {
    const v = c.value.trim();
    if (['begin with', 'contains', 'end with'].includes(c.condition) && WRITABLE.some(r => r.test(v))) {
      add('warn', e.tag, item.id, `Excludes ${c.field} ${c.condition} "${v}", a user-writable location. Malware placed there will not be logged.`);
    } else if (c.condition === 'image' || (c.condition === 'end with' && !v.includes('\\') && !v.includes('/'))) {
      add('info', e.tag, item.id, `Excludes any binary named "${v}" anywhere on disk. A full path is harder to spoof.`);
    } else if (c.condition === 'contains' && v.length < 5) {
      add('warn', e.tag, item.id, `Very broad exclusion: ${c.field} contains "${v}".`);
    }
  }
}

export { EVENT_BY_TAG };
