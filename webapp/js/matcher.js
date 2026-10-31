// Sysmon rule evaluation and event parsing.
//
// evaluate(cfg, event) reproduces how Sysmon filters an event:
//   - an event type that is not configured falls back to Sysmon's default;
//   - include rules (if any are active) must match for the event to be kept;
//   - any matching exclude rule drops the event, and exclude always wins;
//   - items in a filter are OR'ed; a <Rule> combines its conditions with its groupRelation.
// All comparisons are case-insensitive, like Sysmon.

import { EVENTS, EVENT_BY_TAG } from './schema.js';

const ID_TO_TAG = new Map();
export function tagForEventId(id) {
  if (!ID_TO_TAG.size || !ID_TO_TAG.has(+id)) for (const e of EVENTS) for (const i of e.ids) ID_TO_TAG.set(i, e.tag);
  return ID_TO_TAG.get(+id) || null;
}

// Values are split on ';' and used literally (spaces are significant, as in Sysmon).
const split = v => v.split(';').filter(Boolean);
const baseName = v => v.split(/[\\/]/).pop();

export function testCondition(condition, fieldValue, ruleValue) {
  const f = String(fieldValue ?? '').toLowerCase();
  const v = String(ruleValue ?? '').toLowerCase();
  switch (condition) {
    case 'is': return f === v;
    case 'is not': return f !== v;
    case 'is any': return split(v).includes(f);
    case 'contains': return f.includes(v);
    case 'contains any': return split(v).some(x => f.includes(x));
    case 'contains all': return split(v).every(x => f.includes(x));
    case 'excludes': return !f.includes(v);
    case 'excludes any': return split(v).some(x => !f.includes(x));
    case 'excludes all': return split(v).every(x => !f.includes(x));
    case 'begin with': return f.startsWith(v);
    case 'not begin with': return !f.startsWith(v);
    case 'end with': return f.endsWith(v);
    case 'not end with': return !f.endsWith(v);
    case 'less than': return f < v;
    case 'more than': return f > v;
    case 'image': return /[\\/]/.test(v) ? f === v : baseName(f) === v;
    default: return false;
  }
}

function condMatches(c, fields) {
  return c.enabled !== false && testCondition(c.condition, fields[c.field], c.value);
}

export function itemMatches(item, fields) {
  if (item.enabled === false) return false;
  if (item.kind === 'cond') return condMatches(item, fields);
  const conds = item.conds.filter(c => c.enabled !== false);
  if (!conds.length) return false;
  return item.relation === 'and' ? conds.every(c => condMatches(c, fields)) : conds.some(c => condMatches(c, fields));
}

const live = items => items.filter(i => i.enabled !== false && (i.kind === 'cond' || i.conds.some(c => c.enabled !== false)));

// Returns { tag, logged: true|false|null, reason, include: item|null, exclude: item|null }.
// logged is null when the event type is not configured (Sysmon default applies).
export function evaluate(cfg, event) {
  const tag = event.tag || tagForEventId(event.id);
  const res = { tag, logged: null, reason: '', include: null, exclude: null };
  if (!tag || !EVENT_BY_TAG[tag]) { res.reason = `Event ID ${event.id} cannot be filtered.`; return res; }
  const ev = cfg.events[tag];
  if (!EVENT_BY_TAG[tag].platforms.includes(cfg.platform)) { res.logged = false; res.reason = `${tag} is not available on ${cfg.platform}.`; return res; }
  if (!ev || ev.mode === 'unset') { res.reason = `${tag} is not in the config, so Sysmon's built-in default applies.`; return res; }
  if (ev.mode === 'off') { res.logged = false; res.reason = `${tag} is set to Off.`; return res; }
  if (ev.mode === 'all') { res.logged = true; res.reason = `${tag} is set to Log all.`; return res; }

  const inc = live(ev.include), exc = live(ev.exclude);
  if (!inc.length && !exc.length) { res.logged = false; res.reason = `${tag} has no active rules, so it is not logged.`; return res; }
  if (inc.length) {
    res.include = inc.find(i => itemMatches(i, event.fields)) || null;
    if (!res.include) { res.logged = false; res.reason = 'No include rule matched.'; return res; }
  }
  res.exclude = exc.find(i => itemMatches(i, event.fields)) || null;
  if (res.exclude) { res.logged = false; res.reason = 'An exclude rule matched (exclude always wins).'; return res; }
  res.logged = true;
  res.reason = inc.length ? 'An include rule matched and no exclude rule did.' : 'No exclude rule matched.';
  return res;
}

// Human-readable label for a rule item.
export function describeItem(item) {
  if (!item) return '';
  if (item.kind === 'cond') return `${item.field} ${item.condition} "${item.value}"`;
  const parts = item.conds.filter(c => c.enabled !== false).map(c => `${c.field} ${c.condition} "${c.value}"`);
  return `Rule "${item.name || 'unnamed'}": ${parts.join(item.relation === 'and' ? ' AND ' : ' OR ')}`;
}

// ------------------------------------------------------------------ event parsing

function fromEventElement(el) {
  const kids = name => [...el.getElementsByTagName('*')].filter(n => n.localName === name);
  const idEl = kids('EventID')[0];
  if (!idEl) return null;
  const id = parseInt(idEl.textContent, 10);
  const fields = {};
  for (const d of kids('Data')) {
    const name = d.getAttribute('Name');
    if (name) fields[name] = d.textContent;
  }
  const time = kids('TimeCreated')[0]?.getAttribute('SystemTime') || fields.UtcTime || '';
  return { id, tag: tagForEventId(id), fields, time };
}

const FIELD_NAMES = () => new Set(EVENTS.flatMap(e => e.fields));
const ID_KEYS = ['EventID', 'EventCode', 'event_id', 'eventid', 'Id', 'event.code', 'winlog.event_id'];

function flatten(obj, prefix = '', out = {}) {
  for (const [k, v] of Object.entries(obj || {})) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out);
    else out[key] = v;
  }
  return out;
}

// A flat record from JSON or CSV (Splunk, Elastic/Winlogbeat, Sentinel exports).
function fromRecord(rec) {
  const flat = flatten(rec.result || rec._source || rec);
  let id = null;
  for (const k of ID_KEYS) if (flat[k] !== undefined && flat[k] !== '') { id = parseInt(flat[k], 10); break; }
  if (id === null) {
    const k = Object.keys(flat).find(x => /(^|\.)(event_?id|eventcode)$/i.test(x));
    if (k) id = parseInt(flat[k], 10);
  }
  if (!Number.isFinite(id)) return null;
  const known = FIELD_NAMES();
  const fields = {};
  for (const [k, v] of Object.entries(flat)) {
    const last = k.split('.').pop();
    if (known.has(last) && v !== null && v !== undefined) fields[last] = String(v);
  }
  // Some exports embed the raw event XML.
  for (const v of Object.values(flat)) {
    if (typeof v === 'string' && v.includes('<Data Name=') && !Object.keys(fields).length) {
      const parsed = parseEvents(v)[0];
      if (parsed) return parsed;
    }
  }
  const time = flat.UtcTime || flat['@timestamp'] || flat.TimeCreated || flat._time || flat.TimeGenerated || '';
  return { id, tag: tagForEventId(id), fields, time: String(time) };
}

function parseCsv(text) {
  const rows = [];
  let row = [], cell = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (q) {
      if (ch === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (ch === '"') q = false;
      else cell += ch;
    } else if (ch === '"') q = true;
    else if (ch === ',') { row.push(cell); cell = ''; }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      row.push(cell); rows.push(row); row = []; cell = '';
    } else cell += ch;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  const [head, ...body] = rows.filter(r => r.some(c => c !== ''));
  return body.map(r => Object.fromEntries(head.map((h, i) => [h.trim(), r[i] ?? ''])));
}

// Accepts Event Viewer / wevtutil XML (one or many <Event>), syslog lines containing
// Sysmon for Linux XML, JSON (array, object or JSON lines) and CSV with a header row.
export function parseEvents(text) {
  text = String(text || '').trim();
  if (!text) return [];
  const xmlEvents = text.match(/<Event[\s>][\s\S]*?<\/Event>/g);
  if (xmlEvents) {
    const out = [];
    for (const chunk of xmlEvents) {
      const doc = new DOMParser().parseFromString(chunk, 'application/xml');
      if (doc.getElementsByTagName('parsererror').length) continue;
      const ev = fromEventElement(doc.documentElement);
      if (ev) out.push(ev);
    }
    return out;
  }
  if (text[0] === '[' || text[0] === '{') {
    let records;
    try {
      const data = JSON.parse(text);
      records = Array.isArray(data) ? data : data.hits?.hits || data.results || [data];
    } catch {
      records = text.split('\n').map(l => l.trim()).filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
    }
    return records.map(fromRecord).filter(Boolean);
  }
  if (text.includes(',')) return parseCsv(text).map(fromRecord).filter(Boolean);
  return [];
}
