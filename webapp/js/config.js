// Config model, XML parser and XML generator.
//
// Model:
//   { platform, schemaversion, header, options: {Tag: value}, extra: [xmlString],
//     events: { Tag: { mode, include: Item[], exclude: Item[] } } }
//   mode: 'unset' (not in config) | 'off' (empty include) | 'all' (empty exclude) | 'filtered'
//   Item: { kind: 'cond', id, field, condition, value, name, comment, before, enabled }
//       | { kind: 'rule', id, name, relation, comment, before, enabled, conds: Cond[] }

import { EVENTS, EVENT_BY_TAG, OPTIONS, OPTION_TAGS, LATEST } from './schema.js';

let seq = 0;
export const uid = () => 'i' + (++seq).toString(36) + Math.random().toString(36).slice(2, 6);

export function emptyEvent() {
  return { mode: 'unset', include: [], exclude: [] };
}

export function newConfig(platform = 'windows') {
  const events = {};
  for (const e of EVENTS) events[e.tag] = emptyEvent();
  return {
    platform,
    schemaversion: LATEST[platform].schema,
    header: '',
    options: platform === 'windows' ? { HashAlgorithms: 'md5,sha256,IMPHASH', CheckRevocation: 'False' } : {},
    extra: [],
    events,
  };
}

export function newCond(field = 'Image', condition = 'is', value = '', extra = {}) {
  return { kind: 'cond', id: uid(), field, condition, value, name: '', comment: '', before: [], enabled: true, ...extra };
}

export function newRule(relation = 'and', name = '') {
  return { kind: 'rule', id: uid(), name, relation, comment: '', before: [], enabled: true, conds: [] };
}

// ---------------------------------------------------------------- parsing

const DISABLED_PREFIX = 'DISABLED:';

function commentText(node) {
  return node.nodeValue.replace(/\s+/g, ' ').trim();
}

// Is this comment on the same line as the element before it?
function isTrailing(commentNode) {
  const prev = commentNode.previousSibling;
  if (!prev) return false;
  if (prev.nodeType === Node.TEXT_NODE) {
    if (prev.nodeValue.includes('\n')) return false;
    const before = prev.previousSibling;
    return !!before && (before.nodeType === Node.ELEMENT_NODE || isTrailing2(before));
  }
  return prev.nodeType === Node.ELEMENT_NODE || prev.nodeType === Node.COMMENT_NODE && isTrailing(prev);
}
function isTrailing2(n) { return n.nodeType === Node.COMMENT_NODE && isTrailing(n); }

function parseDisabled(text) {
  const xml = text.slice(DISABLED_PREFIX.length).trim().replace(/&#45;/g, '-');
  const doc = new DOMParser().parseFromString(`<x>${xml}</x>`, 'application/xml');
  if (doc.querySelector('parsererror')) return null;
  const el = doc.documentElement.firstElementChild;
  return el ? parseItem(el) : null;
}

function parseCond(el) {
  return newCond(el.localName, el.getAttribute('condition') || 'is', el.textContent, {
    name: el.getAttribute('name') || '',
  });
}

function parseItem(el) {
  if (el.localName === 'Rule') {
    const rule = newRule((el.getAttribute('groupRelation') || 'or').toLowerCase(), el.getAttribute('name') || '');
    walkChildren(el, rule.conds, true);
    return rule;
  }
  return parseCond(el);
}

// Read the children of an event filter (or <Rule>) into `items`, attaching comments.
function walkChildren(parent, items, condsOnly = false) {
  let pending = [];
  for (const n of parent.childNodes) {
    if (n.nodeType === Node.ELEMENT_NODE) {
      if (condsOnly && n.localName === 'Rule') continue;
      const item = parseItem(n);
      item.before = pending;
      pending = [];
      items.push(item);
    } else if (n.nodeType === Node.COMMENT_NODE) {
      const t = commentText(n);
      if (!t) continue;
      if (t.startsWith(DISABLED_PREFIX)) {
        const item = parseDisabled(n.nodeValue.trim());
        if (item && (!condsOnly || item.kind === 'cond')) {
          item.enabled = false;
          item.before = pending;
          pending = [];
          items.push(item);
          continue;
        }
      }
      const last = items[items.length - 1];
      if (last && isTrailing(n)) last.comment = last.comment ? `${last.comment} | ${t}` : t;
      else pending.push(t);
    }
  }
}

export function parseXml(text) {
  const doc = new DOMParser().parseFromString(text, 'application/xml');
  const err = doc.querySelector('parsererror');
  if (err) throw new Error('XML is not well-formed: ' + err.textContent.split('\n')[0]);
  const root = doc.documentElement;
  if (root.localName !== 'Sysmon') throw new Error(`Root element is <${root.localName}>, expected <Sysmon>`);

  const notes = [];
  const sourceSchema = root.getAttribute('schemaversion') || '';
  const cfg = newConfig('windows');
  cfg.options = {};
  cfg.sourceSchema = sourceSchema;

  // Leading comment block becomes the header.
  for (const n of doc.childNodes) {
    if (n.nodeType === Node.COMMENT_NODE) { cfg.header = n.nodeValue.replace(/^\s*\n|\s+$/g, ''); break; }
  }

  let linuxHint = false;
  for (const el of root.children) {
    if (el.localName === 'EventFiltering') continue;
    if (OPTION_TAGS.includes(el.localName)) {
      cfg.options[el.localName] = OPTIONS.find(o => o.tag === el.localName).type === 'flag' ? true : el.textContent.trim();
    } else {
      cfg.extra.push(new XMLSerializer().serializeToString(el));
      notes.push(`Kept unknown top-level element <${el.localName}> as-is.`);
    }
  }

  const filtering = root.querySelector(':scope > EventFiltering');
  const seen = new Set();
  const addFilter = (evEl, groupRelation, groupName) => {
    const tag = evEl.localName;
    if (!EVENT_BY_TAG[tag]) { notes.push(`Skipped unknown event filter <${tag}>.`); return; }
    const onmatch = (evEl.getAttribute('onmatch') || 'include').toLowerCase() === 'exclude' ? 'exclude' : 'include';
    const ev = cfg.events[tag];
    const items = [];
    walkChildren(evEl, items);
    if (groupRelation === 'and' && items.some(i => i.kind === 'cond')) {
      // An AND RuleGroup over plain conditions is one compound rule.
      const rule = newRule('and', groupName || '');
      rule.conds = items.filter(i => i.kind === 'cond');
      items.splice(0, items.length, rule, ...items.filter(i => i.kind === 'rule'));
    }
    ev[onmatch].push(...items);
    seen.add(`${tag}:${onmatch}`);
    if (items.some(i => /^\//.test(i.value || '') || (i.conds || []).some(c => /^\//.test(c.value)))) linuxHint = true;
  };

  if (filtering) {
    for (const el of filtering.children) {
      if (el.localName === 'RuleGroup') {
        const rel = (el.getAttribute('groupRelation') || 'or').toLowerCase();
        for (const evEl of el.children) addFilter(evEl, rel, el.getAttribute('name'));
      } else {
        addFilter(el, 'or');
      }
    }
  }

  for (const e of EVENTS) {
    const ev = cfg.events[e.tag];
    const inc = seen.has(`${e.tag}:include`), exc = seen.has(`${e.tag}:exclude`);
    if (ev.include.length || ev.exclude.length) ev.mode = 'filtered';
    else if (exc) ev.mode = 'all';
    else if (inc) ev.mode = 'off';
    else ev.mode = 'unset';
  }

  // Platform: Linux configs use / paths and lack Windows-only options.
  if (linuxHint && !cfg.options.HashAlgorithms) cfg.platform = 'linux';
  cfg.schemaversion = LATEST[cfg.platform].schema;
  if (sourceSchema && parseFloat(sourceSchema) < 4) {
    notes.push(`Schema ${sourceSchema} used AND between different fields when no RuleGroup was set. This builder writes everything in OR RuleGroups (the 4.x behaviour); review exclusions that relied on AND.`);
  }
  if (sourceSchema && sourceSchema !== cfg.schemaversion) {
    notes.push(`Imported schema ${sourceSchema}; output targets ${cfg.schemaversion}.`);
  }
  return { config: cfg, notes };
}

// ---------------------------------------------------------------- generation

export function escapeXml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function safeComment(s) {
  return String(s).replace(/--/g, '- -').replace(/-$/, '- ');
}

function condXml(c) {
  const attrs = [];
  if (c.name) attrs.push(`name="${escapeXml(c.name)}"`);
  attrs.push(`condition="${escapeXml(c.condition)}"`);
  return `<${c.field} ${attrs.join(' ')}>${escapeXml(c.value)}</${c.field}>`;
}

function itemXml(item, ind, opts) {
  const lines = opts.comments ? (item.before || []).map(b => `${ind}<!-- ${safeComment(b)} -->`) : [];
  if (!item.enabled) {
    if (!opts.keepDisabled) return [];
    // Disabled items are kept as a comment that parseXml restores.
    const flat = itemXml({ ...item, enabled: true, before: [], comment: '',
      conds: (item.conds || []).map(c => ({ ...c, enabled: true, before: [], comment: '' })) },
      '', { comments: false, keepDisabled: false }).map(l => l.trim()).join(' ');
    return [...lines, `${ind}<!-- ${DISABLED_PREFIX} ${flat.replace(/-/g, '&#45;')} -->`];
  }
  const trail = opts.comments && item.comment ? ` <!-- ${safeComment(item.comment)} -->` : '';
  if (item.kind === 'cond') return [...lines, `${ind}${condXml(item)}${trail}`];
  return [
    ...lines,
    `${ind}<Rule name="${escapeXml(item.name)}" groupRelation="${item.relation}">${trail}`,
    ...item.conds.flatMap(c => itemXml(c, ind + '  ', opts)),
    `${ind}</Rule>`,
  ];
}

export function activeCount(items) {
  return items.filter(i => i.enabled && (i.kind === 'cond' || i.conds.some(c => c.enabled))).length;
}

export function generateXml(cfg, opts = {}) {
  opts = { comments: true, keepDisabled: true, ...opts };
  const out = [];
  if (opts.comments && cfg.header) out.push('<!--', safeComment(cfg.header), '-->');
  out.push(`<Sysmon schemaversion="${escapeXml(cfg.schemaversion)}">`);

  for (const o of OPTIONS) {
    const v = cfg.options[o.tag];
    if (v === undefined || v === '' || v === false) continue;
    if (!o.platforms.includes(cfg.platform)) continue;
    out.push(o.type === 'flag' ? `  <${o.tag}/>` : `  <${o.tag}>${escapeXml(v)}</${o.tag}>`);
  }
  for (const x of cfg.extra) out.push('  ' + x);

  out.push('  <EventFiltering>');
  for (const e of EVENTS) {
    if (!e.platforms.includes(cfg.platform)) continue;
    const ev = cfg.events[e.tag];
    if (!ev || ev.mode === 'unset') continue;
    out.push('', `    <!-- Event ID ${e.ids.join(', ')} : ${e.title} -->`);

    if (ev.mode === 'off' || ev.mode === 'all') {
      out.push(`    <${e.tag} onmatch="${ev.mode === 'off' ? 'include' : 'exclude'}"/>`);
      continue;
    }
    let wrote = false;
    for (const onmatch of ['include', 'exclude']) {
      const items = ev[onmatch];
      // A filter with no live rules is left out: an empty include would silence the event.
      if (!activeCount(items)) continue;
      out.push('    <RuleGroup name="" groupRelation="or">', `      <${e.tag} onmatch="${onmatch}">`);
      for (const it of items) out.push(...itemXml(it, '        ', opts));
      out.push(`      </${e.tag}>`, '    </RuleGroup>');
      wrote = true;
    }
    if (!wrote) out.push(`    <${e.tag} onmatch="include"/> <!-- no active rules: event not logged -->`);
  }
  out.push('', '  </EventFiltering>', '</Sysmon>', '');
  return out.join('\n');
}
