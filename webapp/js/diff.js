// Compare two configs rule by rule.

import { EVENTS, OPTIONS } from './schema.js';

const condSig = c => `${c.field}|${c.condition}|${String(c.value).toLowerCase()}`;
export function itemSig(item) {
  if (item.kind === 'cond') return condSig(item);
  return `rule:${item.relation}:[${item.conds.filter(c => c.enabled !== false).map(condSig).sort().join(',')}]`;
}

// Returns { events: [{ tag, modeA, modeB, include: {added, removed}, exclude: {added, removed} }], options: [...] }
// "added" = only in B, "removed" = only in A. Disabled items are ignored.
export function diffConfigs(a, b) {
  const events = [];
  for (const e of EVENTS) {
    const ea = a.events[e.tag] || { mode: 'unset', include: [], exclude: [] };
    const eb = b.events[e.tag] || { mode: 'unset', include: [], exclude: [] };
    const row = { tag: e.tag, modeA: ea.mode, modeB: eb.mode };
    let changed = ea.mode !== eb.mode;
    for (const k of ['include', 'exclude']) {
      const la = ea.mode === 'filtered' ? ea[k].filter(i => i.enabled !== false) : [];
      const lb = eb.mode === 'filtered' ? eb[k].filter(i => i.enabled !== false) : [];
      const sa = new Set(la.map(itemSig)), sb = new Set(lb.map(itemSig));
      row[k] = { added: lb.filter(i => !sa.has(itemSig(i))), removed: la.filter(i => !sb.has(itemSig(i))) };
      if (row[k].added.length || row[k].removed.length) changed = true;
    }
    if (changed) events.push(row);
  }
  const options = [];
  for (const o of OPTIONS) {
    const va = a.options[o.tag] ?? '', vb = b.options[o.tag] ?? '';
    if (String(va) !== String(vb)) options.push({ tag: o.tag, a: va, b: vb });
  }
  if (a.schemaversion !== b.schemaversion) options.push({ tag: 'schemaversion', a: a.schemaversion, b: b.schemaversion });
  return { events, options };
}

export function diffTotals(d) {
  let added = 0, removed = 0;
  for (const e of d.events) for (const k of ['include', 'exclude']) { added += e[k].added.length; removed += e[k].removed.length; }
  return { added, removed };
}

// One-paragraph summary for the changelog in the config header. `d` compares previous -> current.
export function changelogLine(d, version, date = new Date()) {
  const { added, removed } = diffTotals(d);
  const parts = [];
  const per = d.events.map(e => {
    const n = e.include.added.length + e.exclude.added.length, m = e.include.removed.length + e.exclude.removed.length;
    const bits = [];
    if (n) bits.push(`+${n}`);
    if (m) bits.push(`-${m}`);
    if (e.modeA !== e.modeB) bits.push(`${e.modeA}->${e.modeB}`);
    return bits.length ? `${e.tag} ${bits.join(' ')}` : null;
  }).filter(Boolean);
  if (added || removed) parts.push(`+${added}/-${removed} rules`);
  if (per.length) parts.push(per.join(', '));
  if (d.options.length) parts.push('settings: ' + d.options.map(o => o.tag).join(', '));
  return `${date.toISOString().slice(0, 10)} v${version}: ${parts.join('; ') || 'no rule changes'}`;
}

export function diffMarkdown(d, nameA, nameB) {
  const out = [`# Sysmon config diff`, '', `- **A:** ${nameA}`, `- **B:** ${nameB}`, ''];
  const { added, removed } = diffTotals(d);
  out.push(`${added} rules only in B, ${removed} rules only in A, ${d.events.length} event types differ.`, '');
  if (d.options.length) {
    out.push('## Settings', '', '| Setting | A | B |', '| --- | --- | --- |');
    for (const o of d.options) out.push(`| ${o.tag} | ${o.a || '(unset)'} | ${o.b || '(unset)'} |`);
    out.push('');
  }
  const desc = i => i.kind === 'cond' ? `\`${i.field} ${i.condition} ${i.value}\`` :
    `Rule "${i.name}" (${i.relation}): ` + i.conds.map(c => `\`${c.field} ${c.condition} ${c.value}\``).join(', ');
  for (const e of d.events) {
    out.push(`## ${e.tag}`, '');
    if (e.modeA !== e.modeB) out.push(`Mode: ${e.modeA} → ${e.modeB}`, '');
    for (const k of ['include', 'exclude']) {
      for (const i of e[k].added) out.push(`- **+ ${k}:** ${desc(i)}`);
      for (const i of e[k].removed) out.push(`- **− ${k}:** ${desc(i)}`);
    }
    out.push('');
  }
  return out.join('\n');
}
