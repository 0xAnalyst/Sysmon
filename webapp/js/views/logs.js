// Log analysis: load a sample of real Sysmon events, measure what the config would keep,
// rank the noisiest processes, and add exclusions with a safety rating.

import { EVENT_BY_TAG, imageFieldFor } from '../schema.js';
import { parseEvents, evaluate } from '../matcher.js';
import { WRITABLE } from '../validate.js';
import { newCond } from '../config.js';

const local = { name: '', events: [], spanHours: 0 };

function parseTime(t) {
  if (!t) return NaN;
  const s = /^\d{4}-\d{2}-\d{2} \d/.test(t) ? t.replace(' ', 'T') + 'Z' : t;
  return Date.parse(s);
}

function setSample(name, events) {
  local.name = name;
  local.events = events;
  const times = events.map(e => parseTime(e.time)).filter(Number.isFinite);
  local.spanHours = times.length > 1 ? (Math.max(...times) - Math.min(...times)) / 3.6e6 : 0;
}

async function readFile(file) {
  const buf = new Uint8Array(await file.arrayBuffer());
  // PowerShell redirects write UTF-16; detect the BOM.
  if (buf[0] === 0xff && buf[1] === 0xfe) return new TextDecoder('utf-16le').decode(buf);
  if (buf[0] === 0xfe && buf[1] === 0xff) return new TextDecoder('utf-16be').decode(buf);
  // Some tools write UTF-16LE without a BOM: most odd bytes are zero.
  const n = Math.min(buf.length, 4096);
  let zeros = 0;
  for (let i = 1; i < n; i += 2) if (buf[i] === 0) zeros++;
  return new TextDecoder(zeros > n / 4 ? 'utf-16le' : 'utf-8').decode(buf);
}

function safety(path, platform) {
  const p = String(path || '');
  if (!p) return ['review', 'No path'];
  if (WRITABLE.some(r => r.test(p))) return ['risky', 'User-writable location: malware could run from here and inherit the exclusion'];
  if (platform === 'linux' ? /^\/(usr\/)?s?bin\//.test(p) || /^\/usr\/lib\//.test(p) : /^c:\\(windows|program files( \(x86\))?)\\/i.test(p)) {
    return ['safer', 'Admin-writable location; exact path exclusion'];
  }
  return ['review', 'Check who can write to this folder'];
}

function analyse(cfg) {
  const perTag = new Map();
  const groups = new Map();
  const hits = new Map();
  let kept = 0, dropped = 0, deflt = 0;
  for (const ev of local.events) {
    const r = evaluate(cfg, ev);
    if (!r.tag) continue;
    const t = perTag.get(r.tag) || { total: 0, kept: 0, dropped: 0, deflt: 0 };
    t.total++;
    if (r.logged === true) { t.kept++; kept++; }
    else if (r.logged === false) { t.dropped++; dropped++; }
    else { t.deflt++; deflt++; }
    perTag.set(r.tag, t);
    for (const it of [r.include, r.exclude]) if (it) hits.set(it.id, (hits.get(it.id) || 0) + 1);
    if (r.logged === true && EVENT_BY_TAG[r.tag]) {
      const field = imageFieldFor(r.tag);
      const val = field ? ev.fields[field] || '(empty)' : '(n/a)';
      const key = `${r.tag}\u0000${val}`;
      const g = groups.get(key) || { tag: r.tag, field, value: val, count: 0 };
      g.count++;
      groups.set(key, g);
    }
  }
  return { perTag, top: [...groups.values()].sort((a, b) => b.count - a.count).slice(0, 30), kept, dropped, deflt, hits };
}

// For the overview table.
export function measuredVolume(ctx) {
  if (!local.events.length || local.spanHours < 1) return {};
  const a = analyse(ctx.state.cfg);
  const perDay = {};
  for (const [tag, t] of a.perTag) perDay[tag] = t.kept / local.spanHours * 24;
  return { perDay };
}

const fmt = n => Math.round(n).toLocaleString();

export function html(ctx) {
  const { h, state } = ctx;
  const cfg = state.cfg;
  const lin = cfg.platform === 'linux';
  const how = lin
    ? `<code>sudo journalctl -t sysmon --since "-24h" -o cat &gt; sysmon-sample.log</code>`
    : `<code>wevtutil qe Microsoft-Windows-Sysmon/Operational /c:50000 /rd:true /f:xml &gt; sysmon-sample.xml</code>`;
  let out = `<header><h2>Log analysis</h2>
    <p class="lede">Load real Sysmon events, ideally from a machine running a broad config, to see what this config would keep, where the volume comes from, and which processes are safe to exclude. Files are read in your browser and never uploaded.</p></header>
    <div class="callout info"><div><p><b>Get a sample:</b> ${how}</p>
      <p>Also accepted: <code>Get-WinEvent ... | % { $_.ToXml() }</code>, Splunk/Elastic/Sentinel exports as JSON or CSV with an EventID column.</p></div></div>
    <div class="toolbar"><button class="primary" data-act="logs-open">Open log files…</button>
      <input type="file" id="logs-file" multiple hidden accept=".xml,.json,.jsonl,.csv,.log,.txt">
      ${local.events.length ? `<button class="small" data-act="logs-clear">Clear sample</button>` : ''}
      <span class="count">${local.events.length ? `${h(local.name)} · ${fmt(local.events.length)} events${local.spanHours ? ` over ${local.spanHours < 48 ? local.spanHours.toFixed(1) + ' h' : (local.spanHours / 24).toFixed(1) + ' days'}` : ''}` : 'No sample loaded'}</span></div>`;
  if (!local.events.length) return out;

  const a = analyse(cfg);
  const perDay = n => local.spanHours >= 1 ? fmt(n / local.spanHours * 24) : '–';
  const pct = (n, d) => d ? `${Math.round(n / d * 100)}%` : '–';
  out += `<div class="stats">
      <div class="stat"><b>${fmt(a.kept)}</b><span>kept by this config (${pct(a.kept, local.events.length)})</span></div>
      <div class="stat"><b>${fmt(a.dropped)}</b><span>dropped</span></div>
      <div class="stat"><b>${fmt(a.deflt)}</b><span>event types not configured</span></div>
      <div class="stat"><b>${perDay(a.kept)}</b><span>kept per day, this sample</span></div>
    </div>
    <h3>Volume by event</h3>
    <div class="table-wrap"><table class="grid-table"><thead><tr><th>Event</th><th class="num">In sample</th><th class="num">Kept</th><th class="num">Dropped</th><th class="num">Kept / day</th></tr></thead><tbody>
    ${[...a.perTag.entries()].sort((x, y) => y[1].kept - x[1].kept).map(([tag, t]) =>
      `<tr data-jump="${tag}"><td>${h(tag)}</td><td class="num">${fmt(t.total)}</td><td class="num">${fmt(t.kept)}</td><td class="num">${fmt(t.dropped)}${t.deflt ? ` <small>(${fmt(t.deflt)} default)</small>` : ''}</td><td class="num">${perDay(t.kept)}</td></tr>`).join('')}
    </tbody></table></div>
    <h3>Noisiest processes still logged</h3>
    <p class="mode-help">Excluding by exact path is the narrowest option. "Risky" paths are user-writable, so an exclusion there also hides malware that runs from the same place.</p>
    <div class="table-wrap"><table class="grid-table"><thead><tr><th>Event</th><th>Process</th><th class="num">Events</th><th class="num">Share</th><th>Safety</th><th></th></tr></thead><tbody>
    ${a.top.map((g, i) => {
      const [lvl, why] = safety(g.value, cfg.platform);
      const canExclude = g.field && g.value !== '(empty)';
      return `<tr><td>${h(g.tag)}</td><td class="mono wrap">${h(g.value)}</td><td class="num">${fmt(g.count)}</td><td class="num">${pct(g.count, a.kept)}</td>
        <td><span class="safety ${lvl}" title="${h(why)}">${lvl}</span></td>
        <td>${canExclude ? `<button class="small" data-act="logs-exclude" data-idx="${i}">Exclude path</button>` : ''}</td></tr>`;
    }).join('') || '<tr><td colspan="6" class="empty">Nothing in this sample would be logged.</td></tr>'}
    </tbody></table></div>`;

  // Include rules that never matched anything in the sample.
  const quiet = [];
  for (const tag of a.perTag.keys()) {
    const ev = cfg.events[tag];
    if (ev?.mode !== 'filtered') continue;
    for (const it of ev.include) if (it.enabled !== false && !a.hits.has(it.id)) quiet.push({ tag, it });
  }
  out += `<details class="quiet"><summary>${quiet.length} include rules never matched in this sample</summary>
    <p class="mode-help">Normal for detection rules on clean machines. Useful to spot typos or rules written for a different path layout.</p>
    <ul>${quiet.slice(0, 200).map(q => `<li><a href="#" data-jump="${q.tag}" data-item="${q.it.id}">${h(q.tag)}: ${h(q.it.kind === 'cond' ? `${q.it.field} ${q.it.condition} ${q.it.value}` : q.it.name || 'rule')}</a></li>`).join('')}</ul></details>`;
  local.lastTop = a.top;
  return out;
}

export function click(act, btn, ctx) {
  if (act === 'logs-open') {
    const input = ctx.$('#logs-file');
    input.onchange = async () => {
      const files = [...input.files];
      if (!files.length) return;
      ctx.toast(`Reading ${files.length} file${files.length > 1 ? 's' : ''}…`);
      const events = [];
      for (const f of files) events.push(...parseEvents(await readFile(f)));
      if (!events.length) return ctx.toast('No Sysmon events found in those files.');
      setSample(files.map(f => f.name).join(', '), events);
      ctx.render();
    };
    input.click();
    return true;
  }
  if (act === 'logs-clear') { setSample('', []); ctx.render(); return true; }
  if (act === 'logs-exclude') {
    const g = local.lastTop?.[+btn.dataset.idx];
    if (!g) return true;
    const ev = ctx.state.cfg.events[g.tag];
    ctx.commit();
    if (ev.mode === 'all') ev.mode = 'filtered';
    ev.exclude.push(newCond(g.field, 'is', g.value, { comment: `Log analysis: ${g.count} events in sample` }));
    ctx.render();
    ctx.toast(`Excluded ${g.value} from ${g.tag}. Ctrl+Z to undo.`);
    return true;
  }
  return false;
}

