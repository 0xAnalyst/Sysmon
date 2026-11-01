import { EVENTS, EVENT_BY_TAG, CONDITIONS, OPTIONS, SCHEMA_VERSIONS, LATEST, BUILTIN, minSchemaForEvent, imageFieldFor, applyManifest } from './schema.js';
import { newConfig, newCond, newRule, parseXml, generateXml, escapeXml, activeCount } from './config.js';
import { validate } from './validate.js';
import { PRESETS, STARTERS, PRODUCTS } from './presets.js';
import { diffConfigs, changelogLine } from './diff.js';
import { encodeShare, hasShare, decodeShare, clearShare } from './share.js';
import * as tester from './views/tester.js';
import * as logs from './views/logs.js';
import * as coverageView from './views/coverage.js';
import * as compare from './views/compare.js';
import * as modulesView from './views/modules.js';
import * as detectionsView from './views/detections.js';
import * as deployView from './views/deploy.js';

const STORE_KEY = 'sysmon-builder:v1';
const SCHEMA_KEY = 'sysmon-builder:schema';
const $ = (sel, root = document) => root.querySelector(sel);
const h = escapeXml;

const VIEWS = { tester, logs, coverage: coverageView, compare, modules: modulesView, detections: detectionsView, deploy: deployView };

const state = {
  cfg: null,
  baseline: null,        // JSON of the config at the last import / download, for the changelog
  view: 'overview',
  search: '',
  issues: [],
  notes: [],
  undo: [],
  redo: [],
  typing: false,
  customSchema: null,
  wizard: { values: '', match: 'begin with', events: null, comment: '' },
};

// ------------------------------------------------------------------ storage

function save() {
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify({ cfg: state.cfg, view: state.view, baseline: state.baseline }));
  } catch { /* storage unavailable or full */ }
}
function restore() {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (!raw) return false;
    const { cfg, view, baseline } = JSON.parse(raw);
    if (!cfg?.events) return false;
    fillEvents(cfg);
    state.cfg = cfg;
    state.baseline = baseline || JSON.stringify(cfg);
    state.view = view || 'overview';
    return true;
  } catch { return false; }
}
function fillEvents(cfg) {
  for (const e of EVENTS) cfg.events[e.tag] ||= { mode: 'unset', include: [], exclude: [] };
}
function loadCustomSchema() {
  try {
    const s = JSON.parse(localStorage.getItem(SCHEMA_KEY) || 'null');
    if (s?.text) { state.customSchema = { ...applyManifest(s.text, s.platform), platform: s.platform }; }
  } catch { /* ignore a bad stored schema */ }
}

// ------------------------------------------------------------------ undo / redo

function commit() {
  state.undo.push(JSON.stringify(state.cfg));
  if (state.undo.length > 60) state.undo.shift();
  state.redo = [];
  updateUndoButtons();
}
function undo() {
  if (!state.undo.length) return toast('Nothing to undo.');
  state.redo.push(JSON.stringify(state.cfg));
  state.cfg = JSON.parse(state.undo.pop());
  fillEvents(state.cfg);
  render();
}
function redo() {
  if (!state.redo.length) return toast('Nothing to redo.');
  state.undo.push(JSON.stringify(state.cfg));
  state.cfg = JSON.parse(state.redo.pop());
  fillEvents(state.cfg);
  render();
}
function updateUndoButtons() {
  $('#undo').disabled = !state.undo.length;
  $('#redo').disabled = !state.redo.length;
}

// ------------------------------------------------------------------ helpers

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove('show'), 3600);
}

function eventsForPlatform() {
  return EVENTS.filter(e => e.platforms.includes(state.cfg.platform));
}

function findItem(id) {
  for (const e of EVENTS) {
    const ev = state.cfg.events[e.tag];
    for (const onmatch of ['include', 'exclude']) {
      const list = ev[onmatch];
      for (let i = 0; i < list.length; i++) {
        const it = list[i];
        if (it.id === id) return { item: it, list, index: i, tag: e.tag, onmatch };
        if (it.kind === 'rule') {
          const j = it.conds.findIndex(c => c.id === id);
          if (j >= 0) return { item: it.conds[j], list: it.conds, index: j, tag: e.tag, onmatch, parent: it };
        }
      }
    }
  }
  return null;
}

const issuesFor = tag => state.issues.filter(i => i.event === tag);
function worstLevel(list) {
  if (list.some(i => i.level === 'error')) return 'error';
  if (list.some(i => i.level === 'warn')) return 'warn';
  return list.length ? 'info' : null;
}
const ruleCount = ev => activeCount(ev.include) + activeCount(ev.exclude);
function isNewEvent(tag) {
  const src = parseFloat(state.cfg.sourceSchema || '0');
  return src > 0 && parseFloat(minSchemaForEvent(EVENT_BY_TAG[tag].ids[0])) > src;
}

function downloadText(name, text, type = 'text/plain') {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
async function copyText(text, what = 'Copied.') {
  try { await navigator.clipboard.writeText(text); toast(what); } catch { toast('Clipboard is blocked here; use Download.'); }
}

async function fetchPreset(id) {
  const p = PRESETS.find(x => x.id === id);
  for (const file of p?.files || []) {
    try {
      const res = await fetch(file);
      if (res.ok) return await res.text();
    } catch { /* try the next location */ }
  }
  return null;
}

function jumpTo(tag, itemId) {
  state.view = 'event:' + tag;
  state.search = '';
  render();
  if (itemId) focusRow(itemId);
}

// Context handed to the view modules.
const ctx = {
  state, h, $, toast, commit, render: () => render(), refresh: () => refresh(), findItem, jumpTo, eventsForPlatform,
  currentXml: () => currentXml(), downloadText, copyText, fetchPreset, PRESETS,
};

// ------------------------------------------------------------------ rendering: chrome

function renderTarget() {
  const c = state.cfg;
  const v = SCHEMA_VERSIONS.find(s => s.schema === c.schemaversion);
  $('#target-label').textContent = `${c.platform === 'linux' ? 'Linux' : 'Windows'} · schema ${c.schemaversion}` +
    (c.platform === 'windows' && v ? ` · Sysmon ${v.sysmon}` : '') + (state.customSchema ? ' · custom schema' : '');
}

function modePill(ev) {
  if (ev.mode === 'unset') return '<span class="pill">default</span>';
  if (ev.mode === 'off') return '<span class="pill off">off</span>';
  if (ev.mode === 'all') return '<span class="pill all">all</span>';
  return `<span class="pill filtered">${ruleCount(ev)}</span>`;
}

const NAV = [
  ['Configuration', [['overview', 'Overview & issues'], ['options', 'Global settings'], ['modules', 'Detection modules'], ['wizard', 'Exclusion wizard']]],
  ['Analyze', [['tester', 'Event tester'], ['logs', 'Log analysis'], ['coverage', 'ATT&CK coverage'], ['compare', 'Compare & merge']]],
  ['Export', [['detections', 'SIEM & Sigma'], ['deploy', 'Deployment scripts']]],
];

function renderSidebar() {
  const counts = { error: 0, warn: 0, info: 0 };
  for (const i of state.issues) counts[i.level]++;
  const issuePill = counts.error ? `<span class="pill err">${counts.error}</span>` : counts.warn ? `<span class="pill warn">${counts.warn}</span>` : '<span class="pill">0</span>';
  const item = (view, label, right = '') =>
    `<button class="nav-item plain ${state.view === view ? 'active' : ''}" data-view="${view}"><span class="ename">${h(label)}</span>${right}</button>`;

  let html = '';
  for (const [title, items] of NAV) {
    html += `<h2>${title}</h2>`;
    for (const [view, label] of items) {
      if (view === 'wizard' && state.cfg.platform !== 'windows') continue;
      html += item(view, label, view === 'overview' ? issuePill : '');
    }
  }
  html += '<h2>Events</h2>';
  for (const e of eventsForPlatform()) {
    const ev = state.cfg.events[e.tag];
    const lvl = worstLevel(issuesFor(e.tag).filter(i => i.level !== 'info'));
    let right = modePill(ev);
    if (lvl === 'error') right = '<span class="pill err">!</span>';
    else if (ev.mode === 'unset' && isNewEvent(e.tag)) right = '<span class="pill new">new</span>';
    html += `<button class="nav-item ${state.view === 'event:' + e.tag ? 'active' : ''}" data-view="event:${e.tag}" title="${h(e.tag)}">
      <span class="eid">${e.ids.join(',')}</span><span class="ename">${h(e.title)}</span>${right}</button>`;
  }
  $('#sidebar').innerHTML = html;
}

function highlight(xml) {
  return h(xml)
    .replace(/&lt;!--[\s\S]*?--&gt;/g, m => `\u0001${m}\u0002`)
    .replace(/(&lt;\/?)([\w]+)/g, (m, a, b) => `${a}<span class="t">${b}</span>`)
    .replace(/(\s)([\w]+)=(&quot;.*?&quot;)/g, '$1<span class="a">$2</span>=<span class="s">$3</span>')
    .replace(/\u0001([\s\S]*?)\u0002/g, (m, c) => `<span class="c">${c.replace(/<[^>]+>/g, '')}</span>`);
}

function currentXml() {
  return generateXml(state.cfg, { comments: $('#opt-comments').checked, keepDisabled: $('#opt-disabled').checked });
}

function renderPreview() {
  if ($('#layout').classList.contains('no-preview')) return;
  $('#xml code').innerHTML = highlight(currentXml());
  const lin = state.cfg.platform === 'linux';
  $('#deploy').innerHTML = lin
    ? `<p>Install / update on Linux:</p><code>sudo sysmon -accepteula -i sysmonconfig-linux.xml</code><code>sudo sysmon -c sysmonconfig-linux.xml</code>`
    : `<p>Install / update on Windows (elevated):</p><code>Sysmon64.exe -accepteula -i sysmonconfig.xml</code><code>Sysmon64.exe -c sysmonconfig.xml</code>`;
}

// Cheap refresh after field edits: everything except the main panel.
function refresh() {
  state.issues = validate(state.cfg);
  renderTarget();
  renderSidebar();
  renderPreview();
  markRowIssues();
  if (state.view === 'overview') renderOverviewIssues();
  updateUndoButtons();
  save();
}
const refreshSoon = (() => { let t; return () => { clearTimeout(t); t = setTimeout(refresh, 180); }; })();

function render() {
  state.issues = validate(state.cfg);
  renderTarget();
  renderSidebar();
  renderMain();
  renderPreview();
  updateUndoButtons();
  save();
}

// ------------------------------------------------------------------ main views

function renderMain() {
  const main = $('#main');
  const [kind, tag] = state.view.split(':');
  if (kind === 'event' && EVENT_BY_TAG[tag]) main.innerHTML = eventView(tag);
  else if (kind === 'options') main.innerHTML = optionsView();
  else if (kind === 'wizard') main.innerHTML = wizardView();
  else if (VIEWS[kind]) main.innerHTML = notesHtml() + VIEWS[kind].html(ctx);
  else { state.view = 'overview'; main.innerHTML = overviewView(); renderOverviewIssues(); }
  if (kind === 'event') { applySearch(); markRowIssues(); }
  VIEWS[kind]?.after?.(ctx);
}

function notesHtml() {
  if (!state.notes.length) return '';
  return `<div class="callout info"><div>${state.notes.map(n => `<p>${h(n)}</p>`).join('')}</div>
    <button class="small" data-act="dismiss-notes">Dismiss</button></div>`;
}

// Rough volume when an event logs everything, for a typical workstation.
const VOLUME = {
  ProcessCreate: 'Medium', FileCreateTime: 'Medium', NetworkConnect: 'Very high', ProcessTerminate: 'Medium', DriverLoad: 'Low',
  ImageLoad: 'Very high', CreateRemoteThread: 'Low', RawAccessRead: 'Low', ProcessAccess: 'Very high', FileCreate: 'Very high',
  RegistryEvent: 'Very high', FileCreateStreamHash: 'Medium', PipeEvent: 'High', WmiEvent: 'Low', DnsQuery: 'High',
  FileDelete: 'High + disk', ClipboardChange: 'Medium', ProcessTampering: 'Low', FileDeleteDetected: 'High',
  FileBlockExecutable: 'Low', FileBlockShredding: 'Low', FileExecutableDetected: 'Low',
};
function volumeLabel(tag) {
  const ev = state.cfg.events[tag];
  const base = VOLUME[tag] || 'Unknown';
  if (ev.mode === 'off') return ['None', 'off'];
  if (ev.mode === 'unset') return ['Sysmon default', ''];
  if (ev.mode === 'all') return [base, base.startsWith('Very') ? 'hot' : ''];
  if (activeCount(ev.include)) return ['Low (include rules)', 'cool'];
  if (activeCount(ev.exclude)) return [`${base}, minus exclusions`, base.startsWith('Very') ? 'warm' : ''];
  return ['None', 'off'];
}

function overviewView() {
  const c = state.cfg;
  const evs = eventsForPlatform();
  const configured = evs.filter(e => c.events[e.tag].mode !== 'unset').length;
  const rules = evs.reduce((n, e) => n + ruleCount(c.events[e.tag]), 0);
  const newOnes = evs.filter(e => c.events[e.tag].mode === 'unset' && isNewEvent(e.tag));
  const counts = { error: 0, warn: 0, info: 0 };
  for (const i of state.issues) counts[i.level]++;
  const measured = logs.measuredVolume?.(ctx) || {};

  return `${notesHtml()}
    <header><h2>Overview</h2>
    <p class="lede">Pick an event on the left to tune its rules, or use the tools under Analyze to test the config against real events and logs. Everything stays in this browser; <kbd>?</kbd> shows keyboard shortcuts.</p></header>
    <div class="stats">
      <div class="stat"><b>${configured}/${evs.length}</b><span>events configured</span></div>
      <div class="stat"><b>${rules}</b><span>active rules</span></div>
      <div class="stat"><b style="color:var(--error)">${counts.error}</b><span>errors</span></div>
      <div class="stat"><b style="color:var(--warn)">${counts.warn}</b><span>warnings</span></div>
    </div>
    ${newOnes.length ? `<div class="callout"><p><b>${newOnes.length} event type${newOnes.length > 1 ? 's' : ''} added since schema ${h(c.sourceSchema)}</b> are not configured: ${newOnes.map(e => h(e.tag)).join(', ')}.</p>
      <button class="small primary" data-act="apply-all-starters">Apply recommended starters</button></div>` : ''}
    <h3>Events and expected volume</h3>
    <div class="table-wrap"><table class="grid-table">
      <thead><tr><th>ID</th><th>Event</th><th>Mode</th><th class="num">Include</th><th class="num">Exclude</th><th>Expected volume</th>${measured.perDay ? '<th class="num">Measured / day</th>' : ''}</tr></thead>
      <tbody>${evs.map(e => {
        const ev = c.events[e.tag];
        const [vol, cls] = volumeLabel(e.tag);
        const m = measured.perDay?.[e.tag];
        return `<tr data-jump="${e.tag}"><td class="mono">${e.ids.join(',')}</td><td>${h(e.tag)}</td><td>${modePill(ev)}</td>
          <td class="num">${ev.mode === 'filtered' ? activeCount(ev.include) : '–'}</td><td class="num">${ev.mode === 'filtered' ? activeCount(ev.exclude) : '–'}</td>
          <td><span class="vol ${cls}">${vol}</span></td>${measured.perDay ? `<td class="num">${m === undefined ? '–' : Math.round(m).toLocaleString()}</td>` : ''}</tr>`;
      }).join('')}</tbody></table></div>
    <p class="mode-help">Expected volume is a rough guide for one workstation. Load a log sample under <a href="#" data-view="logs">Log analysis</a> to measure it.</p>
    <h3>Issues</h3><div class="issues" id="issue-list"></div>`;
}

function renderOverviewIssues() {
  const el = $('#issue-list');
  if (!el) return;
  const order = { error: 0, warn: 1, info: 2 };
  const list = [...state.issues].sort((a, b) => order[a.level] - order[b.level]);
  el.innerHTML = list.length ? list.map(i => `<button class="issue ${i.level}" data-jump="${i.event || ''}" data-item="${i.itemId || ''}">
      <span class="lvl">${i.level}</span><span class="ev">${h(i.event || 'global')}</span><span class="msg">${h(i.msg)}</span></button>`).join('')
    : '<p class="empty">No issues found.</p>';
}

const MODE_HELP = {
  unset: 'Not in the config: Sysmon uses its built-in default for this event.',
  off: 'Nothing is logged (written as an empty include filter).',
  all: 'Every event is logged (written as an empty exclude filter).',
  filtered: 'Include rules pick what to log; exclude rules remove matches and always win. With only exclude rules, everything else is logged.',
};

function eventView(tag) {
  const e = EVENT_BY_TAG[tag];
  const ev = state.cfg.events[tag];
  const starter = STARTERS[tag];
  const min = minSchemaForEvent(e.ids[0]);
  const modes = [['unset', 'Not set'], ['off', 'Off'], ['all', 'Log all'], ['filtered', 'Filtered']];
  let html = `${notesHtml()}<header>
    <h2>${h(e.title)} <code>${e.tag} · Event ID ${e.ids.join(', ')}${min !== '4.00' ? ` · schema ${min}+` : ''}</code></h2>
    <p class="lede">${h(e.help)}</p>
    <div class="modes" role="group" aria-label="Logging mode">${modes.map(([m, l]) =>
      `<button data-act="mode" data-mode="${m}" aria-pressed="${ev.mode === m}">${l}</button>`).join('')}</div>
    <p class="mode-help">${MODE_HELP[ev.mode]}</p></header>`;

  if (starter && (ev.mode === 'unset' || isNewEvent(tag) && !ruleCount(ev))) {
    html += `<div class="callout"><p><b>Recommended start:</b> ${h(starter.desc)}</p>
      <button class="small primary" data-act="starter">Apply</button></div>`;
  }
  if (ev.mode !== 'filtered') {
    const n = ev.include.length + ev.exclude.length;
    if (n) html += `<p class="mode-help">${n} saved rule${n > 1 ? 's are' : ' is'} kept but not written while the mode is not "Filtered".</p>`;
    return html;
  }

  html += `<div class="toolbar"><input type="search" id="search" placeholder="Filter rules by value, field, comment… ( / )" value="${h(state.search)}">
    <span class="count" id="search-count"></span></div>`;
  for (const onmatch of ['include', 'exclude']) {
    const list = ev[onmatch];
    const hint = onmatch === 'include' ? 'Log only events matching any of these.' : 'Drop events matching any of these. Overrides include.';
    html += `<section class="list ${onmatch}" data-list="${onmatch}">
      <header><h3>${onmatch}</h3><span class="hint">${hint} ${activeCount(list)} active.</span>
        <button class="small" data-act="add-cond" data-onmatch="${onmatch}">+ Condition</button>
        <button class="small" data-act="add-rule" data-onmatch="${onmatch}">+ AND rule</button></header>
      ${list.length ? list.map(it => itemHtml(it, e)).join('') : '<div class="empty">No rules.</div>'}
    </section>`;
  }
  return html;
}

function fieldOptions(e, current) {
  const fields = e.fields.includes(current) ? e.fields : [current, ...e.fields];
  return fields.map(f => `<option ${f === current ? 'selected' : ''}>${h(f)}</option>`).join('');
}
function condOptions(current) {
  const names = CONDITIONS.map(c => c.name);
  const all = names.includes(current) ? names : [current, ...names];
  return all.map(c => `<option ${c === current ? 'selected' : ''} title="${h(CONDITIONS.find(x => x.name === c)?.help || '')}">${h(c)}</option>`).join('');
}

// Big lists render each dropdown with only its current value; the full option list is
// filled in when the dropdown is first focused or clicked.
function fillLazySelect(ev) {
  const sel = ev.target;
  if (sel.tagName !== 'SELECT' || !sel.dataset.lazy) return;
  const tag = state.view.startsWith('event:') ? state.view.slice(6) : null;
  if (!tag) return;
  sel.innerHTML = sel.dataset.lazy === 'field' ? fieldOptions(EVENT_BY_TAG[tag], sel.value) : condOptions(sel.value);
  delete sel.dataset.lazy;
}

function sectionsHtml(item) {
  return (item.before || []).map((b, i) => `<div class="section" data-sec-of="${item.id}"><span>${h(b)}</span>
    <button class="ghost small" data-act="del-section" data-id="${item.id}" data-idx="${i}" title="Remove comment">✕</button></div>`).join('');
}

const grip = id => `<span class="grip" draggable="true" data-drag="${id}" title="Drag to reorder" aria-hidden="true">⋮⋮</span>`;

function condHtml(c, e, inRule) {
  const showName = c.name || c.showName;
  return `${sectionsHtml(c)}<div class="row ${c.enabled ? '' : 'disabled'}" data-id="${c.id}">
    ${grip(c.id)}
    <input class="on" type="checkbox" ${c.enabled ? 'checked' : ''} data-k="enabled" title="Enabled" aria-label="Enabled">
    <select data-k="field" data-lazy="field" aria-label="Field"><option selected>${h(c.field)}</option></select>
    <select data-k="condition" data-lazy="condition" aria-label="Condition"><option selected>${h(c.condition)}</option></select>
    <input class="value" data-k="value" value="${h(c.value)}" spellcheck="false" aria-label="Value">
    <input class="note" data-k="comment" value="${h(c.comment)}" placeholder="comment" aria-label="Comment">
    <button class="icon" data-act="tag" data-id="${c.id}" title="RuleName tag (e.g. MITRE technique)">#</button>
    ${inRule ? '<span></span>' : `<button class="icon" data-act="move" data-id="${c.id}" title="Move to the other list">⇅</button>`}
    <button class="icon" data-act="del" data-id="${c.id}" title="Delete">✕</button>
    ${showName ? `<div class="tagname">name=<input data-k="name" value="${h(c.name)}" placeholder="technique_id=T1059,technique_name=…" aria-label="Rule name"></div>` : ''}
  </div>`;
}

function itemHtml(it, e) {
  if (it.kind === 'cond') return condHtml(it, e, false);
  return `${sectionsHtml(it)}<div class="rule ${it.enabled ? '' : 'disabled'}" data-id="${it.id}">
    <div class="rule-head" data-id="${it.id}">
      ${grip(it.id)}
      <input class="on" type="checkbox" ${it.enabled ? 'checked' : ''} data-k="enabled" aria-label="Rule enabled">
      <input class="rname" data-k="name" value="${h(it.name)}" placeholder="Rule name (e.g. TechniqueID=T1059)" aria-label="Rule name">
      <select data-k="relation" aria-label="Combine conditions with">
        <option value="and" ${it.relation === 'and' ? 'selected' : ''}>ALL must match (and)</option>
        <option value="or" ${it.relation === 'or' ? 'selected' : ''}>ANY may match (or)</option></select>
      <span class="badge">${it.conds.length} cond</span>
      <button class="small ghost" data-act="move" data-id="${it.id}" title="Move to the other list">⇅</button>
      <button class="small ghost" data-act="del" data-id="${it.id}" title="Delete rule">✕</button>
    </div>
    ${it.conds.map(c => condHtml(c, e, true)).join('')}
    <div class="rule-foot"><button class="small" data-act="add-cond-in" data-id="${it.id}">+ Condition</button></div>
  </div>`;
}

function markRowIssues() {
  const main = $('#main');
  main.querySelectorAll('.issue-error,.issue-warn,.issue-info').forEach(r => {
    r.classList.remove('issue-error', 'issue-warn', 'issue-info');
    r.removeAttribute('title');
  });
  const by = new Map();
  for (const i of state.issues) if (i.itemId) (by.get(i.itemId) || by.set(i.itemId, []).get(i.itemId)).push(i);
  for (const [id, list] of by) {
    const row = main.querySelector(`.row[data-id="${id}"], .rule[data-id="${id}"] > .rule-head`);
    if (!row) continue;
    row.classList.add('issue-' + worstLevel(list));
    row.title = list.map(i => `${i.level.toUpperCase()}: ${i.msg}`).join('\n');
  }
}

function applySearch() {
  const q = state.search.trim().toLowerCase();
  const main = $('#main');
  let shown = 0, total = 0;
  main.querySelectorAll('.list > .row, .list > .rule').forEach(el => {
    total++;
    const text = [...el.querySelectorAll('input, select')].map(i => i.value).join(' ').toLowerCase();
    const hit = !q || text.includes(q);
    el.hidden = !hit;
    main.querySelectorAll(`[data-sec-of="${el.dataset.id}"]`).forEach(s => (s.hidden = !hit || !!q));
    if (hit) shown++;
  });
  const cnt = $('#search-count');
  if (cnt) cnt.textContent = q ? `${shown} of ${total} shown` : `${total} rules`;
}

function optionsView() {
  const c = state.cfg;
  const opts = OPTIONS.filter(o => o.platforms.includes(c.platform));
  const schemaOpts = SCHEMA_VERSIONS.slice().reverse().map(s =>
    `<option value="${s.schema}" ${s.schema === c.schemaversion ? 'selected' : ''}>${s.schema} (Sysmon ${s.sysmon})</option>`).join('');
  const custom = SCHEMA_VERSIONS.some(s => s.schema === c.schemaversion) ? '' : `<option selected>${h(c.schemaversion)}</option>`;
  const cs = state.customSchema;

  const optField = o => {
    const v = c.options[o.tag];
    let input;
    if (o.type === 'bool') {
      input = `<select data-opt="${o.tag}"><option value="" ${v === undefined || v === '' ? 'selected' : ''}>(default)</option>
        <option ${v === 'True' ? 'selected' : ''}>True</option><option ${v === 'False' ? 'selected' : ''}>False</option></select>`;
    } else if (o.type === 'flag') {
      input = `<label><input type="checkbox" data-opt="${o.tag}" ${v ? 'checked' : ''}> Enabled</label>`;
    } else if (o.type === 'hashes') {
      const set = new Set((v || '').split(',').map(s => s.trim().toUpperCase()).filter(Boolean));
      input = `<div class="chips">${['MD5', 'SHA1', 'SHA256', 'IMPHASH', '*'].map(a =>
        `<button class="chip" data-act="hash" data-alg="${a}" aria-pressed="${set.has(a)}">${a === '*' ? '* (all)' : a}</button>`).join('')}</div>`;
    } else {
      input = `<input type="text" data-opt="${o.tag}" value="${h(v ?? '')}" placeholder="${h(o.placeholder || '')}">`;
    }
    return `<div class="field"><label>${o.tag}</label><div>${input}<div class="help">${h(o.help)}</div></div></div>`;
  };

  return `${notesHtml()}<header><h2>Global settings</h2><p class="lede">Top-level entries of the config, the schema the XML is written for, and the file header.</p></header>
  <div class="form">
    <div class="field"><label>Platform</label><div><select id="platform">
      <option value="windows" ${c.platform === 'windows' ? 'selected' : ''}>Windows (Sysmon ${LATEST.windows.sysmon})</option>
      <option value="linux" ${c.platform === 'linux' ? 'selected' : ''}>Linux (Sysmon for Linux)</option></select>
      <div class="help">Events and settings that the platform does not support are left out of the output.</div></div></div>
    <div class="field"><label>Schema version</label><div><select id="schema">${custom}${schemaOpts}</select>
      <div class="help">Use the newest schema your fleet's Sysmon binary supports. Latest known: ${LATEST[c.platform].schema}.</div></div></div>
    <div class="field"><label>Exact schema</label><div>
      ${cs ? `<p class="help ok">Using the schema from <code>sysmon -s</code>: binary ${h(cs.binaryversion || '?')}, schema ${h(cs.schemaversion)}, ${cs.events} event types (${h(cs.platform)}).${cs.added.length ? ` New: ${h(cs.added.join(', '))}.` : ''}</p>
        <button class="small" data-act="schema-clear">Go back to the built-in schema</button>`
      : `<textarea id="schema-text" spellcheck="false" placeholder="Paste the output of: Sysmon64.exe -s"></textarea>
        <div class="help">Paste the output of <code>sysmon -s</code> from the binary you deploy, so field and event checks match it exactly, including events newer than this builder knows.</div>
        <button class="small" data-act="schema-apply">Use this schema</button>`}
    </div></div>
    ${opts.map(optField).join('')}
    <div class="field"><label>Header comment</label><div><textarea id="header" spellcheck="false">${h(c.header)}</textarea>
      <div class="help">Written at the top of the file. Good place for version, owner and change notes.</div></div></div>
    <div class="field"><label>Changelog</label><div>
      <label><input type="checkbox" id="changelog" ${c.changelog !== false ? 'checked' : ''}> Add a changelog line to the header on each download</label>
      <div class="help">Summarises rule changes since the last import or download, and bumps the config version (now v${c.version || 1}).</div></div></div>
  </div>`;
}

function wizardView() {
  const w = state.wizard;
  const evs = eventsForPlatform().filter(e => imageFieldFor(e.tag));
  if (!w.events) w.events = evs.filter(e => !['ProcessCreate', 'ProcessTerminate', 'FileBlockExecutable', 'FileBlockShredding', 'FileDelete'].includes(e.tag)).map(e => e.tag);
  const matches = [
    ['begin with', 'Folder', 'Everything under an install folder, e.g. C:\\Program Files\\CrowdStrike\\'],
    ['is', 'Exact path', 'One binary, e.g. C:\\Program Files\\Agent\\agent.exe'],
    ['image', 'Image name', 'Binary name anywhere on disk, e.g. agent.exe. Easiest to spoof.'],
  ];
  return `${notesHtml()}<header><h2>Exclusion wizard</h2>
    <p class="lede">Add the same process exclusion to many events at once: typical for AV/EDR, backup and monitoring agents that flood ImageLoad, ProcessAccess, Registry and Network events.</p></header>
  <div class="form">
    <div class="field"><label>Common products</label><div><div class="chips">${PRODUCTS.map((p, i) =>
      `<button class="chip" data-act="product" data-idx="${i}">${h(p.label)}</button>`).join('')}</div>
      <div class="help">Adds the product's default install folders below. Check the paths against your environment.</div></div></div>
    <div class="field"><label for="wz-values">Processes / folders</label><div>
      <textarea id="wz-values" spellcheck="false" placeholder="C:\\Program Files\\Vendor\\Agent\\">${h(w.values)}</textarea>
      <div class="help">One per line.</div></div></div>
    <div class="field"><label>Match as</label><div class="radios">${matches.map(([v, l, d]) =>
      `<label><input type="radio" name="wz-match" value="${v}" ${w.match === v ? 'checked' : ''}> <span><b>${l}</b> <small>${h(d)}</small></span></label>`).join('')}</div></div>
    <div class="field"><label>Events</label><div>
      <div class="checks">${evs.map(e => {
        const m = state.cfg.events[e.tag].mode;
        return `<label><input type="checkbox" name="wz-ev" value="${e.tag}" ${w.events.includes(e.tag) ? 'checked' : ''}> ${h(e.tag)} <small>${imageFieldFor(e.tag)} · ${m === 'unset' ? 'not set' : m}</small></label>`;
      }).join('')}</div>
      <div class="help">Exclusions are only added to events that are "Filtered" or "Log all". Adding one to an Off or Not-set event would turn it on.</div></div></div>
    <div class="field"><label for="wz-comment">Comment</label><div><input type="text" id="wz-comment" value="${h(w.comment)}" placeholder="e.g. CrowdStrike Falcon sensor"></div></div>
    <div class="field"><span></span><div><button class="primary" data-act="wizard-apply">Add exclusions</button></div></div>
  </div>`;
}

// ------------------------------------------------------------------ actions

function applyStarter(tag) {
  const s = STARTERS[tag];
  if (!s) return;
  const ev = state.cfg.events[tag];
  ev.mode = s.mode;
  if (s.include) ev.include.push(...s.include());
  if (s.exclude) ev.exclude.push(...s.exclude());
}

function addCond(tag, onmatch) {
  const e = EVENT_BY_TAG[tag];
  const field = e.fields.find(f => /Image|TargetFilename|TargetObject|QueryName|PipeName/.test(f)) || e.fields[1];
  const c = newCond(field, 'is', '');
  state.cfg.events[tag][onmatch].unshift(c);
  render();
  focusRow(c.id);
}

function focusRow(id) {
  const row = $(`#main [data-id="${id}"]`);
  if (!row) return;
  row.hidden = false;
  row.scrollIntoView({ block: 'center' });
  row.classList.add('flash');
  (row.querySelector('input.value') || row.querySelector('input.rname'))?.focus();
}

function wizardApply() {
  const w = state.wizard;
  const values = w.values.split('\n').map(s => s.trim()).filter(Boolean);
  if (!values.length) return toast('Add at least one process or folder.');
  if (!w.events.length) return toast('Select at least one event.');
  commit();
  let added = 0;
  const touched = [], skipped = [];
  for (const tag of w.events) {
    const ev = state.cfg.events[tag];
    if (ev.mode === 'off' || ev.mode === 'unset') { skipped.push(tag); continue; }
    const field = imageFieldFor(tag);
    let n = 0;
    for (const v of values) {
      const dup = ev.exclude.some(i => i.kind === 'cond' && i.field === field && i.condition === w.match && i.value.toLowerCase() === v.toLowerCase());
      if (dup) continue;
      ev.exclude.push(newCond(field, w.match, v, { comment: w.comment }));
      n++;
    }
    if (n) { added += n; touched.push(tag); if (ev.mode === 'all') ev.mode = 'filtered'; }
  }
  render();
  toast(`Added ${added} exclusion${added === 1 ? '' : 's'} to ${touched.length} event${touched.length === 1 ? '' : 's'}.` +
    (skipped.length ? ` Skipped (off / not set): ${skipped.join(', ')}.` : ''));
}

async function loadPreset(id) {
  const p = PRESETS.find(x => x.id === id);
  if (!p) return;
  if (state.cfg) commit();
  if (p.platform) {
    state.cfg = newConfig(p.platform);
    state.notes = [];
    state.baseline = JSON.stringify(state.cfg);
    state.view = 'overview';
    render();
    return toast(`Loaded: ${p.label}`);
  }
  const text = await fetchPreset(id);
  if (text === null) return toast(`Could not load the ${p.label} preset. Serve the repo over HTTP, not file://.`);
  importXml(text, p.note, false);
}

function importXml(text, note, announce = true) {
  try {
    const { config, notes } = parseXml(text);
    if (state.cfg && announce) commit();
    state.cfg = config;
    state.baseline = JSON.stringify(config);
    state.notes = note ? [note, ...notes] : notes;
    state.view = 'overview';
    state.search = '';
    render();
    const n = eventsForPlatform().reduce((s, e) => s + ruleCount(config.events[e.tag]), 0);
    toast(`${announce ? 'Imported' : 'Loaded'} ${n} rules (${config.platform}, source schema ${config.sourceSchema || '?'}).`);
  } catch (err) {
    toast(err.message);
  }
}

function download() {
  const c = state.cfg;
  if (c.changelog !== false && state.baseline) {
    const d = diffConfigs(JSON.parse(state.baseline), c);
    if (d.events.length || d.options.length) {
      commit();
      c.version = (c.version || 1) + 1;
      let header = c.header || '';
      if (!/^\s*Changelog:/m.test(header)) header = (header ? header.replace(/\s+$/, '') + '\n\n' : '') + '  Changelog:';
      c.header = `${header}\n    ${changelogLine(d, c.version)}`;
    }
  }
  downloadText(c.platform === 'linux' ? 'sysmonconfig-linux.xml' : 'sysmonconfig.xml', currentXml(), 'application/xml');
  state.baseline = JSON.stringify(c);
  render();
  const errs = state.issues.filter(i => i.level === 'error').length;
  if (errs) toast(`Downloaded, but there ${errs === 1 ? 'is 1 error' : `are ${errs} errors`}. Sysmon may reject the file.`);
}

async function share() {
  try {
    const url = await encodeShare(generateXml(state.cfg, { comments: true, keepDisabled: true }));
    await copyText(url, `Share link copied (${Math.round(url.length / 1024)} KB). The config is inside the link; nothing is uploaded.`);
  } catch (err) {
    toast('Could not create a share link: ' + err.message);
  }
}

// Drag and drop reordering within one list.
let dragId = null;
function onDragStart(ev) {
  const g = ev.target.closest?.('[data-drag]');
  if (!g) return;
  dragId = g.dataset.drag;
  ev.dataTransfer.effectAllowed = 'move';
  ev.dataTransfer.setData('text/plain', dragId);
  g.closest('.row, .rule')?.classList.add('dragging');
}
function dropTarget(ev) {
  if (!dragId) return null;
  const el = ev.target.closest?.('.row[data-id], .rule[data-id]');
  if (!el || el.dataset.id === dragId) return null;
  const a = findItem(dragId), b = findItem(el.dataset.id);
  return a && b && a.list === b.list ? { el, a, b } : null;
}
function onDragOver(ev) {
  const t = dropTarget(ev);
  if (!t) return;
  ev.preventDefault();
  document.querySelectorAll('.drop-before').forEach(x => x.classList.remove('drop-before'));
  t.el.classList.add('drop-before');
}
function onDrop(ev) {
  const t = dropTarget(ev);
  if (!t) return;
  ev.preventDefault();
  commit();
  const [moved] = t.a.list.splice(t.a.index, 1);
  t.a.list.splice(t.a.list.indexOf(t.b.item), 0, moved);
  dragId = null;
  render();
}
function onDragEnd() {
  dragId = null;
  document.querySelectorAll('.drop-before, .dragging').forEach(x => x.classList.remove('drop-before', 'dragging'));
}

// ------------------------------------------------------------------ events

function onClick(ev) {
  const nav = ev.target.closest('[data-view]');
  if (nav) {
    ev.preventDefault();
    state.view = nav.dataset.view;
    state.search = '';
    render();
    $('#main').scrollTop = 0;
    return;
  }
  const jump = ev.target.closest('[data-jump]');
  if (jump && !ev.target.closest('[data-act]')) {
    ev.preventDefault();
    if (jump.dataset.jump) jumpTo(jump.dataset.jump, jump.dataset.item);
    else { state.view = 'options'; render(); }
    return;
  }
  const btn = ev.target.closest('[data-act]');
  if (!btn) return;
  const act = btn.dataset.act;
  const [kind] = state.view.split(':');
  if (VIEWS[kind]?.click?.(act, btn, ctx)) return;
  const tag = state.view.startsWith('event:') ? state.view.slice(6) : null;

  switch (act) {
    case 'mode': commit(); state.cfg.events[tag].mode = btn.dataset.mode; return render();
    case 'starter': commit(); applyStarter(tag); return render();
    case 'apply-all-starters': {
      commit();
      const done = [];
      for (const e of eventsForPlatform()) {
        if (state.cfg.events[e.tag].mode === 'unset' && isNewEvent(e.tag) && STARTERS[e.tag]) { applyStarter(e.tag); done.push(e.tag); }
      }
      render();
      return toast(`Applied starters: ${done.join(', ') || 'none'}.`);
    }
    case 'dismiss-notes': state.notes = []; return render();
    case 'add-cond': commit(); return addCond(tag, btn.dataset.onmatch);
    case 'add-rule': {
      commit();
      const r = newRule('and');
      const e = EVENT_BY_TAG[tag];
      r.conds.push(newCond(e.fields.includes('Image') ? 'Image' : e.fields[1], 'end with', ''));
      state.cfg.events[tag][btn.dataset.onmatch].unshift(r);
      render();
      return focusRow(r.id);
    }
    case 'add-cond-in': {
      commit();
      const f = findItem(btn.dataset.id);
      const c = newCond(f.item.conds[0]?.field || 'Image', 'is', '');
      f.item.conds.push(c);
      render();
      return focusRow(c.id);
    }
    case 'del': {
      const f = findItem(btn.dataset.id);
      if (!f) return;
      commit();
      const removed = f.list.splice(f.index, 1)[0];
      // Keep section comments by handing them to the next item.
      if (removed.before?.length && f.list[f.index]) f.list[f.index].before = [...removed.before, ...f.list[f.index].before];
      render();
      return toast('Rule deleted. Ctrl+Z to undo.');
    }
    case 'move': {
      const f = findItem(btn.dataset.id);
      if (!f || f.parent) return;
      commit();
      f.list.splice(f.index, 1);
      const other = f.onmatch === 'include' ? 'exclude' : 'include';
      state.cfg.events[f.tag][other].unshift(f.item);
      render();
      focusRow(f.item.id);
      return toast(`Moved to ${other}.`);
    }
    case 'tag': {
      const f = findItem(btn.dataset.id);
      f.item.showName = !f.item.showName || !!f.item.name;
      render();
      return $(`#main .row[data-id="${f.item.id}"] .tagname input`)?.focus();
    }
    case 'del-section': {
      commit();
      findItem(btn.dataset.id).item.before.splice(+btn.dataset.idx, 1);
      return render();
    }
    case 'hash': {
      commit();
      const alg = btn.dataset.alg;
      let set = new Set((state.cfg.options.HashAlgorithms || '').split(',').map(s => s.trim().toUpperCase()).filter(Boolean));
      if (alg === '*') set = set.has('*') ? new Set() : new Set(['*']);
      else { set.delete('*'); set.has(alg) ? set.delete(alg) : set.add(alg); }
      state.cfg.options.HashAlgorithms = [...set].join(',');
      return render();
    }
    case 'product': {
      const p = PRODUCTS[+btn.dataset.idx];
      const cur = state.wizard.values.split('\n').map(s => s.trim()).filter(Boolean);
      for (const path of p.paths) if (!cur.includes(path)) cur.push(path);
      state.wizard.values = cur.join('\n');
      state.wizard.match = 'begin with';
      if (!state.wizard.comment) state.wizard.comment = p.label;
      return renderMain();
    }
    case 'wizard-apply': return wizardApply();
    case 'schema-apply': {
      const text = $('#schema-text').value;
      try {
        const res = applyManifest(text, state.cfg.platform);
        state.customSchema = { ...res, platform: state.cfg.platform };
        try { localStorage.setItem(SCHEMA_KEY, JSON.stringify({ text, platform: state.cfg.platform })); } catch { /* not persisted */ }
        fillEvents(state.cfg);
        if (res.schemaversion) state.cfg.schemaversion = res.schemaversion;
        render();
        return toast(`Schema ${res.schemaversion} loaded: ${res.events} event types, ${res.changed.length} with different fields, ${res.added.length} new.`);
      } catch (err) { return toast(err.message); }
    }
    case 'schema-clear':
      try { localStorage.removeItem(SCHEMA_KEY); } catch { /* ignore */ }
      state.cfg.schemaversion = BUILTIN[state.cfg.platform].schema;
      save();
      return location.reload();
  }
}

function onInput(ev) {
  const t = ev.target;
  if (t.id === 'search') { state.search = t.value; return applySearch(); }
  if (t.id === 'wz-values') { state.wizard.values = t.value; return; }
  if (t.id === 'wz-comment') { state.wizard.comment = t.value; return; }
  const [kind] = state.view.split(':');
  if (VIEWS[kind]?.input?.(t, ctx)) return;
  const beginTyping = () => { if (!state.typing) { commit(); state.typing = true; } };
  if (t.id === 'header') { beginTyping(); state.cfg.header = t.value; return refreshSoon(); }
  if (t.dataset.opt && t.type !== 'checkbox' && t.tagName !== 'SELECT') {
    beginTyping();
    state.cfg.options[t.dataset.opt] = t.value;
    return refreshSoon();
  }
  const k = t.dataset.k;
  if (!k || t.type === 'checkbox' || t.tagName === 'SELECT') return;
  const holder = t.closest('[data-id]');
  const f = holder && findItem(holder.dataset.id);
  if (!f) return;
  beginTyping();
  f.item[k] = t.value;
  refreshSoon();
}

function onChange(ev) {
  const t = ev.target;
  state.typing = false;
  const [kind] = state.view.split(':');
  if (VIEWS[kind]?.change?.(t, ctx)) return;
  if (t.id === 'platform') {
    commit();
    state.cfg.platform = t.value;
    state.cfg.schemaversion = LATEST[t.value].schema;
    return render();
  }
  if (t.id === 'schema') { commit(); state.cfg.schemaversion = t.value; return render(); }
  if (t.id === 'changelog') { state.cfg.changelog = t.checked; return save(); }
  if (t.name === 'wz-match') { state.wizard.match = t.value; return; }
  if (t.name === 'wz-ev') {
    state.wizard.events = [...document.querySelectorAll('input[name="wz-ev"]:checked')].map(i => i.value);
    return;
  }
  if (t.dataset.opt && (t.type === 'checkbox' || t.tagName === 'SELECT')) {
    commit();
    const v = t.type === 'checkbox' ? t.checked : t.value;
    if (v === '' || v === false) delete state.cfg.options[t.dataset.opt];
    else state.cfg.options[t.dataset.opt] = v;
    return refresh();
  }
  const k = t.dataset.k;
  if (!k || (t.type !== 'checkbox' && t.tagName !== 'SELECT')) return;
  const holder = t.closest('[data-id]');
  const f = holder && findItem(holder.dataset.id);
  if (!f) return;
  commit();
  if (k === 'enabled') {
    f.item.enabled = t.checked;
    t.closest('.row, .rule')?.classList.toggle('disabled', !t.checked);
  } else {
    f.item[k] = t.value;
  }
  refresh();
}

function onKey(ev) {
  const mod = ev.metaKey || ev.ctrlKey;
  const inText = ev.target.matches?.('textarea') || (ev.target.matches?.('input') && !ev.target.closest('#main .row, #main .rule-head'));
  if (mod && ev.key.toLowerCase() === 'z' && !inText) { ev.preventDefault(); return ev.shiftKey ? redo() : undo(); }
  if (mod && ev.key.toLowerCase() === 'y' && !inText) { ev.preventDefault(); return redo(); }
  if (mod && ev.key.toLowerCase() === 's') { ev.preventDefault(); return download(); }
  if (ev.target.matches?.('input, textarea, select')) return;
  if (ev.key === '/') { const s = $('#search'); if (s) { ev.preventDefault(); s.focus(); } }
  if (ev.key === '?') $('#keys-dialog').showModal();
}

async function init() {
  loadCustomSchema();
  $('#preset').innerHTML = PRESETS.map(p => `<option value="${p.id}">${h(p.label)}</option>`).join('');
  $('#load-preset').onclick = () => loadPreset($('#preset').value);
  $('#import-file').onclick = () => $('#file-input').click();
  $('#file-input').onchange = async e => {
    const file = e.target.files[0];
    if (file) importXml(await file.text(), `Imported ${file.name}.`);
    e.target.value = '';
  };
  const dlg = $('#paste-dialog');
  $('#import-paste').onclick = () => { $('#paste-text').value = ''; dlg.showModal(); };
  dlg.addEventListener('close', () => { if (dlg.returnValue === 'ok' && $('#paste-text').value.trim()) importXml($('#paste-text').value, 'Imported pasted XML.'); });
  $('#download').onclick = download;
  $('#share').onclick = share;
  $('#undo').onclick = undo;
  $('#redo').onclick = redo;
  $('#copy').onclick = () => copyText(currentXml(), 'XML copied.');
  $('#toggle-preview').onclick = () => {
    const off = $('#layout').classList.toggle('no-preview');
    $('#toggle-preview').setAttribute('aria-pressed', String(!off));
    renderPreview();
  };
  $('#opt-comments').onchange = renderPreview;
  $('#opt-disabled').onchange = renderPreview;

  document.addEventListener('click', onClick);
  document.addEventListener('input', onInput);
  document.addEventListener('change', onChange);
  document.addEventListener('keydown', onKey);
  document.addEventListener('focusin', fillLazySelect);
  document.addEventListener('mousedown', fillLazySelect, true);
  document.addEventListener('dragstart', onDragStart);
  document.addEventListener('dragover', onDragOver);
  document.addEventListener('drop', onDrop);
  document.addEventListener('dragend', onDragEnd);

  const restored = restore();
  if (hasShare()) {
    try {
      const xml = await decodeShare();
      clearShare();
      importXml(xml, restored ? 'Opened from a share link. Your previous config is one Ctrl+Z away.' : 'Opened from a share link.');
      return;
    } catch {
      clearShare();
      toast('The share link is damaged or incomplete.');
    }
  }
  if (restored) render();
  else loadPreset('windows');
}

init();
