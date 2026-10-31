import { EVENTS, EVENT_BY_TAG, CONDITIONS, OPTIONS, SCHEMA_VERSIONS, LATEST, minSchemaForEvent, imageFieldFor } from './schema.js';
import { newConfig, newCond, newRule, parseXml, generateXml, escapeXml, activeCount } from './config.js';
import { validate } from './validate.js';
import { PRESETS, STARTERS, PRODUCTS } from './presets.js';

const STORE_KEY = 'sysmon-builder:v1';
const $ = (sel, root = document) => root.querySelector(sel);
const h = escapeXml;

const state = {
  cfg: null,
  view: 'overview',
  search: '',
  issues: [],
  notes: [],
  wizard: { values: '', match: 'begin with', events: null, comment: '' },
};

// ------------------------------------------------------------------ storage

function save() {
  try { localStorage.setItem(STORE_KEY, JSON.stringify({ cfg: state.cfg, view: state.view })); } catch { /* storage unavailable */ }
}
function restore() {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (!raw) return false;
    const { cfg, view } = JSON.parse(raw);
    if (!cfg?.events) return false;
    for (const e of EVENTS) cfg.events[e.tag] ||= { mode: 'unset', include: [], exclude: [] };
    state.cfg = cfg;
    state.view = view || 'overview';
    return true;
  } catch { return false; }
}

// ------------------------------------------------------------------ helpers

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove('show'), 3200);
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

function issuesFor(tag) {
  return state.issues.filter(i => i.event === tag);
}

function worstLevel(list) {
  if (list.some(i => i.level === 'error')) return 'error';
  if (list.some(i => i.level === 'warn')) return 'warn';
  return list.length ? 'info' : null;
}

function ruleCount(ev) {
  return activeCount(ev.include) + activeCount(ev.exclude);
}

function isNewEvent(tag) {
  const src = parseFloat(state.cfg.sourceSchema || '0');
  return src > 0 && parseFloat(minSchemaForEvent(EVENT_BY_TAG[tag].ids[0])) > src;
}

// ------------------------------------------------------------------ rendering: chrome

function renderTarget() {
  const c = state.cfg;
  const v = SCHEMA_VERSIONS.find(s => s.schema === c.schemaversion);
  $('#target-label').textContent = `${c.platform === 'linux' ? 'Linux' : 'Windows'} · schema ${c.schemaversion}` +
    (c.platform === 'windows' && v ? ` · Sysmon ${v.sysmon}` : '');
}

function modePill(ev) {
  if (ev.mode === 'unset') return '<span class="pill">default</span>';
  if (ev.mode === 'off') return '<span class="pill off">off</span>';
  if (ev.mode === 'all') return '<span class="pill all">all</span>';
  return `<span class="pill filtered">${ruleCount(ev)}</span>`;
}

function renderSidebar() {
  const nav = $('#sidebar');
  const counts = { error: 0, warn: 0, info: 0 };
  for (const i of state.issues) counts[i.level]++;
  const issuePill = counts.error ? `<span class="pill err">${counts.error}</span>` : counts.warn ? `<span class="pill warn">${counts.warn}</span>` : '<span class="pill">0</span>';

  const item = (view, label, right = '', cls = 'plain') =>
    `<button class="nav-item ${cls} ${state.view === view ? 'active' : ''}" data-view="${view}">${label}${right}</button>`;

  let html = '<h2>Configuration</h2>';
  html += item('overview', '<span class="ename">Overview &amp; issues</span>', issuePill);
  html += item('options', '<span class="ename">Global settings</span>');
  if (state.cfg.platform === 'windows') html += item('wizard', '<span class="ename">Exclusion wizard</span>');
  html += '<h2>Events</h2>';
  for (const e of EVENTS) {
    const supported = e.platforms.includes(state.cfg.platform);
    if (!supported) continue;
    const ev = state.cfg.events[e.tag];
    const lvl = worstLevel(issuesFor(e.tag).filter(i => i.level !== 'info'));
    let right = modePill(ev);
    if (lvl === 'error') right = '<span class="pill err">!</span>';
    else if (ev.mode === 'unset' && isNewEvent(e.tag)) right = '<span class="pill new">new</span>';
    html += `<button class="nav-item ${state.view === 'event:' + e.tag ? 'active' : ''}" data-view="event:${e.tag}" title="${h(e.tag)}">
      <span class="eid">${e.ids.join(',')}</span><span class="ename">${h(e.title)}</span>${right}</button>`;
  }
  nav.innerHTML = html;
}

function highlight(xml) {
  return h(xml)
    .replace(/&lt;!--[\s\S]*?--&gt;/g, m => `\u0001c${m}\u0002`)
    .replace(/(&lt;\/?)([\w]+)/g, (m, a, b) => `${a}<span class="t">${b}</span>`)
    .replace(/(\s)([\w]+)=(&quot;.*?&quot;)/g, '$1<span class="a">$2</span>=<span class="s">$3</span>')
    .replace(/\u0001c([\s\S]*?)\u0002/g, (m, c) => `<span class="c">${c.replace(/<[^>]+>/g, '')}</span>`);
}

function currentXml() {
  return generateXml(state.cfg, { comments: $('#opt-comments').checked, keepDisabled: $('#opt-disabled').checked });
}

function renderPreview() {
  const xml = currentXml();
  $('#xml code').innerHTML = highlight(xml);
  const lin = state.cfg.platform === 'linux';
  $('#deploy').innerHTML = lin
    ? `<p>Install / update on Linux:</p><code>sudo sysmon -accepteula -i sysmonconfig.xml</code><code>sudo sysmon -c sysmonconfig.xml</code>`
    : `<p>Install / update on Windows (elevated):</p><code>Sysmon64.exe -accepteula -i sysmonconfig.xml</code><code>Sysmon64.exe -c sysmonconfig.xml</code>`;
}

// Cheap refresh after field edits: everything except the main panel.
function refresh() {
  state.issues = validate(state.cfg);
  renderTarget();
  renderSidebar();
  if (!$('#layout').classList.contains('no-preview')) renderPreview();
  markRowIssues();
  if (state.view === 'overview') renderOverviewIssues();
  save();
}
const refreshSoon = (() => { let t; return () => { clearTimeout(t); t = setTimeout(refresh, 180); }; })();

function render() {
  state.issues = validate(state.cfg);
  renderTarget();
  renderSidebar();
  renderMain();
  if (!$('#layout').classList.contains('no-preview')) renderPreview();
  save();
}

// ------------------------------------------------------------------ main views

function renderMain() {
  const main = $('#main');
  const [kind, tag] = state.view.split(':');
  if (kind === 'event' && EVENT_BY_TAG[tag]) main.innerHTML = eventView(tag);
  else if (kind === 'options') main.innerHTML = optionsView();
  else if (kind === 'wizard') main.innerHTML = wizardView();
  else { main.innerHTML = overviewView(); renderOverviewIssues(); }
  if (kind === 'event') { applySearch(); markRowIssues(); }
}

function notesHtml() {
  if (!state.notes.length) return '';
  return `<div class="callout info"><div>${state.notes.map(n => `<p>${h(n)}</p>`).join('')}</div>
    <button class="small" data-act="dismiss-notes">Dismiss</button></div>`;
}

function overviewView() {
  const c = state.cfg;
  const evs = eventsForPlatform();
  const configured = evs.filter(e => c.events[e.tag].mode !== 'unset').length;
  const rules = evs.reduce((n, e) => n + ruleCount(c.events[e.tag]), 0);
  const newOnes = evs.filter(e => c.events[e.tag].mode === 'unset' && isNewEvent(e.tag));
  const counts = { error: 0, warn: 0, info: 0 };
  for (const i of state.issues) counts[i.level]++;

  return `${notesHtml()}
    <header><h2>Overview</h2>
    <p class="lede">Pick an event on the left to tune its include and exclude rules. Use the exclusion wizard to quiet your AV/EDR and agents across events at once. The XML on the right updates as you edit and is saved in this browser.</p></header>
    <div class="stats">
      <div class="stat"><b>${configured}/${evs.length}</b><span>events configured</span></div>
      <div class="stat"><b>${rules}</b><span>active rules</span></div>
      <div class="stat"><b style="color:var(--error)">${counts.error}</b><span>errors</span></div>
      <div class="stat"><b style="color:var(--warn)">${counts.warn}</b><span>warnings</span></div>
    </div>
    ${newOnes.length ? `<div class="callout"><p><b>${newOnes.length} event type${newOnes.length > 1 ? 's' : ''} added since schema ${h(c.sourceSchema)}</b> are not configured: ${newOnes.map(e => h(e.tag)).join(', ')}.</p>
      <button class="small primary" data-act="apply-all-starters">Apply recommended starters</button></div>` : ''}
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

  html += `<div class="toolbar"><input type="search" id="search" placeholder="Filter rules by value, field, comment…" value="${h(state.search)}">
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

function sectionsHtml(item) {
  return (item.before || []).map((b, i) => `<div class="section" data-sec-of="${item.id}"><span>${h(b)}</span>
    <button class="ghost small" data-act="del-section" data-id="${item.id}" data-idx="${i}" title="Remove comment">✕</button></div>`).join('');
}

function condHtml(c, e, inRule) {
  const showName = c.name || c.showName;
  return `${sectionsHtml(c)}<div class="row ${c.enabled ? '' : 'disabled'}" data-id="${c.id}">
    <input class="on" type="checkbox" ${c.enabled ? 'checked' : ''} data-k="enabled" title="Enabled" aria-label="Enabled">
    <select data-k="field" aria-label="Field">${fieldOptions(e, c.field)}</select>
    <select data-k="condition" aria-label="Condition">${condOptions(c.condition)}</select>
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
    <div class="rule-head row-like" data-id="${it.id}">
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
    const id = el.dataset.id;
    main.querySelectorAll(`[data-sec-of="${id}"]`).forEach(s => (s.hidden = !hit || !!q));
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

  return `${notesHtml()}<header><h2>Global settings</h2><p class="lede">Top-level entries of the config, and the schema the XML is written for.</p></header>
  <div class="form">
    <div class="field"><label>Platform</label><div><select id="platform">
      <option value="windows" ${c.platform === 'windows' ? 'selected' : ''}>Windows (Sysmon ${LATEST.windows.sysmon})</option>
      <option value="linux" ${c.platform === 'linux' ? 'selected' : ''}>Linux (Sysmon for Linux)</option></select>
      <div class="help">Events and settings that the platform does not support are left out of the output.</div></div></div>
    <div class="field"><label>Schema version</label><div><select id="schema">${custom}${schemaOpts}</select>
      <div class="help">Use the newest schema your fleet's Sysmon binary supports. Latest: ${LATEST[c.platform].schema}. Run <code>sysmon -s</code> to check.</div></div></div>
    ${opts.map(optField).join('')}
    <div class="field"><label>Header comment</label><div><textarea id="header" spellcheck="false">${h(c.header)}</textarea>
      <div class="help">Written at the top of the file. Good place for version, owner and change notes.</div></div></div>
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

function setMode(tag, mode) {
  const ev = state.cfg.events[tag];
  ev.mode = mode;
  render();
}

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
  const field = e.fields.find(f => /Image|TargetFilename|TargetObject|QueryName|PipeName/.test(f) && f !== 'RuleName') || e.fields[1];
  const c = newCond(field, 'is', '');
  state.cfg.events[tag][onmatch].unshift(c);
  render();
  focusRow(c.id);
}

function focusRow(id) {
  const row = $(`#main [data-id="${id}"]`);
  if (!row) return;
  row.scrollIntoView({ block: 'center' });
  row.classList.add('flash');
  (row.querySelector('input.value') || row.querySelector('input.rname'))?.focus();
}

function wizardApply() {
  const w = state.wizard;
  const values = w.values.split('\n').map(s => s.trim()).filter(Boolean);
  if (!values.length) return toast('Add at least one process or folder.');
  if (!w.events.length) return toast('Select at least one event.');
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
  if (p.platform) {
    state.cfg = newConfig(p.platform);
    state.notes = [];
  } else {
    for (const file of p.files) {
      try {
        const res = await fetch(file);
        if (!res.ok) continue;
        return importXml(await res.text(), p.note, false);
      } catch { /* try the next location */ }
    }
    return toast(`Could not load the ${p.label} preset. Serve the repo over HTTP, not file://.`);
  }
  state.view = 'overview';
  render();
  toast(`Loaded: ${p.label}`);
}

function importXml(text, note, announce = true) {
  try {
    const { config, notes } = parseXml(text);
    state.cfg = config;
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
  const blob = new Blob([currentXml()], { type: 'application/xml' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = state.cfg.platform === 'linux' ? 'sysmonconfig-linux.xml' : 'sysmonconfig.xml';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  const errs = state.issues.filter(i => i.level === 'error').length;
  if (errs) toast(`Downloaded, but there ${errs === 1 ? 'is 1 error' : `are ${errs} errors`}. Sysmon may reject the file.`);
}

// ------------------------------------------------------------------ events

function onClick(ev) {
  const nav = ev.target.closest('[data-view]');
  if (nav) {
    state.view = nav.dataset.view;
    state.search = '';
    render();
    $('#main').scrollTop = 0;
    return;
  }
  const jump = ev.target.closest('[data-jump]');
  if (jump) {
    if (jump.dataset.jump) {
      state.view = 'event:' + jump.dataset.jump;
      state.search = '';
      render();
      if (jump.dataset.item) focusRow(jump.dataset.item);
    } else { state.view = 'options'; render(); }
    return;
  }
  const btn = ev.target.closest('[data-act]');
  if (!btn) return;
  const act = btn.dataset.act;
  const tag = state.view.startsWith('event:') ? state.view.slice(6) : null;

  switch (act) {
    case 'mode': return setMode(tag, btn.dataset.mode);
    case 'starter': applyStarter(tag); return render();
    case 'apply-all-starters': {
      const done = [];
      for (const e of eventsForPlatform()) {
        if (state.cfg.events[e.tag].mode === 'unset' && isNewEvent(e.tag) && STARTERS[e.tag]) { applyStarter(e.tag); done.push(e.tag); }
      }
      render();
      return toast(`Applied starters: ${done.join(', ') || 'none'}.`);
    }
    case 'dismiss-notes': state.notes = []; return render();
    case 'add-cond': return addCond(tag, btn.dataset.onmatch);
    case 'add-rule': {
      const r = newRule('and');
      const e = EVENT_BY_TAG[tag];
      r.conds.push(newCond(e.fields.includes('Image') ? 'Image' : e.fields[1], 'end with', ''));
      state.cfg.events[tag][btn.dataset.onmatch].unshift(r);
      render();
      return focusRow(r.id);
    }
    case 'add-cond-in': {
      const f = findItem(btn.dataset.id);
      const c = newCond(f.item.conds[0]?.field || 'Image', 'is', '');
      f.item.conds.push(c);
      render();
      return focusRow(c.id);
    }
    case 'del': {
      const f = findItem(btn.dataset.id);
      if (!f) return;
      const removed = f.list.splice(f.index, 1)[0];
      // Keep section comments by handing them to the next item.
      if (removed.before?.length && f.list[f.index]) f.list[f.index].before = [...removed.before, ...f.list[f.index].before];
      state.lastDeleted = { ...f, removed };
      render();
      return toast('Rule deleted.');
    }
    case 'move': {
      const f = findItem(btn.dataset.id);
      if (!f || f.parent) return;
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
      const f = findItem(btn.dataset.id);
      f.item.before.splice(+btn.dataset.idx, 1);
      return render();
    }
    case 'hash': {
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
  }
}

function onInput(ev) {
  const t = ev.target;
  if (t.id === 'search') { state.search = t.value; return applySearch(); }
  if (t.id === 'wz-values') { state.wizard.values = t.value; return; }
  if (t.id === 'wz-comment') { state.wizard.comment = t.value; return; }
  if (t.id === 'header') { state.cfg.header = t.value; return refreshSoon(); }
  if (t.dataset.opt && t.type !== 'checkbox' && t.tagName !== 'SELECT') {
    state.cfg.options[t.dataset.opt] = t.value;
    return refreshSoon();
  }
  const k = t.dataset.k;
  if (!k || t.type === 'checkbox' || t.tagName === 'SELECT') return;
  const holder = t.closest('[data-id]');
  const f = holder && findItem(holder.dataset.id);
  if (!f) return;
  f.item[k] = t.value;
  refreshSoon();
}

function onChange(ev) {
  const t = ev.target;
  if (t.id === 'platform') {
    state.cfg.platform = t.value;
    state.cfg.schemaversion = LATEST[t.value].schema;
    if (state.view.startsWith('event:') && !EVENT_BY_TAG[state.view.slice(6)].platforms.includes(t.value)) state.view = 'options';
    return render();
  }
  if (t.id === 'schema') { state.cfg.schemaversion = t.value; return render(); }
  if (t.name === 'wz-match') { state.wizard.match = t.value; return; }
  if (t.name === 'wz-ev') {
    state.wizard.events = [...document.querySelectorAll('input[name="wz-ev"]:checked')].map(i => i.value);
    return;
  }
  if (t.dataset.opt) {
    const v = t.type === 'checkbox' ? t.checked : t.value;
    if (v === '' || v === false) delete state.cfg.options[t.dataset.opt];
    else state.cfg.options[t.dataset.opt] = v;
    return refresh();
  }
  const k = t.dataset.k;
  if (!k) return;
  const holder = t.closest('[data-id]');
  const f = holder && findItem(holder.dataset.id);
  if (!f) return;
  if (k === 'enabled') {
    f.item.enabled = t.checked;
    (t.closest('.row, .rule'))?.classList.toggle('disabled', !t.checked);
    return refresh();
  }
  f.item[k] = t.value;
  if (k === 'field' || k === 'condition' || k === 'relation') refresh();
}

function init() {
  $('#preset').innerHTML = PRESETS.map(p => `<option value="${p.id}">${h(p.label)}</option>`).join('');
  $('#load-preset').onclick = () => {
    if (state.cfg && !confirm('Replace the current configuration?')) return;
    loadPreset($('#preset').value);
  };
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
  $('#copy').onclick = async () => {
    try { await navigator.clipboard.writeText(currentXml()); toast('XML copied.'); } catch { toast('Clipboard is blocked here; use Download.'); }
  };
  $('#toggle-preview').onclick = () => {
    const off = $('#layout').classList.toggle('no-preview');
    $('#toggle-preview').setAttribute('aria-pressed', String(!off));
    if (!off) renderPreview();
  };
  $('#opt-comments').onchange = renderPreview;
  $('#opt-disabled').onchange = renderPreview;

  document.addEventListener('click', onClick);
  document.addEventListener('input', onInput);
  document.addEventListener('change', onChange);

  if (restore()) {
    render();
  } else {
    loadPreset('windows');
  }
}

init();
