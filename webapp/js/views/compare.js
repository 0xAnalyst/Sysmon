// Compare the current config with another one and merge rules across.

import { parseXml, uid } from '../config.js';
import { diffConfigs, diffTotals, diffMarkdown, itemSig } from '../diff.js';
import { describeItem } from '../matcher.js';

const local = { name: '', other: null };

const clone = item => {
  const c = JSON.parse(JSON.stringify(item));
  c.id = uid();
  c.before = [];
  if (c.conds) c.conds.forEach(x => { x.id = uid(); x.before = []; });
  delete c.module;
  return c;
};

function load(ctx, name, xmlOrCfg) {
  try {
    local.other = typeof xmlOrCfg === 'string' ? parseXml(xmlOrCfg).config : xmlOrCfg;
    local.name = name;
  } catch (err) {
    ctx.toast(err.message);
  }
  ctx.render();
}

export function html(ctx) {
  const { h, state, PRESETS } = ctx;
  let out = `<header><h2>Compare &amp; merge</h2>
    <p class="lede">Diff this config against another one: your last download, a bundled preset, or any Sysmon XML (SwiftOnSecurity, sysmon-modular, a colleague's version). Pull individual rules across, or export the diff for review.</p></header>
    <div class="toolbar">
      <select id="cmp-source"><option value="">Compare with…</option>
        <option value="baseline">Last import / download of this config</option>
        ${PRESETS.filter(p => p.files).map(p => `<option value="preset:${p.id}">${h(p.label)}</option>`).join('')}
        <option value="file">XML file…</option><option value="paste">Paste XML…</option></select>
      <input type="file" id="cmp-file" accept=".xml" hidden>
      ${local.other ? `<span class="count">Comparing with: <b>${h(local.name)}</b></span>` : ''}
    </div>
    <textarea id="cmp-paste" class="code-input" hidden placeholder="Paste Sysmon XML, then press Compare"></textarea>
    <button id="cmp-paste-go" class="small" data-act="cmp-paste" hidden>Compare</button>`;
  if (!local.other) return out;

  const d = diffConfigs(state.cfg, local.other);
  const t = diffTotals(d);
  out += `<div class="stats">
      <div class="stat"><b>${t.added}</b><span>rules only in theirs</span></div>
      <div class="stat"><b>${t.removed}</b><span>rules only in yours</span></div>
      <div class="stat"><b>${d.events.length}</b><span>event types differ</span></div>
    </div>
    <div class="toolbar">${t.added ? '<button class="small primary" data-act="cmp-take-all">Add all their rules</button>' : ''}
      <button class="small" data-act="cmp-report">Download diff report (Markdown)</button></div>`;
  if (d.options.length) {
    out += `<h3>Settings</h3><div class="table-wrap"><table class="grid-table"><thead><tr><th>Setting</th><th>Yours</th><th>Theirs</th></tr></thead><tbody>
      ${d.options.map(o => `<tr><td>${h(o.tag)}</td><td class="mono">${h(o.a || '(unset)')}</td><td class="mono">${h(o.b || '(unset)')}</td></tr>`).join('')}</tbody></table></div>`;
  }
  if (!d.events.length) return out + '<p class="empty">No rule differences.</p>';
  for (const e of d.events) {
    out += `<section class="card diff-event"><header><h3><a href="#" data-jump="${e.tag}">${h(e.tag)}</a></h3>
      ${e.modeA !== e.modeB ? `<span>mode: <b>${e.modeA}</b> (yours) vs <b>${e.modeB}</b> (theirs) <button class="small" data-act="cmp-mode" data-tag="${e.tag}">Use theirs</button></span>` : ''}</header>`;
    for (const k of ['include', 'exclude']) {
      const { added, removed } = e[k];
      if (!added.length && !removed.length) continue;
      out += `<h4 class="${k}">${k}</h4><ul class="diff">
        ${added.map(i => `<li class="add"><span>+ ${h(describeItem(i))}${i.name ? ` <small>${h(i.name)}</small>` : ''}</span>
          <button class="small" data-act="cmp-take" data-tag="${e.tag}" data-k="${k}" data-sig="${h(itemSig(i))}">Add to mine</button></li>`).join('')}
        ${removed.map(i => `<li class="del"><span>− ${h(describeItem(i))}</span>
          <button class="small ghost" data-act="cmp-drop" data-id="${i.id}">Remove from mine</button></li>`).join('')}
      </ul>`;
    }
    out += '</section>';
  }
  return out;
}

function takeItem(ctx, tag, k, sig) {
  const theirs = local.other.events[tag][k].find(i => itemSig(i) === sig);
  if (!theirs) return false;
  const ev = ctx.state.cfg.events[tag];
  if (ev.mode !== 'filtered') ev.mode = 'filtered';
  ev[k].push(clone(theirs));
  return true;
}

export function click(act, btn, ctx) {
  const { state } = ctx;
  if (act === 'cmp-take') {
    ctx.commit();
    takeItem(ctx, btn.dataset.tag, btn.dataset.k, btn.dataset.sig);
    ctx.render();
    return true;
  }
  if (act === 'cmp-take-all') {
    ctx.commit();
    const d = diffConfigs(state.cfg, local.other);
    let n = 0;
    for (const e of d.events) for (const k of ['include', 'exclude']) for (const i of e[k].added) if (takeItem(ctx, e.tag, k, itemSig(i))) n++;
    ctx.render();
    ctx.toast(`Added ${n} rules. Ctrl+Z to undo.`);
    return true;
  }
  if (act === 'cmp-drop') {
    const f = ctx.findItem(btn.dataset.id);
    if (f) { ctx.commit(); f.list.splice(f.index, 1); ctx.render(); }
    return true;
  }
  if (act === 'cmp-mode') {
    ctx.commit();
    state.cfg.events[btn.dataset.tag].mode = local.other.events[btn.dataset.tag].mode;
    ctx.render();
    return true;
  }
  if (act === 'cmp-report') {
    ctx.downloadText('sysmon-config-diff.md', diffMarkdown(diffConfigs(state.cfg, local.other), 'current config', local.name), 'text/markdown');
    return true;
  }
  if (act === 'cmp-paste') { load(ctx, 'pasted XML', ctx.$('#cmp-paste').value); return true; }
  return false;
}

export function change(t, ctx) {
  if (t.id === 'cmp-source') {
    const v = t.value;
    if (v === 'baseline') {
      if (!ctx.state.baseline) { ctx.toast('No baseline yet.'); return true; }
      load(ctx, 'last import / download', JSON.parse(ctx.state.baseline));
    } else if (v.startsWith('preset:')) {
      const p = ctx.PRESETS.find(x => x.id === v.slice(7));
      ctx.fetchPreset(p.id).then(xml => xml ? load(ctx, p.label, xml) : ctx.toast('Could not load that preset.'));
    } else if (v === 'file') {
      const f = ctx.$('#cmp-file');
      f.onchange = async () => { if (f.files[0]) load(ctx, f.files[0].name, await f.files[0].text()); };
      f.click();
    } else if (v === 'paste') {
      ctx.$('#cmp-paste').hidden = false;
      ctx.$('#cmp-paste-go').hidden = false;
      ctx.$('#cmp-paste').focus();
    }
    return true;
  }
  return false;
}
