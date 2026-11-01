// ATT&CK coverage matrix built from technique IDs in include rule names.

import { coverage, matrix, navigatorLayer, TECH_BY_ID, ATTACK_VERSION } from '../attack.js';
import { describeItem } from '../matcher.js';

const local = { hidePre: true, onlyCovered: false, selected: null };
const PRE = ['reconnaissance', 'resource-development'];

export function html(ctx) {
  const { h, state } = ctx;
  const cov = coverage(state.cfg);
  const rows = matrix(state.cfg, cov.byTech).filter(r => !(local.hidePre && PRE.includes(r.tactic)));
  const allIds = new Set();
  let covered = 0;
  for (const r of rows) for (const t of r.techniques) {
    for (const id of [t.id, ...t.subs.map(s => s.id)]) {
      if (allIds.has(id)) continue;
      allIds.add(id);
      if (cov.byTech.has(id)) covered++;
    }
  }
  const parentsCovered = new Set(rows.flatMap(r => r.techniques.filter(t => t.count || t.subCount).map(t => t.id))).size;
  const parentsTotal = new Set(rows.flatMap(r => r.techniques.map(t => t.id))).size;
  const max = Math.max(1, ...[...cov.byTech.values()].map(v => v.length));
  const heat = n => n ? Math.min(5, 1 + Math.floor(4 * Math.log(n) / Math.log(max + 1))) : 0;

  const cols = rows.map(r => {
    const techs = local.onlyCovered ? r.techniques.filter(t => t.count || t.subCount) : r.techniques;
    const cov2 = r.techniques.filter(t => t.count || t.subCount).length;
    return `<div class="tactic"><header><b>${h(r.name)}</b><span>${cov2}/${r.techniques.length}</span></header>
      ${techs.map(t => {
        const n = t.count + t.subs.reduce((s, x) => s + x.count, 0);
        return `<button class="tech heat-${heat(n)} ${local.selected === t.id ? 'sel' : ''}" data-act="cov-select" data-id="${t.id}" title="${h(t.id)} ${h(t.name)}: ${n} rule${n === 1 ? '' : 's'}">
          <span class="tid">${t.id}</span><span class="tname">${h(t.name)}</span>
          ${n ? `<span class="tcount">${n}${t.subs.length ? ` · ${t.subCount}/${t.subs.length} sub` : ''}</span>` : ''}</button>`;
      }).join('')}</div>`;
  }).join('');

  let detail = '';
  if (local.selected) {
    const t = TECH_BY_ID.get(local.selected);
    const ids = [local.selected, ...[...TECH_BY_ID.keys()].filter(k => k.startsWith(local.selected + '.'))];
    const sections = ids.filter(id => cov.byTech.has(id)).map(id => `<h4>${id} ${h(TECH_BY_ID.get(id)?.name || '')}</h4><ul>${
      cov.byTech.get(id).map(r => `<li><a href="#" data-jump="${r.tag}" data-item="${r.item.id}">${h(r.tag)}: ${h(describeItem(r.item))}</a></li>`).join('')}</ul>`).join('');
    detail = `<aside class="card cov-detail"><header><h3>${local.selected} ${h(t?.name || '')}</h3>
      <a href="https://attack.mitre.org/techniques/${local.selected.replace('.', '/')}/" target="_blank" rel="noopener">ATT&amp;CK page ↗</a></header>
      ${sections || '<p class="empty">No include rules reference this technique or its sub-techniques.</p>'}</aside>`;
  }

  return `<header><h2>ATT&amp;CK coverage</h2>
    <p class="lede">Techniques referenced by enabled include rules (rule names like <code>technique_id=T1003</code>, <code>TechniqueID=T1021.004</code>, <code>attack.t1083</code>). This is visibility, not detection: a logged event still needs a query or analyst. ${h(ATTACK_VERSION)}, ${state.cfg.platform === 'linux' ? 'Linux' : 'Windows'} techniques.</p></header>
    <div class="stats">
      <div class="stat"><b>${parentsCovered}/${parentsTotal}</b><span>techniques with rules</span></div>
      <div class="stat"><b>${covered}</b><span>techniques + sub-techniques</span></div>
      <div class="stat"><b>${cov.tagged}</b><span>tagged include rules</span></div>
      <div class="stat"><b>${cov.untagged}</b><span>untagged include rules</span></div>
    </div>
    <div class="toolbar">
      <label><input type="checkbox" id="cov-pre" ${local.hidePre ? 'checked' : ''}> Hide pre-compromise tactics</label>
      <label><input type="checkbox" id="cov-only" ${local.onlyCovered ? 'checked' : ''}> Only covered techniques</label>
      <button class="small" data-act="cov-layer">Download ATT&amp;CK Navigator layer</button>
    </div>
    ${detail}
    <div class="matrix-wrap"><div class="matrix">${cols}</div></div>`;
}

export function click(act, btn, ctx) {
  if (act === 'cov-select') { local.selected = local.selected === btn.dataset.id ? null : btn.dataset.id; ctx.render(); return true; }
  if (act === 'cov-layer') {
    const cov = coverage(ctx.state.cfg);
    const layer = navigatorLayer(ctx.state.cfg, cov.byTech, `Sysmon coverage (${ctx.state.cfg.platform})`);
    ctx.downloadText('sysmon-attack-layer.json', JSON.stringify(layer, null, 2), 'application/json');
    ctx.toast('Layer downloaded. Open it at mitre-attack.github.io/attack-navigator.');
    return true;
  }
  return false;
}

export function change(t, ctx) {
  if (t.id === 'cov-pre') { local.hidePre = t.checked; ctx.render(); return true; }
  if (t.id === 'cov-only') { local.onlyCovered = t.checked; ctx.render(); return true; }
  return false;
}
