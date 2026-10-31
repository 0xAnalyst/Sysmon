// Export named include rules as SIEM queries or Sigma rules.

import { namedRules, splunk, sentinel, elastic, sigma } from '../detections.js';

const FORMATS = [
  ['sigma', 'Sigma', 'yml'], ['splunk', 'Splunk SPL', 'spl'], ['sentinel', 'Microsoft Sentinel KQL', 'kql'], ['elastic', 'Elastic KQL', 'txt'],
];
const GEN = { sigma, splunk, sentinel, elastic };
const local = { format: 'sigma', q: '' };

function all(ctx) {
  return namedRules(ctx.state.cfg).filter(r => !local.q || `${r.tag} ${r.name}`.toLowerCase().includes(local.q.toLowerCase()));
}

export function html(ctx) {
  const { h } = ctx;
  const rules = all(ctx);
  const total = namedRules(ctx.state.cfg).length;
  return `<header><h2>SIEM queries &amp; Sigma</h2>
    <p class="lede">Sysmon records the name of the include rule that matched in each event's <code>RuleName</code> field. The SIEM queries below search for those names. The Sigma rules are rebuilt from the conditions, so they also work on data collected with other configs.</p></header>
    <div class="toolbar">
      <div class="modes" role="group" aria-label="Format">${FORMATS.map(([id, label]) =>
        `<button data-act="det-format" data-format="${id}" aria-pressed="${local.format === id}">${label}</button>`).join('')}</div>
    </div>
    <div class="toolbar">
      <input type="search" id="det-q" placeholder="Filter by event or rule name" value="${h(local.q)}">
      <span class="count">${rules.length} of ${total} named rules</span>
      ${rules.length ? '<button class="small primary" data-act="det-all">Download all</button>' : ''}
    </div>
    ${total ? '' : '<p class="empty">No include rules have a name. Add one with the # button on a rule, e.g. technique_id=T1059.001,technique_name=PowerShell.</p>'}
    ${rules.slice(0, 120).map((r, i) => `<article class="card det">
      <header><h3>${h(r.name)}</h3><span class="pill">${h(r.tag)} · ${r.items.length} rule${r.items.length > 1 ? 's' : ''}</span>
        <button class="small" data-act="det-copy" data-idx="${i}">Copy</button></header>
      <pre class="code">${h(GEN[local.format](ctx.state.cfg, r))}</pre></article>`).join('')}
    ${rules.length > 120 ? `<p class="mode-help">Showing 120 of ${rules.length}. Download all to get everything.</p>` : ''}`;
}

export function click(act, btn, ctx) {
  if (act === 'det-format') { local.format = btn.dataset.format; ctx.render(); return true; }
  if (act === 'det-copy') { ctx.copyText(GEN[local.format](ctx.state.cfg, all(ctx)[+btn.dataset.idx]), 'Copied.'); return true; }
  if (act === 'det-all') {
    const [, label, ext] = FORMATS.find(f => f[0] === local.format);
    const rules = all(ctx);
    const text = local.format === 'sigma'
      ? rules.map(r => GEN.sigma(ctx.state.cfg, r)).join('---\n')
      : rules.map(r => `// ${r.tag}: ${r.name}\n${GEN[local.format](ctx.state.cfg, r)}\n`).join('\n');
    ctx.downloadText(`sysmon-detections.${ext}`, text);
    ctx.toast(`Downloaded ${rules.length} ${label} ${local.format === 'sigma' ? 'rules' : 'queries'}.`);
    return true;
  }
  return false;
}

export function input(t, ctx) {
  if (t.id !== 'det-q') return false;
  local.q = t.value;
  clearTimeout(local.timer);
  local.timer = setTimeout(() => { ctx.render(); const q = ctx.$('#det-q'); q.focus(); q.setSelectionRange(q.value.length, q.value.length); }, 250);
  return true;
}
