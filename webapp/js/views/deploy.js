// Deployment script generator.

import { TARGETS, generate } from '../deploy.js';

const local = { target: null, share: '\\\\UNCPATH\\Sysmon', exe: 'Sysmon64.exe', configName: 'sysmonconfig.xml', hash: '', hashOf: '' };

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

function script(ctx) {
  const xml = ctx.currentXml();
  return generate(local.target, { xml, hash: local.hashOf === xml ? local.hash : '(computing…)', share: local.share, exe: local.exe, configName: local.configName });
}

export function html(ctx) {
  const { h, state } = ctx;
  const targets = TARGETS.filter(t => t.platform === state.cfg.platform);
  if (!targets.some(t => t.id === local.target)) local.target = targets[0].id;
  const t = TARGETS.find(x => x.id === local.target);
  const win = state.cfg.platform === 'windows';
  return `<header><h2>Deployment scripts</h2>
    <p class="lede">Scripts that install Sysmon, upgrade it when the binary changes, and reapply the config only when its content changes. They are safe to run on every boot or check-in.</p></header>
    <div class="toolbar"><div class="modes" role="group" aria-label="Target">${targets.map(x =>
      `<button data-act="dep-target" data-id="${x.id}" aria-pressed="${x.id === local.target}">${h(x.label)}</button>`).join('')}</div></div>
    <p class="mode-help">${h(t.help)}</p>
    ${win && local.target.startsWith('gpo') ? `<div class="form compact">
      <div class="field"><label for="dep-share">Share path</label><div><input type="text" id="dep-share" value="${h(local.share)}"></div></div>
      <div class="field"><label for="dep-exe">Sysmon binary</label><div><select id="dep-exe">
        <option ${local.exe === 'Sysmon64.exe' ? 'selected' : ''}>Sysmon64.exe</option><option ${local.exe === 'Sysmon.exe' ? 'selected' : ''}>Sysmon.exe</option></select></div></div>
      <div class="field"><label for="dep-cfg">Config file name</label><div><input type="text" id="dep-cfg" value="${h(local.configName)}"></div></div>
    </div>` : ''}
    <div class="toolbar"><button class="small primary" data-act="dep-download">Download ${h(t.file)}</button><button class="small" data-act="dep-copy">Copy</button>
      ${local.target.startsWith('intune') || !win ? '<span class="count">The config is embedded with the comment and disabled-rule options of the XML preview.</span>' : ''}</div>
    <pre class="code tall" id="dep-code">${h(script(ctx))}</pre>`;
}

export function after(ctx) {
  const xml = ctx.currentXml();
  if (local.hashOf === xml) return;
  sha256(xml).then(hash => {
    local.hash = hash;
    local.hashOf = xml;
    const el = ctx.$('#dep-code');
    if (el) el.textContent = script(ctx);
  });
}

export function click(act, btn, ctx) {
  if (act === 'dep-target') { local.target = btn.dataset.id; ctx.render(); return true; }
  if (act === 'dep-copy') { ctx.copyText(script(ctx), 'Script copied.'); return true; }
  if (act === 'dep-download') { ctx.downloadText(TARGETS.find(x => x.id === local.target).file, script(ctx)); return true; }
  return false;
}

export function input(t) {
  if (t.id === 'dep-share') { local.share = t.value; return true; }
  if (t.id === 'dep-cfg') { local.configName = t.value; return true; }
  return false;
}

export function change(t, ctx) {
  if (t.id === 'dep-exe') { local.exe = t.value; ctx.render(); return true; }
  if (t.id === 'dep-share' || t.id === 'dep-cfg') { ctx.render(); return true; }
  return false;
}
