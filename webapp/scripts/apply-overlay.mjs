// Merges a client overlay (a Sysmon XML holding only extra exclusions, or extra includes) into a
// base config, then validates the result with the incident-response profile.
//   node scripts/apply-overlay.mjs ../dfir/windows-ir.xml client-overlay.xml out/sysmon-client.xml
// Exits 1 if the merged config breaks an IR rule; check it against the real cases afterwards with
// scripts/check-cases.mjs.
import './dom.mjs';
import { readFileSync, writeFileSync } from 'node:fs';
import { basename } from 'node:path';
import { parseXml, generateXml } from '../js/config.js';
import { validate } from '../js/validate.js';

const [baseFile, overlayFile, outFile] = process.argv.slice(2);
if (!outFile) {
  console.error('usage: node scripts/apply-overlay.mjs <base.xml> <overlay.xml> <out.xml>');
  process.exit(2);
}
const { config: base } = parseXml(readFileSync(baseFile, 'utf8'));
const { config: overlay } = parseXml(readFileSync(overlayFile, 'utf8'));

let added = 0;
for (const [tag, ov] of Object.entries(overlay.events)) {
  if (ov.mode !== 'filtered') continue;
  const ev = base.events[tag];
  if (!ev) continue;
  if (ov.include.length && ev.mode === 'all') {
    console.log(`::warning::${tag}: ignoring overlay includes, the base config already logs every ${tag} event`);
  } else if (ov.include.length) {
    ev.include.push(...ov.include);
    added += ov.include.length;
  }
  if (ov.exclude.length) {
    if (ev.mode === 'all' || ev.mode === 'unset' || ev.mode === 'off') {
      if (ev.mode === 'off') { console.log(`::warning::${tag}: base config has it off; overlay exclusions ignored`); continue; }
      ev.mode = 'filtered';
    }
    ev.exclude.push(...ov.exclude);
    added += ov.exclude.length;
  }
}
base.header = `${base.header || ''}\n  Client overlay: ${basename(overlayFile)} (${added} rules) merged on ${new Date().toISOString().slice(0, 10)}`;
writeFileSync(outFile, generateXml(base));

const issues = validate(base, { profile: 'ir' }).filter(i => i.level !== 'info');
for (const i of issues) console.log(`::${i.level === 'error' ? 'error' : 'warning'}::${i.event ? i.event + ': ' : ''}${i.msg}`);
console.log(`${outFile}: merged ${added} overlay rules; ${issues.filter(i => i.level === 'error').length} IR error(s)`);
process.exit(issues.some(i => i.level === 'error') ? 1 : 0);
