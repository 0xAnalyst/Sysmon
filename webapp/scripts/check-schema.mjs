// Compares the schema printed by a real `sysmon -s` with the builder's built-in schema and
// prints GitHub annotations for anything new, so the builder can be updated.
//   Sysmon64.exe -s > schema.xml && node scripts/check-schema.mjs schema.xml
import './dom.mjs';
import { readFileSync } from 'node:fs';
import { EVENTS, CONDITION_NAMES, LATEST } from '../js/schema.js';

const buf = readFileSync(process.argv[2]);
// sysmon -s writes UTF-16LE, usually without a BOM, so look for the zero high bytes too.
let zeros = 0;
for (let i = 1; i < Math.min(buf.length, 4096); i += 2) if (buf[i] === 0) zeros++;
const utf16 = (buf[0] === 0xff && buf[1] === 0xfe) || zeros > Math.min(buf.length, 4096) / 4;
const text = (utf16 ? buf.toString('utf16le') : buf.toString('utf8')).replace(/^\uFEFF/, '');
const start = text.indexOf('<manifest');
if (start < 0) {
  console.log(`::error::No <manifest> in the sysmon -s output (${buf.length} bytes, starts ${JSON.stringify(text.slice(0, 200))})`);
  process.exit(1);
}
const doc = new DOMParser().parseFromString(text.slice(start, text.lastIndexOf('</manifest>') + 11), 'application/xml');
const root = doc.documentElement;

const real = new Map();
for (const ev of root.getElementsByTagName('event')) {
  const tag = ev.getAttribute('rulename');
  if (!tag) continue;
  const fields = real.get(tag) || new Set();
  for (const d of ev.getElementsByTagName('data')) fields.add(d.getAttribute('name'));
  real.set(tag, fields);
}

const findings = [];
const schema = root.getAttribute('schemaversion');
console.log(`sysmon -s: binary ${root.getAttribute('binaryversion')}, schema ${schema}, ${real.size} filterable event types`);
if (schema !== LATEST.windows.schema) findings.push(`Sysmon reports schema ${schema}; the builder targets ${LATEST.windows.schema} (js/schema.js LATEST)`);
for (const [tag, fields] of real) {
  const e = EVENTS.find(x => x.tag === tag);
  if (!e) { findings.push(`New event type ${tag}: add it to EVENTS in js/schema.js`); continue; }
  const missing = [...fields].filter(f => !e.fields.includes(f));
  if (missing.length) findings.push(`${tag} has fields the builder does not know: ${missing.join(', ')}`);
  const extra = e.fields.filter(f => !fields.has(f) && f !== 'RuleName');
  if (extra.length) findings.push(`${tag}: builder lists fields Sysmon does not report: ${extra.join(', ')}`);
}
for (const e of EVENTS.filter(x => x.platforms.includes('windows'))) {
  if (!real.has(e.tag)) findings.push(`${e.tag} is not in this Sysmon's schema`);
}
for (const f of root.getElementsByTagName('filter')) {
  const c = f.textContent.trim();
  if (c && !CONDITION_NAMES.includes(c)) findings.push(`New condition "${c}": add it to CONDITIONS in js/schema.js`);
}
for (const f of findings) console.log(`::warning title=Sysmon schema drift::${f}`);
console.log(findings.length ? `${findings.length} difference(s) found` : 'Builder schema matches this Sysmon');
