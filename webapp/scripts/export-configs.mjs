// Writes the XML this builder generates into a folder, so CI can feed it to a real Sysmon.
//   node scripts/export-configs.mjs out
import './dom.mjs';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseXml, generateXml, newConfig, newCond, newRule } from '../js/config.js';
import { EVENTS, CONDITIONS } from '../js/schema.js';
import { MODULES, includeWouldNarrow } from '../js/modules.js';
import { STARTERS } from '../js/presets.js';
import { validate } from '../js/validate.js';

const outDir = resolve(process.argv[2] || 'out');
const repo = resolve(process.cwd(), '..');
mkdirSync(outDir, { recursive: true });

function withModulesAndStarters(cfg) {
  for (const [tag, s] of Object.entries(STARTERS)) {
    const ev = cfg.events[tag];
    if (ev.mode !== 'unset') continue;
    ev.mode = s.mode;
    if (s.include) ev.include.push(...s.include());
    if (s.exclude) ev.exclude.push(...s.exclude());
  }
  for (const m of MODULES.filter(x => x.platform === cfg.platform)) {
    for (const spec of m.rules) {
      const ev = cfg.events[spec.event];
      if (includeWouldNarrow(ev)) continue;
      ev.mode = 'filtered';
      ev.include.push(...spec.items());
    }
  }
  return cfg;
}

// Every event with every condition, plus AND and OR rules. Block events only match a
// folder that does not exist, so applying this config on a CI runner is harmless.
function allConditions(platform) {
  const cfg = newConfig(platform);
  cfg.options.DnsLookup = 'False';
  for (const e of EVENTS.filter(x => x.platforms.includes(platform))) {
    const ev = cfg.events[e.tag];
    ev.mode = 'filtered';
    const field = ['Image', 'SourceImage', 'ImageLoaded', 'QueryName', 'Operation'].find(f => e.fields.includes(f)) || e.fields[1];
    const safe = e.tag.startsWith('FileBlock') ? 'C:\\sysmon-ci-no-such-dir\\' : platform === 'linux' ? '/opt/ci/x' : 'C:\\ci\\x.exe';
    for (const c of CONDITIONS) {
      const value = c.multi ? `${safe};y` : safe;
      ev.include.push(newCond(field, c.name, value, { name: `ci ${c.name}` }));
    }
    for (const rel of ['and', 'or']) {
      const r = newRule(rel, `ci ${rel}`);
      r.conds.push(newCond(field, 'begin with', safe), newCond(e.fields[e.fields.length - 1], 'contains', 'ci'));
      ev.include.push(r);
    }
    ev.exclude.push(newCond(field, 'end with', '.ci-excluded'));
  }
  return cfg;
}

const configs = {
  'windows-preset.xml': parseXml(readFileSync(resolve(repo, 'sysmonv9.xml'), 'utf8')).config,
  'windows-modules.xml': withModulesAndStarters(parseXml(readFileSync(resolve(repo, 'sysmonv9.xml'), 'utf8')).config),
  'windows-all-conditions.xml': allConditions('windows'),
  'linux-preset.xml': parseXml(readFileSync(resolve(repo, 'SysmonForLinux/config.xml'), 'utf8')).config,
  'linux-modules.xml': withModulesAndStarters(parseXml(readFileSync(resolve(repo, 'SysmonForLinux/config.xml'), 'utf8')).config),
  'linux-all-conditions.xml': allConditions('linux'),
};

let errors = 0;
for (const [name, cfg] of Object.entries(configs)) {
  // The "all conditions" configs exist to exercise the parser, not to be sensible.
  const issues = validate(cfg).filter(i => i.level === 'error');
  if (issues.length && !name.includes('all-conditions')) {
    errors += issues.length;
    for (const i of issues) console.log(`::error title=${name}::${i.event || ''} ${i.msg}`);
  }
  writeFileSync(resolve(outDir, name), generateXml(cfg));
  console.log(`wrote ${name}`);
}
process.exit(errors ? 1 : 0);
