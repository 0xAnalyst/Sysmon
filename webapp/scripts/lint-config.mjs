// Runs the builder's validation on Sysmon config files and prints GitHub annotations.
//   node scripts/lint-config.mjs ../sysmonv9.xml ../SysmonForLinux/config.xml
// Exits 1 on errors and warnings. Info-level notes (for example name-only image
// exclusions) are listed but do not fail the run.
import './dom.mjs';
import { readFileSync } from 'node:fs';
import { parseXml } from '../js/config.js';
import { validate } from '../js/validate.js';

const LEVEL = { error: 'error', warn: 'warning', info: 'notice' };
let failed = 0;
for (const file of process.argv.slice(2)) {
  const { config: cfg } = parseXml(readFileSync(file, 'utf8'));
  const issues = validate(cfg);
  for (const i of issues) {
    console.log(`::${LEVEL[i.level]} file=${file}::${i.event ? i.event + ': ' : ''}${i.msg}`);
  }
  const bad = issues.filter(i => i.level !== 'info').length;
  failed += bad;
  console.log(`${file}: ${bad} error(s)/warning(s), ${issues.length - bad} note(s)`);
}
process.exit(failed ? 1 : 0);
