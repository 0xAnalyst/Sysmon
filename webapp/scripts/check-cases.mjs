// Runs events reconstructed from real intrusions through a config with the builder's rule engine.
//   node scripts/check-cases.mjs ../dfir/windows-ir.xml ../dfir/tests/cases.json
//   node scripts/check-cases.mjs --report-only ../sysmonv9.xml ../dfir/tests/cases.json
// Exits 1 when a case does not get its expected verdict, unless --report-only is given.
// With GITHUB_STEP_SUMMARY set, also writes a Markdown table to the job summary.
import './dom.mjs';
import { readFileSync, appendFileSync } from 'node:fs';
import { basename } from 'node:path';
import { parseXml } from '../js/config.js';
import { evaluate, describeItem } from '../js/matcher.js';

const args = process.argv.slice(2);
const reportOnly = args.includes('--report-only');
const [configFile, casesFile] = args.filter(a => !a.startsWith('--'));
const { config: cfg } = parseXml(readFileSync(configFile, 'utf8'));
const { cases } = JSON.parse(readFileSync(casesFile, 'utf8'));

const rows = cases.map(c => {
  const r = evaluate(cfg, c.event);
  // Not configured means Sysmon's built-in default applies, which an IR config must not rely on.
  const verdict = r.logged === true ? 'logged' : r.logged === false ? 'dropped' : 'not configured';
  const why = r.exclude ? `excluded by ${describeItem(r.exclude)}` : r.include ? `included by ${describeItem(r.include)}` : r.reason;
  return { ...c, verdict, why, ok: verdict === c.expect };
});

const failed = rows.filter(r => !r.ok);
const logged = rows.filter(r => r.expect === 'logged');
const caught = logged.filter(r => r.verdict === 'logged').length;
for (const r of failed) {
  const msg = `${r.id} (${r.event.tag}): expected ${r.expect}, got ${r.verdict}. ${r.behavior}. ${r.why}`;
  console.log(reportOnly ? `  miss: ${msg}` : `::error file=${casesFile}::${msg}`);
}
const name = basename(configFile);
console.log(`${name}: logs ${caught}/${logged.length} intrusion behaviors; ${rows.length - failed.length}/${rows.length} cases as expected`);

if (process.env.GITHUB_STEP_SUMMARY) {
  const lines = [`### ${name}: ${caught}/${logged.length} intrusion behaviors logged`, ''];
  if (failed.length) {
    lines.push('| Case | Event | Expected | Got | Why |', '| --- | --- | --- | --- | --- |');
    for (const r of failed) lines.push(`| ${r.behavior} | ${r.event.tag} | ${r.expect} | ${r.verdict} | ${r.why.replace(/\|/g, '\\|')} |`);
  } else {
    lines.push('Every case got its expected verdict.');
  }
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, lines.join('\n') + '\n\n');
}
process.exit(failed.length && !reportOnly ? 1 : 0);
