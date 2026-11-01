// Fails if any of the given files is not well-formed XML.
//   node scripts/check-xml.mjs a.xml b.xml
import './dom.mjs';
import { readFileSync } from 'node:fs';

let bad = 0;
for (const file of process.argv.slice(2)) {
  const doc = new DOMParser().parseFromString(readFileSync(file, 'utf8'), 'application/xml');
  const err = doc.getElementsByTagName('parsererror')[0];
  if (err) { console.log(`::error file=${file}::Not well-formed XML: ${err.textContent.trim().split('\n')[0]}`); bad++; }
  else console.log(`${file}: OK`);
}
process.exit(bad ? 1 : 0);
