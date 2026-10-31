import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Tests run from webapp/; the configs live at the repo root.
const repo = resolve(process.cwd(), '..');
export const windowsXml = () => readFileSync(resolve(repo, 'sysmonv9.xml'), 'utf8');
export const linuxXml = () => readFileSync(resolve(repo, 'SysmonForLinux/config.xml'), 'utf8');
