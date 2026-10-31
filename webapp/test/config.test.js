import { describe, it, expect } from 'vitest';
import { parseXml, generateXml, newConfig, newCond, newRule } from '../js/config.js';
import { EVENTS } from '../js/schema.js';
import { windowsXml, linuxXml } from './helpers.js';

const countConds = cfg => EVENTS.reduce((n, e) => n + ['include', 'exclude'].reduce((m, k) =>
  m + cfg.events[e.tag][k].reduce((s, i) => s + (i.kind === 'rule' ? i.conds.length : 1), 0), 0), 0);

const sourceConds = xml => {
  const doc = new DOMParser().parseFromString(xml, 'application/xml');
  return [...doc.querySelectorAll('EventFiltering *')].filter(el =>
    el.getAttribute('condition') !== null || (!el.children.length && el.parentElement.getAttribute('onmatch') !== null)).length;
};

describe.each([['windows', windowsXml], ['linux', linuxXml]])('%s preset', (platform, load) => {
  it('keeps every condition and detects the platform', () => {
    const { config } = parseXml(load());
    expect(config.platform).toBe(platform);
    expect(countConds(config)).toBe(sourceConds(load()));
  });

  it('round-trips to identical XML', () => {
    const x1 = generateXml(parseXml(load()).config);
    const x2 = generateXml(parseXml(x1).config);
    expect(x2).toBe(x1);
    expect(new DOMParser().parseFromString(x1, 'application/xml').querySelector('parsererror')).toBeNull();
  });
});

describe('generator', () => {
  it('escapes values and keeps disabled rules as restorable comments', () => {
    const cfg = newConfig('windows');
    const ev = cfg.events.ProcessCreate;
    ev.mode = 'filtered';
    ev.include.push(newCond('CommandLine', 'contains', '--flag & <x> "q"', { comment: 'a -- b' }));
    ev.include.push(newCond('CommandLine', 'contains any', '-enc;--x', { enabled: false, name: 'T1059' }));
    const r = newRule('and', 'pair');
    r.conds.push(newCond('Image', 'end with', 'ssh.exe'), newCond('CommandLine', 'contains', '-R', { enabled: false }));
    ev.exclude.push(r);
    const back = parseXml(generateXml(cfg)).config.events.ProcessCreate;
    expect(back.include.map(i => [i.value, i.enabled, i.name])).toEqual([
      ['--flag & <x> "q"', true, ''],
      ['-enc;--x', false, 'T1059'],
    ]);
    expect(back.exclude[0].conds.map(c => [c.value, c.enabled])).toEqual([['ssh.exe', true], ['-R', false]]);
  });

  it('writes Off and Log all as empty filters and skips unset events', () => {
    const cfg = newConfig('windows');
    cfg.events.ImageLoad.mode = 'off';
    cfg.events.DnsQuery.mode = 'all';
    const xml = generateXml(cfg);
    expect(xml).toContain('<ImageLoad onmatch="include"/>');
    expect(xml).toContain('<DnsQuery onmatch="exclude"/>');
    expect(xml).not.toContain('<ProcessCreate');
  });

  it('never writes an empty include next to live excludes', () => {
    const cfg = newConfig('windows');
    const ev = cfg.events.NetworkConnect;
    ev.mode = 'filtered';
    ev.include.push(newCond('Image', 'is', 'a.exe', { enabled: false }));
    ev.exclude.push(newCond('Image', 'is', 'b.exe'));
    const xml = generateXml(cfg);
    expect(xml).not.toContain('<NetworkConnect onmatch="include">');
    expect(xml).toContain('<NetworkConnect onmatch="exclude">');
  });
});

describe('parser', () => {
  it('turns an AND RuleGroup into one AND rule', () => {
    const { config } = parseXml(`<Sysmon schemaversion="4.90"><EventFiltering>
      <RuleGroup name="g" groupRelation="and"><ProcessCreate onmatch="include">
        <Image condition="end with">timeout.exe</Image><CommandLine condition="contains">100</CommandLine>
      </ProcessCreate></RuleGroup></EventFiltering></Sysmon>`);
    const [item] = config.events.ProcessCreate.include;
    expect(item.kind).toBe('rule');
    expect(item.relation).toBe('and');
    expect(item.conds).toHaveLength(2);
  });

  it('warns about AND semantics when upgrading schema 3.x', () => {
    const { notes } = parseXml('<Sysmon schemaversion="3.40"><EventFiltering/></Sysmon>');
    expect(notes.join(' ')).toMatch(/AND between different fields/);
  });

  it('rejects non-Sysmon XML', () => {
    expect(() => parseXml('<foo/>')).toThrow(/expected <Sysmon>/);
  });
});
