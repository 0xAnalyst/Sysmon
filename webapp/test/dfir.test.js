import { describe, it, expect } from 'vitest';
import { parseXml, generateXml, newCond } from '../js/config.js';
import { validate } from '../js/validate.js';
import { evaluate } from '../js/matcher.js';
import { dfirXml, dfirCases, windowsXml } from './helpers.js';

const verdict = (cfg, c) => {
  const r = evaluate(cfg, c.event);
  return r.logged === true ? 'logged' : r.logged === false ? 'dropped' : 'not configured';
};
const misses = cfg => dfirCases().filter(c => verdict(cfg, c) !== c.expect).map(c => c.id);

describe('DFIR config', () => {
  const cfg = parseXml(dfirXml()).config;

  it('passes the incident-response validation profile', () => {
    const bad = validate(cfg, { profile: 'ir' }).filter(i => i.level !== 'info');
    expect(bad).toEqual([]);
  });

  it('gives every real-intrusion case its expected verdict', () => {
    expect(misses(cfg)).toEqual([]);
  });

  it('keeps every verdict after a round trip through the generator (as overlays do)', () => {
    expect(misses(parseXml(generateXml(cfg)).config)).toEqual([]);
  });

  it('cases include noise checks, so exclusions are tested too', () => {
    expect(dfirCases().some(c => c.expect === 'dropped')).toBe(true);
  });
});

describe('IR validation profile', () => {
  it('rejects the production config, which uses include lists for core events', () => {
    const errors = validate(parseXml(windowsXml()).config, { profile: 'ir' }).filter(i => i.level === 'error');
    expect(errors.map(e => e.event)).toContain('NetworkConnect');
  });

  it('turns name-only and user-writable exclusions into errors', () => {
    const cfg = parseXml(dfirXml()).config;
    cfg.events.NetworkConnect.mode = 'filtered';
    cfg.events.NetworkConnect.exclude.push(newCond('Image', 'image', 'svchost.exe'));
    cfg.events.FileCreate.exclude.push(newCond('TargetFilename', 'begin with', 'C:\\Users\\'));
    const errors = validate(cfg, { profile: 'ir' }).filter(i => i.level === 'error').map(i => i.msg).join('\n');
    expect(errors).toMatch(/named "svchost.exe"/);
    expect(errors).toMatch(/user-writable/);
    // The same exclusions are only notes/warnings outside the IR profile.
    expect(validate(cfg).filter(i => i.level === 'error')).toEqual([]);
  });

  it('flags a core event that is narrowed to an include list', () => {
    const cfg = parseXml(dfirXml()).config;
    cfg.events.DnsQuery.mode = 'filtered';
    cfg.events.DnsQuery.include.push(newCond('QueryName', 'end with', '.ru'));
    expect(validate(cfg, { profile: 'ir' }).some(i => i.level === 'error' && i.event === 'DnsQuery')).toBe(true);
  });
});
