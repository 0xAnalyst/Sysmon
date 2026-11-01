import { describe, it, expect } from 'vitest';
import { validate } from '../js/validate.js';
import { newConfig, newCond } from '../js/config.js';

const msgs = cfg => validate(cfg).map(i => `${i.level}: ${i.msg}`);

describe('validate', () => {
  it('flags fields that do not belong to the event', () => {
    const cfg = newConfig('windows');
    cfg.events.DnsQuery.mode = 'filtered';
    cfg.events.DnsQuery.include.push(newCond('TargetFilename', 'is', 'x'));
    expect(msgs(cfg).join('\n')).toMatch(/error: TargetFilename is not a field of DnsQuery/);
  });

  it('flags events newer than the target schema', () => {
    const cfg = newConfig('windows');
    cfg.schemaversion = '4.50';
    cfg.events.FileExecutableDetected.mode = 'all';
    expect(msgs(cfg).join('\n')).toMatch(/needs schema 4.90/);
  });

  it('warns about exclusions in user-writable paths', () => {
    const cfg = newConfig('windows');
    cfg.events.ProcessCreate.mode = 'filtered';
    cfg.events.ProcessCreate.exclude.push(newCond('Image', 'begin with', 'C:\\Users\\Public\\'));
    expect(msgs(cfg).join('\n')).toMatch(/user-writable location/);
  });

  it('does not treat the admin-only DriverStore\\Temp as user-writable', () => {
    const cfg = newConfig('windows');
    cfg.events.FileCreate.mode = 'filtered';
    cfg.events.FileCreate.exclude.push(newCond('TargetFilename', 'begin with', 'C:\\Windows\\System32\\DriverStore\\Temp\\'));
    cfg.events.FileCreate.exclude.push(newCond('TargetFilename', 'begin with', 'C:\\Windows\\Temp\\'));
    const out = msgs(cfg).filter(m => /user-writable/.test(m));
    expect(out).toHaveLength(1);
    expect(out[0]).toMatch(/C:\\Windows\\Temp/);
  });

  it('warns about leading spaces but only notes trailing ones', () => {
    const cfg = newConfig('windows');
    cfg.events.DriverLoad.mode = 'filtered';
    cfg.events.DriverLoad.exclude.push(newCond('Signature', 'begin with', 'Intel '));
    cfg.events.DriverLoad.exclude.push(newCond('Signature', 'begin with', ' Microsoft'));
    const out = msgs(cfg).join('\n');
    expect(out).toMatch(/warn: Value " Microsoft" starts with a space/);
    expect(out).toMatch(/info: Value "Intel " ends with a space/);
  });

  it('points out revoked ATT&CK IDs', () => {
    const cfg = newConfig('windows');
    cfg.events.RegistryEvent.mode = 'filtered';
    cfg.events.RegistryEvent.include.push(newCond('TargetObject', 'contains', '\\Run', { name: 'technique_id=T1060' }));
    expect(msgs(cfg).join('\n')).toMatch(/T1060 \(now T1547.001\)/);
  });
});
