import { describe, it, expect } from 'vitest';
import { testCondition, evaluate, parseEvents } from '../js/matcher.js';
import { newConfig, newCond, newRule } from '../js/config.js';

describe('conditions', () => {
  const cases = [
    ['is', 'C:\\A.exe', 'c:\\a.exe', true],
    ['is not', 'a', 'b', true],
    ['is any', 'b', 'a;b;c', true],
    ['contains', 'powershell -enc', 'ENC', true],
    ['contains any', 'curl x', 'wget;curl', true],
    ['contains all', 'dd if=/dev/zero of=x', 'dd;if=;of=', true],
    ['contains all', 'dd if=x', 'dd;if=;of=', false],
    ['excludes', 'abc', 'x', true],
    ['excludes any', 'abc', 'a;x', true],
    ['excludes all', 'abc', 'x;y', true],
    ['excludes all', 'abc', 'a;y', false],
    ['begin with', 'C:\\Users\\bob', 'c:\\users', true],
    ['not begin with', 'C:\\Windows', 'c:\\users', true],
    ['end with', 'C:\\x\\lsass.exe', '\\lsass.exe', true],
    ['not end with', 'a.dll', '.exe', true],
    ['less than', 'a', 'b', true],
    ['more than', 'b', 'a', true],
    ['image', 'C:\\Windows\\System32\\certutil.exe', 'certutil.exe', true],
    ['image', 'C:\\Temp\\certutil.exe', 'C:\\Windows\\System32\\certutil.exe', false],
  ];
  it.each(cases)('%s: %s vs %s', (cond, field, value, expected) => {
    expect(testCondition(cond, field, value)).toBe(expected);
  });
});

describe('evaluate', () => {
  const cfg = newConfig('windows');
  const pc = cfg.events.ProcessCreate;
  pc.mode = 'filtered';
  pc.include.push(newCond('Image', 'end with', '\\powershell.exe'));
  const r = newRule('and', 'office child');
  r.conds.push(newCond('ParentImage', 'end with', '\\winword.exe'), newCond('Image', 'end with', '\\cmd.exe'));
  pc.include.push(r);
  pc.exclude.push(newCond('CommandLine', 'contains', 'safe-script'));
  cfg.events.ImageLoad.mode = 'off';
  cfg.events.DnsQuery.mode = 'all';
  const ev = (id, fields) => ({ id, fields });

  it('keeps include matches', () => expect(evaluate(cfg, ev(1, { Image: 'C:\\x\\powershell.exe' })).logged).toBe(true));
  it('drops events no include matches', () => expect(evaluate(cfg, ev(1, { Image: 'C:\\x\\notepad.exe' })).logged).toBe(false));
  it('lets exclude win', () => {
    const res = evaluate(cfg, ev(1, { Image: 'C:\\x\\powershell.exe', CommandLine: 'run safe-script' }));
    expect(res.logged).toBe(false);
    expect(res.exclude).not.toBeNull();
  });
  it('needs every condition of an AND rule', () => {
    expect(evaluate(cfg, ev(1, { Image: 'C:\\x\\cmd.exe', ParentImage: 'C:\\o\\WINWORD.EXE' })).include?.name).toBe('office child');
    expect(evaluate(cfg, ev(1, { Image: 'C:\\x\\cmd.exe', ParentImage: 'C:\\x\\explorer.exe' })).logged).toBe(false);
  });
  it('handles Off, Log all and unset', () => {
    expect(evaluate(cfg, ev(7, {})).logged).toBe(false);
    expect(evaluate(cfg, ev(22, {})).logged).toBe(true);
    expect(evaluate(cfg, ev(3, {})).logged).toBeNull();
  });
  it('maps registry IDs 12-14 to RegistryEvent', () => {
    expect(evaluate(cfg, ev(13, {})).tag).toBe('RegistryEvent');
  });
});

describe('parseEvents', () => {
  it('reads Event Viewer XML', () => {
    const [e] = parseEvents(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID>
      <TimeCreated SystemTime="2026-10-31T00:00:00Z"/></System><EventData><Data Name="Image">C:\\a.exe</Data></EventData></Event>`);
    expect(e).toMatchObject({ id: 1, tag: 'ProcessCreate', fields: { Image: 'C:\\a.exe' } });
  });
  it('reads Winlogbeat-style JSON lines', () => {
    const evs = parseEvents('{"winlog":{"event_id":3,"event_data":{"Image":"C:\\\\b.exe","DestinationPort":"443"}}}\n{"winlog":{"event_id":22,"event_data":{"QueryName":"x.com"}}}');
    expect(evs.map(e => e.tag)).toEqual(['NetworkConnect', 'DnsQuery']);
    expect(evs[0].fields.DestinationPort).toBe('443');
  });
  it('reads CSV exports', () => {
    const [e] = parseEvents('EventCode,Image,CommandLine\n1,"C:\\a.exe","a.exe ""quoted"", arg"\n');
    expect(e.fields.CommandLine).toBe('a.exe "quoted", arg');
  });
});
