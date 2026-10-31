import { describe, it, expect } from 'vitest';
import { newConfig, newCond, parseXml } from '../js/config.js';
import { EVENT_BY_TAG, CONDITION_NAMES } from '../js/schema.js';
import { MODULES, includeWouldNarrow } from '../js/modules.js';
import { STARTERS } from '../js/presets.js';
import { diffConfigs, changelogLine, diffMarkdown } from '../js/diff.js';
import { namedRules, sigma, splunk, sentinel, elastic } from '../js/detections.js';
import { TARGETS, generate } from '../js/deploy.js';
import { coverage, techniqueIds, navigatorLayer } from '../js/attack.js';
import { windowsXml } from './helpers.js';

const allItems = list => list.flatMap(i => (i.kind === 'rule' ? i.conds : [i]));

describe('modules and starters', () => {
  it.each(MODULES.map(m => [m.id, m]))('%s only uses valid events, fields and conditions', (id, m) => {
    for (const spec of m.rules) {
      const e = EVENT_BY_TAG[spec.event];
      expect(e, spec.event).toBeDefined();
      expect(e.platforms).toContain(m.platform);
      for (const c of allItems(spec.items())) {
        expect(e.fields, `${spec.event}.${c.field}`).toContain(c.field);
        expect(CONDITION_NAMES).toContain(c.condition);
        expect(c.value).not.toBe('');
      }
    }
  });

  it('starters use valid fields', () => {
    for (const [tag, s] of Object.entries(STARTERS)) {
      for (const c of allItems([...(s.include?.() || []), ...(s.exclude?.() || [])])) expect(EVENT_BY_TAG[tag].fields).toContain(c.field);
    }
  });

  it('knows when include rules would narrow an event', () => {
    expect(includeWouldNarrow({ mode: 'all', include: [], exclude: [] })).toBe(true);
    expect(includeWouldNarrow({ mode: 'filtered', include: [], exclude: [newCond('Image', 'is', 'x')] })).toBe(true);
    expect(includeWouldNarrow({ mode: 'unset', include: [], exclude: [] })).toBe(false);
  });
});

describe('diff', () => {
  it('reports added and removed rules and builds a changelog line', () => {
    const a = newConfig('windows');
    const b = newConfig('windows');
    b.events.DnsQuery.mode = 'filtered';
    b.events.DnsQuery.exclude.push(newCond('QueryName', 'end with', '.arpa'));
    const d = diffConfigs(a, b);
    expect(d.events).toHaveLength(1);
    expect(d.events[0].exclude.added).toHaveLength(1);
    expect(changelogLine(d, 3, new Date('2026-10-31'))).toBe('2026-10-31 v3: +1/-0 rules; DnsQuery +1 unset->filtered');
    expect(diffMarkdown(d, 'a', 'b')).toContain('**+ exclude:**');
  });
});

describe('detections', () => {
  const cfg = parseXml(windowsXml()).config;
  const rules = namedRules(cfg);

  it('finds named include rules', () => expect(rules.length).toBeGreaterThan(10));

  it('builds Sigma with ATT&CK tags and a condition', () => {
    const y = sigma(cfg, rules[0]);
    expect(y).toMatch(/^title: /m);
    expect(y).toMatch(/^ {4}condition: /m);
    expect(y).toMatch(/attack\.t\d{4}/);
  });

  it('builds RuleName queries for each SIEM', () => {
    for (const fn of [splunk, sentinel, elastic]) expect(fn(cfg, rules[0])).toContain(rules[0].name.replace(/\\/g, '\\\\').slice(0, 10));
  });
});

describe('coverage', () => {
  it('maps revoked technique IDs to their replacement', () => {
    expect(techniqueIds('technique_id=T1060,technique_name=Registry Run Keys')).toEqual(['T1547.001']);
    expect(techniqueIds('TechniqueID=attack.t1083')).toEqual(['T1083']);
  });

  it('produces a Navigator layer', () => {
    const cfg = parseXml(windowsXml()).config;
    const cov = coverage(cfg);
    const layer = navigatorLayer(cfg, cov.byTech);
    expect(layer.domain).toBe('enterprise-attack');
    expect(layer.techniques.length).toBe(cov.byTech.size);
  });
});

describe('deployment scripts', () => {
  it.each(TARGETS.map(t => [t.id]))('%s embeds the inputs', id => {
    const out = generate(id, { xml: '<Sysmon schemaversion="4.90"/>', hash: 'ABC123', share: '\\\\srv\\share' });
    expect(out.length).toBeGreaterThan(200);
    if (id.startsWith('intune') || id === 'linux-sh' || id === 'ansible') expect(out).toContain('ABC123');
    if (id.startsWith('gpo')) expect(out).toContain('\\\\srv\\share');
  });

  it('batch script compares hashes instead of only checking that a file exists', () => {
    const bat = generate('gpo-bat', { xml: '', hash: '' });
    expect(bat).toContain('certutil -hashfile');
    expect(bat).toMatch(/-c "%SHARE%\\%CFG%"/);
  });
});
