// MITRE ATT&CK coverage from rule names (technique_id=T1003, TechniqueID=T1021.004, attack.t1083 ...).

import { TACTICS, TECHNIQUES, ATTACK_VERSION, REVOKED } from './attack-data.js';
import { EVENTS } from './schema.js';

export { TACTICS, ATTACK_VERSION };
export const TECH_BY_ID = new Map(TECHNIQUES.map(([id, name, tactics, plats]) => [id, { id, name, tactics, plats }]));

const TECH_RE = /\bT\d{4}(?:\.\d{3})?\b/gi;
const rawIds = text => [...new Set((String(text || '').match(TECH_RE) || []).map(t => t.toUpperCase()))];

// Technique IDs in a rule name, with revoked IDs mapped to their current replacement.
export function techniqueIds(text) {
  return [...new Set(rawIds(text).map(id => REVOKED[id] || id))].filter(id => TECH_BY_ID.has(id));
}

// [[oldId, newId]] for revoked IDs used in a rule name.
export function revokedIds(text) {
  return rawIds(text).filter(id => REVOKED[id]).map(id => [id, REVOKED[id]]);
}

// Rules that add visibility: enabled include rules in events that are logged.
// Returns { byTech: Map(id -> [{tag, item}]), untagged, tagged }.
export function coverage(cfg) {
  const byTech = new Map();
  let untagged = 0, tagged = 0;
  for (const e of EVENTS) {
    if (!e.platforms.includes(cfg.platform)) continue;
    const ev = cfg.events[e.tag];
    if (!ev || ev.mode !== 'filtered') continue;
    for (const item of ev.include) {
      if (item.enabled === false) continue;
      const names = [item.name, ...(item.conds || []).map(c => c.name)].join(' ');
      const ids = techniqueIds(names);
      if (!ids.length) { untagged++; continue; }
      tagged++;
      for (const id of ids) (byTech.get(id) || byTech.set(id, []).get(id)).push({ tag: e.tag, item });
    }
  }
  return { byTech, untagged, tagged };
}

// Matrix rows for a platform: [{ tactic, name, techniques: [{ id, name, count, subCount, subs }] }]
export function matrix(cfg, byTech) {
  const plat = cfg.platform === 'linux' ? 'l' : 'w';
  return TACTICS.map(([short, name]) => {
    const parents = TECHNIQUES.filter(([id, , tac, p]) => !id.includes('.') && tac.includes(short) && p.includes(plat));
    const techniques = parents.map(([id, tname]) => {
      const subs = TECHNIQUES.filter(([sid, , tac, p]) => sid.startsWith(id + '.') && tac.includes(short) && p.includes(plat))
        .map(([sid, sname]) => ({ id: sid, name: sname, count: byTech.get(sid)?.length || 0 }));
      const count = byTech.get(id)?.length || 0;
      return { id, name: tname, count, subs, subCount: subs.filter(s => s.count).length };
    });
    return { tactic: short, name, techniques };
  });
}

// ATT&CK Navigator layer (https://mitre-attack.github.io/attack-navigator/).
export function navigatorLayer(cfg, byTech, title) {
  const max = Math.max(1, ...[...byTech.values()].map(v => v.length));
  const version = (ATTACK_VERSION.match(/v(\d+)/) || [])[1] || '17';
  return {
    name: title || 'Sysmon config coverage',
    versions: { attack: version, navigator: '5.1.0', layer: '4.5' },
    domain: 'enterprise-attack',
    description: `Techniques referenced by include rule names in a Sysmon ${cfg.platform} config (schema ${cfg.schemaversion}).`,
    filters: { platforms: [cfg.platform === 'linux' ? 'Linux' : 'Windows'] },
    gradient: { colors: ['#d6f5ef', '#0f766e'], minValue: 0, maxValue: max },
    techniques: [...byTech.entries()].map(([id, list]) => ({
      techniqueID: id,
      score: list.length,
      comment: [...new Set(list.map(r => r.tag))].join(', '),
      enabled: true,
    })),
  };
}
