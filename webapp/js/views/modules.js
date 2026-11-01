// Detection module library: switch curated rule packs on and off.

import { MODULES, includeWouldNarrow } from '../modules.js';
import { EVENT_BY_TAG } from '../schema.js';

const enabled = (cfg, id) => Object.values(cfg.events).some(ev => ev.include.some(i => i.module === id));

function enable(ctx, m) {
  const cfg = ctx.state.cfg;
  const prev = (cfg.modulePrev ||= {})[m.id] = {};
  const skipped = [];
  let added = 0;
  for (const spec of m.rules) {
    const ev = cfg.events[spec.event];
    if (!ev || !EVENT_BY_TAG[spec.event].platforms.includes(cfg.platform)) continue;
    if (includeWouldNarrow(ev)) { skipped.push(spec.event); continue; }
    prev[spec.event] = ev.mode;
    if (ev.mode !== 'filtered') ev.mode = 'filtered';
    const items = spec.items().map(i => ({ ...i, module: m.id }));
    items[0].before = [`Module: ${m.title}`];
    ev.include.push(...items);
    added += items.length;
  }
  return { added, skipped };
}

function disable(ctx, m) {
  const cfg = ctx.state.cfg;
  let removed = 0;
  for (const [tag, ev] of Object.entries(cfg.events)) {
    const before = ev.include.length;
    ev.include = ev.include.filter(i => i.module !== m.id);
    removed += before - ev.include.length;
    const prev = cfg.modulePrev?.[m.id]?.[tag];
    if (prev && !ev.include.length && !ev.exclude.length) ev.mode = prev;
  }
  if (cfg.modulePrev) delete cfg.modulePrev[m.id];
  return removed;
}

export function html(ctx) {
  const { h, state } = ctx;
  const mods = MODULES.filter(m => m.platform === state.cfg.platform);
  return `<header><h2>Detection modules</h2>
    <p class="lede">Curated include rules for common attacker tradecraft, tagged with ATT&amp;CK technique IDs. Turning a module off removes exactly the rules it added. Modules never narrow an event that already logs everything: if ProcessCreate logs all processes, adding include rules would hide the rest, so that part is skipped.</p></header>
    <div class="module-grid">${mods.map(m => {
      const on = enabled(state.cfg, m.id);
      const count = m.rules.reduce((n, r) => n + r.items().length, 0);
      const covered = m.rules.filter(r => includeWouldNarrow(state.cfg.events[r.event])).map(r => r.event);
      return `<article class="card module ${on ? 'on' : ''}">
        <header><h3>${h(m.title)}</h3><button class="small ${on ? '' : 'primary'}" data-act="mod-toggle" data-id="${m.id}">${on ? 'Turn off' : 'Turn on'}</button></header>
        <p>${h(m.desc)}</p>
        <p class="meta">${count} rules · ${m.rules.map(r => h(r.event)).join(', ')}</p>
        ${covered.length && !on ? `<p class="meta">Already logging everything: ${covered.map(h).join(', ')} (skipped)</p>` : ''}
      </article>`;
    }).join('') || '<p class="empty">No modules for this platform yet.</p>'}</div>`;
}

export function click(act, btn, ctx) {
  if (act !== 'mod-toggle') return false;
  const m = MODULES.find(x => x.id === btn.dataset.id);
  ctx.commit();
  if (enabled(ctx.state.cfg, m.id)) {
    const n = disable(ctx, m);
    ctx.toast(`Removed ${n} rules from "${m.title}".`);
  } else {
    const { added, skipped } = enable(ctx, m);
    ctx.toast(`Added ${added} rules from "${m.title}".` + (skipped.length ? ` Skipped ${skipped.join(', ')}: it already logs everything.` : ''));
  }
  ctx.render();
  return true;
}
