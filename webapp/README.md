# Sysmon Config Builder

A browser-based editor for Sysmon configurations, targeting the latest Sysmon schema (**4.90**, Sysmon 15.x, event IDs 1–29) and Sysmon for Linux. It is a static site with no build step and no backend: config files never leave the browser.

Live at **https://0xanalyst.github.io/Sysmon/**. It starts from this repo's `sysmonv9.xml` and `SysmonForLinux/config.xml` and can import any other Sysmon XML.

## Features

- **Presets**: the 0xAnalyst Windows config (MITRE/JPCERT/sysmon-modular) and Linux config (MSTIC + Sigma + GTFOBins), or a blank config.
- **Import** any config by file or paste. Older schemas (3.x, 4.x) are upgraded to the target schema.
- **Event editor**: for each event, choose *Not set / Off / Log all / Filtered*, then edit include and exclude rules. You can change the field, condition, value, `name=` (RuleName / MITRE tag) and comment, disable a rule without deleting it, move a rule between include and exclude, and filter the list.
- **Compound rules**: `<Rule groupRelation="and|or">` blocks, as used in the Linux config.
- **Exclusion wizard**: add the same process or folder exclusion to many events at once, with shortcuts for common AV/EDR and log agents. It only touches events that are already being logged, so it never switches an event on by accident.
- **Starters for newer events** (DnsQuery, ProcessTampering, FileDeleteDetected, FileExecutableDetected, and others) for configs written before those events existed.
- **Validation**:
  - fields that don't exist for the event, and unknown conditions
  - events that are too new for the chosen schema
  - duplicate rules, and rules that are both included and excluded
  - values with stray leading or trailing spaces
  - **risky exclusions** in user-writable paths (`C:\Users`, `AppData`, `Temp`, `/tmp`…) where malware could hide
- **Live XML preview** with copy, download, and the install/update commands.
- **Lossless round-trip**: comments, section headings, `name=` tags and disabled rules are kept. Disabled rules are written as `<!-- DISABLED: ... -->` and come back as disabled when re-imported.
- Your work is saved automatically in the browser's local storage.

## Run locally

ES modules need to be served over HTTP. Opening `index.html` from disk won't work. Serve the **repo root** so the presets resolve:

```bash
python3 -m http.server 8765
```

Then open http://localhost:8765/webapp/.

## Deployment

`.github/workflows/pages.yml` publishes `webapp/` to GitHub Pages on every push to `master` that touches the app or the configs. It copies `sysmonv9.xml` and `SysmonForLinux/config.xml` into the site as presets, so the builder always offers the latest committed configs.

## Layout

| Path | Purpose |
| --- | --- |
| `js/schema.js` | Events, fields, conditions, options and schema history. Update this when Sysmon adds events. |
| `js/config.js` | XML parser and generator, and the config model |
| `js/validate.js` | Validation rules |
| `js/presets.js` | Presets, starter rules for newer events, and EDR/agent paths for the wizard |
| `js/app.js` | UI |
| `presets/*.xml` | Added at deploy time from the repo's configs |

## Notes on semantics

- The generator writes each event's include and exclude rules into its own `RuleGroup groupRelation="or"`. An imported `RuleGroup groupRelation="and"` becomes an AND `<Rule>`, so the behavior is unchanged.
- In schema 3.x, filters without a RuleGroup ANDed different fields together. The importer warns about this when it upgrades an old config, so check exclusions that relied on it.
- **Off** is written as an empty `onmatch="include"` (log nothing). **Log all** is written as an empty `onmatch="exclude"`. **Not set** leaves the event out, so Sysmon's default applies.
