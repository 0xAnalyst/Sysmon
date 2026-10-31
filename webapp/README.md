# Sysmon Config Builder

Live at **https://0xanalyst.github.io/Sysmon/**.

A browser-based workbench for building, testing and deploying Sysmon configurations. It targets the latest Sysmon schema (**4.90**, Sysmon 15.x, event IDs 1–29) and Sysmon for Linux. It is a static site with no backend: configs and log samples never leave your browser.

It starts from this repo's `sysmonv9.xml` and `SysmonForLinux/config.xml`, and imports any other Sysmon XML (SwiftOnSecurity, sysmon-modular, MSTIC…). Older schemas are upgraded.

## What it does

### Configure
- **Event editor**: set each event to *Not set / Off / Log all / Filtered* and edit its include and exclude rules. You can change the field, condition, value, `name=` (RuleName / MITRE tag) and comment, and use compound `<Rule groupRelation="and|or">` blocks. Rules can be disabled, moved between include and exclude, reordered by dragging, and filtered.
- **Undo/redo** for every change, plus keyboard shortcuts (press `?` in the app).
- **Detection modules**: curated, ATT&CK-tagged rule packs such as C2 named pipes, LOLBin network connections, LSASS dumping, registry persistence, ransomware prep, staging drops, DNS abuse and Linux persistence. Turning a module off removes exactly the rules it added. A module never narrows an event that already logs everything.
- **Exclusion wizard**: add the same process or folder exclusion across many events, with shortcuts for common AV/EDR and log agents.
- **Starters** for events added after older configs were written (DnsQuery, ProcessTampering, FileDeleteDetected, FileExecutableDetected…).
- **Exact schema**: paste the output of `sysmon -s` from the binary you deploy, and field and event checks will match it exactly.
- **Validation**:
  - fields that don't belong to the event, and unknown conditions
  - events that are too new for the target schema
  - duplicate rules, and stray leading or trailing spaces
  - revoked ATT&CK IDs in rule names
  - **risky exclusions** in user-writable paths

### Analyze
- **Event tester**: paste real events and see whether they are logged or dropped, and which rule decided. Edit fields to ask "what if". An **evasion check** tries a renamed binary, a copy in a user-writable folder, and an obfuscated command line, and flags any that would avoid logging. Accepted formats:
  - Event Viewer XML
  - `wevtutil` or `Get-WinEvent` output
  - Sysmon for Linux syslog
  - Splunk or Elastic JSON/CSV
- **Log analysis**: load a sample of real logs to see:
  - what this config would keep, per event and per day
  - the noisiest processes, each with a safety rating (*safer / review / risky*) and a one-click exclusion
  - which include rules never fired
- **ATT&CK coverage**: a heatmap of techniques referenced by include rule names. Revoked IDs are mapped to their replacements. Click a technique to see its rules, or export an **ATT&CK Navigator layer**.
- **Compare & merge**: diff against your last download, a preset or any XML. Pull rules across one by one or all at once, and export a Markdown diff for review.

### Export
- **Download** with an automatic changelog line in the header (`+12/-3 rules; ProcessAccess +9 …`) and a version bump.
- **Share links**: the config is compressed into the URL itself, and nothing is uploaded.
- **SIEM & Sigma**: for every named include rule, generate:
  - Sigma rules rebuilt from the conditions, with ATT&CK tags
  - Splunk SPL, Microsoft Sentinel KQL and Elastic queries that search on `RuleName`
- **Deployment scripts**: each one installs Sysmon when missing, upgrades it when the binary changes, and reapplies the config only when its SHA256 changes. Available targets:
  - GPO startup script (batch or PowerShell)
  - Intune remediation (detection and remediation, with the config embedded)
  - Linux shell script
  - Ansible playbook

## Develop

ES modules need to be served over HTTP. Serve the **repo root** so the presets resolve:

```bash
python3 -m http.server 8765
```

Then open http://localhost:8765/webapp/.

Tests use Vitest with jsdom and need Node 22 or 24:

```bash
cd webapp && npm ci && npm test
```

## CI

- **`.github/workflows/validate.yml`** runs on every change to the app or the configs, and weekly:
  1. Unit tests.
  2. Generates configs from the presets, from the presets plus every module and starter, and from a synthetic config that uses every event and every condition.
  3. Installs the real Sysmon from Sysinternals on a Windows runner and applies each generated config.
  4. Compares `sysmon -s` with the builder's schema and warns about new events, fields or conditions.

  A Sysmon for Linux job does the same on Ubuntu. It is marked experimental because it depends on the runner kernel's eBPF support.
- **`.github/workflows/pages.yml`** runs the tests, then publishes the app to GitHub Pages with the repo's current configs as presets.

## Layout

| Path | Purpose |
| --- | --- |
| `js/schema.js` | Events, fields, conditions, options, schema history, and the `sysmon -s` loader |
| `js/config.js` | XML parser and generator, and the config model |
| `js/matcher.js` | Sysmon rule evaluation and event parsing (XML, JSON, CSV) |
| `js/validate.js` | Validation rules |
| `js/modules.js`, `js/presets.js` | Detection modules, presets, starters and EDR paths |
| `js/attack.js`, `js/attack-data.js` | ATT&CK coverage. Regenerate the data with `scripts/build-attack.py` |
| `js/diff.js`, `js/detections.js`, `js/deploy.js`, `js/share.js` | Diff/changelog, SIEM/Sigma, deployment scripts, share links |
| `js/views/*.js` | One module per Analyze/Export page |
| `scripts/` | CI helpers: config export, schema-drift check, ATT&CK data build |
| `test/` | Vitest suites |

## Notes on semantics

- Each event's include and exclude rules are written into their own `RuleGroup groupRelation="or"`. An imported `RuleGroup groupRelation="and"` becomes an AND `<Rule>`, so the behavior is unchanged.
- In schema 3.x, filters without a RuleGroup ANDed different fields together. The importer warns about this when upgrading.
- **Off** is written as an empty `onmatch="include"`, **Log all** as an empty `onmatch="exclude"`, and **Not set** leaves the event out so Sysmon's default applies.
- Disabled rules are written as `<!-- DISABLED: ... -->` comments and come back disabled when re-imported.
