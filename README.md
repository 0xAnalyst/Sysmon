# Sysmon configuration, scripts and config builder

Sysmon configurations for Windows and Linux mapped to MITRE ATT&CK, a startup script for deploying them, and a web app for tuning them to your environment.

[![Validate configs](https://github.com/0xAnalyst/Sysmon/actions/workflows/validate.yml/badge.svg)](https://github.com/0xAnalyst/Sysmon/actions/workflows/validate.yml)
[![Deploy config builder](https://github.com/0xAnalyst/Sysmon/actions/workflows/pages.yml/badge.svg)](https://github.com/0xAnalyst/Sysmon/actions/workflows/pages.yml)
[![Latest release](https://img.shields.io/github/v/release/0xAnalyst/Sysmon)](https://github.com/0xAnalyst/Sysmon/releases/latest)
[![Config license: CC BY 4.0](https://img.shields.io/badge/configs-CC%20BY%204.0-lightgrey)](LICENSE)
[![Code license: MIT](https://img.shields.io/badge/code-MIT-blue)](webapp/LICENSE)

## Sysmon Config Builder

**Open it at https://0xanalyst.github.io/Sysmon/**

The builder starts from the configs in this repo, or from any Sysmon XML you import, and targets the latest Sysmon schema (4.90, Sysmon 15.x, event IDs 1–29) and Sysmon for Linux. It runs entirely in your browser: configs and log samples are never uploaded.

| | |
| --- | --- |
| **Configure** | Edit every event's include and exclude rules, with undo/redo, compound AND/OR rules and drag-to-reorder. Turn ATT&CK-tagged **detection modules** on and off, add AV/EDR **exclusions** across many events at once, and load the exact schema of your Sysmon binary from `sysmon -s`. |
| **Validate** | Catches fields that don't belong to an event, events newer than the target schema, duplicate rules, stray spaces, revoked ATT&CK IDs and **risky exclusions** in user-writable paths. |
| **Event tester** | Paste real events (Event Viewer XML, `Get-WinEvent`, Linux syslog, Splunk/Elastic JSON or CSV) to see whether each is logged or dropped, and which rule decided. An **evasion check** tries renamed binaries, copies in user-writable folders and obfuscated command lines. |
| **Log analysis** | Load a sample of real logs to see how much the config keeps per event and per day. It ranks the noisiest processes, rates each exclusion's safety and lists include rules that never fired. |
| **ATT&CK coverage** | A heatmap of the techniques your rules reference, exportable as an ATT&CK Navigator layer. |
| **Compare & merge** | Diff against your last download, a preset or any XML, and pull rules across. |
| **Export** | Download with an automatic changelog and version bump, or share the whole config inside a link. Generate Sigma rules, Splunk/Sentinel/Elastic queries, and deployment scripts for GPO, Intune, Linux and Ansible. |

See [`webapp/README.md`](webapp/README.md) for the full feature list and how to run it locally.

## Configurations

Download a tested version from [Releases](https://github.com/0xAnalyst/Sysmon/releases), or take the latest from `master`. The Windows config's changelog is in its header comment.

| File | Platform | Description |
| --- | --- | --- |
| [`sysmonv9.xml`](sysmonv9.xml) | Windows | The main config. The builder's default preset. |
| [`SysmonForLinux/config.xml`](SysmonForLinux/config.xml) | Linux | Sysmon for Linux config. The builder's Linux preset. |
| [`archive/sysmonconfig.xml`](archive/) | Windows | The first config in this repo. Not maintained. |

### Windows (`sysmonv9.xml`)
We added detections from [JPCERT's tool analysis result sheet](https://jpcertcc.github.io/ToolAnalysisResultSheet/). We also included most of [sysmon-modular](https://github.com/olafhartong/sysmon-modular) and some of the [Sigma Sysmon rules](https://github.com/SigmaHQ/sigma). Our target is to map most of MITRE ATT&CK and JPCERT in this config.

You might need to add exclusions for software in your environment, such as antivirus, EDR or application whitelisting. Some events are noisy, such as the pipe events. The builder's exclusion wizard and log analysis are designed for exactly this.

### Linux (`SysmonForLinux/config.xml`)
Based on the MSTIC Sysmon for Linux config, with added detections from Sigma Linux rules, GTFOBins and malware research. See [`SysmonForLinux/README.md`](SysmonForLinux/README.md).

## Deploying with Group Policy

[`startupscript.bat`](startupscript.bat) is a GPO computer startup script. Put `sysmon.exe` and your config on a file share, set `SHARE`, `EXE` and `CFG` at the top of the script, and add it as a startup script. On each boot it:

- installs Sysmon when it is missing
- reinstalls when the binary on the share changes
- reapplies the config when the copy on the share changes (compared by SHA256), keeping the local copy only if Sysmon accepted it

To roll out a config change, replace the file on the share. The builder's **Deploy** page generates the same script, and PowerShell, Intune, Linux and Ansible versions, with your config name filled in.

## Continuous validation

Every change to the configs or the builder, and a weekly scheduled run, goes through [`validate.yml`](.github/workflows/validate.yml):

1. Runs the builder's unit tests, and lints both configs with its validator. Errors or warnings fail the run.
2. Generates configs from the presets, from the presets with every module and starter enabled, and from a synthetic config that uses every event and condition.
3. Installs the real Sysmon from Sysinternals on a Windows runner and applies the repo config and each generated config. Sysmon for Linux does the same on Ubuntu.
4. Compares `sysmon -s` from the latest Sysmon release with the builder's schema, and warns when a release adds events, fields or conditions.

Pushes to `master` that touch the builder or the configs redeploy the site, with the current configs as its presets.

## Contributing

Reports of noisy events and missed detections are welcome. Use the issue templates, and see [CONTRIBUTING.md](CONTRIBUTING.md) for how to propose a rule. Report bypasses and vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

To publish a release, push a tag such as `v10.1`. [`release.yml`](.github/workflows/release.yml) reruns the validation and attaches the configs, the startup script and checksums.

## License

The configurations are licensed under [CC BY 4.0](LICENSE), and the config builder and scripts under [MIT](webapp/LICENSE). They build on SwiftOnSecurity's sysmon-config, sysmon-modular, Sigma, JPCERT/CC research, MSTIC-Sysmon and GTFOBins. See [NOTICE.md](NOTICE.md) for credits and licenses.
