# Licenses and attribution

## This repository

| Content | License |
| --- | --- |
| Sysmon configurations (`sysmonv9.xml`, `SysmonForLinux/config.xml`, `dfir/windows-ir.xml`, `dfir/overlays/`, `archive/`) | [Creative Commons Attribution 4.0](LICENSE) |
| The config builder (`webapp/`), `startupscript.bat`, `dfir/scripts/`, `dfir/tests/` and CI workflows | [MIT](webapp/LICENSE) |

When you publish or redistribute a config from this repo, or one derived from it, keep the credit lines in its header comment.

## Sources

The configurations build on the following work. Credit for individual rules is also kept in comments inside the configs.

| Source | Used in | License |
| --- | --- | --- |
| [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) by @SwiftOnSecurity and contributors | Base of the Windows configs | CC BY 4.0 |
| [sysmon-modular](https://github.com/olafhartong/sysmon-modular) by Olaf Hartong | Windows detections | MIT |
| [Sigma](https://github.com/SigmaHQ/sigma) rules by SigmaHQ and contributors | Windows and Linux detections | [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License) |
| [JPCERT/CC Tool Analysis Result Sheet](https://jpcertcc.github.io/ToolAnalysisResultSheet/) | Windows detections | Research reference |
| [microsoft/MSTIC-Sysmon](https://github.com/microsoft/MSTIC-Sysmon) | Base of the Linux config | MIT |
| [GTFOBins](https://gtfobins.github.io/) | Linux detections | Research reference (GPL-3.0 project) |
| [The DFIR Report](https://thedfirreport.com/reports/) | Design of `dfir/` and its test cases (behaviors summarized, no report text reproduced) | Research reference |
| [MITRE ATT&CK](https://attack.mitre.org/) | Rule names and the builder's coverage data | [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) |

The builder's ATT&CK data (`webapp/js/attack-data.js`) is generated from [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data). © The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.
