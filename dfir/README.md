# Sysmon for incident response

A Sysmon configuration and a small kit for **incident response engagements** on Windows: deploy fast on hosts that may already be compromised, log what investigations need, collect the evidence with hashes, and leave the client's systems as they were.

It is not a production detection config. It logs far more than [`sysmonv9.xml`](../sysmonv9.xml) and is meant to run for the length of an engagement.

| File | Purpose |
| --- | --- |
| [`windows-ir.xml`](windows-ir.xml) | The IR Sysmon config (schema 4.90, Sysmon 15.x) |
| [`scripts/Deploy-SysmonIR.ps1`](scripts/Deploy-SysmonIR.ps1) | Install or reconfigure Sysmon, raise log sizes, enable the needed audit policy, self-test |
| [`scripts/Collect-SysmonIR.ps1`](scripts/Collect-SysmonIR.ps1) | Export logs and deleted-file copies into a zip with a SHA256 manifest |
| [`scripts/Remove-SysmonIR.ps1`](scripts/Remove-SysmonIR.ps1) | Restore the client's original Sysmon, logging and audit settings |
| [`overlays/example-client.xml`](overlays/example-client.xml) | Template for per-client noise exclusions |
| [`tests/cases.json`](tests/cases.json) | Events reconstructed from real intrusions; the config must log all of them |
| [`tests/Test-SysmonIRKit.ps1`](tests/Test-SysmonIRKit.ps1) | Lab check that a deployed host logs intrusion-like activity |

The scripts run on Windows PowerShell 5.1 and need an elevated prompt. Every release attaches the kit as `sysmon-dfir-kit.zip`.

## Why it is built this way

The design comes from the 82 intrusions published by [The DFIR Report](https://thedfirreport.com/reports/) between 2020 and 2026. Approximate share of intrusions:

| Finding | Share | What the config does about it |
| --- | --- | --- |
| C2 ran inside an injected Windows process (svchost, dllhost, wermgr, winlogon…) | 37% | Network connections and DNS are logged for every process, not a list of "interesting" programs |
| Binaries were renamed or disguised (rclone as `svchost.exe`, rundll32 as `calc.exe`) | 60% | Exclusions are by full path only; the IR validation rejects name-only exclusions |
| LSASS was accessed for credentials | 70% | Every handle to LSASS that can read memory is logged |
| Tools were written to ProgramData, Temp, Users\Public, PerfLogs, Windows\Temp | 30–55% each | Every file written there is logged, plus every new executable anywhere |
| Attackers deleted their tools after use | 37% | Executables and scripts deleted from those folders are kept in `SysmonIRArchive` |
| Persistence by scheduled task, service, Run key or remote-access tool | 30–48% each | Task, service, autostart, Defender, RDP, firewall and logging registry keys are logged |
| Ransomware followed initial access within hours (often 2–5 h) | many | Deployment takes minutes; collect or forward continuously |

The reports also lean on Windows logs as much as on Sysmon: logons (4624), new services (7045/4697), share access (5145) and PowerShell script blocks (4104). The deploy script turns those on too.

**Real-case tests.** [`tests/cases.json`](tests/cases.json) holds 71 events reconstructed from the reports: 65 intrusion behaviors the config must log, and 6 noise checks that confirm the exclusions work. CI runs them on every change with the builder's rule engine. For comparison, the production config logs 32 of the 65.

## Engagement workflow

### Before the engagement
1. Run the kit once in a lab or on a test host: `Deploy-SysmonIR.ps1`, then `tests\Test-SysmonIRKit.ps1`, then `Collect-SysmonIR.ps1` and `Remove-SysmonIR.ps1`.
2. Check performance on a workstation, a server and a domain controller like the client's.
3. Agree with the client in writing: what is collected (command lines can contain secrets), where evidence is stored, and how long the kit stays installed.

### Per client: exclusions overlay
Never edit `windows-ir.xml` per client. Copy [`overlays/example-client.xml`](overlays/example-client.xml), add only exclusions confirmed as noise in that client's logs (the builder's **Log analysis** page ranks the noisiest processes), then merge and check:

```bash
cd webapp && node scripts/apply-overlay.mjs ../dfir/windows-ir.xml ../dfir/overlays/acme.xml ../out/sysmon-acme.xml
```

```bash
node scripts/check-cases.mjs ../out/sysmon-acme.xml ../dfir/tests/cases.json
```

The merge rejects name-only exclusions, exclusions in user-writable folders, and anything that stops a core event from logging everything. The case check shows whether an exclusion hides a real intrusion behavior. You can also load the config in the [builder](https://0xanalyst.github.io/Sysmon/) (preset **0xAnalyst Windows DFIR**) and add exclusions there.

### Deploy
On each host, from an elevated PowerShell:

```powershell
.\Deploy-SysmonIR.ps1 -SysmonExe \\share\ir\Sysmon64.exe -ConfigPath \\share\ir\sysmon-acme.xml
```

- Use `-Download` instead of `-SysmonExe` to fetch Sysmon from Sysinternals (the Microsoft signature is checked).
- If Sysmon is already installed (standalone or the built-in Windows feature), the script exports its event log and config first, then applies the IR config to it. Removal restores the original config.
- Runs the same way through EDR live response, PsExec, a GPO startup script or Velociraptor (point the `Windows.Sysinternals.SysmonInstall` artifact at the same config). Re-running is safe.
- `-DetailedFileShare` adds 5145 auditing (noisy on file servers and DCs). `-SkipAuditPolicy` and `-SkipLogSizes` leave those settings alone.

### During the engagement
- Forward the Sysmon and Security logs off the host (WEF, the client's SIEM agent, Velociraptor), or run `Collect-SysmonIR.ps1` regularly. Attackers clear logs.
- Watch for hosts that go quiet, and for Sysmon events 4 (service state), 16 (config change) and 255 (error).
- Watch disk use of `C:\SysmonIRArchive` on busy hosts.
- Triage exported logs with Hayabusa or Chainsaw. Rule names carry ATT&CK IDs, so matches show the technique.

### Collect and remove

```powershell
.\Collect-SysmonIR.ps1 -OutputDir \\evidence\case-1234
.\Remove-SysmonIR.ps1 -RemoveArchive
```

The zip holds the exported logs, the deleted-file copies, the deployment backups (including any Sysmon log from before deployment), host details and `manifest-sha256.csv`; its own hash is in `<zip>.sha256`. Removal refuses to run before a collection exists (override with `-Force`).

## Caveats

- **Windows versions.** Microsoft lists current Sysmon for Windows 11 and Windows Server 2019 or later. Older servers (2012 R2, 2016) need an older Sysmon binary and a config with an older schema; test before relying on them.
- **Group Policy.** A domain GPO that sets advanced audit policy overrides the script's audit settings at the next refresh. Check with `auditpol /get /category:*`.
- **Safe Mode.** Some ransomware reboots into Safe Mode, where Sysmon may not run. The config logs changes to the `SafeBoot` key that precede it.
- **Off by default:** clipboard capture (user data, needs explicit approval) and the blocking events 27/28 (they change the hosts under investigation).
- **Volume.** Expect several times the event volume of a production config. Size forwarding accordingly.
