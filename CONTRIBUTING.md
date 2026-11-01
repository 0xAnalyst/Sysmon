# Contributing

Thanks for helping improve these configs. False-positive reports are as valuable as new detections.

## Reporting

- **Noisy event or missed detection:** open an issue with the matching template. Include the Sysmon event (XML from Event Viewer or `Get-WinEvent ... | % { $_.ToXml() }`), with hostnames and usernames removed.
- **Security problem in the builder or a bypass of the config:** see [SECURITY.md](SECURITY.md).

## Changing a config

The quickest way is the [config builder](https://0xanalyst.github.io/Sysmon/): import the config, make your change, and download it. The builder validates the config, and its event tester shows which rule matches an event.

When adding a rule:

1. **Name include rules with their ATT&CK technique**, in the format the configs already use:
   `name="technique_id=T1547.001,technique_name=Registry Run Keys / Startup Folder"`.
   Use current technique IDs; the builder flags revoked ones.
2. **Add a comment** saying what the rule catches or excludes, and credit your source.
3. **Prefer full paths for exclusions.** Excluding a binary by name, or a folder users can write to, lets an attacker hide by copying malware there. The builder warns about both.
4. **Test it.** Paste a sample event into the builder's event tester and check the verdict. Put the event in your pull request if you can.

## Checks

Every pull request that touches a config or the builder runs [validate.yml](.github/workflows/validate.yml). It:

- lints both configs with the builder's validator (`webapp/scripts/lint-config.mjs`), which must report no errors or warnings
- runs the builder's tests
- installs the real Sysmon on Windows and Sysmon for Linux on Ubuntu, and applies every config

To run the lint and tests locally (Node 22 or 24):

```bash
cd webapp && npm ci && npm test
```

```bash
node scripts/lint-config.mjs ../sysmonv9.xml ../SysmonForLinux/config.xml
```

## Changing the builder

See [webapp/README.md](webapp/README.md) for its layout and how to run it locally. Keep it dependency-free in the browser: plain ES modules, no build step.

## Licensing

By contributing you agree that config changes are licensed under CC BY 4.0 and code changes under MIT, as described in [NOTICE.md](NOTICE.md).
