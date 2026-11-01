# Security policy

## Reporting

Please report security problems privately, through GitHub's [private vulnerability reporting](https://github.com/0xAnalyst/Sysmon/security/advisories/new), not in a public issue. This covers:

- a way to stop a config from logging activity it is meant to catch (an exclusion an attacker can abuse)
- a vulnerability in the config builder site, such as script injection through an imported config or share link
- a problem in the deployment scripts

We will acknowledge reports as soon as we can and credit you in the fix unless you prefer otherwise.

## Scope notes

Sysmon is not hardened against an attacker with administrator rights, and any filtering config leaves gaps by design. Reports are most useful when they show a realistic technique that the config misses and suggest a rule that catches it without much noise.

The builder runs entirely in your browser. It has no backend, and configs and logs you load are never uploaded.
