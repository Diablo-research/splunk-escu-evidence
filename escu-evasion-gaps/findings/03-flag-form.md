# Finding: option-char substitution (- vs /), ArgFuscator-validated

## The gap
Many rules match a command-line switch in ONE prefix form only — e.g. `process="*/create*"` or `process="*-enc*"`. The target binary accepts the other prefix equally, so swapping `/create`↔`-create` runs identically but evades the rule. Sigma solves this with the `windash` modifier; ESCU has no equivalent (only 2 rules handle it).

## Live Splunk confirmation
Combined originals → ff_orig.log, one-flag-prefix-swapped → ff_swapped.log, uploaded, rex Image/CommandLine, stats count by source.

| Rule | Type | swap | orig | swapped | fixed |
|---|---|---|---|---|---|
| Windows DISM Remove Defender | TTP | /disable-feature → -disable-feature | 2 | 0 | 2 |
| Certutil exe certificate extraction | TTP | -exportPFX → /exportPFX | 12 | 0 | 12 |
| Bcdedit Command Back To Normal Mode Boot | TTP | /deletevalue → -deletevalue | 2 | 0 | 2 |

## Two-sided confirmation
- Attack side: anchored to ArgFuscator.net (Wietze Beukema), which lab-validated option-char substitution per binary. 24 of the flag_form binaries (covering ~160 rules) accept both `/` and `-`: powershell, auditpol, schtasks, wmic, certutil, regsvr32, cmdkey, taskkill, dism, w32tm, netstat, msiexec, ipconfig, wevtutil, bcdedit, csc, query, reg, whoami, takeown, ftp, procdump, adfind, certreq.
- Detection side: sandbox replay — mutate the matched flag's prefix in each rule's attack_data, confirm the match drops to 0. A rule counts only when BOTH hold.

## Result: 29 confirmed flag-form bypasses
15 TTP, 9 Anomaly, 5 Hunting. Full table: results/flag_form_confirmed_final.csv (BYPASS rows). High-impact:
- Defense evasion: DISM Remove Defender, Bcdedit (safe mode / normal boot), Powershell Defender Threat Actions Set to Allow, Auditpol tampering ×3.
- Credential access: Certutil certificate extraction (12 ev), cmdkey password-store deletion/query.
- Execution/persistence/lateral: Schtasks family (Create Run As System, Highest Privileges, remote scheduling, forcing reboot), Remote Process Instantiation via WMI/PowerShell, Wmic uninstall (16 ev).

## Fix
Match both prefixes: `process IN ("*/create*","*-create*")` or `match(process,"[-/]create")`. Better: an ESCU equivalent of Sigma's `windash` (normalise `/`↔`-`, ideally Unicode dashes U+2013/2014/2015). ArgFuscator also validates Unicode-dash and other obfuscations per binary — a second wave.

## Caveat
Option-char substitution is a parser-level property, validated by ArgFuscator on its modeled command; extending to a specific flag not in ArgFuscator's test string is reasonable but not individually lab-tested. Three rules were confirmed in live Splunk; the remainder rest on the replay simulation plus ArgFuscator. 23 candidates were not reproduced from their shipped dataset (the flag is not present as expected) and require a crafted event.
