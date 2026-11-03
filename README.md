# Evidence for Splunk ESCU detection proposals

Raw lab logs, test scripts and Splunk results behind five detection proposals opened on
[splunk/security_content](https://github.com/splunk/security_content). Everything here was produced in a small
home lab ([LAB.md](LAB.md)): **one Windows 11 workstation, one Windows Server 2025 domain controller VM, and one Splunk
Enterprise container**. No production telemetry is included, and no false-positive rate is claimed beyond the
controlled negative cases listed in each folder.

| Folder | Issue | Machine | Events | Proposed detections (type, expected results on the dataset) | Splunk output |
|---|---|---|---|---|---|
| [01-ssh-keygen-pkcs11-provider](01-ssh-keygen-pkcs11-provider/README.md) | [#4382](https://github.com/splunk/security_content/issues/4382) | Host A (Windows 11) | 488 | Windows SSH Keygen Unsigned PKCS11 Provider Load (Anomaly, 13) | [replay](01-ssh-keygen-pkcs11-provider/results/splunk-replay.md) |
| [02-winget-configure](02-winget-configure/README.md) | [#4383](https://github.com/splunk/security_content/issues/4383) | Host A (Windows 11) | 49 | Windows WinGet Configuration File From Remote URL (TTP, 1)<br>Windows WinGet Configuration Remoting Server Execution (Anomaly, 6) | [replay](02-winget-configure/results/splunk-replay.md) |
| [03-dmsa-badsuccessor](03-dmsa-badsuccessor/README.md) | [#4384](https://github.com/splunk/security_content/issues/4384) | VM B (Server 2025 DC) | 49 | Windows AD dMSA Object Creation (Anomaly, 2)<br>Windows AD dMSA Predecessor Link Without Superseded Account Link (TTP, 1) | [replay](03-dmsa-badsuccessor/results/splunk-replay.md) |
| [04-chromium-remote-debugging](04-chromium-remote-debugging/README.md) | [#4389](https://github.com/splunk/security_content/issues/4389) | Host A (Windows 11) | 188 | Windows Chromium Browser Remote Debugging Enabled (Anomaly, 5)<br>Windows Non-Browser Process Connection To Chromium DevTools Port (Hunting, 1) | [replay](04-chromium-remote-debugging/results/splunk-replay.md) |
| [05-adexplorer-snapshot](05-adexplorer-snapshot/README.md) | [#4393](https://github.com/splunk/security_content/issues/4393) | VM B (Server 2025 DC) | 127 | Windows AD Snapshot Created By ADExplorer (TTP, 4)<br>Windows Sysinternals ADExplorer Execution (Anomaly, 5) | [replay](05-adexplorer-snapshot/results/splunk-replay.md) |

## What each folder contains
- `README.md`: the technique, the exact lab setup, every test case (positives and negatives), what the data shows, sample raw events and limits.
- `data/windows-events.log`: the raw Windows XML events (Sysmon or Security) exported with `Get-WinEvent ... ToXml()`, in the format used by [splunk/attack_data](https://github.com/splunk/attack_data). `dataset.yml` gives the source and sourcetype.
- `detections/`: the proposed ESCU YAML files, as in the patch that would be submitted.
- `lab/`: the capture script that generated the data, with its Sysmon configuration or audit setup.
- `results/`: `splunk-replay.md` / `.json` from `tools/replay.py`, and the native lab notes.

[`contentctl-build.txt`](contentctl-build.txt) shows all nine detections added to current `splunk/security_content` develop and built with `contentctl-ng`.

## Reproduce
1. Any Splunk with ESCU (`DA-ESS-ContentUpdate`) and the Sysmon / Windows TA: load `data/windows-events.log` with the sourcetype and source from `dataset.yml`, and run each YAML search with its filter macro removed.
2. Or run `tools/replay.py` inside the Splunk container (`/opt/splunk/bin/splunk cmd python3 tools/replay.py <repo>`). It creates one index per proposal (`ev_*`), loads the dataset, checks that the indexed events are byte-identical to the file, runs the proposed and comparison searches exactly as written (filter macro replaced by `search *`, index added), and writes `results/splunk-replay.md`. `tools/contentctl-check.sh` adds the YAML files to current develop and runs `contentctl-ng build`.

## Anonymization
Workstation captures: host and user names replaced (`WIN-*-LAB`, `LabUser`), private IP replaced. DC captures: IP addresses and the domain SID replaced (`S-1-5-21-1000000000-2000000000-3000000000`); the lab domain `lab.local` and its throw-away objects are unchanged. Nothing else was edited.

## Licence
The datasets and scripts may be redistributed under Apache-2.0, including inclusion in splunk/attack_data and splunk/security_content.

Author: Nazar Diachok ([Diablo-research](https://github.com/Diablo-research)).
