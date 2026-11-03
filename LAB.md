# Lab environment

The lab has **two Windows machines and one Splunk instance**. It is a test lab, not a production network: each
dataset comes from controlled test cases (positives and negatives) run by the scripts in that folder's `lab/`.

| Machine | Role | OS / software | Used for |
|---|---|---|---|
| **Host A** | physical workstation | Windows 11 Home x64; Sysmon 15.22 (configs in each `lab/`); Windows OpenSSH 9.5.6.2; WinGet 1.29.380; Edge 156.0.4314.58; Chrome 156.0.8078.74 | 01 PKCS#11, 02 WinGet, 04 Chromium |
| **VM B** | domain controller | Windows Server 2025 Standard Evaluation (build 26100), single DC of the isolated domain `lab.local`, VMware Workstation Pro on Host A (NAT network); Sysmon 15.22; Security auditing "Directory Service Changes" + SACL (see 03) | 03 dMSA, 05 ADExplorer |
| **Splunk** | SIEM | Splunk Enterprise in a Docker container on Host A, with ESCU (`DA-ESS-ContentUpdate`) and the Sysmon TA. Exact versions are printed at the top of each `results/splunk-replay.md` | all |

## Method (same for every proposal)
1. Apply the Sysmon configuration (or audit policy) in `lab/`.
2. Run the test script. It executes each case (including negative controls), waits, stops the processes it started, and exports the matching events with `Get-WinEvent ... ToXml()`.
3. Load the XML into Splunk as `XmlWinEventLog` (source `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` or `XmlWinEventLog:Security`).
4. Run the proposed YAML searches exactly as written (filter macro replaced by `search *`), plus comparison searches for existing logic.
5. Add the YAML files to `splunk/security_content` develop and run the field-order hook and `contentctl-ng build` (`tools/contentctl-check.sh`; output in [`contentctl-build.txt`](contentctl-build.txt)).

## What this lab does not show
- False-positive rates in real environments: only the listed negative controls were tested.
- Multi-DC or multi-host behaviour (one DC, one workstation).
- EDR data sources other than Sysmon / Windows Security.
