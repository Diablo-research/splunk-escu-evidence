# Native lab results, 2026-11-02

Windows Server 2025 Standard Evaluation domain controller (lab.local), Sysinternals ADExplorer64.exe, Sysmon 15.22 with `lab/adx-sysmon.xml`. Test script: `lab/Test-ADExplorerSnapshot.ps1`, run as LAB\Administrator. The EulaAccepted value was preset, as an attacker would do. Run run-20261102-044002, 127 events.

| Case | How | Existing Sigma-style process rule (image name + "snapshot") | Existing Sigma-style file rule (ADExplorer image writes .dat) | New Execution (Anomaly) | New Snapshot (TTP) |
|---|---|---|---|---|---|
| cli_snapshot_dat | `ADExplorer64.exe -snapshot "" snap-cli.dat` | yes | yes | yes | **yes** |
| cli_snapshot_tmp_ext | `ADExplorer64.exe -snapshot "" cache-0001.tmp` | yes | **no** | yes | **yes** |
| renamed_cli_snapshot | copy renamed to `svc-helper.exe`, `-snapshot` | **no** | **no** | yes (renamed=yes) | **yes** |
| gui_menu_snapshot | GUI, File > Create Snapshot to snap-gui.dat | **no** | yes | yes | **yes** |
| gui_launch_no_snapshot | GUI start, connect, close | no | no | yes | no (correct) |
| negative_powershell_ldap | PowerShell LDAP query | no | no | no | no |

Each existing approach catches 2 of the 4 real snapshots. Correlating OriginalFileName `AdExp` (EID 1) with file creation (EID 11) by ProcessGuid catches all 4.

## Observations
1. **OriginalFileName is `AdExp`** and survives renaming (svc-helper.exe kept it).
2. **Every connection writes the ADSI schema cache** `%LOCALAPPDATA%\Microsoft\Windows\SchCache\<dc>.sch`, even without a snapshot. A rule on "any file written by ADExplorer" would fire on every GUI use, so this path is excluded.
3. **GUI snapshots leave no command-line trace**; only the file write shows that a snapshot was taken.
4. **The extension is arbitrary**: `.tmp` worked the same as `.dat`.
5. **LDAP (EID 3):** ADExplorer and the renamed copy connect to 389 over loopback and link-local IPv6, mixed in with lsass, ADWS, dfsrs and svchost. Port-based hunting is noisy on a DC.
6. **Registry:** each start writes `HKU\<SID>\SOFTWARE\Sysinternals\Active Directory Explorer\EulaAccepted`, including the renamed copy. This could support a later generic "renamed Sysinternals tool" analytic.

## Splunk (lab, exact YAML searches with the filter macro expanded to `search *`)
- Windows Sysinternals ADExplorer Execution: 5 results (renamed=yes on svc-helper.exe; snapshot_cli=yes on the 3 CLI cases).
- Windows AD Snapshot Created By ADExplorer: 4 results (snap-cli.dat, cache-0001.tmp, snap-renamed.dat, snap-gui.dat). No SchCache result.
