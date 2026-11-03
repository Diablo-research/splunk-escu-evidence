# Sysinternals ADExplorer Active Directory snapshots

Proposal: splunk/security_content#4393

**Technique.** Sysinternals Active Directory Explorer can save a full offline snapshot of a domain, which attackers (Scattered Spider, LAPSUS$) use for reconnaissance and BloodHound ingestion. Snapshots can be taken from the command line (`-snapshot "" <file>`) or from the GUI menu, by a renamed copy, to any file name and extension.

**Lab.** VM B in [LAB.md](../LAB.md): Windows Server 2025 domain controller (`lab.local`), Sysinternals `ADExplorer64.exe`, Sysmon 15.22 with `lab/adx-sysmon.xml`. Test script: `lab/Test-ADExplorerSnapshot.ps1`, run as the lab domain administrator. The EulaAccepted value was preset, as an attacker would do.

**Dataset.** `data/windows-events.log`: 127 events (EID 1: 13, EID 3: 94, EID 11: 8, EID 12: 6, EID 13: 6). sha256 `401d49e8fb1127fc2278843208c70617948c42ec0de8ff6232ae5ba5a50bc747`.

## Test cases
| Case | How | Existing Sigma-style process logic | Existing Sigma-style file logic | Execution (proposed) | Snapshot (proposed) |
|---|---|---|---|---|---|
| cli_snapshot_dat | `ADExplorer64.exe -snapshot "" snap-cli.dat` | yes | yes | yes | yes |
| cli_snapshot_tmp_ext | `ADExplorer64.exe -snapshot "" cache-0001.tmp` | yes | **no** | yes | yes |
| renamed_cli_snapshot | copy renamed `svc-helper.exe`, `-snapshot` | **no** | **no** | yes (renamed=yes) | yes |
| gui_menu_snapshot | GUI, File > Create Snapshot -> snap-gui.dat | **no** | yes | yes | yes |
| gui_launch_no_snapshot | GUI start, connect, close | no | no | yes | no (correct) |
| negative_powershell_ldap | PowerShell LDAP query | no | no | no | no |

## Proposed detections
| Detection | Type | Data source | Expected results on this dataset |
|---|---|---|---|
| [Windows AD Snapshot Created By ADExplorer](detections/windows_ad_snapshot_created_by_adexplorer.yml) | TTP | Sysmon EventID 1 AND Sysmon EventID 11 | 4 |
| [Windows Sysinternals ADExplorer Execution](detections/windows_sysinternals_adexplorer_execution.yml) | Anomaly | Sysmon EventID 1 | 5 |

## What the data shows
- OriginalFileName is `AdExp` and survives renaming (`svc-helper.exe` keeps it).
- Every connection writes the ADSI schema cache `%LOCALAPPDATA%\Microsoft\Windows\SchCache\<dc>.sch`, even without a snapshot. "Any file written by ADExplorer" would fire on every GUI use, so this path is excluded.
- A GUI snapshot leaves no command-line trace; only the file write shows it.
- Each Sigma-style approach catches 2 of the 4 real snapshots (comparison searches in the replay). Correlating OriginalFileName `AdExp` (EID 1) with EID 11 by ProcessGuid catches all 4.
- LDAP traffic (EID 3, port 389) from ADExplorer is mixed with lsass, ADWS, dfsrs and svchost on a DC, so port-based hunting is noisy.

## Results
- Splunk replay of this dataset: [`results/splunk-replay.md`](results/splunk-replay.md).
- Native lab notes: [`results/lab-results.md`](results/lab-results.md).

## Sample events
<details><summary>EID 1: renamed copy svc-helper.exe, OriginalFileName AdExp</summary>

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-02T12:40:35.5409736Z"/>
    <EventRecordID>57</EventRecordID>
    <Correlation/>
    <Execution ProcessID="1996" ThreadID="5208"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN-9FBIF1KHFAH.lab.local</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-11-02 12:40:35.528</Data>
    <Data Name="ProcessGuid">{6924c894-84c3-6ae8-d400-000000000500}</Data>
    <Data Name="ProcessId">1244</Data>
    <Data Name="Image">C:\ADLab\run-20261102-044002\svc-helper.exe</Data>
    <Data Name="FileVersion">1.52</Data>
    <Data Name="Description">Active Directory Editor</Data>
    <Data Name="Product">Sysinternals ADExplorer</Data>
    <Data Name="Company">Sysinternals - www.sysinternals.com</Data>
    <Data Name="OriginalFileName">AdExp</Data>
    <Data Name="CommandLine">"C:\ADLab\run-20261102-044002\svc-helper.exe" -snapshot "" "C:\ADLab\run-20261102-044002\snap-renamed.dat" </Data>
    <Data Name="CurrentDirectory">C:\WINDOWS\system32\</Data>
    <Data Name="User">LAB\Administrator</Data>
    <Data Name="LogonGuid">{6924c894-83e0-6ae8-3184-060000000000}</Data>
    <Data Name="LogonId">0x68431</Data>
    <Data Name="TerminalSessionId">1</Data>
    <Data Name="IntegrityLevel">High</Data>
    <Data Name="Hashes">SHA256=E451287843B3927C6046EAABD3E22B929BC1F445EEC23A73B1398B115D02E4FB</Data>
    <Data Name="ParentProcessGuid">{6924c894-849b-6ae8-c300-000000000500}</Data>
    <Data Name="ParentProcessId">5868</Data>
    <Data Name="ParentImage">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="ParentCommandLine">"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" </Data>
    <Data Name="ParentUser">LAB\Administrator</Data>
  </EventData>
</Event>
```
</details>

<details><summary>EID 11: snap-renamed.dat written by svc-helper.exe</summary>

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>
    <EventID>11</EventID>
    <Version>2</Version>
    <Level>4</Level>
    <Task>11</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-02T12:40:37.3604997Z"/>
    <EventRecordID>68</EventRecordID>
    <Correlation/>
    <Execution ProcessID="1996" ThreadID="5208"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN-9FBIF1KHFAH.lab.local</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-11-02 12:40:37.360</Data>
    <Data Name="ProcessGuid">{6924c894-84c3-6ae8-d400-000000000500}</Data>
    <Data Name="ProcessId">1244</Data>
    <Data Name="Image">C:\ADLab\run-20261102-044002\svc-helper.exe</Data>
    <Data Name="TargetFilename">C:\ADLab\run-20261102-044002\snap-renamed.dat</Data>
    <Data Name="CreationUtcTime">2026-11-02 12:40:37.358</Data>
    <Data Name="User">LAB\Administrator</Data>
  </EventData>
</Event>
```
</details>

<details><summary>EID 11: snap-gui.dat written from the GUI menu (no snapshot argument on the command line)</summary>

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>
    <EventID>11</EventID>
    <Version>2</Version>
    <Level>4</Level>
    <Task>11</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-02T12:41:30.9326087Z"/>
    <EventRecordID>136</EventRecordID>
    <Correlation/>
    <Execution ProcessID="1996" ThreadID="5208"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN-9FBIF1KHFAH.lab.local</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-11-02 12:41:30.931</Data>
    <Data Name="ProcessGuid">{6924c894-84d6-6ae8-d800-000000000500}</Data>
    <Data Name="ProcessId">6856</Data>
    <Data Name="Image">C:\ADLab\tools\ADExplorer64.exe</Data>
    <Data Name="TargetFilename">C:\ADLab\run-20261102-044002\snap-gui.dat</Data>
    <Data Name="CreationUtcTime">2026-11-02 12:41:30.929</Data>
    <Data Name="User">LAB\Administrator</Data>
  </EventData>
</Event>
```
</details>

<details><summary>EID 11: SchCache .sch written on every connection (excluded)</summary>

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>
    <EventID>11</EventID>
    <Version>2</Version>
    <Level>4</Level>
    <Task>11</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-02T12:40:58.1905799Z"/>
    <EventRecordID>98</EventRecordID>
    <Correlation/>
    <Execution ProcessID="1996" ThreadID="5208"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN-9FBIF1KHFAH.lab.local</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-11-02 12:40:58.187</Data>
    <Data Name="ProcessGuid">{6924c894-84d6-6ae8-d800-000000000500}</Data>
    <Data Name="ProcessId">6856</Data>
    <Data Name="Image">C:\ADLab\tools\ADExplorer64.exe</Data>
    <Data Name="TargetFilename">C:\Users\Administrator\AppData\Local\Microsoft\Windows\SchCache\WIN-9FBIF1KHFAH.lab.local.sch</Data>
    <Data Name="CreationUtcTime">2026-11-01 17:06:40.912</Data>
    <Data Name="User">LAB\Administrator</Data>
  </EventData>
</Event>
```
</details>

## Limits
- Needs OriginalFileName; a rebuilt binary with altered version information is not covered.
- The TTP needs EID 11 for the folder the snapshot is written to.
- Single DC; the snapshot was taken on the DC itself. Snapshots taken from a workstation produce the same process and file events on that workstation.

## Reproduce
- **Replay the dataset in any Splunk with ESCU and the Sysmon / Windows TA:** load `data/windows-events.log` with sourcetype `XmlWinEventLog` and source `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, then run the YAML searches with the filter macro removed. `tools/replay.py` does exactly this and writes `results/splunk-replay.md`.
- **Regenerate the dataset:** run the capture script in `lab/` on the machine described in [LAB.md](../LAB.md).

## Files
- `data/windows-events.log`
- `detections/windows_ad_snapshot_created_by_adexplorer.yml`
- `detections/windows_sysinternals_adexplorer_execution.yml`
- `lab/Test-ADExplorerSnapshot.ps1`
- `lab/adx-sysmon.xml`
- `results/lab-results.md`
- `results/splunk-replay.md`, `results/splunk-replay.json` (written by `tools/replay.py`)
- `dataset.yml`, `replay.json` (dataset metadata and the searches the replay runs)
