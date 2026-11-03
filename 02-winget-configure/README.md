# WinGet Configuration (winget configure) abuse

Proposal: splunk/security_content#4383

**Technique.** `winget configure -f <file or URL>` applies a WinGet Configuration (DSC) file. The resources run inside `ConfigurationRemotingServer.exe`, a WinGet component started by `winget.exe`. The file can be fetched straight from a URL.

**Lab.** Host A in [LAB.md](../LAB.md) (Windows 11 x64), WinGet 1.29.380 (App Installer 1.29.380.0), Sysmon 15.22 with `lab/winget-lab-sysmon.xml`. The configuration (`lab/lab.winget`) is a read-only `Microsoft.Windows.Developer/OsVersion` assertion: it changes nothing on the host. The remote case uses the same file from a public gist.

**Dataset.** `data/windows-events.log`: 49 events (EID 1: 14, EID 3: 3, EID 5: 14, EID 7: 6, EID 11: 12). sha256 `07e64c16dc68b0f2189d509359d41ea08083c63fc5a05760f29fbc35073b171a`.

## Test cases
| Case | winget command | ConfigurationRemotingServer.exe | Remote URL | Expected (CRS / URL) |
|---|---|---|---|---|
| negative_version | `--version` | no | no | 0 / 0 |
| negative_list | `list --count 1` | no | no | 0 / 0 |
| configure_validate | `configure validate -f <local>` | yes | no | 1 (preview) / 0 |
| configure_show | `configure show -f <local>` | yes | no | 1 (preview) / 0 |
| configure_local_f | `configure -f <local .winget>` | yes | no | 1 (apply) / 0 |
| configure_local_file | `configure --file <local .winget>` | yes | no | 1 (apply) / 0 |
| configure_local_txt | `configure -f <local .txt>` | yes | no | 1 (apply) / 0 |
| configure_remote | `configure -f https://gist.githubusercontent.com/...` | yes | yes | 1 (apply) / 1 |

## Proposed detections
| Detection | Type | Data source | Expected results on this dataset |
|---|---|---|---|
| [Windows WinGet Configuration File From Remote URL](detections/windows_winget_configuration_file_from_remote_url.yml) | TTP | Sysmon EventID 1 | 1 |
| [Windows WinGet Configuration Remoting Server Execution](detections/windows_winget_configuration_remoting_server_execution.yml) | Anomaly | Sysmon EventID 1 | 6 |

## What the data shows
- Every `configure` subcommand, including the preview ones (`show`, `validate`), starts `ConfigurationRemotingServer.exe`. The analytic labels each hit `preview` or `apply` instead of dropping previews.
- The file extension is not checked: a `.txt` file applies exactly like `.winget`.
- `ConfigurationRemotingServer.exe` made an outbound HTTPS connection during a benign `validate`, so a network-only rule would be noisy. No network analytic is proposed.
- WinGet and CRS have no OriginalFileName in Sysmon (`-`).
- Prerequisite seen in the lab: the store-stub App Installer returns 0x8A150069 until `winget configure --enable` is run.

## Results
- Splunk replay of this dataset: [`results/splunk-replay.md`](results/splunk-replay.md).
- Native lab notes: [`results/lab-results.md`](results/lab-results.md).

## Sample events
<details><summary>EID 1: winget.exe configure -f https://... (remote configuration)</summary>

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
    <TimeCreated SystemTime="2026-11-01T01:46:42.9044564Z"/>
    <EventRecordID>719</EventRecordID>
    <Correlation/>
    <Execution ProcessID="44988" ThreadID="18344"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN-WINGET-LAB</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-11-01 01:46:42.889</Data>
    <Data Name="ProcessGuid">{0ebc32d9-9a02-6ae6-0098-000000001e00}</Data>
    <Data Name="ProcessId">28528</Data>
    <Data Name="Image">C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.29.380.0_x64__8wekyb3d8bbwe\winget.exe</Data>
    <Data Name="FileVersion">-</Data>
    <Data Name="Description">-</Data>
    <Data Name="Product">-</Data>
    <Data Name="Company">-</Data>
    <Data Name="OriginalFileName">-</Data>
    <Data Name="CommandLine">"C:\Users\LabUser\AppData\Local\Microsoft\WindowsApps\winget.exe" configure -f https://gist.githubusercontent.com/Diablo-research/67da8b67650f700068decf371e80bc07/raw/b0b83ca6374aecc155d380c4349863a007636b0c/lab.winget --accept-configuration-agreements --disable-interactivity </Data>
    <Data Name="CurrentDirectory">C:\Users\LabUser\Downloads\WingetGapLab\run-20261101-014543\</Data>
    <Data Name="User">WIN-WINGET-LAB\LabUser</Data>
    <Data Name="LogonGuid">{0ebc32d9-96c7-6ac6-25b4-640000000000}</Data>
    <Data Name="LogonId">0x64b425</Data>
    <Data Name="TerminalSessionId">1</Data>
    <Data Name="IntegrityLevel">High</Data>
    <Data Name="Hashes">SHA256=CE0BB2B4871CB7F41F40D34AD47E8414A426DC5F6A303C14CEE335A71D8602ED</Data>
    <Data Name="ParentProcessGuid">{0ebc32d9-6d5f-6ae6-d891-000000001e00}</Data>
    <Data Name="ParentProcessId">25320</Data>
    <Data Name="ParentImage">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="ParentCommandLine">"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" </Data>
    <Data Name="ParentUser">WIN-WINGET-LAB\LabUser</Data>
  </EventData>
</Event>
```
</details>

<details><summary>EID 1: ConfigurationRemotingServer.exe started by that winget.exe</summary>

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
    <TimeCreated SystemTime="2026-11-01T01:46:43.7264071Z"/>
    <EventRecordID>721</EventRecordID>
    <Correlation/>
    <Execution ProcessID="44988" ThreadID="18344"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN-WINGET-LAB</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-11-01 01:46:43.713</Data>
    <Data Name="ProcessGuid">{0ebc32d9-9a03-6ae6-0198-000000001e00}</Data>
    <Data Name="ProcessId">37892</Data>
    <Data Name="Image">C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.29.380.0_x64__8wekyb3d8bbwe\DotNet\ConfigurationRemotingServer.exe</Data>
    <Data Name="FileVersion">-</Data>
    <Data Name="Description">-</Data>
    <Data Name="Product">-</Data>
    <Data Name="Company">-</Data>
    <Data Name="OriginalFileName">-</Data>
    <Data Name="CommandLine">"C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.29.380.0_x64__8wekyb3d8bbwe\DotNet\ConfigurationRemotingServer.exe" DotNet\ConfigurationRemotingServer.exe 4d454f57010000007f41755cd64d97519bba04ca0dad11c7800a0000050000000b97a9ea6cee0424873f7923634c52a507f00000706fffff562708bd920a3fad00000000 77B27EC7-9ABE-493F-B0EE-EEF6AA200071 28528 pwsh</Data>
    <Data Name="CurrentDirectory">C:\Users\LabUser\Downloads\WingetGapLab\run-20261101-014543\</Data>
    <Data Name="User">WIN-WINGET-LAB\LabUser</Data>
    <Data Name="LogonGuid">{0ebc32d9-96c7-6ac6-25b4-640000000000}</Data>
    <Data Name="LogonId">0x64b425</Data>
    <Data Name="TerminalSessionId">1</Data>
    <Data Name="IntegrityLevel">High</Data>
    <Data Name="Hashes">SHA256=8B1B3AC2D2C14ADD892C8817D09E1D9BDF27DD9F0B23AD19991AC824BE6F936B</Data>
    <Data Name="ParentProcessGuid">{0ebc32d9-9a02-6ae6-0098-000000001e00}</Data>
    <Data Name="ParentProcessId">28528</Data>
    <Data Name="ParentImage">C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.29.380.0_x64__8wekyb3d8bbwe\winget.exe</Data>
    <Data Name="ParentCommandLine">"C:\Users\LabUser\AppData\Local\Microsoft\WindowsApps\winget.exe" configure -f https://gist.githubusercontent.com/Diablo-research/67da8b67650f700068decf371e80bc07/raw/b0b83ca6374aecc155d380c4349863a007636b0c/lab.winget --accept-configuration-agreements --disable-interactivity </Data>
    <Data Name="ParentUser">WIN-WINGET-LAB\LabUser</Data>
  </EventData>
</Event>
```
</details>

## Limits
- Legitimate developer-machine provisioning with `winget configure` will match the Anomaly; baseline by user and host.
- Renamed copies cannot be caught through OriginalFileName.

## Reproduce
- **Replay the dataset in any Splunk with ESCU and the Sysmon / Windows TA:** load `data/windows-events.log` with sourcetype `XmlWinEventLog` and source `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, then run the YAML searches with the filter macro removed. `tools/replay.py` does exactly this and writes `results/splunk-replay.md`.
- **Regenerate the dataset:** run the capture script in `lab/` on the machine described in [LAB.md](../LAB.md).

## Files
- `data/windows-events.log`
- `detections/windows_winget_configuration_file_from_remote_url.yml`
- `detections/windows_winget_configuration_remoting_server_execution.yml`
- `lab/Test-WingetConfigure.ps1`
- `lab/lab.winget`
- `lab/winget-lab-sysmon.xml`
- `results/lab-results.md`
- `results/splunk-replay.md`, `results/splunk-replay.json` (written by `tools/replay.py`)
- `dataset.yml`, `replay.json` (dataset metadata and the searches the replay runs)
