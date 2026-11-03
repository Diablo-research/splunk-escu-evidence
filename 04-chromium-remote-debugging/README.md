# Chromium remote debugging used for cookie theft

Proposal: splunk/security_content#4389

**Technique.** Since Chrome's App-Bound Encryption, infostealers start Chrome or Edge with `--remote-debugging-port` / `--remote-debugging-pipe` and a non-default `--user-data-dir`, often headless or off-screen, then read cookies through the DevTools Protocol. Chrome 136+ blocks this for the *default* profile only.

**Lab.** Host A in [LAB.md](../LAB.md) (Windows 11 x64), Edge 156.0.4314.58, Chrome 156.0.8078.74, Sysmon 15.22 with `lab/lab-sysmon-v3.xml`. Every case used a new, **empty** temporary profile. The only DevTools request made was `GET /json/version` (browser version); no cookies or page data were read.

**Dataset.** `data/windows-events.log`: 188 events (EID 1: 182, EID 3: 6), including browser child processes so the `--type=` exclusion is exercised. sha256 `55fd5f5bda65799a0c0b7e8f80e9f43614f67240eb28d76900753330c21a3e9b`.

## Test cases
| Case | Command-line flags | /json/version | Expected |
|---|---|---|---|
| negative_user_data_dir_only | `--user-data-dir` | - | no result |
| negative_headless_dump_dom | `--headless --disable-gpu --dump-dom` | - | no result (matches existing ESCU Headless Browser Usage) |
| debug_port_headless (Edge) | `--headless=new --remote-debugging-port=9222` | 200 | Remote Debugging (fixed port, hidden) |
| debug_port_offscreen (Edge) | `--remote-debugging-port=9223 --window-position=-32000,-32000` | 200 | Remote Debugging (fixed port, hidden) |
| debug_port_zero_automation (Edge) | `--headless=new --remote-debugging-port=0` | - | Remote Debugging (port 0) |
| debug_pipe_headless (Edge) | `--headless=new --remote-debugging-pipe` | - | Remote Debugging (pipe) |
| chrome_debug_port_headless | `--headless=new --remote-debugging-port=9224` | 200 | Remote Debugging (fixed port, hidden) |
| version queries | powershell.exe -> 127.0.0.1:9222/9223/9224 | - | DevTools hunt: 1 (powershell.exe) |

## Proposed detections
| Detection | Type | Data source | Expected results on this dataset |
|---|---|---|---|
| [Windows Chromium Browser Remote Debugging Enabled](detections/windows_chromium_browser_remote_debugging_enabled.yml) | Anomaly | Sysmon EventID 1 | 5 |
| [Windows Non-Browser Process Connection To Chromium DevTools Port](detections/windows_non_browser_process_connection_to_chromium_devtools_port.yml) | Hunting | Sysmon EventID 3 | 1 |

## What the data shows
- The existing ESCU **Headless Browser Usage** requires `--headless` AND `--disable-gpu`; it matched only the benign `--dump-dom` negative and none of the 5 debugging launches (comparison search in the replay).
- An elevated launcher makes the browser relaunch itself with `--do-not-de-elevate` (parent = the same browser), which would double-count; the analytic excludes that relaunch.
- The Sysmon TA leaves `process_path` empty on EID 3, so the hunt groups on raw `Image` / `ProcessGuid`.
- The browser's accepting side of each connection appears as `<unknown process>` with `Initiated=false` and is excluded.

## Results
- Splunk replay of this dataset: [`results/splunk-replay.md`](results/splunk-replay.md).
- Native lab notes: [`results/lab-results.md`](results/lab-results.md).

## Sample events
<details><summary>EID 1: msedge.exe --headless=new --remote-debugging-port=9222 with a temporary profile</summary>

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
    <TimeCreated SystemTime="2026-11-01T18:37:16.6478739Z"/>
    <EventRecordID>3330</EventRecordID>
    <Correlation/>
    <Execution ProcessID="44988" ThreadID="18344"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN-COOKIE-LAB</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-11-01 18:37:16.633</Data>
    <Data Name="ProcessGuid">{0ebc32d9-86dc-6ae7-eca1-000000001e00}</Data>
    <Data Name="ProcessId">6484</Data>
    <Data Name="Image">C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe</Data>
    <Data Name="FileVersion">156.0.4314.58</Data>
    <Data Name="Description">Microsoft Edge</Data>
    <Data Name="Product">Microsoft Edge</Data>
    <Data Name="Company">Microsoft Corporation</Data>
    <Data Name="OriginalFileName">msedge.exe</Data>
    <Data Name="CommandLine">"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --headless=new --remote-debugging-port=9222 --user-data-dir="C:\Users\LabUser\Downloads\CookieLab\run-20261101-183705\profile-debug_port_headless" about:blank </Data>
    <Data Name="CurrentDirectory">C:\Users\LabUser\Downloads\CookieLab\</Data>
    <Data Name="User">WIN-COOKIE-LAB\LabUser</Data>
    <Data Name="LogonGuid">{0ebc32d9-96c7-6ac6-25b4-640000000000}</Data>
    <Data Name="LogonId">0x64b425</Data>
    <Data Name="TerminalSessionId">1</Data>
    <Data Name="IntegrityLevel">High</Data>
    <Data Name="Hashes">SHA256=D35D48B11F0439EEEDDBBFF0BF54856E922F5E1506A2F3098B5A808FCEC4068B</Data>
    <Data Name="ParentProcessGuid">{0ebc32d9-5f67-6ae7-429d-000000001e00}</Data>
    <Data Name="ParentProcessId">12356</Data>
    <Data Name="ParentImage">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="ParentCommandLine">"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" </Data>
    <Data Name="ParentUser">WIN-COOKIE-LAB\LabUser</Data>
  </EventData>
</Event>
```
</details>

<details><summary>EID 3: powershell.exe -> 127.0.0.1:9222 (non-browser client of the DevTools port)</summary>

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>
    <EventID>3</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>3</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-01T18:37:23.4727341Z"/>
    <EventRecordID>3412</EventRecordID>
    <Correlation/>
    <Execution ProcessID="44988" ThreadID="43048"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN-COOKIE-LAB</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-11-01 18:37:28.349</Data>
    <Data Name="ProcessGuid">{0ebc32d9-5f67-6ae7-429d-000000001e00}</Data>
    <Data Name="ProcessId">12356</Data>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="User">WIN-COOKIE-LAB\LabUser</Data>
    <Data Name="Protocol">tcp</Data>
    <Data Name="Initiated">true</Data>
    <Data Name="SourceIsIpv6">false</Data>
    <Data Name="SourceIp">127.0.0.1</Data>
    <Data Name="SourceHostname">WIN-COOKIE-LAB</Data>
    <Data Name="SourcePort">65111</Data>
    <Data Name="SourcePortName">-</Data>
    <Data Name="DestinationIsIpv6">false</Data>
    <Data Name="DestinationIp">127.0.0.1</Data>
    <Data Name="DestinationHostname">WIN-COOKIE-LAB</Data>
    <Data Name="DestinationPort">9222</Data>
    <Data Name="DestinationPortName">-</Data>
  </EventData>
</Event>
```
</details>

## Limits
- CDP enabled from inside a running browser, or attachment through `DevToolsActivePort`, is not covered.
- Automation frameworks (Selenium, Puppeteer, Playwright) and developers match; tune with `debug_mode` and the parent process.
- The hunt needs loopback EID 3, which many Sysmon configurations exclude.

## Reproduce
- **Replay the dataset in any Splunk with ESCU and the Sysmon / Windows TA:** load `data/windows-events.log` with sourcetype `XmlWinEventLog` and source `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, then run the YAML searches with the filter macro removed. `tools/replay.py` does exactly this and writes `results/splunk-replay.md`.
- **Regenerate the dataset:** run the capture script in `lab/` on the machine described in [LAB.md](../LAB.md).

## Files
- `data/windows-events.log`
- `detections/windows_chromium_browser_remote_debugging_enabled.yml`
- `detections/windows_non_browser_process_connection_to_chromium_devtools_port.yml`
- `lab/Test-BrowserDebugging.ps1`
- `lab/lab-sysmon-v3.xml`
- `results/lab-results.md`
- `results/splunk-replay.md`, `results/splunk-replay.json` (written by `tools/replay.py`)
- `dataset.yml`, `replay.json` (dataset metadata and the searches the replay runs)
