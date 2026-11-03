# Native lab results, 2026-11-01

Windows 11, Edge 156.0.4314.58, Chrome 156.0.8078.74, Sysmon 15.22 with `lab/lab-sysmon-v3.xml`. Capture script: `lab/Test-BrowserDebugging.ps1`. Every case used a new, empty temporary profile. The only DevTools request was GET /json/version. Host and user are anonymized (WIN-COOKIE-LAB, LabUser).

| Case | Command-line flags | /json/version | Existing ESCU "Headless Browser Usage" | New analytic |
|---|---|---|---|---|
| negative_user_data_dir_only | --user-data-dir | - | no | no |
| negative_headless_dump_dom | --headless --disable-gpu --dump-dom | - | **yes** | no |
| debug_port_headless (Edge) | --headless=new --remote-debugging-port=9222 | **200** | no | **yes** (fixed port, hidden) |
| debug_port_offscreen (Edge) | --remote-debugging-port=9223 --window-position=-32000,-32000 | **200** | no | **yes** (fixed port, hidden) |
| debug_port_zero_automation (Edge) | --headless=new --remote-debugging-port=0 | - | no | **yes** (port 0) |
| debug_pipe_headless (Edge) | --headless=new --remote-debugging-pipe | - | no | **yes** (pipe) |
| chrome_debug_port_headless | --headless=new --remote-debugging-port=9224 | **200** | no | **yes** (fixed port, hidden) |

## Observations
1. **Current browsers still allow it.** Edge 156 and Chrome 156 both expose the DevTools endpoint when remote debugging is combined with a non-default `--user-data-dir`. The Chrome 136 restriction only covers the default profile.
2. **The existing ESCU analytic misses every remote-debugging launch.** Headless Browser Usage requires both `--headless` and `--disable-gpu`, so it matched only the benign `--dump-dom` negative.
3. **Elevated launches are logged twice.** When the launcher is elevated, the browser relaunches itself with `--do-not-de-elevate` (parent = the same browser), producing a second main-process event. The analytic excludes this relaunch, so each launch is reported once. The pipe case did not relaunch.
4. **Network events (Sysmon EID 3):**
   - The client side of each version query is `powershell.exe -> 127.0.0.1:9222/9223/9224`, with `Initiated=true`.
   - The browser's accepting side shows as `<unknown process>`, with `Initiated=false` and a null ProcessGuid, because the browser had already exited.
5. **Splunk field gap:** the Sysmon TA leaves `process_path` empty on EID 3 events. Grouping by it dropped every result, so the hunt groups by the raw `Image`, `ProcessGuid` and `ProcessId` fields.
6. **Sysmon config:** under schemaversion 4.50, Sysmon 15.22 silently ignored a configuration that used "end with any" / "contains any" / "is any". Plain conditions worked.

## Splunk (lab, exact YAML searches with the filter macro expanded to `search *`)
- Windows Chromium Browser Remote Debugging Enabled: 5 results (Edge 9222, 9223, port 0 and pipe; Chrome 9224). No hits on either negative.
- Windows Non-Browser Process Connection To Chromium DevTools Port: 1 result (powershell.exe; ports 9222, 9223, 9224).
