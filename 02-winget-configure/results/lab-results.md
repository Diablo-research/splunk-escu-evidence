# Native lab results, 2026-11-01

Windows 11 x64, WinGet v1.29.380 (App Installer 1.29.380.0), Sysmon 15.22 with `winget-lab-sysmon.xml`. Configuration: `lab.winget`, a read-only Microsoft.Windows.Developer/OsVersion assertion. Remote case: the same file served from a GitHub gist over https. Capture script: `Test-WingetConfigure.ps1`. Host and user anonymized (WIN-WINGET-LAB, LabUser).

| Case | winget command | Exit | ConfigurationRemotingServer.exe | Network (Sysmon EID 3) |
|---|---|---|---|---|
| negative_version | `--version` | 0 | no | none |
| negative_list | `list --count 1` | 0 | no | none |
| configure_validate | `configure validate -f <local>` | 0 | yes | CRS -> 150.171.109.244:443 |
| configure_show | `configure show -f <local>` | 0 | yes | none |
| configure_local_f | `configure -f <local .winget>` | 0 | yes | none |
| configure_local_file | `configure --file <local .winget>` | 0 | yes | none |
| configure_local_txt | `configure -f <local .txt>` | 0 | yes | none |
| configure_remote | `configure -f https://gist.githubusercontent.com/...` | 0 | yes | winget.exe -> GitHub CDN :443 |

## Observations
1. **Preview subcommands also start ConfigurationRemotingServer.exe.** That is why the Anomaly analytic labels each hit with `configuration_action` (preview or apply) instead of excluding previews.
2. **ConfigurationRemotingServer.exe made an outbound HTTPS connection during a benign `configure validate`.** Public guidance that any outbound connection from this process is high risk would therefore produce false positives. No network analytic is proposed.
3. **The CRS command line has the form `<blob> <GUID> <parent winget PID> pwsh`**, which ties it to the launching winget process.
4. **WinGet and CRS have OriginalFileName "-"** in Sysmon, so renamed copies cannot be caught through OriginalFileName.
5. **The file extension is not checked:** `.txt` applies like `.winget`.
6. **Prerequisites seen in the lab:**
   - The Store-stub App Installer returns 0x8A150069 (APPINSTALLER_CLI_ERROR_PACKAGE_IS_STUB) until `winget configure --enable` is run.
   - A Sysmon configuration that does not record processes under `C:\Program Files\WindowsApps\` sees none of this activity.

## Splunk (lab, Endpoint.Processes via tstats, exact YAML searches with the filter macro expanded to `search *`)
- **Windows WinGet Configuration Remoting Server Execution:** 6 results (4 apply, 2 preview). The two negative controls returned 0.
- **Windows WinGet Configuration File From Remote URL:** 1 result (configure_remote).
