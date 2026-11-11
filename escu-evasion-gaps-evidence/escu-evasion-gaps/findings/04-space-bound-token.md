# Finding: space-bound token bypass (quote/char insertion)

## The gap
Rules match a token bound by literal spaces, e.g. `process="* stop *"`, `process="* restore *"`. An attacker inserts a quote pair inside the token (`st""op`, `res""tore`) — CommandLineToArgvW collapses `""`, so the tool parses the original token, but the raw CommandLine no longer contains ` stop ` / ` restore `, so the rule misses. (Tab substitution is a second vector.)

## Attack-side lab confirmation (Win11 25H2) — ALL CONFIRMED
Quote-inserted read-only commands, all obeyed (quotes collapse):
- `reg qu""ery ... /v ProductName` → returned ProductName.
- `netsh ad""vfirewall show allprofiles` → printed all profiles.
- `sc.exe qu""ery WinDefend` → SERVICE_NAME WinDefend, STATE RUNNING. (PowerShell `sc` alone aliases Set-Content; use sc.exe.)
- `schtasks /qu""ery /fo LIST` → listed tasks.
- powershell: ArgFuscator-validated.

## Detection-sim BYPASS: 7 — both sides confirmed
| Rule | Binary | Type | token | orig→mut | attack-side |
|---|---|---|---|---|---|
| Windows Registry Entries Restored Via Reg | reg.exe | Hunting | restore | 567→0 | CONFIRMED |
| Windows Proxy Via Netsh | netsh.exe | Anomaly | portproxy,v4tov4 | 2→0 | CONFIRMED |
| Windows Delete or Modify System Firewall | netsh.exe | Hunting | firewall | 1→0 | CONFIRMED |
| Windows Service Stop By Deletion | sc.exe | Hunting | delete | 10→0 | CONFIRMED |
| Windows Scheduled Task with Highest Privileges | schtasks.exe | TTP | highest | 1→0 | CONFIRMED |
| Malicious PowerShell Process - Execution Policy Bypass | powershell.exe | Anomaly | bypass | 1→0 | ArgFuscator |
| Windows Powershell RemoteSigned File | powershell.exe | Anomaly | remotesigned | 1→0 | ArgFuscator |

(The 7 are listed in the table above; Scheduled Task Highest Privileges and PowerShell RemoteSigned also appear in flag_form — multiple obfuscations apply.)

## Fix
Normalise the command line before matching (strip quotes, collapse whitespace) — the best argument for an ESCU command-line normalisation macro, mirroring Sigma / Defender parse-command-line. Per-rule space-tolerant matching is brittle. Needs false-positive testing; lowest-priority class.
