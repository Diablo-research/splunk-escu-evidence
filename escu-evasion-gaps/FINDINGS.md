# Findings — ESCU endpoint evasion & logic gaps

Scanned on `splunk/security_content` develop **4c1652e**. Attack side anchored to
**ArgFuscator** (`aeca415`) and lab tests on **Windows 11 25H2 (build 26200)** and
**Windows Server**.

## Summary
**158 distinct production detections** are evadable without changing attacker
behaviour, or fail on default modern Windows: **62 TTP · 67 Anomaly · 29 Hunting**.
Most trace to one root cause — a rule hardcodes `Processes.process_name=X` instead
of using the `process_X` macro ESCU already ships, and a couple of those macros are
themselves incomplete. The rest are case-sensitive `match()`, bypassable `NOT`
exclusions, and command-line obfuscation the rules don't account for.

**14 rules are confirmed end-to-end in a live Splunk** (fires on original, 0 on the
evaded copy, recovers with the fix). The rest share the same root cause and the
replay method in `README.md`.

| # | Class | Rules | TTP | Anom | Hunt | Fix |
|---|---|---|---|---|---|---|
| 1 | Renamed binary (no `original_file_name`) | 89 | 36 | 37 | 16 | use `process_*` macro |
| 2 | Option-char substitution (`/`↔`-`) | 29 | 15 | 9 | 5 | match both prefixes |
| 3 | Sibling binary not covered | 13 | 5 | 1 | 7 | `process_powershell` / add sibling |
| 4 | Bypassable `NOT` exclusions (name/path/cmdline) | 33 | 14 | 15 | 4 | anchor / qualify the exclusion |
| 5 | `process_net` matches net1.exe only | 8 | 0 | 5 | 3 | macro += net.exe |
| 6 | Space-bound token (quote/char insertion) | 7 | 1 | 3 | 3 | normalize command line |
| 7 | Case-sensitive `match()` | 4 | 3 | 1 | 0 | add `(?i)` |

Some rules appear in more than one class; 158 is the distinct total. Counts are
after excluding scanner false positives (SQLCMD's genuinely case-sensitive flags,
drive-anchored path exclusions, cmd-intrinsic techniques, rules already covering
PowerShell).

## Root cause, in one example
ESCU already ships the correct pattern:
```
process_powershell:  (process_name=pwsh.exe OR process_name=powershell.exe
                      OR original_file_name=PowerShell.EXE OR original_file_name=pwsh.dll
                      OR original_file_name=powershell_ise.EXE OR process_name=powershell_ise.exe)
```
This defeats renaming (`original_file_name`) and the pwsh sibling. But
`getadcomputer_with_powershell.yml` hardcodes `process_name="powershell.exe"`, so it
is evaded by both. `process_wmic` is the same story. Using the macro closes classes
1 and 3 together.

---

## Class 1 — Renamed binary (89)
`original_file_name` (PE version resource) does not change on rename and cannot be
forged for a signed Microsoft binary. Rules matching `process_name` only miss a
renamed copy. Live proof (rule's own attack_data, process renamed to svc.exe,
OriginalFileName intact):

| Rule | fires | renamed | +fix |
|---|---|---|---|
| Deleting Shadow Copies (vssadmin, T1490) | yes | 0 | yes |
| Excessive Usage of NSLOOKUP App | 407 | 0 | 407 |
| Excessive Usage Of Taskkill | 257 | 0 | 257 |
| RDP Client Launched with Admin Session | 10 | 0 | 10 |
| Wmic NonInteractive App Uninstallation | 16 | 0 | 16 |

Full list: `results/rename_gap_89.csv`. Top binaries: powershell(16), wmic(14),
cmd(13), schtasks(11). Fix: use the `process_*` macro, or add
`OR Processes.original_file_name=<value>`.

## Class 2 — Option-char substitution `/`↔`-` (29)
Rule matches a switch in one prefix form (`*/create*` or `*-enc*`); the binary
accepts the other. 24 affected binaries confirmed by ArgFuscator to accept both
`/` and `-`. Live proof (prefix swapped in the dataset):

| Rule | fires | swapped | +fix |
|---|---|---|---|
| DISM Remove Defender (T1562.001) | 2 | 0 | 2 |
| Certutil certificate extraction | 12 | 0 | 12 |
| Bcdedit Back To Normal Mode Boot | 2 | 0 | 2 |

Full list: `results/flag_form_confirmed_final.csv`. Incl. Auditpol tampering, the
Schtasks family, Remote Process Instantiation via WMI/PowerShell, cmdkey cred store.
Fix: match both prefixes (`match(process,"[-/]create")`) or a Sigma-`windash`
equivalent macro.

## Class 3 — Sibling binary (13)
Separate binary, same capability (pwsh for powershell, wscript↔cscript). Live proof:
Jscript/Vbscript via Cscript↔Wscript (fires→0→fix). 10 PowerShell rules fixed by
`process_powershell`; `process_wscript` exists but omits the cscript sibling and
there is no `process_cscript` — the macro library has a sibling gap.

## Class 4 — Bypassable `NOT` exclusions (33)
- **by_name (8):** `NOT Image="*\<name>"` → rename tool to the excluded name to
  evade (mirror of Class 1 on the NOT side). Fix: qualify with `original_file_name`.
- **path_wildcard (14):** `NOT Image="*\windows\*"` (no drive anchor) → run from
  `C:\Users\Public\windows\…`. Incl. CMLUA/CMSTPLUA UAC Bypass, Raw Access to
  MBR/Disk, DLL Search-Order Hijacking, InstallUtil in Non Standard Path. Fix:
  anchor to drive root (`*:\Windows\…`) or a `^`-anchored regex.
- **cmdline (11):** `NOT process="*<string>*"` → satisfy with a dummy argument. Fix:
  anchor to the real field/position.

## Class 5 — `process_net` matches net1.exe only (coverage is OS-dependent)
`process_net = (process_name=net1.exe OR original_file_name=net1.exe)`. Whether
`net <verb>` spawns net1.exe — and thus whether a net1-only rule fires — depends on
the Windows version (Win32_ProcessStartTrace, `lab/Test-Net1Spawn.ps1`):

| verb | Win11 25H2 | Server | rule |
|---|---|---|---|
| user (incl. `/delete`) | no net1 | net1 | User Deletion / Disabled |
| localgroup | no net1 | no net1 | Group Discovery |
| accounts | no net1 | net1 | Password Policy |
| share | net1 | net1 | (covered) |

`net localgroup` spawns no net1 on either OS → Group Discovery is bypassed
everywhere; `net user`/`accounts` fire on Server but miss on Win11 → the same rule's
coverage flips with the OS. No evasion needed. Fix: `process_net` should also match
`net.exe` — one non-breaking macro change makes all 19 `process_net` rules fire
uniformly.

## Class 6 — Space-bound token (7)
`* restore *` matched with literal spaces; `res""tore` runs identically
(CommandLineToArgvW collapses `""`) but no longer contains the spaced token.
Lab-confirmed on Win11: `reg qu""ery`, `netsh ad""vfirewall`, `sc.exe qu""ery`,
`schtasks /qu""ery` all obeyed. Incl. Registry Entries Restored Via Reg (567→0 sim),
Service Stop By Deletion, Proxy Via Netsh. Fix: a command-line normalization macro
(strip quotes, collapse whitespace) before token checks — mirrors Sigma / Defender
parse-command-line. Needs false-positive testing; lowest-priority class.

## Class 7 — Case-sensitive `match()` (4)
`match()` without `(?i)` on case-insensitive Windows values: RunDLL Loading DLL By
Ordinal, Windows .Key File Creation, Windows RDP File Execution, WinDBG Spawning
AutoIt3. Fix: add `(?i)`. (SQLCMD excluded — its flags are genuinely case-sensitive,
e.g. `-E` trusted connection vs `-e` echo.)

---

## Data-source note
`original_file_name` is present on Sysmon EID 1 and EDR (CrowdStrike, Defender for
Endpoint). Windows Security 4688 lacks the field, so on 4688-only telemetry Class 1
cannot be closed this way, though some rules list 4688 as a supported data_source —
a maintainer decision.

## Suggested fix batching
- **A — macro family (classes 1, 3, 5):** use/complete the `process_*` macros.
  Highest-confidence, least arguable; lead here.
- **B — obfuscation (classes 2, 6):** match both prefixes; command-line
  normalization.
- **C — exclusions / logic (classes 4, 7):** anchor exclusions; add `(?i)`.
