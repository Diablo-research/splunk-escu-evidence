# Section A: rule-logic bugs (case_sensitive, cmd_only_scope, exclusions)

These classes need reading, not mutating. 93 candidates → ~40 real after filtering scanner false positives.

## Summary
| Class | Candidates | Real | FP/inherent/weak |
|---|---|---|---|
| case_sensitive | 6 | 4 | 2 |
| cmd_only_scope | 14 | 3 | 11 |
| exclusion_cmdline | 11 | 11 | 0 |
| exclusion_by_name | 8 | 8 | 0 |
| exclusion_path_wildcard | 54 | 14 | 40 |
| Total | 93 | ~40 | ~53 |

## case_sensitive (6) → 4 real
REAL (fix `(?i)`): RunDLL Loading DLL By Ordinal `match(process,"rundll32.+#\d+")`; Windows .Key File Creation `\.key$`; Windows RDP File Execution (path keywords \Temp\ \Downloads\ \Outlook\); WinDBG Spawning AutoIt3 `\.(au3|a3x|exe|aut|aup)$`.
WEAK: BRC4 Loaded Dll — case is ORed with OriginalFileName==; real bugs are `where ImageLoadedCount==4` (a decoy 5th matching DLL silences it) and flags+Signed in the BY clause.
FALSE POSITIVE: SQLCMD Execution — sqlcmd flags ARE case-sensitive (-E trusted vs -e echo; -I vs -i); the rule correctly uses [Qq]/[iI] where case-free and exact -E/-U where it matters.

## cmd_only_scope (14) → ~3 real
REAL (action doable from another process): Credential Dumping via Copy Command from Shadow Copy (copy SAM via print.exe/esentutl/PowerShell); Process Deleting Its Process File Path (self-delete via PowerShell/API); Scheduled Task XML Built Via Console Echo (write XML via PowerShell).
INHERENT (technique is cmd-only): CMD Carry Out String (/c /k), CMD Echo Pipe (%comspec%), Credential Dumping via Symlink (mklink), Recursive Delete (rd), List ENV Via SET (set), Impacket Lateral Movement ×2.
FALSE POSITIVE (rule also covers powershell*): Get ADUser, Get ADUserResultantPasswordPolicy, Get DomainPolicy, Get DomainUser.

## exclusion_cmdline (11) → 11 real (moderate)
All shape `NOT process="*<string>*"`; attacker adds the string as a dummy argument to evade. Rules/strings: Possible Lateral Movement PowerShell Spawn (CCM), Process Execution via WMI (dismhost.exe), Regsvr32 Silent Install (TeamsMeetingAddin), Application Whitelisting Bypass (Netskope EPDLP), Change File Association To Notepad, Execution of MSC File (eventvwr.msc), For Loop In Cmd (SQL Server parent), InstallUtil Uninstall (CCM), Remote Management Execute Shell (Uninstall reg path), React/Next.js Child (mkcert), VMware Tools Child (poweroff-vm-default.bat).

## exclusion_by_name (8) → 8 real — MIRROR of the rename finding
`NOT Image/process_name/process_path="*\<name>"`; rename attacker tool to the excluded name. Rules/names: Local LLM Framework DNS Query (browsers), Modification Of Wallpaper (explorer.exe), Cloud Files Filter (box/dropbox/googledrive), Defender MpClient.dll Loaded by Non-Defender (MpCmdRun.exe), Error Report in ReportQueue (svchost/werfault), Known Abused DLL Loaded (TiWorker/wuacltcore), Non Discord App Access Discord LevelDB (discord.exe), Unsecured Outlook Credentials (HxOutlook/Outlook.exe).
FIX: qualify the exclusion with original_file_name — the attacker's renamed tool has its own OFN, so an OFN-qualified exclusion no longer excludes it and the rule fires.

## exclusion_path_wildcard (54) → 14 real, 33 weak, 7 narrow
REAL nested-folder bypass (14): `NOT Image="*\windows\*"` (no drive anchor) — run from `C:\Users\Public\windows\evil.exe` and the substring makes the exclusion swallow it. Rules: CMLUA/CMSTPLUA UAC Bypass, MSI Module Loaded by Non-System Binary, Msmpeng Application DLL Side Loading, SchCache Change By App Connect, UAC Bypass With Colorui COM Object, Wbemprox COM Object Execution, Windows CAB File on Disk, Windows Defacement Modify Transcodedwallpaper, Windows DLL Search Order Hijacking Hunt, Windows Hijack Execution Flow Version Dll Side Load, Windows Input Capture Using Credential UI Dll, Windows InstallUtil in Non Standard Path, Windows Raw Access To Disk Volume Partition, Windows Raw Access To Master Boot Record Drive.
WEAK (33): `NOT process_path="*:\Windows\System32\*"` — the `:` anchors to a drive root; needs a writable drive root (USB / mapped drive). Lower severity.
NARROW (7): Chrome AppData application-path exclusions.

## Fixes
- case_sensitive: add `(?i)`.
- cmd_only_scope (real): widen scope beyond cmd.exe to the real capability.
- exclusion_cmdline: anchor the exclusion to the real field/position, not a free substring.
- exclusion_by_name: qualify with original_file_name (mirror of the rename fix).
- exclusion_path_wildcard (14 real): anchor the excluded path to the drive root or a `^`-anchored regex.
