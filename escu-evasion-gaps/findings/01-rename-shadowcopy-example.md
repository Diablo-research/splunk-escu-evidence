# Worked example: Shadow Copy (T1490) rename bypass

Detailed walk-through of one Class-1 rule, as the template for the method.

## The gap
`detections/endpoint/deleting_shadow_copies.yml` filters:
```
WHERE ( Processes.process_name=vssadmin.exe OR Processes.process_name=wmic.exe )
      Processes.process=*delete* Processes.process=*shadow*
```
`original_file_name` is only in the BY clause (grouping, not filtering). Copy
vssadmin.exe to svc.exe and run `svc.exe delete shadows /all /quiet`: shadow copies
are deleted, the analytic does not fire.

## Live proof (local Splunk)
Rule's own attack_data (T1490/atomic_red_team/windows-sysmon.log), mutated copy with
Image/CommandLine vssadmin.exe→svc.exe, OriginalFileName left = VSSADMIN.EXE.

| Test | count |
|---|---|
| current rule vs original | 1 (fires) |
| current rule vs renamed | 0 (BYPASS) |
| fixed rule vs renamed | 1 (fix works) |

## Fix
```
WHERE ( (Processes.process_name=vssadmin.exe OR Processes.original_file_name=VSSADMIN.EXE) OR `process_wmic` )
      Processes.process=*delete* Processes.process=*shadow*
```
`process_wmic` already exists and does the name-or-original-name check; the cleanest
option is a matching `process_vssadmin` macro used by all three shadow-copy rules
(Deleting / Creation of / Resize ShadowStorage).

OriginalFileName values read from the live signed binaries (Test-RenamedBinaries.ps1):
vssadmin.exe → VSSADMIN.EXE (Microsoft Windows), wmic.exe → wmic.exe.
