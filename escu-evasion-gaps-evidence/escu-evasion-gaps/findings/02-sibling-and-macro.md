# Finding: sibling-binary bypass + the unifying macro root cause

## Unifying insight
name_only (rename) and sibling_missing are the SAME root cause: a rule hardcodes `Processes.process_name=X` when ESCU already ships a `process_X` macro that matches the renamed form (original_file_name) AND sibling binaries. Using the macro closes both gaps at once.

Proof: `process_powershell` already =
`(process_name=pwsh.exe OR process_name=powershell.exe OR original_file_name=pwsh.dll OR original_file_name=PowerShell.EXE OR original_file_name=powershell_ise.EXE OR process_name=powershell_ise.exe)`
— covers the sibling (pwsh), the rename (original_file_name), and powershell_ise. But e.g. `getadcomputer_with_powershell.yml` hardcodes `process_name="powershell.exe"`, so it is bypassed by pwsh AND by rename. Same for `process_wmic`.

Fix pattern: replace the hardcoded `process_name=X` with the existing `` `process_X` `` macro.

## Real-Splunk confirmed (3 cscript/wscript)
Combined 3 datasets → sib_orig.log, sibling-swapped → sib_swapped.log, uploaded, rex-extract Image/CommandLine, stats count by source. All three: original 1, swapped 0, fix recovers.

| Rule | swap | orig | swapped | fixed |
|---|---|---|---|---|
| Execute Javascript With Jscript COM CLSID (TTP) | cscript→wscript | 1 | 0 | 1 |
| Jscript Execution Using Cscript App (Anomaly) | cscript→wscript | 1 | 0 | 1 |
| Vbscript Execution Using Wscript App (TTP) | wscript→cscript | 1 | 0 | 1 |

## The 10 powershell→pwsh clean bypasses (fix: use `process_powershell`)
| # | Rule | File | Type | MITRE |
|---|---|---|---|---|
| 1 | GetAdComputer with PowerShell | getadcomputer_with_powershell.yml | Hunting | T1018 |
| 2 | GetAdGroup with PowerShell | getadgroup_with_powershell.yml | Hunting | T1069.002 |
| 3 | GetCurrent User with PowerShell | getcurrent_user_with_powershell.yml | Hunting | T1033 |
| 4 | GetDomainComputer with PowerShell | getdomaincomputer_with_powershell.yml | TTP | T1018 |
| 5 | GetDomainController with PowerShell | getdomaincontroller_with_powershell.yml | Hunting | T1018 |
| 6 | GetDomainGroup with PowerShell | getdomaingroup_with_powershell.yml | TTP | T1069.002 |
| 7 | GetLocalUser with PowerShell | getlocaluser_with_powershell.yml | Hunting | T1087.001 |
| 8 | GetNetTcpconnection with PowerShell | getnettcpconnection_with_powershell.yml | Hunting | T1049 |
| 9 | GetWmiObject User Account with PowerShell | getwmiobject_user_account_with_powershell.yml | Hunting | T1087.001 |
| 10 | Windows PowGoop Beacon Decoding | windows_powgoop_beacon_decoding.yml | TTP | T1059.001, T1001 |

7/10 are Hunting (lower impact). The 3 TTP ones (GetDomainComputer, GetDomainGroup, PowGoop) generate findings; PowGoop is malware C2 decoding.

## The 3 cscript/wscript bypasses
Fix is NOT a one-word macro swap: `process_wscript` exists (wscript + original_file_name) but there is NO `process_cscript`, and `process_wscript` omits the cscript sibling. Add the sibling explicitly, or introduce a combined `process_scripting` macro. The macro library itself therefore has a sibling gap.

Attack side (known, no lab): pwsh.exe runs the same cmdlets as powershell.exe (PowerShell 7, incl. ActiveDirectory); wscript.exe runs the same .vbs/.js as cscript.exe (both Windows Script Host). Both WSH hosts accept //E:JScript / //E:VBScript and the engine-CLSID form, verified in the live tests.
