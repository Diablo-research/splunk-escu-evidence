# Finding: process_net matches net1.exe only; net1-spawn is OS-dependent

Confirmed on two OSes — Windows 11 25H2 (build 26200) and Windows Server. Behaviour differs between them.

## The macro bug
`process_net = (Processes.process_name=net1.exe OR Processes.original_file_name=net1.exe)` — net1 ONLY. Used by 19 endpoint rules. Whether `net <verb>` spawns net1.exe (and thus whether a net1-only rule fires) depends on the Windows version/edition — so coverage is inconsistent.

## Empirical test — net1 spawned by `net <verb>`? (Win32_ProcessStartTrace, admin; lab/Test-Net1Spawn.ps1)
| verb | Win11 25H2 | Windows Server | affected rule(s) |
|---|---|---|---|
| user (incl. `/delete`) | NO | YES | User Deletion / User Disabled / Create Local Admin / Guest Account Enabled Via Net |
| localgroup | NO | NO | Group Discovery / Sensitive Group Discovery (bypassed on BOTH) |
| accounts | NO | YES | Password Policy Discovery / Set Password Policy Unlimited |
| use | NO | NO | Network Share Interaction / OneDrive Share Mounted |
| session | NO | NO | — |
| share | YES | YES | Create/delete shares (covered on both) |
| view | YES | NO | — |

Win11 destructive verb confirmed: `net user testzz /add` then `/delete` → net1 NOT spawned (rule misses on Win11).

## Implication
Coverage of the net1-only rules is OS-dependent and inconsistent:
- `net localgroup` spawns no net1 on EITHER OS → Group Discovery Via Net is bypassed on both (strongest, consistent gap).
- `net user` / `net accounts` spawn net1 on Server but NOT on Win11 → User Deletion, Password Policy etc. silently work on Server but miss on Windows 11. The same rule's coverage flips with the OS.
No attacker trick needed — default behaviour differs.

## Fix (one macro, makes coverage uniform)
```
process_net:  (Processes.process_name=net.exe OR Processes.process_name=net1.exe
               OR Processes.original_file_name=net.exe OR Processes.original_file_name=net1.exe)
```
Fixes all 19 process_net rules at once, non-breaking: matches the action whether it runs in net.exe or spawns net1, on any Windows version. Closes rename too (adds original_file_name).
