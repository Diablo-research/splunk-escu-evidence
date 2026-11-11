# ESCU endpoint evasion & logic-gap audit — evidence

Reproducible evidence for a reported set of evasion/logic gaps in
`splunk/security_content` endpoint detections. Scanned on **develop `4c1652e`**;
attack side anchored to **ArgFuscator** (`aeca415`) and to lab tests on
**Windows 11 25H2 (build 26200)** and **Windows Server**.

**Headline:** 158 distinct production detections are evadable or fail on default
modern Windows — **62 TTP, 67 Anomaly, 29 Hunting** — most tracing to rules that
hardcode `process_name=X` instead of using the `process_X` macro ESCU already ships.
14 rules are confirmed end-to-end in a live Splunk; the rest share the same root
cause and the replay method below.

See `FINDINGS.md` for the full write-up and per-class fixes.

## Layout
```
tools/     the reproduction chain (Python 3.8+, pyyaml)
  escu_gap_scanner.py    static scanner: flags each gap class in the SPL
  mutate_dataset.py      makes the "evaded" copy of a rule's attack_data
  sandbox_replay.py      replays every name_only rule orig-vs-mutated, no Splunk
lab/       Windows host tests (run as Administrator)
  Test-RenamedBinaries.ps1   reads each binary's real OriginalFileName + signer
  Test-Net1Spawn.ps1         does `net <verb>` spawn net1.exe on this OS?
results/   the two long lists (smaller sets are tables in findings/ and FINDINGS.md)
  rename_gap_89.csv              89 rename bypasses (Class 1)
  flag_form_confirmed_final.csv  option-char (/ vs -) results (Class 2)
findings/  per-class write-ups with the exact fixes
screenshots/   live-Splunk proof triangles (fires / 0 / fix recovers)
```

The full raw scan (all ~915 candidate findings across every class) is not shipped —
regenerate it with `escu_gap_scanner.py` (below).
```
```

## Reproduce

### 1. Scan the rules (no Splunk, no Windows)
```
pip install pyyaml openpyxl
git clone --depth 1 https://github.com/splunk/security_content
python3 tools/escu_gap_scanner.py --repo security_content        # -> escu_gaps.csv
python3 tools/escu_gap_scanner.py --repo security_content --explain "Deleting Shadow Copies"
```

### 2. Replay a rule end-to-end in a lab Splunk
Download the rule's own `attack_data` (URL in its YAML `tests: attack_data: data:`),
make the evaded copy, load both into a scratch index, and compare:
```
python3 tools/mutate_dataset.py --in windows-sysmon.log --target vssadmin.exe
```
Upload `*.log` and `*.renamed.log` (sourcetype `XmlWinEventLog`), then in Splunk
(fields rex-extracted so no Sysmon TA is required):
```
index=<test> (source=*orig* OR source=*renamed*)
| rex "Name=['\"]Image['\"]>(?<img>[^<]+)"
| rex "Name=['\"]CommandLine['\"]>(?<cmd>[^<]+)"
| rex "Name=['\"]OriginalFileName['\"]>(?<ofn>[^<]+)"
| search img="*vssadmin.exe" cmd="*delete*" cmd="*shadow*" | stats count by source
```
Original fires, renamed = 0 (bypass); add `OR ofn="VSSADMIN.EXE"` and the renamed
copy is caught again (fix works). Same shape for the other classes (prefix swap,
quote insertion, sibling swap).

### 3. Confirm the attack side on a Windows host
```
# OriginalFileName values for the rename fixes (read-only):
.\lab\Test-RenamedBinaries.ps1 -List rename_test_list.txt
# does `net <verb>` spawn net1.exe here? (Administrator)
.\lab\Test-Net1Spawn.ps1
```
Option-char (`/`↔`-`) and quote-insertion behaviour is validated per binary by
ArgFuscator (https://argfuscator.net) and reproduced directly on Windows 11/Server.

## Notes
- Counts are after excluding scanner false positives (e.g. SQLCMD's genuinely
  case-sensitive flags, drive-anchored path exclusions, cmd-intrinsic techniques).
- `sandbox_replay.py` is a simulation of the SPL match logic, anchored to the live
  Splunk results; it narrows the field, the live runs confirm.
