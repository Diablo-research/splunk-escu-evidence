# Screenshots — live Splunk proof

Each proof: the current rule fires on the original source and returns 0 (row absent)
on the evaded copy; the fixed rule recovers the evaded copy (both sources counted).
Data uploaded as sourcetype XmlWinEventLog, fields rex-extracted at search time
(no Sysmon TA required). Index rename_test.

## Class 1 — rename (proof_orig vs proof_renamed)
- class1_rename_nslookup_current/fixed.png   407 / 0 ; fix 407 / 407
- class1_rename_taskkill_current/fixed.png   257 / 0 ; fix 257 / 257
- class1_rename_mstsc_current/fixed.png       10 / 0 ; fix  10 / 10
- class1_rename_wmic_current/fixed.png        16 / 0 ; fix  16 / 16
  (Deleting Shadow Copies was confirmed by counts 1 / 0 / 1 — no screenshot kept.)

## Class 2 — option-char / vs - (ff_orig vs ff_swapped)
- class2_flag_dism_current/fixed.png          2 / 0 ; fix 2 / 2
- class2_flag_certutil_current/fixed.png      12 / 0 ; fix 12 / 12
- class2_flag_bcdedit_current/fixed.png        2 / 0 ; fix 2 / 2

## Class 3 — sibling cscript/wscript (sib_orig vs sib_swapped)
- class3_sibling_jscript_clsid_current/fixed.png     1 / 0 ; fix 1 / 1
- class3_sibling_jscript_cscript_current/fixed.png   1 / 0 ; fix 1 / 1
- class3_sibling_vbscript_wscript_current/fixed.png  1 / 0 ; fix 1 / 1

## Class 5 — net1-only macro (OS-dependent)
- class5_net1spawn_win11.txt     Win11 25H2 (build 26200) net1-spawn table
- class5_net1spawn_server.png    Windows Server net1-spawn table (differs: user/accounts spawn net1)
