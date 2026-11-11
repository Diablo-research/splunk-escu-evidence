#!/usr/bin/env python3
"""
mutate_dataset.py - make the "renamed binary" copy of a rule's test dataset.
Developed with AI assistance to speed up the analysis.

For the name_only gap we need to prove a rule stops matching when the process
is renamed. This takes a Sysmon/EDR log (the rule's own attack_data) and
rewrites the IMAGE PATH filename to a new name, while leaving OriginalFileName
untouched -- which is exactly what a real rename does.

How it tells them apart: the image path always has a separator before the
name (...\vssadmin.exe), while the OriginalFileName value does not
(<Data Name='OriginalFileName'>VSSADMIN.EXE</Data>). So replacing only
"\vssadmin.exe" / "/vssadmin.exe" hits Image and CommandLine but never
OriginalFileName. The script then VERIFIES no OriginalFileName value changed.

Usage:
    python3 mutate_dataset.py --in windows-sysmon.log --target vssadmin.exe
    # writes windows-sysmon.renamed.log, process renamed to svc.exe

    python3 mutate_dataset.py --in in.log --target wmic.exe --newname abcd.exe --out out.log

Then load both logs into your lab Splunk and run the rule's search against each.
"""

import argparse
import re
import sys
from pathlib import Path


def mutate(text, target, newname):
    base = re.escape(target)                       # vssadmin\.exe
    # image path: a separator, then the target name, as a whole token
    path_re = re.compile(r'(?P<sep>[\\/])' + base + r'(?P<edge>["\'\s<&]|$)', re.IGNORECASE)
    n = {"count": 0}

    def repl(m):
        n["count"] += 1
        return m.group("sep") + newname + m.group("edge")

    out = path_re.sub(repl, text)
    return out, n["count"]


def original_file_names(text):
    """Every OriginalFileName value in the log (to prove we didn't touch them)."""
    return re.findall(r"OriginalFileName['\"]?\s*[>=:]\s*['\"]?([A-Za-z0-9_.\-]+)", text, re.IGNORECASE)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="infile", required=True, type=Path)
    ap.add_argument("--target", required=True, help="binary to rename, e.g. vssadmin.exe")
    ap.add_argument("--newname", default="svc.exe", help="new on-disk name (default svc.exe)")
    ap.add_argument("--out", type=Path, help="output log (default: <in>.renamed.log)")
    args = ap.parse_args()

    if not args.infile.exists():
        sys.exit(f"input not found: {args.infile}")
    text = args.infile.read_text(encoding="utf-8", errors="replace")

    ofn_before = original_file_names(text)
    new_text, count = mutate(text, args.target, args.newname)
    ofn_after = original_file_names(new_text)

    if count == 0:
        print(f"WARNING: no image path for '{args.target}' found. Is this the right dataset?")
    if ofn_before != ofn_after:
        sys.exit("ABORT: an OriginalFileName value changed - the mutation is unsafe, not writing output.")

    out = args.out or args.infile.with_suffix(".renamed.log")
    out.write_text(new_text, encoding="utf-8")

    print(f"target        : {args.target} -> {args.newname}")
    print(f"image paths rewritten : {count}")
    print(f"OriginalFileName values preserved : {len(ofn_after)} (unchanged)")
    if ofn_after:
        print(f"  e.g. OriginalFileName still = {ofn_after[0]}")
    print(f"written       : {out}")
    print()
    print("Next: load both logs into Splunk, run the rule's search over each.")
    print("  original -> should FIRE ;  renamed -> should be SILENT (that is the gap).")


if __name__ == "__main__":
    main()
