#!/usr/bin/env python3
"""
escu_gap_scanner.py - find detection-logic gaps in Splunk ESCU rules.
Developed with AI assistance to speed up the analysis.

Reads every detection YAML in a splunk/security_content checkout, expands the
macros, pulls out the parts of the SPL that actually FILTER events, and runs a
set of checks. Each check looks for one class of weakness: a small change in
how an attacker runs a tool that makes the rule stop matching.

This is static analysis. A finding is a CANDIDATE, not a proven bypass. The
"confidence" column says how much has to  be verified:
    logic  - the bug is visible in the SPL itself (e.g. case-sensitive regex)
    review - read the rule; it may be intentional or covered elsewhere
    lab    - needs a lab test (does the binary really accept that variant?)

Usage:
    python3 escu_gap_scanner.py --repo ~/security_content
    python3 escu_gap_scanner.py --repo ~/security_content --checks case_regex,name_only
    python3 escu_gap_scanner.py --repo ~/security_content --explain "RunDLL Loading DLL By Ordinal"
    python3 escu_gap_scanner.py --selftest

Needs: Python 3.8+, PyYAML (pip install pyyaml).
"""

import argparse
import csv
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is missing: pip install pyyaml")


# =============================================================================
# 1. LOADING THE REPO
# =============================================================================

def load_macros(repo):
    """Return {macro_name: definition} from macros/*.yml.

    Macros with arguments (e.g. `base64decode(x)`) are stored as "name(N)"
    in Splunk. We keep them under the bare name and substitute $arg$ later.
    """
    macros = {}
    for f in sorted((repo / "macros").glob("*.yml")):
        d = yaml.safe_load(f.read_text(encoding="utf-8"))
        if d and "name" in d and "definition" in d:
            macros[d["name"]] = {"definition": str(d["definition"]),
                                 "args": d.get("arguments") or []}
    return macros


def load_detections(repo, subdirs, include_experimental):
    """Yield one dict per detection YAML."""
    for sub in subdirs:
        for f in sorted((repo / "detections" / sub).glob("*.yml")):
            d = yaml.safe_load(f.read_text(encoding="utf-8"))
            if not d or "search" not in d:
                continue
            if d.get("status") != "production" and not include_experimental:
                continue
            yield {
                "name": d.get("name", f.stem),
                "file": str(f.relative_to(repo)),
                "type": d.get("type", ""),
                "status": d.get("status", ""),
                "data_source": d.get("data_source") or [],
                "search": str(d["search"]),
            }


# =============================================================================
# 2. MACRO EXPANSION
# =============================================================================
# A rule like  WHERE `process_rundll32`  hides its real logic inside a macro.
# If we do not expand it we cannot tell that the macro already checks
# original_file_name, and we would report a false "renamed binary" gap.

MACRO_RE = re.compile(r"`([A-Za-z0-9_]+)(?:\(([^`]*)\))?`")


def expand_macros(spl, macros, depth=0):
    if depth > 10:                       # protection against macro loops
        return spl

    def repl(m):
        name, argtext = m.group(1), m.group(2)
        if name.endswith("_filter"):     # per-rule tuning macro, empty by default
            return ""
        macro = macros.get(name)
        if macro is None:
            return m.group(0)            # unknown macro: leave it as text
        body = macro["definition"]
        if argtext is not None and macro["args"]:
            values = [a.strip() for a in argtext.split(",")]
            for argname, value in zip(macro["args"], values):
                body = body.replace(f"${argname}$", value)
        return expand_macros(body, macros, depth + 1)

    return MACRO_RE.sub(repl, spl)


# =============================================================================
# 3. SPLITTING THE SEARCH INTO PIPELINE SEGMENTS
# =============================================================================
# "| tstats ... | where ... | stats ..." -> ["tstats ...", "where ...", ...]
# A plain split on "|" breaks on pipes inside quotes or [subsearches], so we
# walk the string and only split at top level.

def split_pipes(spl):
    segments, buf = [], []
    in_quote = False
    bracket = 0
    i = 0
    while i < len(spl):
        c = spl[i]
        if c == "\\" and i + 1 < len(spl):      # keep escapes intact
            buf.append(spl[i:i + 2])
            i += 2
            continue
        if c == '"':
            in_quote = not in_quote
        elif not in_quote and c == "[":
            bracket += 1
        elif not in_quote and c == "]":
            bracket -= 1
        elif c == "|" and not in_quote and bracket == 0:
            segments.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    segments.append("".join(buf).strip())
    return [s for s in segments if s]


def find_top_level(text, keyword, start=0):
    """Index of a whole-word keyword outside quotes and parentheses, or -1."""
    depth, in_quote = 0, False
    kw = keyword.lower()
    low = text.lower()
    i = start
    while i < len(text):
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            in_quote = not in_quote
        elif not in_quote:
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif depth == 0 and low.startswith(kw, i):
                before = text[i - 1] if i else " "
                after = text[i + len(kw)] if i + len(kw) < len(text) else " "
                if not before.isalnum() and not after.isalnum() and before != "_" and after != "_":
                    return i
        i += 1
    return -1


# =============================================================================
# 4. FINDING THE FILTER TEXT
# =============================================================================
# Only part of the search decides which events match.
#   | tstats ... where <FILTER> by <GROUPING FIELDS>
#   `sysmon` EventCode=1 <FILTER>          (raw search before the first pipe)
#   | search <FILTER>   | where <FILTER>   | regex <FILTER>
# The BY clause of almost every ESCU tstats rule lists
# Processes.original_file_name. If we grepped the whole search we would think
# every rule handles renamed binaries.

FILTER_COMMANDS = {"search", "where", "regex"}


def filter_parts(spl):
    """Return a list of (command, text) for the filtering parts of the search."""
    parts = []
    segs = split_pipes(spl)
    for n, seg in enumerate(segs):
        first = seg.split(None, 1)[0].lower() if seg.split() else ""
        rest = seg.split(None, 1)[1] if len(seg.split(None, 1)) > 1 else ""
        if n == 0 and first in ("tstats", "from", "datamodel"):
            w = find_top_level(seg, "where")
            if w != -1:
                b = find_top_level(seg, "by", w)
                parts.append(("tstats-where", seg[w + 5:b if b != -1 else None]))
        elif n == 0 and first not in ("inputlookup", "rest", "makeresults", "loadjob"):
            parts.append(("base-search", seg))        # raw search: all of it filters
        elif first in FILTER_COMMANDS:
            parts.append((first, rest))
        elif first == "eval":
            parts.append(("eval", rest))              # only used by the regex check
    return parts


# =============================================================================
# 5. PARSING FIELD TERMS
# =============================================================================
# We need "which field is compared to which values, and is it negated?".
# Handles:  field=value  field="value"  field!=value  field IN ("a","b")
# Data model prefixes (Processes.process_name) are stripped to process_name.

TERM_RE = re.compile(
    r'(?P<field>[A-Za-z_][A-Za-z0-9_.]*)\s*'
    r'(?:(?P<op>!=|==|=)\s*(?P<val>"(?:[^"\\]|\\.)*"|[^\s()|,]+)'
    r'|\s+IN\s*\((?P<list>[^)]*)\))',
    re.IGNORECASE)
LIST_ITEM_RE = re.compile(r'"((?:[^"\\]|\\.)*)"|([^\s,"]+)')


def unquote(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] == '"':
        v = v[1:-1]
    return v


def is_negated(text, pos):
    """True if the term at text[pos] sits under a NOT.

    Looks at the word just before the term; if the term is the first thing in
    a parenthesised group, climbs out of the group and looks again. So both
    `NOT a=1` and `NOT (a=1 OR b=2)` count as negated for a and b.
    """
    while True:
        before = text[:pos].rstrip()
        if re.search(r"\bNOT$", before, re.IGNORECASE):
            return True
        # find the enclosing "(" of this term
        depth = 0
        k = len(before) - 1
        while k >= 0:
            if before[k] == ")":
                depth += 1
            elif before[k] == "(":
                if depth == 0:
                    break
                depth -= 1
            k -= 1
        if k < 0:
            return False
        pos = k                           # check what stands before the "("


def iter_terms(text):
    """Yield (field, op, [values], negated) for each comparison in text."""
    for m in TERM_RE.finditer(text):
        field = m.group("field").split(".")[-1]
        if field.upper() in ("AND", "OR", "NOT"):
            continue
        if m.group("list") is not None:
            values = [unquote(a or b) for a, b in LIST_ITEM_RE.findall(m.group("list"))]
            op = "IN"
        else:
            values = [unquote(m.group("val"))]
            op = m.group("op")
        negated = is_negated(text, m.start()) or op == "!="
        yield field, op, values, negated


# =============================================================================
# 6. THE CHECKS
# =============================================================================
# Each check gets the rule and its filter parts and returns a list of findings:
#   (gap_class, confidence, detail, evidence)

NAME_FIELDS = {"process_name", "image", "process_path", "process_exec"}
OFN_FIELDS = {"original_file_name", "originalfilename"}
CMDLINE_FIELDS = {"process", "commandline", "parent_process", "parentcommandline",
                  "process_command_line", "cmd_line"}
PATH_FIELDS = NAME_FIELDS | {"imageloaded", "file_path", "targetfilename",
                             "parent_process_path", "parentimage", "process_current_directory"}


def exe_name(value):
    """'C:\\Windows\\System32\\rundll32.exe' or '*\\rundll32.exe' -> 'rundll32.exe'."""
    v = value.replace("\\\\", "\\").split("\\")[-1].lower()
    if re.fullmatch(r"[a-z0-9_.\-]+\.(exe|com|scr|msc|cpl)", v):
        return v
    return None


def positive_targets(parts):
    """Binary names the rule is LOOKING FOR (not the ones it excludes)."""
    names = set()
    for cmd, text in parts:
        if cmd == "eval":
            continue
        for field, op, values, neg in iter_terms(text):
            if field.lower() in NAME_FIELDS and not neg:
                names.update(n for n in map(exe_name, values) if n)
    return names


def has_ofn(parts):
    return any(field.lower() in OFN_FIELDS
               for cmd, text in parts if cmd != "eval"
               for field, *_ in iter_terms(text))


def is_windows_rule(rule, spl):
    ds = " ".join(map(str, rule["data_source"]))
    if "linux" in ds.lower():
        return False
    return bool(re.search(r"windows|sysmon|crowdstrike|powershell", ds, re.I)) or ".exe" in spl.lower()


# --- Class 1: matched by file name only ------------------------------------
# Copy rundll32.exe to C:\Users\Public\notes.exe and process_name no longer
# says rundll32.exe. original_file_name comes from the PE version resource,
# which survives a rename.

def check_name_only(rule, parts, spl):
    targets = positive_targets(parts)
    if targets and not has_ofn(parts):
        return [("name_only", "review",
                 "process matched by file name only; a renamed copy is not matched",
                 ", ".join(sorted(targets)))]
    return []


# --- Class 2: one switch prefix only ----------------------------------------
# Many Windows tools parse "-x", "/x" and, for PowerShell, Unicode dashes
# (U+2013 en dash, U+2014 em dash, U+2015 horizontal bar) the same way.
# A rule that only looks for "*-enc*" misses "/enc" and "\u2013enc".

FLAG_RE = re.compile(r"(?:^|(?<=[\s*\"'(]))([-/\u2013\u2014\u2015])([A-Za-z][A-Za-z0-9_]{0,30})")


def cmdline_values(parts):
    """All literal strings compared against command-line fields."""
    out = []
    for cmd, text in parts:
        if cmd == "eval":
            continue
        for field, op, values, neg in iter_terms(text):
            if field.lower() in CMDLINE_FIELDS and not neg:
                out.extend(values)
        # match(process, "regex") style conditions
        for f, pat in re.findall(r'match\(\s*(?:lower\()?\s*([A-Za-z_.]+)\s*\)?\s*,\s*"((?:[^"\\]|\\.)*)"', text):
            if f.split(".")[-1].lower() in CMDLINE_FIELDS:
                out.append(re.sub(r"\\s[+*]?", " ", pat))   # treat \s as a space
    return out


def check_flag_form(rule, parts, spl):
    if not is_windows_rule(rule, spl):
        return []
    seen = defaultdict(set)                       # flag word -> prefixes seen
    alldash = " ".join(cmdline_values(parts))
    if re.search(r"\[[^\]]*-[^\]]*/[^\]]*\]|\[[^\]]*/[^\]]*-[^\]]*\]", alldash):
        return []                                 # regex like [-/]enc: already handles both
    unicode_ok = bool(re.search(r"[\u2013\u2014\u2015]|x\{201[345]\}|\\u201[345]", alldash))
    for value in cmdline_values(parts):
        if "://" in value:
            continue                              # URLs are not switches
        for prefix, word in FLAG_RE.findall(value):
            seen[word.lower()].add(prefix)
    findings = []
    for word, prefixes in sorted(seen.items()):
        missing = []
        if prefixes == {"-"}:
            missing.append("/" + word)
        if prefixes == {"/"}:
            missing.append("-" + word)
        if "-" in prefixes and not unicode_ok:
            missing.append("\u2013" + word + " (Unicode dash)")
        if missing:
            findings.append(("flag_form", "lab",
                             "switch matched in one form only; confirm the binary accepts: " + ", ".join(missing),
                             "".join(sorted(prefixes)) + word))
    return findings


# --- Class 3: case-sensitive comparison on case-insensitive data -----------
# In SPL, `search` and tstats WHERE are case-insensitive, but match(),
# like(), the regex command and where field="x" are case-sensitive.
# Windows does not care: RUNDLL32.EXE, Rundll32 and rundll32 all run.

CASE_FIELDS = CMDLINE_FIELDS | PATH_FIELDS | {"process_name", "parent_process_name"}


def case_confidence(pattern):
    """'logic' if the pattern contains name/path text (always case-insensitive
    on Windows); 'review' if its letters are only switches like -r / --run,
    because some programs treat -r and -R differently (php, ssh-keygen)."""
    p = literal_letters(pattern)
    p = re.sub(r"--?[A-Za-z][A-Za-z-]*|\[[^\]]*\]", "", p)         # drop switches, [classes]
    return "logic" if re.search(r"[A-Za-z]{2,}", p) else "review"


def literal_letters(pattern):
    """Remove regex escapes (\\d \\s \\w \\b \\x{202E}, also double-escaped
    forms) so only letters the pattern really matches literally remain."""
    p = re.sub(r"\\+x\{[0-9A-Fa-f]+\}", "", pattern)
    return re.sub(r"\\+[a-zA-Z]", "", p)


def check_case_regex(rule, parts, spl):
    # Linux and macOS ARE case-sensitive, so this check is Windows-only.
    if not is_windows_rule(rule, spl):
        return []
    findings = []
    for cmd, text in parts:
        # match(field, "regex") and like(field, "pattern")
        for fn, arg, pat in re.findall(r'\b(match|like)\(\s*([^,]+?)\s*,\s*"((?:[^"\\]|\\.)*)"\s*\)', text):
            field = arg.strip().split(".")[-1].lower()
            if arg.strip().lower().startswith(("lower(", "upper(")):
                continue                              # value normalised first: fine
            if field not in CASE_FIELDS:
                continue
            if fn == "match" and pat.startswith("(?i)"):
                continue
            if re.search(r"[A-Za-z]", literal_letters(pat)):
                findings.append(("case_sensitive", case_confidence(pat),
                                 f"{fn}() on {field} without (?i) or lower(); Windows values can be any case",
                                 f'{fn}({arg.strip()}, "{pat}")'))
        if cmd == "regex":
            m = re.match(r'\s*([A-Za-z_.]+)\s*!?=\s*"((?:[^"\\]|\\.)*)"', text)
            if (m and m.group(1).split(".")[-1].lower() in CASE_FIELDS
                    and not m.group(2).startswith("(?i)")
                    and re.search(r"[A-Za-z]", literal_letters(m.group(2)))):
                findings.append(("case_sensitive", case_confidence(m.group(2)),
                                 "regex command without (?i) on a Windows field",
                                 text.strip()[:120]))
        if cmd == "where":
            for field, op, values, neg in iter_terms(text):
                if field.lower() in CASE_FIELDS and op in ("=", "==", "IN") and not neg:
                    # only quoted strings: where a=b compares two FIELDS
                    strings = [v for v in values if f'"{v}"' in text]
                    if any(re.search(r"[A-Za-z]", literal_letters(v)) for v in strings):
                        findings.append(("case_sensitive", "logic",
                                         f"where {field}{op}... is a case-sensitive string compare",
                                         f"{field} {op} {values[:3]}"))
    return findings


# --- Class 4: only looks at cmd.exe -----------------------------------------
# "copy \\?\GLOBALROOT\...\SAM" is caught when typed into cmd.exe. The same
# file read by print.exe, esentutl.exe or a PowerShell one-liner never
# passes through cmd.exe, so a rule scoped to cmd.exe does not see it.

def check_cmd_scope(rule, parts, spl):
    targets = positive_targets(parts)
    if targets == {"cmd.exe"} and cmdline_values(parts):
        return [("cmd_only_scope", "review",
                 "rule only inspects cmd.exe command lines; check if the same action works from another process",
                 "; ".join(cmdline_values(parts)[:3]))]
    return []


# --- Class 5: bypassable exclusions -----------------------------------------
# a) NOT process="*\\Program Files\\*"  - the attacker just adds a dummy
#    argument containing "\Program Files\" to the command line.
# b) NOT process_path="*\\Windows\\System32\\*" - leading wildcard, so
#    C:\Users\Public\Windows\System32\evil.exe is also excluded.
#    Anchor exclusions instead: "C:\\Windows\\System32\\*" or a ^-anchored regex.

def check_exclusions(rule, parts, spl):
    findings = []
    for cmd, text in parts:
        if cmd == "eval":
            continue
        for field, op, values, neg in iter_terms(text):
            if not neg:
                continue
            f = field.lower()
            for v in values:
                if f in CMDLINE_FIELDS and "\\" in v and v.startswith("*"):
                    findings.append(("exclusion_cmdline", "review",
                                     "excluded by a command-line substring; an extra dummy argument can satisfy it",
                                     f"NOT {field}={v}"))
                elif f in PATH_FIELDS and re.fullmatch(r"\*\\+[^\\*]+\.\w+", v):
                    findings.append(("exclusion_by_name", "review",
                                     "excluded by file name only; a tool renamed to this name is excluded too",
                                     f"NOT {field}={v}"))
                elif f in PATH_FIELDS and v.startswith("*") and "\\" in v.strip("*"):
                    findings.append(("exclusion_path_wildcard", "review",
                                     "path exclusion starts with *; any folder ending in that path is excluded too",
                                     f"NOT {field}={v}"))
    return findings


# --- Class 6: sibling binary missing ----------------------------------------
# Same capability, different binary: powershell.exe vs pwsh.exe,
# cscript.exe vs wscript.exe, net.exe vs net1.exe.

SIBLINGS = [
    {"powershell.exe", "pwsh.exe"},
    {"cscript.exe", "wscript.exe"},
    {"net.exe", "net1.exe"},
    {"ssh.exe", "scp.exe", "sftp.exe"},
]


def check_siblings(rule, parts, spl):
    targets = positive_targets(parts)
    findings = []
    for group in SIBLINGS:
        present = targets & group
        missing = group - targets
        if present and missing:
            findings.append(("sibling_missing", "lab",
                             "covers " + ", ".join(sorted(present)) + " but not " + ", ".join(sorted(missing)),
                             ", ".join(sorted(present))))
    return findings


# --- Class 7: token pinned between literal spaces ---------------------------
# "* stop *" needs a real space on both sides. Windows argument parsing also
# splits on TAB, and drops quotes inside a word: net "stop" svc and
# net st""op svc both run, but neither contains " stop ".

SPACE_TOKEN_RE = re.compile(r"(?:^|\*) ([A-Za-z][A-Za-z0-9_:/-]{1,30}) (?:\*|$)")


def check_space_token(rule, parts, spl):
    if not is_windows_rule(rule, spl):
        return []
    hits = []
    for v in cmdline_values(parts):
        hits += SPACE_TOKEN_RE.findall(v)
    if hits:
        return [("space_bound_token", "lab",
                 "token must be surrounded by spaces; test tab separators and quote insertion",
                 ", ".join(sorted(set(hits))[:5]))]
    return []


CHECKS = {
    "name_only": check_name_only,
    "flag_form": check_flag_form,
    "case_regex": check_case_regex,
    "cmd_scope": check_cmd_scope,
    "exclusions": check_exclusions,
    "siblings": check_siblings,
    "space_token": check_space_token,
}


# =============================================================================
# 7. RUNNING IT
# =============================================================================

def analyse(rule, macros, checks):
    spl = expand_macros(rule["search"], macros)
    parts = filter_parts(spl)
    findings = []
    for name in checks:
        findings.extend(CHECKS[name](rule, parts, spl))
    return spl, parts, findings


def explain(rule, macros, checks):
    """Print every step for one rule, so you can see what the scanner sees."""
    spl, parts, findings = analyse(rule, macros, checks)
    print(f"== {rule['name']}  ({rule['file']}, {rule['type']})")
    print("\n-- original search --\n" + rule["search"].strip())
    print("\n-- after macro expansion --\n" + re.sub(r"\s+", " ", spl).strip())
    print("\n-- filter parts (what decides which events match) --")
    for cmd, text in parts:
        print(f"[{cmd}] {re.sub(r'\s+', ' ', text).strip()}")
    print("\n-- parsed terms --")
    for cmd, text in parts:
        for field, op, values, neg in iter_terms(text):
            print(f"  {'NOT ' if neg else ''}{field} {op} {values}")
    print("\n-- positive target binaries:", sorted(positive_targets(parts)) or "none")
    print("-- original_file_name used in filter:", has_ofn(parts))
    print("\n-- findings --")
    for f in findings or [("none", "", "", "")]:
        print("  ", " | ".join(f))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", type=Path, help="path to a splunk/security_content checkout")
    ap.add_argument("--subdirs", default="endpoint", help="comma list under detections/ (default: endpoint)")
    ap.add_argument("--checks", default=",".join(CHECKS), help="comma list of checks: " + ", ".join(CHECKS))
    ap.add_argument("--include-experimental", action="store_true")
    ap.add_argument("--out", type=Path, default=Path("escu_gaps.csv"))
    ap.add_argument("--explain", metavar="RULE_NAME", help="show the full analysis for one rule")
    ap.add_argument("--selftest", action="store_true", help="run the built-in examples and exit")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())
    if not args.repo:
        ap.error("--repo is required")

    checks = [c.strip() for c in args.checks.split(",") if c.strip()]
    unknown = set(checks) - set(CHECKS)
    if unknown:
        ap.error("unknown checks: " + ", ".join(sorted(unknown)))

    # Fail loudly on a wrong path: Path.glob() on a missing folder just
    # returns nothing, which would look like "0 rules, no gaps".
    repo = args.repo.resolve()
    missing = [p for p in ["macros"] + ["detections/" + s for s in args.subdirs.split(",")]
               if not (repo / p).is_dir()]
    if missing:
        sys.exit(f"Not a security_content checkout: {repo}\n"
                 f"Missing folder(s): {', '.join(missing)}\n"
                 "Point --repo at the folder that contains 'macros' and 'detections'.")

    macros = load_macros(args.repo)
    rules = list(load_detections(args.repo, args.subdirs.split(","), args.include_experimental))

    if args.explain:
        match = [r for r in rules if r["name"].lower() == args.explain.lower()]
        if not match:
            sys.exit(f"rule not found: {args.explain}")
        explain(match[0], macros, checks)
        return

    rows, per_class, flagged = [], Counter(), set()
    for rule in rules:
        _, _, findings = analyse(rule, macros, checks)
        seen_class = set()
        for gap_class, conf, detail, evidence in findings:
            rows.append([rule["name"], rule["type"], rule["status"], gap_class, conf, detail, evidence, rule["file"]])
            if gap_class not in seen_class:
                per_class[gap_class] += 1
                seen_class.add(gap_class)
            flagged.add(rule["name"])

    with args.out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["rule", "type", "status", "gap_class", "confidence", "detail", "evidence", "file"])
        w.writerows(rows)

    print(f"Scanned {len(rules)} rules, {len(macros)} macros.")
    print(f"Rules with at least one finding: {len(flagged)}")
    for gap_class, n in per_class.most_common():
        print(f"  {gap_class:<26} {n:>4} rules")
    print(f"Details: {args.out}")


# =============================================================================
# 8. SELF-TEST: one tiny rule per gap class
# =============================================================================

SELFTEST_MACROS = {
    "process_rundll32": {"definition": "(Processes.process_name=rundll32.exe OR Processes.original_file_name=RUNDLL32.EXE)", "args": []},
}

SELFTEST_CASES = [
    # (expected class or None, search)
    ("name_only", '| tstats count from datamodel=Endpoint.Processes where Processes.process_name=mshta.exe Processes.process="*http*" by Processes.original_file_name'),
    (None,        '| tstats count from datamodel=Endpoint.Processes where `process_rundll32` Processes.process="*,#1*" by Processes.dest'),
    ("flag_form", '| tstats count from datamodel=Endpoint.Processes where Processes.process_name=powershell.exe Processes.process="*-enc*" by Processes.dest'),
    ("case_sensitive", '| tstats count from datamodel=Endpoint.Processes where `process_rundll32` by Processes.process | `drop_dm_object_name(Processes)` | where match(process,"rundll32.+#\\d+")'),
    (None,        '| tstats count from datamodel=Endpoint.Processes where `process_rundll32` by Processes.process | where match(process,"(?i)rundll32.+#\\d+")'),
    ("cmd_only_scope", '| tstats count from datamodel=Endpoint.Processes where Processes.process_name=cmd.exe Processes.process="*\\\\config\\\\sam*" by Processes.dest'),
    ("exclusion_cmdline", '| tstats count from datamodel=Endpoint.Processes where Processes.original_file_name=ssh-keygen.exe Processes.process="*-D*" NOT Processes.process IN ("*\\\\Program Files\\\\*") by Processes.dest'),
    ("exclusion_path_wildcard", '`sysmon` EventCode=7 OriginalFileName=x.exe NOT ImageLoaded="*\\\\Windows\\\\System32\\\\*"'),
    ("exclusion_by_name", '`sysmon` EventCode=22 NOT Image="*\\\\arc.exe" QueryName="*ollama*"'),
    ("sibling_missing", '| tstats count from datamodel=Endpoint.Processes where Processes.process_name=powershell.exe Processes.original_file_name=x by Processes.dest'),
    ("space_bound_token", '| tstats count from datamodel=Endpoint.Processes where Processes.original_file_name=net1.exe Processes.process="* stop *" by Processes.dest'),
]


def selftest():
    failed = 0
    for expected, search in SELFTEST_CASES:
        rule = {"name": "t", "file": "t", "type": "", "status": "", "data_source": ["Sysmon EventID 1"], "search": search}
        _, _, findings = analyse(rule, SELFTEST_MACROS, list(CHECKS))
        classes = {f[0] for f in findings}
        ok = (expected in classes) if expected else not (classes & {"name_only", "case_sensitive"})
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  expect={expected or 'no name/case finding'}  got={sorted(classes)}")
    print("selftest:", "OK" if not failed else f"{failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    main()
