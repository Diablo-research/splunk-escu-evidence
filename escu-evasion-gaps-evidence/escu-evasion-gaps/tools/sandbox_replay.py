#!/usr/bin/env python3
"""
sandbox_replay.py - simulate the Splunk replay for every name_only rule,
without Splunk. Validated against the live Splunk result for Deleting Shadow
Copies (per-event: current fires, renamed silent, fixed recovers).
Developed with AI assistance to speed up the analysis.

For each rule:
  current(ev)  = (Image basename in name_targets) AND all cmd_incl substrings
                 in CommandLine AND no cmd_excl AND (parent match if any)
  mutate(ev)   = rename every name_target in Image+CommandLine to svc.exe,
                 leave OriginalFileName
  fixed(ev)    = (name match OR OriginalFileName in the target's real OFNs)
                 AND the same cmd/parent conditions

Verdict:
  original==0            -> NO-REPRO (logic/field not modelled; test in Splunk)
  renamed==0 & fixed>0   -> BYPASS CONFIRMED, fix recovers
  0<renamed<original     -> PARTIAL (some matches not via the renamed binary)
  renamed>=original      -> NOT BYPASSED by rename
"""
import csv, os, re, sys, hashlib, yaml
sys.path.insert(0, '/home/claude')
import escu_gap_scanner as sc

REPO = 'sc'
GAPS = '/mnt/user-data/attachments/f3d13b8f-8bc5-5f44-bace-adb8efc8d3eb/a13dc2bc-escu_gaps.csv'
ADDIR = 'ad'
PARENT_FIELDS = {'parent_process_name', 'parentimage'}

macros = sc.load_macros(__import__('pathlib').Path(REPO))

def cache(u): return os.path.join(ADDIR, hashlib.sha1(u.encode()).hexdigest() + '.log')

def parse_rule(relfile):
    d = yaml.safe_load(open(os.path.join(REPO, relfile), encoding='utf-8'))
    spl = sc.expand_macros(str(d['search']), macros)
    parts = sc.filter_parts(spl)
    name_targets, cmd_incl, cmd_excl, parents = set(), [], [], set()
    for cmd, text in parts:
        if cmd == 'eval': continue
        for field, op, values, neg in sc.iter_terms(text):
            f = field.lower()
            if f in sc.NAME_FIELDS and not neg:
                for v in values:
                    n = sc.exe_name(v)
                    if n: name_targets.add(n)
            elif f in sc.CMDLINE_FIELDS:
                for v in values:
                    s = v.strip('*').lower()
                    if s: (cmd_excl if neg else cmd_incl).append(s)
            elif f in PARENT_FIELDS and not neg:
                for v in values:
                    n = sc.exe_name(v)
                    if n: parents.add(n)
    data = [a.get('data','') for t in (d.get('tests') or []) for a in (t.get('attack_data') or []) if a.get('data','').endswith('.log')]
    return name_targets, cmd_incl, cmd_excl, parents, data

def field(ev, name):
    m = re.search(r"Name=['\"]"+re.escape(name)+r"['\"]>([^<]*)", ev)
    return (m.group(1) if m else "")

def basename(path): return re.split(r'[\\/]', path)[-1].lower()

def load_events(urls):
    evs = []
    for u in urls:
        p = cache(u)
        if not os.path.exists(p): continue
        raw = open(p, encoding='utf-8', errors='replace').read()
        evs += re.findall(r'<Event\b.*?</Event>', raw, re.S)
    return evs

def matcher(name_targets, cmd_incl, cmd_excl, parents):
    def m(ev, ofn_ok=None):
        img = basename(field(ev, 'Image'))
        cmd = field(ev, 'CommandLine').lower()
        name_hit = img in name_targets
        if ofn_ok is not None and not name_hit:
            name_hit = field(ev, 'OriginalFileName').lower() in ofn_ok
        if not name_hit: return False
        if not all(s in cmd for s in cmd_incl): return False
        if any(s in cmd for s in cmd_excl): return False
        if parents and basename(field(ev, 'ParentImage')) not in parents: return False
        return True
    return m

def mutate(ev, targets):
    out = ev
    for t in targets:
        out = re.sub(r'([\\/])' + re.escape(t), r'\1svc.exe', out, flags=re.I)
    return out

def run():
    rules = {}
    for r in csv.DictReader(open(GAPS, encoding='utf-8')):
        if r['gap_class'] == 'name_only':
            rules.setdefault(r['file'].replace('\\','/'), r['rule'])

    out = []
    for relfile, rulename in rules.items():
        try:
            nt, ci, ce, par, data = parse_rule(relfile)
        except Exception as e:
            out.append([rulename, 'ERROR', 0,0,0, str(e)[:60], relfile]); continue
        if not nt or not data:
            out.append([rulename, 'NO-TARGET/DATA', 0,0,0, '', relfile]); continue
        evs = load_events(data)
        if not evs:
            out.append([rulename, 'NO-EVENTS', 0,0,0, '', relfile]); continue
        m = matcher(nt, ci, ce, par)
        orig = [e for e in evs if m(e)]
        ofn_ok = {field(e,'OriginalFileName').lower() for e in orig if field(e,'OriginalFileName')}
        mut = [mutate(e, nt) for e in evs]
        renamed = sum(m(e) for e in mut)
        fixed = sum(m(e, ofn_ok) for e in mut)
        o = len(orig)
        if o == 0: verdict = 'NO-REPRO'
        elif renamed == 0 and fixed > 0: verdict = 'BYPASS-CONFIRMED'
        elif renamed == 0 and fixed == 0: verdict = 'BYPASS-NO-OFN'
        elif renamed < o: verdict = 'PARTIAL'
        else: verdict = 'NOT-BYPASSED'
        out.append([rulename, verdict, o, renamed, fixed, ','.join(sorted(nt)), relfile])

    out.sort(key=lambda r: (r[1] != 'BYPASS-CONFIRMED', -r[2]))
    with open('replay_sim_results.csv','w',newline='',encoding='utf-8') as fh:
        w = csv.writer(fh); w.writerow(['rule','verdict','original','renamed','fixed','name_targets','file'])
        w.writerows(out)
    from collections import Counter
    c = Counter(r[1] for r in out)
    print(f"rules tested: {len(out)}")
    for k,v in c.most_common(): print(f"  {k:<18} {v}")
    print("written: replay_sim_results.csv")

if __name__ == '__main__':
    run()
