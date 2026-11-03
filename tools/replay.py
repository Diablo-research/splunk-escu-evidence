#!/usr/bin/env python3
"""Replay every proposal dataset in this repository into a local Splunk lab and run the proposed
and comparison searches exactly as written (filter macro -> `search *`, index injected).
Runs with Splunk's bundled Python: /opt/splunk/bin/splunk cmd python3 tools/replay.py <repo dir>
Uses only the standard library. Creates one index per proposal (ev_<id>). Changes no ESCU content."""
import base64, datetime, hashlib, json, os, re, ssl, sys, time
import urllib.error, urllib.parse, urllib.request
from collections import Counter
from pathlib import Path

BASE = "https://127.0.0.1:8089"


class Splunk:
    def __init__(self):
        pw = os.environ.get("SPLUNK_PASSWORD")
        if not pw:
            raise RuntimeError("SPLUNK_PASSWORD is not set in the container.")
        self.auth = "Basic " + base64.b64encode(("admin:" + pw).encode()).decode()
        self.ctx = ssl._create_unverified_context()  # lab self-signed cert on container loopback

    def request(self, path, form=None, raw=None):
        headers = {"Authorization": self.auth}
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif raw is not None:
            data, headers["Content-Type"] = raw, "text/plain; charset=utf-8"
        req = urllib.request.Request(BASE + path, data=data, headers=headers)
        with urllib.request.urlopen(req, context=self.ctx, timeout=120) as r:
            return r.read()

    def json(self, path):
        return json.loads(self.request(path + ("&" if "?" in path else "?") + "output_mode=json"))

    def search(self, spl):
        data = self.request("/servicesNS/admin/DA-ESS-ContentUpdate/search/v2/jobs/export", form={
            "search": spl, "output_mode": "json", "earliest_time": "0", "latest_time": "+10y",
            "preview": "false", "count": "0"})
        rows, warnings = [], []
        for line in data.decode().splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            msgs = list(item.get("messages", []))
            if isinstance(item.get("message"), dict):
                msgs.append(item["message"])
            for m in msgs:
                kind = str(m.get("type", "")).upper()
                if kind in ("ERROR", "FATAL"):
                    raise RuntimeError("Splunk search error: " + str(m.get("text", m)))
                if kind.startswith("WARN"):
                    warnings.append(str(m.get("text", "")))
            if "result" in item:
                rows.append(item["result"])
        return rows, warnings


def environment(client):
    env = {"replayed_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
    try:
        e = client.json("/services/server/info")["entry"][0]["content"]
        env["splunk"] = "{} {}".format(e.get("product_type", "Splunk"), e.get("version"))
    except Exception as ex:
        env["splunk"] = "unknown ({})".format(ex)
    apps = []
    try:
        for a in client.json("/services/apps/local?count=0")["entry"]:
            n = a["name"]
            if n == "DA-ESS-ContentUpdate" or "sysmon" in n.lower() or n.lower().startswith("splunk_ta_windows"):
                apps.append("{} {}".format(n, a["content"].get("version", "?")))
    except Exception as ex:
        apps.append("unknown ({})".format(ex))
    env["apps"] = sorted(apps)
    return env


def prepare(spl, index):
    spl = re.sub(r"`[A-Za-z0-9_]+_filter`", "search *", spl)
    spl = spl.replace("__INDEX__", index)
    m = re.search(r"from\s+datamodel=[\w.]+\s+where", spl, re.I)
    if m:
        return spl[:m.end()] + " index=" + index + spl[m.end():]
    if spl.lstrip().startswith("|"):
        return spl
    if "index=" + index in spl:
        return spl if spl.lstrip().startswith("search ") else "search " + spl
    return "search index=" + index + " " + spl


def cell(v):
    if isinstance(v, list):
        v = "; ".join(str(x) for x in v)
    v = str(v).replace("|", "\\|").replace("\n", " ")
    return v if len(v) <= 140 else v[:137] + "..."


def table(rows, fields):
    if not rows:
        return "_No results._\n"
    fields = [f for f in fields if any(f in r for r in rows)] or sorted(rows[0].keys())[:6]
    out = "| " + " | ".join(fields) + " |\n|" + "---|" * len(fields) + "\n"
    for r in rows:
        out += "| " + " | ".join(cell(r.get(f, "")) for f in fields) + " |\n"
    return out


def replay_case(client, case_dir, env):
    cfg = json.loads((case_dir / "replay.json").read_text())
    index = cfg["index"]
    raw = (case_dir / cfg["data"]).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    events = re.findall(r"<Event\b[^>]*>.*?</Event>", raw.decode("utf-8-sig"), re.S)
    print("\n=== {} ({} events, sha256 {}) ===".format(cfg["title"], len(events), digest[:16]), flush=True)
    try:
        client.request("/services/data/indexes/" + index + "?output_mode=json")
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
        client.request("/services/data/indexes", form={"name": index, "output_mode": "json"})
    count = lambda: int((client.search("search index=" + index + " | stats count")[0] or [{"count": 0}])[0]["count"])
    if count() == 0:
        params = urllib.parse.urlencode({"index": index, "sourcetype": cfg["sourcetype"], "source": cfg["source"], "host": cfg["host"]})
        for ev in events:
            client.request("/services/receivers/simple?" + params, raw=ev.encode())
        print("Submitted {} events to index {}".format(len(events), index), flush=True)
    else:
        print("Index {} already holds data; not resent.".format(index), flush=True)
    for _ in range(45):
        n = count()
        if n >= len(events):
            break
        time.sleep(2)
    if n != len(events):
        raise RuntimeError("Expected {} indexed events in {}, found {}".format(len(events), index, n))
    norm = lambda s: s.replace("\r\n", "\n").strip()
    indexed, _ = client.search("search index=" + index + " | table _raw")
    identical = Counter(map(norm, events)) == Counter(norm(r["_raw"]) for r in indexed)
    print("Indexed {} events; byte-identical to the dataset: {}".format(n, identical), flush=True)

    report = {"title": cfg["title"], "issue": cfg.get("issue"), "index": index, "dataset": cfg["data"],
              "dataset_sha256": digest, "events": len(events), "indexed_identical": identical,
              "environment": env, "searches": []}
    all_ok = identical
    for s in cfg["searches"]:
        spl = (case_dir / s["file"]).read_text() if s.get("file", "").endswith(".spl") else s["spl"]
        query = prepare(spl, index)
        rows, warns = client.search(query)
        exp = s.get("expected")
        ok = (exp is None) or (len(rows) == exp)
        if s["kind"] == "proposed":
            all_ok = all_ok and ok
        print("[{}] {}: expected {} -> got {} {}".format(s["kind"], s["name"], "n/a" if exp is None else exp,
              len(rows), "PASS" if ok else "FAIL"), flush=True)
        report["searches"].append({"name": s["name"], "kind": s["kind"], "note": s.get("note", ""),
                                   "expected": exp, "actual": len(rows), "passed": ok, "warnings": warns,
                                   "executed_search": query, "fields": s.get("fields", []), "results": rows})
    report["passed"] = all_ok

    res = case_dir / "results"
    res.mkdir(exist_ok=True)
    (res / "splunk-replay.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    md = ["# Splunk replay results: {}\n".format(cfg["title"]),
          "Generated by `tools/replay.py` on {}. Splunk: {}. Apps: {}.\n".format(env["replayed_utc"], env["splunk"], ", ".join(env["apps"])),
          "- Dataset: `{}` ({} events, sha256 `{}`)".format(cfg["data"], len(events), digest),
          "- Index: `{}`; indexed events byte-identical to the dataset: **{}**".format(index, identical),
          "- Searches run exactly as in the YAML, with the filter macro replaced by `search *` and the index added.\n",
          "| Search | Kind | Expected | Actual | Result |", "|---|---|---|---|---|"]
    for s in report["searches"]:
        md.append("| {} | {} | {} | {} | {} |".format(s["name"], s["kind"], "n/a" if s["expected"] is None else s["expected"],
                  s["actual"], ("PASS" if s["passed"] else "FAIL") if s["expected"] is not None else "info"))
    for s in report["searches"]:
        md.append("\n## {} ({})\n".format(s["name"], s["kind"]))
        if s["note"]:
            md.append(s["note"] + "\n")
        md.append(table(s["results"], s["fields"]))
        md.append("<details><summary>Executed search</summary>\n\n```spl\n{}\n```\n</details>".format(s["executed_search"].strip()))
    (res / "splunk-replay.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    return all_ok


def main(root):
    root = Path(root)
    client = Splunk()
    env = environment(client)
    print("Splunk: {} | {}".format(env["splunk"], ", ".join(env["apps"])), flush=True)
    summary = []
    for case_dir in sorted(p for p in root.iterdir() if (p / "replay.json").exists()):
        try:
            ok = replay_case(client, case_dir, env)
        except Exception as ex:
            print("STOP {}: {}".format(case_dir.name, ex), flush=True)
            ok = False
        summary.append((case_dir.name, ok))
    print("\n=== SUMMARY ===")
    for name, ok in summary:
        print("{:40} {}".format(name, "PASS" if ok else "FAIL"))
    return 0 if all(ok for _, ok in summary) else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
