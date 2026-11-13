#!/usr/bin/env python3
"""
test_rules.py: evaluate the JSON detection rules in rules/ against sample
events and report which rules fire.

The rules deliberately mirror SIEM / Sigma-style structure (log source,
filter conditions, threshold + time window, grouping) but are stored as
JSON so they can be parsed with the Python standard library alone -
no PyYAML or third-party packages required.

Supported detection types:
  match     - fires if at least one event equals every filter field
  threshold - fires if events matching the filter, grouped by `group_by`,
              reach `threshold_count` events (or distinct values of
              `distinct_field`) inside a sliding `window_minutes` window

Usage:
  python3 src/test_rules.py
  python3 src/test_rules.py --rules rules --events data/sample-events.json
"""

import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def matches(event, filter_fields):
    return all(event.get(k) == v for k, v in filter_fields.items())


def evaluate_match(rule, events):
    hits = [e for e in events if matches(e, rule["detection"]["filter"])]
    if hits:
        e = hits[0]
        return True, (f"{len(hits)} matching event(s); first at "
                      f"{e['timestamp']} user={e.get('user', '-')} "
                      f"src_ip={e.get('src_ip', '-')}")
    return False, "no events matched the filter conditions"


def evaluate_threshold(rule, events):
    det = rule["detection"]
    window = timedelta(minutes=det["window_minutes"])
    threshold = det["threshold_count"]
    groups = defaultdict(list)
    for e in events:
        if matches(e, det["filter"]):
            key = tuple(e.get(f) for f in det["group_by"])
            groups[key].append(e)
    for key, evs in sorted(groups.items(), key=lambda kv: str(kv[0])):
        evs.sort(key=lambda e: e["_dt"])
        for i, start in enumerate(evs):
            in_window = [x for x in evs[i:] if x["_dt"] - start["_dt"] <= window]
            if det.get("distinct_field"):
                value = len({x[det["distinct_field"]] for x in in_window})
                unit = f"distinct {det['distinct_field']} values"
            else:
                value = len(in_window)
                unit = "events"
            if value >= threshold:
                label = ", ".join(f"{f}={v}" for f, v in
                                  zip(det["group_by"], key))
                return True, (f"{label}: {value} {unit} within "
                              f"{det['window_minutes']} min starting "
                              f"{start['timestamp']}")
    return False, (f"no group reached {threshold} within "
                   f"{det['window_minutes']} min")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Test SIEM-style rules.")
    parser.add_argument("--rules", default="rules",
                        help="Directory containing rule .json files")
    parser.add_argument("--events", default="data/sample-events.json",
                        help="Sample events JSON file")
    args = parser.parse_args(argv)

    events = load_json(args.events)
    for e in events:
        e["_dt"] = datetime.fromisoformat(e["timestamp"])

    rule_files = sorted(Path(args.rules).glob("*.json"))
    rules = [load_json(f) for f in rule_files]

    print(f"Loaded {len(rules)} rules and {len(events)} sample events.\n")
    fired = 0
    for rule in rules:
        det = rule["detection"]
        if det["type"] == "match":
            hit, detail = evaluate_match(rule, events)
        elif det["type"] == "threshold":
            hit, detail = evaluate_threshold(rule, events)
        else:
            hit, detail = False, f"unsupported detection type: {det['type']}"
        fired += hit
        status = "FIRED    " if hit else "NOT FIRED"
        print(f"[{status}] {rule['id']}  {rule['name']} "
              f"(severity: {rule['severity']}, MITRE {rule['mitre_attack']['technique_id']})")
        print(f"            {detail}")
    print(f"\nResult: {fired} of {len(rules)} rules fired on the sample data.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
