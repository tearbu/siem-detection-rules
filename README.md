# SIEM Detection Rules

Five documented, testable detection rules for identity-focused attacks — plus a small harness that evaluates them against sample events and shows exactly which rules fire and why.

## Why it matters

Detection rules are only useful if they are documented (what they catch, how they work, why they false-positive) and testable (you can run sample data through them and prove they fire). This project packages both halves: each rule states its log source, MITRE ATT&CK mapping, plain-English detection logic, machine-readable conditions, and false-positive notes, and `src/test_rules.py` executes the conditions against sample events so the rules are verified, not just written down.

## The rules

| ID | Rule | Severity | MITRE ATT&CK | Logic in one line |
|----|------|----------|--------------|-------------------|
| DET-001 | Brute force login attempts against a single account | High | T1110.001 | ≥ 5 login failures for one user + source IP within 10 min |
| DET-002 | Password spraying from a single source | High | T1110.003 | One source IP fails against ≥ 4 distinct users within 30 min |
| DET-003 | Member added to privileged admin group | High | T1098 | Any `member_added` event targeting the Domain Admins group |
| DET-004 | Multiple MFA prompts denied (MFA fatigue) | Medium | T1110 | ≥ 3 denied MFA prompts for one user within 15 min |
| DET-005 | Service account used for interactive login | High | T1078 | Any successful **interactive** login by an account flagged as a service account |

Each rule lives in `rules/*.json` with a consistent schema: `id`, `name`, `description`, `severity`, `mitre_attack` (tactic + technique), `log_source`, `detection` (type, filter conditions, plain-English logic, and for threshold rules the grouping, count, and time window), and `false_positive_notes`.

### Why JSON instead of YAML/Sigma?

Production SIEM rules are usually YAML (Sigma format). These rules are stored as **JSON in the same structure** — log source, filter conditions, aggregation, time window, level, ATT&CK tags — so they map one-to-one onto Sigma concepts (a Sigma version would put `logsource`/`detection.selection`/`condition: count() by user > 4` in place of the `filter`/`threshold` fields here). JSON is used for one pragmatic reason: it parses with the Python standard library, so the test harness runs anywhere with zero installs. Converting any rule here to Sigma YAML is a formatting exercise, not a redesign.

## How to run

Python 3.9+, standard library only — nothing to install.

```bash
python3 src/test_rules.py
```

Optional: `--rules <dir>` and `--events <file>` to point the harness at other rule sets or event data. Events are a JSON list; each event is a flat object of fields (`timestamp`, `event_type`, `user`, `src_ip`, `result`, `logon_type`, `is_service_account`, …) and rules match on exact field equality plus their threshold/window aggregation.

## Sample output (actual run)

The bundled `data/sample-events.json` holds 30 fictional events containing a brute-force burst, a spraying source, a Domain Admins addition, an MFA-denial burst, and service accounts authenticating only via batch/service (non-interactive) logons.

```text
Loaded 5 rules and 30 sample events.

[FIRED    ] DET-001  Brute force login attempts against a single account (severity: high, MITRE T1110.001)
            user=jdoe, src_ip=203.0.113.45: 6 events within 10 min starting 2026-11-10T09:02:11
[FIRED    ] DET-002  Password spraying from a single source (severity: high, MITRE T1110.003)
            src_ip=198.51.100.23: 5 distinct user values within 30 min starting 2026-11-10T11:15:09
[FIRED    ] DET-003  Member added to privileged admin group (severity: high, MITRE T1098)
            1 matching event(s); first at 2026-11-10T13:42:10 user=- src_ip=10.1.3.8
[FIRED    ] DET-004  Multiple MFA prompts denied (possible MFA fatigue attack) (severity: medium, MITRE T1110)
            user=carol: 4 events within 15 min starting 2026-11-10T15:03:22
[NOT FIRED] DET-005  Service account used for interactive login (severity: high, MITRE T1078)
            no events matched the filter conditions

Result: 4 of 5 rules fired on the sample data.
```

### Why DET-005 does not fire — stated honestly

DET-005 is **not** broken; the sample data deliberately contains no event of the type it detects. The only service-account events in `sample-events.json` are `svc_reports` and `svc_backup` authenticating with `logon_type` `batch` and `service` — exactly the non-interactive behavior the rule considers normal. DET-005 needs a successful login event with `logon_type: "interactive"` **and** `is_service_account: true`, and no such event exists in the sample set. Add one and the rule fires; the non-firing result demonstrates that the rule distinguishes logon types rather than alerting on every service-account use.

## Files

```text
rules/det-001-brute-force.json                      rule: brute force
rules/det-002-password-spraying.json                rule: password spraying
rules/det-003-admin-group-member-added.json         rule: privileged group change
rules/det-004-mfa-fatigue.json                      rule: MFA fatigue
rules/det-005-service-account-interactive-login.json rule: service account misuse
src/test_rules.py                                   evaluation harness (match + threshold detection types)
data/sample-events.json                             30 fictional events exercising 4 of 5 rules
```

## Honest limitations

- **Teaching-grade evaluation, not a SIEM.** The harness supports two detection types (exact field match, and threshold-over-sliding-window with grouping/distinct counting). Real platforms add correlations across event types, lookups, and suppression lists that are only described in the rules' text here, not executed.
- **Exact-equality filters.** Filter fields must match values exactly (no regex, wildcards, or CIDR matching), so the rules as written target one normalized event schema.
- **No performance claims.** The harness loads everything into memory and is meant for dozens-to-hundreds of sample events and for validating logic, not for streaming production log volumes.
- **Thresholds are starting points**, taken from common practice; each rule's `false_positive_notes` explains what would need tuning (shared egress IPs, break-glass changes, users with flaky authenticator apps) in a real environment.
- **All events, users, and IPs are fictional** (external addresses use the documentation ranges 203.0.113.0/24 and 198.51.100.0/24).

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Araf Abubakar.
