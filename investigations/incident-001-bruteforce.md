# Incident 001 — Local Brute Force Simulation
**Analyst:** Umair Haider  **Date:** 2026-09-12  **Severity:** Low

## Summary
Detected repeated authentication failures against account `testuser`
on the lab host, followed by a successful authentication.

## Timeline
- 16:04 — First authentication failure observed
- 16:18 — 12 total failures recorded over 14 minutes
- 16:18 — Successful authentication; session opened

## Evidence
Commands run and what each returned:
- `grep -c "authentication failure" /var/log/auth.log` → 12

## Analysis
12 authentication failures against local user `testuser` via `su`. Originating from a local user session at console pts/0 between time 16:04 till 16:18. Rate of approximately 0.86 attempts per minute indicates that it is normal user speed not by an automated tools. Successful authorization at 16:18 immediately following failure sequence. `testuser` is unprivileged with no sudo entitlement, no persistent mechanism, no new SUID binaries or unexpected outbound traffic.
Pattern is consistent with someone guessing the password or legitimate user trying to remember the forgotten password. Absent a remote source and post event anomaly, confidence in malicious attempt is low.

**Verdict:** Benign — low confidence in malicious intent.

## Post-Compromise Checks
- Cron persistence: clean
- SUID binaries created today: clean
- Account manipulation: clean
- Active connections: clean

## Recommendation
No containment action required at this time. Confirm with account owner whether the failed attempts were self-generated. If unconfirmed, review account for unauthorized use and consider password reset.

## MITRE ATT&CK
- T1110.001 — Brute Force: Password Guessing
- T1078 — Valid Accounts