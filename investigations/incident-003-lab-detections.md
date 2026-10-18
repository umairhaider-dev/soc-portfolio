# Lab Detection Coverage Exercise

**Analyst:** Umair Haider
**Date:** 2026-10-14 / 2026-10-16
**Environment:** Wazuh 4.14.8 manager, Windows endpoint (`win-endpoint-01`), agent-based collection

---

## Objective

Assess the detection coverage provided by Wazuh's default ruleset by generating activity for six known ATT&CK techniques and confirming what the SIEM surfaced, at what severity.

Prerequisite: process creation auditing (Event ID 4688) and command-line inclusion were enabled on the endpoint before testing. Neither is on by default — the absence of that configuration is itself a visibility gap, not an absence of activity.

---

## Results

| Technique | ID | Activity generated | Detected | Rule / Level | Assessment |
|---|---|---|---|---|---|
| Create Account | T1136.001 | `net user labtest /add` | Yes | 60109 / 8 | Strong — clear description, appropriate severity |
| Brute Force | T1110.001 | 8+ failed interactive logons | Yes | 60122 / 5 | Individual failures logged; see note on correlation below |
| Valid Accounts | T1078 | Successful logon after failures | Yes | 60118 / 3 | Logged, but not correlated with the preceding failures |
| Command & Scripting Interpreter: PowerShell | T1059.001 | `powershell.exe -nop -w hidden -enc <base64>` | **Collected, not detected** | 67027 / 3 | **Gap — see below** |
| Scheduled Task | T1053.005 | `schtasks /create` | Yes | — | Detected |
| Indicator Removal: Clear Logs | T1070.001 | `wevtutil cl Application` | Yes | — | Detected |

Additional detections observed during testing:

| Event | Rule / Level | Note |
|---|---|---|
| Account lockout | 60115 / — | Fired on the 10th failed attempt — endpoint lockout policy threshold |
| New external device recognised | 60227 / 8 | Event ID 6416 — covers the malicious-USB technique identified in the FIN7 profile |
| Account deleted | 60111 / 8 | Cleanup activity |

---

## Coverage Gaps Identified

### T1059.001 — PowerShell: collected but not detected

Rule 67027 ("A process was created", level 3) fires for every 4688 event regardless of command-line content. A PowerShell invocation using `-nop -w hidden -enc` produced an alert identical to `notepad.exe` opening a text file.

The telemetry was complete — `win.eventdata.commandLine` contained every flag. The gap was in detection logic, not collection. In a SOC filtering its queue above level 5, this activity would not have reached an analyst.

**Addressed in [detection-engineering/detection-rules.md](../detection-engineering/detection-rules.md)** — rules 100100–100102.

### T1110.001 / T1078 — no correlation between failures and success

Individual failed logons (60122) and the subsequent success (60118) were each logged, but as unrelated events. The sequence that distinguishes a blocked attempt from a successful compromise was not expressed by any default rule.

Correlation rules 100200–100202 were written to close this. They are deployed but validation is incomplete — see the detection-rules document for the environment constraints that prevented end-to-end testing.

---

## Analysis

Default coverage was stronger than expected for **account manipulation and persistence** — account creation, deletion, scheduled tasks and log clearing all produced appropriately severe, clearly described alerts without any tuning.

It was weakest where **context determines maliciousness**. Process creation and authentication events were collected faithfully but evaluated in isolation. A default ruleset can reasonably flag "an account was created" as noteworthy on its own; it cannot know that this particular command line, or this particular sequence of events, is the interesting one. That judgement is what custom rules encode.

The practical conclusion: out-of-the-box SIEM coverage is a starting position, not a capability. The difference between an alert that says "a process was created" and one that says "possible obfuscated payload, T1059.001" is entirely the work done after deployment.

---

## Method Note

Activity was generated natively on the endpoint rather than from an attacker host. No offensive tooling was used — each technique was reproduced with built-in Windows utilities against a disposable local account in an isolated lab, and all test artefacts were removed afterwards.
