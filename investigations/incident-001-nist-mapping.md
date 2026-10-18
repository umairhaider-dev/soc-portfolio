# Incident 001 — NIST IR Lifecycle Mapping

A retrospective mapping of [Incident 001](incident-001-bruteforce.md) against the four phases of NIST SP 800-61, written to identify what the investigation could and could not establish, and why.

---

## 1. Preparation

**What existed:**

- Authentication logging enabled; `/var/log/auth.log` being written
- Standard Linux tooling available for log analysis

**What did not:**

- **No centralised logging.** All evidence was local to the host. A compromised machine controls its own logs.
- **No baseline.** Without a record of normal authentication patterns for this host, "12 failures in 14 minutes" had no reference point. The rate assessment was derived from first principles rather than from measured normal.
- **No playbook.** Investigation steps were improvised, which makes the result dependent on the analyst rather than repeatable. This gap was addressed afterwards by writing the [SSH brute force playbook](../playbooks/ssh-brute-force-playbook.md).
- **No retention policy.** When the original log lines were needed again for the write-up, they had rotated away. Evidence that exists at the time of an incident is not necessarily evidence that exists when the report is written.

Preparation was the weakest phase, and it constrained every phase that followed.

---

## 2. Detection and Analysis

**Detection:** none. The activity was found by manual inspection, not surfaced by any control. In a real environment this sequence would have gone unnoticed.

**Analysis performed:**

| Step | Finding |
|---|---|
| Counted failures | 12 authentication failures via `su` |
| Established source | Local user at console pts/0 — not remote |
| Calculated rate | ~0.86 attempts/minute, consistent with human typing |
| Confirmed outcome | Successful authentication immediately following the failures |
| Assessed account | `testuser` — unprivileged, no sudo entitlement |
| Checked post-authentication | Cron, SUID binaries, account changes, active connections — all clean |

**Severity assessment:** initially recorded as High on the basis of the failure-then-success pattern alone. Revised to **Low** after the rate analysis and source attribution showed the pattern was equally consistent with a legitimate user recovering a forgotten password.

Downgrading on evidence was the correct outcome. The first assessment assumed the dramatic explanation; the second tested it.

---

## 3. Containment, Eradication, Recovery

**Actions taken:** none. The assessment did not support containment, and acting without justification is itself a cost — unnecessary isolation disrupts the user and consumes response capacity.

**If the assessment had been malicious:**

1. Capture volatile evidence before changing host state
2. Isolate the host at the network layer, leaving it running
3. Disable the affected account and revoke active sessions
4. Review for persistence before considering recovery

**Evidence preservation tension:** isolation and shutdown both destroy volatile evidence. Memory holds running processes, network connections and injected code that never touched disk, and all of it is lost on power-off. The order of volatility dictates capturing memory before disk — which conflicts directly with the instinct to contain immediately. In practice the decision depends on whether the attacker is actively causing damage.

---

## 4. Post-Incident Activity

**What worked:**

- The rate calculation prevented a false positive being escalated as a compromise
- Post-authentication checks were completed rather than assumed
- The conclusion was bounded by the available evidence rather than extended beyond it

**What did not:**

- The first draft of the report attributed the failures to an external source that did not appear anywhere in the evidence. Corrected on review, but it is the failure mode worth noting: a plausible narrative filled a gap where a fact belonged.
- Evidence was not preserved before cleanup. The test account was deleted and the relevant log entries later rotated out.

**Detection gap identified:**

This activity would not have been detected by any network-layer control. It was entirely local — no packets crossed the network, so an IDS, IPS or firewall would have observed nothing.

| Control | Would it have detected this? |
|---|---|
| IDS / IPS | No — no network traffic generated |
| Firewall | No — no boundary crossed |
| Antivirus | No — no malicious file involved |
| HIDS / EDR | **Yes** — reads local authentication events |
| SIEM | **Yes**, if `auth.log` were being forwarded |

**Recommended improvements:**

1. Deploy host-based collection forwarding authentication events to a SIEM — the only control class that would have surfaced this
2. Establish a baseline of normal authentication behaviour per host
3. Define log retention sufficient to outlast investigation and reporting
4. Correlate failure bursts with subsequent success, rather than alerting on failures alone

Items 1 and 4 were implemented subsequently in the [home SOC lab](../lab/lab-build-log.md) and [detection rules](../detection-engineering/detection-rules.md).
