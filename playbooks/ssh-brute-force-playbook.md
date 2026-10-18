# Playbook: SSH Brute Force Alert

**Version:** 1.0  
**Author:** Umair Haider  
**Last updated:** 9/20/2026

## Trigger

This playbook is triggered when multiple failed SSH authentication attempts are detected from the same source IP against a Linux system within a short period.

**Example trigger:**

> 10 or more failed SSH login attempts from the same source IP within 5 minutes.

The exact threshold can be adjusted based on the environment.

---

## Severity Guidance

|Condition|Severity|
|-|-|
|Failures only, external source, no success|Low / Medium|
|Failures followed by success|High|
|Success + privileged account|High / Critical|
|Success + post-auth anomaly|Critical|

> **Important:** Severity should also consider the affected system, account importance, source IP reputation, and what happened after authentication.

---

# Investigation Steps

## Step 1 — Confirm the alert

First, confirm that the alert represents real SSH authentication failures.

### Commands

On many Linux systems:

```bash
grep "Failed password" /var/log/auth.log
```

To look for failures from a specific IP:

```bash
grep "Failed password" /var/log/auth.log | grep "SOURCE_IP"
```

To look at recent authentication events:

```bash
sudo journalctl -u ssh --since "1 hour ago"
```

On some systems the SSH service is named `sshd`:

```bash
sudo journalctl -u sshd --since "1 hour ago"
```

### What you're establishing

Identify:

* **Source IP** — Where are the attempts coming from?
* **Target host** — Which system is being attacked?
* **Target account** — Which username is being targeted?
* **Time window** — When did the attempts occur?
* **Number of attempts** — How many failures occurred?
* **Authentication method** — Password, public key, etc.

### Example

```text
Source: 203.0.113.50
Target: web-server-01
Account: admin
Failures: 47
Time: 14:02–14:05
```

At this point, you are trying to answer:

> **"Is this actually a burst of SSH authentication failures?"**

---

# Step 2 — Determine the Rate

Calculate:

**Failed attempts ÷ time period = attempts per unit of time**

### Example

47 failures in 3 minutes:

**47 ÷ 3 = ~15.7 attempts/minute**

This tells you how aggressively the source is attempting authentication.

### What the rate can indicate

|Pattern|Possible interpretation|
|-|-|
|1–2 attempts over several minutes|Could be a user mistake|
|Several attempts repeatedly|Suspicious|
|Many attempts in a short period|Likely automated|
|Hundreds/thousands of attempts|Strong indication of automated brute force|

There is **no universal number** that proves an attack.

Consider:

* Normal user behavior
* Internet exposure of the server
* Source IP
* Username being targeted
* Number of accounts targeted
* Whether authentication eventually succeeded

### Decision point

Ask:

> **Does the frequency and pattern look like normal user behavior or automated authentication attempts?**

Do not classify an event as malicious based only on the number of failures.

---

# Step 3 — Did It Succeed?

This is the **critical branch**.

Search for successful SSH authentication:

```bash
grep "Accepted" /var/log/auth.log
```

For a specific source IP:

```bash
grep "Accepted" /var/log/auth.log | grep "SOURCE_IP"
```

You can also check successful logins:

```bash
last
```

### What you're looking for

Example:

```text
Failed password for admin from 203.0.113.50
Failed password for admin from 203.0.113.50
Failed password for admin from 203.0.113.50
Accepted password for admin from 203.0.113.50
```

This is much more concerning than failures alone.

### If there is NO successful login

Ask:

* Was the source external?
* Was the targeted account valid?
* Were there only failed attempts?
* Is there any other suspicious activity?

**Action:**

* Document the activity.
* Consider blocking/rate-limiting the source according to organizational procedures.
* Check whether other hosts were targeted by the same source.
* Close or monitor the alert if no additional suspicious activity is found.

### If authentication SUCCEEDED

**Escalate and continue the investigation.**

A successful login following repeated failures could indicate that the attacker obtained valid credentials.

Proceed to **Step 4**.

---

# Step 4 — Investigate Post-Authentication Activity

After a successful login, determine what the account did.

First check recent login activity:

```bash
last
```

Check currently logged-in users:

```bash
who
```

Check recent authentication events:

```bash
sudo journalctl --since "1 hour ago" | grep -Ei "ssh|sudo|session"
```

Check `sudo` activity:

```bash
sudo grep "sudo" /var/log/auth.log
```

Look for commands executed through the shell history when appropriate:

```bash
cat ~/.bash_history
```

For another user's history, only access it if you are authorized:

```bash
sudo cat /home/USERNAME/.bash_history
```

### Look for suspicious activity

Examples include:

* Unexpected `sudo` usage
* Creation of new users
* Changes to SSH configuration
* Downloading unknown files
* Installing unexpected software
* Starting unusual processes
* Disabling security controls
* Accessing sensitive files
* Connecting to unusual external systems
* Persistence mechanisms

Check recent processes:

```bash
ps aux --sort=-%cpu | head
```

Check listening network services:

```bash
sudo ss -tulpn
```

### Key question

> **What happened after the successful authentication?**

A successful login by itself does not prove compromise. The activity that follows helps determine the risk.

---

# Step 5 — Assess the Account

Determine exactly what account was accessed.

### Check account information

```bash
id USERNAME
```

This shows the user's UID and group memberships.

Check whether the account has administrative privileges:

```bash
sudo -l -U USERNAME
```

Check the account:

```bash
grep "^USERNAME:" /etc/passwd
```

### Determine the account type

Ask:

* Is this an administrator?
* Is this a normal user?
* Is this a service account?
* Is interactive SSH access expected?
* Is remote access normally allowed?
* Was the account supposed to log in at this time?
* Is the source IP normally associated with this user?

### Important distinction

A successful login to:

```text
root
```

is significantly different from a successful login to a low-privilege user.

But don't automatically assume that a normal user is harmless.

Check whether the account can:

* Use `sudo`
* Access sensitive data
* Access other systems
* Modify applications
* Read credentials
* Execute privileged commands

---

# Escalation Criteria

Escalate to **Tier 2 immediately** if:

* Repeated SSH failures are followed by a **successful authentication**.
* The successful login involves a **privileged or administrative account**.
* Suspicious commands, `sudo` activity, persistence, or unusual processes are observed after authentication.
* The same source is targeting **multiple accounts or multiple systems**.
* There is evidence of credential compromise or unauthorized access.

---

# Close Criteria

Close as **false positive / benign** only when the investigation supports a reasonable explanation, such as:

* A legitimate user repeatedly entered the wrong password.
* An approved vulnerability scanner or security tool generated the authentication attempts.
* An authorized administrator was testing authentication.
* The source IP belongs to an approved internal system performing the activity.
* No successful unauthorized authentication occurred.
* No suspicious post-authentication activity was identified.

### What must be documented

Document:

* Why the activity occurred
* Source IP
* Target host
* Target account
* Number of failures
* Time period
* Whether authentication succeeded
* Evidence checked
* Who/what generated the activity
* Why the event was considered benign

**Do not close an alert simply because there was no successful login.**

---

# Required Documentation

Regardless of the outcome, record:

### Alert Information

* Alert ID
* Date/time
* Source IP
* Destination/target host
* Target username
* Number of failed attempts
* Detection threshold

### Investigation

* Authentication logs reviewed
* Successful login identified: **Yes / No**
* Account privilege level
* Source IP reputation/context if available
* Post-authentication activity reviewed
* Related systems/accounts checked

### Final Assessment

Record one of:

```text
Benign
Suspicious Activity
Confirmed Unauthorized Access
False Positive
```

Then provide a short explanation.

### Example ticket note

```text
47 failed SSH authentication attempts were observed
from 203.0.113.50 against web-server-01 targeting the
admin account between 14:02 and 14:05.

No successful authentication was identified.

The source was external and the attempt rate was approximately
16 attempts/minute, consistent with automated authentication
attempts.

No post-authentication activity was observed.

Assessment: Suspicious SSH brute-force activity with no
evidence of successful compromise.
```

---

# MITRE ATT&CK

* **T1110.001 — Brute Force: Password Guessing**

  * Repeated attempts to guess an account password.
* **T1078 — Valid Accounts**

  * Applies when an attacker successfully uses legitimate credentials.

### Important distinction

**Failed login attempts → T1110.001**

**Successful use of compromised legitimate credentials → potentially T1078**

Do not map every SSH brute-force alert to T1078. You need evidence that valid credentials were actually used.

---

# Beginner Analyst Decision Flow

```text
SSH Brute Force Alert
        │
        ▼
Confirm failed authentication
        │
        ▼
Identify source + target + account
        │
        ▼
How many attempts and how quickly?
        │
        ▼
Did authentication succeed?
      /       \
    NO         YES
    │           │
    ▼           ▼
Check other   Escalate
targets       │
    │         ▼
    │     Investigate
    │     post-auth activity
    │         │
    ▼         ▼
No further   Assess account
suspicious       │
activity         ▼
    │       Determine impact
    ▼
Document + close/monitor
```

## Analyst Mindset

Don't train yourself to think:

> **"Many failed logins = brute force = close."**

Train yourself to think:

> **"What happened, did authentication succeed, whose account was involved, and what happened afterward?"**

That distinction turns this from a **log-checking exercise into an actual SOC investigation**.

