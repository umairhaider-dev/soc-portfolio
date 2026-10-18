# Incident 002 — Phishing Email Analysis
**Analyst:** Umair Haider
**Date:** 2026-09-23
**Sample received:** 2026-09-06 15:55:39 -0700
**Severity:** High (personal mailbox) / High (if received in enterprise)
**Verdict:** Malicious — payment card harvesting phishing

---

## Summary

Bulk phishing email impersonating a generic "Cloud Services" provider, claiming a storage subscription payment has failed and directing the recipient to "Update payment method." The payload link is hosted on **Google Cloud Storage**, abusing a trusted domain to defeat reputation-based filtering. The message contains extensive filter-evasion engineering: forged headers, an invalid Content-Transfer-Encoding value, hidden text, randomized nonsense HTML tags, and unrelated multilingual filler content.

Authentication (SPF/DKIM) passes — **for the attacker's own domain**, not the domain in the From header. This is a textbook example of authentication passing while the message is entirely fraudulent.

---

## Sender Analysis

| Field | Value | Assessment |
|---|---|---|
| Display name | `[REDACTED-USERNAME]` | **Spoofed** — impersonates the recipient's own address to imply a trusted/self-sent message |
| From address | `alert-7591@ursix[.]bof` | **`.bof` is not a valid TLD.** Non-existent domain |
| Return-Path | `return@sb021.worldline-solutions.my[.]id` | Lookalike of **Worldline**, a real payment processor, on a cheap Indonesian TLD |
| Sender | `[REDACTED-USERNAME]@nW2O.sb021.worldline-solutions.my[.]id` | Victim's username grafted onto attacker domain |
| To | `me@aol[.]com` | **Does not match the actual recipient** — bulk BCC distribution |
| SPF | pass (`sb021.worldline-solutions.my[.]id` → 147.135.203.120) | Passes for the **attacker's** domain |
| DKIM | pass (`d=nW2O.sb021.worldline-solutions.my[.]id`) | Signed by the **attacker's** domain |
| DMARC | **absent — no result returned** | From domain (`ursix[.]bof`) publishes no DMARC and does not align with the authenticated domain |
| Sending IP | 147.135.203.120 | HELO `sb021.site`; reverse DNS `e-presidentielle.lesechos.fr` — **mismatch suggests compromised or repurposed host** |

### Key finding: authentication pass is meaningless here

SPF and DKIM both pass because the attacker controls `worldline-solutions.my[.]id` and authenticated it correctly. Neither mechanism validates the `From:` header the user actually sees. **No DMARC result is present at all**, which is the critical absence — DMARC is the only one of the three that enforces alignment with the visible sender.

Contrast with a legitimate message (Exness/Amazon SES, analysed previously): `dmarc=pass ... header.from=exness.com`. Here there is no DMARC line, and the From domain is a fabricated TLD.

---

## Forged and Malformed Headers

| Artifact | Why it matters |
|---|---|
| `Received: from efianalytics.com ... with ESMTPS id ?act=cl&pid=12931_md&uid=2...` | **Forged Received header.** The "ESMTPS id" is a URL query string, not a message ID. Injected by the attacker to fake a delivery chain |
| `Content-Transfer-Encoding: zWddQINLnI` | **Invalid value.** Legitimate values are 7bit/8bit/binary/quoted-printable/base64. Content is actually base64 — designed to break gateway parsers |
| `Content-Type: multipart/digest` | Unusual for marketing/notification mail; parser confusion |
| Duplicate `Delivered-To` and `Content-Length` headers | Header injection / parser confusion |
| `X-Google-Sender-Delegation: ... Trusted Sender` | **Fabricated header** inventing a trust signal |
| `X-Originating-IP: 217.18.210.147` | Does not match actual SMTP source; forged |
| Date inconsistency (23:12:49 +0200 vs Google receipt 15:55:39 -0700); stray body date `06/15/2024` | Sloppy template reuse |

---

## URL Analysis

| URL (defanged) | Assessment |
|---|---|
| `hxxps://storage.googleapis[.]com/midfielders/midfielders.html?act=cl&pid=12931_md&uid=2&vid=378355&ofid=335&lid=490&cid=561601` | **Primary payload.** Attacker-controlled HTML hosted in a public Google Cloud Storage bucket |
| `hxxps://storage.googleapis[.]com/midfielders/midfielders.html?act=un&...` | "Unsubscribe" link — **same page**, only `act=cl` → `act=un`. Unsubscribing leads to the phishing page |
| `hxxp://rCiExDK[.]bof/LEAVE=To` | List-Unsubscribe header; same fake `.bof` TLD |

**Entire email body is a single wrapping `<a>` tag** — every pixel of the message is clickable, not just the button.

**Trusted-service abuse:** `storage.googleapis.com` is legitimate Google infrastructure. Domain reputation, TLS certificate, and category filters all pass. Only the path and bucket name (`midfielders`) are attacker-controlled. Blocking the domain is impossible without breaking Google Cloud Storage entirely.

**Tracking parameters** (`uid`, `vid`, `ofid`, `lid`, `cid`) indicate a commercial phishing kit with per-recipient campaign tracking — confirming bulk distribution.

---

## Filter Evasion Techniques Observed

1. **Base64-encoded HTML body** with an invalid Content-Transfer-Encoding label
2. **Hidden text blocks** — `font-size:1px; opacity:0; max-height:0px; overflow:hidden` filled with `&nbsp;` padding (Bayesian filter poisoning)
3. **Randomized nonsense HTML tags** — `<gijx40pdyq>`, `<julfxloq05>`, mismatched open/close tags. Defeats signature matching and HTML parsing
4. **Unrelated multilingual filler** — French job-application template, university election notice, customer service reply, forum archive text. Hashbusting so each message is unique
5. **Hidden social engineering** — "This message was sent from a trusted sender" inside an invisible `<object>`
6. **Subject/body mismatch** — Subject says storage is *full*; body says *payment failed*. Two lures in one template

---

## Attachment Analysis

None. Pure link-based credential/payment harvesting.

---

## Social Engineering Indicators

| Lever | How it's used |
|---|---|
| **Urgency** | "avoid service interruption" |
| **Fear of loss** | "Without enough Cloud space, you may not be able to store all your data and files" |
| **Authority** | Generic "Cloud Services" branding — deliberately vague to avoid trademark-based detection while still sounding official |
| **Legitimacy props** | Fake Subscription ID `CLDSTRG-92837465`, professional HTML styling, "sent automatically by Cloud Services" footer |
| **Low-friction ask** | Single "Update payment method" button |

**Target:** payment card details, not credentials. The lure is a billing failure, so the harvesting page will request card number, expiry, and CVV.

---

## Verdict

**Malicious — high confidence.** Evidence:

1. From-header domain uses a **non-existent TLD** (`.bof`)
2. **No DMARC alignment** between the authenticated domain and the visible sender
3. Return-Path domain **impersonates a real payment processor** (Worldline) on an unrelated TLD
4. **Forged Received header** containing phishing URL parameters
5. **Invalid Content-Transfer-Encoding** — deliberate parser evasion
6. Recipient in `To:` does not match actual delivery — bulk BCC
7. Payload hosted on **abused trusted infrastructure**
8. Multiple independent **filter-evasion techniques** layered together

No legitimate sender engineers headers this way.

---

## Recommended Response

**Scope**
- Search mail environment for sender domain `worldline-solutions.my[.]id`, subject "Warning! Your Cloud Storage Is Full", and the `midfielders` URL path
- Query proxy/DNS logs for access to the `storage.googleapis.com/midfielders/` path
- Identify any recipient who clicked

**Contain**
- Purge from all mailboxes (search-and-destroy)
- Block sender domain, sending IP 147.135.203.120, and the specific GCS object URL at proxy/gateway
- **Do not block `storage.googleapis.com` wholesale** — block by full path only

**Remediate (if anyone submitted card data)**
- Instruct affected users to contact their card issuer and freeze/reissue immediately
- Treat as a fraud incident, not only a security one

**Report**
- Report the abusive bucket to Google Cloud abuse so the object is removed at source
- Submit URL to URLhaus / PhishTank for community benefit

**Close the loop**
- Notify the reporting user that the email was confirmed malicious and actioned

---

## IOCs (defanged)

| Type | Value |
|---|---|
| Sender domain | `worldline-solutions.my[.]id` |
| Sender subdomain | `sb021.worldline-solutions.my[.]id`, `nW2O.sb021.worldline-solutions.my[.]id` |
| From domain | `ursix[.]bof` |
| Unsubscribe domain | `rCiExDK[.]bof` |
| Sending IP | 147.135.203.120 |
| Claimed originating IP | 217.18.210.147 |
| Payload URL | `hxxps://storage.googleapis[.]com/midfielders/midfielders.html` |
| Campaign ID | `pid=12931_md`, `cid=561601` |
| Subject | Warning! Your Cloud Storage Is Full |

**Pyramid of Pain note:** every IOC above sits at the bottom two tiers (IPs, domains) — trivially replaced. Durable detection here targets the **behaviour**: HTML email whose entire body is a single anchor to a cloud-storage-hosted `.html` object, combined with an invalid Content-Transfer-Encoding value.

---

## MITRE ATT&CK

| Technique | ID |
|---|---|
| Phishing: Spearphishing Link | T1566.002 |
| User Execution: Malicious Link | T1204.001 |
| Acquire Infrastructure: Web Services | T1583.006 |
| Impersonation | T1656 |
