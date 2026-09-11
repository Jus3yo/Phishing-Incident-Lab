# Cloudora Payroll Phishing Investigation (Training Lab)

> Fictional client "Cloudora" (B2B HR software) — training scenario from MyFirstHack /
> myfirstcyberjob community resources. All domains, IPs, and identities are simulated.

## Description

On **August 25, 2026**, 40 Cloudora employees were targeted by a payroll-themed phishing
campaign impersonating Cloudora HR ("confirm your payroll details before 5pm"). The attacker ran
**two variants**:

- **Variant A** — spoofed the real `payroll@cloudora.io` address outright. Failed SPF, DKIM, and
  DMARC. Easy to catch, and partly quarantined by Exchange Online Protection.
- **Variant B** — used an attacker-registered lookalike domain, `cloudora-hr-portal.example`,
  fully SPF/DKIM/DMARC-authenticated *for that fake domain*. Passed every filter and reached
  every targeted inbox.

Six employees clicked the phishing link; **two submitted their credentials** and were
subsequently compromised by an attacker signing in from Amsterdam, Netherlands. The incident was
reported the same morning by an employee, and the compromised accounts were contained within
hours. A separately-reported Mailchimp newsletter was investigated in parallel and cleared as a
false positive.

This repo documents the full investigation: the original phishing/benign `.eml` samples, the
step-by-step analyst walkthrough (header analysis → threat intel enrichment → log queries), the
KQL queries run against Sentinel/ADX, and the final incident report.

## Key findings

1. **A payroll-themed phishing campaign targeted 40 mailboxes** using two subject lines, both
   impersonating Cloudora HR and pointing to the lookalike domain `cloudora-hr-portal.example`.
2. **Passing authentication did not mean the email was legitimate.** Variant B was fully
   SPF/DKIM/DMARC-aligned — but only for the attacker's own domain, not Cloudora's. This let it
   evade filtering that Variant A's outright spoof did not.
3. **Two accounts were compromised** — `freya.lynn@cloudora.io` and `ryan.boyd@cloudora.io` —
   both submitted credentials to the fake login page and were later accessed by the attacker from
   `198.18.7.200` (Amsterdam) via Windows 11/Chrome, a device never previously associated with
   either account (impossible-travel vs. their normal UK sign-ins).
4. **Four more employees clicked but did not submit credentials** (seth.lane, chloe.price,
   hugo.marsh, dina.said). No unusual sign-ins were found for them, but they're treated as
   elevated-risk and given precautionary password resets.
5. **30 employees received but didn't click**, and **4 more were fully protected by EOP
   quarantine** (never saw the message).
6. **The reported Mailchimp newsletter was a false positive** — legitimately SPF/DKIM/DMARC
   aligned to `cloudora.io`, with valid unsubscribe headers, and correctly cleared.
7. **No evidence of fraudulent payments or data theft** based on available logs. Containment
   (session revocation, password resets, MFA re-registration, IOC blocking, mailbox remediation)
   was completed the same day.

Full detail, MITRE ATT&CK mapping, timeline, and recommendations are in
[`Cloudora_Incident_Report.pdf`](Cloudora_Incident_Report.pdf).

## Repo structure

```
.
├── README.md                      # this file
├── Investigation_Walkthrough.md   # full analyst walkthrough, converted from the original .docx
├── KQL_Queries.md                 # every KQL query used, with results and screenshots
├── Cloudora_Incident_Report.pdf   # final incident report
├── emails/                        # original .eml samples (phishing variants + benign control)
└── images/                        # screenshots referenced by the walkthrough / queries docs
```

### Email samples

| File | Description |
|---|---|
| `01_phishing_payroll_variantA_reported.eml` | Variant A, as originally reported by James Holt |
| `02_phishing_payroll_variantB.eml` | Variant B (lookalike domain, fully authenticated) |
| `03_benign_mailchimp_newsletter.eml` | Legitimate newsletter reported at the same time (false positive) |
| `04_legit_cloudora_hr_payroll_reference.eml` | Genuine Cloudora HR payroll email, for comparison |
| `05_phishing_payroll_variantA_forwarded.eml` | Variant A, forwarded copy with headers preserved |
| `06_phishing_payroll_variantA_firstwave.eml` | Variant A, first-wave sample (198.18.44.10) |

## Suggested next steps for this lab

- Try re-deriving Findings 1–6 yourself from the raw `.eml` files before reading `Investigation_Walkthrough.md`.
- Re-run the queries in `KQL_Queries.md` against your own sample data to practice the KQL patterns.
- Extend the MITRE ATT&CK mapping in the incident report with detection/mitigation ideas of your own.
