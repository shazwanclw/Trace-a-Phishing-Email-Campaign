# Cloudora Security Operations | Payroll Phishing Campaign Investigation

[![Incident Severity: P1 Critical](https://img.shields.io/badge/Severity-P1%20Critical-red.svg)](https://github.com/)
[![Log Telemetry: Microsoft Defender / Entra ID](https://img.shields.io/badge/Telemetry-Exchange%20%7C%20Entra%20ID-blue.svg)](https://github.com/)
[![Investigation Tool: KQL / ADX](https://img.shields.io/badge/Hunting-KQL%20%2F%20Azure%20Data%20Explorer-0078D4.svg)](https://github.com/)
[![Framework: MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-orange.svg)](https://attack.mitre.org/)
[![Status: Contained & Eradicated](https://img.shields.io/badge/Status-Contained%20%26%20Eradicated-brightgreen.svg)](https://github.com/)

---

## 📌 Executive Overview & Incident Scenario

This repository documents an end-to-end simulated security operations center (SOC) investigation into a targeted, payroll-themed credential phishing campaign launched against **Cloudora** (a London-based B2B HR software organization). 

The attack involved dual delivery vectors: direct domain spoofing failing transport validation, and an adversary-controlled lookalike infrastructure configured with valid cryptographic authentication. Telemetry correlation via **Kusto Query Language (KQL)** in **Azure Data Explorer (ADX)** revealed that multiple employees interacted with the lure, resulting in **two active cloud account compromises** from an external adversary node in Amsterdam.

```
                    ┌──────────────────────────────────────────────┐
                    │   Adversary Phishing Ingress (40 Targets)    │
                    └──────────────────────┬───────────────────────┘
                                           │
                    ┌──────────────────────┴───────────────────────┐
                    ▼                                              ▼
       ┌─────────────────────────┐                    ┌─────────────────────────┐
       │   Variant A (Spoofed)   │                    │  Variant B (Lookalike)  │
       │  payroll@cloudora.io    │                    │ payroll@cloudora-hr-... │
       │ SPF/DKIM/DMARC = FAIL   │                    │ SPF/DKIM/DMARC = PASS   │
       └────────────┬────────────┘                    └────────────┬────────────┘
                    │                                              │
                    └──────────────────────┬───────────────────────┘
                                           │
                    ┌──────────────────────▼───────────────────────┐
                    │  Exchange Online & User Mailbox Telemetry   │
                    │  • 36 Delivered | 4 Intercepted by EOP       │
                    │  • 6 Total Link Clicks                       │
                    └──────────────────────┬───────────────────────┘
                                           │
                    ┌──────────────────────▼───────────────────────┐
                    │    Credential Theft & Account Compromise    │
                    │  • Freya Lynn (08:47 UTC) -> Login (10:34)  │
                    │  • Ryan Boyd  (09:05 UTC) -> Login (13:22)  │
                    │  • Attacker Ingress: 198.18.7.200 (NL)       │
                    └──────────────────────┬───────────────────────┘
                                           │
                    ┌──────────────────────▼───────────────────────┐
                    │ SOC Containment & Eradication Sequence      │
                    │  1. Revoke Active Tokens & Web Sessions      │
                    │  2. Force Directory Credential Reset         │
                    │  3. Enforce & Re-register MFA                │
                    │  4. Blacklist Malicious IPs & Lookalikes     │
                    │  5. Zero-Hour Auto Purge (ZAP) Mailboxes     │
                    │  6. Forensic Post-Check Verification         │
                    └──────────────────────────────────────────────┘
```

---

## 🎯 Incident Quick Facts

| Parameter | Record Details |
| :--- | :--- |
| **Ticket Identifier** | `CLD-0002` (Reported Phishing Impersonating Cloudora HR) |
| **Incident Report ID** | `CLD-IR-0002` ([Markdown Report](./Report/CLD-IR-0002_Incident_Report.md) / [PDF Report](./Report/CLD-IR-0002_Incident_Report.pdf)) |
| **Incident Severity** | **P1 - Critical** (Active Cloud Account Takeover & Data Exposure) |
| **Impacted Organization** | Cloudora (150-user B2B HR Software Provider) |
| **Compromised Accounts** | `freya.lynn@cloudora.io`, `ryan.boyd@cloudora.io` |
| **Investigative Toolset** | RFC 822 Email Header Analysis, Azure Data Explorer, KQL, Threat Intel Enrichment |

---

## 🔬 Email Triage & Header Analysis

The investigation began with raw RFC 822 header extraction (`.eml`) from reported messages to determine technical provenance and authentication states:

### 1. Phishing Variant A — Direct Header Spoofing
* **From Address:** `payroll@cloudora.io` (Forged internal identity)
* **Reply-To Address:** `hr-support@cloudora-hr-portal.example` (Adversary extraction channel)
* **Sending Infrastructure:** `198.18.44.10` & `198.18.44.23` (`mail.cloudora-hr-portal.example`)
* **Authentication Verdict:** `spf=fail`, `dkim=fail`, `dmarc=fail (action=quarantine)`, `compauth=fail reason=001`
* **Harvesting URL:** `hxxps://cloudora-hr-portal[.]example/payroll/login`

### 2. Phishing Variant B — Lookalike Domain Deception
* **From Address:** `payroll@cloudora-hr-portal.example` (Lookalike brand)
* **Sending Infrastructure:** `198.18.51.7`
* **Authentication Verdict:** `spf=pass`, `dkim=pass`, `dmarc=pass (action=none)`
* **Harvesting URL:** `hxxps://login.cloudora-hr-portal[.]example/verify`
* **Key Analytical Takeaway:** Passing SPF/DKIM/DMARC only validates that the email originated from the domain specified in the header (`cloudora-hr-portal.example`), **not** that the domain itself is legitimate or safe.

### 3. False Positive Resolution — "Cloudora Monthly" Newsletter
* **From Address:** `news@cloudora.io` (Delivered via Mailchimp `mcsv.net`)
* **Authentication Verdict:** `spf=pass`, `dkim=pass (header.d=cloudora.io)`, `dmarc=pass`
* **Verdict:** Validated genuine marketing newsletter with authentic list-unsubscribe headers; formally cleared from the incident.

---

## 🔍 KQL Threat Hunting & Forensic Investigation

All log analysis was conducted using KQL across Exchange Online Message Trace (`CloudoraMsgTrace_CL`) and Microsoft Entra ID Sign-In logs (`CloudoraSignIn_CL`).

### Step 1: Campaign Scoping & Delivery Breakdown
Quantified the overall volume, delivery actions, and authentication outcomes across both campaign waves.

```kql
CloudoraMsgTrace_CL
| where EventType == "Delivery"
| summarize Messages = count(), Recipients = dcount(RecipientAddress)
    by Campaign, SenderAddress, SenderIP, SPFResult, DKIMResult, DMARCResult, DeliveryAction
| order by Campaign asc, SenderIP asc
```

![Campaign Scoping](./Screenshots/01%20Scope%20the%20Campaign.png)

---

### Step 2: URL Click Telemetry & Credential Harvest Identification
Filtered click logs to determine which recipients visited the hostile harvest portals and who submitted credentials.

```kql
CloudoraMsgTrace_CL
| where EventType == "Click"
| project TimeGenerated, RecipientAddress, Campaign, Url, ClickIP, CredentialsSubmitted
| order by TimeGenerated asc
```

![Everyone Who Clicked](./Screenshots/02%20Everyone%20who%20clicked.png)

---

### Step 3: Victim 1 Sign-In Correlation (Freya Lynn)
Correlated credential submitters with authentication telemetry to verify if harvested passwords were utilized.

```kql
let CredVictims = CloudoraMsgTrace_CL
    | where EventType == "Click" and CredentialsSubmitted == "Yes"
    | distinct RecipientAddress;
CloudoraSignIn_CL
| where UserPrincipalName in (CredVictims)
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, City, Country, DeviceOS, Browser
| order by UserPrincipalName asc, TimeGenerated asc
```

![Check If Submitted Credential Used](./Screenshots/03%20Check%20if%20Submitted%20credential%20get%20used.png)

> **Finding:** Following credential entry at 08:47 UTC, `freya.lynn@cloudora.io` suffered an unauthorized login at 10:34:20 UTC from `198.18.7.200` (Amsterdam, Netherlands) on a Windows 11 / Chrome device, demonstrating impossible travel against her legitimate UK sign-in.

---

### Step 4: Pivoting on Adversary Ingress IP (`198.18.7.200`)
Pivoted across the entire Entra ID tenant to detect any other identities accessed by the adversary.

```kql
CloudoraSignIn_CL
| where IPAddress startswith "198.18.7." and ResultType == "0"
| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            Apps = make_set(AppDisplayName) by UserPrincipalName, IPAddress, Country
| order by FirstSeen asc
```

![Attacker IP Pivot](./Screenshots/04%20Check%20if%20Anyone%20Else%20CompromiseD.png)

> **Critical Discovery:** A second compromised identity was uncovered — `ryan.boyd@cloudora.io`.

---

### Step 5: Second Victim Deep Dive (Ryan Boyd)
Confirmed Ryan Boyd's interaction in the message trace and mapped the adversary's sign-in activity.

```kql
// Part A: Confirm Click & Credential Submission
CloudoraMsgTrace_CL
| where EventType =~ "click" and RecipientAddress =~ "ryan.boyd@cloudora.io"
| extend SubmittedCredentials = tostring(CredentialsSubmitted)
| project TimeGenerated, Campaign, ClickIP, Url, SubmittedCredentials
```

![Second Victim Confirmed](./Screenshots/05%20Second%20Victim%20confirmed%20.png)

```kql
// Part B: Reconstruct Sign-In Timeline
CloudoraSignIn_CL
| where UserPrincipalName =~ "ryan.boyd@cloudora.io"
| extend IsSuccessful = (ResultType == "0")
| project TimeGenerated, AppDisplayName, IPAddress, Location = strcat(City, ", ", Country), Device = strcat(DeviceOS, " / ", Browser), ResultType
| order by TimeGenerated asc
```

![Second Victim Timeline](./Screenshots/06%20Second%20Victime%20Timeline.png)

> **Timeline:** Ryan Boyd submitted credentials at 09:05:44 UTC. The attacker authenticated from Amsterdam (`198.18.7.200`) at 13:22:05 UTC, accessing Outlook Web App at 13:25:33 UTC.

---

### Step 6: Scoping Non-Interacting Near-Miss Recipients
Isolated all users who received the malicious email directly into their inboxes but did not click the link, enabling targeted awareness communications.

```kql
CloudoraMsgTrace_CL
| where EventType == "Delivery" and DeliveryAction == "Delivered"
| distinct RecipientAddress
| join kind=leftanti (
    CloudoraMsgTrace_CL
    | where EventType == "Click"
    | distinct RecipientAddress
) on RecipientAddress
| sort by RecipientAddress asc
```

![Near Miss Recipients](./Screenshots/07%20All%20victim%20that%20received%20email.png)

---

### Step 7: SIEM Detection Engineering (Click-to-Foreign-Login Rule)
Constructed a correlation detection rule for Microsoft Sentinel / Defender that triggers when an account registers a phishing click followed by a cross-border authentication within 4 hours.

```kql
// Title: Cloudora - Anomalous Foreign Sign-in Post Phishing Interaction
// Severity: High
// Description: Correlates link-click telemetry with rapid cross-border authentication
let AlertWindow = 4h;
let AuthorizedCountries = dynamic(["United Kingdom", "United States"]);

CloudoraMsgTrace_CL
| where EventType =~ "Click"
| project ClickTimestamp = TimeGenerated, TargetUser = tolower(RecipientAddress), PhishURL = Url, SourceClickIP = ClickIP
| join kind=inner (
    CloudoraSignIn_CL
    | where ResultType == "0"
    | project AuthTimestamp = TimeGenerated, TargetUser = tolower(UserPrincipalName), IngressIP = IPAddress, Country, DeviceOS, Browser, AppDisplayName
) on TargetUser
| where AuthTimestamp between (ClickTimestamp .. (ClickTimestamp + AlertWindow))
| where IngressIP != SourceClickIP
| where Country !in (AuthorizedCountries)
| project TargetUser, ClickTimestamp, AuthTimestamp, DeltaMinutes = datetime_diff('minute', AuthTimestamp, ClickTimestamp), SourceClickIP, IngressIP, Country, DeviceOS, Browser, AppDisplayName, PhishURL
```

![Detection Rule Output](./Screenshots/09%20Ways%20to%20detect%20early%20compromise.png)

---

## 🛡️ Incident Response: Containment & Eradication Sequence

In accordance with enterprise incident response procedures, containment actions were prioritized in strict logical order:

| Step | Action | Target Entity | Strategic Justification |
| :---: | :--- | :--- | :--- |
| **1** | **Revoke Active Sessions & Tokens** | `freya.lynn`<br>`ryan.boyd` | **Immediate cutoff.** Resetting passwords without revoking OAuth/web tokens leaves existing adversary sessions active. |
| **2** | **Force Password Reset** | `freya.lynn`<br>`ryan.boyd` | Invalidates stolen credentials in Entra ID directory once active sessions are killed. |
| **3** | **Enforce MFA Re-Registration** | `freya.lynn`<br>`ryan.boyd` | Mandates strong multi-factor challenges, mitigating single-factor password replay. |
| **4** | **Perimeter Infrastructure Blacklist** | Malicious IPs & Lookalike Domains | Blocks relays (`198.18.44.10`, `.23`, `198.18.51.7`), ingress node (`198.18.7.200`), and `*.cloudora-hr-portal.example` at mail gateway and firewalls. |
| **5** | **Zero-Hour Auto Purge (ZAP)** | Enterprise Mail Fleet | Excises all phishing copies across 36 delivered mailboxes to eliminate secondary clicks. |
| **6** | **Forensic Verification Check** | Sign-In Logs | Confirmed zero post-containment telemetry matching `198.18.7.200`. |

---

## 🗺️ MITRE ATT&CK Matrix Mapping

| Tactic | Technique ID | Technique Name | Evidence & Incident Context |
| :--- | :--- | :--- | :--- |
| **Initial Access** | `T1566.002` | Spearphishing Link | Delivery of payroll lure emails directing users to external harvesting sites. |
| **Credential Access** | `T1598.003` | Spearphishing Link for Information | Deceptive login pages harvesting corporate passwords. |
| **Initial Access / Persistence** | `T1078.004` | Valid Accounts: Cloud Accounts | Attacker authenticated to Microsoft 365 cloud resources using stolen credentials. |
| **Resource Development** | `T1583.001` | Acquire Infrastructure: Domains | Attacker registered lookalike domain `cloudora-hr-portal.example` prior to launch. |

---

## 🚨 Indicators of Compromise (IOCs)

```
================================================================================
CATEGORY       INDICATOR VALUE                        CONTEXT
================================================================================
Domain         cloudora-hr-portal[.]example           Phishing Landing & Lookalike Domain
Hostname       login.cloudora-hr-portal[.]example     Variant B Harvesting Host
Hostname       mail.cloudora-hr-portal[.]example      Inbound Ingress Mail Relay
URL            hxxps://cloudora-hr-portal[.]example/payroll/login   Variant A Harvest URL
URL            hxxps://login.cloudora-hr-portal[.]example/verify    Variant B Harvest URL
IPv4           198.18.44.10                           Variant A (Wave 1) Sending Relay
IPv4           198.18.44.23                           Variant A (Wave 2) Sending Relay
IPv4           198.18.51.7                            Variant B Outbound Mail Relay
IPv4           198.18.7.200                           Adversary Sign-In IP (Amsterdam, NL)
Sender         payroll@cloudora.io                    Spoofed Sender Header (Variant A)
Sender         payroll@cloudora-hr-portal.example     Lookalike Sender Header (Variant B)
Reply-To       hr-support@cloudora-hr-portal.example  Attacker Extraction Mailbox
================================================================================
```

---

## 📂 Repository Structure

```
.
├── KQL Queries/
│   ├── 01_campaign_scoping.kql          # Step 6a: Scope campaign volume and auth verdicts
│   ├── 02_click_analysis.kql             # Step 6c: Identify clickers and credential submitters
│   ├── 03_freya_lynn_investigation.kql   # Step 6d: First victim Entra ID sign-in correlation
│   ├── 04_attacker_ip_pivot.kql          # Step 6e: Pivot on attacker IP (198.18.7.200)
│   ├── 05_ryan_boyd_second_victim.kql    # Task 1: Second victim confirmation & timeline
│   ├── 06_near_miss_accounts.kql         # Task 2: Scoping delivered non-clicking recipients
│   ├── 07_detection_analytic_rule.kql    # Task 4: Detection rule for click-to-foreign-login
│   └── README.md                         # Query catalog and ingestion guide
├── Report/
│   ├── CLD-IR-0002_Incident_Report.md    # Formal SOC incident report (Markdown)
│   └── CLD-IR-0002_Incident_Report.pdf   # Formatted executive incident report (PDF)
├── Screenshots/
│   ├── 01 Scope the Campaign.png
│   ├── 02 Everyone who clicked.png
│   ├── 03 Check if Submitted credential get used.png
│   ├── 04 Check if Anyone Else CompromiseD.png
│   ├── 05 Second Victim confirmed .png
│   ├── 06 Second Victime Timeline.png
│   ├── 07 All victim that received email.png
│   └── 09 Ways to detect early compromise.png
└── README.md                             # Main portfolio case study overview
```

---

## 💡 Lessons Learned & Strategic Recommendations

1. **User Reporting Velocity:** Rapid detection was driven by proactive user submission (`james.holt`). Maintaining a simple, blame-free reporting mechanism directly reduces mean time to detect (MTTD).
2. **Never Stop at Victim One:** Pivoting on adversary infrastructure (`198.18.7.200`) identified a second compromised account that would have otherwise remained undetected.
3. **Domain Alignment Over Pass/Fail Checks:** Cryptographic passes on SPF/DKIM only validate domain ownership, not domain legitimacy. Mail filters must evaluate domain age and brand similarity.
4. **Enforce Phishing-Resistant MFA:** Hardware FIDO2 tokens or number-matching MFA neutralize credential harvesting attacks even when users enter passwords.
5. **DMARC `p=reject` Enforcement:** Raising Cloudora's public DMARC policy from `p=quarantine` to `p=reject` ensures forged emails are discarded upstream.

---

> **Disclaimer:** *This investigation is a simulated security operations engagement based on synthetic training data provided by MyFirstHack. All corporate names, IP addresses, domains, and identities are synthetic and used strictly for educational and portfolio demonstration purposes.*
