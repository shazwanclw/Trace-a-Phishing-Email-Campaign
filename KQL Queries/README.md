# Cloudora Phishing Campaign | KQL Query Pack

This directory contains the complete collection of Kusto Query Language (KQL) queries developed and utilized during the investigation of incident **CLD-IR-0002** (Ticket **CLD-0002**).

These queries are designed for execution in **Azure Data Explorer (ADX)**, **Microsoft Sentinel**, and **Microsoft Defender for Endpoint/Office 365**.

---

## Log Tables Schema Reference

| Table Name | Description | Key Telemetry Columns |
| :--- | :--- | :--- |
| `CloudoraMsgTrace_CL` | Exchange Online message trace, delivery, and URL click logs | `TimeGenerated`, `EventType`, `Campaign`, `SenderAddress`, `SenderIP`, `RecipientAddress`, `DeliveryAction`, `SPFResult`, `DKIMResult`, `DMARCResult`, `Url`, `ClickIP`, `CredentialsSubmitted` |
| `CloudoraSignIn_CL` | Microsoft Entra ID cloud authentication and access telemetry | `TimeGenerated`, `UserPrincipalName`, `AppDisplayName`, `IPAddress`, `City`, `Country`, `DeviceOS`, `Browser`, `ResultType` |

> **Note on Data Ingestion:**
> - `TimeGenerated` must be typed as `datetime`.
> - `CredentialsSubmitted`, `SPFResult`, `DKIMResult`, `DMARCResult` in `CloudoraMsgTrace_CL` must be typed as `string`.
> - `ResultType` in `CloudoraSignIn_CL` must be typed as `string` (`"0"` = Success).

---

## Query Inventory & Mapping

| File | Investigation Phase | Primary Purpose |
| :--- | :--- | :--- |
| [`01_campaign_scoping.kql`](./01_campaign_scoping.kql) | Step 6a: Campaign Scoping | Quantifies delivered vs quarantined messages across sender IPs and SPF/DKIM/DMARC authentication verdicts. |
| [`02_click_analysis.kql`](./02_click_analysis.kql) | Step 6c: Click Telemetry | Enumerates all users who interacted with the phishing links and isolates credential submitters (`CredentialsSubmitted == "Yes"`). |
| [`03_freya_lynn_investigation.kql`](./03_freya_lynn_investigation.kql) | Step 6d: Victim 1 Sign-in Correlation | Correlates credential submitters with successful Entra ID authentications to detect initial account compromise (Freya Lynn). |
| [`04_attacker_ip_pivot.kql`](./04_attacker_ip_pivot.kql) | Step 6e: Attacker Infrastructure Pivot | Pivots on the malicious ingress IP (`198.18.7.200`) to uncover all compromised identities across the tenant. |
| [`05_ryan_boyd_second_victim.kql`](./05_ryan_boyd_second_victim.kql) | Task 1: Victim 2 Forensic Deep-Dive | Confirms Ryan Boyd's credential submission and maps the attacker's interactive session timeline and accessed workloads. |
| [`06_near_miss_accounts.kql`](./06_near_miss_accounts.kql) | Task 2: Near-Miss Scoping | Uses anti-join logic (`kind=leftanti`) to isolate all 30 recipients who received the phish into their inbox but never clicked. |
| [`07_detection_analytic_rule.kql`](./07_detection_analytic_rule.kql) | Task 4: Detection Engineering | Production-grade correlation rule linking phishing URL clicks with subsequent cross-border/foreign logins within a 4-hour window. |
