# Azure Sentinel Detection Lab

Hands-on SOC project showing end-to-end detection engineering in **Microsoft Sentinel**.

## Highlights
- Windows 11 VM + Log Analytics Workspace in Azure
- Windows Security Events ingested via **Azure Monitor Agent (AMA)** with a **Data Collection Rule (DCR)**
- Two custom **KQL analytics rules**
  - **Failed Login Flood** (Event ID 4625)
  - **Brute Force Success** (4625 → 4624 sequence)
- Alerts promoted to **Incidents** in Sentinel
- **MITRE ATT&CK:** Credential Access / **T1110 – Brute Force**
- Full case study PDF (screens & notes)

> 📄 **Case Study PDF:** [SentinelLab-OmariMiller.pdf](docs/SentinelLab-OmariMiller.pdf)

---

## Architecture
- **Resource Group:** `SentinelLab-RG`
- **Compute (VM):** `WinTestVM` (Windows 11)
- **Workspace:** `SentinelLab-WS` (Log Analytics)
- **Connector:** Windows Security Events via **AMA**
- **DCR:** `SecurityEvents-DCR` (applied to VM)

---

## Data Ingestion
Windows Security Events are collected on the VM and forwarded by **Azure Monitor Agent** to the workspace via the **DCR**.  
Connector status shows **Connected**, with recent “Last data received”.

---

## Detections (KQL)

### 1) Failed Login Flood (Scheduled)
Detect ≥10 failed logons for the same user in a 5-minute window.

- **Query file:** [`queries/failed_login_flood.kql`](queries/failed_login_flood.kql)
- **Entity mapping:** `Account → TargetUser`
- **Severity:** Medium/High
- **ATT&CK:** T1110 (Brute Force)

### 2) Brute Force Success (NRT)
Multiple failures followed by a success for the same user within ~10 minutes.

- **Query file:** [`queries/brute_force_success.kql`](queries/brute_force_success.kql)
- **Entity mapping:** `Account → TargetUser`
- **Severity:** High
- **ATT&CK:** T1110 (Brute Force)

---

## Validation Steps

1. **Generate events from the host**
   - Perform 5–7 **failed RDP logins** (wrong password), then one **successful** login.
2. **Confirm raw logs in Sentinel → Logs**
   ```kusto
   SecurityEvent
   | where EventID in (4624, 4625)
   | summarize count() by EventID
