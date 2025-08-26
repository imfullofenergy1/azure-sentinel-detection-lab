# azure-sentinel-detection-lab

Hands-on SOC project demonstrating end-to-end detection engineering in Microsoft Sentinel.

**Highlights**
- Windows 11 VM + Log Analytics Workspace in Azure
- Windows Security Events ingested via Azure Monitor Agent (AMA) + DCR
- Custom KQL analytics rules:
  - **Failed Login Flood** (Event ID 4625)
  - **Brute Force Success** (4625 → 4624 sequence)
- MITRE ATT&CK mapping: **Credential Access / T1110 (Brute Force)**
- Validated by generating incidents in Sentinel

---

## Architecture

- **Resource Group:** `SentinelLab-RG`
- **Compute:** `WinTestVM` (Windows 11)
- **Workspace:** `SentinelLab-WS` (Log Analytics)
- **Connector:** Windows Security Events via **AMA**
- **DCR:** `SecurityEvents-DCR` (applied to VM)

Diagram (conceptual):
