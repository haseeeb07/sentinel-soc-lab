
# Incident 001 — Ransomware Campaign: Phishing to Encryption

**Date triaged:** 2026-07-17
**Analyst:** Haseeb
**Environment:** Microsoft Sentinel Training Lab (law-soc-lab), investigated via Microsoft Defender XDR unified portal
**Incident ID:** 1 — "NRT Security Event log cleared"
**Severity as raised:** Medium (single alert) — **reassessed by analyst to Critical** once full scope was established

---

## Summary

What began as a single Medium-severity "Security Event log cleared" alert on one host turned out to be the tail end of a full multi-stage ransomware campaign. Starting from a phishing payload executed by a single user, the attacker established persistence, dumped credentials, moved laterally across at least seven machines (including a domain controller and the CEO's workstation), disabled security tooling, staged sensitive documents for theft, deleted volume shadow copies, and cleared event logs to cover their tracks.

The log-clear alert I was handed was the attacker's anti-forensics step near the end of the operation. Closing it in isolation would have missed the entire campaign. Pivoting on the involved host and user and correlating across data sources (email, endpoint, identity, cloud) revealed the true scope.

---

## Initial alert

- **Alert:** NRT Security Event log cleared (Windows Event ID 1102)
- **Host:** win11a (win11a.pkwork.onmicrosoft.com)
- **Account:** PKWORK\mirage
- **Time:** 2026-07-17 15:04:34
- **MITRE:** T1070.001 — Indicator Removal: Clear Windows Event Logs (Defense Evasion)
- **Rule logic:** Fires on Event ID 1102 with source `Microsoft-Windows-Eventlog`, deliberately scoped to avoid false positives from AD FS servers.

Log clearing is almost never legitimate on a normal endpoint, so the analytical question became: *what was mirage doing on win11a before the logs were wiped?*

---

## Investigation

### Pivot 1 — Entity graph
The incident graph linked two entities: the user **mirage** and the host **win11a** (Association). Only one alert was correlated at the incident level, so the story had to be reconstructed by hunting.

### Pivot 2 — Cross-source timeline (Advanced Hunting)
A broad search on `win11a` / `mirage` across all tables returned 266 events and revealed telemetry from multiple sources firing in sequence — confirming this was not an isolated event:

| Time (approx) | Source | Stage |
|---|---|---|
| 14:54 | MailGuard365 (email) | Phishing delivery — initial access |
| 14:57 | Okta (identity) | Identity/account activity |
| 15:01–15:02 | CrowdStrike (endpoint) | Malware alerts + detections |
| 15:03 | GCP Audit Logs (cloud) | Cloud activity |
| 15:04:34 | SecurityEvent | **Event 1102 — log cleared** |

### Pivot 3 — Endpoint detail (CrowdStrikeDetections, 54 events)
Drilling into the endpoint detections reconstructed the full kill chain. Earliest events establish patient zero:

- **14:46:27 — Initial execution (T1204.002):** mirage ran `report.exe` from `C:\Users\mirage\Downloads\` — the phishing payload.
- **14:50:15 — Persistence (T1547.001):** `reg add HKCU\...\CurrentVersion\Run /v UpdateSvc ... svchost_update.exe /f` — Run key for reboot survival.
- **14:51:42 — Credential access (T1003.001):** `rundll32.exe comsvcs.dll MiniDump` — LSASS memory dump to harvest credentials.

The campaign then progressed through the full attack lifecycle.

---

## Kill chain (MITRE ATT&CK)

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Phishing | — | MailGuard365 email threat; `report.exe` delivered to Downloads |
| Execution | User Execution: Malicious File | T1204.002 | `report.exe` run by mirage |
| Execution | Command & Scripting Interpreter | T1059 | `powershell.exe -enc SQBuAHYAbwBrAGUA...` (decodes to `Invoke-WebRequest`) |
| Persistence | Registry Run Keys | T1547.001 | `reg add ...\CurrentVersion\Run` |
| Credential Access | OS Credential Dumping (LSASS) | T1003.001 | `rundll32.exe comsvcs.dll MiniDump` |
| Defense Evasion | Impair Defenses | T1562 | `Set-MpPreference -DisableRealtimeMonitoring $true` |
| Defense Evasion | Clear Windows Event Logs | T1070.001 | Event ID 1102 (the original alert) |
| Lateral Movement | Remote Services (SMB) | T1021 | `net use \\target\C$ /user:admin` |
| Collection | Data from Local System | T1005 | `xcopy "C:\Users\*\Documents\*.docx" C:\Temp\staging` |
| Command & Control | Application Layer Protocol | T1071 | Beacon to 192.0.2.100:443 / `update-service-cdn.xyz` |
| Impact | Data Encrypted for Impact | T1486 | `vssadmin.exe delete shadows /all /quiet` (ransomware precursor) |

---

## Scope — affected assets

The campaign spread well beyond the initial host. Confirmed affected:

| Host | Account(s) | Notable activity |
|---|---|---|
| win11a | mirage | Patient zero — full chain |
| win11b | ceo | Execution, tamper (**high-value target**) |
| win11c | spatel | Malicious PowerShell |
| win11d | psharma | Lateral movement, tamper |
| dev-ws01 | aturner | Execution, ransomware behavior |
| it-ws01 | jliu | LSASS dumping, staging, execution |
| srv-file01 | jliu | LSASS dumping, lateral movement |
| srv-dc01 | jliu | Ransomware behavior (**domain controller — critical**) |

At least 6 user accounts and 8 machines involved, including a domain controller and the CEO's workstation.

---

## Indicators of Compromise (IOCs)

- **C2 IP:** 192.0.2.100 (port 443, outbound)
- **C2 domain:** update-service-cdn.xyz
- **Malicious payload:** report.exe — SHA256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- **Persistence artifact:** `C:\Users\mirage\AppData\Local\Temp\svchost_update.exe` (Run key value `UpdateSvc`)
- **Encoded PowerShell:** `powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==` → `Invoke-WebRequest`

---

## Verdict

**True positive — confirmed multi-stage ransomware campaign.**

The original "log cleared" alert is one anti-forensics action within a large intrusion. Severity Medium was correct for the single alert in isolation, but the correlated picture is Critical: credential theft, lateral movement to a DC, data staging, and ransomware impact behaviors.

**Analyst note on data quality:** several endpoint detections carry a `false_positive` disposition in the raw feed despite being clearly malicious (e.g., LSASS dumping, shadow-copy deletion). In a production environment these dispositions would be individually validated rather than trusted — mislabeled dispositions are a real tuning and process risk.

---

## Response actions

Immediate (containment):
- Isolate all affected hosts, prioritizing srv-dc01 (domain controller) and the CEO workstation.
- Disable/reset compromised accounts: mirage, jliu, spatel, aturner, psharma, ceo — assume all credentials on affected hosts are compromised due to LSASS dumping.
- Block C2 indicators at the firewall/proxy: 192.0.2.100 and update-service-cdn.xyz.

Eradication & recovery:
- Remove persistence (Run key `UpdateSvc`, `svchost_update.exe`).
- Hunt for report.exe (hash above) across the estate; quarantine.
- Validate shadow copies / backups given `vssadmin delete shadows` — restore from known-good offline backups if encryption occurred.

Follow-up:
- Force org-wide password reset; review privileged accounts on the DC.
- Investigate the originating phishing email in MailGuard365; purge from other mailboxes.

---

## Lessons / detection tuning

- **A single low/medium alert can be the visible tip of a critical incident.** The log-clear only became meaningful after pivoting on entities and correlating across sources. Reinforces always checking what preceded a defense-evasion alert.
- **Correlation across data sources is essential.** Endpoint, email, identity, and cloud each held one piece; only together did the ransomware campaign become clear.
- **Detection opportunity:** LSASS dumping via `rundll32 comsvcs.dll MiniDump` and `vssadmin delete shadows` are high-fidelity behaviors — worth ensuring dedicated, high-severity analytics rules exist for both so they don't rely on correlation to surface.
- **Disposition hygiene:** the mislabeled `false_positive` detections show why analysts must validate rather than trust vendor dispositions.
