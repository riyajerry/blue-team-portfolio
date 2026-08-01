# Threat Actor Profile — APT28 (Fancy Bear)
### GRU Unit 26165 | Russian Military Intelligence
**Profile Reference:** TAP-2026-APT28 | **Classification:** TLP:WHITE

| Field | Details |
|-------|---------|
| **Also Known As** | Fancy Bear, Sofacy, Sednit, STRONTIUM, Forest Blizzard, Pawn Storm, FROZENLAKE |
| **Attribution** | Russian GRU — 85th GTsSS, Military Unit 26165 |
| **Active Since** | 2004 (publicly reported from 2007) |
| **Motivation** | Espionage, intelligence collection, influence operations — geopolitical, not financial |
| **Threat Level** | 🔴 CRITICAL |
| **MITRE Group ID** | [G0007](https://attack.mitre.org/groups/G0007) |
| **Navigator Layer** | [apt28-navigator-layer.json](apt28-navigator-layer.json) |

---

## 1. Who Is APT28?

APT28 is one of the most sophisticated and long-running state-sponsored cyber espionage groups in the world. Widely attributed to Russia's Main Directorate of the General Staff (GRU), specifically Unit 26165, the group has been conducting cyber operations in support of Russian military and strategic intelligence objectives since at least 2004.

Unlike financially motivated threat actors, APT28 operates exclusively in service of geopolitical goals — collecting intelligence, stealing sensitive military and political information, and conducting influence operations that align with Russia's strategic interests. They are patient, resourceful, and highly adaptive, having evolved their tooling and techniques significantly over two decades of operation.

In 2018, the US Department of Justice indicted five GRU Unit 26165 officers for cyber operations conducted between 2014 and 2018, targeting the World Anti-Doping Agency (WADA), the Organisation for the Prohibition of Chemical Weapons (OPCW), and a US nuclear facility — providing the clearest public confirmation of attribution to date.

As of 2025, APT28 remains highly active, with ongoing campaigns targeting European entities, NATO member organisations, and organisations involved in supporting Ukraine.

---

## 2. Who Do They Target?

| Sector | Why APT28 Targets Them |
|--------|------------------------|
| Government agencies | Political intelligence, diplomatic communications, policy decisions |
| Military & defence contractors | Weapons systems, operational planning, defence technology |
| Political parties & elections | Influence operations — leaking compromising material to affect outcomes |
| NATO member organisations | Alliance intelligence, collective defence planning |
| Critical infrastructure | Energy, telecommunications — strategic disruption capability |
| Ukraine-support organisations | Aid logistics, military support tracking |
| Think tanks & NGOs | Policy research, organisations critical of the Russian government |
| Media organisations | Journalist sources, influence over public narrative |

---

## 3. Top 10 TTPs (MITRE ATT&CK)

| # | Technique ID | Technique Name | Tactic | How APT28 Uses It |
|---|-------------|----------------|--------|-------------------|
| 1 | T1566.001 | Spearphishing Attachment | Initial Access | Targeted emails with malicious Office documents or PDFs disguised as legitimate communications |
| 2 | T1110.003 | Password Spraying | Credential Access | Tries a small number of common passwords across many accounts — avoids lockouts |
| 3 | T1557 | Adversary-in-the-Middle | Credential Access | Phishing proxies intercept MFA tokens and session cookies — bypasses MFA entirely |
| 4 | T1078 | Valid Accounts | Defence Evasion | Uses stolen credentials to authenticate as legitimate users — blends with normal traffic |
| 5 | T1053.005 | Scheduled Task | Persistence | Creates scheduled tasks to maintain access and execute payloads after reboots |
| 6 | T1071.001 | Web Protocols C2 | Command & Control | Uses HTTP/HTTPS for C2 to blend with normal web traffic |
| 7 | T1083 | File & Directory Discovery | Discovery | Enumerates file systems to locate sensitive documents and credentials |
| 8 | T1048 | Exfiltration Over Alternative Protocol | Exfiltration | Exfiltrates via FTP/DNS to evade data loss prevention tools |
| 9 | T1027 | Obfuscated Files | Defence Evasion | Encodes and obfuscates payloads to evade antivirus and EDR |
| 10 | T1021.001 | Remote Desktop Protocol | Lateral Movement | Uses RDP with stolen credentials to move laterally across networks |

---

## 4. Notable & Unique Techniques

### Nearest Neighbour Attack
Documented in November 2024 — APT28 compromised a building adjacent to the target, then pivoted through their Wi-Fi network to reach the intended victim. This demonstrates their willingness to conduct close-access operations and use indirect paths when direct network access is blocked.

### Adversary-in-the-Middle (AiTM) Phishing
APT28 operates phishing pages that act as transparent proxies — capturing authenticated session tokens in real time. This bypasses MFA entirely, since they steal the authenticated session rather than the password.

### Living off the Land
APT28 heavily favours built-in Windows tools — PowerShell, WMI, scheduled tasks, RDP — over custom malware. Detection requires behavioural context, not just tool identification.

---

## 5. Detection Opportunities

| TTP | What to Look For | Splunk SPL | EventCode | Priority |
|-----|-----------------|------------|-----------|----------|
| Password Spraying | Many failed logins across accounts from same source | `index=main EventCode=4625 \| stats count by src, Account_Name \| where count > 5` | 4625 | 🔴 Critical |
| Scheduled Task Persistence | New scheduled task created outside business hours | `index=main EventCode=4698` | 4698 | 🟠 High |
| Lateral Movement via RDP | Successful Type 10 logon from unexpected IP | `index=main EventCode=4624 Logon_Type=10` | 4624 | 🟠 High |
| Suspicious Process Spawning | PowerShell/cmd spawned by unusual parent | `EventCode=4688 parent spawning powershell/cmd` | 4688 | 🟠 High |
| Valid Account Abuse | Logins at unusual hours or geolocations | `index=main EventCode=4624 Logon_Type=3` | 4624 | 🟡 Medium |

> All five SPL queries are variants of detection rules built and validated in the home lab SIEM in Project 1 of this portfolio.

---

## 6. Full MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Initial Access | T1566.001 / T1566.002 | Spearphishing Attachment / Link |
| Initial Access | T1078 | Valid Accounts |
| Execution | T1059.001 | PowerShell |
| Execution | T1059.003 | Windows Command Shell |
| Persistence | T1053.005 | Scheduled Task |
| Persistence | T1547.001 | Registry Run Keys |
| Privilege Escalation | T1134 | Access Token Manipulation |
| Defence Evasion | T1027 | Obfuscated Files |
| Defence Evasion | T1078 | Valid Accounts |
| Credential Access | T1110.003 | Password Spraying |
| Credential Access | T1557 | Adversary-in-the-Middle |
| Discovery | T1083 | File & Directory Discovery |
| Discovery | T1018 | Remote System Discovery |
| Lateral Movement | T1021.001 | Remote Desktop Protocol |
| Lateral Movement | T1021.002 | SMB/Admin Shares |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol |
| Command & Control | T1071.001 | Web Protocols |

---

## 7. Defensive Recommendations

### Immediately actionable
- Deploy phishing-resistant MFA (hardware tokens or passkeys) — standard TOTP MFA is bypassed by APT28's AiTM technique
- Enable audit logging for all authentication events (EventCodes 4624, 4625, 4648) and forward to a SIEM
- Block known APT28 infrastructure at the firewall — CISA advisories publish current IOCs
- Monitor for password spraying patterns (>5 failures across accounts from same source IP)

### Within 30 days
- Deploy endpoint detection with parent-child process monitoring — catches PowerShell spawned by unusual parents
- Implement network segmentation to limit lateral movement — RDP should not be accessible between all endpoints
- Enable scheduled task creation alerts (EventCode 4698) in your SIEM
- Conduct phishing awareness training focused on credential harvesting pages

### Strategic
- Assume stolen credentials are in use — monitor for logins at unusual hours or locations even when credentials appear valid
- Treat MFA as a layer, not a solution — AiTM attacks mean MFA is necessary but not sufficient
- Review Wi-Fi network security and physical perimeter — the Nearest Neighbour attack exploits adjacent networks

---

## 8. Key Takeaways for SOC Analysts

- **MFA is not a silver bullet.** APT28's AiTM technique defeats standard MFA. Only FIDO2/passkey-based MFA reliably mitigates this.
- **Living off the land makes them hard to catch.** Detection requires behavioural context — not what tools are present, but how and when they are used.
- **The Nearest Neighbour attack redefines the perimeter.** Network security cannot be considered in isolation from the physical environment.
- **Dwell time is the window.** APT28 is patient. Early detection via SIEM alerting is the difference between catching an intrusion early and discovering it months later.

---

*Sources: MITRE ATT&CK G0007 | CISA Advisories | The DFIR Report | SOCRadar APT28 Profile*
*Analyst: Riya | MSc Cybersecurity, MTU Cork | Profile Reference: TAP-2026-APT28*
