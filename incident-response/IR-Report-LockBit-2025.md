# Incident Response Report — IR-2025-001
## Cobalt Strike & LockBit Ransomware Intrusion

| Field | Details |
|-------|---------|
| **Analyst** | Riya — MSc Cybersecurity, MTU Cork |
| **Report Date** | June 2026 |
| **Incident Type** | Ransomware — LockBit 3.0 |
| **Threat Actor** | LockBit Ransomware Group (suspected affiliate) |
| **Dwell Time** | 11 days (initial access to ransomware deployment) |
| **Severity** | 🔴 CRITICAL |
| **Source** | The DFIR Report, January 2025 — thedfirreport.com |

---

## 1. Executive Summary

This report documents the analysis of a real-world ransomware intrusion attributed to a LockBit affiliate, originally published by The DFIR Report in January 2025. The incident demonstrates a sophisticated, multi-stage attack spanning **11 days** from initial access to full ransomware deployment across an enterprise network.

The attacker gained initial access through a **trojanized installer** — a file named `setup_wm.exe` disguised as a Windows Media Configuration Utility, downloaded from a malicious website. Over the following 11 days, the attacker deployed Cobalt Strike for command and control, moved laterally across the network using stolen credentials, exfiltrated data using Rclone to Mega.io, and ultimately deployed LockBit 3.0 ransomware across all reachable Windows systems.

This is a textbook example of **double extortion ransomware** — the attacker stole data before encrypting it, meaning the victim faced both the threat of data loss and public exposure of sensitive information.

| Metric | Value |
|--------|-------|
| Dwell Time | 11 days |
| Ransomware Family | LockBit 3.0 |
| Attacker Tools Used | 10+ |
| Extortion Method | Double extortion (encrypt + threaten to publish) |

---

## 2. Incident Timeline

| Day | Phase | Activity | MITRE Technique |
|-----|-------|----------|-----------------|
| Day 0 | Initial Access | User downloads and executes `setup_wm.exe` — a trojanized installer disguised as Windows Media Configuration Utility from `accessservicesonline[.]com` | T1566.002, T1204.002 |
| Day 0 | Execution & C2 | Cobalt Strike Beacon deployed. Attacker establishes persistent Command & Control channel to remote infrastructure | T1059.003, T1071.001 |
| Day 1–2 | Persistence | SystemBC and GhostSOCKS deployed as SOCKS5 proxies. Scheduled Tasks and Registry Run Keys created to survive reboots | T1053.005, T1547.001 |
| Day 2–5 | Discovery | Attacker runs `nltest` to find domain controllers, Seatbelt for host enumeration, SharpView for AD reconnaissance, and a custom `check.exe` recon tool | T1018, T1069, T1087 |
| Day 5–9 | Lateral Movement | Attacker moves across the network using PsExec, WMI, RDP, and SMB. Stolen credentials used to authenticate as legitimate users on other machines | T1021.002, T1021.001, T1047 |
| Day 9–10 | Exfiltration | Rclone used to exfiltrate sensitive data to Mega.io via FTP. Data stolen before encryption begins — the first step of double extortion | T1048, T1567.002 |
| Day 11 | Impact | LockBit 3.0 deployed across all reachable Windows systems via PsExec, WMI, and BITSAdmin. Defender disabled, Volume Shadow Copies deleted, ransom note dropped | T1486, T1490, T1562.001 |

---

## 3. Attacker Tools & Techniques

| Tool | Category | MITRE Technique | Purpose |
|------|----------|-----------------|---------|
| Cobalt Strike | C2 Framework | T1071.001 | Primary command and control — attacker's remote access tool |
| SystemBC | Proxy Malware | T1090.002 | SOCKS5 proxy to tunnel traffic and hide C2 communications |
| GhostSOCKS | Proxy Malware | T1090.002 | Additional SOCKS proxy for redundant C2 channels |
| nltest | Discovery (built-in) | T1018 | Native Windows tool used to enumerate domain controllers |
| Seatbelt | Recon Tool | T1082 | Host enumeration — OS info, installed software, credentials |
| SharpView | AD Recon | T1087.002 | Active Directory reconnaissance — users, groups, GPOs |
| PsExec | Lateral Movement | T1021.002 | Remote execution on other machines using stolen credentials |
| WMI | Lateral Movement (built-in) | T1047 | Native Windows tool abused for stealthy remote execution |
| Rclone | Exfiltration | T1567.002 | Data theft to Mega.io cloud storage before encryption |
| LockBit 3.0 | Ransomware | T1486 | Final payload — encrypts all reachable Windows file systems |

---

## 4. Indicators of Compromise (IOCs)

| Type | Indicator | Context |
|------|-----------|---------|
| Domain | `accessservicesonline[.]com` | Malicious download site — initial access vector |
| Filename | `setup_wm.exe` | Trojanized installer disguised as Windows Media tool |
| Tool | `rclone.exe` | Legitimate tool abused for data exfiltration to Mega.io |
| Destination | `mega[.]io / Mega.nz FTP endpoints` | Cloud storage used for stolen data staging |
| Process | `powershell.exe` spawning `schtasks.exe` | Persistence mechanism — detectable via EventCode 4698 |
| Registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Registry Run Key — malware auto-starts on login |
| Command | `vssadmin delete shadows /all /quiet` | Volume Shadow Copy deletion — removes Windows backups |

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observable |
|--------|-------------|----------------|------------|
| Initial Access | T1204.002 | Malicious File | `setup_wm.exe` execution |
| Execution | T1059.003 | Windows Command Shell | `cmd.exe` spawned by beacon |
| Persistence | T1053.005 | Scheduled Task | EventCode 4698 — task created |
| Persistence | T1547.001 | Registry Run Keys | HKCU Run key modified |
| Defence Evasion | T1562.001 | Disable Security Tools | Defender GPO modified |
| Credential Access | T1003 | OS Credential Dumping | Credentials extracted from memory |
| Discovery | T1018 | Remote System Discovery | `nltest /dclist` |
| Lateral Movement | T1021.002 | SMB/Admin Shares | PsExec over SMB |
| Lateral Movement | T1047 | WMI Execution | WMI remote process creation |
| Exfiltration | T1567.002 | Exfil to Cloud Storage | Rclone → Mega.io |
| Impact | T1486 | Data Encrypted for Impact | LockBit 3.0 deployed |
| Impact | T1490 | Inhibit System Recovery | VSS copies deleted |

---

## 6. Detection Opportunities

The following detections, mapped to the SIEM rules built in this portfolio's home lab, would have identified attacker activity at multiple stages of the kill chain:

| Attack Stage | Detection Rule | Splunk SPL | EventCode | Severity |
|-------------|----------------|------------|-----------|----------|
| Persistence | Scheduled task created | `index=main EventCode=4698` | 4698 | 🟠 High |
| Execution | PowerShell spawning schtasks | `EventCode=4688 parent=powershell child=schtasks` | 4688 | 🔴 Critical |
| Credential Access | Brute force — >5 failed logins | `EventCode=4625 count > 5` | 4625 | 🟠 High |
| Lateral Movement | Admin login from unexpected IP | `EventCode=4624 LogonType=3` | 4624 | 🟡 Medium |
| Defence Evasion | Scheduled task disabled/modified | `EventCode=4701 OR EventCode=4702` | 4701/4702 | 🟠 High |

> All five detection rules above are operational in the home SIEM lab documented in Project 1 of this portfolio, validated against real simulated attack traffic using Atomic Red Team.

---

## 7. Remediation Recommendations

| # | Recommendation | Priority | Timeframe |
|---|---------------|----------|-----------|
| 1 | Isolate all affected systems and revoke all active credentials immediately. Assume all domain credentials are compromised | 🔴 Critical | 24 hours |
| 2 | Restore from clean backups predating Day 0. Verify backup integrity before restoration | 🔴 Critical | 24–48 hrs |
| 3 | Block `accessservicesonline[.]com` and Mega.io FTP endpoints at the firewall | 🔴 Critical | 24 hours |
| 4 | Deploy application allowlisting to prevent unauthorised tools (Rclone, PsExec, Seatbelt) from executing | 🟠 High | 7 days |
| 5 | Implement MFA on all remote access (RDP, VPN) to prevent lateral movement using stolen credentials | 🟠 High | 7 days |
| 6 | Enable Windows audit policies for Process Creation (4688), Scheduled Tasks (4698), and Registry modifications (4657) across all endpoints | 🟠 High | 7 days |
| 7 | Deploy a SIEM with detection rules for patterns identified in Section 6. Prioritise scheduled task and parent-child process rules | 🟠 High | 30 days |
| 8 | Conduct user awareness training focused on trojanized installers and suspicious download sources | 🟡 Medium | 30 days |

---

## 8. Lessons Learned

### What the attacker did well
- Used a trojanized legitimate-looking installer to bypass user suspicion
- Blended in with native Windows tools (WMI, PsExec, schtasks) — Living off the Land
- Maintained multiple redundant C2 channels so losing one didn't end the intrusion
- Deleted Volume Shadow Copies before encrypting — removing the victim's easiest recovery option
- Stole data before encrypting — double extortion maximises leverage over the victim

### Where defenders could have intervened
- **Day 0** — Web filtering could have blocked the download from `accessservicesonline[.]com`
- **Day 0** — EDR with behavioural detection should have flagged `setup_wm.exe` on execution
- **Day 1–2** — Scheduled task creation (EventCode 4698) should have triggered a SIEM alert
- **Day 5–9** — PsExec lateral movement generates distinctive EventCode 4688 events — detectable with rules built in this lab
- **Day 9–10** — Rclone uploading large volumes of data to Mega.io should have triggered a DLP alert
- **Day 11** — Mass file encryption generates I/O spikes detectable by EDR tools

### Key takeaway
An 11-day dwell time means the attacker was visible in logs for nearly two weeks before causing damage. With the SIEM detection rules built in this portfolio, three attack techniques (scheduled task creation, suspicious process spawning, and brute force credential use) would have generated alerts within hours. **Early detection is the difference between a contained incident and a full ransomware deployment.**

---

## 9. Analyst Notes

This report was produced as part of a blue team cybersecurity portfolio, based on the publicly available incident report published by The DFIR Report (January 2025). The analysis demonstrates applied knowledge of:

- **Incident response methodology** — structured timeline, IOC extraction, and formal reporting
- **MITRE ATT&CK framework** — mapping real attacker behaviour to standardised technique IDs
- **SIEM detection engineering** — connecting observed attack techniques to Splunk SPL detection rules
- **Threat intelligence** — understanding attacker tooling, motivation, and double extortion economics

The detection rules referenced in Section 6 are operational in the home lab SIEM environment documented in Project 1 of this portfolio. All three primary detections (EventCode 4698, 4688 parent-child, 4625 brute force) were validated against real simulated attack traffic generated using Atomic Red Team.

---

*Source: The DFIR Report, January 2025 | [thedfirreport.com](https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/)*  
*Case Reference: IR-2025-001 | Analyst: Riya, MSc Cybersecurity, MTU Cork*
