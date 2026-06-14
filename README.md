# Blue Team Security Portfolio

**Name:** Riya Jerry  
**Degree:** MSc Cybersecurity — Munster Technological University Cork  
**Focus:** SOC Analysis · Threat Detection · Incident Response  
**Status:** Actively seeking junior SOC Analyst roles in Ireland  

---

## About this portfolio

This repository documents hands-on blue team projects built in a home lab environment.
Each project mirrors real SOC analyst workflows from configuring a SIEM and writing 
detection rules, to producing formal incident response reports.

Everything here was built from scratch on a home lab running VirtualBox on Windows 11,
with an Ubuntu Server SIEM host and a Windows 10 target machine.

---

## Projects

| # | Project | Status | Key Tools |
|---|---------|--------|-----------|
| 1 | [Home SIEM Lab — Splunk + Detection Rules](#project-1--home-siem-lab) | ✅ Complete | Splunk, Windows Event Logs, SPL |
| 2 | Incident Response Report | 🔄 In progress | MITRE ATT&CK, Any.run |
| 3 | Threat Actor Profile — APT28 | 🔄 In progress | MITRE Navigator, OSINT |

---

## Project 1 — Home SIEM Lab

### What I built
A home SIEM lab using Splunk Enterprise (free tier) to ingest and monitor 
Windows Event Logs in real time. The lab simulates a basic SOC monitoring environment 
with a log-generating Windows 10 endpoint and a dedicated Ubuntu Server SIEM host.

### Lab architecture
Windows 10 VM  →  Splunk Universal Forwarder  →  Ubuntu Server VM (Splunk Enterprise)
[Target machine]        [port 9997]                    [SIEM host — port 8000]

### What I did
- Configured VirtualBox with two VMs: Windows 10 (target) and Ubuntu 22.04 (SIEM)
- Installed Splunk Enterprise on Ubuntu and Splunk Universal Forwarder on Windows
- Forwarded Windows Security, System, and Application event logs to Splunk
- Confirmed real-time log ingestion using `index=main` searches
- Verified detection of EventCode 4624 (successful login) and 4625 (failed login)
- Deliberately generated failed login events to validate detection capability

### Key event codes monitored

| EventCode | Meaning | Why it matters |
|-----------|---------|----------------|
| 4624 | Successful logon | Baseline activity — spikes indicate brute force success |
| 4625 | Failed logon | Primary indicator of brute force or credential stuffing |
| 4688 | Process created | Detects suspicious process execution |
| 4720 | User account created | Common persistence technique |


### Screenshots

#### Splunk dashboard — logs flowing
![Splunk logs flowing](screenshots/splunk-logs-flowing.png)

#### EventCode 4625 — failed login detected
![Failed login detected](screenshots/eventcode-4625-detected.png)
---

## Tools & technologies

`Splunk Enterprise` `Splunk Universal Forwarder` `VirtualBox` `Ubuntu Server 22.04`  
`Windows 10` `Windows Event Logs` `SPL (Search Processing Language)` `MITRE ATT&CK`

---

## Lab environment

| Component | Details |
|-----------|---------|
| Host machine | Windows 11, 16GB RAM |
| Hypervisor | VirtualBox 7.x |
| SIEM host | Ubuntu Server 22.04 LTS — 4GB RAM, 2 vCPUs |
| Target machine | Windows 10 Pro — 4GB RAM, 2 vCPUs |
| Splunk version | Enterprise 9.x (free tier — 500MB/day) |

---
---

## Week 3–4 — Detection Rules & Dashboard

### What I built
Four SPL detection rules running as live alerts in Splunk, 
triggered by real attack simulations using Atomic Red Team. 
A SOC dashboard visualising all detections in one place.

### Attack simulations run

| Atomic Test | MITRE Technique | What it simulates |
|-------------|----------------|-------------------|
| T1053.005 | Scheduled Task | Attacker persistence after reboot |
| T1136.001 | Create Local User | Attacker creating backdoor account |
| T1547.001 | Registry Run Keys | Malware running on startup |

### Detection rules written

#### Rule 1 — Brute Force Login Detection
**EventCode:** 4625 — Failed logon  
**MITRE:** T1110 — Brute Force  
**Logic:** Counts failed logins per account. Fires when same 
account fails more than 5 times — indicates credential stuffing 
or password guessing attack.

```spl
index=main EventCode=4625 earliest=-60m
| stats count by Account_Name, ComputerName
| where count > 5
| table Account_Name, ComputerName, count
| sort -count
```

#### Rule 2 — Suspicious Process Creation
**EventCode:** 4688 — Process created  
**MITRE:** T1059 — Command and Scripting Interpreter  
**Logic:** Alerts when high-risk processes like powershell.exe 
or cmd.exe are spawned. These are normal processes but become 
suspicious when appearing unexpectedly or in volume.

```spl
index=main EventCode=4688
| eval process=lower(New_Process_Name)
| search process IN ("*powershell.exe*","*cmd.exe*",
  "*wscript.exe*","*mshta.exe*","*rundll32.exe*")
| table _time, ComputerName, Account_Name, 
  New_Process_Name, Creator_Process_Name
| sort -_time
```

#### Rule 3 — Suspicious Parent-Child Process Spawning
**EventCode:** 4688 — Process created  
**MITRE:** T1059.001 — PowerShell, T1566 — Phishing  
**Logic:** Detects shells or interpreters spawned by unusual 
parent processes. A key indicator of malicious Office macros, 
WMI abuse, or living-off-the-land attacks. Splunk's own 
processes are excluded to reduce false positives.

```spl
index=main EventCode=4688
| eval parent=lower(Creator_Process_Name)
| eval child=lower(New_Process_Name)
| search child IN ("*powershell.exe*","*cmd.exe*",
  "*wscript.exe*","*mshta.exe*","*rundll32.exe*","*schtasks.exe*")
| search parent IN ("*svchost.exe*","*schtasks.exe*",
  "*msiexec.exe*","*wmic.exe*","*powershell.exe*",
  "*winword.exe*","*excel.exe*","*outlook.exe*")
| where NOT match(parent,"splunk")
| where NOT match(child,"splunk")
| table _time, ComputerName, Account_Name,
  Creator_Process_Name, New_Process_Name
| sort -_time
```

#### Rule 4 — Scheduled Task Persistence Detection
**EventCode:** 4698 — Scheduled task created  
**MITRE:** T1053.005 — Scheduled Task  
**Logic:** Fires any time a scheduled task is created. 
Legitimate software rarely creates scheduled tasks silently — 
this is a high-confidence indicator of attacker persistence.

```spl
index=main (EventCode=4698 OR EventCode=4702)
| table _time, ComputerName, Account_Name, Message
| sort -_time
```

### Key finding — real suspicious activity detected
During testing, the following genuine suspicious behaviour 
was observed and caught by Rule 3:
- `svchost.exe` spawning `rundll32.exe` under user account `riya`
- `powershell.exe` spawning `schtasks.exe` three times in quick 
  succession — consistent with automated attacker tooling

### Screenshots

#### SOC dashboard — all detections in one view
![SOC Dashboard](screenshots/soc-dashboard.png)

#### Rule 3 — parent-child process detections
![Parent child process detection](screenshots/parent-child-detection.png)

#### Rule 4 — scheduled task persistence caught
![Scheduled task detection](screenshots/scheduled-task-detection.png)

### What I learned
- Windows audit policies are off by default — enabling them 
  is a critical first step in any SOC deployment
- Splunk's bucket and stats commands are the core of 
  threshold-based alerting
- Excluding known-good processes (like Splunk's own binaries) 
  from rules is essential to reduce false positive noise
- Real suspicious activity appeared during testing, 
  svchost spawning rundll32 under a user account is 
  genuinely worth investigating

*This portfolio is actively updated as I complete new projects.*
