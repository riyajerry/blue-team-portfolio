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

*This portfolio is actively updated as I complete new projects.*
