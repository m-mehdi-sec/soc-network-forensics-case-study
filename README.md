# SOC Network Forensics Case Study

## Overview

This repository documents a simulated SOC investigation based on a network forensics and incident response scenario.

The case starts with a suspicious PowerShell alert from Wazuh on a Windows client in the Support department. The investigation follows the evidence across multiple log sources, including Windows Security Events, DNS logs, firewall logs, IDS alerts, Wireshark-style packet records, Wazuh File Integrity Monitoring events, and file server access logs.

The main goal of this case study is to show how a SOC analyst can move from a single alert to a full incident timeline by correlating different evidence sources.

This is not a tool installation lab. It is a defensive analysis case focused on investigation logic, evidence correlation, incident classification, containment, and lessons learned.

---

## Scenario

A SOC team at a fictional company receives a Wazuh alert about suspicious PowerShell execution on a Windows endpoint.

Affected endpoint:

~~~text
Hostname: WIN11-SUPPORT-04
IP address: 10.10.40.24
User: NORDSECURE\support.johan
Department: Support
~~~

The suspicious activity begins after the user receives and opens a macro-enabled Word document from an external email.

The investigation indicates a likely phishing-based attack chain:

~~~text
Phishing email
↓
Macro-enabled Word document
↓
WINWORD.EXE starts PowerShell
↓
Encoded PowerShell command
↓
External DNS and HTTPS communication
↓
Suspicious files created
↓
Persistence attempt
↓
SMB access to file server
↓
Attempted access to restricted HR and Finance shares
~~~

---

## Network Context

The fictional environment is segmented into multiple internal networks.

| Network | Purpose |
|--------|---------|
| 10.10.10.0/24 | HR |
| 10.10.20.0/24 | Finance |
| 10.10.30.0/24 | Development |
| 10.10.40.0/24 | Support |
| 10.10.50.0/24 | Servers |
| 10.10.60.0/24 | Management |
| 10.10.70.0/24 | Guest |
| 10.10.80.0/24 | VPN |
| 10.10.90.0/24 | SIEM / Monitoring |

Important systems:

| Host | IP Address | Purpose |
|------|------------|---------|
| DC01 | 10.10.50.10 | Active Directory / DNS |
| FILE01 | 10.10.50.20 | File Server |
| TICKET01 | 10.10.50.30 | Ticketing System |
| SIEM01 | 10.10.90.10 | Wazuh / SIEM |
| FW01 | 10.10.60.1 | Firewall |
| VPN01 | 10.10.80.1 | VPN |

---

## Investigation Goal

The goal of the investigation is to answer the following questions:

- What happened?
- When did the activity start?
- Which user and endpoint were affected?
- What was the likely initial attack vector?
- Which evidence supports the conclusion?
- Which indicators of compromise were found?
- Was persistence established?
- Was there any sign of lateral movement or file access?
- Was data exfiltration confirmed?
- What containment actions should be taken?
- How could the incident have been prevented?

---

## Evidence Sources

This case study uses several evidence sources to build a complete picture of the incident.

| Evidence Source | What It Shows |
|----------------|---------------|
| Wazuh Alert | Suspicious PowerShell execution |
| Email Gateway Log | Possible phishing email and malicious attachment |
| Windows Process Logs | WINWORD.EXE spawning PowerShell |
| DNS Logs | Suspicious domain lookups |
| Firewall Logs | External HTTPS connections |
| Wireshark-style Records | DNS, TCP handshake, and TLS metadata |
| Wazuh FIM | Suspicious files created on disk |
| Windows Security Events | Logons, process creation, and scheduled task creation |
| IDS Alerts | Malware-like network behavior |
| File Server Logs | SMB session and attempted access to shared folders |

The key lesson is that no single tool gives the full picture. The incident becomes clear only when multiple evidence sources are correlated.

---

## Initial Alert

The first alert came from Wazuh.

~~~text
Time: 2026-05-20 09:14:33
Agent: WIN11-SUPPORT-04
Agent IP: 10.10.40.24
Rule Level: 10
Rule Description: Suspicious PowerShell execution detected
User: NORDSECURE\support.johan
Process: powershell.exe
Parent Process: WINWORD.EXE
CommandLine: powershell.exe -ExecutionPolicy Bypass -EncodedCommand ...
MITRE Tactic: Execution
MITRE Technique: T1059 – Command and Scripting Interpreter
~~~

This is suspicious because Microsoft Word normally should not start PowerShell. This behavior is commonly associated with phishing attacks where a malicious Office document uses macros or embedded code to execute commands.

The following indicators make the alert high risk:

~~~text
WINWORD.EXE → powershell.exe
ExecutionPolicy Bypass
EncodedCommand
External network connections
Suspicious files created
Persistence attempt
~~~

---

## Summary of Findings

The investigation indicates that the affected user opened a macro-enabled Word document delivered through email.

Shortly after the document was opened, Microsoft Word started PowerShell with an encoded command and execution policy bypass. The endpoint then performed DNS lookups for suspicious domains and established HTTPS connections to external IP addresses.

Wazuh File Integrity Monitoring detected suspicious files created on disk, and Windows Security Events showed a scheduled task being created. This indicates a persistence attempt.

The endpoint also established an SMB session with the internal file server and accessed files in the Support share. Attempts to access HR and Finance resources were denied, which shows that least privilege helped limit the impact.

---

## High-Level Timeline

| Time | Event | Source |
|------|-------|--------|
| 09:08:44 | Phishing email delivered | Email Gateway |
| 09:10:18 | User opened macro-enabled Word document | Windows Process Log |
| 09:10:25 | WINWORD.EXE started PowerShell | Windows Process Log / Wazuh |
| 09:10:30 | DNS query to suspicious domain | DNS Log |
| 09:10:31 | HTTPS connection to external IP | Firewall / Wireshark |
| 09:10:43 | Suspicious script created | Wazuh FIM |
| 09:10:48 | Suspicious executable created | Wazuh FIM |
| 09:11:10 | Scheduled task created | Windows Security Event |
| 09:13:44 | SMB session to FILE01 | File Server Log |
| 09:14:33 | Wazuh alert generated | Wazuh / SIEM |

A more detailed timeline is available in [timeline.md](timeline.md).

---

## MITRE ATT&CK Summary

| Tactic | Technique | Evidence |
|--------|-----------|----------|
| Initial Access | Phishing | Email with macro-enabled Word attachment |
| Execution | PowerShell | WINWORD.EXE starts powershell.exe |
| Defense Evasion | Encoded / Obfuscated Command | EncodedCommand |
| Persistence | Scheduled Task / Startup Folder | WindowsUpdateCheck and updater.lnk |
| Command and Control | Web Protocols | HTTPS connections to suspicious IPs |
| Discovery | File and Directory Discovery | Attempts to access HR and Finance shares |
| Lateral Movement | SMB | SMB session to FILE01 |
| Collection | Data from Network Share | Multiple files read from Support share |

More details are available in [attack-classification.md](attack-classification.md).

---

## Indicators of Compromise

Example IoCs identified during the investigation:

~~~text
185.44.12.90
185.44.12.91
91.203.18.77

update-cdn.cloud-sync.example
api.drop-storage.example
windows-update-check.example

C:\Users\Public\update.ps1
C:\Users\Public\client.exe
C:\Users\support.johan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\updater.lnk

Scheduled Task: \WindowsUpdateCheck
Attachment: Faktura_45892.docm
~~~

The full IoC list is available in [iocs.md](iocs.md).

---

## Incident Severity

The incident should be treated as high severity.

Main reasons:

- Suspicious PowerShell execution from Word
- Encoded PowerShell command
- External HTTPS communication
- Suspicious files created on disk
- Persistence attempt
- SMB access to internal file server
- Attempted access to restricted HR and Finance shares
- Multiple log sources confirm suspicious behavior

Even though data exfiltration was not confirmed, the combination of execution, persistence, external communication, and internal file access makes this a serious incident.

---

## Containment Actions

Recommended immediate actions:

~~~text
Isolate WIN11-SUPPORT-04 from the network
Temporarily disable NORDSECURE\support.johan
Block suspicious IP addresses
Block suspicious domains
Preserve Wazuh, Windows, DNS, firewall, IDS, and file server logs
Collect suspicious files for further analysis
Search the environment for the same IoCs
~~~

Actions to avoid before evidence collection:

~~~text
Do not delete suspicious files immediately
Do not reboot the endpoint immediately
Do not wipe the system before collecting evidence
~~~

This is important because deleting files or rebooting the endpoint can destroy forensic evidence.

More details are available in [incident-report.md](incident-report.md).

---

## Repository Structure

~~~text
soc-network-forensics-case-study/
│
├── README.md
├── incident-report.md
├── timeline.md
├── iocs.md
├── attack-classification.md
├── lessons-learned.md
└── screenshots/
~~~

---

## Documentation

- [Incident Report](incident-report.md)
- [Timeline](timeline.md)
- [Indicators of Compromise](iocs.md)
- [Attack Classification](attack-classification.md)
- [Lessons Learned](lessons-learned.md)

---

## Lessons Learned

This case shows that a single alert is only the beginning of an investigation.

Wazuh detected suspicious PowerShell activity, but that alert alone did not explain the full incident. The full picture became clear only after correlating multiple evidence sources.

Main lessons:

- One tool is not enough.
- One alert does not tell the full story.
- A timeline is critical in incident response.
- DNS and firewall logs are very valuable.
- Wireshark metadata is useful even when traffic is encrypted.
- File Integrity Monitoring can reveal dropped files.
- Windows events can reveal persistence.
- IDS can confirm malware-like network behavior.
- File server logs can show post-compromise activity.
- Least privilege can reduce the impact of an attack.

The most important takeaway:

~~~text
An alert tells you that something may be wrong.
A timeline helps you understand what actually happened.
Correlation across multiple log sources turns alerts into evidence.
~~~

---

## Disclaimer

This repository is based on a simulated and fictional SOC case study created for defensive cybersecurity learning.

No real company data, real user data, malware samples, or live attack infrastructure are included.

The purpose of this repository is to document defensive analysis, incident response thinking, and network forensics methodology.
