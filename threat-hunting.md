# Threat Hunting

## Overview

This document describes follow-up threat hunting activities after the simulated SOC incident.

The purpose is to check whether the same indicators or similar behavior exist on other systems in the environment.

The investigation should not stop at the first affected endpoint. After confirming suspicious activity on `WIN11-SUPPORT-04`, the next step is to search for related activity across the rest of the network.

---

## Hunting Goal

The main goal is to answer:

```text
Was this activity limited to one endpoint,
or are there signs of the same attack elsewhere in the environment?
```

---

## Hunting Hypotheses

| Hunting Hypothesis | Data Source | What to Look For |
|-------------------|------------|------------------|
| Other clients contacted the same external IPs | Firewall logs / IDS logs | Connections to `185.44.12.90`, `185.44.12.91`, or `91.203.18.77` |
| Other clients queried the same suspicious domains | DNS logs | Queries for `update-cdn.cloud-sync.example`, `api.drop-storage.example`, or `windows-update-check.example` |
| Other endpoints created the same suspicious files | Wazuh FIM / EDR | `update.ps1`, `client.exe`, or similar files in `C:\Users\Public\` |
| Other users received the same phishing email | Email gateway logs | Same sender, subject, attachment name, or attachment hash |
| Other endpoints have similar persistence | Windows Event Logs / Wazuh | Scheduled tasks similar to `WindowsUpdateCheck` |
| The affected user logged in elsewhere | Windows Security Events / AD logs | Logon activity for `NORDSECURE\support.johan` on other systems |
| Other Office processes spawned PowerShell | Windows Process Logs / SIEM | `WINWORD.EXE`, `EXCEL.EXE`, or `OUTLOOK.EXE` starting `powershell.exe` |

---

## Priority Hunting Areas

### 1. Network Connections

Search firewall and IDS logs for the suspicious external IP addresses.

```text
185.44.12.90
185.44.12.91
91.203.18.77
```

Focus on:

```text
Source IP
Destination IP
Destination port
Timestamp
Bytes sent
Bytes received
Firewall action
IDS alert name
```

This can show whether more internal systems communicated with the same infrastructure.

---

### 2. DNS Activity

Search DNS logs for suspicious domains.

```text
update-cdn.cloud-sync.example
api.drop-storage.example
windows-update-check.example
```

Focus on:

```text
Client IP
Query name
Response IP
Timestamp
Number of repeated queries
```

If several clients queried the same domains, the incident may be larger than one endpoint.

---

### 3. Suspicious Files

Search endpoint telemetry or Wazuh FIM events for these files:

```text
C:\Users\Public\update.ps1
C:\Users\Public\client.exe
```

Also search for similar patterns:

```text
C:\Users\Public\*.ps1
C:\Users\Public\*.exe
```

The folder `C:\Users\Public\` is interesting because attackers often use writable locations to drop files.

---

### 4. Suspicious Process Chains

Search for Office applications starting PowerShell.

Examples:

```text
WINWORD.EXE → powershell.exe
EXCEL.EXE → powershell.exe
OUTLOOK.EXE → powershell.exe
```

Also look for command-line flags such as:

```text
-ExecutionPolicy Bypass
-EncodedCommand
-NoProfile
-WindowStyle Hidden
```

These patterns can indicate malicious scripting activity.

---

### 5. Persistence Hunting

Search for scheduled tasks and Startup folder changes.

Important indicators:

```text
Scheduled Task: WindowsUpdateCheck
Startup Shortcut: updater.lnk
```

Look for:

```text
Event ID 4698
New scheduled tasks
Startup folder modifications
Shortcuts pointing to suspicious executables
Tasks running from user-writable directories
```

Persistence hunting is important because attackers often try to survive reboot or logoff.

---

### 6. Email Hunting

Search the email gateway for similar messages.

Look for:

```text
Sender: faktura@transport-service-billing.com
Subject: Obetald transportfaktura – åtgärd krävs
Attachment: Faktura_45892.docm
Attachment SHA256:
9f2c1e8b8d77aa35f4e6a9bd9981120f2d9913aa0e1d91c6b554a88a0c4a1991
```

Questions to answer:

```text
Did more users receive the same email?
Did anyone else open the attachment?
Was the attachment blocked for some users?
Did the email bypass SPF, DKIM, or DMARC checks?
```

---

## Example Hunting Table

| Question | Data Source | Priority |
|---------|------------|----------|
| Did other hosts contact `185.44.12.90`? | Firewall logs | High |
| Did other hosts query `update-cdn.cloud-sync.example`? | DNS logs | High |
| Are there more copies of `client.exe`? | Wazuh FIM / EDR | High |
| Did more users receive `Faktura_45892.docm`? | Email gateway | High |
| Are there more scheduled tasks named like `WindowsUpdateCheck`? | Windows Event Logs | Medium |
| Did `support.johan` log in to other systems? | AD / Windows logs | Medium |
| Did other Office apps spawn PowerShell? | Process logs / SIEM | High |

---

## Expected Outcomes

The threat hunting process should help determine whether:

```text
The incident was isolated to one endpoint
More users received the same phishing email
More endpoints contacted the same external infrastructure
The same payload exists on other systems
The attacker attempted to move laterally
The affected account was used elsewhere
```

---

## Hunting Result Interpretation

### If No Additional Matches Are Found

If no other systems show the same indicators, the incident may be limited to `WIN11-SUPPORT-04`.

Recommended next steps:

```text
Continue monitoring
Complete endpoint recovery
Reset affected user credentials
Keep IoCs blocked
Document the incident
```

### If Additional Matches Are Found

If other systems show the same indicators, the incident scope increases.

Recommended next steps:

```text
Isolate additional affected systems
Expand log collection
Review email exposure
Check for shared credentials
Escalate incident severity
Start broader incident response process
```

---

## Conclusion

Threat hunting is important because a confirmed incident on one endpoint may be only part of a larger attack.

In this case, the most important hunting focus areas are:

```text
External IP connections
Suspicious DNS queries
Office spawning PowerShell
Dropped files in C:\Users\Public\
Scheduled task persistence
Same phishing email across users
Affected user logons on other systems
```

The goal is to move from reactive alert analysis to proactive investigation across the environment.
