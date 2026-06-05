# Attack Classification

## Overview

This document classifies the simulated SOC incident based on observed evidence and common attack phases.

The goal is to map the activity to a structured attack chain and show which phases are confirmed, partially supported, or not confirmed.

---

## Attack Chain Summary

The investigation indicates the following likely attack chain:

```text
Initial Access
↓
Execution
↓
Defense Evasion
↓
Command and Control
↓
File Creation
↓
Persistence
↓
Internal Access
↓
Discovery / Collection Attempt
```

---

## Attack Phase Classification

| Attack Phase | Status | Evidence |
|-------------|--------|----------|
| Initial Access | Confirmed | Phishing email with macro-enabled Word attachment |
| Execution | Confirmed | `WINWORD.EXE` started `powershell.exe` |
| Defense Evasion | Confirmed | PowerShell used `ExecutionPolicy Bypass` and `EncodedCommand` |
| Command and Control | Likely | HTTPS connections to suspicious external IP addresses |
| Persistence | Confirmed | Scheduled task and Startup shortcut observed |
| Credential Access | Not confirmed | No direct evidence of credential dumping or password theft |
| Discovery | Likely | Attempts to access HR and Finance shares |
| Lateral Movement | Partial | SMB session established to `FILE01` |
| Collection | Partial | Multiple files read from Support share |
| Exfiltration | Not confirmed | No clear proof that data was transferred out |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|--------|-----------|----------|
| Initial Access | Phishing | Email with `Faktura_45892.docm` |
| Execution | Command and Scripting Interpreter: PowerShell | `powershell.exe` launched by `WINWORD.EXE` |
| Defense Evasion | Obfuscated Files or Information | `EncodedCommand` |
| Defense Evasion | Impair Defenses / Policy Bypass | `ExecutionPolicy Bypass` |
| Command and Control | Web Protocols | HTTPS traffic to external IPs |
| Persistence | Scheduled Task / Job | `WindowsUpdateCheck` scheduled task |
| Persistence | Startup Folder | `updater.lnk` in Startup folder |
| Discovery | File and Directory Discovery | Access attempts to HR and Finance shares |
| Lateral Movement | SMB / Windows File Sharing | SMB session to `FILE01` |
| Collection | Data from Network Shared Drive | Multiple files read from Support share |

---

## Confirmed Phases

### Initial Access

The likely initial access vector was phishing.

Evidence:

```text
Email delivered to support.johan
Attachment: Faktura_45892.docm
DKIM: Fail
DMARC: Fail
```

The `.docm` file type is important because it can contain macros.

---

### Execution

Execution is confirmed because Microsoft Word started PowerShell.

Evidence:

```text
Parent Process: WINWORD.EXE
Process: powershell.exe
```

This is suspicious because Word normally should not launch PowerShell.

---

### Defense Evasion

Defense evasion is supported by the PowerShell command-line behavior.

Evidence:

```text
powershell.exe -ExecutionPolicy Bypass -EncodedCommand
```

`ExecutionPolicy Bypass` attempts to avoid normal PowerShell script restrictions.

`EncodedCommand` can hide the real command being executed.

---

### Persistence

Persistence is confirmed.

Evidence:

```text
Scheduled Task: WindowsUpdateCheck
Startup Shortcut: updater.lnk
```

This means the attacker or malware likely attempted to run again after reboot or user logon.

---

## Likely or Partial Phases

### Command and Control

Command and Control is likely but not fully confirmed.

Evidence:

```text
HTTPS connections to external IP addresses
Suspicious TLS connection to newly observed domain
```

Because the traffic used TLS, the actual content was not visible. However, the timing and destination make the activity suspicious.

---

### Discovery

Discovery is likely.

Evidence:

```text
Access denied to HR share
Access denied to Finance share
```

The endpoint attempted to access areas outside the normal Support scope.

This may indicate that the attacker or malware was checking what resources were available.

---

### Lateral Movement

Lateral movement is partial.

Evidence:

```text
SMB session established to FILE01
```

This shows internal movement from the endpoint to a file server, but there is no proof that another system was fully compromised.

---

### Collection

Collection is partial.

Evidence:

```text
Multiple files read from \\FILE01\Support\Kundärenden\2026\
```

Files were accessed, but there is no confirmed proof that they were packaged or exfiltrated.

---

## Not Confirmed Phases

### Credential Access

Credential access is not confirmed.

There is no clear evidence of:

```text
Credential dumping
Password theft
LSASS access
Suspicious authentication tool usage
```

---

### Exfiltration

Exfiltration is not confirmed.

There was external HTTPS traffic, but the available evidence does not prove that internal data was sent out.

More investigation would be needed, for example:

```text
Proxy logs
TLS inspection logs
Endpoint memory analysis
Packet capture metadata
File access correlation with outbound traffic
```

---

## Severity Assessment

The incident should be classified as high severity.

Reasons:

```text
Confirmed suspicious execution
Confirmed defense evasion behavior
Likely external command and control
Confirmed persistence
Internal file server access
Attempted access to restricted resources
Multiple evidence sources support the attack chain
```

Even without confirmed exfiltration, the combination of execution, persistence, and internal access makes this a serious incident.

---

## Most Important Evidence

The strongest evidence in this case is the combination of:

```text
Phishing email
WINWORD.EXE spawning powershell.exe
ExecutionPolicy Bypass
EncodedCommand
Suspicious DNS queries
HTTPS connections to external IPs
Suspicious files created
Scheduled task created
SMB session to FILE01
```

One event alone might not be enough, but together they form a clear attack chain.

---

## Conclusion

The incident is best classified as a phishing-based malware execution case with confirmed persistence and suspicious internal file server activity.

The investigation does not confirm credential theft or data exfiltration, but the available evidence is strong enough to treat the endpoint as compromised and perform containment, evidence preservation, and threat hunting across the environment.
