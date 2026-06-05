# Indicators of Compromise (IoCs)

## Overview

This document contains all identified Indicators of Compromise (IoCs) discovered during the investigation.

These indicators can be used for:

- Threat hunting
- Detection engineering
- SIEM correlation rules
- Firewall blocking
- DNS filtering
- Incident response activities

---

## IP Addresses

The following external IP addresses were observed during the investigation.

```text
185.44.12.90
185.44.12.91
91.203.18.77
```

### Recommended Action

```text
Block at firewall
Search historical logs
Check for additional hosts contacting these IPs
```

---

## Domains

The following domains were queried by the affected endpoint.

```text
update-cdn.cloud-sync.example
api.drop-storage.example
windows-update-check.example
```

These domains imitate legitimate cloud or update services.

### Recommended Action

```text
Block at DNS filtering layer
Search DNS logs for additional requests
Search proxy logs for related activity
```

---

## Suspicious Files

The following files were created during the incident.

```text
C:\Users\Public\update.ps1
C:\Users\Public\client.exe
```

### Why They Matter

```text
update.ps1
Possible PowerShell payload

client.exe
Possible downloaded executable
```

### Recommended Action

```text
Collect files
Calculate hashes
Analyze in isolated environment
```

---

## Persistence Indicators

### Scheduled Task

```text
WindowsUpdateCheck
```

### Startup Shortcut

```text
updater.lnk
```

Location:

```text
C:\Users\support.johan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
```

### Why They Matter

These artifacts indicate a persistence attempt.

Persistence allows malicious code to run again after logon or reboot.

---

## Process Indicators

### Parent-Child Process Relationship

```text
WINWORD.EXE
└── powershell.exe
```

### Command-Line Pattern

```text
powershell.exe -ExecutionPolicy Bypass -EncodedCommand
```

### Why They Matter

Microsoft Word normally should not launch PowerShell.

The use of:

```text
ExecutionPolicy Bypass
EncodedCommand
```

is commonly associated with malicious scripting activity.

---

## Email Indicators

### Attachment

```text
Faktura_45892.docm
```

### File Type

```text
.docm
```

Macro-enabled Microsoft Word document.

### Why It Matters

Macro-enabled Office files are frequently used in phishing campaigns to trigger malicious execution.

---

## User Account

```text
NORDSECURE\support.johan
```

### Activity Observed

```text
Opened suspicious document
Generated PowerShell activity
Accessed FILE01
Attempted access to restricted shares
```

---

## Host Indicators

### Endpoint

```text
Hostname: WIN11-SUPPORT-04
IP Address: 10.10.40.24
```

### Related Internal System

```text
Hostname: FILE01
IP Address: 10.10.50.20
```

---

## Threat Hunting Queries

### Search for IP Activity

```text
185.44.12.90
185.44.12.91
91.203.18.77
```

### Search for Domains

```text
update-cdn.cloud-sync.example
api.drop-storage.example
windows-update-check.example
```

### Search for Files

```text
update.ps1
client.exe
```

### Search for Persistence

```text
WindowsUpdateCheck
updater.lnk
```

### Search for Process Activity

```text
WINWORD.EXE -> powershell.exe
powershell.exe -ExecutionPolicy Bypass
powershell.exe -EncodedCommand
```

---

## Detection Opportunities

The following indicators could be used in detection rules:

```text
WINWORD.EXE spawning powershell.exe
PowerShell with EncodedCommand
PowerShell with ExecutionPolicy Bypass
Creation of update.ps1
Creation of client.exe
Creation of WindowsUpdateCheck scheduled task
Connections to identified external IP addresses
DNS queries to identified domains
```

---

## Summary

The strongest IoCs identified in this investigation are:

```text
185.44.12.90
185.44.12.91
91.203.18.77

update-cdn.cloud-sync.example
api.drop-storage.example
windows-update-check.example

update.ps1
client.exe

WindowsUpdateCheck
updater.lnk

WINWORD.EXE -> powershell.exe
powershell.exe -ExecutionPolicy Bypass -EncodedCommand

Faktura_45892.docm
```

These indicators should be prioritized for blocking, monitoring, and threat hunting across the environment.
