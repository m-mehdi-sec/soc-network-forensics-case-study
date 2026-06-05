# Timeline

## Purpose

This file documents the incident timeline for the simulated SOC investigation.

The goal is to show how the activity developed over time and how different log sources help connect the full attack chain.

---

## Timeline Overview

| Time | Event | Source | Interpretation |
|------|-------|--------|----------------|
| 09:08:44 | Email delivered to `support.johan` | Email Gateway Log | Possible phishing email delivered |
| 09:10:18 | User opened `Faktura_45892.docm` | Windows Process Log | User interaction with macro-enabled document |
| 09:10:25 | `WINWORD.EXE` started `powershell.exe` | Windows Process Log | Suspicious process chain |
| 09:10:26 | PowerShell used `EncodedCommand` | Wazuh / Process Log | Possible obfuscation or hidden command execution |
| 09:10:30 | DNS query for `update-cdn.cloud-sync.example` | DNS Log | Suspicious domain lookup |
| 09:10:31 | HTTPS connection to `185.44.12.90` | Firewall / Wireshark | External communication started |
| 09:10:32 | IDS alert: Possible PowerShell Download Cradle | IDS Alert | Malware-like download behavior detected |
| 09:10:43 | `update.ps1` created in `C:\Users\Public\` | Wazuh FIM | Suspicious script dropped on disk |
| 09:10:48 | `client.exe` created in `C:\Users\Public\` | Wazuh FIM | Possible payload dropped on disk |
| 09:11:02 | DNS query for `api.drop-storage.example` | DNS Log | Second suspicious external domain |
| 09:11:05 | HTTPS connection to `91.203.18.77` | Firewall Log | Larger external data transfer observed |
| 09:11:06 | IDS alert: Suspicious TLS connection | IDS Alert | Connection to newly observed domain |
| 09:11:10 | Scheduled task `WindowsUpdateCheck` created | Windows Security Event | Persistence attempt |
| 09:11:14 | `updater.lnk` modified in Startup folder | Wazuh FIM | Additional persistence indicator |
| 09:12:11 | DNS query for `windows-update-check.example` | DNS Log | Suspicious domain using legitimate-looking name |
| 09:12:14 | HTTPS connection to `185.44.12.91` | Firewall Log | Continued external communication |
| 09:13:44 | SMB session established to `FILE01` | Windows / File Server Log | Internal file server access |
| 09:13:52 | IDS alert: Suspicious SMB session after malware-like activity | IDS Alert | SMB activity becomes more suspicious due to earlier events |
| 09:14:02 | Multiple files read from Support share | File Server Log | Possible collection activity |
| 09:14:27 | Access denied to HR share | File Server Log | Attempted access to restricted data |
| 09:14:31 | Access denied to Finance share | File Server Log | Attempted access to restricted data |
| 09:14:33 | Wazuh alert triggered | Wazuh / SIEM | Suspicious PowerShell activity detected by SIEM |

---

## Key Timeline Phases

### 1. Initial Access

| Time | Event |
|------|-------|
| 09:08:44 | Phishing email delivered |
| 09:10:18 | User opened macro-enabled document |

The incident appears to begin with an email containing the attachment `Faktura_45892.docm`.

The file extension `.docm` is important because it can contain macros.

---

### 2. Execution

| Time | Event |
|------|-------|
| 09:10:25 | `WINWORD.EXE` started `powershell.exe` |
| 09:10:26 | PowerShell used `EncodedCommand` |

This is one of the most important parts of the timeline.

Microsoft Word starting PowerShell is suspicious because Word normally should not launch command-line tools. The use of `EncodedCommand` also suggests that the command may have been hidden or obfuscated.

---

### 3. External Communication

| Time | Event |
|------|-------|
| 09:10:30 | DNS query to `update-cdn.cloud-sync.example` |
| 09:10:31 | HTTPS connection to `185.44.12.90` |
| 09:11:02 | DNS query to `api.drop-storage.example` |
| 09:11:05 | HTTPS connection to `91.203.18.77` |
| 09:12:11 | DNS query to `windows-update-check.example` |
| 09:12:14 | HTTPS connection to `185.44.12.91` |

The endpoint contacted several suspicious external domains and IP addresses.

The traffic used HTTPS on port 443. This does not mean the traffic is safe. It only means the communication is encrypted.

---

### 4. File Creation

| Time | Event |
|------|-------|
| 09:10:43 | `update.ps1` created |
| 09:10:48 | `client.exe` created |

The files were created in:

```text
C:\Users\Public\
```

This location is interesting because attackers often use folders that are writable by normal users.

---

### 5. Persistence

| Time | Event |
|------|-------|
| 09:11:10 | Scheduled task `WindowsUpdateCheck` created |
| 09:11:14 | Startup shortcut `updater.lnk` modified |

These events indicate persistence.

Persistence means the attacker or malware tries to survive logout, reboot, or user restart by making sure the malicious code can run again later.

---

### 6. Internal Access

| Time | Event |
|------|-------|
| 09:13:44 | SMB session to `FILE01` |
| 09:14:02 | Multiple files read from Support share |
| 09:14:27 | Access denied to HR share |
| 09:14:31 | Access denied to Finance share |

The endpoint later accessed the file server.

The access to the Support share may be normal for the user, but in this context it becomes suspicious because it happened after malware-like behavior.

The denied access to HR and Finance shows that least privilege helped reduce the impact.

---

## Timeline Interpretation

The timeline shows a clear attack flow:

```text
Phishing email
↓
User opens macro-enabled document
↓
Word starts PowerShell
↓
Encoded PowerShell command runs
↓
External DNS and HTTPS communication starts
↓
Suspicious files are created
↓
Persistence is attempted
↓
Endpoint accesses internal file server
↓
Restricted HR and Finance access is denied
```

---

## Most Important Events

The most important events in the timeline are:

| Time | Event | Why It Matters |
|------|-------|----------------|
| 09:10:18 | User opened `Faktura_45892.docm` | Likely start of user-triggered execution |
| 09:10:25 | Word started PowerShell | Strong suspicious process relationship |
| 09:10:31 | HTTPS connection to external IP | Possible payload download or C2 |
| 09:10:43 | `update.ps1` created | Suspicious script dropped |
| 09:11:10 | Scheduled task created | Persistence attempt |
| 09:13:44 | SMB session to FILE01 | Possible post-compromise internal activity |
| 09:14:27 | Access denied to HR | Shows attempted access beyond normal Support scope |
| 09:14:33 | Wazuh alert triggered | SIEM detection point |

---

## Detection Gap Observation

One interesting point is that several suspicious actions happened before the Wazuh alert at `09:14:33`.

For example:

```text
09:10:25 - PowerShell started
09:10:31 - External HTTPS connection
09:10:43 - Suspicious file created
09:11:10 - Scheduled task created
09:13:44 - SMB session to FILE01
09:14:33 - Wazuh alert triggered
```

This shows why timeline building is important.

The alert is not always the beginning of the incident. It is often just the first moment when the security system reports something clearly suspicious.

---

## Conclusion

The timeline supports the conclusion that this was not just a single suspicious alert.

The events show a connected chain of activity starting with a likely phishing email and continuing through execution, external communication, file creation, persistence, and internal file server access.

The timeline also shows why multiple log sources are needed. Each source provides one part of the story, but the full attack path becomes clear only when the events are placed in time order.
