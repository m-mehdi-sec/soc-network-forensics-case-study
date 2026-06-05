# Lessons Learned

## Overview

This case study helped me understand how a SOC investigation works beyond just looking at a single alert.

At first, the case looked like a normal Wazuh alert about suspicious PowerShell activity. But after reviewing the different log sources, it became clear that the alert was only one part of a bigger attack chain.

The most important lesson is that an alert is not the full story. It is the starting point for an investigation.

---

## One Alert Is Not Enough

The first alert came from Wazuh and showed suspicious PowerShell execution.

That was important, but it did not explain:

- How the attack started
- What the user opened
- Which external systems were contacted
- Which files were created
- Whether persistence was attempted
- Whether internal resources were accessed

This showed me that a SOC analyst should not stop at the first alert. The next step is to investigate what happened before and after the alert.

---

## Correlation Is the Key

The clearest lesson from this case was the importance of correlating multiple log sources.

Each source showed one part of the attack:

| Source | Value |
|--------|-------|
| Email Gateway | Showed the likely phishing email |
| Windows Logs | Showed Word starting PowerShell |
| Wazuh | Detected suspicious endpoint behavior |
| DNS Logs | Showed suspicious domain lookups |
| Firewall Logs | Showed outbound HTTPS connections |
| Wireshark-style Records | Confirmed network communication metadata |
| Wazuh FIM | Showed suspicious files created |
| Windows Security Events | Showed persistence through scheduled task |
| IDS Alerts | Confirmed malware-like network behavior |
| File Server Logs | Showed internal file access attempts |

No single tool showed everything.

The full incident only became clear when the events were connected together.

---

## Timeline Building Is Very Important

Building a timeline made the whole case much easier to understand.

Instead of looking at isolated logs, the timeline showed the flow of the attack:

```text
Phishing email
↓
Document opened
↓
PowerShell executed
↓
External communication
↓
Files created
↓
Persistence attempted
↓
File server accessed
```

This helped answer the most important questions:

- What happened first?
- What happened next?
- When did the suspicious activity start?
- How far did the attacker or malware get?
- Which evidence supports the conclusion?

The timeline turned separate events into a clear story.

---

## HTTPS Does Not Always Mean Safe

One important lesson was that HTTPS traffic is not automatically safe.

In the firewall logs, the traffic was allowed because it matched a normal rule:

```text
Support VLAN → Internet → HTTPS
```

But attackers can also use HTTPS for:

- Payload download
- Command and control
- Data transfer
- Hiding inside normal-looking encrypted traffic

So the firewall did not necessarily fail. The traffic matched an allowed rule, but the destination and timing made it suspicious.

This helped me understand why DNS monitoring, IDS alerts, proxy logs, and endpoint telemetry are also needed.

---

## Endpoint and Network Logs Work Best Together

Wazuh and Windows logs showed what happened on the endpoint.

DNS, firewall, IDS, and Wireshark-style records showed what happened on the network.

Together, they gave a much stronger picture.

Endpoint logs answered questions like:

```text
What process started?
What file was created?
Was persistence attempted?
Which user was involved?
```

Network logs answered questions like:

```text
Which domain was queried?
Which IP was contacted?
Which port was used?
Was traffic allowed?
Was the connection suspicious?
```

This showed why SOC teams need both endpoint visibility and network visibility.

---

## Persistence Is a Serious Indicator

The scheduled task and Startup shortcut were important because they showed a possible persistence attempt.

Persistence means the attacker or malware tries to keep running even after:

- Logout
- Reboot
- User restart
- Temporary interruption

In this case, the following indicators were important:

```text
Scheduled Task: WindowsUpdateCheck
Startup Shortcut: updater.lnk
```

This made the incident more serious because it suggested that the activity was not just a one-time script execution.

---

## Least Privilege Reduced the Impact

The affected user account was able to access the Support share, but access to HR and Finance was denied.

That was important.

It showed that least privilege helped reduce the possible damage.

If the user had broader permissions, the attacker or malware could possibly have accessed more sensitive data.

This made it clear why access control and segmentation matter in real environments.

---

## Not Everything Can Be Confirmed

Another important lesson was the difference between suspicion and proof.

In this case, there was evidence of:

- Phishing
- Execution
- External communication
- File creation
- Persistence
- Internal file access

But there was no confirmed proof of:

- Credential theft
- Full lateral movement
- Data exfiltration

This is important because a SOC analyst should not guess too much.

It is better to say:

```text
This is confirmed.
This is likely.
This is not confirmed.
More investigation is needed.
```

That makes the analysis more professional and reliable.

---

## Defense in Depth Makes More Sense Now

This case made it much clearer why organizations need several security layers.

One tool alone would not have been enough.

Important layers in this case included:

- Email security
- Endpoint monitoring
- SIEM
- DNS logging
- Firewall logging
- IDS
- File Integrity Monitoring
- Windows event logging
- Access control
- Least privilege

Each layer helped show a different part of the incident.

This is a practical example of defense in depth.

---

## Main Takeaways

The biggest takeaways from this case are:

```text
One alert is only the beginning.
One tool is not enough.
A timeline is critical.
Multiple log sources must be correlated.
HTTPS can still be malicious.
Persistence makes an incident more serious.
Least privilege can reduce the impact.
A SOC analyst must separate proof from assumptions.
```

---

## Personal Reflection

I really liked this type of case because it felt close to how a real SOC investigation works.

Instead of only learning one tool, I had to understand how different logs fit together. The case made it much clearer how an attack can be analyzed from many different angles.

It also helped me understand why SOC analysts need both technical knowledge and analytical thinking.

For me, the most valuable part was seeing how a single PowerShell alert turned into a full attack timeline when the evidence from Wazuh, Windows logs, DNS, firewall logs, IDS, Wireshark-style records, and file server logs was connected together.

That made the whole attack chain much easier to understand.
