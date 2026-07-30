# Threat-Hunting-Scenario-Scattered-Invoice

## RDP Compromise Incident

**Report ID:** IR-2026-0225-BEC

**Analyst:** Nadezna Morris

**Date:** 11-April-2026

**Incident Date:** 25-Febuary-2026

---

## Executive Summary

On 25 February 2026, finance employee Mark Smith (`m.smith@lognpacific.org`) was targeted with an MFA fatigue (push bombing) attack, receiving repeated sign-in approval prompts while at home. After denying three requests, he approved a fourth to stop the notifications, unknowingly granting a threat actor access to his account from an IP address in the Netherlands (205.147.16.190). The attacker authenticated to One Outlook Web from a Linux device running Firefox — a stark contrast to Mark's usual Windows corporate endpoint — and no Conditional Access policy blocked the sign-in. Within the same session, the attacker read Mark's mailbox, created two malicious inbox rules (one to silently forward financially themed emails to an external address, `insights@duck.com`, and one to delete security/breach-related alerts), accessed SharePoint and OneDrive content, and sent a thread-hijacked email to `j.reynolds@lognpacific.org` posing as Mark with updated banking details on an existing invoice thread. Finance processed the fraudulent payment believing it followed standard verification procedure, resulting in a £24,500 wire transfer to attacker-controlled banking details, which was subsequently frozen by the receiving bank. The tactics, techniques, and procedures observed — MFA fatigue, inbox rule persistence for defence evasion, BEC targeting finance via thread hijacking, and use of anonymising/VPN infrastructure — are consistent with the threat group **Scattered Spider**, previously linked to attacks on MGM Resorts and Caesars Entertainment.

---

## 1. Findings

### **Key Indicators of Compromise (IOCs):**

| Type                    | Indicator                                                    | Description                                                            |
| ----------------------- | -------------------------------------------------------------| ---------------------------------------------------------------------- |
| Attacker IP             | 205.147.16.190`                                              | Geolocates to Netherlands (NL); used for sign-in, mailbox access, and BEC email send |
| Exfil destination       | `insights@duck.com`                                          | `ForwardTo` address on malicious inbox rule                            |
| Inbox rule name         | `.`                                                          | First rule — forwards financial-keyword emails externally              |
| Inbox rule name         | `..`                                                         | Second rule — deletes security-alert emails                            |
| Rule keywords           | `invoice, payment, wire, transfer`                           | SubjectOrBodyContainsWords on forwarding rule                          |
| Rule keywords           | suspicious, security, phishing, unusual, compromised, verify | Keywords on deletion rule (hiding breach evidence)                     |
| Session ID              | 00225cfa-a0ff-fb46-a079-5d152fcdf72a                         | AAD session tying sign-in, inbox rules, and email activity together    |
| Device & UA fingerprint | Linux / Firefox 147.0                                        | Anomalous vs. Mark's normal Windows managed device                     |
| BEC subject             | RE: Invoice #INV-2026-0892 - Updated Banking Details         | Thread-hijacked email to j.reynolds@lognpacific.org                    |
| Auth signal             | Error code 50074                                             | MFA required but not satisfied — precedes fatigue attack pattern       |

---

***FLAG 0 - Scattered Spider/ Environment Access***

**Objective:** Confirm you have access. What is the name of the Sentinel workspace containing the investigation data?

**Flag:** `law-cyber-range`


---

***FLAG 1 - Compromised Account***

**Objective:** Before you can investigate, confirm the compromised identity. Query SigninLogs for the user identified in the incident.

**Flag:** `m.smith@lognpacific.org`


---

***FLAG 2 - Attacker Source IP***

**Objective:** Baseline Mark's sign-in activity. Compare successful authentications before the attack window against the evening activity. Geography and timing will separate legitimate from malicious.

**Flag:** `205.147.16.190`


---

***FLAG 3 - Attack Origin Country***

**Objective:** You have the attacker's IP. Now determine where it geolocates to. Does an employee in one country suddenly authenticating from another make sense?

**Flag:** `NL`


---

***FLAG 4 - MFA Denial Error Code***

**Objective:** What error code indicates that strong authentication (MFA) was required but not completed?

**Flag:** `50074`




---

***FLAG 5 - MFA Fatigue Intensity***

**Objective:** How many MFA push requests did Mark deny before he approved one?

**Flag:** `3`



---

***FLAG 6 - Application Accessed***

**Objective:** After beating MFA, the attacker accessed a specific Microsoft application. A remote attacker without the desktop app installed would use the web version. What application did the attacker authenticate to?

**Flag:** `One Outlook Web`



---

***FLAG 7 - Attacker Operating System***

**Objective:** Mark's corporate device runs Windows on a managed endpoint. The attacker authenticated from something very different. Comparing device profiles between legitimate and malicious sessions is how you spot compromised accounts at scale.

**Flag:** `Linux`



---

***FLAG 8 - Attacker Browser***

**Objective:** Cross-reference with Mark's normal browser. Different browser, different OS, different country. Three anomaly layers beyond just the IP.

**Flag:** `Firefox 147.0`



---

***FLAG 9 - First Post-Auth Action***

**Objective:** The first action after authentication reveals intent. Did they exfiltrate immediately? Set up persistence? Or read the inbox to understand the target? Query CloudAppEvents for the attacker's IP during the attack window. Sort by time ascending. What was the very first ActionType?

**Flag:** `MailItemsAccessed`



---

***FLAG 10 - Rule Creation Method***

**Objective:** Sophisticated attackers establish persistence to maintain access. Inbox rules are a favourite. They are silent, persistent, and often overlooked. Query CloudAppEvents for the attack timeframe. Look at the ActionType field for anything related to email rule creation.

**Flag:** `New-InboxRule`



---

***FLAG 11 - Forward Rule Name***

**Objective:** Attackers name rules strategically to be as inconspicuous as possible. Examine the RawEventData for the inbox rule creation event. Find the Name parameter.

**Flag:** `.`




---

***FLAG 12 - Forward Destination***

**Objective:** The external email receiving forwarded messages is attacker-controlled infrastructure. This is a critical IOC for email gateway blocking. Find the ForwardTo parameter in the rule configuration.

**Flag:** `insights@duck.com`



---

***FLAG 13 - Forward Keywords***

**Objective:** The keywords triggering the forwarding rule reveal what data the attacker wants. Financial keywords indicate invoice fraud. Find the SubjectOrBodyContainsWords parameter.

**Flag:** `invoice, payment, wire, transfer`



---

***FLAG 14 - Rule Processing Flag***

**Objective:** Smart attackers configure rules so no other rules process the matched emails after theirs. This prevents the user's own rules from alerting them. What parameter ensures this rule takes priority over all others?

**Flag:** `StopProcessingRules`



---

***FLAG 15 - Delete Rule Name***

**Objective:** Inbox rules can delete messages as easily as forward them. Attackers create rules to automatically delete security notifications and suspicious activity alerts. Query CloudAppEvents for ALL inbox rule creation events during the attack window. What is the second rule's name?

**Flag:** `..`



---

***FLAG 16 - Delete Keywords***

**Objective:** The keywords targeted for deletion reveal what the attacker wants to hide. Security-related terms mean they are hiding breach notifications. Parse the second rule's configuration. Find the keyword triggers.

**Flag:** `suspicious, security, phishing, unusual, compromised, verify`



---

***FLAG 17 - BEC Target***

**Objective:** Pivot to EmailEvents. Filter by the compromised account as sender and the attacker's IP. Who received the fraudulent email?

**Flag:** `j.reynolds@lognpacific.org`



---

***FLAG 18 - BEC Subject Line***

**Objective:** The subject line reveals the social engineering pretext. The attacker replied to an existing thread rather than creating a new email. Classic thread hijacking.

**Flag:** `RE: Invoice #INV-2026-0892 - Updated Banking Details`




---

***FLAG 19 - Email Direction***

**Objective:** Was this email sent externally or within the organisation? The direction determines whether email gateway rules could have caught it.

**Flag:** `Intra-org`



---

***FLAG 20 - BEC Sender IP***

**Objective:** Cross-correlate. The SenderIPv4 on the BEC email should match the attacker's sign-in IP. This proves the same session was used for authentication and email sending.

**Flag:** `205.147.16.190`



---

***FLAG 21 - Cloud App Accessed***

**Objective:** Query CloudAppEvents filtered to the attacker's IP. Look for file access ActionTypes. Check the Application field.

**Flag:** `Microsoft OneDrive for Business`



---

***FLAG 22 - SharePoint App Accessed***

**Objective:** The attacker did not stop at personal files. The sign-in logs show authentication to another Microsoft cloud application during the attack window. Query SigninLogs for the attacker's IP. What other application did they access?

**Flag:** `Microsoft SharePoint Online`



---

***FLAG 23 - Session Correlation***

**Objective:** One identifier links all attacker activity across sign-ins, inbox rules, and email. Find the session ID that ties the entire investigation together. Check the CloudAppEvents inbox rule events. In RawEventData, find AppAccessContext.AADSessionId. Then confirm it matches the SessionId in SigninLogs for the attacker's successful authentication.

**Flag:** `00225cfa-a0ff-fb46-a079-5d152fcdf72a`



---

***FLAG 24 - Conditional Access Status***

**Objective:** Conditional Access policies can block sign-ins from unmanaged devices or risky locations. Check the attacker's successful sign-in. What was the ConditionalAccessStatus?

**Flag:** `notApplied`



---

***FLAG 25 - MFA Fatigue MITRE ID***

**Objective:** Map the MFA fatigue technique to the MITRE ATT&CK framework. What technique ID describes repeated MFA push notifications to wear down the user?

**Flag:** `T1621`



---

***FLAG 26 - Email Rules MITRE ID***

**Objective:** The attacker created inbox rules to hide evidence. Map this defence evasion technique to MITRE ATT&CK. What technique ID specifically describes hiding malicious activity through email rules?

**Flag:** `T1564.008`



---

***FLAG 27 - Credential Source***

**Objective:** The threat group behind this attack is known for purchasing credentials from a specific source. These credentials are harvested by malware that steals saved passwords, session tokens, and browser data from infected machines. What type of malware typically provides initial credentials to groups like this?

**Flag:** `Infostealer`



---

***FLAG 28 - Immediate Containment***

**Objective:** The attacker still has a valid session. The inbox rules are still active. What is the first containment action?

**Flag:** `Revoke Sessions`




---

***FLAG 29 - Threat Actor Attribution***

**Objective:** Throughout this investigation you observed MFA fatigue, inbox rule persistence, BEC targeting finance, and use of anonymising infrastructure. The briefing mentioned a group that targeted MGM Resorts and Caesars Entertainment. Who did this?

**Flag:** `Scattered Spider`



---

## 2. Investigation Summary

**Identity & Initial Access:** Baselining `SigninLogs` for `m.smith@lognpacific.org` showed legitimate authentications aligned with expected geography and working hours prior to the attack window. On the evening of 25 February, sign-in attempts began originating from `205.147.16.190` (NL) — a location inconsistent with Mark's normal activity. Multiple attempts returned error code **50074** (MFA required, not satisfied), reflecting **3 denied push notifications** before Mark approved one, completing the MFA fatigue attack (T1621).

**Post-Auth Access:** The successful sign-in authenticated to **One Outlook Web**, consistent with browser-based remote access rather than a native desktop client. Device telemetry showed a **Linux** host running **Firefox 147.0** — diverging from Mark's managed Windows endpoint on three anomaly layers: IP/geography, device OS, and browser. Notably, `ConditionalAccessStatus` on this sign-in was **notApplied**, meaning no CA policy intervened to block or challenge the anomalous session.

**Mailbox Activity (CloudAppEvents):** Sorted by time ascending, the attacker's first action was **MailItemsAccessed** — reconnaissance of the mailbox before taking further action. The attacker then created two inbox rules via New-InboxRule:  
- Rule `.` — forwards mail containing `invoice, payment, wire, transfer` to `insights@duck.com`, with `StopProcessingRules` set to suppress any subsequent (including the victim's own) rule evaluation.
- Rule `..` — deletes mail containing `suspicious, security, phishing, unusual, compromised, verify`, suppressing security alerts and breach notifications from ever reaching the inbox view.

**Lateral Data Access:** The same attacker IP was observed accessing **Microsoft OneDrive for Business** (file access ActionTypes) and authenticating to **Microsoft SharePoint Online**, indicating the compromise extended beyond email into document repositories.

**BEC Payload:** Pivoting into `EmailEvents` filtered on sender `m.smith@lognpacific.org` and the attacker IP identified an **Intra-org** email sent to `j.reynolds@lognpacific.org`, subject "`RE: Invoice #INV-2026-0892 - Updated Banking Details`" — a reply injected into an existing thread (thread hijacking) rather than a new message, lending it credibility. The SenderIPv4 on this email matched the attacker's sign-in IP (`205.147.16.190`), confirming the same authenticated session was used both to access the mailbox and to send the fraudulent instruction.

**Session Correlation:** The `AADSessionId` (`00225cfa-a0ff-fb46-a079-5d152fcdf72a`) recovered from the inbox rule `RawEventData.AppAccessContext` matched the `SessionId` on the attacker's successful sign-in in `SigninLogs`, confirming a single continuous session was responsible for authentication, mailbox reconnaissance, rule creation, data access, and email fraud.

**Outcome:** Finance received the spoofed intra-org email appearing to come from a trusted colleague with updated bank details on a real, in-progress invoice, and processed a £24,500 payment per normal procedure. The receiving bank's fraud controls flagged and froze the transfer before final settlement.

---

## 3. MITRE ATT&CK Mapping

| Tactic                             | Technique                                                                                  | Evidence                      |
| ---------------------------------- | ------------------------------------------------------------------------------------------ | ----------------------------- |
| Resource Development               | T1586 / T1589 - Compromise Accounts / Gather Victim Identity Information | Attacker likely obtained initial valid credentials via infostealer-harvested data prior to the attack|
| Initial Access                     | T1078 - Valid Accounts                                                   | Attacker authenticated as m.smith@lognpacific.org using compromised (but valid) credentials |
| Initial Access / Credential Access | T1621 - Multi-Factor Authentication Request Generation                   | Repeated MFA push prompts sent to Mark Smith's device; 3 denied, 4th approved (MFA fatigue) |
| Defense Evasion                    | T1078.004 - Valid Accounts: Cloud Accounts                               | Use of a legitimate, authenticated cloud identity to blend in with normal activity |
| Defense Evasion                    | T1564.008 - Hide Artifacts: Email Hiding Rules                           | Two inbox rules created — one forwarding financial emails externally, one deleting security alerts |
| Defense Evasion                    | T1070 - Indicator Removal                                                | Deletion rule (..) removes security/phishing/compromise-related emails to hide evidence of the intrusion |
| Persistence                        | T1098.002 - Account Manipulation: Additional Email Delegate Permissions / Mailbox Rules | Inbox rules (New-InboxRule) established persistent, silent access to future incoming mail |
| Collection                         | T1114 - Email Collection                                                 | MailItemsAccessed — attacker read mailbox contents immediately after authentication |
| Collection                         | T1114.003 - Email Collection: Email Forwarding Rule                      | Forwarding rule (.) auto-sends invoice/payment/wire/transfer emails to insights@duck.com |
| Collection                         | T1213 - Data from Information Repositories                               | Access to Microsoft OneDrive for Business and SharePoint Online during the session |
| Command and Control                | T1090 - Proxy                                                            | Attacker IP (205.147.16.190, NL) inconsistent with victim's normal geography, suggesting VPN/proxy infrastructure |
| Impact                             | T1657 - Financial Theft                                                  | Thread-hijacked BEC email led to a fraudulent £24,500 wire transfer |

---

## 4. Recommendations

### Immediate Action  
- Revoke all active sessions and refresh tokens for m.smith@lognpacific.org (invalidates session 00225cfa-a0ff-fb46-a079-5d152fcdf72a).
- Force password reset and re-enrol MFA for the compromised account.
- Delete both malicious inbox rules (. and ..) and audit all mailboxes org-wide for similarly named/suspicious rules.
- Block/blacklist attacker IP 205.147.16.190 and domain duck.com (or the specific address insights@duck.com) at the email gateway and firewall.
- Notify the bank and initiate formal recall/fraud dispute for the £24,500 transfer; confirm freeze status with receiving bank.
- Alert j.reynolds@lognpacific.org and finance team; place a hold on any further payments referencing INV-2026-0892 pending manual verification.

### Short-term Remediation  
- Enable number-matching MFA and disable simple push-approval to mitigate future MFA fatigue attacks.
- Deploy Conditional Access policies requiring compliant/managed devices and blocking or challenging sign-ins from unfamiliar geographies (address the notApplied gap identified).
- Enable alerting on inbox rule creation containing forwarding to external domains and/or matching high-risk keyword patterns.
- Review and audit OneDrive/SharePoint access logs for the compromised account for data exfiltration scope.
- Conduct targeted user awareness training on MFA fatigue and BEC/thread-hijacking tactics for finance staff.
- Implement out-of-band verification for any banking/payment detail changes (e.g., phone callback to a known-good number).

### Long-term Remediation 
- Deploy a risk-based sign-in policy (e.g., Identity Protection) to automatically flag/block impossible-travel and anomalous device sign-ins.
- Implement DMARC/DKIM/SPF enforcement and internal anti-spoofing controls even for intra-org mail flows.
- Establish a continuous hunting use case for New-InboxRule / Set-InboxRule events with external forwarding or security-keyword deletion patterns.
- Review third-party credential exposure (infostealer log monitoring) via dark web/credential-monitoring services, given this threat actor's known reliance on purchased infostealer-harvested credentials.
- Formalise a payment verification policy (dual-approval + callback verification for any bank detail changes) across all vendor/finance workflows.
- Conduct a tabletop exercise simulating Scattered Spider TTPs (MFA fatigment, help-desk social engineering, BEC) to validate detection and response readiness.

---

**Report Status:** Complete

**Next Review:** 18-April-2026

**Distribution:** Cyber Range
