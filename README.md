# Threat-Hunting-Scenario-Scattered-Invoice

## RDP Compromise Incident

**Report ID:** INC-2026-1104

**Analyst:** Nadezna Morris

**Date:** 11-April-2026

**Incident Date:** 10-Febuary-2026

---

## Executive Summary

---

## 1. Findings

### **Key Indicators of Compromise (IOCs):**

| Type             | Indicator                     |
| ---------------- | ------------------------------|


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


---

## 3. MITRE ATT&CK Mapping

| Tactic               | Technique                                                                                  | Evidence                                    |
| -------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------- |



---

## 4. Recommendations

### Immediate Action  

### Short-term Remediation  

### Long-term Remediation 

---

**Report Status:** Complete

**Next Review:** 18-April-2026

**Distribution:** Cyber Range
