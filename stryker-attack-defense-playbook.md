# Lessons from the Stryker Cyberattack: A Practical Microsoft Defense Playbook

**Author:** Security Architect | Microsoft Identity & Endpoint Security
**Published:** March 2026
**Tags:** `Microsoft Sentinel` `Entra ID` `Intune` `Zero Trust` `KQL` `Incident Response` `Global Secure Access`

---

> *"The attacker didn't break Microsoft. They walked in through the front door using stolen keys, and nobody was watching."*

---

## Introduction

On March 11, 2026, Stryker Corporation, one of the world's largest medical device manufacturers, suffered one of the most destructive cyberattacks in recent memory. A pro-Iranian hacktivist group called **Handala** gained administrative credentials to Stryker's Microsoft 365 tenant and used **Microsoft Intune**, Stryker's own device management platform, to factory-reset devices across 79 countries between 5:00 and 8:00 a.m. UTC. No malware. No ransomware. Just a compromised admin account, a newly created backdoor GA account, and a few clicks in a portal that every IT administrator has access to.

56,000 employees were impacted. Manufacturing halted. Hospital supply chains stalled. Login screens across the organization were defaced with Handala's logo and propaganda messages. Employees on BYOD programs lost personal photos, password managers, and MFA apps alongside corporate data.

The platform didn't fail. **The access controls around it did.**

This post walks through each control gap in the attack and gives you the specific steps to close them. Everything here uses tooling already built into Microsoft E3/E5 licensing. No third-party vendors required.

---

## Table of Contents

1. [Understanding the Attack Chain](#1-understanding-the-attack-chain)
2. [Protecting Global Administrator Accounts](#2-protecting-global-administrator-accounts)
3. [Restricting Admin Portal Access with Entra Private Access](#3-restricting-admin-portal-access-with-entra-private-access)
4. [Locking Down Intune Device Wipe Capabilities](#4-locking-down-intune-device-wipe-capabilities)
5. [Multi-Admin Approval for Destructive Actions](#5-multi-admin-approval-for-destructive-actions)
6. [KQL Hunting Queries and Sentinel Alerts](#6-kql-hunting-queries-and-sentinel-alerts)
7. [Automated Response with Logic Apps](#7-automated-response-with-logic-apps)
8. [Full Control Stack Summary](#8-full-control-stack-summary)

---

## 1. Understanding the Attack Chain

> ⚠️ **Disclaimer:** No official attack chain has been publicly released by Stryker Corporation or Microsoft. The reconstruction below is based solely on reporting from public sources including [BleepingComputer](https://www.bleepingcomputer.com/news/security/stryker-attack-wiped-tens-of-thousands-of-devices-no-malware-needed/), [KrebsOnSecurity](https://krebsonsecurity.com/2026/03/iran-backed-hackers-claim-wiper-attack-on-medtech-firm-stryker/), [Cybersecurity Dive](https://www.cybersecuritydive.com/news/stryker-attack-device-management-microsoft-iran/814816/), [Arctic Wolf](https://arcticwolf.com/resources/blog/stryker-systems-disrupted-cyber-attack-handala-group-claims-responsibility/), and [The Record](https://therecord.media/stryker-cyberattack-impact-iran). Some steps are inferred from the nature of the attack and available evidence. This is a best-effort reconstruction for defensive learning purposes only. Treat it as a working hypothesis, not confirmed fact.

---

### Reconstructed Attack Chain

Before building defenses, understand what the available evidence suggests happened, step by step:

```
[1] INITIAL ACCESS — Vector unconfirmed
    ┌─────────────────────────────────────────────────────────────┐
    │ Handala obtained valid credentials for at least one         │
    │ Stryker administrator account.                              │
    │                                                             │
    │ Likely method: phishing, credential stuffing, AiTM proxy,  │
    │ or third-party/supply chain breach — not confirmed.         │
    │                                                             │
    │ Source: BleepingComputer (source familiar with attack)      │
    └─────────────────────────────────────────────────────────────┘
    ⚠️ Control gap: No phishing-resistant MFA on admin accounts

[2] AUTHENTICATION — MFA bypassed or absent
    ┌─────────────────────────────────────────────────────────────┐
    │ Attacker successfully authenticated to the Microsoft 365    │
    │ tenant using the compromised admin credentials.             │
    │                                                             │
    │ MFA was either not enforced, or bypassed via token theft /  │
    │ SIM swap / AiTM — exact method not confirmed publicly.      │
    └─────────────────────────────────────────────────────────────┘
    ⚠️ Control gap: Weak or absent MFA on privileged accounts

[3] PRIVILEGE CONFIRMATION — GA access verified
    ┌─────────────────────────────────────────────────────────────┐
    │ Attacker confirmed the compromised account held Global      │
    │ Administrator privileges, which provide unrestricted access │
    │ to Microsoft Intune by inheritance.                         │
    └─────────────────────────────────────────────────────────────┘
    ⚠️ Control gap: Standing GA access, no JIT/PIM controls

[4] PERSISTENCE — New GA backdoor account created
    ┌─────────────────────────────────────────────────────────────┐
    │ ★ KEY STEP — reported by BleepingComputer                   │
    │                                                             │
    │ Before executing the wipe, the attacker created a NEW       │
    │ Global Administrator account in the tenant.                 │
    │                                                             │
    │ This is a standard attacker persistence technique:          │
    │ even if the original compromised account is detected and    │
    │ its password reset, the backdoor GA account survives and    │
    │ retains full tenant access.                                 │
    │                                                             │
    │ Source: BleepingComputer — source familiar with the attack  │
    └─────────────────────────────────────────────────────────────┘
    ⚠️ Control gap: No alert on new GA account creation,
                   no PIM approval required for GA assignment,
                   no restriction on GA account creation

[5] MASS WIPE EXECUTION — Intune abused at scale
    ┌─────────────────────────────────────────────────────────────┐
    │ Between 5:00 and 8:00 a.m. UTC on March 11, the attacker   │
    │ used the Intune admin console to issue factory reset / wipe │
    │ commands across the device estate.                          │
    │                                                             │
    │ ~80,000 devices confirmed wiped (BleepingComputer source).  │
    │ Handala claimed 200,000+ including servers and mobiles.     │
    │                                                             │
    │ No approval required. No second human in the loop.         │
    │ In some departments up to 95% of devices were erased.       │
    │                                                             │
    │ Login screens defaced with Handala's logo and propaganda.   │
    │                                                             │
    │ Sources: BleepingComputer, ProArch, Arctic Wolf             │
    └─────────────────────────────────────────────────────────────┘
    ⚠️ Control gap: No Multi-Admin Approval for wipe actions,
                   no scope tag partitioning, no bulk wipe alert,
                   no GSA/compliant device requirement for admin portal

[6] CLAIMED EXFILTRATION — Unconfirmed
    ┌─────────────────────────────────────────────────────────────┐
    │ Handala claimed to have stolen ~50 terabytes of data.       │
    │ Stryker's investigation found NO evidence of data           │
    │ exfiltration at time of writing.                            │
    │                                                             │
    │ Sources: Stryker official statement, The Record             │
    └─────────────────────────────────────────────────────────────┘
```

### Attack Chain Summary: What Each Step Exploited

| Step | What Was Missing | Section That Fixes It |
|---|---|---|
| Initial access | Phishing-resistant MFA | §2.1 |
| Authentication bypass | FIDO2 / device-bound auth | §2.1 |
| Standing GA access | PIM JIT elevation | §2.2 |
| **New GA account created** | **GA creation restriction + alert** | **§2.2, §6.1, §6.2** |
| Unrestricted Intune access | Scope tags + custom wipe role | §4.2, §4.3 |
| No wipe approval | Multi-Admin Approval | §5 |
| Admin portal reachable remotely | Entra Private Access + GSA | §3 |
| No detection | Sentinel hunting queries | §6 |

Each step had a gap that could have been closed with controls most organizations already have licensed. The sections below work through each one.

---

## 2. Protecting Global Administrator Accounts

### 2.1 Enforce Phishing-Resistant MFA (FIDO2) for All GAs

Standard MFA (SMS, authenticator app push) can be bypassed via phishing, SIM swap, and adversary-in-the-middle (AiTM) attacks. For Global Administrators, the only acceptable MFA is **phishing-resistant**:

- **FIDO2 hardware security keys** (YubiKey 5 series, Feitian, etc.)
- **Windows Hello for Business** (device-bound, biometric)
- **Certificate-based authentication** with smartcard

FIDO2 keys are cryptographically bound to both the physical device and the specific domain. Even if an attacker has your password and a TOTP code, they cannot authenticate without the physical key in hand.

**How to enforce FIDO2 for GA accounts:**

**Step 1: Enable FIDO2 in the Authentication Methods Policy**

1. Navigate to: `Entra admin center → Protection → Authentication methods → Policies`
2. Select **FIDO2 security key**
3. Set **Enable** to `Yes`
4. Under **Target**, select your GA group or All Users
5. Configure:
   - Allow self-service setup: `Yes` (for initial rollout)
   - Enforce attestation: `Yes` (ensures key is from a known manufacturer)
   - Key restrictions: `Yes` → add your approved AAGUID list (YubiKey, Feitian, etc.)
6. Save

**Step 2: Create a Conditional Access Policy requiring FIDO2 for GA roles**

1. Navigate to: `Entra admin center → Protection → Conditional Access → New Policy`
2. **Name:** `REQUIRE - Phishing-Resistant MFA for Global Admins`
3. **Users:** Include → Directory roles → Global Administrator, Privileged Role Administrator, Intune Service Administrator
4. **Target resources:** All cloud apps
5. **Grant:** Require authentication strength → **Phishing-resistant MFA**
6. **Enable policy:** On (test in Report-only first)

```json
{
  "displayName": "REQUIRE - Phishing-Resistant MFA for Global Admins",
  "state": "enabled",
  "conditions": {
    "users": {
      "includeRoles": [
        "62e90394-69f5-4237-9190-012177145e10",
        "e8611ab8-c189-46e8-94e1-60213ab1f814",
        "3a2c62db-5318-420d-8d74-23affee5d9d5"
      ]
    },
    "applications": {
      "includeApplications": ["All"]
    }
  },
  "grantControls": {
    "operator": "AND",
    "authenticationStrength": {
      "id": "00000000-0000-0000-0000-000000000004"
    }
  }
}
```

> **Role GUIDs:** Global Administrator = `62e90394-69f5-4237-9190-012177145e10`, Privileged Role Administrator = `e8611ab8-c189-46e8-94e1-60213ab1f814`, Intune Service Administrator = `3a2c62db-5318-420d-8d74-23affee5d9d5`

---

### 2.2 Restrict Global Administrator Account Creation

Attackers who gain GA access routinely create additional GA accounts as persistence backdoors. This way, even if you detect and reset the original compromised account, they still have a live foothold.

**Step 1: Enable PIM for the GA role with Approval Required**

1. Navigate to: `Entra admin center → Identity Governance → Privileged Identity Management → Entra Roles`
2. Select **Global Administrator**
3. Click **Settings** → Edit
4. Configure:

| Setting | Value |
|---|---|
| Activation maximum duration | 2 hours |
| Require justification on activation | Yes |
| Require approval to activate | Yes |
| Approvers | [Dedicated security group, not GA members themselves] |
| Require MFA on activation | Yes (phishing-resistant) |
| Require ticket information | Yes |

5. Under **Assignment** tab:
   - Allow permanent eligible assignment: `No`
   - Allow permanent active assignment: `No`
   - Expire active assignments after: `8 hours`

**Step 2: Alert on any direct GA assignment (bypassing PIM)**

Any attempt to assign GA outside of PIM is a red flag. Configure this in Sentinel (query in Section 6).

**Step 3: Restrict who can grant GA assignments**

By default, any existing GA can assign GA to others. Restrict this:

1. Navigate to: `Entra admin center → Roles and administrators → Role settings`
2. Under **Privileged Role Administrator**, restrict activation to a named group of 3 people or fewer
3. This means only designated IAM admins can elevate others to GA, even if a GA account gets compromised

---

### 2.3 Break-Glass Account Hygiene

Break-glass accounts are your emergency access accounts for when PIM or Conditional Access locks everyone out. A few non-negotiable rules:

**Requirements for break-glass accounts:**

- Create **exactly 2** break-glass accounts per tenant
- Use `*.onmicrosoft.com` UPN. Do NOT federate to your identity provider.
- Exclude from **all** Conditional Access policies (including GSA and FIDO2 requirements)
- Use **long randomly generated passwords** (32+ characters) stored in a physical vault (not a password manager)
- Assign a FIDO2 key stored separately from the password, in a physically secured location
- **Never use for day-to-day tasks.** Any sign-in should trigger an immediate P1 alert.

**Monitoring break-glass:**

```kql
SigninLogs
| where UserPrincipalName in ("breakglass1@contoso.onmicrosoft.com",
                               "breakglass2@contoso.onmicrosoft.com")
| project TimeGenerated, UserPrincipalName, IPAddress,
          Location, ResultType, ResultDescription
| order by TimeGenerated desc
```

Any result from this query should be treated as a critical security event.

---

## 3. Restricting Admin Portal Access with Entra Private Access

This control would have stopped the Stryker attack cold, even with valid stolen credentials. The idea is straightforward: **admin portals are unreachable unless the device is managed, compliant, and running the Global Secure Access client.** No client, no portal, end of story.

### 3.1 Architecture Overview

```
Attacker with stolen credentials
  → No GSA client installed
  → Tries to reach portal.azure.com / intune.microsoft.com
  → Conditional Access: "Compliant Network" signal absent
  → ACCESS DENIED — portal never loads

Legitimate admin
  → Managed device + GSA client running
  → "Compliant Network" signal present in token
  → FIDO2 challenge passed
  → PIM elevation approved
  → Admin portal accessible
```

### 3.2 What to Put Behind Private Access vs. What to Keep Public

> ⚠️ **Critical:** Do NOT proxy device enrollment endpoints through Private Access. This creates a bootstrapping deadlock where new devices can never enroll.

**Put behind Private Access (admin consoles only):**

| Endpoint | Purpose |
|---|---|
| `entra.microsoft.com` | Entra admin portal |
| `aad.portal.azure.com` | Legacy AAD portal |
| `portal.azure.com` | Azure portal |
| `endpoint.microsoft.com` | Intune admin console |
| `security.microsoft.com` | Defender / Sentinel portal |

**Keep on public internet path (device enrollment):**

| Endpoint | Purpose |
|---|---|
| `enrollment.manage.microsoft.com` | Intune MDM enrollment |
| `EnterpriseEnrollment.<yourdomain>.com` | Auto-discovery |
| `device.login.microsoftonline.com` | Entra device registration |
| `enterpriseregistration.windows.net` | Hybrid join |
| `login.microsoftonline.com` | AAD authentication (all devices) |
| `ztd.dds.microsoft.com` | Autopilot Zero Touch |
| `cs.dds.microsoft.com` | Autopilot device provisioning |

### 3.3 Step-by-Step: Configure Entra Private Access for Admin Portals

**Step 1: Enable Global Secure Access in your tenant**

1. Navigate to: `Entra admin center → Global Secure Access → Get started`
2. Activate Global Secure Access for your tenant
3. Ensure Microsoft Entra Private Access and Microsoft Entra Internet Access licenses are assigned

**Step 2: Create a Private Access Application for Admin Portals**

1. Navigate to: `Entra admin center → Global Secure Access → Applications → Enterprise applications`
2. Click **New application → Private Access**
3. Configure:

| Field | Value |
|---|---|
| Name | `Admin Portals - Restricted Access` |
| Connector group | Your nearest connector group |

4. Add application segments:

```
Segment 1:
  FQDN: entra.microsoft.com
  Port: 443
  Protocol: HTTPS

Segment 2:
  FQDN: portal.azure.com
  Port: 443
  Protocol: HTTPS

Segment 3:
  FQDN: endpoint.microsoft.com
  Port: 443
  Protocol: HTTPS

Segment 4:
  FQDN: security.microsoft.com
  Port: 443
  Protocol: HTTPS
```

5. Under **Users and groups**, assign only your admin groups (not all users)

**Step 3: Deploy the GSA Client via Intune**

1. Navigate to: `Intune admin center → Apps → Windows → Add`
2. Select **Line-of-business app** or use the Microsoft Store version of the GSA client
3. Deploy to **All Devices** (required, not available)
4. This ensures GSA client is present on all managed devices before the Conditional Access policy enforces it

**Step 4: Create the Conditional Access Policy**

1. Navigate to: `Entra admin center → Protection → Conditional Access → New Policy`
2. Configure:

| Field | Value |
|---|---|
| Name | `REQUIRE - GSA Compliant Network for Admin Portals` |
| Users | Include: GA role, Intune Admin role, Security Admin role |
| Target resources | Microsoft Azure Management, Microsoft Intune, Microsoft Intune Enrollment |
| Network condition | **Not** Compliant Network (Global Secure Access) |
| Grant | Block |

```json
{
  "displayName": "REQUIRE - GSA Compliant Network for Admin Portals",
  "state": "enabled",
  "conditions": {
    "users": {
      "includeRoles": [
        "62e90394-69f5-4237-9190-012177145e10",
        "3a2c62db-5318-420d-8d74-23affee5d9d5",
        "194ae4cb-b126-40b2-bd5b-6091b380977d"
      ]
    },
    "applications": {
      "includeApplications": [
        "797f4846-ba00-4fd7-ba43-dac1f8f63013",
        "0000000a-0000-0000-c000-000000000000"
      ]
    },
    "locations": {
      "includeLocations": ["All"],
      "excludeLocations": ["AllCompliantNetwork"]
    }
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["block"]
  }
}
```

**Step 5: Add Device Compliance Requirement**

Layer a second policy on top:

```
Name: REQUIRE - Compliant Device for Admin Portals
Users: Same admin roles
Target resources: Same admin apps
Conditions: All platforms
Grant:
  - Require device to be marked compliant
  - Require Entra joined device
  - Operator: AND
```

---

### 3.4 Autopilot and New Device Bootstrapping

For organizations using Windows Autopilot:

1. Autopilot runs **before** the GSA client is installed, so ensure Autopilot endpoints stay on your public internet path and are not behind Private Access.
2. The GSA client is deployed **by Intune** as part of the device configuration profile. Enrollment happens first, then GSA lands, then the full lockdown kicks in.
3. The sequence: `OOBE → Autopilot → Intune Enrollment → GSA Client Deploy → Compliant Network signal active → Admin portals accessible`

For **Hybrid Entra Join** environments:
- Add your on-premises IP ranges as a **Named Location** in Conditional Access and mark it as trusted
- Exclude this named location from the GSA policy for the join registration process
- Once joined and compliant, devices fall under the full GSA policy

---

## 4. Locking Down Intune Device Wipe Capabilities

### 4.1 Roles That Can Wipe Devices

Understanding which roles have wipe capability is the first step:

| Role | Wipe Access | Scope |
|---|---|---|
| Global Administrator | Full factory wipe + retire + delete | Entire tenant |
| Intune Service Administrator | Full factory wipe + retire + delete | Entire tenant |
| Endpoint Security Manager | Full wipe | Entire tenant |
| Help Desk Operator | Selective wipe / retire | Assigned devices only |
| Policy and Profile Manager | None | N/A |
| Read Only Operator | None | N/A |
| **Custom Role** | Configurable | Configurable via scope tags |

The core problem is that **GA and Intune Service Administrator have no built-in scope limits**. They can touch every device in the tenant. That is exactly what Handala exploited.

### 4.2 Create a Dedicated Wipe Role with Minimum Permissions

Instead of relying on broad built-in roles, create a custom Intune role scoped to only what is needed:

**Step 1: Create the Custom Role**

1. Navigate to: `Intune admin center → Tenant administration → Roles → Create`
2. Name: `Device Wipe Operator - Restricted`
3. Under **Permissions**, enable only:

```
Managed Devices:
  ✅ Remote tasks - Wipe
  ✅ Remote tasks - Retire
  ✅ Remote tasks - Sync
  ✅ View reports
  ❌ Delete (keep separate)
  ❌ Update properties
  ❌ Assign (no profile changes)

All other categories: ❌ disabled
```

4. Save the role

**Step 2: Assign the Role with Scope Tags**

1. Navigate to the role → **Assignments** → Add assignment
2. Assign to a security group containing **maximum 3 named individuals**
3. Under **Scope (Groups)**, select only the device groups this team should manage
4. Under **Scope (Tags)**, assign relevant scope tags (e.g., "Region-EMEA")

An admin scoped to EMEA devices cannot see APAC or NA devices in their Intune console at all, let alone wipe them.

### 4.3 Implement Scope Tags by Region/Business Unit

Scope tags don't get nearly enough attention. They partition your device estate so that no single credential has tenant-wide destructive reach:

**Step 1: Create Scope Tags**

1. Navigate to: `Intune admin center → Tenant administration → Roles → Scope (Tags)`
2. Create tags:

```
Tag Name: Region-NorthAmerica
Tag Name: Region-EMEA
Tag Name: Region-APAC
Tag Name: BU-Manufacturing
Tag Name: BU-Clinical
Tag Name: Priority-Critical  (servers, clinical systems)
```

**Step 2: Apply Tags to Devices**

Use a dynamic device group + Intune policy to auto-assign scope tags based on device attributes (country, department, device name prefix, etc.)

**Step 3: Assign Scope Tags to Admin Roles**

When assigning the custom wipe role, restrict each assignment to relevant scope tags. A compromised regional IT admin account then has a limited blast radius, not access to 200,000 devices across 79 countries.

---

## 5. Multi-Admin Approval for Destructive Actions

This is the one control that could have stopped the wipe outright, even with valid admin credentials in hand. A single person cannot initiate and complete a device wipe without a second human approving it first.

### 5.1 How Multi-Admin Approval Works

```
Admin A → Initiates wipe on device(s)
            ↓
         Action enters "Pending Approval" state
         Device is NOT wiped yet
            ↓
         Admin B (approver) receives email notification
            ↓
         Admin B reviews: Who requested? Which devices? Justification?
            ↓
         Admin B Approves → Wipe executes
         Admin B Rejects  → Wipe cancelled, requestor notified
```

### 5.2 Step-by-Step: Configure Multi-Admin Approval

**Step 1: Create the Approver Security Group**

1. In Entra admin center, create a security group: `Intune-WipeApprovers`
2. Add 3–5 senior security/IT staff as members
3. **Critical:** Keep zero overlap with the group that can *request* wipes. An attacker who compromises one account should not be able to approve their own request.

**Step 2: Create the Access Policy**

1. Navigate to: `Intune admin center → Tenant administration → Multi Admin Approval → Access policies`
2. Click **Create**
3. Configure:

| Field | Value |
|---|---|
| Name | `Require Approval - Device Wipe and Retire` |
| Description | `All device wipe, retire, and delete actions require secondary approval` |
| Resource type | `Managed Devices` |
| Actions | `Wipe, Retire, Delete` |
| Approvers | `Intune-WipeApprovers` (security group) |
| Notification email | security-ops@contoso.com |

4. Save

**Step 3: Test the Policy**

1. Log in as a non-approver admin
2. Attempt to wipe a test device
3. Confirm the action enters "Pending" state and does NOT execute immediately
4. Log in as an approver and verify the approval notification and workflow
5. Approve the action and confirm it executes
6. Verify the audit log captures both the request and approval events

### 5.3 What MAA Protects and What It Doesn't

| Scenario | MAA Protection |
|---|---|
| Single compromised admin initiates mass wipe | ✅ Blocked, requires second approver |
| Insider threat from one malicious admin | ✅ Blocked, second human required |
| Accidental bulk wipe from misconfigured script | ✅ Blocked, human approval required |
| Attacker compromises BOTH a requestor and approver | ❌ Not covered here, pair with FIDO2 + GSA |
| Attacker with approver credentials approves their own wipe | ❌ Requires strict group separation |

MAA is a strong friction layer but it is not a standalone fix. It works best as part of the full stack described in this post.

---

## 6. KQL Hunting Queries and Sentinel Alerts

All queries below target **Microsoft Sentinel** using the `AuditLogs`, `SigninLogs`, `IntuneAuditLogs`, and `IdentityInfo` tables. Schedule each as an **Analytics Rule** with the severity and frequency noted.

---

### Query 1: New Global Administrator Role Assignment

**Risk:** Backdoor GA account creation, the most common attacker persistence technique in cloud tenants.

```kql
AuditLogs
| where OperationName == "Add member to role"
| where TargetResources[0].modifiedProperties has "Global Administrator"
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend TargetObjectId = tostring(TargetResources[0].id)
| extend RoleName = tostring(
    parse_json(tostring(TargetResources[0].modifiedProperties))
    [0].newValue)
| project TimeGenerated, InitiatedBy, TargetUser,
          TargetObjectId, RoleName, CorrelationId
| order by TimeGenerated desc
```

**Sentinel Rule Settings:**
- Severity: High
- Run frequency: Every 5 minutes
- Alert threshold: > 0 results
- MITRE: Persistence → T1098.003 (Account Manipulation: Additional Cloud Roles)

---

### Query 2: New Account Created and GA Assigned Within 1 Hour

**Risk:** This is exactly the persistence pattern used in the Stryker attack. Create a fresh account, immediately elevate it to GA, and it survives any password reset on the original compromised account.

```kql
let newAccounts = AuditLogs
| where OperationName == "Add user"
| project CreatedTime = TimeGenerated,
          NewUser = tostring(TargetResources[0].userPrincipalName),
          CreatedBy = tostring(InitiatedBy.user.userPrincipalName);
let gaAssignments = AuditLogs
| where OperationName == "Add member to role"
| where TargetResources[0].modifiedProperties has "Global Administrator"
| project AssignedTime = TimeGenerated,
          AssignedUser = tostring(TargetResources[0].userPrincipalName),
          AssignedBy = tostring(InitiatedBy.user.userPrincipalName);
newAccounts
| join kind=inner gaAssignments on $left.NewUser == $right.AssignedUser
| where (AssignedTime - CreatedTime) between (0min .. 60min)
| extend TimeDeltaMinutes = datetime_diff('minute', AssignedTime, CreatedTime)
| project NewUser, CreatedTime, CreatedBy, AssignedTime,
          AssignedBy, TimeDeltaMinutes
| order by TimeDeltaMinutes asc
```

**Sentinel Rule Settings:**
- Severity: **Critical**
- Run frequency: Every 5 minutes
- Alert threshold: > 0 results
- MITRE: Persistence → T1136.003 (Create Account: Cloud Account), T1098.003

---

### Query 3: Global Admin Sign-In from Non-Compliant or Unmanaged Device

**Risk:** A GA account signing in from outside your managed device estate. Could be an attacker on a personal machine or a BYOD device that never got enrolled in Intune.

```kql
let gaUsers = IdentityInfo
| where AssignedRoles has "Global Administrator"
| summarize by AccountUPN;
SigninLogs
| where UserPrincipalName in (gaUsers)
| where DeviceDetail.isCompliant == false
    or DeviceDetail.isManaged == false
    or isempty(DeviceDetail.deviceId)
| extend DeviceCompliant = tostring(DeviceDetail.isCompliant)
| extend DeviceManaged = tostring(DeviceDetail.isManaged)
| extend DeviceId = tostring(DeviceDetail.deviceId)
| extend OS = tostring(DeviceDetail.operatingSystem)
| project TimeGenerated, UserPrincipalName, IPAddress,
          Location, DeviceCompliant, DeviceManaged,
          DeviceId, OS, ConditionalAccessStatus, ResultType
| where ResultType == 0
| order by TimeGenerated desc
```

**Sentinel Rule Settings:**
- Severity: High
- Run frequency: Every 15 minutes
- MITRE: Initial Access → T1078 (Valid Accounts)

---

### Query 4: GA Sign-In from New Geography (First Seen in 30 Days)

**Risk:** A GA credential used from a country or region with no sign-in history. One of the cleaner indicators of account compromise.

```kql
let lookback = 30d;
let gaUsers = IdentityInfo
| where AssignedRoles has "Global Administrator"
| summarize by AccountUPN;
let historicalLocations = SigninLogs
| where TimeGenerated between (ago(lookback) .. ago(1d))
| where UserPrincipalName in (gaUsers)
| where ResultType == 0
| summarize HistoricCountries = make_set(Location) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(1d)
| where UserPrincipalName in (gaUsers)
| where ResultType == 0
| join kind=leftouter historicalLocations on UserPrincipalName
| where Location !in (HistoricCountries)
| project TimeGenerated, UserPrincipalName, IPAddress,
          Location, HistoricCountries, ConditionalAccessStatus
| order by TimeGenerated desc
```

**Sentinel Rule Settings:**
- Severity: High
- Run frequency: Every 1 hour
- MITRE: Initial Access → T1078.004 (Cloud Accounts)

---

### Query 5: Intune Bulk Device Wipe Detection

**Risk:** Mass wipe in progress. This is the Stryker attack signature. The alert fires if more than 10 wipe-class actions come from a single initiator within a 15-minute window.

```kql
IntuneAuditLogs
| where OperationName in (
    "Wipe",
    "RetireDevice",
    "DeleteDevice",
    "FactoryReset",
    "FreshStart",
    "RemoteLock"
  )
| extend Actor = tostring(Actor)
| extend TargetDevice = tostring(TargetObjectName)
| summarize
    ActionCount = count(),
    DeviceList = make_set(TargetDevice),
    Actions = make_set(OperationName)
    by bin(TimeGenerated, 15m), Actor
| where ActionCount > 10
| extend DeviceCount = array_length(DeviceList)
| project TimeGenerated, Actor, ActionCount,
          DeviceCount, Actions, DeviceList
| order by ActionCount desc
```

**Sentinel Rule Settings:**
- Severity: **Critical**
- Run frequency: Every 5 minutes
- Threshold: Tune the `> 10` value based on your environment's normal baseline
- MITRE: Impact → T1485 (Data Destruction), T1561 (Disk Wipe)

---

### Query 6: Intune Multi-Admin Approval Approved by Same Person Who Requested

**Risk:** A misconfigured access policy, or a compromised approver account used to rubber-stamp a destructive request from the same attacker.

```kql
IntuneAuditLogs
| where OperationName == "ApproveRequest"
| extend ApproverUPN = tostring(Actor)
| extend RequestId = tostring(CorrelationId)
| join kind=inner (
    IntuneAuditLogs
    | where OperationName == "CreateRequest"
    | where TargetObjectName in ("Wipe", "Retire", "Delete")
    | extend RequesterUPN = tostring(Actor)
    | extend RequestId = tostring(CorrelationId)
) on RequestId
| where ApproverUPN == RequesterUPN
| project TimeGenerated, ApproverUPN, RequesterUPN,
          RequestId, TargetObjectName
```

**Sentinel Rule Settings:**
- Severity: Critical
- Run frequency: Every 5 minutes
- Alert threshold: > 0 results (self-approval should never occur)

---

### Query 7: Break-Glass Account Activity

**Risk:** Break-glass accounts should never see activity outside a declared emergency. Any sign-in is a P1 event by default.

```kql
// Update the list below with your actual break-glass UPNs
let breakGlassAccounts = dynamic([
    "breakglass1@contoso.onmicrosoft.com",
    "breakglass2@contoso.onmicrosoft.com"
]);
SigninLogs
| where UserPrincipalName in (breakGlassAccounts)
| project TimeGenerated, UserPrincipalName, IPAddress,
          Location, ResultType, ResultDescription,
          ConditionalAccessStatus, DeviceDetail
| order by TimeGenerated desc
```

**Sentinel Rule Settings:**
- Severity: **Critical**
- Run frequency: Every 5 minutes
- Threshold: > 0 results
- Action: Immediate P1 page to security leadership

---

### Query 8: PIM Bypass, Direct GA Assignment Without Eligible Role Activation

**Risk:** If PIM is your gate for GA access, any direct active assignment that did not come through a PIM activation is a bypass. That means either a misconfiguration or an attacker who found a way around your controls.

```kql
AuditLogs
| where OperationName == "Add member to role"
| where TargetResources[0].modifiedProperties has "Global Administrator"
| where InitiatedBy !has "MS-PIM"
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, InitiatedBy, TargetUser,
          OperationName, CorrelationId
| order by TimeGenerated desc
```

**Sentinel Rule Settings:**
- Severity: High
- Run frequency: Every 5 minutes
- Threshold: > 0 results

---

## 7. Automated Response with Logic Apps

Detection without automated response is just logging. You need containment that works at 3am without someone on-call having to act. Here is a Logic App playbook that auto-disables an account when triggered by the "new account + GA assigned in 1 hour" Sentinel alert.

### 7.1 Logic App: Auto-Disable Suspicious New GA Account

**Trigger:** Microsoft Sentinel alert (connected via Sentinel Automation rule)

```
Trigger: When a Microsoft Sentinel incident is created
  ↓
Condition: Alert name contains "New Account GA Assigned"
  ↓
Action 1: Get account details from alert entities
  ↓
Action 2: HTTP POST to Microsoft Graph API
  PATCH https://graph.microsoft.com/v1.0/users/{userId}
  Body: { "accountEnabled": false }
  Auth: Managed Identity with User.ReadWrite.All
  ↓
Action 3: Add comment to Sentinel incident
  "Account {UPN} automatically disabled pending investigation.
   Disabled at: {timestamp}
   Triggered by: Auto-Response Playbook v1.0"
  ↓
Action 4: Send email to security-ops@contoso.com
  Subject: [AUTO-RESPONSE] GA Backdoor Account Disabled - {UPN}
  Body: Incident details + link to Sentinel incident
  ↓
Action 5: Post to Teams security channel
  Card: Incident details, affected account, action taken
```

**How to deploy:**

1. Navigate to: `Azure portal → Logic Apps → Create`
2. Use the **Blank Logic App** template
3. Add the trigger: `Microsoft Sentinel → When a response to a Microsoft Sentinel alert is triggered`
4. Grant the Logic App a **Managed Identity** with:
   - `User.ReadWrite.All` in Microsoft Graph
   - `Microsoft Sentinel Responder` role
5. In Sentinel: `Automation → Automation rules → Create`
   - Trigger: When incident is created
   - Condition: Alert name contains your rule name
   - Action: Run playbook → select your Logic App

---

## 8. Full Control Stack Summary

Here is the full picture, showing how each layer maps to the attack steps from Section 1:

```
╔══════════════════════════════════════════════════════════════════╗
║              STRYKER-PROOF MICROSOFT TENANT HARDENING            ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  LAYER 1 — IDENTITY                                              ║
║  ├─ FIDO2 hardware keys mandatory for all GA/privileged roles    ║
║  ├─ PIM: JIT elevation, 2hr max, approval required               ║
║  ├─ GA creation restricted to ≤3 named IAM admins               ║
║  └─ Break-glass accounts: vault stored, monitored 24/7           ║
║                                                                  ║
║  LAYER 2 — NETWORK / DEVICE                                      ║
║  ├─ Entra Private Access: admin portals behind GSA tunnel        ║
║  ├─ Conditional Access: compliant network signal required        ║
║  ├─ Conditional Access: Intune-compliant device required         ║
║  └─ Enrollment endpoints kept on public path (no deadlock)       ║
║                                                                  ║
║  LAYER 3 — INTUNE HARDENING                                      ║
║  ├─ Scope tags: partition device estate by region/BU             ║
║  ├─ Custom wipe role: minimum permissions, scoped to region      ║
║  ├─ Remove wipe permission from GA/Intune Admin where possible   ║
║  └─ BYOD review: audit personally enrolled devices               ║
║                                                                  ║
║  LAYER 4 — MULTI-ADMIN APPROVAL                                  ║
║  ├─ MAA policy on Wipe, Retire, Delete                           ║
║  ├─ Approver group: zero overlap with requestor group            ║
║  └─ Approvers protected by FIDO2 + GSA (same as GAs)            ║
║                                                                  ║
║  LAYER 5 — DETECTION                                             ║
║  ├─ Sentinel: New GA assignment (real-time)                      ║
║  ├─ Sentinel: New account + GA within 1 hour (critical)          ║
║  ├─ Sentinel: GA sign-in from unmanaged device                   ║
║  ├─ Sentinel: GA sign-in from new geography                      ║
║  ├─ Sentinel: Bulk wipe > 10 devices in 15 min                   ║
║  ├─ Sentinel: MAA self-approval detected                         ║
║  ├─ Sentinel: Break-glass account any sign-in                    ║
║  └─ Sentinel: PIM bypass — direct GA assignment                  ║
║                                                                  ║
║  LAYER 6 — AUTOMATED RESPONSE                                    ║
║  ├─ Logic App: Auto-disable suspicious GA account                ║
║  ├─ Logic App: Notify security team + Teams channel              ║
║  └─ Logic App: Add Sentinel incident comment                     ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  RESULT: Attacker with stolen GA credentials cannot              ║
║  authenticate (FIDO2), cannot reach the portal (GSA),            ║
║  cannot elevate (PIM), cannot wipe at scale (scope tags),        ║
║  cannot complete wipe alone (MAA), and is detected within        ║
║  minutes if any of the above is bypassed (Sentinel).             ║
╚══════════════════════════════════════════════════════════════════╝
```

### Licensing Requirements

| Control | Minimum License |
|---|---|
| FIDO2 authentication methods | Entra ID P1 |
| Conditional Access | Entra ID P1 |
| Privileged Identity Management | Entra ID P2 |
| Entra Private Access / GSA | Microsoft Entra Suite or standalone |
| Intune RBAC + Scope Tags | Microsoft Intune Plan 1 |
| Multi-Admin Approval | Microsoft Intune Plan 2 |
| Microsoft Sentinel | Microsoft Sentinel (PAYG or commitment tier) |
| Logic App Playbooks | Azure Logic Apps (consumption plan) |

---

## Closing Thoughts

The Stryker attack was not sophisticated. It was effective because the attacker found a high-powered weapon, Microsoft Intune, completely unguarded. The controls in this post are not cutting-edge research. They are production-ready, Microsoft-native, and available in licensing that most enterprise organizations already own.

If you run Intune at scale, especially in healthcare or critical infrastructure, none of this is optional hardening. It is the floor, not the ceiling.

Start with FIDO2 on all GA accounts and Multi-Admin Approval on wipe actions. Those two alone would have changed the outcome of the Stryker attack.

---

## References

### Incident Reporting (Public Sources)

> *The attack chain in this post is reconstructed from the sources below. No official attack chain has been released by Stryker or Microsoft. All technical inferences are for defensive educational purposes only.*

- [Stryker Official Statement — Customer Updates: Network Disruption (March 2026)](https://www.stryker.com/us/en/about/news/2026/a-message-to-our-customers-03-2026.html)
- [BleepingComputer — Stryker attack wiped tens of thousands of devices, no malware needed](https://www.bleepingcomputer.com/news/security/stryker-attack-wiped-tens-of-thousands-of-devices-no-malware-needed/)
- [KrebsOnSecurity — Iran-Backed Hackers Claim Wiper Attack on Medtech Firm Stryker](https://krebsonsecurity.com/2026/03/iran-backed-hackers-claim-wiper-attack-on-medtech-firm-stryker/)
- [Cybersecurity Dive — Stryker attack raises concerns about role of device management tool](https://www.cybersecuritydive.com/news/stryker-attack-device-management-microsoft-iran/814816/)
- [The Record (Recorded Future) — Stryker says hospital tools are safe, but digital ordering still down](https://therecord.media/stryker-cyberattack-impact-iran)
- [TechCrunch — Stryker says it's restoring systems after pro-Iran hackers wiped thousands of devices](https://techcrunch.com/2026/03/17/stryker-says-its-restoring-systems-after-pro-iran-hackers-wiped-thousands-of-employee-devices/)
- [Nextgov/FCW — Suspected pro-Iran hacker group tied to Stryker cyberattack](https://www.nextgov.com/cybersecurity/2026/03/suspected-pro-iran-hacker-group-tied-stryker-cyberattack/412050/)
- [Arctic Wolf — Stryker Systems Disrupted in Cyber Attack; Handala Group Claims Responsibility](https://arcticwolf.com/resources/blog/stryker-systems-disrupted-cyber-attack-handala-group-claims-responsibility/)
- [GovInfoSecurity — Medtech Firm Stryker Disrupted by Pro-Iran Hackers](https://www.govinfosecurity.com/medtech-firm-stryker-disrupted-by-pro-iran-hackers-a-30980)
- [ProArch — Stryker Cyberattack 2026: Lessons from a Global Wiper Attack](https://www.proarch.com/blog/threats-vulnerabilities/stryker-wiper-attack-analysis)
- [Chief Healthcare Executive — The Stryker cyberattack and what hospitals should be doing](https://www.chiefhealthcareexecutive.com/view/the-stryker-cyberattack-and-what-hospitals-should-be-doing)
- [Forrester — From Operating Rooms to iPhones: What the Stryker Attack Reveals About Third-Party Risk](https://www.forrester.com/blogs/from-operating-rooms-to-iphones-what-the-stryker-attack-reveals-about-third-party-risk/)

### Microsoft Documentation

- [Microsoft Intune Required Endpoints](https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints)
- [Entra Private Access — Concept Overview](https://learn.microsoft.com/en-us/entra/global-secure-access/concept-private-access)
- [Privileged Identity Management for Entra Roles](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure)
- [Multi Admin Approval in Intune](https://learn.microsoft.com/en-us/mem/intune/fundamentals/multi-admin-approval)
- [Conditional Access Authentication Strengths](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths)
- [FIDO2 Security Keys in Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless)
- [Intune Scope Tags and Role-Based Access Control](https://learn.microsoft.com/en-us/mem/intune/fundamentals/scope-tags)
- [Windows Autopilot Required Network Endpoints](https://learn.microsoft.com/en-us/autopilot/requirements?tabs=networking)
- [Entra ID Break Glass Accounts](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access)

---

*If this post helped your organization, consider sharing it with your security team. The controls described here are implementable in a weekend, and they could be the difference between a contained incident and a Stryker-scale disaster.*

*Questions or additions? Open an issue or pull request on GitHub.*

---
**© 2026. Licensed under MIT. Feel free to adapt and share.**
