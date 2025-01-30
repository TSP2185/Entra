# **Automatically Revoke User Tokens When Disabled in Entra ID**

Automatically revoking a user's **access token** when they are **disabled in Microsoft Entra ID (formerly Azure AD)** is crucial for enforcing security policies and preventing unauthorized access. Here's how you can achieve this:

---

## **1. Enable Conditional Access Policy for Sign-in Risk**
- Entra ID includes **Risk-based Conditional Access** that **blocks sign-ins** when risk is detected (e.g., disabled accounts).
- Go to **Microsoft Entra Admin Center** → **Security** → **Conditional Access**.
- Create a policy targeting **high-risk sign-ins** and set **"Block Access"**.

---

## **2. Use Continuous Access Evaluation (CAE)**
- **Microsoft Entra ID supports Continuous Access Evaluation (CAE)**, which **revokes tokens in near real-time** when user status changes.
- **How to Enable CAE:**
  1. Go to **Entra Admin Center** → **Identity** → **Security** → **Continuous Access Evaluation**.
  2. Ensure **CAE is enabled** for your tenant.
  3. Apps supporting **CAE** will automatically revoke user tokens when a user is **disabled**.

---

## **3. Use Microsoft Graph API to Revoke Tokens Upon Disablement**
- You can **force token revocation** immediately when a user is **disabled** using **Microsoft Graph API**.
- Use the following **PowerShell script** to automate this via **Microsoft Graph API**:

### **PowerShell Script to Revoke Tokens When User is Disabled**
```powershell
# Install Microsoft Graph PowerShell module if not already installed
Install-Module Microsoft.Graph -Scope CurrentUser

# Connect to Microsoft Graph with the required scope
Connect-MgGraph -Scopes "User.ReadWrite.All"

# Define the User Principal Name (UPN) or Object ID of the disabled user
$UserId = "user@yourdomain.com"  # Replace with the actual user email or object ID

# Disable the user in Entra ID
Update-MgUser -UserId $UserId -AccountEnabled $false

# Revoke all refresh tokens for the user
Revoke-MgUserSignInSession -UserId $UserId
```
This script **disables the user** and **revokes their tokens immediately**, logging them out from all active sessions.

---

## **4. Automate Token Revocation Using Entra ID Dynamic Groups + Logic Apps**
You can automate the process using **Microsoft Entra ID Dynamic Groups** and **Azure Logic Apps**:

- **Create a Dynamic Group in Entra ID** that automatically detects disabled users.
- **Trigger an Azure Logic App or Power Automate Flow** when a user enters this group.
- **Call the Microsoft Graph API** to revoke their tokens.

---

## **5. Enforce Sign-Out via Entra ID Portal**
As an admin, you can manually revoke a user’s session via:

1. **Go to Microsoft Entra ID** → **Users**.
2. **Select the disabled user**.
3. **Click on "Revoke Sessions"** to force sign-out.

---

## **Conclusion**
- **Best Practice**: Enable **CAE** for **automatic** real-time token revocation.
- **Immediate Action**: Use **Graph API** (`Revoke-MgUserSignInSession`) to force sign-outs.
- **Automate**: Set up **Entra ID Dynamic Groups + Azure Logic Apps** to trigger automatic revocation.

This ensures that **disabled users lose access instantly**, enhancing security and compliance. 🚀

Write-Output "User disabled and tokens revoked successfully!"
