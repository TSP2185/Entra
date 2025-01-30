## **Automate Token Revocation Using Microsoft Entra ID Dynamic Groups and Azure Logic Apps**

You can automate the process using **Microsoft Entra ID Dynamic Groups** and **Azure Logic Apps** to ensure immediate token revocation when a user is disabled.

### **Steps to Automate Token Revocation**
1. **Create a Dynamic Group in Entra ID**  
   - Navigate to **Microsoft Entra Admin Center** → **Groups**.
   - Click **"New group"** and select **"Dynamic User"** as the group type.
   - Define the **membership rule** to automatically detect disabled users:
     ```plaintext
     (user.accountEnabled -eq false)
     ```
   - Save and create the dynamic group.

2. **Trigger an Azure Logic App or Power Automate Flow**  
   - Create a new **Azure Logic App** or **Power Automate Flow**.
   - Set the **trigger** to monitor changes in the dynamic group.
   - Configure it to **run when a user is added** to the disabled users group.

3. **Call the Microsoft Graph API to Revoke Tokens**  
   - Use the **"HTTP"** action in Logic Apps to send a request to **Microsoft Graph API**:
     ```http
     POST https://graph.microsoft.com/v1.0/users/{userId}/revokeSignInSessions
     ```
   - Authenticate using **Azure AD App Registration** with appropriate permissions (`User.ReadWrite.All`).
   - Execute the API call to **revoke all active user sessions**.

---

### **Outcome**
With this setup, whenever a user is **disabled in Entra ID**, their tokens are **automatically revoked** in real-time, preventing unauthorized access. 🚀
