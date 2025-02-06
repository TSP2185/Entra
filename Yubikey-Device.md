# **Restrict YubiKey Usage at the OS Level Using Intune and Certificate-Based Authentication**

## **Overview of the Process**
1. **Set Up Intune for Device Management**
2. **Enable Windows Hello for Business (WHfB) with Certificate-Based Authentication**
3. **Configure an Enterprise PKI for Certificate Issuance**
4. **Enroll YubiKey in PIV Mode and Issue a User Certificate**
5. **Bind the YubiKey to a Specific Device Using Intune & Conditional Access**
6. **Test Authentication & Restriction Enforcement**

---

## **1. Set Up Intune for Device Management**

### **Step 1: Enroll Devices in Intune**
1. Go to the **Microsoft Intune Admin Center**:  
   [https://intune.microsoft.com](https://intune.microsoft.com)
2. Navigate to **Devices > Windows > Enrollment**
3. Ensure the device enrollment method (Autopilot or manually) is enabled.
4. Assign a device compliance policy requiring **device compliance for authentication**.

---

## **2. Enable Windows Hello for Business with Certificate-Based Authentication**

### **Step 1: Enable CBA in Azure AD**
1. Go to **Azure AD Admin Center**:  
   [https://aad.portal.azure.com](https://aad.portal.azure.com)
2. Navigate to **Azure Active Directory > Security > Authentication Methods**.
3. Under **Certificate-Based Authentication**, select **Enable**.
4. Define authentication rules for CBA:
   - **User Binding**: Use **UPN** or **email address**.
   - **Certificate Issuance Policy**: Choose **Issuer DN** of your CA.
   - **Revocation Check**: Enable **OCSP** or **CRL**.

### **Step 2: Configure Intune Policy to Require Smart Card**
1. Go to **Intune Admin Center**.
2. Navigate to **Endpoint Security > Account Protection > Windows Hello for Business**.
3. Click **Create Policy** and set:
   - **Enable Windows Hello for Business**: **Yes**.
   - **Key Trust or Certificate Trust**: **Choose Certificate Trust**.
   - **Require Hardware-Backed TPM**: **Yes**.
   - **Allow Certificate Authentication Only**: **Yes**.
4. Assign the policy to **target users**.

---

## **3. Configure Enterprise PKI for Certificate Issuance**

### **Step 1: Set Up an Enterprise CA (If Not Already Configured)**
1. Install **AD Certificate Services** on a Windows Server:
   ```powershell
   Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
   ```
2. Configure the CA:
   ```powershell
   Install-AdcsCertificationAuthority -CAType EnterpriseRootCA
   ```
3. Issue a **User Authentication Certificate Template**.

### **Step 2: Create a Certificate Template for YubiKey (PIV)**
1. Open **Certification Authority** (certsrv.msc).
2. Right-click **Certificate Templates > Manage**.
3. Duplicate the **Smart Card Logon** template.
4. Set **Subject Name** to **User Principal Name (UPN)**.
5. Enable **Client Authentication & Smart Card Logon**.
6. Publish the template.

---

## **4. Enroll YubiKey in PIV Mode and Issue a User Certificate**

### **Step 1: Configure YubiKey for PIV Mode**
1. Download and install **YubiKey Manager** from [https://www.yubico.com/products/services-software/download/yubikey-manager/](https://www.yubico.com/products/services-software/download/yubikey-manager/).
2. Insert the YubiKey and open **YubiKey Manager**.
3. Navigate to **Applications > PIV**.
4. Click **Configure Certificates** and generate a **Certificate Signing Request (CSR)**.

### **Step 2: Issue a Certificate for YubiKey**
1. Submit the CSR to the Enterprise CA:
   ```powershell
   certreq -submit -attrib "CertificateTemplate:SmartCardLogon" path\to\csr.req
   ```
2. Download and install the issued certificate into **YubiKey PIV Slot 9a**.

---

## **5. Bind the YubiKey to a Specific Device Using Intune & Conditional Access**

### **Step 1: Create a Conditional Access Policy**
1. Go to **Azure AD Admin Center**.
2. Navigate to **Security > Conditional Access**.
3. Click **Create Policy** and set:
   - **Users or workload identities**: Target the **specific user or group**.
   - **Cloud apps or actions**: Select **Microsoft 365 or required application**.
   - **Conditions > Device platform**: Choose **Windows**.
   - **Grant Access**: Require **Require authentication strength** → **Certificate-based authentication**.
   - **Require compliant device**: **Enable**.

### **Step 2: Enforce Device Binding**
1. Enable **device compliance enforcement** in Intune:
   - Navigate to **Intune Admin Center**.
   - Go to **Devices > Compliance policies**.
   - Create a new policy requiring **device compliance for login**.
2. Ensure that **only enrolled devices can authenticate** with YubiKey:
   ```powershell
   Set-AzureADDevice -DeviceId <Device-ID> -Enabled $True -IsCompliant $True
   ```

---

## **6. Test Authentication & Restriction Enforcement**
1. Try logging into a non-enrolled device using the **YubiKey**.
2. If configured correctly, authentication should **fail** because the device is not registered.
3. Try logging into the **enrolled device**, and authentication should **succeed**.

---



Would you like additional **troubleshooting tips** or **PowerShell automation scripts** for bulk deployment? 🚀

