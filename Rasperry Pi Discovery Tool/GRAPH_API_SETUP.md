# Graph API Setup Guide

**Yeyland Wutani - Network Discovery Pi**

This guide walks you through creating the Azure App Registration needed for the Network Discovery Pi to send emails via Microsoft Graph API.

---

## Prerequisites

- Access to an **Azure Active Directory** tenant (Microsoft 365 admin or delegated access)
- A **Microsoft 365 licensed mailbox** to send reports from (the `from_email` address)
- Admin consent authority for the tenant (or ability to request it)

---

## Step 1: Access Azure Active Directory

1. Sign in to the [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** (search or left menu)
3. Select **App registrations** from the left sidebar

---

## Step 2: Create a New App Registration

1. Click **+ New registration**
2. Fill in:
   - **Name**: `NetworkDiscoveryPi` (or any descriptive name)
   - **Supported account types**: `Accounts in this organizational directory only (Single tenant)`
   - **Redirect URI**: Leave blank (not needed for client credentials flow)
3. Click **Register**
4. **Copy the following values** (you will need them for the installer):
   - **Application (client) ID** → this is your `client_id`
   - **Directory (tenant) ID** → this is your `tenant_id`

---

## Step 3: Create a Client Secret

1. In your newly created app registration, click **Certificates & secrets**
2. Click **+ New client secret**
3. Set a description (e.g., `NetworkDiscoveryPi-Secret`) and an expiry (24 months recommended)
4. Click **Add**
5. **Immediately copy the secret VALUE** (it will only be shown once)
   - This is your `client_secret`

> **Security Note:** Store this secret securely. Once you leave the page, it cannot be retrieved again.

---

## Step 4: Add API Permissions

1. Click **API permissions** in the left sidebar
2. Click **+ Add a permission**
3. Select **Microsoft Graph**
4. Select **Application permissions** (not Delegated—this runs headless)
5. Search for and add:
   - `Mail.Send` (under Mail)
6. Click **Add permissions**
7. Click **Grant admin consent for [Your Organization]**
8. Confirm by clicking **Yes**

The `Mail.Send` permission will now show a green checkmark with "Granted for [org]".

---

## Step 5: Configure the From Email Address

The `from_email` must be a **licensed Microsoft 365 user mailbox**. This is the address that will appear as the sender of all discovery reports.

Recommended approach:
- Create a dedicated shared mailbox: `discovery-pi@yourcompany.com`
- Or use an existing service account mailbox

> **Note:** The Graph API client credentials flow uses application permissions—the app sends mail *as* the specified user. The from_email account does **not** need to be signed in.

---

## Step 6: Verify Configuration

After running the installer, the configuration wizard will automatically test authentication. You can also test manually:

```bash
/opt/network-discovery/venv/bin/python3 /opt/network-discovery/bin/test-email.py
```

If authentication fails, check:
1. Tenant ID, Client ID, and Client Secret are correct in `config.json`
2. `Mail.Send` permission is added **and admin consent was granted**
3. The `from_email` is a valid, licensed M365 mailbox in the same tenant
4. The app registration is not disabled or expired

---

## Troubleshooting Authentication

| Error | Likely Cause |
|-------|-------------|
| `AADSTS700016` | Invalid client ID or wrong tenant |
| `AADSTS7000215` | Invalid client secret (wrong value or expired) |
| `AADSTS650057` | `Mail.Send` permission not added or admin consent not granted |
| `Authorization_RequestDenied` | Admin consent not granted or wrong permission type |
| `ErrorSendAsDenied` | `from_email` mailbox not in tenant or not licensed |

---

## Client Secret Rotation

Client secrets expire. To rotate:
1. In Azure Portal → App registrations → Your app → Certificates & secrets
2. Create a new secret **before** the old one expires
3. Run `sudo /opt/network-discovery/bin/update-config.sh` to update the secret
4. Verify with the test-email script
5. Delete the old secret in Azure

---

*Yeyland Wutani LLC — IT Consulting & Cybersecurity Services*
