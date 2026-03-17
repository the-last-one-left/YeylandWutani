# Microsoft Graph API Setup — Azure App Registration

**Yeyland Wutani LLC** | *Building Better Systems*

---

The Risk Scanner uses the Microsoft Graph API (client credentials flow) to send
email reports. This requires a one-time Azure App Registration with `Mail.Send`
application permission.

This is the same setup used by the Yeyland Wutani Network Discovery Tool — if that
tool is already deployed on this tenant, you can reuse the existing App Registration
(see [Sharing One App Registration for Both Tools](#sharing-one-app-registration-for-both-tools)).

---

## Prerequisites

- An Azure AD tenant — included with any Microsoft 365 subscription
- **Global Administrator** or **Application Administrator** role in that tenant
- The sending mailbox must exist in the tenant (a licensed user mailbox or a shared mailbox — see the [Shared Mailbox Option](#shared-mailbox-option-recommended) below)
- The admin who grants consent must have the appropriate role — if you are the MSP technician, ensure you have delegated admin access or ask the client's M365 admin to grant consent

---

## Step 1: Create the App Registration

1. Sign in to the [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** (search for it in the top bar)
3. In the left sidebar, click **App registrations**
4. Click **+ New registration**
5. Fill in the registration form:
   - **Name**: `YW Risk Scanner` (or `YW Network Scanner` for the Discovery Tool — pick a name that identifies both the tool and your organization)
   - **Supported account types**: `Accounts in this organizational directory only (Single tenant)`
   - **Redirect URI**: Leave blank — this is not needed for the client credentials flow
6. Click **Register**
7. On the Overview page that appears, copy and save:
   - **Application (client) ID** — this is your `client_id`
   - **Directory (tenant) ID** — this is your `tenant_id`

---

## Step 2: Create a Client Secret

1. In your new app registration, click **Certificates & secrets** in the left sidebar
2. Click **+ New client secret**
3. Fill in the form:
   - **Description**: `Risk Scanner Production`
   - **Expiry**: `24 months` (recommended — see note below)
4. Click **Add**
5. **Immediately copy the Value field** — it is shown only once. After you navigate away, the full value cannot be retrieved again.

This value is your `client_secret`.

> **Set a calendar reminder now** for 23 months from today to rotate this secret before it expires. An expired secret will cause all email sends to fail silently until the config is updated. See [Client Secret Rotation](#client-secret-rotation) below.

---

## Step 3: Add the Mail.Send Permission

1. In the app registration, click **API permissions** in the left sidebar
2. Click **+ Add a permission**
3. Select **Microsoft Graph**
4. Select **Application permissions** (not Delegated — the scanner runs headless with no signed-in user)
5. In the search box, type `Mail.Send`
6. Check the box next to **Mail.Send** (under the Mail section)
7. Click **Add permissions**

**The permission is not yet active.** You must grant admin consent:

8. Back on the API permissions page, click **Grant admin consent for {your organization name}**
9. Click **Yes** to confirm

The `Mail.Send` row should now show a green checkmark and "Granted for {org}". If it still shows a yellow warning icon, admin consent was not completed — do not proceed until this is resolved.

---

## Step 4: Collect Your Credentials

From the app registration **Overview** page, collect the following four values. You will enter these into the installer wizard or `config.json`:

| Config Key | Where to Find It |
|---|---|
| `tenant_id` | "Directory (tenant) ID" on the Overview page |
| `client_id` | "Application (client) ID" on the Overview page |
| `client_secret` | The Value you copied in Step 2 |
| `from_email` | The email address of the mailbox the scanner sends FROM |
| `to_email` | The email address where reports should be delivered |

The `from_email` must be a mailbox that exists in the same Azure AD tenant. It does not need to be signed in or have an active user session — the scanner sends mail on behalf of the mailbox using application permissions.

---

## Step 5: Add to config.json

The installer wizard prompts for all of these values interactively. If configuring manually, add this block to `/opt/risk-scanner/config/config.json`:

```json
"graph_api": {
    "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_secret": "your-secret-value-here",
    "from_email": "scanner@yourdomain.com",
    "to_email": "admin@yourdomain.com",
    "cc_emails": []
}
```

After editing, reset the file permissions:

```bash
sudo chmod 640 /opt/risk-scanner/config/config.json
sudo chown risk-scanner:risk-scanner /opt/risk-scanner/config/config.json
```

---

## Shared Mailbox Option (Recommended)

Using a shared mailbox as the `from_email` is the recommended approach. Shared mailboxes do not require a Microsoft 365 license in most M365 plans (Business Basic, Business Standard, Business Premium, and Exchange Online plans all include shared mailboxes at no additional cost).

Create a shared mailbox in the **Exchange Admin Center**:

1. Navigate to [admin.exchange.microsoft.com](https://admin.exchange.microsoft.com)
2. Go to **Recipients → Mailboxes**
3. Click **+ Add a shared mailbox**
4. Fill in:
   - **Display name**: `Risk Scanner` (or `YW Risk Scanner`)
   - **Email address**: `scanner@yourdomain.com` (or `risk-scanner@yourdomain.com`)
5. Click **Save**

Set `from_email` to this address in `config.json`. No license needs to be assigned to the shared mailbox for the Graph API `Mail.Send` application permission to work.

---

## Verifying the Setup

After configuring `config.json`, test the Graph API connection by sending the initial check-in email:

```bash
sudo -u risk-scanner /opt/risk-scanner/venv/bin/python /opt/risk-scanner/bin/initial-checkin.py
```

Check the output and the log file if it fails:

```bash
tail -50 /opt/risk-scanner/logs/initial-checkin.log
```

### Common Errors and Resolutions

| Error | Likely Cause | Resolution |
|---|---|---|
| `AADSTS700016` | Wrong tenant ID or client ID | Verify both values on the app registration Overview page |
| `AADSTS7000215` | Wrong or expired client secret | Re-copy the secret value; rotate if expired |
| `AADSTS650057` | `Mail.Send` not added or consent not granted | Complete Step 3; ensure admin consent shows a green checkmark |
| `Authorization_RequestDenied` | Delegated (not Application) permission was added, or consent not granted | Ensure "Application permissions" was selected in Step 3, not "Delegated permissions" |
| `ErrorSendAsDenied` | `from_email` is not in this tenant, or is deleted/disabled | Verify the from_email mailbox exists and is active in the same Azure AD tenant |

---

## Client Secret Rotation

Client secrets expire. An expired secret causes all email sends to fail. To rotate before expiry:

1. In Azure Portal → App registrations → YW Risk Scanner → **Certificates & secrets**
2. Create a **new** client secret with a new description and 24-month expiry
3. **Copy the new Value immediately**
4. Update the config on the Pi:
   ```bash
   sudo /opt/risk-scanner/bin/update-config.sh
   ```
   Enter the new client secret when prompted.
5. Verify with a test send:
   ```bash
   sudo -u risk-scanner /opt/risk-scanner/venv/bin/python /opt/risk-scanner/bin/initial-checkin.py
   ```
6. After confirming the new secret works, return to Azure Portal and **delete the old secret**

---

## Sharing One App Registration for Both Tools

If both the **Network Discovery Tool** and the **Risk Scanner** are deployed on the same tenant (or by the same MSP for the same client), they can share a single Azure App Registration.

- The same `tenant_id`, `client_id`, and `client_secret` work for both tools
- Each tool has its own `config.json` with its own `from_email` and `to_email` — these can be the same or different addresses
- A single `Mail.Send` permission and admin consent grant covers both tools
- Credential rotation only needs to happen in one place in Azure Portal, but must be updated in both tools' `config.json` files

If deploying both tools, naming the App Registration something neutral like `YW Scanners` or `YW MSP Tools` is recommended so it is clearly associated with all Yeyland Wutani tools on that tenant.

---

*Yeyland Wutani LLC — IT Consulting & Cybersecurity Services*
*See also: [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for Graph API error resolution*
