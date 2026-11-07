# Connecting AccessGuard to Microsoft Entra ID

AccessGuard reads your tenant through Microsoft Graph using an **app registration with read-only application permissions**. Setting it up takes about ten minutes and needs someone who can grant admin consent (Privileged Role Administrator or Global Administrator).

You can use the PowerShell script (fastest) or the Entra admin center.

---

## Option A — PowerShell script

Requires the Microsoft Graph PowerShell SDK (`Install-Module Microsoft.Graph -Scope CurrentUser`).

```powershell
./scripts/setup-entra-app.ps1
# or, with a shorter secret lifetime:
./scripts/setup-entra-app.ps1 -SecretMonths 3
```

The script:

1. creates an app registration called **AccessGuard (read-only)**, single-tenant;
2. adds the six read-only Microsoft Graph application permissions listed below, resolving each by name rather than by hard-coded ID;
3. grants admin consent for those permissions only;
4. creates a client secret (6 months by default) and prints the values for your `.env` file.

Read the script before running it — it is short, and it only writes to the app registration it creates.

## Option B — Entra admin center

1. Go to **Entra admin center → Identity → Applications → App registrations → New registration**.
   - Name: `AccessGuard (read-only)`
   - Supported account types: **Accounts in this organizational directory only**
   - Leave the redirect URI empty → **Register**.
2. Copy the **Application (client) ID** and **Directory (tenant) ID** from the overview page.
3. Open **API permissions → Add a permission → Microsoft Graph → Application permissions** and add:

   | Permission | Why |
   |---|---|
   | `User.Read.All` | Users, account status and hybrid-sync flag |
   | `Directory.Read.All` | Organisation details, tenant-wide consent grants, directory objects |
   | `AuditLog.Read.All` | Sign-in activity and the MFA registration report |
   | `RoleManagement.Read.Directory` | Directory role definitions and assignments |
   | `Application.Read.All` | App registrations, credentials, owners and app permissions |
   | `UserAuthenticationMethod.Read.All` | MFA registration details |

   Make sure you choose **Application permissions**, not delegated. Remove the default delegated `User.Read` permission if you like — AccessGuard does not use it.
4. Click **Grant admin consent for <your tenant>** and confirm every permission shows *Granted*.
5. Add a credential under **Certificates & secrets**:
   - **Certificate (recommended):** upload the public key (`.cer`/`.pem`). Put the private key PEM path in `AZURE_CLIENT_CERT_PATH` and the thumbprint in `AZURE_CLIENT_CERT_THUMBPRINT`.
   - **Client secret:** set an expiry of 6 months or less and copy the *Value* (not the Secret ID) into `AZURE_CLIENT_SECRET`.

## Configure and verify

```bash
cp .env.example .env    # then fill in the three or four AZURE_ values
accessguard check-permissions
accessguard scan
```

`check-permissions` lists the permissions in the token, anything missing, and anything **unnecessary** that you should remove to keep the scanner least-privilege.

## Licensing notes

- **Sign-in activity** (dormant-account checks) and the **MFA registration report** need Entra ID P1 or P2. Without them AccessGuard skips those checks and tells you so in the dashboard and report.
- Newly created accounts can take a little while to appear in sign-in activity; brand-new accounts get a grace period (`ACCESSGUARD_NEVER_SIGNED_IN_GRACE_DAYS`, 30 days by default).

## Hardening the app registration

- Assign two **owners** to the app registration so it never becomes an orphan (AccessGuard would flag it under AG-012).
- Rotate the credential before it expires (AG-010 will remind you).
- Consider a Conditional Access policy for workload identities (Entra Workload ID licence) to restrict where the app can sign in from.
- Store `.env` securely and never commit it — it is in `.gitignore` already.

## Removing AccessGuard

Delete the app registration. Then delete the `data/` folder (or the Docker volume), which holds your scan snapshots.
