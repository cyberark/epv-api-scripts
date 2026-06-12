# Installation Guide — Personal Privileged Accounts

This guide takes you from nothing to a successful first run.

## Prerequisites

| Requirement | Details |
| --- | --- |
| PowerShell | 5.1 or later |
| CyberArk PVWA | v12.1 or later (v2 REST API required) |
| Network access | The machine running the script must reach the PVWA URL on HTTPS |
| Vault permissions | See Step 2 below |

## Step 1 — Get the scripts

Clone or download the repository and locate the `Personal Privileged Accounts` folder:

```powershell
git clone https://github.com/cyberark/epv-api-scripts.git
Set-Location '.\epv-api-scripts\Personal Privileged Accounts'
```

If you do not have Git, download the ZIP from GitHub and extract it. The scripts do not require installation — they run directly from the folder.

## Step 2 — Vault permissions

The vault account used to run the script needs the following:

- **Add Safes** — to create personal safes
- **Manage Safe Members** on any safe it will modify — to add members after creation

On-premises: grant these permissions directly to the vault user or to a group it belongs to.

Privilege Cloud: the service account or user must be a member of the **Privilege Cloud Administrators** role, or a custom role with equivalent permissions.

## Step 3 — Create a config file

Copy the appropriate example file and edit it to match your environment.

**On-premises:**

```powershell
Copy-Item .\PersonalPrivilegedAccounts.json .\MyConfig.json
```

**Privilege Cloud:**

```powershell
Copy-Item .\PersonalPrivilegedAccounts-PCloud.json .\MyConfig.json
```

Open `MyConfig.json` and update:

- `CPMName` — the name of your CPM (e.g. `PasswordManager`). Leave blank for SRS accounts on PCloud.
- `SafeNamePattern` — the pattern for personal safe names (e.g. `*_ADM`). The `*` is replaced with the `userName` value from the CSV.
- `DefaultSafeMembers` — the groups or users added to every safe. Replace the example names with your actual vault groups.
  - On-premises: set `SearchIn` to the name of your vault directory (usually `"Vault"` for built-in groups, or the LDAP directory name for domain groups).
  - Privilege Cloud: set `SearchIn` to the GUID of your Identity directory. Find it in Identity Administration under **Directories**. Set `MemberType` to `"Role"` for Identity roles/groups or `"User"` for individual vault users.

The easiest way to make changes is with the `Edit-PersonalPrivilegedAccountsConfig.ps1` script (see [USER-GUIDE.md](USER-GUIDE.md)). To validate the file after editing:

```powershell
$params = @{
    FilePath  = '.\MyConfig.json'
    Operation = 'Validate'
}
.\Edit-PersonalPrivilegedAccountsConfig.ps1 @params
```

## Step 4 — Prepare a CSV

Copy the sample and replace the data with real users:

```powershell
Copy-Item .\sample_personal_accounts.csv .\accounts.csv
```

Open `accounts.csv` and fill in at minimum:

| Column | Notes |
| --- | --- |
| `userName` | The vault username of the account owner |
| `accountAddress` | The target address / domain for the account |
| `accountPlatform` | The platform ID to assign (must exist in your vault) |

Leave all other columns blank to use the defaults from your config file. See [USER-GUIDE.md](USER-GUIDE.md) for a full column reference.

## Step 5 — First run

### On-premises (interactive — prompts for credentials)

```powershell
$params = @{
    PVWAURL    = 'https://pvwa.company.com/PasswordVault'
    ConfigPath = '.\MyConfig.json'
    CSVPath    = '.\accounts.csv'
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

### On-premises with credentials supplied

```powershell
$params = @{
    PVWAURL         = 'https://pvwa.company.com/PasswordVault'
    ConfigPath      = '.\MyConfig.json'
    CSVPath         = '.\accounts.csv'
    PVWACredentials = (Get-Credential)
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

### Privilege Cloud

```powershell
# Obtain a token first (requires the Identity module from epv-api-scripts)
$PCloudURL = 'https://tenant.privilegecloud.cyberark.cloud/PasswordVault'
$token = Get-IdentityHeader -IdentityUserName 'admin@company.com' -PCloudURL $PCloudURL

$params = @{
    PVWAURL    = $PCloudURL
    logonToken = $token
    ConfigPath = '.\MyConfig.json'
    CSVPath    = '.\accounts.csv'
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

If the script completes without errors, verify in the vault that the safes and accounts were created. Check the log file (written to the script directory by default) if any rows were skipped or failed.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `401 Unauthorized` | Wrong credentials or the account does not have API access |
| `403 Forbidden` on safe creation | Vault user is missing the **Add Safes** permission |
| `403 Forbidden` on member add | Vault user is not a member of the safe with **Manage Safe Members** |
| `Config set not found` | The `-SafeConfigSet` / `-UserConfigSet` value does not exist in the JSON file |
| `accountAddress is required` | The CSV row has no `accountAddress` and the config has no `accountAddress` default |
| SSL errors | Add `-DisableCertificateValidation` for test environments with self-signed certs |

## Next steps

- [USER-GUIDE.md](USER-GUIDE.md) — how to use the scripts day-to-day
- [REFERENCE.md](REFERENCE.md) — full parameter and config schema reference
