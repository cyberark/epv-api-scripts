# Personal Privileged Accounts

Automates the creation of personal privileged safes and account onboarding in CyberArk via the v2 REST API. Works with both on-premises vaults and Privilege Cloud.

## What it does

For each row in a CSV, the main script:

1. Creates a personal safe for the user (skips if it already exists)
2. Adds the user as safe owner plus any configured default members
3. Bulk-onboards the account via the CyberArk Bulk Accounts API

## Files

| File | Description |
| --- | --- |
| `Create-PersonalPrivilgedAccounts.ps1` | Main script |
| `Edit-PersonalPrivilegedAccountsConfig.ps1` | Create, update, and validate the JSON config file |
| `PersonalPrivilegedAccounts.json` | Example config — on-premises |
| `PersonalPrivilegedAccounts-PCloud.json` | Example config — Privilege Cloud |
| `sample_personal_accounts.csv` | Example CSV with all supported columns |
| `Test-PersonalPrivilgedAccounts.ps1` | End-to-end test runner |
| `Test-PersonalPrivilgedAccountsConfig.ps1` | Config validation script |
| `Test-PersonalPrivilgedAccounts.json` | Fixture config for the E2E test runner |
| `Test-PersonalPrivilgedAccounts.csv` | Fixture CSV for the E2E test runner |
| `Test-PersonalPrivilgedAccounts.md` | E2E test plan and assertion table |

## Quick start

```powershell
# On-premises — interactive
$params = @{
    PVWAURL = 'https://pvwa.company.com/PasswordVault'
    CSVPath = '.\accounts.csv'
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

```powershell
# Privilege Cloud — pre-obtained token
$PCloudURL = 'https://tenant.privilegecloud.cyberark.cloud/PasswordVault'
$token = Get-IdentityHeader -IdentityUserName 'user@company.com' -PCloudURL $PCloudURL

$params = @{
    PVWAURL    = $PCloudURL
    logonToken = $token
    CSVPath    = '.\accounts.csv'
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

## Requirements

- PowerShell 5.1+
- CyberArk PVWA v12.1+ (v2 REST API)
- Vault account with permission to create safes and add safe members

## Documentation

| Document | Contents |
| --- | --- |
| [INSTALL.md](INSTALL.md) | Prerequisites, permissions, config setup, first run |
| [USER-GUIDE.md](USER-GUIDE.md) | CSV format, config sets, common scenarios, automation |
| [REFERENCE.md](REFERENCE.md) | All parameters, full config schema, permission tables |
