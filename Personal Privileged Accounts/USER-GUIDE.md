# User Guide — Personal Privileged Accounts

This guide covers day-to-day use: populating a CSV, selecting config sets, common scenarios, and running with automation.

## How it works

`Create-PersonalPrivilgedAccounts.ps1` processes one row per user. For each row it:

1. Determines the safe name from `SafeNamePattern` (replaces `*` with `userName`)
2. Creates the safe if it does not exist, using settings from the active `SafeConfigSet`
3. Adds the CSV user as safe owner and any `DefaultSafeMembers` from the config
4. Onboards the account using settings from the active `UserConfigSet` (skipped when `createSafeOnly` is set)

The script is idempotent — rows for safes and members that already exist are skipped without error.

## Preparing the CSV

Start from the sample:

```powershell
Copy-Item .\sample_personal_accounts.csv .\accounts.csv
```

### Required columns

| Column | Description |
| --- | --- |
| `userName` | Vault username of the account owner |
| `accountAddress` | Target address or domain (can be set as a default in `UserConfigSet` instead) |
| `accountPlatform` | Platform ID — must exist in the vault |

### Optional columns

| Column | Description |
| --- | --- |
| `SafeConfigSet` | Override the active `SafeConfigSet` for this row |
| `UserConfigSet` | Override the active `UserConfigSet` for this row |
| `SafeNamePattern` | Override the safe name pattern for this row (e.g. `*_PRIV`) |
| `safeName` | Explicit safe name (skips the pattern entirely) |
| `CPMName` | Override the CPM for this row |
| `NumberOfDaysRetention` | Override day-based retention for this row |
| `NumberOfVersionsRetention` | Override version-based retention for this row |
| `accountUser` | Account username (defaults to `userName` or the pattern in `UserConfigSet`) |
| `password` | Initial password; leave blank to let CPM set it |
| `enableAutoMgmt` | `yes` or `no` |
| `manualMgmtReason` | Required when `enableAutoMgmt` is `no` |
| `remoteMachineAddresses` | Semicolon-separated list of allowed remote machines |
| `restrictMachineAccessToList` | `yes` or `no` |
| `networkId` | PCloud + SRS only — connector ID for Secrets Rotation Service |
| `createSafeOnly` | `yes` or `no` — create safe and add members but skip account onboarding |

Any extra column (e.g. `logonDomain`, `database`) is automatically passed as a platform account property.

### Example CSV

```csv
userName,accountAddress,accountPlatform,SafeConfigSet
jsmith,corp.example.com,WinDomain,prod
abrown,corp.example.com,WinDomain,prod
dbadmin,db.example.com,Oracle,dev
```

## Config sets

`PersonalPrivilegedAccounts.json` has named sets for `SafeConfigSet` and `UserConfigSet`. Named sets merge on top of `default`, so you only need to specify what changes.

Config layering (lowest priority to highest):

1. Script baseline defaults
2. `default` set in the JSON
3. Named set (selected by `-SafeConfigSet` / `-UserConfigSet` parameter or per CSV row)
4. Explicit CSV columns (always win for that row)
5. Explicit CLI parameters (always win for the whole run)

To select a named set for the whole run:

```powershell
$params = @{
    PVWAURL       = 'https://pvwa.company.com/PasswordVault'
    CSVPath       = '.\accounts.csv'
    SafeConfigSet = 'prod'
    UserConfigSet = 'prod'
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

To override per row, set the `SafeConfigSet` and/or `UserConfigSet` columns in the CSV.

### Managing config sets

Use `Edit-PersonalPrivilegedAccountsConfig.ps1` to add or update sets without editing JSON by hand.

**Add a SafeConfigSet named `prod`:**

```powershell
$params = @{
    FilePath              = '.\PersonalPrivilegedAccounts.json'
    Operation             = 'Set'
    ConfigSetType         = 'SafeConfigSet'
    SetName               = 'prod'
    CPMName               = 'PasswordManager_Prod'
    NumberOfDaysRetention = 30
    SafeNamePattern       = '*_PROD'
}
.\Edit-PersonalPrivilegedAccountsConfig.ps1 @params
```

**Add a UserConfigSet named `dev`:**

```powershell
$params = @{
    FilePath           = '.\PersonalPrivilegedAccounts.json'
    Operation          = 'Set'
    ConfigSetType      = 'UserConfigSet'
    SetName            = 'dev'
    AccountUserPattern = '*_adm'
    AccountPlatform    = 'WinDomain'
    AccountAddress     = 'dev.corp.com'
    EnableAutoMgmt     = 'no'
    ManualMgmtReason   = 'Managed externally'
}
.\Edit-PersonalPrivilegedAccountsConfig.ps1 @params
```

**Validate the config file:**

```powershell
.\Edit-PersonalPrivilegedAccountsConfig.ps1 -FilePath .\PersonalPrivilegedAccounts.json -Operation Validate
```

## Common scenarios

### Create safes only (no account onboarding)

Use `-CreateSafeOnly` for the whole run, or set `createSafeOnly=yes` per row:

```powershell
$params = @{
    PVWAURL        = 'https://pvwa.company.com/PasswordVault'
    CSVPath        = '.\accounts.csv'
    CreateSafeOnly = $true
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

### Override CPM and retention for one run

```powershell
$params = @{
    PVWAURL                   = 'https://pvwa.company.com/PasswordVault'
    CSVPath                   = '.\accounts.csv'
    CPMName                   = 'PasswordManager_DR'
    NumberOfVersionsRetention = 10
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

### Allow duplicate accounts

By default the script skips a row if an account with the same `userName`, `address`, and `platformId` already exists in the safe. Pass `-AllowDuplicateAccounts` to onboard anyway:

```powershell
$params = @{
    PVWAURL                = 'https://pvwa.company.com/PasswordVault'
    CSVPath                = '.\accounts.csv'
    AllowDuplicateAccounts = $true
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

### Platform-specific properties

Add extra columns to the CSV for any platform account property (e.g. `logonDomain`). They are passed directly to the vault:

```csv
userName,accountAddress,accountPlatform,logonDomain
jsmith,corp.example.com,WinDomain,CORP
```

## Running with automation

### On-premises — scheduled task

Store credentials in a secure credential file or Windows Credential Manager, then call the script from a scheduled task or CI pipeline.

**Option A — PSCredential from an encrypted file:**

```powershell
# One-time setup (run as the service account):
$cred = Get-Credential
$cred | Export-Clixml -Path 'C:\Scripts\pvwa_cred.xml'
```

```powershell
# Scheduled task script:
$cred   = Import-Clixml -Path 'C:\Scripts\pvwa_cred.xml'
$params = @{
    PVWAURL         = 'https://pvwa.company.com/PasswordVault'
    ConfigPath      = 'C:\Scripts\PersonalPrivilegedAccounts.json'
    CSVPath         = 'C:\Scripts\accounts.csv'
    PVWACredentials = $cred
    SafeConfigSet   = 'prod'
    UserConfigSet   = 'prod'
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

> `Export-Clixml` encrypts the password using the Windows Data Protection API (DPAPI). The file can only be decrypted by the same user account on the same machine.

**Option B — Reuse a session token across multiple scripts:**

If you run several CyberArk scripts in one pipeline, log on once and pass the token to each:

```powershell
# Logon once
$authParams = @{
    Uri         = 'https://pvwa.company.com/PasswordVault/API/Auth/cyberark/Logon'
    Method      = 'POST'
    Body        = (@{ username = $env:CYB_USER; password = $env:CYB_PASS } | ConvertTo-Json)
    ContentType = 'application/json'
}
$token = (Invoke-RestMethod @authParams).Trim('"')

# Pass the token to the script — no logon/logoff overhead
$params = @{
    PVWAURL    = 'https://pvwa.company.com/PasswordVault'
    logonToken = $token
    CSVPath    = '.\accounts.csv'
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

### On-premises — Credential Provider (CP)

If the CyberArk Credential Provider agent is installed on the server running the script, use `CLIPasswordSDK.exe` to retrieve the PVWA service account password at runtime without storing it anywhere:

```powershell
$sdkArgs = @(
    'GetPassword'
    '/p', 'AppDescs.AppID=PPAAutomation'
    '/p', 'Query=Safe=PPASafe;Object=PVWAServiceAccount'
    '/o', 'Password'
)
$password = & 'C:\Program Files (x86)\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe' @sdkArgs

$securePass = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('pvwasvc', $securePass)

$params = @{
    PVWAURL         = 'https://pvwa.company.com/PasswordVault'
    PVWACredentials = $cred
    CSVPath         = '.\accounts.csv'
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

> The AppID (`PPAAutomation`) must be registered in the vault with an allowed machine address matching the server running the script.

### On-premises — Central Credential Provider (CCP)

The CCP exposes a REST endpoint — no agent installation required. It supports both GET (parameters in the query string) and POST (JSON body).

**GET — allowed IP / OS user (parameters in query string):**

```powershell
$ccpBase   = 'https://ccp.company.com/AIMWebService/api/Accounts'
$ccpQuery  = 'AppID=PPAAutomation&Safe=PPASafe&Object=PVWAServiceAccount'
$result    = Invoke-RestMethod -Uri "${ccpBase}?${ccpQuery}" -Method GET

$securePass = ConvertTo-SecureString $result.Content -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($result.UserName, $securePass)

$params = @{
    PVWAURL         = 'https://pvwa.company.com/PasswordVault'
    PVWACredentials = $cred
    CSVPath         = '.\accounts.csv'
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

**POST with client certificate — JSON body, certificate passed separately:**

> POST requests require CCP 14.2 or later. Use the GET method above for older versions.

```powershell
$cert = Get-ChildItem -Path Cert:\LocalMachine\My |
    Where-Object { $_.Subject -like '*PPAAutomation*' } |
    Select-Object -First 1

$ccpBody = @{
    AppID  = 'PPAAutomation'
    Safe   = 'PPASafe'
    Object = 'PVWAServiceAccount'
} | ConvertTo-Json

$ccpParams = @{
    Uri         = 'https://ccp.company.com/AIMWebService/api/Accounts'
    Method      = 'POST'
    ContentType = 'application/json'
    Body        = $ccpBody
    Certificate = $cert
}
$result = Invoke-RestMethod @ccpParams

$securePass = ConvertTo-SecureString $result.Content -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($result.UserName, $securePass)

$params = @{
    PVWAURL         = 'https://pvwa.company.com/PasswordVault'
    PVWACredentials = $cred
    CSVPath         = '.\accounts.csv'
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

> `$result.Content` is the password. `$result.UserName` is the account username stored in the vault object. Adjust AppID, safe, and object names to match your environment.

### Privilege Cloud — OAuth via CCP (recommended for automation)

For unattended automation, store the OAuth client ID and secret in the vault and retrieve them from the CCP at runtime, then exchange them directly for an Identity Bearer token.

> CCP POST requests require CCP 14.2 or later.

**Step 1 — retrieve the OAuth client credentials from the CCP:**

```powershell
$ccpBody = @{
    AppID  = 'PPAAutomation'
    Safe   = 'PPASafe'
    Object = 'PCloudOAuthClientSecret'
} | ConvertTo-Json

$ccpParams = @{
    Uri         = 'https://ccp.company.com/AIMWebService/api/Accounts'
    Method      = 'POST'
    ContentType = 'application/json'
    Body        = $ccpBody
}
$ccpResult    = Invoke-RestMethod @ccpParams
$clientId     = $ccpResult.UserName
$clientSecret = $ccpResult.Content
```

**Step 2 — exchange credentials for an Identity OAuth token:**

The Identity token endpoint is `https://{tenant}.id.cyberark.cloud/oauth2/platformtoken`. Replace `{tenant}` with your Identity tenant subdomain (visible in the Identity Administration console URL).

```powershell
$tokenParams = @{
    Uri         = 'https://tenant.id.cyberark.cloud/oauth2/platformtoken'
    Method      = 'POST'
    ContentType = 'application/x-www-form-urlencoded'
    Body        = @{
        grant_type    = 'client_credentials'
        client_id     = $clientId
        client_secret = $clientSecret
    }
}
$tokenResponse = Invoke-RestMethod @tokenParams
```

**Step 3 — build the header hashtable and run the script:**

```powershell
$logonToken = @{
    Authorization           = "Bearer $($tokenResponse.access_token)"
    'X-IDAP-NATIVE-CLIENT'  = 'true'
}

$PCloudURL = 'https://tenant.privilegecloud.cyberark.cloud/PasswordVault'
$params = @{
    PVWAURL    = $PCloudURL
    logonToken = $logonToken
    ConfigPath = 'C:\Scripts\PersonalPrivilegedAccounts-PCloud.json'
    CSVPath    = 'C:\Scripts\accounts.csv'
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

> The OAuth service account must be registered in Identity with the **Privilege Cloud Users** role (or equivalent). The CCP AppID must allow the machine running the script.

### Privilege Cloud — OAuth via CCP with client certificate

For environments that use certificate-based CCP authentication:

> POST requests require CCP 14.2 or later.

```powershell
# Step 1 — retrieve credentials from CCP using a client certificate
$cert = Get-ChildItem -Path Cert:\LocalMachine\My |
    Where-Object { $_.Subject -like '*PPAAutomation*' } |
    Select-Object -First 1

$ccpBody = @{
    AppID  = 'PPAAutomation'
    Safe   = 'PPASafe'
    Object = 'PCloudOAuthClientSecret'
} | ConvertTo-Json

$ccpParams = @{
    Uri         = 'https://ccp.company.com/AIMWebService/api/Accounts'
    Method      = 'POST'
    ContentType = 'application/json'
    Body        = $ccpBody
    Certificate = $cert
}
$ccpResult    = Invoke-RestMethod @ccpParams
$clientId     = $ccpResult.UserName
$clientSecret = $ccpResult.Content

# Step 2 — get Identity OAuth token
$tokenParams = @{
    Uri         = 'https://tenant.id.cyberark.cloud/oauth2/platformtoken'
    Method      = 'POST'
    ContentType = 'application/x-www-form-urlencoded'
    Body        = @{
        grant_type    = 'client_credentials'
        client_id     = $clientId
        client_secret = $clientSecret
    }
}
$tokenResponse = Invoke-RestMethod @tokenParams

# Step 3 — run the script
$logonToken = @{
    Authorization           = "Bearer $($tokenResponse.access_token)"
    'X-IDAP-NATIVE-CLIENT'  = 'true'
}

$PCloudURL = 'https://tenant.privilegecloud.cyberark.cloud/PasswordVault'
$params = @{
    PVWAURL    = $PCloudURL
    logonToken = $logonToken
    ConfigPath = 'C:\Scripts\PersonalPrivilegedAccounts-PCloud.json'
    CSVPath    = 'C:\Scripts\accounts.csv'
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

## Testing your config before production

Use `Test-PersonalPrivilgedAccountsConfig.ps1` to verify that a config file behaves correctly against a live vault before promoting it:

```powershell
$params = @{
    ConfigPath  = '.\PersonalPrivilegedAccounts.json'
    PVWAURL     = 'https://pvwa.lab.local/PasswordVault'
    EndUserName = 'labuser1'
}
.\Test-PersonalPrivilgedAccountsConfig.ps1 @params
```

Exit code `0` = all assertions passed. Exit code `1` = one or more failures. See the generated JSON report for details.

To clean up test artifacts after a run:

```powershell
.\Test-PersonalPrivilgedAccountsConfig.ps1 -Cleanup -ReportPath '.\report.json'
```

## See also

- [INSTALL.md](INSTALL.md) — prerequisites and first-run setup
- [REFERENCE.md](REFERENCE.md) — full parameter and config schema reference
