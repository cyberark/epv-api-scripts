# Safe Report

## Overview

Reports on CyberArk safes and/or safe members using the REST API directly.
No external module dependencies (PSPAS not required). PowerShell 5.1+.

## Modes

| Mode | Switches | Default format | With `-EPVFormat` |
|------|----------|---------------|-------------------|
| Safe inventory | *(none)* | SM.ps1 `-Add`/`-Update` | `Import-Safe \| New-Safe / Set-Safe` |
| Safe inventory extended | `-AllSafeDetails` | Same + all API fields | Same |
| Members with context | `-IncludeMembers` | SM.ps1 `-Add`/`-AddMembers` | `Import-SafeMember \| Add-SafeMember` |
| Members + all fields | `-IncludeMembers -AllSafeDetails` | Same + all safe fields | Same |
| Members only | `-MembersOnly` | SM.ps1 `-AddMembers`/`-UpdateMembers` | `Import-SafeMember \| Add-SafeMember` |

## Authentication

### Privilege Cloud (pre-existing token)

Obtain a token via `Get-IdentityHeader` from the [Identity Authentication module](../../Identity%20Authentication/README.md), then pass it as `-logonToken`:

```powershell
$token = Get-IdentityHeader -IdentityUserName 'user@company.com' -PCloudURL 'https://subdomain.privilegecloud.cyberark.cloud/PasswordVault'
.\Get-SafeReport.ps1 -PCloudURL 'https://subdomain.privilegecloud.cyberark.cloud/PasswordVault' -logonToken $token
```

`$logonToken` accepts a `Hashtable` (full header set from `Get-IdentityHeader`) or a `String` (Bearer token).

### Self-hosted PVWA (credential logon)

Omit `-logonToken`. Credentials are prompted or passed via `-PVWACredentials`:

```powershell
.\Get-SafeReport.ps1 -PVWAURL 'https://pvwa.domain.com/PasswordVault' -PVWACredentials $cred
```

## Parameters

### Authentication

| Parameter | Type | Description |
|-----------|------|-------------|
| `PVWAURL` / `PCloudURL` | String | **Required.** Full URL including `/PasswordVault`. Both names accepted. |
| `logonToken` | String / Hashtable | Pre-existing token (Privilege Cloud). Omit for self-hosted. |
| `PVWACredentials` | PSCredential | Credentials for self-hosted PVWA logon |
| `PVWAAuthType` | String | `CyberArk` (default), `LDAP`, `RADIUS` |

### Mode

| Parameter | Description |
|-----------|-------------|
| `AllSafeDetails` | Extend output with all safe API fields |
| `IncludeMembers` | Member rows with safe context (SM.ps1 compatible) |
| `MembersOnly` | Member rows only, minimal safe context (cleanest SM.ps1 format) |
| `EPVFormat` | Switch output to EPV-API-Common format instead of Safe-Management.ps1 format |

### Output

| Parameter | Type | Description |
|-----------|------|-------------|
| `ReportPath` | String | CSV path. Omit to write to the pipeline. |

### Filtering (member modes only)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `SafeName` | String[] | *(all safes)* | One or more safe names to target |
| `UserTypes` | Array | `@('EPVUser','BasicUser')` | User types to include |
| `ExcludeUsers` | Switch | | Exclude users. Combine with `-IncludeGroups` for groups only. |
| `IncludeGroups` | Switch | | Include groups |
| `IncludeApps` | Switch | | Include `AppProvider` and `AIMAccount` members |
| `IncludePredefinedUsers` | Switch | | Include predefined/system users |
| `HidePerms` | Switch | | Suppress all permission columns |
| `PermList` | Array | | Include only these specific permission columns |

## Usage Examples

### Safe inventory

```powershell
# Pipeline (SM.ps1 format - safeName, description, managingCPM, retention)
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token

# Pipeline (EPV-API-Common format - Import-Safe | New-Safe)
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -EPVFormat

# To CSV - SM.ps1 format
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -ReportPath .\safes.csv

# To CSV - EPV-API-Common format
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -EPVFormat -ReportPath .\safes-epv.csv

# All safe fields
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -AllSafeDetails -ReportPath .\safes.csv
```

### Members only (cleanest Safe-Management.ps1 format)

```powershell
# Pipeline
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -MembersOnly

# To CSV - then feed to Safe-Management.ps1
.\.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -MembersOnly -ReportPath .\members.csv
.\Safe-Management.ps1 -PVWAURL $url -logonToken $token -UpdateMembers -AddOnUpdate -FilePath .\members.csv  # upsert (add if missing, update if exists)
.\Safe-Management.ps1 -PVWAURL $url -logonToken $token -AddMembers   -FilePath .\members.csv  # add only
.\Safe-Management.ps1 -PVWAURL $url -logonToken $token -UpdateMembers -FilePath .\members.csv  # update only


# To CSV - then feed to EPV-API-Common
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -MembersOnly -EPVFormat -ReportPath .\members-epv.csv
Import-SafeMember .\members-epv.csv | Add-SafeMember -UpdateOnDuplicate
```

### Members with safe context

```powershell
# Pipeline
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -IncludeMembers

# To CSV - safe + member operations together in one pass
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -IncludeMembers -ReportPath .\full.csv
.\Safe-Management.ps1 -PVWAURL $url -logonToken $token -Add -FilePath .\full.csv

# EPV-API-Common format
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -IncludeMembers -EPVFormat -ReportPath .\full-epv.csv
Import-SafeMember .\full-epv.csv | Add-SafeMember -UpdateOnDuplicate
```

### Safe inventory → EPV-API-Common safe operations

```powershell
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -EPVFormat -ReportPath .\safes-epv.csv
Import-Safe .\safes-epv.csv | New-Safe
Import-Safe .\safes-epv.csv | Set-Safe
```

### Cross-environment migration (full - safes + members)

```powershell
# Export from source
.\Get-SafeReport.ps1 -PCloudURL $srcUrl -logonToken $srcToken -IncludeMembers -AllSafeDetails -ReportPath .\migration.csv

# Apply to target (creates safes AND adds members in one pass)
.\Safe-Management.ps1 -PVWAURL $tgtUrl -logonToken $tgtToken -Add -FilePath .\migration.csv
```

## Safe-Management.ps1 Compatibility

| SM.ps1 mode | Switch | Compatible output | Notes |
|-------------|--------|------------------|-------|
| `-Add` | | Default safe inventory, `-IncludeMembers` | Creates safes; also processes members if present |
| `-Update` | | Default safe inventory, `-IncludeMembers` | Updates safes; also processes members if present |
| `-AddMembers` | | `-MembersOnly`, `-IncludeMembers` | Adds new members only |
| `-UpdateMembers` | | `-MembersOnly`, `-IncludeMembers` | Updates existing members only |
| `-UpdateMembers` | `-AddOnUpdate` | `-MembersOnly`, `-IncludeMembers` | **Upsert** - updates existing, adds missing |
| `-DeleteMembers` | | `-MembersOnly`, `-IncludeMembers` | Removes members |
| `-Delete` | | Any mode | Only needs `safename` column |

## Output Column Reference

### Safe inventory (default)
`safeName`, `description`, `managingCPM`, `numberOfVersionsRetention`, `numDaysRetention`

### Safe inventory with `-AllSafeDetails`
Above + `safeUrlId`, `safeNumber`, `location`, `creator`, `EnableOLAC`, `autoPurgeEnabled`, `creationTime`, `lastModificationTime`, `isExpiredMember`

### Safe inventory with `-EPVFormat`
`'Safe Name'`, `'Description'`, `'Managing CPM'`, `'Number of Versions Retained'`, `'DaysRetention'`, `'OLAC Enabled'`, `'AutoPurgeEnabled'`, `'Location'`

### `-MembersOnly` base columns
`safename`, `member`, `MemberLocation`, `MemberType`

### `-IncludeMembers` base columns
`safename`, `description`, `managingCPM`, `numberOfVersionsRetention`, `numDaysRetention`, `member`, `MemberLocation`, `MemberType`, `Source`, `UserType`

### `-IncludeMembers -AllSafeDetails` additional columns
Above + `safeLocation`, `EnableOLAC`, `autoPurgeEnabled`, `creationTime`, `lastModificationTime`

### Member `-EPVFormat` columns
`'Safe Name'`, `'Member Name'`, `'Member Type'`, + 22 human-readable permission columns matching `Export-SafeMember` / `Import-SafeMember`

### Permission columns (SM.ps1 format, all member modes)
`UseAccounts`, `RetrieveAccounts`, `ListAccounts`, `AddAccounts`, `UpdateAccountContent`, `UpdateAccountProperties`, `InitiateCPMAccountManagementOperations`, `SpecifyNextAccountContent`, `RenameAccounts`, `DeleteAccounts`, `UnlockAccounts`, `ManageSafe`, `ManageSafeMembers`, `BackupSafe`, `ViewAuditLog`, `ViewSafeMembers`, `RequestsAuthorizationLevel`, `AccessWithoutConfirmation`, `CreateFolders`, `DeleteFolders`, `MoveAccountsAndFolders`

Suppressed by `-HidePerms`. Restricted by `-PermList`.

> **`MemberLocation`:** Populated from the API for directory-sourced members; `null` for vault-local members.

## Supported Versions

- CyberArk PVWA v12.1 and above
- CyberArk Privilege Cloud

