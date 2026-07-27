# Safe Report

## Overview

Reports on CyberArk safes and/or safe members using the REST API directly.

## Modes

| Mode | Switches | Default format | With `-EPVFormat` |
|------|----------|-----------------|--------------------|
| Safe inventory | *(none)* | Safe-Management.ps1 `-Add`/`-Update` compatible | `Import-Safe \| New-Safe / Set-Safe` |
| Safe inventory extended | `-AllSafeDetails` | Same + full API fields (quota, timestamps, etc.) | Same |
| Member report | `-Members` | Safe-Management.ps1 `-AddMembers`/`-UpdateMembers` compatible | `Import-SafeMember \| Add-SafeMember` |
| Member report + safe context | `-Members -AllSafeDetails` | Same + safe detail columns | `Import-SafeMember \| Add-SafeMember` |

> **Note:** `quota` and `usedQuota` are only returned by the individual safe endpoint
> (`GET /api/Safes/{SafeUrlId}`), not the list endpoint. Use `-IncludeQuota` to fetch them;
> this triggers one additional API call per safe.

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
| `logonToken` | String / Hashtable | Pre-existing token (Privilege Cloud or pre-authenticated session). Omit for self-hosted. |
| `PVWACredentials` | PSCredential | Credentials for self-hosted PVWA logon. Prompted if omitted. |
| `PVWAAuthType` | String | `CyberArk` (default), `LDAP`, `RADIUS` |

### Mode

| Parameter | Description |
|-----------|-------------|
| `Members` | Switch to member report mode. Default outputs safe inventory. |
| `AllSafeDetails` | Expand output with all safe API fields. Applies to both safe inventory and member modes. |
| `IncludeQuota` | Add `quota` and `usedQuota` columns. Triggers one extra API call per safe to fetch individual safe details. Can be combined with `-AllSafeDetails` or used standalone. |
| `EPVFormat` | Output EPV-API-Common format (spaced headers). Cannot combine with `-HidePerms` or `-PermList`. |

### Output

| Parameter | Type | Description |
|-----------|------|-------------|
| `ReportPath` | String | CSV output path. Omit to write objects to the pipeline. |
| `TimeFormat` | String | Timestamp format for date fields: `Local` (default), `UTC`, `Epoch` (raw integer). |

### Filtering - Safes

| Parameter | Type | Description |
|-----------|------|-------------|
| `SafeName` | String[] | One or more safe names to target. Omit to report on all safes. |
| `IncludeSystemSafes` | Switch | Include system/internal safes and CPM safes (excluded by default). |

### Filtering - Members (`-Members` mode only)

| Parameter | Type | Description |
|-----------|------|-------------|
| `IncludeSystemMembers` | Switch | Include built-in service accounts (Auditors, Batch, PVWAAppUser*, PSMUsers, etc.) and vault predefined users. Mirrors `Migrate.psm1 ownersToRemove`. |
| `IncludeExpiredMembers` | Switch | Include members whose safe membership has expired (excluded by default). |
| `IncludeGroups` | Switch | Include group-type members in addition to users (default: users only). |
| `GroupsOnly` | Switch | Return group members only. Mutually exclusive with `-IncludeGroups`. |
| `HidePerms` | Switch | Suppress all permission columns. Not available with `-EPVFormat`. |
| `PermList` | Array | Include only these specific permission column names. Not available with `-EPVFormat`. |

## Usage Examples

### Safe inventory

```powershell
# Pipeline - SM.ps1 compatible format
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token

# CSV - SM.ps1 format
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -ReportPath .\safes.csv

# CSV - all safe API fields (timestamps, creator, location, etc.)
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -AllSafeDetails -ReportPath .\safes-full.csv

# CSV - include quota/usedQuota (one extra API call per safe)
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -IncludeQuota -ReportPath .\safes-quota.csv

# CSV - full details including quota
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -AllSafeDetails -IncludeQuota -ReportPath .\safes-all.csv

# CSV - EPV-API-Common format (pipe to Import-Safe | New-Safe / Set-Safe)
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -EPVFormat -ReportPath .\safes-epv.csv

# Target a specific safe
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -SafeName 'Win-LocalAdmins'
```

### Member report

```powershell
# Pipeline - lean member rows (safename, member, MemberLocation, MemberType + permissions)
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -Members

# CSV - feed directly to Safe-Management.ps1
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -Members -ReportPath .\members.csv
.\Safe-Management.ps1 -PVWAURL $url -logonToken $token -UpdateMembers -AddOnUpdate -FilePath .\members.csv

# CSV - include safe context columns (description, CPM, retention, timestamps)
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -Members -AllSafeDetails -ReportPath .\members-full.csv

# CSV - include safe context including quota
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -Members -AllSafeDetails -IncludeQuota -ReportPath .\members-full.csv

# CSV - EPV-API-Common format
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -Members -EPVFormat -ReportPath .\members-epv.csv

# Groups only (no users)
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -Members -GroupsOnly -ReportPath .\groups.csv

# Users and groups
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -Members -IncludeGroups -ReportPath .\all-members.csv

# Include system/service accounts normally excluded
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -Members -IncludeSystemMembers -ReportPath .\members-incl-system.csv

# UTC timestamps instead of local
.\Get-SafeReport.ps1 -PCloudURL $url -logonToken $token -Members -AllSafeDetails -TimeFormat UTC -ReportPath .\members.csv
```

### Cross-environment migration

```powershell
# Export safes + members from source
.\Get-SafeReport.ps1 -PCloudURL $srcUrl -logonToken $srcToken -Members -AllSafeDetails -ReportPath .\migration.csv

# Apply to target - creates safes AND sets memberships in one pass
.\Safe-Management.ps1 -PVWAURL $tgtUrl -logonToken $tgtToken -Add -FilePath .\migration.csv
```

## Safe-Management.ps1 Compatibility

| SM.ps1 switch | Compatible output | Notes |
|---------------|-------------------|-------|
| `-Add` | Safe inventory, `-Members -AllSafeDetails` | Creates safes; processes members if `member` column present |
| `-Update` | Safe inventory, `-Members -AllSafeDetails` | Updates safes; processes members if `member` column present |
| `-AddMembers` | `-Members` (any variant) | Adds new members only |
| `-UpdateMembers` | `-Members` (any variant) | Updates existing members only |
| `-UpdateMembers -AddOnUpdate` | `-Members` (any variant) | **Upsert** - updates existing, adds if missing |
| `-DeleteMembers` | `-Members` (any variant) | Removes members |
| `-Delete` | Any mode | Only requires `safename` column |

> Safe-Management.ps1 ignores extra columns, so `-Members -AllSafeDetails` output is fully
> compatible with all member operations even though it contains additional safe detail columns.

## Output Column Reference

### Safe inventory (default)
`safeName`, `description`, `managingCPM`, `numberOfVersionsRetention`, `numDaysRetention`

### Safe inventory with `-AllSafeDetails`
All default columns plus: `safeUrlId`, `safeNumber`, `location`, `creator`, `EnableOLAC`,
`autoPurgeEnabled`, `creationTime`, `lastModificationTime`, `isExpiredMember`

Add `-IncludeQuota` to also include: `quota`, `usedQuota`

> **`isExpiredMember`**: Reflects whether the *currently authenticated user's own* membership
> on that safe is expired. It is **not** a property of the safe itself and should not be
> interpreted as a safe health indicator. Retained for completeness.

### Safe inventory with `-EPVFormat`
`'Safe Name'`, `'Description'`, `'Managing CPM'`, `'Number of Versions Retained'`,
`'DaysRetention'`, `'OLAC Enabled'`, `'AutoPurgeEnabled'`, `'Location'`

### `-Members` base columns
`safename`, `member`, `MemberLocation`, `MemberType`, `membershipExpirationDate`
+ 21 permission columns (see below)

### `-Members -AllSafeDetails` additional columns
All base member columns (including `membershipExpirationDate`) plus: `description`, `managingCPM`,
`numberOfVersionsRetention`, `numDaysRetention`, `Source`, `UserType`, `safeLocation`, `EnableOLAC`,
`autoPurgeEnabled`, `creationTime`, `lastModificationTime`

Add `-IncludeQuota` to also include: `quota`, `usedQuota`

> `Source` and `UserType` are populated from the Users API and require Vault Admin permissions.
> They will be null on non-admin accounts.

### `-Members -EPVFormat` columns
`'Safe Name'`, `'Member Name'`, `'Member Type'`, plus 22 permission columns with human-readable
names (`'Use Accounts'`, `'Retrieve Accounts'`, `'Level 1 Confirmer'`, etc.)

### Permission columns (SM.ps1 format)
`UseAccounts`, `RetrieveAccounts`, `ListAccounts`, `AddAccounts`, `UpdateAccountContent`,
`UpdateAccountProperties`, `InitiateCPMAccountManagementOperations`, `SpecifyNextAccountContent`,
`RenameAccounts`, `DeleteAccounts`, `UnlockAccounts`, `ManageSafe`, `ManageSafeMembers`,
`BackupSafe`, `ViewAuditLog`, `ViewSafeMembers`, `RequestsAuthorizationLevel`,
`AccessWithoutConfirmation`, `CreateFolders`, `DeleteFolders`, `MoveAccountsAndFolders`

Suppressed with `-HidePerms`. Restricted to a subset with `-PermList`.

## Default Member Filtering

By default the member report excludes:

- **System/service accounts by name** (mirrors `Migrate.psm1 ownersToRemove`): Auditors,
  Backup Users, Batch, PasswordManager, DR Users, Master, Notification Engines, Operators,
  PTAAppUsers/PTAUser, PVWAAppUser*, PVWAUsers, PVWAMonitor, PSMUsers, PSMAppUsers,
  Administrator, Export. Use `-IncludeSystemMembers` to include them.
- **Vault predefined users** (`isPredefinedUser = true` from API). Also overridden by
  `-IncludeSystemMembers`.
- **Expired memberships** (`isExpiredMembershipEnable = true`). Use `-IncludeExpiredMembers`
  to include them.
- **Groups** (default: users only). Use `-IncludeGroups` for users + groups, or `-GroupsOnly`
  for groups only.
- **System safes and CPM safes** (excluded from safe list). Use `-IncludeSystemSafes` to
  include them.

## Supported Versions

- CyberArk PVWA v12.1 and above
- CyberArk Privilege Cloud
