# Reference — Personal Privileged Accounts

Full parameter and config schema reference. For setup steps see [INSTALL.md](INSTALL.md). For usage scenarios see [USER-GUIDE.md](USER-GUIDE.md).

---

## Create-PersonalPrivilgedAccounts.ps1

### Connection parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `-PVWAURL` | *(required)* | PVWA base URL (e.g. `https://pvwa.company.com/PasswordVault`) |
| `-AuthenticationType` | `cyberark` | `cyberark` \| `ldap` \| `radius` |
| `-OTP` | — | RADIUS one-time password |
| `-PVWACredentials` | *(prompt)* | PSCredential — if omitted and no `-logonToken`, the script prompts |
| `-logonToken` | — | Pre-obtained token string or hashtable; skips logon/logoff |
| `-DisableCertificateValidation` | `$false` | Bypass SSL validation — test environments only |

### Safe / account parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `-CSVPath` | *(file picker)* | Path to the accounts CSV |
| `-ConfigPath` | *(script dir)* | Path to `PersonalPrivilegedAccounts.json` |
| `-SafeNamePattern` | `*_ADM` | Pattern with exactly one `*` replaced by `userName` |
| `-PlatformID` | `WinDomain` | Default platform ID when the CSV row has no `accountPlatform` |

### Config override parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `-SafeConfigSet` | `default` | Named set within `SafeConfigSet` to apply for the whole run |
| `-UserConfigSet` | `default` | Named set within `UserConfigSet` to apply for the whole run |
| `-FallbackOnInvalidConfigSet` | `$false` | When a CSV row names a set that does not exist: warn and use the base config instead of skipping the row |
| `-AllowDuplicateAccounts` | `$false` | Allow a second account with the same `userName`, `address`, and `platformId` in an existing safe |
| `-CreateSafeOnly` | `$false` | Create the safe and add members but skip account onboarding |
| `-CPMName` | *(from config)* | CPM name for new safes |
| `-NumberOfVersionsRetention` | *(from config)* | Versions to retain — mutually exclusive with days |
| `-NumberOfDaysRetention` | *(from config)* | Days to retain — wins when both are supplied |

### CSV columns

```csv
userName,SafeConfigSet,SafeNamePattern,CPMName,NumberOfDaysRetention,NumberOfVersionsRetention,safeName,UserConfigSet,createSafeOnly,accountUser,password,accountAddress,accountPlatform,enableAutoMgmt,manualMgmtReason,remoteMachineAddresses,restrictMachineAccessToList,networkId
```

| Column | Required | Description |
| --- | --- | --- |
| `userName` | Yes | Vault username — safe owner and substituted into `SafeNamePattern` |
| `SafeConfigSet` | No | Named set to use for this row. Blank = use the `-SafeConfigSet` parameter value (or `default`). Invalid name = skip row (or fallback if `-FallbackOnInvalidConfigSet`). |
| `SafeNamePattern` | No | Row-level override for the safe name pattern |
| `CPMName` | No | Row-level override for the CPM |
| `NumberOfDaysRetention` | No | Row-level override — day-based retention. Clears `NumberOfVersionsRetention` for this row. |
| `NumberOfVersionsRetention` | No | Row-level override — version-based retention. Ignored when `NumberOfDaysRetention` is also set on the same row. |
| `safeName` | No | Explicit safe name. If blank, derived from `SafeNamePattern`. |
| `UserConfigSet` | No | Named set to use for this row (same fallback behaviour as `SafeConfigSet`) |
| `createSafeOnly` | No | `yes` / `no` — creates the safe and members but skips account onboarding for this row |
| `accountUser` | No | Account username. Blank = derived from `accountUserPattern` in `UserConfigSet` (replaces `*` with `userName`), then falls back to `userName`. |
| `password` | No | Initial password. Leave blank to let CPM manage. |
| `accountAddress` | No | Target address or hostname. Blank = falls back to `accountAddress` in `UserConfigSet`. Error if still empty. |
| `accountPlatform` | No | Platform ID. Falls back to config then `-PlatformID` parameter. |
| `enableAutoMgmt` | No | `yes` / `no` |
| `manualMgmtReason` | No | Required when `enableAutoMgmt` is `no` |
| `remoteMachineAddresses` | No | Semicolon-separated list of allowed remote machines |
| `restrictMachineAccessToList` | No | `yes` / `no` |
| `networkId` | No | **PCloud + SRS only.** Connector ID for Secrets Rotation Service rotation. Omit for CPM-managed accounts. |


Any column not in the list above is passed as a platform account property (`platformAccountProperties`).

---

## Configuration file schema

`PersonalPrivilegedAccounts.json` has three top-level sections.

Config layering (lowest to highest priority):

| Priority | Source |
| --- | --- |
| 1 (lowest) | Script baseline defaults |
| 2 | `default` set in the JSON |
| 3 | Named set (via parameter or CSV column) |
| 4 | CSV column values (row-level) |
| 5 (highest) | CLI parameters |

### SafeConfigSet

Controls safe creation. Each named set has an `Options` block and a `Properties` block.

#### SafeConfigSet.Options

| Key | Type | Description |
| --- | --- | --- |
| `useExisting` | bool | `true` — reuse if the safe exists (default). `false` — log an error and skip the row if the safe exists. |

#### SafeConfigSet.Properties

| Key | Type | Description |
| --- | --- | --- |
| `CPMName` | string | CPM assigned to the safe. Omit for SRS accounts (Privilege Cloud only). |
| `NumberOfDaysRetention` | int | Days to retain passwords. Mutually exclusive with `NumberOfVersionsRetention`. |
| `NumberOfVersionsRetention` | int | Versions to retain. Mutually exclusive with `NumberOfDaysRetention`. |
| `SafeNamePattern` | string | Safe name pattern — must contain exactly one `*` |
| `SafeEndUserRole` | string | Built-in role for the CSV `userName` (safe owner). Default: `EndUser` |
| `SafeEndUserRoleConfigSet` | string | `RoleConfigSet` entry to use for the CSV user instead of a built-in role |
| `SafeEndUserSearchIn` | string | **PCloud only.** Identity directory GUID for resolving the CSV user |
| `SafeEndUserMemberType` | string | **PCloud only.** `"User"` or `"Role"` for the CSV user |
| `DefaultSafeMembers` | array | Groups or users added to every safe (see below) |

#### DefaultSafeMembers

Each entry in `DefaultSafeMembers` supports:

| Field | Description |
| --- | --- |
| `Name` | Vault group, user, or Identity role name |
| `SearchIn` | On-prem: vault directory name (e.g. `"Vault"`). PCloud: Identity directory GUID. Use `"Vault"` for built-in vault groups on both platforms. |
| `MemberType` | **PCloud only.** `"Role"` for Identity roles/groups; `"User"` for individual vault users. Omit on-prem. |
| `Role` | Built-in role shortcut |
| `RoleConfigSet` | Reference to a named `RoleConfigSet` entry |
| `Permissions` | Explicit 22-permission object |

Permission is resolved in this order (first match wins): `Permissions` → `RoleConfigSet` → `Role`.

**On-premises example:**

```json
"DefaultSafeMembers": [
    {
        "Name": "VaultAdmins",
        "Role": "Full",
        "SearchIn": "Vault"
    },
    {
        "Name": "AuditGroup",
        "RoleConfigSet": "CustomAudit",
        "SearchIn": "Vault"
    }
]
```

**Privilege Cloud example** (`SearchIn` is an Identity GUID, `MemberType` is required):

```json
"DefaultSafeMembers": [
    {
        "Name": "PPA-SafeAdmins",
        "Role": "Full",
        "SearchIn": "C30B30B1-0B46-49AC-8D99-F6279EED7999",
        "MemberType": "Role"
    },
    {
        "Name": "Privilege Cloud Administrators",
        "Role": "Full",
        "SearchIn": "Vault"
    }
]
```

> Built-in vault groups like `"Privilege Cloud Administrators"` always use `"SearchIn": "Vault"` even on PCloud.

### UserConfigSet

Controls account defaults. Named sets merge on top of `default`.

#### UserConfigSet.Options

| Key | Type | Description |
| --- | --- | --- |
| `accountUserPattern` | string | Pattern for the account username — `*` is replaced with `userName` |
| `allowDuplicateAccounts` | bool | `true` — skip duplicate check for rows in this set |
| `createSafeOnly` | bool | `true` — skip account onboarding for all rows using this set |

#### UserConfigSet.Properties

| Key | Type | Description |
| --- | --- | --- |
| `accountPlatform` | string | Platform ID (e.g. `WinDomain`) |
| `accountAddress` | string | Default address used when the CSV `accountAddress` column is blank |
| `enableAutoMgmt` | `yes`/`no` | Whether CPM manages the account |
| `manualMgmtReason` | string | Reason shown in vault when `enableAutoMgmt` is `no` |
| `remoteMachineAddresses` | string | Semicolon-separated list of allowed remote machines |
| `restrictMachineAccessToList` | `yes`/`no` | Restrict PSM connections to `remoteMachineAddresses` only |
| `networkId` | string | **PCloud + SRS only.** Connector ID for Secrets Rotation Service |

Any extra key in `Properties` that is not listed above is passed as a `platformAccountProperties` default for every account in this set. A CSV column for the same key takes priority.

**Example:**

```json
"UserConfigSet": {
    "default": {
        "Options": {
            "accountUserPattern": "*_adm",
            "allowDuplicateAccounts": false
        },
        "Properties": {
            "accountPlatform": "WinDomain",
            "accountAddress": "corp.example.com",
            "enableAutoMgmt": "yes",
            "logonDomain": "CORP"
        }
    },
    "dev": {
        "Options": {
            "accountUserPattern": "*_adm",
            "allowDuplicateAccounts": false
        },
        "Properties": {
            "accountAddress": "dev.example.com",
            "enableAutoMgmt": "no",
            "manualMgmtReason": "Managed externally in dev"
        }
    }
}
```

### RoleConfigSet

Named permission sets referenced by `DefaultSafeMembers` entries or `SafeEndUserRoleConfigSet`.

```json
"RoleConfigSet": {
    "CustomAudit": {
        "listAccounts": true,
        "viewAuditLog": true,
        "viewSafeMembers": true
    }
}
```

### Built-in role permissions

| Permission | ConnectOnly | ReadOnly | EndUser | Approver | AccountsManager | Full |
| --- | :---: | :---: | :---: | :---: | :---: | :---: |
| useAccounts | ✓ | ✓ | ✓ | | ✓ | ✓ |
| retrieveAccounts | | ✓ | ✓ | | ✓ | ✓ |
| listAccounts | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| addAccounts | | | | | ✓ | ✓ |
| updateAccountContent | | | | | ✓ | ✓ |
| updateAccountProperties | | | | | ✓ | ✓ |
| initiateCPMAccountManagementOperations | | | | | ✓ | ✓ |
| specifyNextAccountContent | | | | | ✓ | ✓ |
| renameAccounts | | | | | ✓ | ✓ |
| deleteAccounts | | | | | ✓ | ✓ |
| unlockAccounts | | | | | ✓ | ✓ |
| manageSafe | | | | | | ✓ |
| manageSafeMembers | | | | ✓ | ✓ | ✓ |
| backupSafe | | | | | | ✓ |
| viewAuditLog | | | ✓ | | ✓ | ✓ |
| viewSafeMembers | | | ✓ | ✓ | ✓ | ✓ |
| accessWithoutConfirmation | | | | | ✓ | ✓ |
| createFolders | | | | | | ✓ |
| deleteFolders | | | | | | ✓ |
| moveAccountsAndFolders | | | | | | ✓ |
| requestsAuthorizationLevel1 | | | | ✓ | ✓ | ✓ |
| requestsAuthorizationLevel2 | | | | | | |

---

## Edit-PersonalPrivilegedAccountsConfig.ps1

Manages the JSON config file. Supports four operations: `Create`, `Set`, `Remove`, `Validate`.

| Parameter | Description |
| --- | --- |
| `-FilePath` | Path to the JSON config file |
| `-Operation` | `Create` \| `Set` \| `Remove` \| `Validate` |
| `-ConfigSetType` | `SafeConfigSet` \| `UserConfigSet` \| `RoleConfigSet` — required for Set and Remove |
| `-SetName` | Name of the set to add, update, or remove |
| `-UseExisting` | `SafeConfigSet.Options.useExisting` — `true` or `false` |
| `-CPMName` | `SafeConfigSet.Properties.CPMName` |
| `-NumberOfDaysRetention` | `SafeConfigSet.Properties.NumberOfDaysRetention` |
| `-NumberOfVersionsRetention` | `SafeConfigSet.Properties.NumberOfVersionsRetention` |
| `-SafeNamePattern` | `SafeConfigSet.Properties.SafeNamePattern` (must contain `*`) |
| `-SafeEndUserRole` | `SafeConfigSet.Properties.SafeEndUserRole` |
| `-SafeEndUserRoleConfigSet` | `SafeConfigSet.Properties.SafeEndUserRoleConfigSet` |
| `-DefaultSafeMembersJson` | `SafeConfigSet.Properties.DefaultSafeMembers` as a JSON array string |
| `-AccountUserPattern` | `UserConfigSet.Options.accountUserPattern` |
| `-AllowDuplicateAccounts` | `UserConfigSet.Options.allowDuplicateAccounts` — `true` or `false` |
| `-AccountPlatform` | `UserConfigSet.Properties.accountPlatform` |
| `-AccountAddress` | `UserConfigSet.Properties.accountAddress` |
| `-EnableAutoMgmt` | `UserConfigSet.Properties.enableAutoMgmt` — `yes` or `no` |
| `-ManualMgmtReason` | `UserConfigSet.Properties.manualMgmtReason` |
| `-RemoteMachineAddresses` | `UserConfigSet.Properties.remoteMachineAddresses` |
| `-RestrictMachineAccessToList` | `UserConfigSet.Properties.restrictMachineAccessToList` — `yes` or `no` |
| `-RoleTemplate` | Starting template for a RoleConfigSet: `Full` \| `EndUser` \| `ReadOnly` \| `UseAndRetrieve` \| `AccountsManager` \| `Custom` |
| `-PermissionsJson` | Permission JSON merged on top of `-RoleTemplate` (e.g. `'{"viewAuditLog":true}'`) |

---

## Test-PersonalPrivilgedAccounts.ps1

End-to-end test runner against a live vault. Generates a unique run ID, builds temporary CSV and config files, runs `Create-PersonalPrivilgedAccounts.ps1`, then asserts results via REST API. Cleanup renames test safes to `DEL_<name>` and attempts deletion. Safe shells may persist if vault retention prevents immediate deletion; accounts are always removed.

Runs 18 assertions: safe creation, safe membership, account onboarding, named config set merging, idempotency, and edge cases.

| Parameter | Default | Description |
| --- | --- | --- |
| `-PVWAURL` | *(defaults)* | PVWA base URL |
| `-AuthenticationType` | `cyberark` | `cyberark` \| `ldap` \| `radius` |
| `-PVWACredentials` | *(prompt)* | PSCredential |
| `-logonToken` | — | Pre-obtained token |
| `-DisableCertificateValidation` | `$false` | Bypass SSL validation |
| `-ScriptPath` | *(script dir)* | Path to `Create-PersonalPrivilgedAccounts.ps1` |
| `-CPMName` | `PasswordManager` | CPM name for test safes |
| `-SafeNamePattern` | `*_ADM` | Safe name pattern for test safes |
| `-AccountPlatform` | *(required)* | Platform ID — must exist in the vault |
| `-LogPath` | *(script dir)* | Log file path |
| `-KeepArtifacts` | `$false` | Keep temporary CSV and config files for debugging |

---

## Test-PersonalPrivilgedAccountsConfig.ps1

Validates a config file by creating test safes and accounts, asserting all 22 permissions, retention, CPM, and end-user role. Produces a JSON report. Supports `-Cleanup` mode to remove test artifacts.

| Parameter | Description |
| --- | --- |
| `-ConfigPath` | Path to the JSON config file (required in normal mode) |
| `-EndUserName` | Vault user used as safe owner in test rows (required in normal mode) |
| `-PVWAURL` | PVWA base URL |
| `-AuthenticationType` | `cyberark` \| `ldap` \| `radius`. Default: `cyberark` |
| `-PVWACredentials` | PSCredential |
| `-logonToken` | Pre-obtained token |
| `-DisableCertificateValidation` | Bypass SSL validation |
| `-ScriptPath` | Path to `Create-PersonalPrivilgedAccounts.ps1` |
| `-SeedLabUsers` | Pre-create vault accounts for each `DefaultSafeMembers` entry that does not exist |
| `-SeedPassword` | SecureString password for seeded users (required with `-SeedLabUsers`) |
| `-ReportPath` | Output path for the JSON report |
| `-Cleanup` | Cleanup mode — reads a report file and removes test artifacts |
| `-SkipSafeConfigSets` | Skip Safe Config Set validation |
| `-SkipUserConfigSets` | Skip User Config Set validation |
| `-KeepArtifacts` | Keep temp CSV and config files after the run |
| `-LogPath` | Log file path |

Exit code `0` = all assertions passed (or warnings only). Exit code `1` = one or more FAIL results.
