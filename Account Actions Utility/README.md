# Account Actions Utility

> **Note:** The content of `sample_account_actions.csv` is for example only and does not represent real accounts.

## Main capabilities

- Triggers CPM account actions (Verify, Change, Reconcile, Resume, Disable, CheckIn, Cancel, SetNextPassword, ChangeInVault) on one or many accounts.
- Two operating modes: **Filters mode** (filter accounts by safe, platform, username, and more) and **CSV mode** (per-row actions from a file).
- CSV mode resolves accounts by **AccountID** (fast path — no search) or by **safe + username + address** lookup.
- Good and bad result CSVs are produced alongside the input file (CSV mode) or in the script folder (Filters mode).
- Optional bulk API modes (`-BulkOnPrem`, `-BulkPCloud`) submit accounts in configurable batches instead of one call per account.
- Privilege Cloud URL is auto-detected from the PVWA URL pattern (`*.privilegecloud.cyberark.cloud` / `*.privilegecloud.cyberark.com`).
- Compatible with PowerShell 5.1 and above.
- Supports CyberArk PVWA v10.4 and above. On-prem bulk API requires v15.2+.

The tool creates a timestamped log file in the same folder as the script: `Account_Actions_Utility_<timestamp>.log`.  
Running with `-Debug` or `-Verbose` adds more detail to the log.

---

## Supported actions

| Action | Individual endpoint | Bulk (on-prem v15.2+) | Bulk (PCloud SRS) | Notes |
|---|---|---|---|---|
| `Verify` | ✅ | ✅ | ✅ (`verify-secret`) | |
| `Change` | ✅ | ✅ | ✅ (`change-secret`) | On-prem bulk supports `-ChangeEntireGroup` |
| `Reconcile` | ✅ | ✅ | ✅ (`reconcile-secret`) | |
| `Resume` | ✅ | ✅ | ✅ | PATCH to re-enable CPM management |
| `Disable` | ✅ | — | — | PATCH to disable CPM management; stores `-DisableReason` |
| `CheckIn` | ✅ | ✅ | ✅ (`unlock`) | Check in exclusive accounts |
| `Cancel` | ✅ | ✅ | ❌ | Cancel a pending CPM task |
| `SetNextPassword` | ✅ | — | — | Requires `-NewCredentials`; use `-ChangeImmediately` to trigger now |
| `ChangeInVault` | ✅ | — | — | Updates stored password only; requires `-NewCredentials` |
| `Delete` | ❌ | ❌ | ✅ (`delete`) | PCloud SRS bulk only |

> `-BulkPCloud` requires the Secrets Rotation Service (SRS) to be provisioned on the tenant.

---

## Parameters

```powershell
Invoke-AccountActions.ps1 -PVWAURL <string>
    [-AuthType <cyberark|ldap|radius>] [-OTP <string>] [-DisableSSLVerify]
    [-PVWACredentials <PSCredential>] [-logonToken <token>] [-concurrentSession]
    [-BulkOnPrem] [-BulkPCloud] [-BatchSize <int>] [-ChangeEntireGroup]
    [-PollInterval <int>] [-DisableReason <string>]
    [-NewCredentials <SecureString>] [-ChangeImmediately]
    { -AccountsAction <action> [Filters params...] | -CsvPath <path> [-CsvDelimiter <Comma|Tab>] }
```

### Common parameters

- **PVWAURL** _(mandatory)_
  - Base URL of the PVWA. Must include `PasswordVault`, e.g. `https://pvwa.example.com/PasswordVault`
  - Privilege Cloud: `https://<tenant>.privilegecloud.cyberark.cloud/PasswordVault`
  - Incorrect Privilege Cloud formats (e.g. `https://<sub>.cyberark.cloud/privilegecloud`) are corrected automatically.

- **logonToken**
  - Pre-existing session token (string) or Authorization header hashtable (e.g. from `Get-IdentityHeader`).
  - When provided, the script does **not** log the session off on exit.
  - To generate a token: see [Identity Authentication](../Identity%20Authentication/README.md)

- **AuthType** — `cyberark` (default) | `ldap` | `radius`

- **OTP** — RADIUS one-time password (only used when `AuthType = radius`)

- **PVWACredentials** — `[PSCredential]` to skip the interactive logon prompt

- **DisableSSLVerify** _(not recommended)_ — Disables certificate validation

- **concurrentSession** — Allows concurrent PVWA sessions

- **DisableReason** — Reason stored when using the `Disable` action. Default: `[No Reason]`
  - Do **not** use a `(CPM)` prefix — PVWA reserves that prefix for the CPM service and will silently discard the value.

- **NewCredentials** — `[SecureString]` required for `SetNextPassword` and `ChangeInVault`

- **ChangeImmediately** — Switch; when set with `SetNextPassword`, triggers an immediate CPM change instead of waiting for the next scheduled interval

- **BulkOnPrem** — Submit accounts via the on-prem bulk API (`/Accounts/{Action}/Bulk`). Requires PVWA v15.2+. Version is verified automatically before proceeding.

- **BulkPCloud** — Submit accounts via the Privilege Cloud SRS bulk API (async; the script polls until each batch completes).

- **BatchSize** — Accounts per bulk batch. Range: 1–10,000. Default: `100`

- **ChangeEntireGroup** — On-prem Change bulk only; sets `ChangeEntireGroup: true` on every item in the batch

- **PollInterval** — Seconds between PCloud bulk status polls. Default: `5`

---

### Filters mode (default)

Filters accounts from PVWA and applies a single action to all matches.

```powershell
Invoke-AccountActions.ps1 -PVWAURL <string> -AccountsAction <action>
    [-SafeName <string>] [-PlatformID <string>] [-UserName <string>]
    [-Address <string>] [-Search <string>]
    [-Filter <string>] [-SavedFilter <string>] [-SearchType <contains|startswith>]
    [-BulkOnPrem | -BulkPCloud] [...]
```

- **AccountsAction** _(mandatory)_ — Action to run on all matched accounts. See [Supported actions](#supported-actions).
- **SafeName** — Filter by safe name (max 28 characters)
- **PlatformID** — Filter by platform ID (exact match, post-filtered in PowerShell)
- **UserName** — Filter by username (exact match, post-filtered in PowerShell)
- **Address** — Filter by address (exact match, post-filtered in PowerShell)
- **Search** — Space-separated keywords passed to `search=` in the API (fuzzy full-text, equivalent to the PVWA search box)
- **Filter** — Freeform expression passed directly to `filter=` in the API. If `-SafeName` is also provided, the two are joined with `AND`. Examples:
  - `"modificationTime gte 1722470400"` — accounts modified after a Unix timestamp (`[int64](Get-Date '2024-08-01' -UFormat %s)` converts a date)
  - `"Username Contains admin"` — field-level filter; check the API docs for expressions supported in your environment
- **SavedFilter** — Named saved filter passed directly to `savedFilter=` in the API. Common values:

  | Value | Description |
  |---|---|
  | `DisabledPasswordByCPM` | Accounts disabled by the CPM (replaces `-CPMDisabled`) |
  | `DisabledPasswordByUser` | Accounts disabled by a user |
  | `FailedChange` | Last change failed |
  | `FailedVerify` | Last verify failed |
  | `FailedReconcile` | Last reconcile failed |
  | `ScheduledForChange` / `ScheduledForVerify` / `ScheduledForReconcile` | Queued for action |
  | `SuccessfullyReconciled` | Last reconcile succeeded |
  | `PolicyFailures` | Platform policy failures |
  | `LockedOrNew` / `Locked` | Locked accounts |
  | `ModifiedByCPM` / `ModifiedByUsers` | Modified by CPM or users |
  | `Deleted` | Deleted accounts |

  > Both on-prem and PCloud support all the above values. PCloud additionally supports `DeleteInsightStatus`.

- **SearchType** — Controls how `search=` keyword matching works. Values: `contains` (default) or `startswith`

Good/bad CSVs are written to:
- `<ScriptFolder>\AccountActions_<timestamp>.good.csv`
- `<ScriptFolder>\AccountActions_<timestamp>.bad.csv`

---

### CSV mode

Each row specifies an action and an account identifier. The input CSV must include an **Action** column and either an **AccountID** column or **safe + username + address** columns.

```powershell
Invoke-AccountActions.ps1 -PVWAURL <string> -CsvPath <path>
    [-CsvDelimiter <Comma|Tab>]
    [-DisableReason <string>] [-NewCredentials <SecureString>] [-ChangeImmediately]
    [-BulkOnPrem | -BulkPCloud] [...]
```

- **CsvPath** _(mandatory)_ — Path to the input CSV file
- **CsvDelimiter** — `Comma` (default) or `Tab`

Good/bad CSVs are written alongside the input file:
- `<CsvPath>.good.csv`
- `<CsvPath>.bad.csv`

#### CSV columns

| Column | Required | Description |
|---|---|---|
| `Action` | **Yes** | Action to perform on this row. See [Supported actions](#supported-actions). |
| `AccountID` | No | CyberArk account ID (e.g. `12_34`). When present, skips the search lookup entirely. |
| `safe` | No* | Safe name. Required when `AccountID` is not provided. |
| `username` | No* | Account username. Required when `AccountID` is not provided. |
| `address` | No* | Account address. Required when `AccountID` is not provided. |
| `platformID` | No | Platform ID. Used as an additional search filter. |
| `name` | No | Account object name. Used as an additional search filter. |
| `DisableReason` | No | Reason for the `Disable` action on this row. Overrides `-DisableReason`. |
| `NewCredentials` | No | New password (plain text) for `SetNextPassword` or `ChangeInVault` on this row. Overrides `-NewCredentials`. |
| `ChangeImmediately` | No | `true`/`false` for `SetNextPassword` on this row. Overrides `-ChangeImmediately`. |

\* At least one of `AccountID` or (`safe` + `username` + `address`) must be present per row.

When the account is successfully resolved, the good/bad CSVs are enriched with the full account details (`AccountID`, `AccountName`, `SafeName`, `UserName`, `Address`, `PlatformID`) regardless of which columns were in the input CSV.

---

## Examples

### Filters mode — verify all accounts in a safe
```powershell
.\Invoke-AccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" `
    -AccountsAction Verify -SafeName "MySafe"
```

### Filters mode — change all failed WinDomain accounts
```powershell
.\Invoke-AccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" `
    -AccountsAction Change -PlatformID "WinDomain" -SavedFilter FailedChange
```

### Filters mode — re-enable all CPM-disabled accounts in a safe
```powershell
.\Invoke-AccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" `
    -AccountsAction Resume -SafeName "MySafe" -SavedFilter DisabledPasswordByCPM
```

### Filters mode — disable accounts in a safe with a reason
```powershell
.\Invoke-AccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" `
    -AccountsAction Disable -SafeName "MySafe" -DisableReason "Decommission Q4"
```

### Filters mode — accounts modified after a specific date
```powershell
# Convert a date to Unix timestamp first
$since = [int64](Get-Date '2024-08-01' -UFormat %s)
.\ Invoke-AccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" `
    -AccountsAction Verify -SafeName "MySafe" -Filter "modificationTime gte $since"
```

### Filters mode — on-prem bulk Verify (v15.2+)
```powershell
.\Invoke-AccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" `
    -AccountsAction Verify -SafeName "MySafe" -BulkOnPrem -BatchSize 200
```

### Filters mode — set next password for all accounts in a safe
```powershell
$newPw = Read-Host -AsSecureString
.\Invoke-AccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" `
    -AccountsAction SetNextPassword -SafeName "MySafe" `
    -NewCredentials $newPw -ChangeImmediately
```

### CSV mode — mixed per-row actions
```powershell
.\Invoke-AccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" `
    -CsvPath .\accounts.csv
```

### CSV mode — retry failures from a previous run
```powershell
.\Invoke-AccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" `
    -CsvPath .\accounts.csv.bad.csv
```

### Use a pre-existing logon token (Privilege Cloud / ISPSS)
```powershell
$token = Get-IdentityHeader -IdentityUserName "user@tenant" -PCloudURL $PCloudURL
.\Invoke-AccountActions.ps1 -PVWAURL $PCloudURL -AccountsAction Verify `
    -SafeName "MySafe" -logonToken $token
```

---

## Notes

- **Retry workflow** — The bad CSV can be fed directly back into the script as `-CsvPath` to retry only the failed rows. The `ErrorMessage` column is stripped on import.
- **`NewCredentials` in CSV** — The `NewCredentials` column accepts a plain-text password. The value is never written to the good/bad output CSVs (nulled on export), but it exists in the input file in clear text — protect input CSVs containing passwords accordingly.
- **`SetNextPassword` / `ChangeInVault` in bulk CSV mode** — These actions require per-account credentials in the request body and cannot be used with `-BulkOnPrem` or `-BulkPCloud`. Rows with those actions will be written to the bad CSV with an explanatory error if bulk mode is active.
- **Token sessions** — When `-logonToken` is supplied, the session is **not** logged off on exit. Manage the session lifetime in the calling context.
- **`-Filter` and `-SafeName`** — If both are provided, they are combined as `filter=safename eq {SafeName} AND {Filter}`. Check the API documentation for the filter expressions supported in your environment.
- **`-SavedFilter`** — Both on-prem and PCloud support the same named filter values. Use `-SavedFilter DisabledPasswordByCPM` to target accounts the CPM has disabled, `-SavedFilter FailedChange` for failed changes, etc.
- **PCloud SRS bulk** (`-BulkPCloud`) requires the Secrets Rotation Service to be enabled on the tenant. If SRS is not provisioned, the bulk endpoint returns 404.
- **On-prem bulk** (`-BulkOnPrem`) against Privilege Cloud is not supported; use `-BulkPCloud` instead.
- **`(CPM)` prefix in disable reasons** — PVWA reserves this prefix for the CPM service. Any `-DisableReason` starting with `(CPM)` will be silently discarded by PVWA; the script warns when this is detected.
- **SetNextPassword / ChangeInVault** require a `-NewCredentials` value and are not available in bulk mode.
