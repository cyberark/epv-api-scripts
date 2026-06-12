# E2E Test Plan — `Create-PersonalPrivilgedAccounts.ps1`

Test runner: `Test-PersonalPrivilgedAccounts.ps1`
Target script: `Create-PersonalPrivilgedAccounts.ps1`
Framework: Plain PowerShell (no Pester required)
Environment: Live CyberArk vault (on-premises or Privilege Cloud)

---

## Test fixture files

Two committed fixture files ship alongside the test runner. They serve as documentation and as inputs for manual one-off runs (see [Running the tests](#running-the-tests)):

| File | Purpose |
| --- | --- |
| `Test-PersonalPrivilgedAccounts.csv` | Static CSV with four rows: `testuser1`/`testuser2` (baseline), `testuser3` (SafeConfigSet=alt), `testuser4` (SafeConfigSet=DoesNotExistXYZ). Safe names are fixed — only use in a fresh environment. |
| `Test-PersonalPrivilgedAccounts.json` | Minimal config: `default` set (7-day retention) and `alt` set (14-day retention) under `SafeConfigSet`. No `DefaultSafeMembers`, no vault group dependencies. |

> **Note:** The automated test runner (`Test-PersonalPrivilgedAccounts.ps1`) does **not** use these files directly. It generates its own temporary CSV and config with unique `e<runId>*` usernames at runtime, then deletes them in the `finally` block. The fixture files are provided for reference and manual use only.

---

## Run-time behaviour

Every invocation of the test runner generates a unique **Run ID** (`MMddHHmmss`) that is embedded in all safe names for that run. This guarantees no name collisions between runs without requiring safe deletion, which is blocked by vault retention policies.

| Artifact | Fate after run |
| --- | --- |
| Temp CSV (`E2ETest_<runId>.csv`) | Deleted in `finally` block |
| Temp CSV (`E2ETest_<runId>_invalid.csv`) | Deleted in `finally` block |
| Temp config (`E2ETest_<runId>_config.json`) | Deleted in `finally` block |
| Safe `e<runId>1_ADM` | **Retained in vault** (retention policy) |
| Safe `e<runId>2_ADM` | **Retained in vault** (retention policy) |
| Safe `e<runId>3_ADM` | **Retained in vault** (retention policy) |
| Safe `e<runId>4_ADM` | **Retained in vault** (retention policy — only created if T13 passes) |

---

## Test data

Four test users are created per run, exercising distinct code paths:

| Field | User 1 | User 2 | User 3 | User 4 |
| --- | --- | --- | --- | --- |
| `userName` | `e<runId>1` | `e<runId>2` | `e<runId>3` | `e<runId>4` |
| `accountUser` | `e<runId>1_adm` | `e<runId>2_adm` | `e<runId>3_adm` | `e<runId>4_adm` |
| `accountAddress` | `testenv.corp.com` | `testenv.corp.com` | `testenv.corp.com` | `testenv.corp.com` |
| `safeName` (CSV) | *(empty — pattern)* | `e<runId>2_ADM` *(explicit)* | *(empty — pattern)* | *(empty — pattern)* |
| `accountPlatform` | `-AccountPlatform` | `-AccountPlatform` | `-AccountPlatform` | `-AccountPlatform` |
| `enableAutoMgmt` | `yes` | `no` | `yes` | `yes` |
| `manualMgmtReason` | *(empty)* | `E2E test manual mgmt` | *(empty)* | *(empty)* |
| `SafeConfigSet` | *(empty)* | *(empty)* | `alt` | `DoesNotExistXYZ` |

**User 1** — baseline happy path: pattern-derived safe name, auto management.
**User 2** — explicit safe name in CSV, manual management with reason.
**User 3** — named `SafeConfigSet=alt` (14-day retention); proves per-row config set merging.
**User 4** — invalid `SafeConfigSet`; proves skip-by-default (T12) and fallback (T13).

---

## Test steps and assertions

### Step 1 — First run (create safes + onboard accounts)

The main script is invoked with the temp CSV, temp config, and a pre-obtained auth header (so the main script skips its own logon/logoff).

| ID | Assertion | Verification method | Expected outcome |
| --- | --- | --- | --- |
| **T01** | Script exits without fatal error | `$LASTEXITCODE` is `$null` or `0` | Pass — no `exit 1` or `exit 5` was triggered |

---

### Step 2 — Safe existence

Direct `GET /api/Safes/{safeName}` REST calls against the vault.

| ID | Assertion | Verification method | Expected outcome |
| --- | --- | --- | --- |
| **T02** | Safe `e<runId>1_ADM` exists | `GET /api/Safes/e<runId>1_ADM` returns non-null | Safe was created by the main script |
| **T03** | Safe `e<runId>2_ADM` exists | `GET /api/Safes/e<runId>2_ADM` returns non-null | Safe was created by the main script |
| **T10** | Safe `e<runId>3_ADM` exists | `GET /api/Safes/e<runId>3_ADM` returns non-null | Per-row `SafeConfigSet=alt` was applied — row was not skipped |

---

### Step 3 — Safe ownership and permissions

Direct `GET /api/Safes/{safeName}/Members/{memberName}` REST calls.

| ID | Assertion | Verification method | Expected outcome |
| --- | --- | --- | --- |
| **T04** | `e<runId>1` is a member of `e<runId>1_ADM` | `GET /Members/e<runId>1` returns non-null | Owner was added with `Add-SafeOwner` |
| **T05** | `e<runId>2` is a member of `e<runId>2_ADM` | `GET /Members/e<runId>2` returns non-null | Owner was added with `Add-SafeOwner` |
| **T06** | `e<runId>1` has `viewAuditLog = true` | `member.permissions.viewAuditLog -eq $true` | Confirms `EndUser` role was applied correctly |
| **T17** | `e<runId>3` has `retrieveAccounts = false` | `member.permissions.retrieveAccounts -ne $true` | Confirms `SafeEndUserRoleConfigSet = 'CustomSafeUser'` from `alt` set was applied (CustomSafeUser grants only `useAccounts` + `listAccounts`) |

---

### Step 4 — Account onboarding

Direct `GET /api/Accounts?filter=safeName eq {safeName}` REST calls.

| ID | Assertion | Verification method | Expected outcome |
| --- | --- | --- | --- |
| **T07** | At least one account exists in `e<runId>1_ADM` | `response.count -gt 0` | Bulk onboard succeeded for user 1's safe |
| **T08** | At least one account exists in `e<runId>2_ADM` | `response.count -gt 0` | Bulk onboard succeeded for user 2's safe |
| **T09** | `e<runId>2_adm` has `automaticManagementEnabled = false` | `account.secretManagement.automaticManagementEnabled -eq $false` | CSV value `enableAutoMgmt=no` was correctly mapped through the bulk API |
| **T15** | User 1's account `userName` = `e<runId>1_adm` | `account.userName` from safe 1 accounts list | `accountUserPattern = '*_adm'` in config derived the account username (CSV column was blank) |
| **T16** | User 1's account `address` = `testenv.corp.com` | `account.address` from safe 1 accounts list | `accountAddress` in `UserConfigSet.default` was used (CSV column was blank) |

---

### Step 5 — Per-row SafeConfigSet / UserConfigSet validation

**Sub-test A** — named config set values applied: checks that the `alt` set (14-day retention) was used for user 3's safe.

| ID | Assertion | Verification method | Expected outcome |
| --- | --- | --- | --- |
| **T11** | Safe `e<runId>3_ADM` has `numberOfDaysRetention = 14` | `safe.numberOfDaysRetention` from `GET /api/Safes/e<runId>3_ADM` | The `alt` SafeConfigSet was merged in, overriding the default 7-day value |

**Sub-test B** — invalid set name skips row by default: a separate temp CSV is created with user 4 using `SafeConfigSet=DoesNotExistXYZ`. The main script is invoked without `-FallbackOnInvalidConfigSet`.

| ID | Assertion | Verification method | Expected outcome |
| --- | --- | --- | --- |
| **T12** | Safe `e<runId>4_ADM` does **not** exist | `GET /api/Safes/e<runId>4_ADM` returns null | Row was skipped because the set name is invalid and no fallback flag was passed |

**Sub-test C** — `-FallbackOnInvalidConfigSet` enables fallback: the same CSV is run again with the switch. The row should now be processed using the base (`default`) config.

| ID | Assertion | Verification method | Expected outcome |
| --- | --- | --- | --- |
| **T13** | Safe `e<runId>4_ADM` **does** exist | `GET /api/Safes/e<runId>4_ADM` returns non-null | `-FallbackOnInvalidConfigSet` caused the row to proceed with base config instead of skipping |

---

### Step 6 — Idempotency re-run

The main script is invoked a second time with identical parameters. Safes and members already exist; the script must handle `SFWS0002` (safe exists) and `SFWS0012` (already a member) gracefully.

| ID | Assertion | Verification method | Expected outcome |
| --- | --- | --- | --- |
| **T14** | Script exits without fatal error on re-run | `$LASTEXITCODE` is `$null` or `0` | Duplicate-safe and duplicate-member errors are handled gracefully (logged as warnings, not fatal) |

---

## Pass / fail criteria

| Outcome | Condition |
| --- | --- |
| **All pass** | Exit code `0`; all 17 assertions `PASS` |
| **Partial failure** | Exit code equals the number of failed assertions |
| **Fatal error** | Script throws an unhandled exception; remaining assertions are skipped |

---

## Running the tests

**Prerequisites satisfied via `CyberArkDefaults` (recommended):**

```powershell
Import-Module G:\epv-api-scripts\.Defaults\CyberArkDefaults.psd1
Set-CyberArkDefaults -PVWAUrl https://pvwa.lab.local/PasswordVault
.\Test-PersonalPrivilgedAccounts.ps1 -AccountPlatform WinDomain
```

**Explicit credential prompt:**

```powershell
.\Test-PersonalPrivilgedAccounts.ps1 -PVWAURL https://pvwa.lab.local/PasswordVault -AccountPlatform WinDomain
```

**With a PSCredential object:**

```powershell
$cred = Get-Credential
.\Test-PersonalPrivilgedAccounts.ps1 -PVWAURL https://pvwa.lab.local/PasswordVault -PVWACredentials $cred -AccountPlatform WinDomain
```

**Privilege Cloud (pre-obtained token):**

```powershell
# Get-IdentityHeader returns a header hashtable: @{ Authorization = "Bearer ..."; 'X-IDAP-NATIVE-CLIENT' = 'true' }
# PVWAURL is never embedded in the token — it must always be supplied separately.
$PCloudURL = 'https://tenant.privilegecloud.cyberark.cloud/PasswordVault'
$token = Get-IdentityHeader -IdentityUserName 'user@company.com' -PCloudURL $PCloudURL
$params = @{
    logonToken      = $token
    PVWAURL         = $PCloudURL
    AccountPlatform = 'WinDomain'
}
.\Test-PersonalPrivilgedAccounts.ps1 @params
```

**With self-signed certificate:**

```powershell
$params = @{
    PVWAURL                      = 'https://pvwa.lab.local/PasswordVault'
    DisableCertificateValidation = $true
    AccountPlatform              = 'WinDomain'
}
.\Test-PersonalPrivilgedAccounts.ps1 @params
```

**Manual run using the committed fixture files (fresh environment only):**

```powershell
# Replace <AccountPlatform> in the CSV and JSON with a real platform ID before running.
# Safe names are static (testuser1_ADM / testuser2_ADM) — do not use if those safes already exist.
$params = @{
    PVWAURL    = 'https://pvwa.lab.local/PasswordVault'
    CSVPath    = '.\Test-PersonalPrivilgedAccounts.csv'
    ConfigPath = '.\Test-PersonalPrivilgedAccounts.json'
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

---

## Known limitations

- **Safes are not deleted.** Test safes (`e<runId>*_ADM`) accumulate in the vault. Each run creates up to 4 safes (safe 4 is only created if T13 passes). They can be identified by the `e` prefix and 10-digit timestamp in the name.
- **T11 is conditional on T10.** If T10 fails (safe 3 not found), T11 is automatically marked as failed.
- **T15/T16 are conditional on T07.** If T07 fails (no accounts in safe 1), T15 and T16 are automatically skipped.
- **T06/T09 are conditional.** If T02/T08 fail (safe or account not found), T06/T09 are automatically skipped to avoid false failures from missing objects.
- **Default safe members are disabled** in the temp config. The test uses an empty `DefaultSafeMembers` array to avoid dependency on vault groups that may not exist in the test environment. To test default member behaviour, add entries to `$testConfig` in the runner or supply a real `-ConfigPath`.
- **`-AccountPlatform` is required.** The platform must already exist in the target vault. `WinDomain`, `WinServerLocal`, and `UnixSSH` are common values — confirm availability with your vault admin. The fixture files use the literal placeholder `<AccountPlatform>` that must be replaced before a manual run.
