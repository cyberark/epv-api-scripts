#Requires -Version 5.1
<#
.SYNOPSIS
    End-to-end test runner for Create-PersonalPrivilgedAccounts.ps1.
.DESCRIPTION
    Generates a unique run ID on every invocation, builds a temporary CSV and config
    file whose safe names embed that ID, executes the main script against a live
    CyberArk environment, then verifies the results via direct REST API calls.

    Every run ID produces unique safe names so there are no collisions between runs.
    In the finally block the script renames each test safe to DEL_<name> and then
    attempts to delete it. The DELETE call removes all accounts within the safe.
    The safe itself may persist if the vault retention policy prevents immediate deletion.
    Temporary CSV and config files are always removed in the finally block.

    Connection parameters are resolved from (highest to lowest priority):
      1. Parameters passed directly to this script
      2. $PSDefaultParameterValues set by the CyberArkDefaults module
         (run: Set-CyberArkDefaults -PVWAUrl ... or import CyberArkDefaults)

    Tests performed:
      T01  Script exits without fatal error (exit code 0) — first run
      T02  Safe for user 1 exists after run
      T03  Safe for user 2 exists after run
      T04  User 1 is a member of their safe
      T05  User 2 is a member of their safe
      T06  User 1's membership has viewAuditLog = true (EndUser role)
      T07  Account(s) onboarded into safe 1
      T08  Account(s) onboarded into safe 2
      T09  User 2's account has automaticManagementEnabled = false
      T10  Safe for user 3 exists (per-row SafeConfigSet 'alt' applied — row not skipped)
      T11  Safe for user 3 has numberOfDaysRetention = 14 (named config set values used)
      T12  Safe for user 4 does NOT exist without -FallbackOnInvalidConfigSet (row skipped)
      T13  Safe for user 4 DOES exist with -FallbackOnInvalidConfigSet (base config used)
      T14  Script exits without fatal error on re-run (idempotency)
      T15  User 1's onboarded account has userName = '<user1Name>_adm' (derived from accountUserPattern)
      T16  User 1's onboarded account has address = 'testenv.corp.com' (derived from config accountAddress)
      T17  User 3's membership has retrieveAccounts = false (SafeEndUserRoleConfigSet 'CustomSafeUser' applied)
      T18  No new account in user 5's safe on re-run with useExisting=false (row skipped when safe already exists)

    # TODO: Allow removal of the script runner's own vault account from a safe after
    #       creation, but ONLY if at least one DefaultSafeMembers entry has been granted
    #       Full control. This prevents the runner accumulating access to all created safes.
    #       Requires: new option in SafeConfigSet.Options (e.g. removeCreatorAfterSetup),
    #       a post-creation Full-member check in Create-PersonalPrivilgedAccounts.ps1,
    #       and corresponding CSV/JSON schema updates.
.PARAMETER PVWAURL
    PVWA base URL (e.g. https://pvwa.lab.local/PasswordVault).
    If omitted, falls back to $PSDefaultParameterValues set by CyberArkDefaults.

.PARAMETER AuthenticationType
    Authentication type for on-premises logon: cyberark | ldap | radius.
    Default: cyberark.

.PARAMETER PVWACredentials
    PSCredential for authentication. If omitted and no logonToken available,
    an interactive prompt is shown.

.PARAMETER logonToken
    Pre-obtained logon token (string or hashtable).
    If omitted, falls back to $PSDefaultParameterValues set by CyberArkDefaults.

.PARAMETER DisableCertificateValidation
    Bypass SSL certificate validation. Use only in test environments.

.PARAMETER ScriptPath
    Full path to Create-PersonalPrivilgedAccounts.ps1.
    Defaults to the same directory as this test script.

.PARAMETER CPMName
    CPM name assigned to test safes. Default: PasswordManager.

.PARAMETER SafeNamePattern
    Safe name pattern (must contain exactly one *). Default: *_ADM.

.PARAMETER AccountPlatform
    Platform ID to assign to test accounts (e.g. WinDomain, WinServerLocal, UnixSSH).
    Must already exist in the target vault. Required — no default is assumed.

.PARAMETER LogPath
    Path for the log file. Defaults to Test-PersonalPrivilgedAccounts.log in the script directory.

.PARAMETER KeepArtifacts
    Keep the temporary CSV and JSON config files after the run instead of deleting them.
    Useful for debugging failed assertions.

.OUTPUTS
    None. Results are written to both the console and the log file.
    Log file defaults to Test-PersonalPrivilgedAccounts.log in the script directory.
    Exit code 0 = all assertions passed; 1 = one or more failed.

.EXAMPLE
    # Relies on CyberArkDefaults already configured in the session:
    .\Test-PersonalPrivilgedAccounts.ps1

.EXAMPLE
    # Explicit connection (on-premises, interactive credential prompt):
    .\Test-PersonalPrivilgedAccounts.ps1 -PVWAURL https://pvwa.lab.local/PasswordVault

.EXAMPLE
    # Explicit connection with credential object:
    $cred = Get-Credential
    .\Test-PersonalPrivilgedAccounts.ps1 -PVWAURL https://pvwa.lab.local/PasswordVault -PVWACredentials $cred

.EXAMPLE
    # Using a pre-obtained token (e.g. from Get-IdentityHeader for PCloud):
    .\Test-PersonalPrivilgedAccounts.ps1 -PVWAURL https://tenant.privilegecloud.cyberark.cloud/PasswordVault -logonToken $token

.NOTES
    Version: 1.0
    Safe cleanup: each test safe is renamed to DEL_<name> and then deleted. The DELETE
    call removes all accounts within the safe. The safe itself may persist if the vault
    retention policy prevents immediate deletion.
#>
[CmdletBinding()]
param (
    #region Connection
    [Parameter(Mandatory = $false)]
    [string]$PVWAURL,

    [Parameter(Mandatory = $false)]
    [ValidateSet('cyberark', 'ldap', 'radius')]
    [string]$AuthenticationType = 'cyberark',

    [Parameter(Mandatory = $false)]
    [PSCredential]$PVWACredentials,

    [Parameter(Mandatory = $false)]
    $logonToken,

    [Parameter(Mandatory = $false)]
    [switch]$DisableCertificateValidation,
    #endregion

    #region Test configuration
    [Parameter(Mandatory = $false)]
    [string]$ScriptPath,

    [Parameter(Mandatory = $false)]
    [string]$CPMName = 'PasswordManager',

    [Parameter(Mandatory = $false)]
    [string]$SafeNamePattern = '*_ADM',

    [Parameter(Mandatory = $true)]
    [string]$AccountPlatform,

    [Parameter(Mandatory = $false)]
    [string]$LogPath,

    [Parameter(Mandatory = $false,
        HelpMessage = 'Keep temp CSV and JSON config files after the run instead of deleting them. Useful for debugging.')]
    [switch]$KeepArtifacts
    #endregion
)

Set-StrictMode -Off
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#region Setup

$testScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# MMddHHmmss = 10 chars → username ≤ 12 chars → safe name ≤ 16 chars (limit is 28)
$runId = Get-Date -Format 'MMddHHmmss'

# Default log path: same directory, same base name as this test script with .log extension
if ([string]::IsNullOrEmpty($LogPath)) {
    $LogPath = Join-Path -Path $testScriptDir -ChildPath (
        [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name) + '.log'
    )
}

#endregion

#region Resolve parameters from PSDefaultParameterValues (CyberArkDefaults module)

if ([string]::IsNullOrEmpty($PVWAURL)) {
    $urlKey = $global:PSDefaultParameterValues.Keys |
    Where-Object { $PSItem -like '*:PVWAURL' -or $PSItem -like '*:PVWAUrl' } |
    Select-Object -First 1
    if ($urlKey) {
        $PVWAURL = $global:PSDefaultParameterValues[$urlKey] 
    }
}

if ($null -eq $logonToken) {
    $tokenKey = $global:PSDefaultParameterValues.Keys |
    Where-Object { $PSItem -like '*:logonToken' } |
    Select-Object -First 1
    if ($tokenKey) {
        $logonToken = $global:PSDefaultParameterValues[$tokenKey] 
    }
}

if (-not $DisableCertificateValidation) {
    $sslKey = $global:PSDefaultParameterValues.Keys |
    Where-Object { $PSItem -like '*:DisableCertificateValidation' } |
    Select-Object -First 1
    if ($null -ne $sslKey -and $global:PSDefaultParameterValues[$sslKey]) {
        $DisableCertificateValidation = $true
    }
}

#endregion

#region Validate prerequisites

if ([string]::IsNullOrEmpty($PVWAURL)) {
    Write-TestLog 'ERROR: -PVWAURL is required. Pass it directly or run Set-CyberArkDefaults first.' -ForegroundColor Red
    exit 1
}

if ([string]::IsNullOrEmpty($ScriptPath)) {
    $ScriptPath = Join-Path -Path $testScriptDir -ChildPath 'Create-PersonalPrivilgedAccounts.ps1'
}

if (-not (Test-Path -Path $ScriptPath -PathType Leaf)) {
    Write-TestLog "ERROR: Script under test not found: $ScriptPath" -ForegroundColor Red
    exit 1
}

if ($DisableCertificateValidation) {
    if (-not ('DisableCertValidationCallback' -as [type])) {
        Add-Type -TypeDefinition @'
using System; using System.Net; using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class DisableCertValidationCallback {
    public static bool ReturnTrue(object s, X509Certificate c,
        X509Chain ch, SslPolicyErrors e) { return true; }
    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(DisableCertValidationCallback.ReturnTrue); }
}
'@
    }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback =
    [DisableCertValidationCallback]::GetDelegate()
}

#endregion

#region Helper functions

function Write-TestLog {
    <#
    .SYNOPSIS Writes a message to the console (coloured) and appends it to the test log file.
    .DESCRIPTION Drop-in replacement for Write-TestLog. Accepts the same first two parameters
                 so callers need only rename Write-TestLog to Write-TestLog.
    #>
    param(
        [Parameter(Position = 0)]
        [AllowEmptyString()]
        [AllowNull()]
        [Object]$Object = '',
        [Parameter(Mandatory = $false)]
        [System.ConsoleColor]$ForegroundColor
    )
    # Console output — preserve colours
    if ($PSBoundParameters.ContainsKey('ForegroundColor')) {
        Write-Host -Object $Object -ForegroundColor $ForegroundColor
    } else {
        Write-Host -Object $Object
    }

    # File output — skip if log path not resolved yet
    if ([string]::IsNullOrEmpty($LogPath)) {
        return 
    }

    $msg = if ($null -eq $Object) {
        '' 
    } else {
        [string]$Object 
    }
    if ([string]::IsNullOrEmpty($msg)) {
        '' | Out-File -Append -FilePath $LogPath -Encoding utf8
        return
    }

    $logPrefix = if ($PSBoundParameters.ContainsKey('ForegroundColor')) {
        switch ($ForegroundColor.ToString()) {
            'Red' {
                '[ERROR]  ' 
            }
            'DarkRed' {
                '[ERROR]  ' 
            }
            'Yellow' {
                '[WARNING]' 
            }
            'DarkYellow' {
                '[WARNING]' 
            }
            default {
                '[INFO]   ' 
            }
        }
    } else {
        '[INFO]   ' 
    }

    $timestamp = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')]`t"
    "$timestamp$logPrefix`t$msg" | Out-File -Append -FilePath $LogPath -Encoding utf8
}

function Get-TestAuthHeader {
    <#
    .SYNOPSIS Returns an Authorization hashtable for verification REST calls.
    #>
    if ($null -ne $logonToken) {
        if ($logonToken -is [hashtable]) {
            return $logonToken 
        }
        return @{ Authorization = $logonToken }
    }

    if ($null -eq $PVWACredentials) {
        $PVWACredentials = $Host.UI.PromptForCredential(
            'E2E Test Authentication',
            "Enter CyberArk credentials ($AuthenticationType)",
            '', '')
        if ($null -eq $PVWACredentials) {
            throw 'No credentials provided — cannot authenticate.' 
        }
    }

    $BSTR = $null
    try {
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PVWACredentials.Password)
        $plainPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        $authBody = @{
            username          = $PVWACredentials.UserName
            password          = $plainPwd
            concurrentSession = $true
        } | ConvertTo-Json -Compress

        $authParams = @{
            Uri         = "$($PVWAURL.TrimEnd('/'))/api/auth/$AuthenticationType/Logon"
            Method      = 'POST'
            Body        = $authBody
            ContentType = 'application/json'
            ErrorAction = 'Stop'
        }
        $token = Invoke-RestMethod @authParams
        return @{ Authorization = $token }
    } finally {
        if ($null -ne $BSTR) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR) 
        }
        $plainPwd = $null
    }
}

function Invoke-VerifyRest {
    <#
    .SYNOPSIS Lightweight REST wrapper for test assertions. Returns $null on failure.
    #>
    param (
        [Parameter(Mandatory = $true)]  [string]$Method,
        [Parameter(Mandatory = $true)]  [string]$URI,
        [Parameter(Mandatory = $true)]  [hashtable]$Header
    )
    try {
        $restParams = @{
            Uri         = $URI
            Method      = $Method
            Headers     = $Header
            ContentType = 'application/json'
            ErrorAction = 'Stop'
        }
        return Invoke-RestMethod @restParams
    } catch {
        return $null
    }
}

$testResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$safeReport = [System.Collections.Generic.List[PSCustomObject]]::new()

function Assert-Condition {
    param (
        [Parameter(Mandatory = $true)]  [string]$Id,
        [Parameter(Mandatory = $true)]  [string]$Description,
        [Parameter(Mandatory = $true)]  [bool]$Condition,
        [Parameter(Mandatory = $false)] [string]$FailDetail = ''
    )
    $status = if ($Condition) {
        'PASS' 
    } else {
        'FAIL' 
    }
    $color = if ($Condition) {
        'Green' 
    } else {
        'Red' 
    }

    Write-TestLog ('  [{0}] {1} - {2}' -f $status, $Id, $Description) -ForegroundColor $color
    if (-not $Condition -and -not [string]::IsNullOrEmpty($FailDetail)) {
        Write-TestLog ('        Detail: {0}' -f $FailDetail) -ForegroundColor DarkRed
    }

    $testResults.Add([PSCustomObject]@{
            Id          = $Id
            Description = $Description
            Status      = $status
            FailDetail  = $FailDetail
        })
}

#endregion

#region Test data — unique names per run

# Usernames: e{10}1 / e{10}4 = 12 chars max → safe names ≤ 16 chars (limit: 28)
$user1Name = "e${runId}1"
$user2Name = "e${runId}2"
$user3Name = "e${runId}3"   # named SafeConfigSet 'alt' — tests per-row config set
$user4Name = "e${runId}4"   # invalid SafeConfigSet — tests skip + fallback behaviour
$user5Name = "e${runId}5"   # useExisting=false — safe created first run; row skipped on re-run
$safe1Name = $SafeNamePattern.Replace('*', $user1Name)
$safe2Name = $SafeNamePattern.Replace('*', $user2Name)
$safe3Name = $SafeNamePattern.Replace('*', $user3Name)
$safe4Name = $SafeNamePattern.Replace('*', $user4Name)
$safe5Name = $SafeNamePattern.Replace('*', $user5Name)
$baseURL = $PVWAURL.TrimEnd('/')

# Runner user is a non-admin vault user created at test start so the BulkActions API works
# (the built-in Administrator account cannot call BulkActions/Accounts — PASWS291E).
$runUserName = "e${runId}run"
$runUserHeader = $null    # header for main-script invocations; falls back to $authHeader
$ownedRunSession = $false   # true when we logon as runner (so we logoff in finally)
$testVaultUserIds = @{}     # username -> userId — all created users are deleted in finally

$tempCsvPath = Join-Path -Path $testScriptDir -ChildPath "E2ETest_${runId}.csv"
$tempCsvPath2 = Join-Path -Path $testScriptDir -ChildPath "E2ETest_${runId}_invalid.csv"
$tempCsvPath3 = Join-Path -Path $testScriptDir -ChildPath "E2ETest_${runId}_noreuse.csv"
$tempConfigPath = Join-Path -Path $testScriptDir -ChildPath "E2ETest_${runId}_config.json"

#endregion

#region Banner

Write-TestLog ''
Write-TestLog ('=' * 72) -ForegroundColor Cyan
Write-TestLog '  E2E Test Runner — Create-PersonalPrivilgedAccounts.ps1' -ForegroundColor Cyan
Write-TestLog ('=' * 72) -ForegroundColor Cyan
Write-TestLog ('  Run ID     : {0}' -f $runId)
Write-TestLog ('  Safe 1     : {0}' -f $safe1Name)
Write-TestLog ('  Safe 2     : {0}' -f $safe2Name)
Write-TestLog ("  Safe 3     : {0}  (named SafeConfigSet 'alt')" -f $safe3Name)
Write-TestLog ('  Safe 4     : {0}  (invalid SafeConfigSet tests)' -f $safe4Name)
Write-TestLog ('  Safe 5     : {0}  (useExisting=false re-run test)' -f $safe5Name)
Write-TestLog ('  PVWA URL   : {0}' -f $PVWAURL)
Write-TestLog ('  Script     : {0}' -f $ScriptPath)
Write-TestLog ('  CPM        : {0}' -f $CPMName)
Write-TestLog ('  Platform   : {0}' -f $AccountPlatform)
Write-TestLog ('  Log file   : {0}' -f $LogPath)
Write-TestLog ('=' * 72) -ForegroundColor Cyan
Write-TestLog ''

#endregion

$authHeader = $null
$ownedSession = $false   # true when we authenticated (so we logoff in finally)

try {

    #region Build temp CSV
    # Test accounts:
    #   user1: auto-managed, safe name from pattern, accountUser BLANK (derived via accountUserPattern)
    #   user2: manual management, explicit safe name, explicit accountUser
    #   user3: per-row SafeConfigSet='alt' (14-day retention), accountUser BLANK (also derived)
    #   user5: useExisting=false — safe5 created on first run; re-run in Step 7 skips the row
    $csvContent = @(
        'userName,SafeConfigSet,SafeNamePattern,CPMName,NumberOfDaysRetention,NumberOfVersionsRetention,safeName,UserConfigSet,accountUser,password,accountAddress,accountPlatform,enableAutoMgmt,manualMgmtReason,remoteMachineAddresses,restrictMachineAccessToList'
        "${user1Name},,,,,,,,,,,${AccountPlatform},yes,,,"  # accountUser+accountAddress blank - derived from config
        "${user2Name},,,,,,${safe2Name},,${user2Name}_adm,,testenv.corp.com,${AccountPlatform},no,E2E test manual mgmt,,"  # explicit accountUser+address
        "${user3Name},alt,,,,,,,,,,${AccountPlatform},yes,,,"  # per-row SafeConfigSet, accountUser+address from config
        "${user5Name},noReuse,,,,,,,,,,${AccountPlatform},yes,,,"  # useExisting=false first run: safe does not exist yet, so it is created
    )
    $csvContent | Out-File -FilePath $tempCsvPath -Encoding utf8 -Force

    # Minimal config: no DefaultSafeMembers to avoid dependency on specific vault groups.
    # 'alt' SafeConfigSet has 14-day retention and SafeEndUserRoleConfigSet 'CustomSafeUser' -
    #   used by user3 to prove per-row config set merging AND SafeEndUserRoleConfigSet application.
    # 'CustomSafeUser' grants only useAccounts+listAccounts, so retrieveAccounts = false on user3.
    # accountUserPattern '*_adm' in UserConfigSet.Options derives account username from userName.
    # 'Vault Admins' group is added as a default safe member with Full access on every created safe.
    $testConfig = [ordered]@{
        SafeConfigSet = [ordered]@{
            default = [ordered]@{
                Options    = [ordered]@{
                    useExisting = $true
                }
                Properties = [ordered]@{
                    CPMName               = $CPMName
                    NumberOfDaysRetention = 7
                    SafeNamePattern       = $SafeNamePattern
                    DefaultSafeMembers    = @(
                        [ordered]@{
                            Name     = 'Vault Admins'
                            Role     = 'Full'
                            SearchIn = 'Vault'
                        }
                    )
                }
            }
            alt     = [ordered]@{
                Options    = [ordered]@{
                    useExisting = $true
                }
                Properties = [ordered]@{
                    NumberOfDaysRetention    = 14
                    SafeEndUserRoleConfigSet = 'CustomSafeUser'
                }
            }
            noReuse = [ordered]@{
                Options    = [ordered]@{
                    useExisting = $false
                }
                Properties = [ordered]@{
                    CPMName               = $CPMName
                    NumberOfDaysRetention = 7
                    SafeNamePattern       = $SafeNamePattern
                }
            }
        }
        UserConfigSet = [ordered]@{
            default = [ordered]@{
                Options    = [ordered]@{
                    accountUserPattern     = '*_adm'
                    allowDuplicateAccounts = $false
                }
                Properties = [ordered]@{
                    accountPlatform = $AccountPlatform
                    accountAddress  = 'testenv.corp.com'
                    enableAutoMgmt  = 'yes'
                }
            }
        }
        RoleConfigSet = [ordered]@{
            CustomSafeUser = [ordered]@{
                useAccounts  = $true
                listAccounts = $true
            }
        }
    }
    $testConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $tempConfigPath -Encoding utf8 -Force

    Write-TestLog "[SETUP] Temp CSV    : $tempCsvPath" -ForegroundColor Gray
    Write-TestLog "[SETUP] Temp config : $tempConfigPath" -ForegroundColor Gray
    Write-TestLog ''
    #endregion

    #region Authenticate (for verification REST calls)
    Write-TestLog '[AUTH] Resolving authentication for verification calls...' -ForegroundColor Gray
    $authHeader = Get-TestAuthHeader
    $ownedSession = ($null -eq $logonToken)   # we own the session only if we created it
    Write-TestLog '[AUTH] Done.' -ForegroundColor Gray
    Write-TestLog ''
    #endregion

    #region Create test vault users
    # Create the safe-member users (user1/2/3) so Add-SafeOwner can resolve them,
    # and a non-admin runner user so the BulkActions API is not blocked (PASWS291E).
    Write-TestLog '[SETUP] Creating test vault users...' -ForegroundColor Gray
    $testUserPassword = 'CyberArkE2E1!'

    foreach ($uname in @($user1Name, $user2Name, $user3Name, $user4Name, $user5Name)) {
        try {
            $createBody = @{
                username              = $uname
                initialPassword       = $testUserPassword
                userType              = 'EPVUser'
                changePassOnNextLogon = $false
            } | ConvertTo-Json -Compress
            $createResult = Invoke-RestMethod -Uri "$baseURL/api/Users" -Method POST `
                -Headers $authHeader -ContentType 'application/json' -Body $createBody -ErrorAction Stop
            $testVaultUserIds[$uname] = $createResult.id
            Write-TestLog "[SETUP] Created vault user: $uname (id=$($createResult.id))" -ForegroundColor Gray
        } catch {
            Write-TestLog "[SETUP] WARN: Could not create vault user '$uname': $($PSItem.Exception.Message)" -ForegroundColor Yellow
        }
    }

    # Runner user — needs AddSafes vault authorization; avoids built-in Administrator restriction.
    try {
        $runUserBody = @{
            username              = $runUserName
            initialPassword       = $testUserPassword
            userType              = 'EPVUser'
            changePassOnNextLogon = $false
            vaultAuthorization    = @('AddSafes')
        } | ConvertTo-Json -Compress
        $runUserResult = Invoke-RestMethod -Uri "$baseURL/api/Users" -Method POST `
            -Headers $authHeader -ContentType 'application/json' -Body $runUserBody -ErrorAction Stop
        $testVaultUserIds[$runUserName] = $runUserResult.id
        Write-TestLog "[SETUP] Created runner vault user: $runUserName (id=$($runUserResult.id))" -ForegroundColor Gray

        $runLogonBody = @{
            username          = $runUserName
            password          = $testUserPassword
            concurrentSession = $true
        } | ConvertTo-Json -Compress
        $runToken = Invoke-RestMethod -Uri "$baseURL/api/auth/cyberark/Logon" `
            -Method POST -ContentType 'application/json' -Body $runLogonBody -ErrorAction Stop
        $runUserHeader = @{ Authorization = $runToken }
        $ownedRunSession = $true
        Write-TestLog "[SETUP] Runner user $runUserName authenticated." -ForegroundColor Gray
    } catch {
        Write-TestLog "[SETUP] WARN: Runner user setup failed: $($PSItem.Exception.Message). Using admin token." -ForegroundColor Yellow
    }

    if ($null -eq $runUserHeader) {
        $runUserHeader = $authHeader 
    }
    Write-TestLog ''
    #endregion

    # Common params passed to the main script
    $mainScriptParams = @{
        PVWAURL         = $PVWAURL
        logonToken      = $runUserHeader    # non-admin runner so BulkActions API is not blocked
        CSVPath         = $tempCsvPath
        ConfigPath      = $tempConfigPath
        SafeNamePattern = $SafeNamePattern
    }
    if ($DisableCertificateValidation) {
        $mainScriptParams.DisableCertificateValidation = $true 
    }

    # ─────────────────────────────────────────────────────────────────────────
    # Step 1 — Execute main script (first run: create safes + onboard accounts)
    # ─────────────────────────────────────────────────────────────────────────
    Write-TestLog ('─' * 72) -ForegroundColor DarkCyan
    Write-TestLog ' Step 1: Execute main script (first run)' -ForegroundColor DarkCyan
    Write-TestLog ('─' * 72) -ForegroundColor DarkCyan

    $null = $LASTEXITCODE
    & $ScriptPath @mainScriptParams
    $step1ExitCode = $LASTEXITCODE

    Assert-Condition -Id 'T01' `
        -Description 'Script exits without fatal error code (first run)' `
        -Condition ($null -eq $step1ExitCode -or $step1ExitCode -eq 0) `
        -FailDetail "Exit code: $step1ExitCode"

    Write-TestLog ''

    # ─────────────────────────────────────────────────────────────────────────
    # Step 2 — Verify safes were created
    # ─────────────────────────────────────────────────────────────────────────
    Write-TestLog ('─' * 72) -ForegroundColor DarkCyan
    Write-TestLog ' Step 2: Verify safes exist' -ForegroundColor DarkCyan
    Write-TestLog ('─' * 72) -ForegroundColor DarkCyan

    $safe1Result = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Safes/$([URI]::EscapeDataString($safe1Name))" `
        -Header $runUserHeader
    Assert-Condition -Id 'T02' `
        -Description "Safe '$safe1Name' exists in the vault" `
        -Condition ($null -ne $safe1Result) `
        -FailDetail 'GET /api/Safes returned null — safe may not have been created'

    $safe2Result = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Safes/$([URI]::EscapeDataString($safe2Name))" `
        -Header $runUserHeader
    Assert-Condition -Id 'T03' `
        -Description "Safe '$safe2Name' exists in the vault" `
        -Condition ($null -ne $safe2Result) `
        -FailDetail 'GET /api/Safes returned null — safe may not have been created'

    $safe3Result = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Safes/$([URI]::EscapeDataString($safe3Name))" `
        -Header $runUserHeader
    Assert-Condition -Id 'T10' `
        -Description "Safe '$safe3Name' exists (per-row SafeConfigSet 'alt' applied — row not skipped)" `
        -Condition ($null -ne $safe3Result) `
        -FailDetail 'GET /api/Safes returned null — safe may not have been created'

    Write-TestLog ''

    # ─────────────────────────────────────────────────────────────────────────
    # Step 3 — Verify safe owners
    # ─────────────────────────────────────────────────────────────────────────
    Write-TestLog ('─' * 72) -ForegroundColor DarkCyan
    Write-TestLog ' Step 3: Verify safe owners (EndUser role)' -ForegroundColor DarkCyan
    Write-TestLog ('─' * 72) -ForegroundColor DarkCyan

    $member1 = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Safes/$([URI]::EscapeDataString($safe1Name))/Members/$([URI]::EscapeDataString($user1Name))" `
        -Header $runUserHeader
    Assert-Condition -Id 'T04' `
        -Description "'$user1Name' is a member of '$safe1Name'" `
        -Condition ($null -ne $member1) `
        -FailDetail "GET /Members/$user1Name returned null"

    $member2 = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Safes/$([URI]::EscapeDataString($safe2Name))/Members/$([URI]::EscapeDataString($user2Name))" `
        -Header $runUserHeader
    Assert-Condition -Id 'T05' `
        -Description "'$user2Name' is a member of '$safe2Name'" `
        -Condition ($null -ne $member2) `
        -FailDetail "GET /Members/$user2Name returned null"

    # Spot-check permissions — EndUser role must have viewAuditLog = true
    if ($null -ne $member1) {
        Assert-Condition -Id 'T06' `
            -Description "'$user1Name' has viewAuditLog = true (EndUser role confirmed)" `
            -Condition ($member1.permissions.viewAuditLog -eq $true) `
            -FailDetail "permissions.viewAuditLog = $($member1.permissions.viewAuditLog)"
    }

    # T17 — user3 safe used SafeConfigSet='alt' which has SafeEndUserRoleConfigSet='CustomSafeUser'.
    # CustomSafeUser grants only useAccounts+listAccounts, so retrieveAccounts must be false.
    $member3 = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Safes/$([URI]::EscapeDataString($safe3Name))/Members/$([URI]::EscapeDataString($user3Name))" `
        -Header $runUserHeader
    if ($null -ne $member3) {
        Assert-Condition -Id 'T17' `
            -Description "'$user3Name' has retrieveAccounts = false (SafeEndUserRoleConfigSet 'CustomSafeUser' applied)" `
            -Condition ($member3.permissions.retrieveAccounts -ne $true) `
            -FailDetail "permissions.retrieveAccounts = $($member3.permissions.retrieveAccounts)"
    }

    Write-TestLog ''

    # ─────────────────────────────────────────────────────────────────────────
    # Step 4 — Verify accounts were onboarded via Bulk API
    # ─────────────────────────────────────────────────────────────────────────
    Write-TestLog ('─' * 72) -ForegroundColor DarkCyan
    Write-TestLog ' Step 4: Verify accounts onboarded' -ForegroundColor DarkCyan
    Write-TestLog ('─' * 72) -ForegroundColor DarkCyan

    $accts1 = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Accounts?filter=$([URI]::EscapeDataString("safeName eq $safe1Name"))" `
        -Header $runUserHeader
    Assert-Condition -Id 'T07' `
        -Description "Account(s) exist in '$safe1Name'" `
        -Condition ($null -ne $accts1 -and $accts1.count -gt 0) `
        -FailDetail "count = $($accts1.count)"

    # Spot-check: user1 accountUser and accountAddress were derived from config (CSV columns blank)
    if ($null -ne $accts1 -and $accts1.count -gt 0) {
        $u1Account = $accts1.value | Select-Object -First 1
        Assert-Condition -Id 'T15' `
            -Description "'${user1Name}_adm' is the onboarded account userName (derived from accountUserPattern)" `
            -Condition ($u1Account.userName -eq "${user1Name}_adm") `
            -FailDetail "userName = $($u1Account.userName)"
        Assert-Condition -Id 'T16' `
            -Description "Account address = 'testenv.corp.com' (derived from config accountAddress)" `
            -Condition ($u1Account.address -eq 'testenv.corp.com') `
            -FailDetail "address = $($u1Account.address)"
    }

    $accts2 = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Accounts?filter=$([URI]::EscapeDataString("safeName eq $safe2Name"))" `
        -Header $runUserHeader
    Assert-Condition -Id 'T08' `
        -Description "Account(s) exist in '$safe2Name'" `
        -Condition ($null -ne $accts2 -and $accts2.count -gt 0) `
        -FailDetail "count = $($accts2.count)"

    # Spot-check: user2 account must have automaticManagementEnabled = false
    if ($null -ne $accts2 -and $accts2.count -gt 0) {
        $u2Account = $accts2.value |
        Where-Object { $PSItem.userName -eq "${user2Name}_adm" } |
        Select-Object -First 1
        if ($null -ne $u2Account) {
            Assert-Condition -Id 'T09' `
                -Description "'${user2Name}_adm' has automaticManagementEnabled = false" `
                -Condition ($u2Account.secretManagement.automaticManagementEnabled -eq $false) `
                -FailDetail "automaticManagementEnabled = $($u2Account.secretManagement.automaticManagementEnabled)"
        } else {
            Assert-Condition -Id 'T09' `
                -Description "'${user2Name}_adm' found in accounts list" `
                -Condition $false `
                -FailDetail 'Account not found in safe2 accounts response'
        }
    }

    Write-TestLog ''

    # ─────────────────────────────────────────────────────────────────────────
    # Step 5 — Per-row SafeConfigSet/UserConfigSet validation
    # ─────────────────────────────────────────────────────────────────────────
    Write-TestLog ('─' * 72) -ForegroundColor DarkCyan
    Write-TestLog ' Step 5: Per-row SafeConfigSet/UserConfigSet validation' -ForegroundColor DarkCyan
    Write-TestLog ('─' * 72) -ForegroundColor DarkCyan

    # T11 — named config set values were actually applied (safe3 should have 14-day retention)
    if ($null -ne $safe3Result) {
        Assert-Condition -Id 'T11' `
            -Description "Safe '$safe3Name' has numberOfDaysRetention = 14 (named 'alt' config set applied)" `
            -Condition ($safe3Result.numberOfDaysRetention -eq 14) `
            -FailDetail "numberOfDaysRetention = $($safe3Result.numberOfDaysRetention)"
    } else {
        Assert-Condition -Id 'T11' `
            -Description "Safe '$safe3Name' retention cannot be verified (T10 failed)" `
            -Condition $false `
            -FailDetail 'Safe does not exist — cannot verify retention'
    }

    # T12/T13 — invalid SafeConfigSet: row skipped by default; safe created when -FallbackOnInvalidConfigSet used
    $invalidSetCsvContent = @(
        'userName,SafeConfigSet,SafeNamePattern,CPMName,NumberOfDaysRetention,NumberOfVersionsRetention,safeName,UserConfigSet,accountUser,password,accountAddress,accountPlatform,enableAutoMgmt,manualMgmtReason,remoteMachineAddresses,restrictMachineAccessToList'
        "${user4Name},DoesNotExistXYZ,,,,,,,,,,${AccountPlatform},yes,,,"
    )
    $invalidSetCsvContent | Out-File -FilePath $tempCsvPath2 -Encoding utf8 -Force

    $skipTestParams = @{
        PVWAURL         = $PVWAURL
        logonToken      = $runUserHeader
        CSVPath         = $tempCsvPath2
        ConfigPath      = $tempConfigPath
        SafeNamePattern = $SafeNamePattern
    }
    if ($DisableCertificateValidation) {
        $skipTestParams.DisableCertificateValidation = $true 
    }

    Write-TestLog '  Sub-test A: invalid SafeConfigSet without -FallbackOnInvalidConfigSet (row should be skipped)' -ForegroundColor Gray
    $null = $LASTEXITCODE
    & $ScriptPath @skipTestParams

    $safe4BeforeFallback = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Safes/$([URI]::EscapeDataString($safe4Name))" `
        -Header $runUserHeader
    Assert-Condition -Id 'T12' `
        -Description "Safe '$safe4Name' does NOT exist (invalid SafeConfigSet skips row by default)" `
        -Condition ($null -eq $safe4BeforeFallback) `
        -FailDetail 'Safe exists — row should have been skipped due to invalid SafeConfigSet'

    Write-TestLog '  Sub-test B: same row with -FallbackOnInvalidConfigSet (safe should be created using base config)' -ForegroundColor Gray
    $fallbackTestParams = @{
        PVWAURL                    = $PVWAURL
        logonToken                 = $runUserHeader
        CSVPath                    = $tempCsvPath2
        ConfigPath                 = $tempConfigPath
        SafeNamePattern            = $SafeNamePattern
        FallbackOnInvalidConfigSet = $true
    }
    if ($DisableCertificateValidation) {
        $fallbackTestParams.DisableCertificateValidation = $true 
    }

    $null = $LASTEXITCODE
    & $ScriptPath @fallbackTestParams

    $safe4AfterFallback = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Safes/$([URI]::EscapeDataString($safe4Name))" `
        -Header $runUserHeader
    Assert-Condition -Id 'T13' `
        -Description "Safe '$safe4Name' DOES exist after -FallbackOnInvalidConfigSet run (base config used)" `
        -Condition ($null -ne $safe4AfterFallback) `
        -FailDetail 'Safe not found — fallback may not have applied correctly'

    Write-TestLog ''

    # ─────────────────────────────────────────────────────────────────────────
    # Step 6 — Idempotency: re-run against safes that already exist
    # ─────────────────────────────────────────────────────────────────────────
    Write-TestLog ('─' * 72) -ForegroundColor DarkCyan
    Write-TestLog ' Step 6: Idempotency — re-run with safes already present' -ForegroundColor DarkCyan
    Write-TestLog ('─' * 72) -ForegroundColor DarkCyan
    Write-TestLog '  (Safe-already-exists errors are expected and should be handled gracefully)' -ForegroundColor Gray
    Write-TestLog '  (-AllowDuplicateAccounts is passed so account creation is not skipped)' -ForegroundColor Gray
    Write-TestLog ''

    $null = $LASTEXITCODE
    & $ScriptPath @mainScriptParams -AllowDuplicateAccounts
    $step6ExitCode = $LASTEXITCODE

    Assert-Condition -Id 'T14' `
        -Description 'Script exits without fatal error code on re-run (idempotency)' `
        -Condition ($null -eq $step6ExitCode -or $step6ExitCode -eq 0) `
        -FailDetail "Exit code: $step6ExitCode"

    Write-TestLog ''

    # ─────────────────────────────────────────────────────────────────────────
    # Step 7 — useExisting=false: re-run for user5 whose safe already exists
    #           -AllowDuplicateAccounts is passed so any skip is solely due to
    #           useExisting=false, not the duplicate-account check.
    #           Expected: account count in safe5 remains 1 (row is skipped).
    # ─────────────────────────────────────────────────────────────────────────
    Write-TestLog ('─' * 72) -ForegroundColor DarkCyan
    Write-TestLog ' Step 7: useExisting=false — row skipped when safe already exists' -ForegroundColor DarkCyan
    Write-TestLog ('─' * 72) -ForegroundColor DarkCyan
    Write-TestLog "  (Safe '$safe5Name' was created in Step 1; re-run with noReuse config should skip the row)" -ForegroundColor Gray
    Write-TestLog ''

    @(
        'userName,SafeConfigSet,SafeNamePattern,CPMName,NumberOfDaysRetention,NumberOfVersionsRetention,safeName,UserConfigSet,accountUser,password,accountAddress,accountPlatform,enableAutoMgmt,manualMgmtReason,remoteMachineAddresses,restrictMachineAccessToList'
        "${user5Name},noReuse,,,,,,,,,,${AccountPlatform},yes,,,"
    ) | Out-File -FilePath $tempCsvPath3 -Encoding utf8 -Force

    $noReuseParams = @{
        PVWAURL                = $PVWAURL
        logonToken             = $runUserHeader
        CSVPath                = $tempCsvPath3
        ConfigPath             = $tempConfigPath
        SafeNamePattern        = $SafeNamePattern
        AllowDuplicateAccounts = $true   # isolate: skip must be from useExisting=false, not duplicate check
    }
    if ($DisableCertificateValidation) {
        $noReuseParams.DisableCertificateValidation = $true 
    }

    $null = $LASTEXITCODE
    & $ScriptPath @noReuseParams

    $accts5After = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Accounts?filter=$([URI]::EscapeDataString("safeName eq $safe5Name"))" `
        -Header $runUserHeader
    $accts5Count = if ($null -ne $accts5After) {
        $accts5After.count 
    } else {
        0 
    }
    Assert-Condition -Id 'T18' `
        -Description "Account count in '$safe5Name' is still 1 after re-run (useExisting=false skipped the row)" `
        -Condition ($accts5Count -eq 1) `
        -FailDetail "account count = $accts5Count — expected 1; if 2, useExisting=false did not skip the row"

    Write-TestLog ''

} catch {
    Write-TestLog ''
    Write-TestLog "FATAL: Unexpected error during test execution: $($PSItem.Exception.Message)" -ForegroundColor Red
    Write-TestLog "       $($PSItem.ScriptStackTrace)" -ForegroundColor DarkRed
} finally {
    # Rename test safes to DEL_ prefix then attempt deletion.
    # Must run BEFORE runner logoff — the runner user is a safe member and can manage safes.
    # The rename marks safes visually; DELETE removes all accounts even if the safe
    # itself cannot be fully purged due to vault retention policy.
    $safeHeader = if ($null -ne $runUserHeader) {
        $runUserHeader 
    } else {
        $authHeader 
    }
    if ($null -ne $safeHeader) {
        $safesToCleanup = [System.Collections.Generic.List[string]]::new()
        foreach ($sn in @($safe1Name, $safe2Name, $safe3Name, $safe5Name)) {
            $safesToCleanup.Add($sn) 
        }
        # Include safe4 only if it was actually created (T13 scenario)
        if ($null -ne $safe4AfterFallback) {
            $safesToCleanup.Add($safe4Name) 
        }

        Write-TestLog "[CLEANUP] Renaming and deleting $($safesToCleanup.Count) test safe(s)..." -ForegroundColor Gray
        foreach ($safeToClean in $safesToCleanup) {
            $delSafeName = "DEL_$safeToClean"
            $renamed = $false

            # Collect accounts in the safe for the report (query before rename)
            $safeAccounts = @()
            $safeDetails = $null
            try {
                $acctResp = Invoke-RestMethod -Uri "$baseURL/api/Accounts?filter=$([URI]::EscapeDataString("safeName eq $safeToClean"))" `
                    -Method GET -Headers $safeHeader -ContentType 'application/json' -ErrorAction Stop
                if ($acctResp.count -gt 0) {
                    # Deduplicate by id, keep full object for report
                    $safeAccounts = @($acctResp.value | Sort-Object id -Unique |
                        ForEach-Object {
                            [PSCustomObject]@{
                                Id       = $PSItem.id
                                Name     = $PSItem.name
                                UserName = $PSItem.userName
                                Address  = $PSItem.address
                                SafeName = $PSItem.safeName
                            }
                        })
                }
            } catch { 
            }

            try {
                # GET current safe properties so PUT can echo them back unchanged except safeName
                $safeDetails = Invoke-RestMethod -Uri "$baseURL/api/Safes/$([URI]::EscapeDataString($safeToClean))" `
                    -Method GET -Headers $safeHeader -ContentType 'application/json' -ErrorAction Stop
                $putBody = @{
                    safeName              = $delSafeName
                    description           = if ($safeDetails.description) {
                        $safeDetails.description 
                    } else {
                        '' 
                    }
                    olacEnabled           = [bool]$safeDetails.olacEnabled
                    managingCPM           = if ($safeDetails.managingCPM) {
                        $safeDetails.managingCPM 
                    } else {
                        '' 
                    }
                    numberOfDaysRetention = [int]$safeDetails.numberOfDaysRetention
                } | ConvertTo-Json -Compress
                Invoke-RestMethod -Uri "$baseURL/api/Safes/$([URI]::EscapeDataString($safeToClean))" `
                    -Method PUT -Headers $safeHeader -ContentType 'application/json' `
                    -Body $putBody -ErrorAction Stop | Out-Null
                Write-TestLog "[CLEANUP] Renamed safe '$safeToClean' -> '$delSafeName'" -ForegroundColor Gray
                $renamed = $true
            } catch {
                Write-TestLog "[CLEANUP] Could not rename safe '$safeToClean': $($PSItem.Exception.Message)" -ForegroundColor Yellow
            }

            # Record safe in report
            $safeReport.Add([PSCustomObject]@{
                    OriginalName = $safeToClean
                    FinalName    = if ($renamed) {
                        $delSafeName 
                    } else {
                        $safeToClean 
                    }
                    Renamed      = $renamed
                    SafeNumber   = if ($null -ne $safeDetails) {
                        $safeDetails.safeNumber 
                    } else {
                        $null 
                    }
                    Accounts     = $safeAccounts
                })

            $nameToDelete = if ($renamed) {
                $delSafeName 
            } else {
                $safeToClean 
            }
            try {
                Invoke-RestMethod -Uri "$baseURL/api/Safes/$([URI]::EscapeDataString($nameToDelete))" `
                    -Method DELETE -Headers $safeHeader -ContentType 'application/json' `
                    -ErrorAction Stop | Out-Null
                Write-TestLog "[CLEANUP] Deleted safe '$nameToDelete'" -ForegroundColor Gray
            } catch {
                Write-TestLog "[CLEANUP] Delete attempted on '$nameToDelete' (accounts removed; safe may persist due to retention): $($PSItem.Exception.Message)" -ForegroundColor Gray
            }
        }
    }

    # Logoff runner user if this test created it
    if ($ownedRunSession -and $null -ne $runUserHeader) {
        try {
            Invoke-RestMethod -Uri "$baseURL/api/Auth/Logoff" -Method POST `
                -Headers $runUserHeader -ContentType 'application/json' `
                -ErrorAction SilentlyContinue | Out-Null
            Write-TestLog '[CLEANUP] Runner user session logged off.' -ForegroundColor Gray
        } catch { 
        }
    }

    # Delete all test vault users created during setup
    if ($testVaultUserIds.Count -gt 0) {
        Write-TestLog "[CLEANUP] Deleting $($testVaultUserIds.Count) test vault user(s)..." -ForegroundColor Gray
        foreach ($entry in $testVaultUserIds.GetEnumerator()) {
            try {
                Invoke-RestMethod -Uri "$baseURL/api/Users/$($entry.Value)" -Method DELETE `
                    -Headers $authHeader -ContentType 'application/json' `
                    -ErrorAction SilentlyContinue | Out-Null
                Write-TestLog "[CLEANUP] Deleted vault user: $($entry.Key) (id=$($entry.Value))" -ForegroundColor Gray
            } catch {
                Write-TestLog "[CLEANUP] Could not delete vault user '$($entry.Key)': $($PSItem.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }

    # Remove temp files
    if ($KeepArtifacts) {
        Write-TestLog '[CLEANUP] -KeepArtifacts set — temp CSV and config files retained:' -ForegroundColor Yellow
        Write-TestLog "          $tempCsvPath" -ForegroundColor Yellow
        Write-TestLog "          $tempCsvPath2" -ForegroundColor Yellow
        Write-TestLog "          $tempCsvPath3" -ForegroundColor Yellow
        Write-TestLog "          $tempConfigPath" -ForegroundColor Yellow
    } else {
        if (Test-Path -Path $tempCsvPath) {
            Remove-Item -Path $tempCsvPath -Force 
        }
        if (Test-Path -Path $tempCsvPath2) {
            Remove-Item -Path $tempCsvPath2 -Force 
        }
        if (Test-Path -Path $tempCsvPath3) {
            Remove-Item -Path $tempCsvPath3 -Force 
        }
        if (Test-Path -Path $tempConfigPath) {
            Remove-Item -Path $tempConfigPath -Force 
        }
        Write-TestLog '[CLEANUP] Temp CSV and config removed.' -ForegroundColor Gray
    }

    # Logoff only if this test script performed authentication
    if ($ownedSession -and $null -ne $authHeader) {
        try {
            $logoffParams = @{
                Uri         = "$baseURL/api/Auth/Logoff"
                Method      = 'POST'
                Headers     = $authHeader
                ContentType = 'application/json'
                ErrorAction = 'SilentlyContinue'
            }
            Invoke-RestMethod @logoffParams | Out-Null
            Write-TestLog '[CLEANUP] Session logged off.' -ForegroundColor Gray
        } catch {
            Write-TestLog '[CLEANUP] Logoff skipped (session may have already expired).' -ForegroundColor Gray
        }
    } else {
        Write-TestLog '[CLEANUP] Session owned externally — not logging off.' -ForegroundColor Gray
    }
}

#region Summary

$passedCount = ($testResults | Where-Object { $PSItem.Status -eq 'PASS' }).Count
$failedCount = ($testResults | Where-Object { $PSItem.Status -eq 'FAIL' }).Count
$totalCount = $testResults.Count

Write-TestLog ''
Write-TestLog ('=' * 72) -ForegroundColor Cyan
$summaryColor = if ($failedCount -eq 0) {
    'Green' 
} else {
    'Red' 
}
Write-TestLog ('  RESULTS: {0} passed, {1} failed out of {2} assertions' -f $passedCount, $failedCount, $totalCount) -ForegroundColor $summaryColor
Write-TestLog ('=' * 72) -ForegroundColor Cyan

if ($failedCount -gt 0) {
    Write-TestLog ''
    Write-TestLog 'Failed assertions:' -ForegroundColor Red
    $testResults | Where-Object { $PSItem.Status -eq 'FAIL' } | ForEach-Object {
        Write-TestLog ('  [{0}] {1}' -f $PSItem.Id, $PSItem.Description) -ForegroundColor Red
        if (-not [string]::IsNullOrEmpty($PSItem.FailDetail)) {
            Write-TestLog ('        {0}' -f $PSItem.FailDetail) -ForegroundColor DarkRed
        }
    }
}

# Safe + account report
if ($safeReport.Count -gt 0) {
    Write-TestLog ''
    Write-TestLog ('─' * 72) -ForegroundColor Cyan
    Write-TestLog '  SAFE & ACCOUNT REPORT' -ForegroundColor Cyan
    Write-TestLog ('─' * 72) -ForegroundColor Cyan
    foreach ($entry in $safeReport) {
        $renameTag = if ($entry.Renamed) {
            "-> $($entry.FinalName)" 
        } else {
            '(rename failed — kept original name)' 
        }
        $safeNumTag = if ($null -ne $entry.SafeNumber) {
            "  [safeNumber: $($entry.SafeNumber)]" 
        } else {
            '' 
        }
        Write-TestLog "  Safe : $($entry.OriginalName)  $renameTag$safeNumTag" -ForegroundColor Yellow
        if ($entry.Accounts.Count -gt 0) {
            foreach ($acct in $entry.Accounts) {
                Write-TestLog "    Account  ID   : $($acct.Id)" -ForegroundColor Gray
                Write-TestLog "             Name : $($acct.Name)  [$($acct.UserName)@$($acct.Address)]  [safe: $($acct.SafeName)]" -ForegroundColor Gray
            }
        } else {
            Write-TestLog '    (no accounts found)' -ForegroundColor DarkYellow
        }
    }
    Write-TestLog ('─' * 72) -ForegroundColor Cyan
}
Write-TestLog ''

#endregion

exit $failedCount
