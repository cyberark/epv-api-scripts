#Requires -Version 5.1
<#
.SYNOPSIS
    Validates a PersonalPrivilegedAccounts.json config file against a live CyberArk vault.

.DESCRIPTION
    Creates test safes and accounts to verify that every SafeConfigSet and UserConfigSet
    defined in the config file behaves as expected in a real vault environment.

    Safe Config Set (SCS) validation
      One safe is created per SafeConfigSet entry (top-down JSON order, numbered 1..N).
      Safe names are generated as 'scs_<runId>_<N>' -- independent of -EndUserName so
      safe-name uniqueness never depends on the provided user existing.
      Safes are created with createSafeOnly=true so no accounts are onboarded into them.
      This keeps the safes empty, allowing clean deletion during cleanup.
      Assertions: safe exists, retention, CPM, Vault Admins Full, each DefaultSafeMembers
      entry (all 22 permissions), end-user permissions (WARNING only if user not found).

    User Config Set (UCS) validation
      One shared safe is pre-created directly via API (PasswordManager CPM, 1-day retention,
      Vault Admins Full). All UCS accounts are onboarded into this single safe.
      One CSV row per UserConfigSet drives account onboarding into that shared safe.
      Assertions: account exists, userName (pattern applied), address, platformId,
      automaticManagementEnabled, and any extra UserDefaults keys.

    No vault users are created by this script. -EndUserName must reference an existing
    vault user; if not found, enduser-permission assertions are recorded as WARNING.

    Use -SeedLabUsers to pre-create EPVUser accounts for every DefaultSafeMembers Name
    that does not already exist (requires -SeedPassword). Seeded users are deleted during
    cleanup.

    After the run a JSON report file is written. Re-run with -Cleanup -ReportPath <file>
    to rename/delete all test safes and delete seeded users.

    # TODO: Allow removal of the script runner's own vault account from a safe after
    #       creation, but ONLY if at least one DefaultSafeMembers entry has been granted
    #       Full control. This prevents the runner accumulating access to all created safes.
    #       Requires: new option in SafeConfigSet.Options (e.g. removeCreatorAfterSetup),
    #       a post-creation Full-member check in Create-PersonalPrivilgedAccounts.ps1,
    #       and corresponding CSV/JSON schema updates.

.PARAMETER ConfigPath
    Path to the PersonalPrivilegedAccounts.json file to validate.
    Required unless -Cleanup is specified.

.PARAMETER PVWAURL
    PVWA base URL (e.g. https://pvwa.lab.local/PasswordVault).
    Falls back to $PSDefaultParameterValues if omitted.

.PARAMETER AuthenticationType
    On-premises authentication type: cyberark | ldap | radius. Default: cyberark.

.PARAMETER PVWACredentials
    PSCredential for authentication. Prompted interactively if omitted.

.PARAMETER logonToken
    Pre-obtained logon token (string or hashtable). Falls back to $PSDefaultParameterValues.

.PARAMETER DisableCertificateValidation
    Bypass SSL certificate validation. Use only in test environments.

.PARAMETER ScriptPath
    Full path to Create-PersonalPrivilgedAccounts.ps1.
    Defaults to the same directory as this script.

.PARAMETER EndUserName
    Existing vault username used as the safe owner (CSV userName) on all Zone 1 rows.
    If this user does not exist in the vault, enduser-permission assertions are WARNING only.
    Required unless -Cleanup is specified.

.PARAMETER SeedLabUsers
    Pre-create EPVUser vault accounts for each DefaultSafeMembers Name not already present.
    Requires -SeedPassword. Created users are recorded in the report and deleted on cleanup.

.PARAMETER SeedPassword
    Initial password for seeded vault users (SecureString). Required when -SeedLabUsers is set.

.PARAMETER ReportPath
    Path for the JSON report file (cleanup mode) or output report path (normal mode).
    Default (normal mode): <ConfigBaseName>_<runId>_report.json in the script directory.
    Required when -Cleanup is specified.

.PARAMETER Cleanup
    Cleanup mode. Reads the report at -ReportPath and:
      - Renames/deletes Zone 1 and Zone 2 test safes
      - Deletes seeded vault users
    Requires -ReportPath.

.PARAMETER SkipSafeConfigSets
    Skip Safe Config Set validation. Useful when you only want to test User Config Sets.

.PARAMETER SkipUserConfigSets
    Skip User Config Set validation. Useful when you only want to test Safe Config Sets.

.PARAMETER KeepArtifacts
    Retain temp CSV and config files after the run. Useful for debugging.

.PARAMETER LogPath
    Path for the log file. Default: Test-PersonalPrivilgedAccountsConfig.log in script dir.

.OUTPUTS
    None. Results are written to the console and the log file.
    Exit code 0 = all assertions passed (or warnings only); 1 = one or more FAILs.

.EXAMPLE
    # Normal run against the lab config:
    $params = @{
        ConfigPath  = '.\PersonalPrivilegedAccounts.json'
        PVWAURL     = 'https://pvwa.lab.local/PasswordVault'
        EndUserName = 'labuser1'
    }
    .\Test-PersonalPrivilgedAccountsConfig.ps1 @params

.EXAMPLE
    # Seed lab users first, then run:
    $params = @{
        ConfigPath   = '.\PersonalPrivilegedAccounts.json'
        EndUserName  = 'labuser1'
        SeedLabUsers = $true
        SeedPassword = (ConvertTo-SecureString 'CyberArkLab1!' -AsPlainText -Force)
    }
    .\Test-PersonalPrivilgedAccountsConfig.ps1 @params

.EXAMPLE
    # Cleanup using an existing report:
    .\Test-PersonalPrivilgedAccountsConfig.ps1 -Cleanup -ReportPath '.\PersonalPrivilegedAccounts_0424103000_report.json'

.NOTES
    Version: 1.0
    Safe names are generated as scs_<runId>_<N> (Zone 1) and ucs_<runId> (Zone 2).
    Safe name uniqueness does not depend on -EndUserName.
    Vault Admins is always added with Full before processing DefaultSafeMembers.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Cleanup',
    Justification = 'Switch activates ParameterSet; checked via $PSCmdlet.ParameterSetName')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'AuthenticationType',
    Justification = 'Read inside Get-TestAuthHeader via $script: scope')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'PVWACredentials',
    Justification = 'Read and written inside Get-TestAuthHeader via $script: scope')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'KeepArtifacts',
    Justification = 'Used inside finally block -- PSScriptAnalyzer false positive')]
[CmdletBinding(DefaultParameterSetName = 'Normal')]
param(
    #region Normal mode
    [Parameter(Mandatory = $true, ParameterSetName = 'Normal')]
    [string]$ConfigPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Normal')]
    [string]$EndUserName,

    [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
    [string]$ScriptPath,

    [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
    [switch]$SeedLabUsers,

    [Parameter(Mandatory = $false, ParameterSetName = 'Normal')]
    [SecureString]$SeedPassword,
    #endregion

    #region Cleanup mode
    [Parameter(Mandatory = $true, ParameterSetName = 'Cleanup')]
    [switch]$Cleanup,
    #endregion

    #region Shared connection
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

    #region Output
    [Parameter(Mandatory = $false)]
    [string]$ReportPath,

    [Parameter(Mandatory = $false)]
    [string]$LogPath,

    [Parameter(Mandatory = $false)]
    [switch]$KeepArtifacts,

    [Parameter(Mandatory = $false)]
    [switch]$SkipSafeConfigSets,

    [Parameter(Mandatory = $false)]
    [switch]$SkipUserConfigSets
    #endregion
)

# Validate Cleanup requires ReportPath
if ($PSCmdlet.ParameterSetName -eq 'Cleanup' -and [string]::IsNullOrEmpty($ReportPath)) {
    throw '-ReportPath is required when -Cleanup is specified.'
}

Set-StrictMode -Off
$LASTEXITCODE = 0
$Error.Clear()
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#region Globals

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$runId = Get-Date -Format 'MMddHHmmss'
$baseURL = $null
$authHeader = $null
$ownedSession = $false

$seededUserIds = @{}

$tempScsConfigPath = $null
$tempScsCsvPath = $null
$tempUcsConfigPath = $null
$tempUcsCsvPath = $null

$assertResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:testCounter = 0
$script:stepCounter = 0

if ([string]::IsNullOrEmpty($LogPath)) {
    $LogPath = Join-Path -Path $scriptDir -ChildPath (
        [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name) + '.log'
    )
}

$reportOutPath = $ReportPath   # may be null in normal mode; computed after runId is known

$ALL_PERMISSIONS = @(
    'useAccounts', 'retrieveAccounts', 'listAccounts', 'addAccounts',
    'updateAccountContent', 'updateAccountProperties',
    'initiateCPMAccountManagementOperations', 'specifyNextAccountContent',
    'renameAccounts', 'deleteAccounts', 'unlockAccounts',
    'manageSafe', 'manageSafeMembers', 'backupSafe',
    'viewAuditLog', 'viewSafeMembers', 'accessWithoutConfirmation',
    'createFolders', 'deleteFolders', 'moveAccountsAndFolders',
    'requestsAuthorizationLevel1'
)

#endregion

#region SSL bypass

if ($DisableCertificateValidation) {
    if (-not ('TACertValidation' -as [type])) {
        Add-Type -TypeDefinition @'
using System; using System.Net; using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class TACertValidation {
    public static bool ReturnTrue(object s, X509Certificate c,
        X509Chain ch, SslPolicyErrors e) { return true; }
    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(TACertValidation.ReturnTrue); }
}
'@
    }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback =
    [TACertValidation]::GetDelegate()
    Write-Warning 'Certificate validation is disabled.'
}

# Seed script-scoped auth state from parameters so callers can pass credentials directly
$script:PVWACredentials = $PVWACredentials
$script:logonToken = $logonToken
$script:AuthenticationType = $AuthenticationType

#endregion

#region Helper functions

function Write-TestLog {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
        Justification = 'Test script requires colored console output via Write-Host')]
    param(
        [Parameter(Position = 0)][AllowEmptyString()][AllowNull()][Object]$Object = '',
        [Parameter(Mandatory = $false)][System.ConsoleColor]$ForegroundColor
    )
    if ($PSBoundParameters.ContainsKey('ForegroundColor')) {
        Write-Host -Object $Object -ForegroundColor $ForegroundColor
    } else {
        Write-Host -Object $Object
    }
    if ([string]::IsNullOrEmpty($script:LogPath)) {
        return
    }
    $msg = if ($null -eq $Object) {
        ''
    } else {
        [string]$Object
    }
    if ([string]::IsNullOrEmpty($msg)) {
        '' | Out-File -Append -FilePath $script:LogPath -Encoding utf8
        return
    }
    $prefix = if ($PSBoundParameters.ContainsKey('ForegroundColor')) {
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
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')]`t$prefix`t$msg" |
    Out-File -Append -FilePath $script:LogPath -Encoding utf8
}

function Invoke-TestRest {
    param(
        [string]$Method,
        [string]$URI,
        [hashtable]$Header,
        [string]$Body = $null
    )
    try {
        $p = @{
            Uri         = $URI
            Method      = $Method
            Headers     = $Header
            ContentType = 'application/json'
            ErrorAction = 'Stop'
        }
        if (-not [string]::IsNullOrEmpty($Body)) {
            $p.Body = $Body
        }
        return Invoke-RestMethod @p
    } catch {
        return $null
    }
}

function Assert-Result {
    param(
        [string]$Id,
        [string]$Description,
        [ValidateSet('PASS', 'FAIL', 'WARN', 'SKIP')][string]$Status,
        [string]$Detail = ''
    )
    $color = switch ($Status) {
        'PASS' {
            'Green'
        }
        'FAIL' {
            'Red'
        }
        'WARN' {
            'Yellow'
        }
        'SKIP' {
            'Gray'
        }
    }
    $script:testCounter++
    $tId = 'T{0:D2}' -f $script:testCounter
    Write-TestLog ('  [{0}] {1} - {2}' -f $Status, $tId, $Description) -ForegroundColor $color
    if ($Status -ne 'PASS' -and -not [string]::IsNullOrEmpty($Detail)) {
        $detailColor = if ($Status -eq 'FAIL') {
            'DarkRed'
        } else {
            'DarkYellow'
        }
        Write-TestLog ("        Detail: $Detail") -ForegroundColor $detailColor
    }
    $script:assertResults.Add([PSCustomObject]@{
            Id          = $Id
            TNum        = $tId
            Description = $Description
            Status      = $Status
            Detail      = $Detail
        })
}

function Write-StepHeader {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
        Justification = 'Test script requires colored console output via Write-Host')]
    param([string]$Title)
    $script:stepCounter++
    Write-TestLog ''
    Write-TestLog ('─' * 72) -ForegroundColor Cyan
    Write-TestLog (" Step $($script:stepCounter): $Title") -ForegroundColor Cyan
    Write-TestLog ('─' * 72) -ForegroundColor Cyan
}

function Get-TestAuthHeader {
    if ($null -ne $script:logonToken) {
        if ($script:logonToken -is [hashtable]) {
            return $script:logonToken
        }
        return @{ Authorization = $script:logonToken }
    }
    if ($null -eq $script:PVWACredentials) {
        $script:PVWACredentials = $Host.UI.PromptForCredential(
            'CyberArk Config Test',
            "Enter credentials ($script:AuthenticationType)", '', '')
        if ($null -eq $script:PVWACredentials) {
            throw 'No credentials provided.'
        }
    }
    $BSTR = $null
    try {
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:PVWACredentials.Password)
        $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        $body = @{
            username          = $script:PVWACredentials.UserName
            password          = $plain
            concurrentSession = $true
        } | ConvertTo-Json -Compress
        $logonParams = @{
            Uri         = "$script:baseURL/api/auth/$script:AuthenticationType/Logon"
            Method      = 'POST'
            Body        = $body
            ContentType = 'application/json'
            ErrorAction = 'Stop'
        }
        $tok = Invoke-RestMethod @logonParams
        return @{ Authorization = $tok }
    } finally {
        if ($null -ne $BSTR) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        }
        Remove-Variable -Name plain -ErrorAction SilentlyContinue
    }
}

function Get-ResolvedPermission {
    <#
    .SYNOPSIS Returns a hashtable of permissions (only true entries) for a DefaultSafeMembers entry.
               Resolution priority: Permissions (inline) > RoleConfigSet (lookup) > Role (template).
    #>
    param(
        $Member,
        $RoleConfigSets
    )
    # Priority 1: inline Permissions object
    if ($null -ne $Member.Permissions) {
        $h = @{}
        $Member.Permissions.PSObject.Properties | Where-Object { [bool]$PSItem.Value } | ForEach-Object { $h[$PSItem.Name] = $true }
        return $h
    }
    # Priority 2: RoleConfigSet lookup
    if (-not [string]::IsNullOrEmpty($Member.RoleConfigSet)) {
        if ($null -ne $RoleConfigSets -and
            $RoleConfigSets.PSObject.Properties.Name -contains $Member.RoleConfigSet) {
            $h = @{}
            $RoleConfigSets.$($Member.RoleConfigSet).PSObject.Properties |
            Where-Object { [bool]$PSItem.Value } | ForEach-Object { $h[$PSItem.Name] = $true }
            return $h
        }
    }
    # Priority 3: built-in Role template
    $perms = @{}
    switch ($Member.Role) {
        'Full' {
            foreach ($p in $script:ALL_PERMISSIONS) {
                $perms[$p] = $true
            }
        }
        'EndUser' {
            $perms.useAccounts = $true; $perms.retrieveAccounts = $true
            $perms.listAccounts = $true; $perms.viewAuditLog = $true
            $perms.viewSafeMembers = $true
        }
        'ReadOnly' {
            $perms.listAccounts = $true; $perms.viewAuditLog = $true
            $perms.viewSafeMembers = $true
        }
        'AccountsManager' {
            $perms.useAccounts = $true; $perms.retrieveAccounts = $true
            $perms.listAccounts = $true; $perms.addAccounts = $true
            $perms.updateAccountContent = $true; $perms.updateAccountProperties = $true
            $perms.initiateCPMAccountManagementOperations = $true
            $perms.specifyNextAccountContent = $true
            $perms.renameAccounts = $true; $perms.deleteAccounts = $true
            $perms.unlockAccounts = $true; $perms.manageSafeMembers = $true
            $perms.viewAuditLog = $true; $perms.viewSafeMembers = $true
            $perms.accessWithoutConfirmation = $true
            $perms.requestsAuthorizationLevel1 = $true
        }
        'Approver' {
            $perms.useAccounts = $true; $perms.retrieveAccounts = $true
            $perms.listAccounts = $true; $perms.viewAuditLog = $true
            $perms.requestsAuthorizationLevel1 = $true
        }
        'ConnectOnly' {
            $perms.useAccounts = $true; $perms.retrieveAccounts = $true
            $perms.listAccounts = $true
        }
    }
    return $perms
}

function Get-EndUserPermission {
    <#
    .SYNOPSIS Resolves expected permissions for the CSV row owner (EndUser).
               Priority: SafeEndUserRoleConfigSet > SafeEndUserRole > 'EndUser' template.
    #>
    param($ScsEntry, $RoleConfigSets)
    $props = if ($null -ne $ScsEntry.Properties) {
        $ScsEntry.Properties
    } else {
        $ScsEntry
    }
    if ($null -ne $props -and -not [string]::IsNullOrEmpty($props.SafeEndUserRoleConfigSet)) {
        $rcsName = $props.SafeEndUserRoleConfigSet
        if ($null -ne $RoleConfigSets -and
            $RoleConfigSets.PSObject.Properties.Name -contains $rcsName) {
            $h = @{}
            $RoleConfigSets.$rcsName.PSObject.Properties |
            Where-Object { [bool]$PSItem.Value } | ForEach-Object { $h[$PSItem.Name] = $true }
            return $h
        }
    }
    $roleName = 'EndUser'
    if ($null -ne $props -and -not [string]::IsNullOrEmpty($props.SafeEndUserRole)) {
        $roleName = $props.SafeEndUserRole
    }
    $fakeMember = [PSCustomObject]@{ Permissions = $null; RoleConfigSet = $null; Role = $roleName }
    return Get-ResolvedPermission -Member $fakeMember -RoleConfigSets $null
}

function Get-CleanupSafeName {
    param([string]$SafeName, [hashtable]$Header)
    $del1 = "DEL_$SafeName"
    $del2 = "DEL2_$SafeName"
    $uri = "$script:baseURL/api/Safes/$([URI]::EscapeDataString($del1))"
    $exists = Invoke-TestRest -Method GET -URI $uri -Header $Header
    if ($null -eq $exists) {
        return $del1
    }
    return $del2
}

# Fetches the required/optional property schema for a platform via GET /API/Platforms/?PlatformName=<id>
# Returns an object with .required and .optional arrays, or $null if the platform is not found.
function Get-PlatformSchema {
    param([string]$PlatformId, [hashtable]$Header)
    $uri = "$script:baseURL/API/Platforms/?PlatformName=$([URI]::EscapeDataString($PlatformId))"
    $resp = Invoke-TestRest -Method GET -URI $uri -Header $Header
    if ($null -ne $resp -and $null -ne $resp.Platforms -and $resp.Platforms.Count -gt 0) {
        $match = $resp.Platforms | Where-Object { $PSItem.general.id -eq $PlatformId } | Select-Object -First 1
        if ($null -ne $match) {
            return $match.properties
        }
    }
    return $null
}

# Maps a platform property name to the UCS Properties key that already covers it.
# $null means the property is always present (handled structurally by the main script).
$script:PlatformPropToUcsKey = @{
    'Address'  = 'accountAddress'
    'Username' = $null            # always provided via accountUser/accountUserPattern
}

# Maps a platform property name to the top-level account API field name.
# Properties not in this map live in acct.platformAccountProperties.<name>.
$script:PlatformPropToAcctField = @{
    'Address'  = 'address'
    'Username' = 'userName'
}

# Known-good test values for common platform optional properties.
# The vault validates types for some fields (e.g. Port must be numeric, UseSSL must be Yes/No).
# Properties not listed here fall back to the generic "test-<name>" string value.
$script:KnownPlatformTestValues = @{
    'Port'                   = '636'
    'UseSSL'                 = 'Yes'
    'StartTLS'               = 'No'
    'AuthenticationType'     = 'Basic'
    'UnlockUserOnReconcile'  = 'No'
    'LogonDomain'            = 'testdomain'
    'UserDN'                 = 'CN=TestUsers,DC=test,DC=com'
    'Host'                   = 'test-host.example.com'
    'DirectoryType'          = 'WindowsActiveDirectory'
    'PluginName'             = 'test'
}

function Invoke-SafeCleanup {
    param([string]$SafeName, [hashtable]$Header)
    $safeUri = "$script:baseURL/api/Safes/$([URI]::EscapeDataString($SafeName))"
    # Delete all accounts in the safe first
    $acctUri = "$script:baseURL/api/Accounts?filter=safeName%20eq%20$([URI]::EscapeDataString($SafeName))&limit=100"
    $acctPage = Invoke-TestRest -Method GET -URI $acctUri -Header $Header
    if ($null -ne $acctPage -and $acctPage.count -gt 0) {
        foreach ($acct in $acctPage.value) {
            $null = Invoke-TestRest -Method DELETE -URI "$script:baseURL/api/Accounts/$($acct.id)" -Header $Header
        }
    }
    # Try direct DELETE first
    try {
        $delParams = @{
            Uri         = $safeUri
            Method      = 'DELETE'
            Headers     = $Header
            ContentType = 'application/json'
            ErrorAction = 'Stop'
        }
        $null = Invoke-RestMethod @delParams
        Write-TestLog "[CLEANUP] Deleted safe '$SafeName'" -ForegroundColor Gray
        return 'Deleted'
    } catch {
        Write-Verbose "Direct DELETE for '$SafeName' threw: $($PSItem.Exception.Message)"
    }
    # Verify it is actually gone (DELETE returns empty on success)
    $still = Invoke-TestRest -Method GET -URI $safeUri -Header $Header
    if ($null -eq $still) {
        Write-TestLog "[CLEANUP] Deleted safe '$SafeName'" -ForegroundColor Gray
        return 'Deleted'
    }
    # DELETE failed -- rename instead
    $delName = Get-CleanupSafeName -SafeName $SafeName -Header $Header
    $safeInfo = Invoke-TestRest -Method GET -URI $safeUri -Header $Header
    if ($null -ne $safeInfo) {
        $putBody = @{
            safeName              = $delName
            description           = if ($safeInfo.description) {
                $safeInfo.description
            } else {
                ''
            }
            olacEnabled           = [bool]$safeInfo.olacEnabled
            managingCPM           = ''
            numberOfDaysRetention = [int]$safeInfo.numberOfDaysRetention
        } | ConvertTo-Json -Compress
        $renamed = Invoke-TestRest -Method PUT -URI $safeUri -Header $Header -Body $putBody
        if ($null -ne $renamed) {
            Write-TestLog "[CLEANUP] Renamed '$SafeName' -> '$delName' (DELETE failed -- safe may have accounts)" -ForegroundColor Yellow
            return "Renamed:$delName"
        }
    }
    Write-TestLog "[CLEANUP] Could not clean up safe '$SafeName'" -ForegroundColor Red
    return 'Failed'
}

#endregion

#region Cleanup mode

if ($PSCmdlet.ParameterSetName -eq 'Cleanup') {
    Write-TestLog ''
    Write-TestLog ('=' * 72) -ForegroundColor Cyan
    Write-TestLog '  CLEANUP MODE' -ForegroundColor Cyan
    Write-TestLog ('=' * 72) -ForegroundColor Cyan

    if (-not (Test-Path -Path $ReportPath -PathType Leaf)) {
        Write-TestLog "ERROR: Report not found: $ReportPath" -ForegroundColor Red
        exit 1
    }
    $report = Get-Content -Path $ReportPath -Raw | ConvertFrom-Json

    if ([string]::IsNullOrEmpty($PVWAURL) -and -not [string]::IsNullOrEmpty($report.PVWAURL)) {
        $PVWAURL = $report.PVWAURL
    }
    if ([string]::IsNullOrEmpty($PVWAURL)) {
        Write-TestLog 'ERROR: -PVWAURL is required for cleanup when not stored in report.' -ForegroundColor Red
        exit 1
    }
    $baseURL = $PVWAURL.TrimEnd('/')

    try {
        $authHeader = Get-TestAuthHeader
        $ownedSession = ($null -eq $logonToken)

        # Zone 1 safes
        foreach ($tc in $report.Zones.SCS) {
            if ($tc.SafeCreated -and $tc.CleanupStatus -ne 'Done') {
                $status = Invoke-SafeCleanup -SafeName $tc.SafeName -Header $authHeader
                $tc.CleanupStatus = $status
            }
        }

        # Zone 2 safe
        if ($null -ne $report.Zones.UCS -and $report.Zones.UCS.SharedSafeCreated) {
            if ($report.Zones.UCS.CleanupStatus -ne 'Done') {
                $status = Invoke-SafeCleanup -SafeName $report.Zones.UCS.SharedSafeName -Header $authHeader
                $report.Zones.UCS.CleanupStatus = $status
            }
        }

        # Seeded users
        if ($null -ne $report.SeededUserIds) {
            foreach ($entry in $report.SeededUserIds.PSObject.Properties) {
                $uid = $entry.Value
                if (-not [string]::IsNullOrEmpty($uid)) {
                    $delUri = "$baseURL/api/Users/$uid"
                    $null = Invoke-TestRest -Method DELETE -URI $delUri -Header $authHeader
                    Write-TestLog "[CLEANUP] Deleted seeded user '$($entry.Name)' (id=$uid)" -ForegroundColor Gray
                }
            }
        }

        # Temp files
        foreach ($tf in @($report.TempScsCsvPath, $report.TempScsConfigPath,
                $report.TempUcsCsvPath, $report.TempUcsConfigPath)) {
            if (-not [string]::IsNullOrEmpty($tf) -and (Test-Path -Path $tf)) {
                Remove-Item -Path $tf -Force
            }
        }

        $report | ConvertTo-Json -Depth 20 |
        Out-File -FilePath $ReportPath -Encoding utf8 -Force
        Write-TestLog "[CLEANUP] Report updated: $ReportPath" -ForegroundColor Gray
    } catch {
        Write-TestLog "ERROR during cleanup: $($PSItem.Exception.Message)" -ForegroundColor Red
    } finally {
        if ($ownedSession -and $null -ne $authHeader) {
            $logoffUri = "$baseURL/api/Auth/Logoff"
            $null = Invoke-TestRest -Method POST -URI $logoffUri -Header $authHeader
        }
    }
    Write-TestLog ''
    Write-TestLog 'Cleanup complete.' -ForegroundColor Cyan
    exit 0
}

#endregion

#region Resolve prerequisites (normal mode)

# PVWAURL from PSDefaultParameterValues
if ([string]::IsNullOrEmpty($PVWAURL)) {
    $urlKey = $global:PSDefaultParameterValues.Keys |
    Where-Object { $PSItem -like '*:PVWAURL' -or $PSItem -like '*:PVWAUrl' } |
    Select-Object -First 1
    if ($urlKey) {
        $PVWAURL = $global:PSDefaultParameterValues[$urlKey]
    }
}
if ([string]::IsNullOrEmpty($PVWAURL)) {
    Write-TestLog 'ERROR: -PVWAURL is required.' -ForegroundColor Red
    exit 1
}
$baseURL = $PVWAURL.TrimEnd('/')
$VaultAdminsName = if ($baseURL -match '\.privilegecloud\.cyberark') {
    'Privilege Cloud Administrators'
} else {
    'Vault Admins'
}

# logonToken from PSDefaultParameterValues
if ($null -eq $logonToken) {
    $tokKey = $global:PSDefaultParameterValues.Keys |
    Where-Object { $PSItem -like '*:logonToken' } | Select-Object -First 1
    if ($tokKey) {
        $logonToken = $global:PSDefaultParameterValues[$tokKey]
    }
}

# ScriptPath
if ([string]::IsNullOrEmpty($ScriptPath)) {
    $ScriptPath = Join-Path -Path $scriptDir -ChildPath 'Create-PersonalPrivilgedAccounts.ps1'
}
if (-not (Test-Path -Path $ScriptPath -PathType Leaf)) {
    Write-TestLog "ERROR: Main script not found: $ScriptPath" -ForegroundColor Red
    exit 1
}

# SeedLabUsers validation
if ($SeedLabUsers -and $null -eq $SeedPassword) {
    Write-TestLog 'ERROR: -SeedPassword is required when -SeedLabUsers is set.' -ForegroundColor Red
    exit 1
}

# Config JSON
if (-not (Test-Path -Path $ConfigPath -PathType Leaf)) {
    Write-TestLog "ERROR: Config file not found: $ConfigPath" -ForegroundColor Red
    exit 1
}
$jsonRaw = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json

if ($null -eq $jsonRaw.SafeConfigSet) {
    Write-TestLog 'ERROR: Config has no SafeConfigSet section.' -ForegroundColor Red
    exit 1
}

# Report output path
if ([string]::IsNullOrEmpty($reportOutPath)) {
    $configBase = [System.IO.Path]::GetFileNameWithoutExtension($ConfigPath)
    $reportOutPath = Join-Path -Path $scriptDir -ChildPath "${configBase}_${runId}_report.json"
}

#endregion

#region Enumerate config keys

$scsKeys = $jsonRaw.SafeConfigSet.PSObject.Properties.Name
$ucsKeys = if ($null -ne $jsonRaw.UserConfigSet) {
    $jsonRaw.UserConfigSet.PSObject.Properties.Name
} else {
    @()
}

#endregion

#region Banner

Write-TestLog ''
Write-TestLog ('=' * 72) -ForegroundColor Cyan
Write-TestLog '  Config Test Runner — Create-PersonalPrivilgedAccounts.ps1' -ForegroundColor Cyan
Write-TestLog ('=' * 72) -ForegroundColor Cyan
Write-TestLog ("  Run ID      : $runId")
$scsIdx = 0
foreach ($k in $scsKeys) {
    $scsIdx++
    Write-TestLog ("  SCS $scsIdx       : $k")
}
$ucsIdx = 0
foreach ($k in $ucsKeys) {
    $ucsIdx++
    Write-TestLog ("  UCS $ucsIdx       : $k")
}
Write-TestLog ("  PVWA URL    : $PVWAURL")
Write-TestLog ("  Script      : $ScriptPath")
Write-TestLog ("  Config      : $ConfigPath")
Write-TestLog ("  End User    : $EndUserName")
Write-TestLog ("  Log file    : $LogPath")
Write-TestLog ('=' * 72) -ForegroundColor Cyan
Write-TestLog ''

#endregion

#region Report scaffold

$reportObj = [ordered]@{
    RunId             = $runId
    RunDate           = (Get-Date -Format 'o')
    ConfigPath        = $ConfigPath
    PVWAURL           = $PVWAURL
    TempScsCsvPath    = $null
    TempScsConfigPath = $null
    TempUcsCsvPath    = $null
    TempUcsConfigPath = $null
    SeededUserIds     = [ordered]@{}
    Zones             = [ordered]@{
        SCS = [System.Collections.Generic.List[object]]::new()
        UCS = $null
    }
}

#endregion

try {
    #region Authentication
    Write-TestLog '[AUTH] Authenticating...' -ForegroundColor Gray
    $authHeader = Get-TestAuthHeader
    $ownedSession = ($null -eq $logonToken)
    Write-TestLog '[AUTH] Done.' -ForegroundColor Gray
    Write-TestLog ''
    #endregion

    #region Verify EndUserName
    $endUserExists = $false
    $euUri = "$baseURL/api/Users?search=$([URI]::EscapeDataString($EndUserName))&filter=componentUser eq false"
    $euSearch = Invoke-TestRest -Method GET -URI $euUri -Header $authHeader
    if ($null -ne $euSearch -and $euSearch.count -gt 0) {
        $exactMatch = $euSearch.Users |
        Where-Object { $PSItem.username -eq $EndUserName } |
        Select-Object -First 1
        if ($null -ne $exactMatch) {
            $endUserExists = $true
        }
    }
    if ($endUserExists) {
        Write-TestLog "[PREFLIGHT] EndUserName '$EndUserName' found in vault." -ForegroundColor Gray
    } else {
        Write-TestLog "[PREFLIGHT] WARNING: EndUserName '$EndUserName' not found -- enduser-permission assertions will be WARNING." -ForegroundColor Yellow
    }
    Write-TestLog ''
    #endregion

    #region Seed lab users
    if ($SeedLabUsers) {
        Write-TestLog '[SEED] Seeding DefaultSafeMembers vault users...' -ForegroundColor Gray
        $membersToSeed = [System.Collections.Generic.List[string]]::new()
        foreach ($scsKey in $scsKeys) {
            $scs = $jsonRaw.SafeConfigSet.$scsKey
            $members = if ($null -ne $scs.Properties -and
                $null -ne $scs.Properties.DefaultSafeMembers) {
                $scs.Properties.DefaultSafeMembers
            } elseif ($null -ne $scs.DefaultSafeMembers) {
                $scs.DefaultSafeMembers
            } else {
                @()
            }
            foreach ($m in $members) {
                if (-not [string]::IsNullOrEmpty($m.Name) -and
                    $m.Name -notin $membersToSeed) {
                    $membersToSeed.Add($m.Name)
                }
            }
        }
        foreach ($uname in $membersToSeed) {
            $chkUri = "$baseURL/api/Users?search=$([URI]::EscapeDataString($uname))"
            $chk = Invoke-TestRest -Method GET -URI $chkUri -Header $authHeader
            $alreadyExists = $null -ne $chk -and $chk.count -gt 0 -and
            ($chk.Users | Where-Object { $PSItem.username -eq $uname })
            if ($alreadyExists) {
                Write-TestLog "[SEED] '$uname' already exists -- skipping." -ForegroundColor Gray
                continue
            }
            $seedBSTR = $null
            $seedPlain = $null
            try {
                $seedBSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SeedPassword)
                $seedPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($seedBSTR)
            } finally {
                if ($null -ne $seedBSTR) {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($seedBSTR)
                }
            }
            $createBody = @{
                username              = $uname
                initialPassword       = $seedPlain
                userType              = 'EPVUser'
                changePassOnNextLogon = $false
            } | ConvertTo-Json -Compress
            $seedPlain = $null
            $usersUri = "$baseURL/api/Users"
            $created = Invoke-TestRest -Method POST -URI $usersUri -Header $authHeader -Body $createBody
            if ($null -ne $created) {
                $seededUserIds[$uname] = [string]$created.id
                $reportObj.SeededUserIds[$uname] = [string]$created.id
                Write-TestLog "[SEED] Created vault user '$uname' (id=$($created.id))" -ForegroundColor Gray
            } else {
                Write-TestLog "[SEED] Could not create vault user '$uname'" -ForegroundColor Yellow
            }
        }
        Write-TestLog ''
    }
    #endregion

    # =========================================================================
    # Safe Config Set validation
    # =========================================================================
    if (-not $SkipSafeConfigSets) {
        $tempScsConfigPath = Join-Path -Path $scriptDir -ChildPath "tpac_scs_${runId}_config.json"
        $reportObj.TempScsConfigPath = $tempScsConfigPath

        $derivedScs = [ordered]@{}
        foreach ($k in $scsKeys) {
            $derivedScs[$k] = $jsonRaw.SafeConfigSet.$k
        }
        $derivedConfig = [ordered]@{
            SafeConfigSet = $derivedScs
            UserConfigSet = [ordered]@{
                default = [ordered]@{
                    Options    = [ordered]@{ accountUserPattern = $null; allowDuplicateAccounts = $false }
                    Properties = [ordered]@{
                        # Placeholder values so New-AccountObject can resolve the account object
                        # and reach safe-creation logic. Zone 1 only asserts safe+members.
                        accountAddress  = 'z1.test.local'
                        accountPlatform = 'WinDomain'
                    }
                }
            }
        }
        if ($null -ne $jsonRaw.RoleConfigSet) {
            $derivedConfig.RoleConfigSet = $jsonRaw.RoleConfigSet
        }
        $derivedConfig | ConvertTo-Json -Depth 20 |
        Out-File -FilePath $tempScsConfigPath -Encoding utf8 -Force

        # Build SCS CSV and test-case list
        $scsCsvLines = [System.Collections.Generic.List[string]]::new()
        $scsCsvLines.Add('userName,safeName,SafeConfigSet,UserConfigSet,createSafeOnly')
        $scsTestCases = [System.Collections.Generic.List[PSCustomObject]]::new()

        $scsIdx = 0
        foreach ($scsKey in $scsKeys) {
            $scsIdx++
            $generatedSafeName = "scs_${runId}_${scsIdx}"

            $chkSafeUri = "$baseURL/api/Safes/$([URI]::EscapeDataString($generatedSafeName))"
            $existing = Invoke-TestRest -Method GET -URI $chkSafeUri -Header $authHeader
            if ($null -ne $existing) {
                Write-TestLog "[SCS] Safe '$generatedSafeName' already exists -- skipping Safe Config Set '$scsKey'" -ForegroundColor Yellow
                $tc = [PSCustomObject]@{
                    Idx              = $scsIdx
                    SCSName          = $scsKey
                    SafeName         = $generatedSafeName
                    SafeCreated      = $false
                    Skipped          = $true
                    AssertionResults = @()
                    CleanupStatus    = 'Skipped'
                }
                $scsTestCases.Add($tc)
                $reportObj.Zones.SCS.Add($tc)
                continue
            }

            # EndUserName used as CSV userName so New-AccountObject can resolve safe naming
            # and ownership. createSafeOnly=true ensures no account is onboarded into the
            # SCS safe -- safes stay empty and can be deleted cleanly during cleanup.
            $scsCsvLines.Add("$EndUserName,$generatedSafeName,$scsKey,,true")
            $tc = [PSCustomObject]@{
                Idx              = $scsIdx
                SCSName          = $scsKey
                SafeName         = $generatedSafeName
                SafeCreated      = $false
                Skipped          = $false
                AssertionResults = [System.Collections.Generic.List[PSCustomObject]]::new()
                CleanupStatus    = $null
            }
            $scsTestCases.Add($tc)
            $reportObj.Zones.SCS.Add($tc)
        }

        $tempScsCsvPath = Join-Path -Path $scriptDir -ChildPath "tpac_scs_${runId}.csv"
        $reportObj.TempScsCsvPath = $tempScsCsvPath
        $scsCsvLines | Out-File -FilePath $tempScsCsvPath -Encoding utf8 -Force

        $activeScsCount = ($scsTestCases | Where-Object { -not $PSItem.Skipped } | Measure-Object).Count
        Write-StepHeader 'Safe Config Sets — run script'
        Write-TestLog "  [SCS] Running main script for $activeScsCount Safe Config Set test safe(s)..." -ForegroundColor Gray

        $mainScsParams = @{
            PVWAURL    = $PVWAURL
            logonToken = $authHeader
            CSVPath    = $tempScsCsvPath
            ConfigPath = $tempScsConfigPath
        }
        if ($DisableCertificateValidation) {
            $mainScsParams.DisableCertificateValidation = $true
        }

        & $ScriptPath @mainScsParams 4>$null 5>$null
        $scsExitCode = $LASTEXITCODE

        $z1Status = if ($null -eq $scsExitCode -or $scsExitCode -eq 0) {
            'PASS'
        } else {
            'FAIL'
        }
        $z1Detail = if ($scsExitCode -ne 0) {
            "Exit code: $scsExitCode"
        } else {
            ''
        }
        Assert-Result -Id 'SCS_run' -Description 'Safe Config Set validation script exited without fatal error' -Status $z1Status -Detail $z1Detail
        Write-TestLog ''

        # Per-SCS assertions
        foreach ($tc in $scsTestCases) {
            if ($tc.Skipped) {
                continue
            }

            $scsEntry = $jsonRaw.SafeConfigSet.$($tc.SCSName)
            $prefix = "SCS_$($tc.Idx)_$($tc.SCSName)"

            Write-StepHeader "Verify Safe Config Set '$($tc.SCSName)' (safe: $($tc.SafeName))"

            # Always add VaultAdminsName Full before asserting (safety net)
            $vaPerms = @{}
            foreach ($p in $ALL_PERMISSIONS) {
                $vaPerms[$p] = $true
            }
            $vaAddBodyHt = @{ memberName = $VaultAdminsName; searchIn = 'Vault'; permissions = $vaPerms }
            if ($baseURL -match '\.privilegecloud\.cyberark') {
                $vaAddBodyHt.memberType = 'Role'
            }
            $vaAddBody = $vaAddBodyHt | ConvertTo-Json -Depth 5 -Compress
            $membersUri = "$baseURL/api/Safes/$([URI]::EscapeDataString($tc.SafeName))/Members"
            $null = Invoke-TestRest -Method POST -URI $membersUri -Header $authHeader -Body $vaAddBody

            # safe_exists
            $safeUri = "$baseURL/api/Safes/$([URI]::EscapeDataString($tc.SafeName))"
            $safeObj = Invoke-TestRest -Method GET -URI $safeUri -Header $authHeader

            $tc.SafeCreated = ($null -ne $safeObj)
            $seStatus = if ($tc.SafeCreated) {
                'PASS'
            } else {
                'FAIL'
            }
            Assert-Result -Id "${prefix}_safe_exists" -Description "Safe '$($tc.SafeName)' created" -Status $seStatus

            if (-not $tc.SafeCreated) {
                Write-TestLog '    (skipping further assertions -- safe not found)' -ForegroundColor DarkYellow
                Write-TestLog ''
                continue
            }

            # safe_empty -- createSafeOnly should leave no accounts in the SCS safe
            $acctCheckUri = "$baseURL/api/Accounts?filter=safeName%20eq%20$([URI]::EscapeDataString($tc.SafeName))&limit=1"
            $acctCheck = Invoke-TestRest -Method GET -URI $acctCheckUri -Header $authHeader
            $acctCount = if ($null -ne $acctCheck) { [int]$acctCheck.count } else { 0 }
            $emptyStatus = if ($acctCount -eq 0) { 'PASS' } else { 'FAIL' }
            $emptyDetail = if ($acctCount -gt 0) { "expected 0 accounts, found $acctCount" } else { '' }
            Assert-Result -Id "${prefix}_safe_empty" -Description "Safe '$($tc.SafeName)' contains no accounts (createSafeOnly)" -Status $emptyStatus -Detail $emptyDetail
            $props = if ($null -ne $scsEntry.Properties) {
                $scsEntry.Properties
            } else {
                $scsEntry
            }
            if ($null -ne $props.NumberOfVersionsRetention) {
                $expected = [int]$props.NumberOfVersionsRetention
                $retStatus = if ([int]$safeObj.numberOfVersionsRetention -eq $expected) {
                    'PASS'
                } else {
                    'FAIL'
                }
                $retDetail = "expected $expected versions, got $($safeObj.numberOfVersionsRetention)"
                Assert-Result -Id "${prefix}_retention" -Description "'$($tc.SafeName)' has numberOfVersionsRetention = $expected (from SCS '$($tc.SCSName)')" -Status $retStatus -Detail $retDetail
            } elseif ($null -ne $props.NumberOfDaysRetention) {
                $expected = [int]$props.NumberOfDaysRetention
                $retStatus = if ([int]$safeObj.numberOfDaysRetention -eq $expected) {
                    'PASS'
                } else {
                    'FAIL'
                }
                $retDetail = "expected $expected days, got $($safeObj.numberOfDaysRetention)"
                Assert-Result -Id "${prefix}_retention" -Description "'$($tc.SafeName)' has numberOfDaysRetention = $expected (from SCS '$($tc.SCSName)')" -Status $retStatus -Detail $retDetail
            }

            # cpm
            if ($null -ne $props.CPMName -and -not [string]::IsNullOrEmpty($props.CPMName)) {
                $cpmStatus = if ($safeObj.managingCPM -eq $props.CPMName) {
                    'PASS'
                } else {
                    'FAIL'
                }
                $cpmDetail = "expected '$($props.CPMName)', got '$($safeObj.managingCPM)'"
                Assert-Result -Id "${prefix}_cpm" -Description "'$($tc.SafeName)' has managingCPM = '$($props.CPMName)' (from SCS '$($tc.SCSName)')" -Status $cpmStatus -Detail $cpmDetail
            }

            # Fetch all members once (including predefined); use client-side lookup for all member assertions
            $allMembersUri = "$baseURL/api/Safes/$([URI]::EscapeDataString($tc.SafeName))/Members?filter=$([URI]::EscapeDataString('includePredefinedUsers eq true'))&limit=1000"
            $allMembersResp = Invoke-TestRest -Method GET -URI $allMembersUri -Header $authHeader
            $allMembers = if ($null -ne $allMembersResp -and $null -ne $allMembersResp.value) {
                $allMembersResp.value
            } else {
                @()
            }

            # vault_admins_full
            $vaCheck = $allMembers | Where-Object { $PSItem.memberName -eq $VaultAdminsName } | Select-Object -First 1
            $vaFull = $null -ne $vaCheck -and
            ($ALL_PERMISSIONS | Where-Object { $vaCheck.permissions.$PSItem -ne $true }).Count -eq 0
            $vaStatus = if ($vaFull) {
                'PASS'
            } else {
                'FAIL'
            }
            $vaDetail = if (-not $vaFull -and $null -ne $vaCheck) {
                'One or more Full permissions missing'
            } elseif ($null -eq $vaCheck) {
                "'$VaultAdminsName' was not found as a safe member"
            } else {
                ''
            }
            Assert-Result -Id "${prefix}_vault_admins_full" -Description "'$VaultAdminsName' has Full permissions on '$($tc.SafeName)'" -Status $vaStatus -Detail $vaDetail

            # DefaultSafeMembers assertions
            $memberList = if ($null -ne $props.DefaultSafeMembers) {
                $props.DefaultSafeMembers
            } else {
                @()
            }
            $memberIdx = 0
            foreach ($mem in $memberList) {
                $memberIdx++
                $memName = $mem.Name
                $memObj = $allMembers | Where-Object { $PSItem.memberName -eq $memName } | Select-Object -First 1

                if ($null -eq $memObj) {
                    Assert-Result -Id "${prefix}_member_${memberIdx}_present" -Description "'$memName' was added as a member of '$($tc.SafeName)'" -Status 'FAIL' -Detail 'Member not found'
                    continue
                }

                Assert-Result -Id "${prefix}_member_${memberIdx}_present" -Description "'$memName' was added as a member of '$($tc.SafeName)'" -Status 'PASS'

                $expectedPerms = Get-ResolvedPermission -Member $mem -RoleConfigSets $jsonRaw.RoleConfigSet
                $failedPerms = @()
                foreach ($p in $ALL_PERMISSIONS) {
                    $exp = if ($expectedPerms.ContainsKey($p)) {
                        [bool]$expectedPerms[$p]
                    } else {
                        $false
                    }
                    $act = [bool]$memObj.permissions.$p
                    if ($exp -ne $act) {
                        $failedPerms += "$p (exp=$exp, act=$act)"
                    }
                }
                $mpStatus = if ($failedPerms.Count -eq 0) {
                    'PASS'
                } else {
                    'FAIL'
                }
                $mpDetail = $failedPerms -join '; '
                Assert-Result -Id "${prefix}_member_${memberIdx}_perms" -Description "'$memName' has the expected permissions on '$($tc.SafeName)' (role: $($mem.Role))" -Status $mpStatus -Detail $mpDetail
            }

            # enduser_perms -- WARNING if user missing, FAIL on perm mismatch
            $euMember = $allMembers | Where-Object { $PSItem.memberName -eq $EndUserName } | Select-Object -First 1

            if ($null -eq $euMember) {
                Assert-Result -Id "${prefix}_enduser_perms" -Description "'$EndUserName' has the expected end-user permissions on '$($tc.SafeName)'" -Status 'WARN' -Detail "'$EndUserName' not found as a safe member"
            } else {
                $expectedEu = Get-EndUserPermission -ScsEntry $scsEntry -RoleConfigSets $jsonRaw.RoleConfigSet
                $failedEuPerms = @()
                foreach ($p in $ALL_PERMISSIONS) {
                    $exp = if ($expectedEu.ContainsKey($p)) {
                        [bool]$expectedEu[$p]
                    } else {
                        $false
                    }
                    $act = [bool]$euMember.permissions.$p
                    if ($exp -ne $act) {
                        $failedEuPerms += "$p (exp=$exp, act=$act)"
                    }
                }
                $euStatus = if ($failedEuPerms.Count -eq 0) {
                    'PASS'
                } else {
                    'FAIL'
                }
                $euDetail = $failedEuPerms -join '; '
                Assert-Result -Id "${prefix}_enduser_perms" -Description "'$EndUserName' has the expected end-user permissions on '$($tc.SafeName)'" -Status $euStatus -Detail $euDetail
            }

            Write-TestLog ''
        }
    } else {
        Write-TestLog '[SCS] Safe Config Set validation skipped (-SkipSafeConfigSets specified).' -ForegroundColor Gray
        Write-TestLog ''
    }

    # =========================================================================
    # User Config Set validation
    # =========================================================================
    if ($ucsKeys.Count -gt 0 -and -not $SkipUserConfigSets) {

        $ucsSafeName = "ucs_$runId"

        $ucsZone = [ordered]@{
            SharedSafeName    = $ucsSafeName
            SharedSafeCreated = $false
            CleanupStatus     = $null
            Cases             = [System.Collections.Generic.List[object]]::new()
        }
        $reportObj.Zones.UCS = $ucsZone

        # Pre-flight collision check
        Write-StepHeader 'User Config Sets — create test safe and run script'
        $ucsSafeUri = "$baseURL/api/Safes/$([URI]::EscapeDataString($ucsSafeName))"
        $ucsExisting = Invoke-TestRest -Method GET -URI $ucsSafeUri -Header $authHeader
        if ($null -ne $ucsExisting) {
            Write-TestLog "[UCS] Shared safe '$ucsSafeName' already exists -- User Config Set validation skipped." -ForegroundColor Yellow
            Assert-Result -Id 'UCS_shared_safe' -Description "User Config Set shared safe '$ucsSafeName' created" -Status 'SKIP' -Detail 'Safe already exists'
        } else {
            # Create shared safe directly
            $ucsCPM = if ($null -ne $jsonRaw.SafeConfigSet -and
                $null -ne $jsonRaw.SafeConfigSet.default -and
                $null -ne $jsonRaw.SafeConfigSet.default.Properties -and
                -not [string]::IsNullOrEmpty($jsonRaw.SafeConfigSet.default.Properties.CPMName)) {
                $jsonRaw.SafeConfigSet.default.Properties.CPMName
            } else {
                'PasswordManager'
            }
            $ucsCreateBody = @{
                safeName              = $ucsSafeName
                description           = "Config test User Config Set (run $runId)"
                olacEnabled           = $false
                managingCPM           = $ucsCPM
                numberOfDaysRetention = 1
            } | ConvertTo-Json -Compress
            $safesUri = "$baseURL/api/Safes"
            $ucsCreated = Invoke-TestRest -Method POST -URI $safesUri -Header $authHeader -Body $ucsCreateBody

            if ($null -eq $ucsCreated) {
                Write-TestLog "[UCS] Failed to create shared safe '$ucsSafeName' -- User Config Set validation skipped." -ForegroundColor Red
                Assert-Result -Id 'UCS_shared_safe' -Description "User Config Set shared safe '$ucsSafeName' created" -Status 'FAIL' -Detail 'POST /api/Safes returned null'
            } else {
                $ucsZone.SharedSafeCreated = $true

                # Add VaultAdminsName Full to Zone 2 safe
                $va2Perms = @{}
                foreach ($p in $ALL_PERMISSIONS) {
                    $va2Perms[$p] = $true
                }
                $va2BodyHt = @{ memberName = $VaultAdminsName; searchIn = 'Vault'; permissions = $va2Perms }
                if ($baseURL -match '\.privilegecloud\.cyberark') {
                    $va2BodyHt.memberType = 'Role'
                }
                $va2Body = $va2BodyHt | ConvertTo-Json -Depth 5 -Compress
                $ucs2MembUri = "$baseURL/api/Safes/$([URI]::EscapeDataString($ucsSafeName))/Members"
                $null = Invoke-TestRest -Method POST -URI $ucs2MembUri -Header $authHeader -Body $va2Body

                Assert-Result -Id 'UCS_shared_safe' -Description "User Config Set shared safe '$ucsSafeName' created" -Status 'PASS'

                # Synthetic config: useExisting SCS, 1-day retention, real UCS entries
                $ucsDerivedConfig = [ordered]@{
                    SafeConfigSet = [ordered]@{
                        default = [ordered]@{
                            Options    = [ordered]@{ useExisting = $true }
                            Properties = [ordered]@{ NumberOfDaysRetention = 1 }
                        }
                    }
                    UserConfigSet = [ordered]@{}
                }
                if ($null -ne $jsonRaw.RoleConfigSet) {
                    $ucsDerivedConfig.RoleConfigSet = $jsonRaw.RoleConfigSet
                }
                foreach ($k in $ucsKeys) {
                    $ucsDerivedConfig.UserConfigSet[$k] = $jsonRaw.UserConfigSet.$k
                }

                $tempUcsConfigPath = Join-Path -Path $scriptDir -ChildPath "tpac_ucs_${runId}_config.json"
                $reportObj.TempUcsConfigPath = $tempUcsConfigPath
                $ucsDerivedConfig | ConvertTo-Json -Depth 20 |
                Out-File -FilePath $tempUcsConfigPath -Encoding utf8 -Force

                # ------------------------------------------------------------------
                # Fetch live platform schemas for all in-scope platforms.
                # Used to ensure required fields are covered and to inject up to
                # 2 optional fields as extra CSV columns.
                # ------------------------------------------------------------------
                $platformSchemas = @{}  # platformId -> properties object { required; optional }
                foreach ($ucsKey in $ucsKeys) {
                    $uEntry = $jsonRaw.UserConfigSet.$ucsKey
                    $uProps = if ($null -ne $uEntry.Properties) { $uEntry.Properties } else { $uEntry }
                    $platId = if ($null -ne $uProps.accountPlatform) { [string]$uProps.accountPlatform } else { '' }
                    if (-not [string]::IsNullOrEmpty($platId) -and -not $platformSchemas.ContainsKey($platId)) {
                        $schema = Get-PlatformSchema -PlatformId $platId -Header $authHeader
                        $platformSchemas[$platId] = $schema
                        if ($null -ne $schema) {
                            $reqNames = ($schema.required | ForEach-Object { $PSItem.name }) -join ', '
                            $optNames = ($schema.optional | Select-Object -First 5 | ForEach-Object { $PSItem.name }) -join ', '
                            Write-TestLog "  [UCS] Platform '$platId': required=[$reqNames]  optional(first5)=[$optNames]" -ForegroundColor Gray
                        } else {
                            Write-TestLog "  [UCS] Platform '$platId': schema not found -- coverage checks skipped." -ForegroundColor Yellow
                        }
                    }
                }

                # ------------------------------------------------------------------
                # Per-UCS: determine which extra CSV columns are needed.
                # ExtraProps: ordered hashtable of { colName -> @{Value; Source; PlatProp} }
                #   Source = 'required' | 'optional'
                #   PlatProp = the platform property name (same as colName for non-mapped props)
                # ------------------------------------------------------------------

                # Per-UCS extra props map: ucsKey -> ordered @{ colName -> @{Value;Source;PlatProp} }
                $ucsExtraPropsMap = @{}

                foreach ($ucsKey in $ucsKeys) {
                    $uEntry = $jsonRaw.UserConfigSet.$ucsKey
                    $uProps = if ($null -ne $uEntry.Properties) { $uEntry.Properties } else { $uEntry }
                    $platId = if ($null -ne $uProps.accountPlatform) { [string]$uProps.accountPlatform } else { '' }
                    $schema = if (-not [string]::IsNullOrEmpty($platId)) { $platformSchemas[$platId] } else { $null }
                    $extraProps = [ordered]@{}

                    if ($null -ne $schema) {
                        # Required: add CSV column if not already covered by UCS Properties
                        foreach ($req in $schema.required) {
                            $ucsKey2 = if ($script:PlatformPropToUcsKey.ContainsKey($req.name)) {
                                $script:PlatformPropToUcsKey[$req.name]
                            } else {
                                $req.name
                            }
                            # $null means always handled (e.g. Username via accountUserPattern)
                            if ($null -eq $ucsKey2) { continue }
                            # Already in UCS Properties?
                            $alreadyCovered = $null -ne $uProps.PSObject.Properties[$ucsKey2] -and
                                -not [string]::IsNullOrEmpty([string]$uProps.$ucsKey2)
                            if (-not $alreadyCovered -and -not $extraProps.Contains($req.name)) {
                                $extraProps[$req.name] = @{
                                    Value    = "req-$($req.name)-test"
                                    Source   = 'required'
                                    PlatProp = $req.name
                                }
                            }
                        }

                        # Optional: pick up to 2 not already covered by UCS Properties
                        $optCount = 0
                        foreach ($opt in $schema.optional) {
                            if ($optCount -ge 2) { break }
                            $ucsKey2 = if ($script:PlatformPropToUcsKey.ContainsKey($opt.name)) {
                                $script:PlatformPropToUcsKey[$opt.name]
                            } else {
                                $opt.name
                            }
                            if ($null -eq $ucsKey2) { continue }
                            $alreadyCovered = $null -ne $uProps.PSObject.Properties[$ucsKey2] -and
                                -not [string]::IsNullOrEmpty([string]$uProps.$ucsKey2)
                            if (-not $alreadyCovered -and -not $extraProps.Contains($opt.name)) {
                                $extraProps[$opt.name] = @{
                                    Value    = "opt-$($opt.name)-test"
                                    Source   = 'optional'
                                    PlatProp = $opt.name
                                }
                                $optCount++
                            }
                        }
                    }
                    $ucsExtraPropsMap[$ucsKey] = $extraProps
                }

                # ------------------------------------------------------------------
                # Build UCS CSV -- one row per UCS, with dynamic extra columns.
                # Each row gets the extra columns for its own UCS (blank for others).
                # Collect the union of all extra column names for the header.
                # ------------------------------------------------------------------
                $allExtraCols = [System.Collections.Generic.List[string]]::new()
                foreach ($ucsKey in $ucsKeys) {
                    foreach ($col in $ucsExtraPropsMap[$ucsKey].Keys) {
                        if (-not $allExtraCols.Contains($col)) {
                            $allExtraCols.Add($col)
                        }
                    }
                }

                $ucsCsvLines = [System.Collections.Generic.List[string]]::new()
                $csvHeaderCols = [System.Collections.Generic.List[string]]::new()
                $null = $csvHeaderCols.Add('userName')
                $null = $csvHeaderCols.Add('safeName')
                $null = $csvHeaderCols.Add('SafeConfigSet')
                $null = $csvHeaderCols.Add('UserConfigSet')
                foreach ($col in $allExtraCols) { $null = $csvHeaderCols.Add($col) }
                $ucsCsvLines.Add(($csvHeaderCols -join ','))

                $ucsIdx = 0
                foreach ($ucsKey in $ucsKeys) {
                    $ucsIdx++
                    $csvUserName = "u${runId}${ucsIdx}"
                    $rowCols = [System.Collections.Generic.List[string]]::new()
                    $null = $rowCols.Add($csvUserName)
                    $null = $rowCols.Add($ucsSafeName)
                    $null = $rowCols.Add('')               # SafeConfigSet (blank -- use default)
                    $null = $rowCols.Add($ucsKey)
                    foreach ($col in $allExtraCols) {
                        $val = if ($ucsExtraPropsMap[$ucsKey].Contains($col)) {
                            $ucsExtraPropsMap[$ucsKey][$col].Value
                        } else {
                            ''
                        }
                        $null = $rowCols.Add($val)
                    }
                    $ucsCsvLines.Add(($rowCols -join ','))

                    $_ucsPlatId = if ($null -ne $jsonRaw.UserConfigSet.$ucsKey.Properties) {
                        [string]$jsonRaw.UserConfigSet.$ucsKey.Properties.accountPlatform
                    } else {
                        ''
                    }
                    $ucsZone.Cases.Add([PSCustomObject]@{
                            Idx              = $ucsIdx
                            UCSName          = $ucsKey
                            CsvUserName      = $csvUserName
                            ExtraProps       = $ucsExtraPropsMap[$ucsKey]   # ordered @{ col -> @{Value;Source;PlatProp} }
                            PlatformSchema   = $platformSchemas[$_ucsPlatId]
                            AccountId        = $null
                            AccountUserName  = $null
                            AccountAddress   = $null
                            AssertionResults = [System.Collections.Generic.List[PSCustomObject]]::new()
                            CleanupStatus    = $null
                        })
                }

                $tempUcsCsvPath = Join-Path -Path $scriptDir -ChildPath "tpac_ucs_${runId}.csv"
                $reportObj.TempUcsCsvPath = $tempUcsCsvPath
                $ucsCsvLines | Out-File -FilePath $tempUcsCsvPath -Encoding utf8 -Force

                Write-TestLog "  [UCS] Running main script for $($ucsKeys.Count) User Config Set row(s)..." -ForegroundColor Gray

                $mainUcsParams = @{
                    PVWAURL    = $PVWAURL
                    logonToken = $authHeader
                    CSVPath    = $tempUcsCsvPath
                    ConfigPath = $tempUcsConfigPath
                }
                if ($DisableCertificateValidation) {
                    $mainUcsParams.DisableCertificateValidation = $true
                }

                $childLogPath = Join-Path -Path $scriptDir -ChildPath 'PersonalPrivilegedAccounts.log'
                $logLinesBefore = if (Test-Path -Path $childLogPath) {
                    (Get-Content -Path $childLogPath).Count
                } else {
                    0
                }
                & $ScriptPath @mainUcsParams 4>$null 5>$null
                $ucsExitCode = $LASTEXITCODE
                $newLogLines = if (Test-Path -Path $childLogPath) {
                    Get-Content -Path $childLogPath | Select-Object -Skip $logLinesBefore
                } else {
                    @()
                }

                # ------------------------------------------------------------------
                # Check log for PASWS018E numeric-type errors and retry once.
                # Pattern: "Account <user>@<addr> (index: N) failed: PASWS018E
                #           Input parameter for [PropName] value is invalid, should be numeric"
                # Only the failed rows are included in the retry CSV.
                # ------------------------------------------------------------------
                $numericProps = [System.Collections.Generic.List[string]]::new()
                $failedUserNames = [System.Collections.Generic.List[string]]::new()
                foreach ($line in $newLogLines) {
                    $lineStr = [string]$line
                    $mProp = [regex]::Match($lineStr, 'PASWS018E Input parameter for \[([^\]]+)\].*should be numeric')
                    if ($mProp.Success) {
                        $badProp = $mProp.Groups[1].Value
                        if (-not $numericProps.Contains($badProp)) {
                            $numericProps.Add($badProp)
                        }
                        # Extract the userName from "Account <user>@<addr> (index: N) failed: ..."
                        $mUser = [regex]::Match($lineStr, 'Account ([^@]+)@')
                        if ($mUser.Success) {
                            $failedUser = $mUser.Groups[1].Value.Trim()
                            if (-not $failedUserNames.Contains($failedUser)) {
                                $failedUserNames.Add($failedUser)
                            }
                        }
                    }
                }

                if ($numericProps.Count -gt 0 -and $failedUserNames.Count -gt 0) {
                    Write-TestLog "  [UCS] Detected numeric validation errors for: $($numericProps -join ', ') on: $($failedUserNames -join ', ') -- correcting and retrying failures only..." -ForegroundColor Yellow

                    # Correct the bad property values to '1' for the affected UCS entries
                    foreach ($ucsKey in $ucsKeys) {
                        foreach ($badProp in $numericProps) {
                            if ($ucsExtraPropsMap[$ucsKey].Contains($badProp)) {
                                $ucsExtraPropsMap[$ucsKey][$badProp].Value = '1'
                            }
                        }
                    }

                    # Rebuild CSV containing only the failed rows (avoid duplicate-account errors)
                    $retryCsvLines = [System.Collections.Generic.List[string]]::new()
                    $retryCsvLines.Add(($csvHeaderCols -join ','))
                    foreach ($utcCase in $ucsZone.Cases) {
                        # Determine the expected account userName for this case (pattern-applied)
                        $retryPattern = $null
                        $retryEntry = $jsonRaw.UserConfigSet.$($utcCase.UCSName)
                        if ($null -ne $retryEntry.Options -and
                            -not [string]::IsNullOrEmpty($retryEntry.Options.accountUserPattern)) {
                            $retryPattern = $retryEntry.Options.accountUserPattern
                        }
                        $retryExpectedUser = if (-not [string]::IsNullOrEmpty($retryPattern)) {
                            $retryPattern.Replace('*', $utcCase.CsvUserName)
                        } else {
                            $utcCase.CsvUserName
                        }

                        if (-not $failedUserNames.Contains($retryExpectedUser)) {
                            continue  # this account succeeded first time -- skip it
                        }

                        $rowCols2 = [System.Collections.Generic.List[string]]::new()
                        $null = $rowCols2.Add($utcCase.CsvUserName)
                        $null = $rowCols2.Add($ucsSafeName)
                        $null = $rowCols2.Add('')
                        $null = $rowCols2.Add($utcCase.UCSName)
                        foreach ($col in $allExtraCols) {
                            $val2 = if ($ucsExtraPropsMap[$utcCase.UCSName].Contains($col)) {
                                $ucsExtraPropsMap[$utcCase.UCSName][$col].Value
                            } else {
                                ''
                            }
                            $null = $rowCols2.Add($val2)
                        }
                        $retryCsvLines.Add(($rowCols2 -join ','))
                        $utcCase.ExtraProps = $ucsExtraPropsMap[$utcCase.UCSName]
                    }
                    $retryCsvLines | Out-File -FilePath $tempUcsCsvPath -Encoding utf8 -Force

                    Write-TestLog "  [UCS] Retrying $($retryCsvLines.Count - 1) failed row(s) with corrected numeric values..." -ForegroundColor Gray
                    & $ScriptPath @mainUcsParams 4>$null 5>$null
                    $ucsExitCode = $LASTEXITCODE
                }

                $z2Status = if ($null -eq $ucsExitCode -or $ucsExitCode -eq 0) {
                    'PASS'
                } else {
                    'FAIL'
                }
                $z2Detail = if ($ucsExitCode -ne 0) {
                    "Exit code: $ucsExitCode"
                } else {
                    ''
                }
                Assert-Result -Id 'UCS_run' -Description 'User Config Set validation script exited without fatal error' -Status $z2Status -Detail $z2Detail
                Write-TestLog ''

                # Per-UCS assertions
                foreach ($utc in $ucsZone.Cases) {
                    $ucsEntry = $jsonRaw.UserConfigSet.$($utc.UCSName)
                    $uprfx = "UCS_$($utc.Idx)_$($utc.UCSName)"

                    # Resolve accountUserPattern -> expected userName on the account
                    $pattern = $null
                    if ($null -ne $ucsEntry.Options -and
                        -not [string]::IsNullOrEmpty($ucsEntry.Options.accountUserPattern)) {
                        $pattern = $ucsEntry.Options.accountUserPattern
                    } elseif ($null -ne $ucsEntry.accountUserPattern) {
                        $pattern = $ucsEntry.accountUserPattern
                    }
                    $expectedAccountUser = if (-not [string]::IsNullOrEmpty($pattern)) {
                        $pattern.Replace('*', $utc.CsvUserName)
                    } else {
                        $utc.CsvUserName
                    }

                    $ucsProps = if ($null -ne $ucsEntry.Properties) {
                        $ucsEntry.Properties
                    } else {
                        $ucsEntry
                    }

                    Write-StepHeader "Verify User Config Set '$($utc.UCSName)'"

                    # Find the account by fetching all accounts in the safe and matching client-side
                    $acctUri = "$baseURL/api/Accounts?filter=$([URI]::EscapeDataString("safeName eq $ucsSafeName"))&limit=1000"
                    $acctResp = Invoke-TestRest -Method GET -URI $acctUri -Header $authHeader
                    if ($null -ne $acctResp -and $acctResp.count -gt 0) {
                        $matched = $acctResp.value | Where-Object { $PSItem.userName -eq $expectedAccountUser } | Select-Object -First 1
                        if ($null -ne $matched) {
                            $acctResp = [PSCustomObject]@{ count = 1; value = @($matched) }
                        } else {
                            $acctResp = [PSCustomObject]@{ count = 0; value = @() }
                        }
                    }

                    $acctExists = $null -ne $acctResp -and $acctResp.count -gt 0
                    $aeStatus = if ($acctExists) {
                        'PASS'
                    } else {
                        'FAIL'
                    }
                    Assert-Result -Id "${uprfx}_account_exists" -Description "Account '$expectedAccountUser' onboarded into '$ucsSafeName'" -Status $aeStatus

                    if (-not $acctExists) {
                        Write-TestLog '    (skipping property assertions -- account not found)' -ForegroundColor DarkYellow
                        Write-TestLog ''
                        continue
                    }

                    $acct = $acctResp.value | Select-Object -First 1
                    $utc.AccountId = $acct.id
                    $utc.AccountUserName = $expectedAccountUser
                    $utc.AccountAddress = $acct.address

                    # userName
                    $unStatus = if ($acct.userName -eq $expectedAccountUser) {
                        'PASS'
                    } else {
                        'FAIL'
                    }
                    $unDetail = "expected '$expectedAccountUser', got '$($acct.userName)'"
                    Assert-Result -Id "${uprfx}_userName" -Description "Account '$expectedAccountUser' in '$ucsSafeName' has userName = '$expectedAccountUser' (from UCS '$($utc.UCSName)')" -Status $unStatus -Detail $unDetail

                    # address
                    if ($null -ne $ucsProps.accountAddress -and
                        -not [string]::IsNullOrEmpty($ucsProps.accountAddress)) {
                        $adStatus = if ($acct.address -eq $ucsProps.accountAddress) {
                            'PASS'
                        } else {
                            'FAIL'
                        }
                        $adDetail = "expected '$($ucsProps.accountAddress)', got '$($acct.address)'"
                        Assert-Result -Id "${uprfx}_address" -Description "Account '$expectedAccountUser' has address = '$($ucsProps.accountAddress)' (from UCS '$($utc.UCSName)')" -Status $adStatus -Detail $adDetail
                    }

                    # platformId
                    if ($null -ne $ucsProps.accountPlatform -and
                        -not [string]::IsNullOrEmpty($ucsProps.accountPlatform)) {
                        $plStatus = if ($acct.platformId -eq $ucsProps.accountPlatform) {
                            'PASS'
                        } else {
                            'FAIL'
                        }
                        $plDetail = "expected '$($ucsProps.accountPlatform)', got '$($acct.platformId)'"
                        Assert-Result -Id "${uprfx}_platform" -Description "Account '$expectedAccountUser' has platformId = '$($ucsProps.accountPlatform)' (from UCS '$($utc.UCSName)')" -Status $plStatus -Detail $plDetail
                    }

                    # automaticManagementEnabled
                    if ($null -ne $ucsProps.enableAutoMgmt -and
                        -not [string]::IsNullOrEmpty($ucsProps.enableAutoMgmt)) {
                        $expAuto = $ucsProps.enableAutoMgmt -match '^y(es)?$'
                        $actAuto = $acct.secretManagement.automaticManagementEnabled -eq $true
                        $amStatus = if ($expAuto -eq $actAuto) {
                            'PASS'
                        } else {
                            'FAIL'
                        }
                        $amDetail = "expected '$expAuto', got '$actAuto'"
                        Assert-Result -Id "${uprfx}_autoMgmt" -Description "Account '$expectedAccountUser' has automaticManagementEnabled = $expAuto (from UCS '$($utc.UCSName)')" -Status $amStatus -Detail $amDetail
                    }

                    # Extra platform properties
                    $reservedKeys = @('accountplatform', 'accountaddress', 'accountuserpattern',
                        'enableautomgmt', 'manualmgmtreason', 'allowduplicateaccounts',
                        'remotemachineaddresses', 'restrictmachineaccesstolist')
                    foreach ($prop in $ucsProps.PSObject.Properties) {
                        if ($prop.Name.ToLower() -in $reservedKeys) {
                            continue
                        }
                        if ([string]::IsNullOrEmpty($prop.Value)) {
                            continue
                        }
                        $actVal = if ($null -ne $acct.platformAccountProperties) {
                            $acct.platformAccountProperties.$($prop.Name)
                        } else {
                            $null
                        }
                        $ppStatus = if ($actVal -eq $prop.Value) {
                            'PASS'
                        } else {
                            'FAIL'
                        }
                        $ppDetail = "expected '$($prop.Value)', got '$actVal'"
                        Assert-Result -Id "${uprfx}_prop_$($prop.Name)" -Description "Account '$expectedAccountUser' has $($prop.Name) = '$($prop.Value)' (from UCS '$($utc.UCSName)')" -Status $ppStatus -Detail $ppDetail
                    }

                    # ----------------------------------------------------------
                    # Platform coverage assertions (live schema)
                    # Required fields: assert each required platform property is
                    #   non-empty on the account (from UCS Properties or extra CSV col).
                    # Optional fields (those injected as extra CSV cols): assert
                    #   the expected value landed in platformAccountProperties.
                    # ----------------------------------------------------------
                    if ($null -ne $utc.PlatformSchema) {
                        # Required field coverage
                        foreach ($req in $utc.PlatformSchema.required) {
                            $acctField = if ($script:PlatformPropToAcctField.ContainsKey($req.name)) {
                                $script:PlatformPropToAcctField[$req.name]
                            } else {
                                $null  # lives in platformAccountProperties
                            }
                            $actReqVal = if ($null -ne $acctField) {
                                # top-level field (address, userName)
                                $acct.$acctField
                            } elseif ($null -ne $acct.platformAccountProperties) {
                                $acct.platformAccountProperties.$($req.name)
                            } else {
                                $null
                            }
                            $reqStatus = if (-not [string]::IsNullOrEmpty($actReqVal)) {
                                'PASS'
                            } else {
                                'FAIL'
                            }
                            $reqDetail = if ([string]::IsNullOrEmpty($actReqVal)) {
                                "required platform property '$($req.name)' is empty/missing on account"
                            } else {
                                ''
                            }
                            Assert-Result -Id "${uprfx}_plat_req_$($req.name)" -Description "Platform '$($ucsProps.accountPlatform)' required property '$($req.name)' is populated on '$expectedAccountUser'" -Status $reqStatus -Detail $reqDetail
                        }

                        # Optional fields injected via extra CSV columns
                        foreach ($col in $utc.ExtraProps.Keys) {
                            $epInfo = $utc.ExtraProps[$col]
                            if ($epInfo.Source -ne 'optional') { continue }
                            $actOptVal = if ($null -ne $acct.platformAccountProperties) {
                                $acct.platformAccountProperties.$col
                            } else {
                                $null
                            }
                            $optStatus = if ($actOptVal -eq $epInfo.Value) {
                                'PASS'
                            } else {
                                'FAIL'
                            }
                            $optDetail = "expected '$($epInfo.Value)', got '$actOptVal'"
                            Assert-Result -Id "${uprfx}_plat_opt_$col" -Description "Platform '$($ucsProps.accountPlatform)' optional property '$col' = '$($epInfo.Value)' on '$expectedAccountUser'" -Status $optStatus -Detail $optDetail
                        }
                    }

                    Write-TestLog ''
                }
            }
        }
    } else {
        if ($SkipUserConfigSets) {
            Write-TestLog '[UCS] User Config Set validation skipped (-SkipUserConfigSets specified).' -ForegroundColor Gray
        } else {
            Write-TestLog '[UCS] No User Config Set entries -- User Config Set validation skipped.' -ForegroundColor Gray
        }
        Write-TestLog ''
    }

} catch {
    Write-TestLog ''
    Write-TestLog "FATAL: $($PSItem.Exception.Message)" -ForegroundColor Red
    Write-TestLog "       $($PSItem.ScriptStackTrace)" -ForegroundColor DarkRed
} finally {
    # Remove temp files
    if (-not $KeepArtifacts) {
        foreach ($tf in @($tempScsCsvPath, $tempScsConfigPath, $tempUcsCsvPath, $tempUcsConfigPath)) {
            if (-not [string]::IsNullOrEmpty($tf) -and (Test-Path -Path $tf)) {
                Remove-Item -Path $tf -Force
            }
        }
        Write-TestLog '  [CLEANUP] Temp files removed.' -ForegroundColor Gray
    } else {
        Write-TestLog '  [CLEANUP] -KeepArtifacts set -- temp files retained.' -ForegroundColor Yellow
    }

    # Logoff only if this script owns the session
    if ($ownedSession -and $null -ne $authHeader) {
        $logoffUri = "$baseURL/api/Auth/Logoff"
        $null = Invoke-TestRest -Method POST -URI $logoffUri -Header $authHeader
        Write-TestLog '  [CLEANUP] Session logged off.' -ForegroundColor Gray
    } else {
        Write-TestLog '  [CLEANUP] Session owned externally -- not logging off.' -ForegroundColor Gray
    }

    # Write report
    $reportObj.AssertionSummary = [ordered]@{
        Pass  = ($assertResults | Where-Object { $PSItem.Status -eq 'PASS' }).Count
        Fail  = ($assertResults | Where-Object { $PSItem.Status -eq 'FAIL' }).Count
        Warn  = ($assertResults | Where-Object { $PSItem.Status -eq 'WARN' }).Count
        Skip  = ($assertResults | Where-Object { $PSItem.Status -eq 'SKIP' }).Count
        Total = $assertResults.Count
    }
    $reportObj.AllAssertions = $assertResults
    $reportObj | ConvertTo-Json -Depth 20 |
    Out-File -FilePath $reportOutPath -Encoding utf8 -Force
    Write-TestLog "  [REPORT] Written to: $reportOutPath" -ForegroundColor Gray
}

#region Summary

$passCount = ($assertResults | Where-Object { $PSItem.Status -eq 'PASS' }).Count
$failCount = ($assertResults | Where-Object { $PSItem.Status -eq 'FAIL' }).Count
$warnCount = ($assertResults | Where-Object { $PSItem.Status -eq 'WARN' }).Count
$skipCount = ($assertResults | Where-Object { $PSItem.Status -eq 'SKIP' }).Count
$total = $assertResults.Count

Write-TestLog ''
Write-TestLog ('=' * 72) -ForegroundColor Cyan
$summaryColor = if ($failCount -eq 0) {
    'Green'
} else {
    'Red'
}
$extras = @()
if ($warnCount -gt 0) {
    $extras += "$warnCount warnings"
}
if ($skipCount -gt 0) {
    $extras += "$skipCount skipped"
}
$extraPart = if ($extras.Count -gt 0) {
    ', ' + ($extras -join ', ')
} else {
    ''
}
$summaryMsg = "  RESULTS: $passCount passed, $failCount failed$extraPart out of $total assertions"
Write-TestLog $summaryMsg -ForegroundColor $summaryColor
Write-TestLog ('=' * 72) -ForegroundColor Cyan

# Helper: turn an assertion ID into a plain-English location label
function Get-AssertionLabel {
    param([string]$AssertId)
    $p = $AssertId -split '_'
    # SCS_run / UCS_run / UCS_shared_safe / SCS_<n>_<name>_... / UCS_<n>_<name>_...
    if ($p.Count -le 2) {
        $label = if ($p[0] -eq 'SCS') {
            'Safe Config Set'
        } else {
            'User Config Set'
        }
        return $label
    }
    $ctxIdx = 0
    if ($p[0] -eq 'SCS' -and [int]::TryParse($p[1], [ref]$ctxIdx)) {
        $scsName = $p[2]
        $tc = $scsTestCases | Where-Object { $PSItem.Idx -eq $ctxIdx } | Select-Object -First 1
        $safePart = if ($null -ne $tc) {
            "  safe: $($tc.SafeName)"
        } else {
            ''
        }
        return "Safe Config Set '$scsName'$safePart"
    }
    if ($p[0] -eq 'UCS' -and [int]::TryParse($p[1], [ref]$ctxIdx)) {
        $ucsName = $p[2]
        if ($null -ne $ucsZone) {
            $utc = $ucsZone.Cases | Where-Object { $PSItem.Idx -eq $ctxIdx } | Select-Object -First 1
            $safePart = "  safe: $($ucsZone.SharedSafeName)"
            $acctPart = if ($null -ne $utc -and $null -ne $utc.AccountUserName) {
                "  account: $($utc.AccountUserName)"
            } else {
                ''
            }
            return "User Config Set '$ucsName'$safePart$acctPart"
        }
        return "User Config Set '$ucsName'"
    }
    return $AssertId
}

if ($failCount -gt 0) {
    Write-TestLog ''
    Write-TestLog 'Failed assertions:' -ForegroundColor Red
    $assertResults | Where-Object { $PSItem.Status -eq 'FAIL' } | ForEach-Object {
        $a = $PSItem
        Write-TestLog ('  [{0}] {1}' -f $a.TNum, $a.Description) -ForegroundColor Red
        if (-not [string]::IsNullOrEmpty($a.Detail)) {
            Write-TestLog ("        Detail: $($a.Detail)") -ForegroundColor DarkRed
        }
    }
}
if ($warnCount -gt 0) {
    Write-TestLog ''
    Write-TestLog 'Warnings:' -ForegroundColor Yellow
    $assertResults | Where-Object { $PSItem.Status -eq 'WARN' } | ForEach-Object {
        $a = $PSItem
        Write-TestLog ('  [{0}] {1}' -f $a.TNum, $a.Description) -ForegroundColor Yellow
        if (-not [string]::IsNullOrEmpty($a.Detail)) {
            Write-TestLog ("        Detail: $($a.Detail)") -ForegroundColor DarkYellow
        }
    }
}

# Resources summary
Write-TestLog ''
Write-TestLog ('=' * 72) -ForegroundColor DarkCyan
Write-TestLog '  RESOURCES CREATED' -ForegroundColor DarkCyan
Write-TestLog ('=' * 72) -ForegroundColor DarkCyan
Write-TestLog ''
Write-TestLog '  Safe Config Set safes:' -ForegroundColor Gray
foreach ($tc in $scsTestCases) {
    $stateLabel = if ($tc.Skipped) {
        'skipped'
    } elseif ($tc.SafeCreated) {
        'created'
    } else {
        'FAILED'
    }
    Write-TestLog ('    [{0}] {1}  (SCS: {2})  [{3}]' -f $tc.Idx, $tc.SafeName, $tc.SCSName, $stateLabel) -ForegroundColor Gray
}
if ($null -ne $ucsZone) {
    Write-TestLog ''
    Write-TestLog ('  User Config Set accounts  (safe: {0}):' -f $ucsZone.SharedSafeName) -ForegroundColor Gray
    foreach ($utc in $ucsZone.Cases) {
        $acctLabel = if ($null -ne $utc.AccountUserName) {
            $utc.AccountUserName
        } else {
            '(not created)'
        }
        $addrLabel = if ($null -ne $utc.AccountAddress) {
            "  address: $($utc.AccountAddress)"
        } else {
            ''
        }
        Write-TestLog ('    [{0}] {1}{2}  (UCS: {3})' -f $utc.Idx, $acctLabel, $addrLabel, $utc.UCSName) -ForegroundColor Gray
    }
}
Write-TestLog ''
Write-TestLog '  To clean up all test resources run:' -ForegroundColor Cyan
Write-TestLog "    .\Test-PersonalPrivilgedAccountsConfig.ps1 -Cleanup -ReportPath '$reportOutPath'" -ForegroundColor Cyan
Write-TestLog ''

#endregion

exit $failCount
