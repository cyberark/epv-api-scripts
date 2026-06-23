#Requires -Version 5.1
<#
.SYNOPSIS
    Creates, modifies, and validates PersonalPrivilegedAccounts JSON config files.

.DESCRIPTION
    Supports four operations against a PersonalPrivilegedAccounts JSON config file:

      Create   — Build a new JSON config file from scratch, optionally walking through
                 default SafeConfigSet and UserConfigSet interactively.
      Set      — Add or update a named set inside an existing JSON file. Merges over
                 existing values so only the supplied fields are changed.
      Remove   — Delete a named set from an existing JSON file.
      Validate — Check that an existing JSON file conforms to the expected schema.

    Any parameter that is required for an operation but not supplied is prompted for
    interactively. When all required parameters are supplied the script runs silently.

    JSON Schema (no backwards-compatibility with the old flat structure):

      SafeConfigSet.<name>
        Options
          useExisting              bool   — true: reuse existing safe; false: error + skip
        Properties
          CPMName                  string — CPM name assigned to the safe
          NumberOfDaysRetention    int    — days to retain (exclusive with Versions)
          NumberOfVersionsRetention int   — version count (exclusive with Days)
          SafeNamePattern          string — safe name pattern; must contain *
          SafeEndUserRole          string — built-in role for end-user owner
          SafeEndUserRoleConfigSet string — RoleConfigSet name for end-user owner
          SafeEndUserSearchIn      string — searchIn value for end-user (e.g. 'Vault' or a directory UUID)
          SafeEndUserMemberType    string — memberType for end-user add call (User, Group, Role, or '' for default)
          DefaultSafeMembers       array  — [{ Name, Role|RoleConfigSet|Permissions, SearchIn, MemberType? }]

      UserConfigSet.<name>
        Options
          accountUserPattern       string — pattern for account username (* → userName)
          allowDuplicateAccounts   bool
        Properties
          accountPlatform          string
          accountAddress           string
          enableAutoMgmt           yes|no
          manualMgmtReason         string
          remoteMachineAddresses   string
          restrictMachineAccessToList yes|no

      RoleConfigSet.<name>   (flat — no Options/Properties split)
          22 boolean permissions: useAccounts, retrieveAccounts, listAccounts, ...

.PARAMETER FilePath
    Path to the JSON config file to create, edit, or validate.

.PARAMETER Operation
    The operation to perform: Create | Set | Remove | Validate.

.PARAMETER ConfigSetType
    Top-level section to target: SafeConfigSet | UserConfigSet | RoleConfigSet.
    Required for Set and Remove.

.PARAMETER SetName
    Name of the named set to add, update, or remove (e.g. 'default', 'prod').
    Required for Set and Remove.

.PARAMETER UseExisting
    SafeConfigSet.Options.useExisting — 'true' or 'false'.

.PARAMETER CPMName
    SafeConfigSet.Properties.CPMName.

.PARAMETER NumberOfDaysRetention
    SafeConfigSet.Properties.NumberOfDaysRetention. Use -1 to leave unchanged.

.PARAMETER NumberOfVersionsRetention
    SafeConfigSet.Properties.NumberOfVersionsRetention. Use -1 to leave unchanged.

.PARAMETER SafeNamePattern
    SafeConfigSet.Properties.SafeNamePattern (must contain *).

.PARAMETER SafeEndUserRole
    SafeConfigSet.Properties.SafeEndUserRole (e.g. EndUser, Full, AccountsManager).
    Mutually exclusive with SafeEndUserRoleConfigSet.

.PARAMETER SafeEndUserRoleConfigSet
    SafeConfigSet.Properties.SafeEndUserRoleConfigSet.
    Mutually exclusive with SafeEndUserRole.

.PARAMETER SafeEndUserSearchIn
    SafeConfigSet.Properties.SafeEndUserSearchIn.
    The searchIn value passed when adding the end-user as a safe member (e.g. 'Vault' or a directory UUID).

.PARAMETER SafeEndUserMemberType
    SafeConfigSet.Properties.SafeEndUserMemberType.
    The memberType passed when adding the end-user (User, Group, Role, or empty for platform default).

.PARAMETER DefaultSafeMembersJson
    SafeConfigSet.Properties.DefaultSafeMembers as a JSON array string.
    Example: '[{"Name":"Vault Admins","Role":"Full","SearchIn":"Vault"}]'

.PARAMETER AccountUserPattern
    UserConfigSet.Options.accountUserPattern (e.g. '*_adm').

.PARAMETER AllowDuplicateAccounts
    UserConfigSet.Options.allowDuplicateAccounts — 'true' or 'false'.

.PARAMETER AccountPlatform
    UserConfigSet.Properties.accountPlatform.

.PARAMETER AccountAddress
    UserConfigSet.Properties.accountAddress.

.PARAMETER EnableAutoMgmt
    UserConfigSet.Properties.enableAutoMgmt — 'yes' or 'no'.

.PARAMETER ManualMgmtReason
    UserConfigSet.Properties.manualMgmtReason.

.PARAMETER RemoteMachineAddresses
    UserConfigSet.Properties.remoteMachineAddresses.

.PARAMETER RestrictMachineAccessToList
    UserConfigSet.Properties.restrictMachineAccessToList — 'yes' or 'no'.

.PARAMETER RoleTemplate
    Starting template for a RoleConfigSet named set:
    Full | EndUser | ReadOnly | UseAndRetrieve | AccountsManager | Custom.
    Custom starts with all permissions false.

.PARAMETER PermissionsJson
    Merges specific permissions on top of RoleTemplate.
    Example: '{"useAccounts":true,"listAccounts":true,"viewAuditLog":true}'

.EXAMPLE
    # Fully interactive — prompts for everything:
    .\Edit-PersonalPrivilegedAccountsConfig.ps1

.EXAMPLE
    # Create a new file interactively:
    .\Edit-PersonalPrivilegedAccountsConfig.ps1 -FilePath .\myconfig.json -Operation Create

.EXAMPLE
    # Add/update a SafeConfigSet named 'prod' (non-interactive):
    .\Edit-PersonalPrivilegedAccountsConfig.ps1 -FilePath .\myconfig.json -Operation Set `
        -ConfigSetType SafeConfigSet -SetName prod `
        -UseExisting true -CPMName PasswordManager_Prod -NumberOfDaysRetention 30 `
        -SafeNamePattern '*_PROD'

.EXAMPLE
    # Add a UserConfigSet named 'dev' (non-interactive):
    .\Edit-PersonalPrivilegedAccountsConfig.ps1 -FilePath .\myconfig.json -Operation Set `
        -ConfigSetType UserConfigSet -SetName dev `
        -AccountUserPattern '*_adm' -AccountPlatform WinDomain `
        -AccountAddress dev.corp.com -EnableAutoMgmt no -ManualMgmtReason 'Managed externally'

.EXAMPLE
    # Add a RoleConfigSet from the EndUser template, then enable accessWithoutConfirmation:
    .\Edit-PersonalPrivilegedAccountsConfig.ps1 -FilePath .\myconfig.json -Operation Set `
        -ConfigSetType RoleConfigSet -SetName PrivUser -RoleTemplate EndUser `
        -PermissionsJson '{"accessWithoutConfirmation":true}'

.EXAMPLE
    # Remove a named set:
    .\Edit-PersonalPrivilegedAccountsConfig.ps1 -FilePath .\myconfig.json -Operation Remove `
        -ConfigSetType SafeConfigSet -SetName dev

.EXAMPLE
    # Validate an existing file:
    .\Edit-PersonalPrivilegedAccountsConfig.ps1 -FilePath .\PersonalPrivilegedAccounts.json -Operation Validate

.NOTES
    Version: 1.0
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Interactive wizard script. Write-Host is used intentionally for coloured user-interface output.')]
param(
    [Parameter(Mandatory = $false)]
    [string]$FilePath,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Create', 'Set', 'Remove', 'Validate')]
    [string]$Operation,

    [Parameter(Mandatory = $false)]
    [ValidateSet('SafeConfigSet', 'UserConfigSet', 'RoleConfigSet')]
    [string]$ConfigSetType,

    [Parameter(Mandatory = $false)]
    [string]$SetName,

    # SafeConfigSet.Options
    [Parameter(Mandatory = $false)]
    [ValidateSet('', 'true', 'false')]
    [string]$UseExisting = '',

    # SafeConfigSet.Properties
    [Parameter(Mandatory = $false)]
    [string]$CPMName,

    [Parameter(Mandatory = $false)]
    [int]$NumberOfDaysRetention = -1,

    [Parameter(Mandatory = $false)]
    [int]$NumberOfVersionsRetention = -1,

    [Parameter(Mandatory = $false)]
    [string]$SafeNamePattern,

    [Parameter(Mandatory = $false)]
    [string]$SafeEndUserRole,

    [Parameter(Mandatory = $false)]
    [string]$SafeEndUserRoleConfigSet,

    [Parameter(Mandatory = $false)]
    [string]$SafeEndUserSearchIn,

    [Parameter(Mandatory = $false)]
    [ValidateSet('', 'User', 'Group', 'Role')]
    [string]$SafeEndUserMemberType = '',

    [Parameter(Mandatory = $false)]
    [string]$DefaultSafeMembersJson,

    # UserConfigSet.Options
    [Parameter(Mandatory = $false)]
    [string]$AccountUserPattern,

    [Parameter(Mandatory = $false)]
    [ValidateSet('', 'true', 'false')]
    [string]$AllowDuplicateAccounts = '',

    # UserConfigSet.Properties
    [Parameter(Mandatory = $false)]
    [string]$AccountPlatform,

    [Parameter(Mandatory = $false)]
    [string]$AccountAddress,

    [Parameter(Mandatory = $false)]
    [ValidateSet('', 'yes', 'no')]
    [string]$EnableAutoMgmt = '',

    [Parameter(Mandatory = $false)]
    [string]$ManualMgmtReason,

    [Parameter(Mandatory = $false)]
    [string]$RemoteMachineAddresses,

    [Parameter(Mandatory = $false)]
    [ValidateSet('', 'yes', 'no')]
    [string]$RestrictMachineAccessToList = '',

    # RoleConfigSet
    [Parameter(Mandatory = $false)]
    [ValidateSet('', 'Full', 'EndUser', 'ReadOnly', 'UseAndRetrieve', 'AccountsManager', 'Custom')]
    [string]$RoleTemplate = '',

    [Parameter(Mandatory = $false)]
    [string]$PermissionsJson
)

Set-StrictMode -Off
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Pre-compute which content parameter groups were explicitly supplied
$explicitSafe = ($UseExisting -ne '' -or -not [string]::IsNullOrEmpty($CPMName) -or
    $NumberOfDaysRetention -ne -1 -or $NumberOfVersionsRetention -ne -1 -or
    -not [string]::IsNullOrEmpty($SafeNamePattern) -or -not [string]::IsNullOrEmpty($SafeEndUserRole) -or
    -not [string]::IsNullOrEmpty($SafeEndUserRoleConfigSet) -or -not [string]::IsNullOrEmpty($SafeEndUserSearchIn) -or
    $SafeEndUserMemberType -ne '' -or -not [string]::IsNullOrEmpty($DefaultSafeMembersJson))

$explicitUser = ($AllowDuplicateAccounts -ne '' -or -not [string]::IsNullOrEmpty($AccountUserPattern) -or
    -not [string]::IsNullOrEmpty($AccountPlatform) -or -not [string]::IsNullOrEmpty($AccountAddress) -or
    $EnableAutoMgmt -ne '' -or -not [string]::IsNullOrEmpty($ManualMgmtReason) -or
    -not [string]::IsNullOrEmpty($RemoteMachineAddresses) -or $RestrictMachineAccessToList -ne '')

$explicitRole = ($RoleTemplate -ne '' -or -not [string]::IsNullOrEmpty($PermissionsJson))

# Sentinel returned by Read-Prompt when the user types '-' to delete a field
$script:CLEAR_VALUE = [char]0x0000

# Sentinel returned by Read-Prompt when the user types '-' to delete/clear a field
$script:CLEAR_VALUE = '-CLEAR-'

$script:ALL_PERMISSIONS = @(
    'useAccounts', 'retrieveAccounts', 'listAccounts', 'addAccounts',
    'updateAccountContent', 'updateAccountProperties',
    'initiateCPMAccountManagementOperations', 'specifyNextAccountContent',
    'renameAccounts', 'deleteAccounts', 'unlockAccounts',
    'manageSafe', 'manageSafeMembers', 'backupSafe',
    'viewAuditLog', 'viewSafeMembers', 'accessWithoutConfirmation',
    'createFolders', 'deleteFolders', 'moveAccountsAndFolders',
    'requestsAuthorizationLevel1', 'requestsAuthorizationLevel2'
)

#region Helper functions

function Read-Selection {
    <#
    .SYNOPSIS Shows a numbered menu and returns the chosen value. Accepts number or value typed directly.
    #>
    param(
        [Parameter(Mandatory = $true)]  [string]$Message,
        [Parameter(Mandatory = $true)]  [string[]]$Choices,
        [Parameter(Mandatory = $false)] [string[]]$Labels  = @(),
        [Parameter(Mandatory = $false)] [string]$Default  = '',
        [Parameter(Mandatory = $false)] [string]$Indent   = '    '
    )
    if ($Labels.Count -eq 0) { $Labels = $Choices }
    Write-Host ''
    Write-Host "${Indent}${Message}" -ForegroundColor DarkCyan
    $defaultIdx = ''
    for ($i = 0; $i -lt $Choices.Count; $i++) {
        $marker = if ($Choices[$i] -eq $Default) { ' *' } else { '  ' }
        Write-Host ("${Indent}  {0}){1} {2}" -f ($i + 1), $marker, $Labels[$i]) -ForegroundColor Gray
        if ($Choices[$i] -eq $Default) { $defaultIdx = [string]($i + 1) }
    }
    $validNums      = @(1..$Choices.Count | ForEach-Object { [string]$PSItem })
    $defaultDisplay = if ([string]::IsNullOrEmpty($defaultIdx)) { '' } else { " [$defaultIdx]" }
    while ($true) {
        $raw = Read-Host "${Indent}Select [1-$($Choices.Count)]${defaultDisplay}"
        $val = if ([string]::IsNullOrEmpty($raw) -and -not [string]::IsNullOrEmpty($defaultIdx)) { $defaultIdx } else { $raw.Trim() }
        if ($val -in $validNums)  { return $Choices[[int]$val - 1] }
        if ($val -in $Choices)    { return $val }
        Write-Host "${Indent}Enter a number 1-$($Choices.Count) or the value directly." -ForegroundColor Yellow
    }
}

function Read-Prompt {
    <#
    .SYNOPSIS Prompts the user with an optional default value. Returns the entered value or the default.
             Type '-' at any optional prompt to remove/clear that field from the config.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$Default = '',
        [switch]$Required,
        [string[]]$ValidValues = @()
    )
    $clearHint      = if (-not $Required) { ' (- to clear)' } else { '' }
    $displayDefault = if ([string]::IsNullOrEmpty($Default)) { '' } else { " [$Default]" }
    while ($true) {
        $raw = Read-Host "${Message}${displayDefault}${clearHint}"
        if ($raw -eq '-' -and -not $Required) { return $script:CLEAR_VALUE }
        $val = if ([string]::IsNullOrEmpty($raw) -and -not [string]::IsNullOrEmpty($Default)) { $Default } else { $raw }
        if ($Required -and [string]::IsNullOrEmpty($val)) {
            Write-Host '  Value is required — please enter a value.' -ForegroundColor Yellow
            continue
        }
        if ($ValidValues.Count -gt 0 -and -not [string]::IsNullOrEmpty($val) -and $val -notin $ValidValues) {
            Write-Host "  Valid values: $($ValidValues -join ' | ')" -ForegroundColor Yellow
            continue
        }
        return $val
    }
}

function ConvertTo-OrderedHashtable {
    <#
    .SYNOPSIS Recursively converts a PSCustomObject tree (from ConvertFrom-Json) to ordered hashtables.
    #>
    param([Parameter(Mandatory = $false)][object]$InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string] -or $InputObject -is [bool] -or
        $InputObject -is [int]    -or $InputObject -is [long] -or $InputObject -is [double]) {
        return $InputObject
    }
    if ($InputObject -is [System.Array]) {
        $arr = @()
        foreach ($item in $InputObject) { $arr += ConvertTo-OrderedHashtable -InputObject $item }
        return (, $arr)  # comma forces single array object return
    }
    if ($InputObject -is [PSCustomObject]) {
        $ht = [ordered]@{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            $ht[$prop.Name] = ConvertTo-OrderedHashtable -InputObject $prop.Value
        }
        return $ht
    }
    return $InputObject
}

function Get-RoleTemplatePermission {
    <#
    .SYNOPSIS Returns an ordered hashtable of permission booleans for the given template name.
    #>
    param([Parameter(Mandatory = $true)][string]$Template)
    $perms = [ordered]@{}
    foreach ($p in $script:ALL_PERMISSIONS) { $perms[$p] = $false }
    switch ($Template) {
        'Full' {
            foreach ($p in $script:ALL_PERMISSIONS) { $perms[$p] = $true }
        }
        'EndUser' {
            $perms.useAccounts      = $true
            $perms.retrieveAccounts = $true
            $perms.listAccounts     = $true
            $perms.viewAuditLog     = $true
            $perms.viewSafeMembers  = $true
        }
        'ReadOnly' {
            $perms.listAccounts    = $true
            $perms.viewAuditLog    = $true
            $perms.viewSafeMembers = $true
        }
        'UseAndRetrieve' {
            $perms.useAccounts      = $true
            $perms.retrieveAccounts = $true
            $perms.listAccounts     = $true
            $perms.viewAuditLog     = $true
        }
        'AccountsManager' {
            $perms.useAccounts                            = $true
            $perms.retrieveAccounts                       = $true
            $perms.listAccounts                           = $true
            $perms.addAccounts                            = $true
            $perms.updateAccountContent                   = $true
            $perms.updateAccountProperties                = $true
            $perms.initiateCPMAccountManagementOperations = $true
            $perms.renameAccounts                         = $true
            $perms.deleteAccounts                         = $true
            $perms.unlockAccounts                         = $true
            $perms.viewAuditLog                           = $true
            $perms.viewSafeMembers                        = $true
        }
    }
    return $perms
}

$script:BUILTIN_ROLES = @('ConnectOnly', 'ReadOnly', 'EndUser', 'Approver', 'AccountsManager', 'Full')

function Read-RoleSelection {
    <#
    .SYNOPSIS Displays a numbered list of built-in CyberArk safe roles and returns the chosen role name.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [string]$Default = 'EndUser'
    )
    Write-Host ''
    Write-Host '      Built-in roles:' -ForegroundColor Gray
    for ($i = 0; $i -lt $script:BUILTIN_ROLES.Count; $i++) {
        $marker = if ($script:BUILTIN_ROLES[$i] -eq $Default) { ' (default)' } else { '' }
        Write-Host ("        {0}) {1}{2}" -f ($i + 1), $script:BUILTIN_ROLES[$i], $marker) -ForegroundColor Gray
    }
    $validChoices = @(1..$script:BUILTIN_ROLES.Count | ForEach-Object { [string]$PSItem })
    $defaultIdx   = [string]($script:BUILTIN_ROLES.IndexOf($Default) + 1)
    if ($defaultIdx -eq '0') { $defaultIdx = '3' }   # fall back to EndUser (index 3)
    while ($true) {
        $raw = Read-Host "      Select role [1-$($script:BUILTIN_ROLES.Count)] [$defaultIdx]"
        $val = if ([string]::IsNullOrEmpty($raw)) { $defaultIdx } else { $raw.Trim() }
        if ($val -in $validChoices) { return $script:BUILTIN_ROLES[[int]$val - 1] }
        # also accept the role name typed directly
        if ($val -in $script:BUILTIN_ROLES) { return $val }
        Write-Host "      Enter a number 1-$($script:BUILTIN_ROLES.Count) or the role name." -ForegroundColor Yellow
    }
}

function Get-OrCreate {
    <#
    .SYNOPSIS Returns the value at $Ht[$Key], creating an empty ordered hashtable if absent.
    #>
    param([Parameter(Mandatory = $true)][System.Collections.Specialized.OrderedDictionary]$Ht, [Parameter(Mandatory = $true)][string]$Key)
    if (-not $Ht.Contains($Key) -or $null -eq $Ht[$Key]) { $Ht[$Key] = [ordered]@{} }
    return $Ht[$Key]
}

function Get-CurStr {
    <#
    .SYNOPSIS Returns $Ht[$Key] as a string, or '' if the key is absent or null.
    #>
    param([Parameter(Mandatory = $true)][System.Collections.Specialized.OrderedDictionary]$Ht, [Parameter(Mandatory = $true)][string]$Key)
    if ($Ht.Contains($Key) -and $null -ne $Ht[$Key]) { return [string]$Ht[$Key] }
    return ''
}

#endregion

#region Set operation handlers

function Invoke-SetSafeConfigSet {
    <#
    .SYNOPSIS Merges Safe config-set values into $JsonData.SafeConfigSet[$SetName].
    #>
    param(
        [Parameter(Mandatory = $true)]  [System.Collections.Specialized.OrderedDictionary]$JsonData,
        [Parameter(Mandatory = $true)]  [string]$SetName,
        [Parameter(Mandatory = $true)]  [bool]$Interactive
    )

    $scs = Get-OrCreate -Ht $JsonData -Key 'SafeConfigSet'

    # Load or create the named set with Options/Properties sub-keys
    if (-not $scs.Contains($SetName) -or $null -eq $scs[$SetName]) {
        $scs[$SetName] = [ordered]@{ Options = [ordered]@{}; Properties = [ordered]@{} }
    }
    $set   = $scs[$SetName]
    $opts  = Get-OrCreate -Ht $set -Key 'Options'
    $props = Get-OrCreate -Ht $set -Key 'Properties'

    if ($Interactive) {
        Write-Host ''
        Write-Host "  Editing SafeConfigSet '$SetName'" -ForegroundColor Cyan
        Write-Host '  (Press Enter to keep the current value shown in [brackets], empty = not set)' -ForegroundColor Gray
        Write-Host ''
        Write-Host '  OPTIONS' -ForegroundColor DarkCyan

        $curUE = Get-CurStr -Ht $opts -Key 'useExisting'
        if ([string]::IsNullOrEmpty($curUE)) { $curUE = 'true' }
        $rawUE = Read-Selection -Message 'useExisting' -Choices @('true', 'false') -Default $curUE -Indent '    '
        $opts['useExisting'] = ($rawUE -eq 'true')

        Write-Host ''
        Write-Host '  PROPERTIES' -ForegroundColor DarkCyan

        $rawCPM = Read-Prompt -Message '    CPMName' -Default (Get-CurStr -Ht $props -Key 'CPMName')
        if ($rawCPM -eq $script:CLEAR_VALUE)               { $props.Remove('CPMName') }
        elseif (-not [string]::IsNullOrEmpty($rawCPM))      { $props['CPMName'] = $rawCPM }

        # Retention type
        $retType = 'days'
        if ($props.Contains('NumberOfVersionsRetention') -and $null -ne $props['NumberOfVersionsRetention']) { $retType = 'versions' }
        elseif ($props.Contains('NumberOfDaysRetention') -and $null -ne $props['NumberOfDaysRetention']) { $retType = 'days' }
        $rawRT = Read-Selection -Message 'Retention type' `
            -Choices @('days', 'versions') `
            -Labels  @('NumberOfDaysRetention', 'NumberOfVersionsRetention') `
            -Default $retType -Indent '    '
        if ($rawRT -eq 'days') {
            $curDays = Get-CurStr -Ht $props -Key 'NumberOfDaysRetention'
            $rawDays = Read-Prompt -Message '    NumberOfDaysRetention' -Default $curDays -Required
            if ($rawDays -match '^\d+$') {
                $props['NumberOfDaysRetention'] = [int]$rawDays
                $props.Remove('NumberOfVersionsRetention')
            }
        }
        elseif ($rawRT -eq 'versions') {
            $curVer = Get-CurStr -Ht $props -Key 'NumberOfVersionsRetention'
            $rawVer = Read-Prompt -Message '    NumberOfVersionsRetention' -Default $curVer -Required
            if ($rawVer -match '^\d+$') {
                $props['NumberOfVersionsRetention'] = [int]$rawVer
                $props.Remove('NumberOfDaysRetention')
            }
        }

        $rawPat = Read-Prompt -Message '    SafeNamePattern (must contain *)' -Default (Get-CurStr -Ht $props -Key 'SafeNamePattern')
        if ($rawPat -eq $script:CLEAR_VALUE) {
            $props.Remove('SafeNamePattern')
        }
        elseif (-not [string]::IsNullOrEmpty($rawPat)) {
            if ($rawPat -notmatch '\*') { Write-Warning "SafeNamePattern '$rawPat' does not contain * — saving anyway" }
            $props['SafeNamePattern'] = $rawPat
        }

        $endType = 'named'
        if ($props.Contains('SafeEndUserRoleConfigSet') -and -not [string]::IsNullOrEmpty($props['SafeEndUserRoleConfigSet'])) { $endType = 'configset' }
        elseif ($props.Contains('SafeEndUserRole') -and -not [string]::IsNullOrEmpty($props['SafeEndUserRole'])) { $endType = 'named' }
        elseif (-not $props.Contains('SafeEndUserRole') -and -not $props.Contains('SafeEndUserRoleConfigSet')) { $endType = 'named' }
        $rawET = Read-Selection -Message 'End-user role type' `
            -Choices @('named', 'configset', 'none') `
            -Labels  @('named role (built-in)', 'RoleConfigSet (custom)', 'none (clear)') `
            -Default $endType -Indent '    '
        if ($rawET -eq 'named') {
            $curRole = Get-CurStr -Ht $props -Key 'SafeEndUserRole'
            if ([string]::IsNullOrEmpty($curRole)) { $curRole = 'EndUser' }
            $selectedRole = Read-RoleSelection -Default $curRole
            $props['SafeEndUserRole'] = $selectedRole
            $props.Remove('SafeEndUserRoleConfigSet')
        }
        elseif ($rawET -eq 'configset') {
            $rawRCS = Read-Prompt -Message '    SafeEndUserRoleConfigSet name' -Default (Get-CurStr -Ht $props -Key 'SafeEndUserRoleConfigSet')
            if ($rawRCS -eq $script:CLEAR_VALUE) {
                $props.Remove('SafeEndUserRoleConfigSet')
            }
            elseif (-not [string]::IsNullOrEmpty($rawRCS)) {
                $props['SafeEndUserRoleConfigSet'] = $rawRCS
                $props.Remove('SafeEndUserRole')
            }
        }
        elseif ($rawET -eq 'none') {
            $props.Remove('SafeEndUserRole')
            $props.Remove('SafeEndUserRoleConfigSet')
        }

        $rawSESI = Read-Prompt -Message '    SafeEndUserSearchIn (e.g. Vault or directory UUID, empty = not set)' -Default (Get-CurStr -Ht $props -Key 'SafeEndUserSearchIn')
        if ($rawSESI -eq $script:CLEAR_VALUE)              { $props.Remove('SafeEndUserSearchIn') }
        elseif (-not [string]::IsNullOrEmpty($rawSESI))    { $props['SafeEndUserSearchIn'] = $rawSESI }

        $curSEMT = Get-CurStr -Ht $props -Key 'SafeEndUserMemberType'
        if ([string]::IsNullOrEmpty($curSEMT)) { $curSEMT = 'none' }
        $rawSEMT = Read-Selection -Message 'SafeEndUserMemberType' `
            -Choices @('none', 'User', 'Group', 'Role') `
            -Labels  @('none (platform default)', 'User', 'Group', 'Role') `
            -Default $curSEMT -Indent '    '
        if ($rawSEMT -eq 'none') { $props.Remove('SafeEndUserMemberType') }
        else                     { $props['SafeEndUserMemberType'] = $rawSEMT }

        if (-not $props.Contains('DefaultSafeMembers') -or $null -eq $props['DefaultSafeMembers']) { $props['DefaultSafeMembers'] = @() }
        $mc = $null
        while ($null -eq $mc -or $mc -eq 'l' -or $mc -eq 'ld') {
            $curMemberCount = @($props['DefaultSafeMembers']).Count
            Write-Host ''
            Write-Host "    DefaultSafeMembers: $curMemberCount member(s) currently defined" -ForegroundColor Gray
            if ($mc -eq 'l' -or $mc -eq 'ld') {
                if ($curMemberCount -eq 0) {
                    Write-Host '      (none)' -ForegroundColor Gray
                }
                else {
                    $idx = 1
                    foreach ($mem in @($props['DefaultSafeMembers'])) {
                        $searchIn = if ($mem.Contains('SearchIn')) { $mem['SearchIn'] } else { '?' }
                        if ($mem.Contains('Role')) {
                            $roleInfo = "Role=$($mem['Role'])"
                        }
                        elseif ($mem.Contains('RoleConfigSet')) {
                            $roleInfo = "RoleConfigSet=$($mem['RoleConfigSet'])"
                        }
                        else {
                            $roleInfo = 'Permissions=<inline>'
                        }
                        Write-Host ("      [$idx] $($mem['Name']) | SearchIn=$searchIn | $roleInfo") -ForegroundColor Cyan

                        if ($mc -eq 'ld') {
                            # Resolve the effective permissions for this member
                            $effPerms = $null
                            if ($mem.Contains('Role')) {
                                $effPerms = Get-RoleTemplatePermission -Template $mem['Role']
                            }
                            elseif ($mem.Contains('RoleConfigSet')) {
                                $rcsName = $mem['RoleConfigSet']
                                if ($jsonData.Contains('RoleConfigSet') -and $null -ne $jsonData['RoleConfigSet'] -and $jsonData['RoleConfigSet'].Contains($rcsName)) {
                                    $effPerms = $jsonData['RoleConfigSet'][$rcsName]
                                }
                                else {
                                    Write-Host "          (RoleConfigSet '$rcsName' not found in this file)" -ForegroundColor Yellow
                                }
                            }
                            elseif ($mem.Contains('Permissions')) {
                                $effPerms = $mem['Permissions']
                            }

                            if ($null -ne $effPerms) {
                                $truePerms = @($effPerms.Keys | Where-Object { $effPerms[$PSItem] -eq $true })
                                if ($truePerms.Count -eq 0) {
                                    Write-Host '          (no permissions granted)' -ForegroundColor DarkGray
                                }
                                else {
                                    Write-Host ("          Granted: $($truePerms -join ', ')") -ForegroundColor DarkCyan
                                }
                            }
                        }
                        $idx++
                    }
                }
            }
            $mc = Read-Selection -Message 'DefaultSafeMembers action' `
                -Choices @('l', 'ld', 'k', 'r', 'a', 'c') `
                -Labels  @('list members (summary)', 'list members (expanded permissions)', 'keep existing', 'replace — paste JSON array', 'add member(s) interactively', 'clear all') `
                -Default 'l' -Indent '    '
        }
        if ($mc -eq 'r') {
            $rawJson = Read-Prompt -Message '    Paste JSON array (e.g. [{"Name":"Grp","Role":"Full","SearchIn":"Vault"}])'
            if (-not [string]::IsNullOrEmpty($rawJson)) {
                try {
                    $props['DefaultSafeMembers'] = ConvertTo-OrderedHashtable -InputObject ($rawJson | ConvertFrom-Json)
                }
                catch { Write-Warning "Invalid JSON — DefaultSafeMembers unchanged: $($_.Exception.Message)" }
            }
        }
        elseif ($mc -eq 'a') {
            $addMore = $true
            while ($addMore) {
                $m             = [ordered]@{}
                $m['Name']     = Read-Prompt -Message '      Member Name' -Required
                $m['SearchIn'] = Read-Prompt -Message '      SearchIn (Vault/LDAP/directory UUID)' -Default 'Vault'
                $rawMT = Read-Selection -Message 'MemberType' `
                    -Choices @('none', 'User', 'Group', 'Role') `
                    -Labels  @('none (platform default)', 'User', 'Group', 'Role') `
                    -Default 'none' -Indent '      '
                if ($rawMT -ne 'none') { $m['MemberType'] = $rawMT }
                $rt = Read-Selection -Message 'Permission type' `
                    -Choices @('role', 'configset', 'inline') `
                    -Labels  @('built-in named role', 'RoleConfigSet (custom)', 'inline JSON permissions object') `
                    -Default 'role' -Indent '      '
                if ($rt -eq 'role') {
                    $m['Role'] = Read-RoleSelection -Default 'EndUser'
                }
                elseif ($rt -eq 'configset') {
                    $m['RoleConfigSet'] = Read-Prompt -Message '      RoleConfigSet name' -Required
                }
                else {
                    $rawIP = Read-Prompt -Message '      Paste Permissions JSON object'
                    if (-not [string]::IsNullOrEmpty($rawIP)) {
                        try { $m['Permissions'] = ConvertTo-OrderedHashtable -InputObject ($rawIP | ConvertFrom-Json) }
                        catch { Write-Warning "Invalid JSON — empty Permissions used: $($_.Exception.Message)"; $m['Permissions'] = [ordered]@{} }
                    }
                }
                $props['DefaultSafeMembers'] = @($props['DefaultSafeMembers']) + @($m)
                Write-Host "      Added '$($m['Name'])'. Total: $(@($props['DefaultSafeMembers']).Count) member(s)." -ForegroundColor Gray
                $another = Read-Selection -Message 'Add another member?' `
                    -Choices @('n', 'y') -Labels @('no — done', 'yes — add another') `
                    -Default 'n' -Indent '      '
                $addMore = ($another -eq 'y')
            }
        }
        elseif ($mc -eq 'c') {
            $props['DefaultSafeMembers'] = @()
        }
    }
    else {
        # Non-interactive: apply only params that carry a non-sentinel value
        if ($UseExisting -ne '') { $opts['useExisting'] = ($UseExisting -eq 'true') }
        if (-not [string]::IsNullOrEmpty($CPMName)) { $props['CPMName'] = $CPMName }
        if ($NumberOfDaysRetention -ne -1) {
            $props['NumberOfDaysRetention'] = $NumberOfDaysRetention
            $props.Remove('NumberOfVersionsRetention')
        }
        if ($NumberOfVersionsRetention -ne -1) {
            $props['NumberOfVersionsRetention'] = $NumberOfVersionsRetention
            $props.Remove('NumberOfDaysRetention')
        }
        if (-not [string]::IsNullOrEmpty($SafeNamePattern)) {
            if ($SafeNamePattern -notmatch '\*') { Write-Warning "SafeNamePattern '$SafeNamePattern' does not contain *" }
            $props['SafeNamePattern'] = $SafeNamePattern
        }
        if (-not [string]::IsNullOrEmpty($SafeEndUserRoleConfigSet)) {
            $props['SafeEndUserRoleConfigSet'] = $SafeEndUserRoleConfigSet
            $props.Remove('SafeEndUserRole')
        }
        elseif (-not [string]::IsNullOrEmpty($SafeEndUserRole)) {
            $props['SafeEndUserRole'] = $SafeEndUserRole
            $props.Remove('SafeEndUserRoleConfigSet')
        }
        if (-not [string]::IsNullOrEmpty($SafeEndUserSearchIn)) { $props['SafeEndUserSearchIn'] = $SafeEndUserSearchIn }
        if ($SafeEndUserMemberType -ne '')                        { $props['SafeEndUserMemberType'] = $SafeEndUserMemberType }
        if (-not [string]::IsNullOrEmpty($DefaultSafeMembersJson)) {
            try {
                $props['DefaultSafeMembers'] = ConvertTo-OrderedHashtable -InputObject ($DefaultSafeMembersJson | ConvertFrom-Json)
            }
            catch { Write-Warning "Invalid DefaultSafeMembersJson — ignored: $($_.Exception.Message)" }
        }
    }
    # Ensure Options comes before Properties in the output
    $scs[$SetName] = [ordered]@{ Options = $opts; Properties = $props }
}

function Invoke-SetUserConfigSet {
    <#
    .SYNOPSIS Merges User config-set values into $JsonData.UserConfigSet[$SetName].
    #>
    param(
        [Parameter(Mandatory = $true)] [System.Collections.Specialized.OrderedDictionary]$JsonData,
        [Parameter(Mandatory = $true)] [string]$SetName,
        [Parameter(Mandatory = $true)] [bool]$Interactive
    )

    $ucs = Get-OrCreate -Ht $JsonData -Key 'UserConfigSet'
    if (-not $ucs.Contains($SetName) -or $null -eq $ucs[$SetName]) {
        $ucs[$SetName] = [ordered]@{ Options = [ordered]@{}; Properties = [ordered]@{} }
    }
    $set   = $ucs[$SetName]
    $opts  = Get-OrCreate -Ht $set -Key 'Options'
    $props = Get-OrCreate -Ht $set -Key 'Properties'

    if ($Interactive) {
        Write-Host ''
        Write-Host "  Editing UserConfigSet '$SetName'" -ForegroundColor Cyan
        Write-Host '  (Press Enter to keep the current value shown in [brackets], empty = not set)' -ForegroundColor Gray
        Write-Host ''
        Write-Host '  OPTIONS' -ForegroundColor DarkCyan

        $rawPat = Read-Prompt -Message '    accountUserPattern (e.g. *_adm)' -Default (Get-CurStr -Ht $opts -Key 'accountUserPattern')
        if ($rawPat -eq $script:CLEAR_VALUE)            { $opts.Remove('accountUserPattern') }
        elseif (-not [string]::IsNullOrEmpty($rawPat)) { $opts['accountUserPattern'] = $rawPat }

        $curDup = Get-CurStr -Ht $opts -Key 'allowDuplicateAccounts'
        if ([string]::IsNullOrEmpty($curDup)) { $curDup = 'false' }
        $rawDup = Read-Selection -Message 'allowDuplicateAccounts' -Choices @('false', 'true') -Default $curDup -Indent '    '
        $opts['allowDuplicateAccounts'] = ($rawDup -eq 'true')

        Write-Host ''
        Write-Host '  PROPERTIES' -ForegroundColor DarkCyan

        $rawPlat = Read-Prompt -Message '    accountPlatform (e.g. WinDomain)' -Default (Get-CurStr -Ht $props -Key 'accountPlatform')
        if ($rawPlat -eq $script:CLEAR_VALUE)             { $props.Remove('accountPlatform') }
        elseif (-not [string]::IsNullOrEmpty($rawPlat))   { $props['accountPlatform'] = $rawPlat }

        $rawAddr = Read-Prompt -Message '    accountAddress (e.g. corp.example.com)' -Default (Get-CurStr -Ht $props -Key 'accountAddress')
        if ($rawAddr -eq $script:CLEAR_VALUE)             { $props.Remove('accountAddress') }
        elseif (-not [string]::IsNullOrEmpty($rawAddr))   { $props['accountAddress'] = $rawAddr }

        $curAM = Get-CurStr -Ht $props -Key 'enableAutoMgmt'
        if ([string]::IsNullOrEmpty($curAM)) { $curAM = 'yes' }
        $rawAM = Read-Selection -Message 'enableAutoMgmt' -Choices @('yes', 'no') -Default $curAM -Indent '    '
        $props['enableAutoMgmt'] = $rawAM

        if ($props.Contains('enableAutoMgmt') -and $props['enableAutoMgmt'] -eq 'no') {
            $rawReason = Read-Prompt -Message '    manualMgmtReason' -Default (Get-CurStr -Ht $props -Key 'manualMgmtReason')
            if ($rawReason -eq $script:CLEAR_VALUE)            { $props.Remove('manualMgmtReason') }
            elseif (-not [string]::IsNullOrEmpty($rawReason))  { $props['manualMgmtReason'] = $rawReason }
        }

        $rawRMA = Read-Prompt -Message '    remoteMachineAddresses (optional, semicolon-separated)' -Default (Get-CurStr -Ht $props -Key 'remoteMachineAddresses')
        if ($rawRMA -eq $script:CLEAR_VALUE) {
            $props.Remove('remoteMachineAddresses')
            $props.Remove('restrictMachineAccessToList')
        }
        elseif (-not [string]::IsNullOrEmpty($rawRMA)) {
            $props['remoteMachineAddresses'] = $rawRMA
            $curRL  = Get-CurStr -Ht $props -Key 'restrictMachineAccessToList'
            if ([string]::IsNullOrEmpty($curRL)) { $curRL = 'yes' }
            $rawRL  = Read-Selection -Message 'restrictMachineAccessToList' -Choices @('yes', 'no') -Default $curRL -Indent '    '
            $props['restrictMachineAccessToList'] = $rawRL
        }
    }
    else {
        if (-not [string]::IsNullOrEmpty($AccountUserPattern))       { $opts['accountUserPattern']    = $AccountUserPattern }
        if ($AllowDuplicateAccounts -ne '')                           { $opts['allowDuplicateAccounts'] = ($AllowDuplicateAccounts -eq 'true') }
        if (-not [string]::IsNullOrEmpty($AccountPlatform))          { $props['accountPlatform']      = $AccountPlatform }
        if (-not [string]::IsNullOrEmpty($AccountAddress))           { $props['accountAddress']       = $AccountAddress }
        if ($EnableAutoMgmt -ne '')                                   { $props['enableAutoMgmt']       = $EnableAutoMgmt }
        if (-not [string]::IsNullOrEmpty($ManualMgmtReason))         { $props['manualMgmtReason']     = $ManualMgmtReason }
        if (-not [string]::IsNullOrEmpty($RemoteMachineAddresses))   { $props['remoteMachineAddresses'] = $RemoteMachineAddresses }
        if ($RestrictMachineAccessToList -ne '')                      { $props['restrictMachineAccessToList'] = $RestrictMachineAccessToList }
    }
    $ucs[$SetName] = [ordered]@{ Options = $opts; Properties = $props }
}

function Invoke-SetRoleConfigSet {
    <#
    .SYNOPSIS Merges Role config-set permissions into $JsonData.RoleConfigSet[$SetName].
    #>
    param(
        [Parameter(Mandatory = $true)] [System.Collections.Specialized.OrderedDictionary]$JsonData,
        [Parameter(Mandatory = $true)] [string]$SetName,
        [Parameter(Mandatory = $true)] [bool]$Interactive
    )

    $rcs = Get-OrCreate -Ht $JsonData -Key 'RoleConfigSet'

    # Load existing permissions or start all-false
    $perms = [ordered]@{}
    foreach ($p in $script:ALL_PERMISSIONS) { $perms[$p] = $false }
    if ($rcs.Contains($SetName) -and $rcs[$SetName] -is [System.Collections.Specialized.OrderedDictionary]) {
        foreach ($p in $script:ALL_PERMISSIONS) {
            if ($rcs[$SetName].Contains($p)) { $perms[$p] = [bool]$rcs[$SetName][$p] }
        }
    }

    if ($Interactive) {
        Write-Host ''
        Write-Host "  Editing RoleConfigSet '$SetName'" -ForegroundColor Cyan
        Write-Host ''
        $tplChoices = @('keep', 'EndUser', 'ReadOnly', 'UseAndRetrieve', 'AccountsManager', 'Full', 'Custom')
        $tplLabels  = @('keep current permissions', 'EndUser', 'ReadOnly', 'UseAndRetrieve', 'AccountsManager', 'Full', 'Custom (all false)')
        $tpl = Read-Selection -Message 'Start from template' -Choices $tplChoices -Labels $tplLabels -Default 'keep' -Indent '  '
        if ($tpl -ne 'keep' -and $tpl -ne 'Custom') {
            $tplPerms = Get-RoleTemplatePermission -Template $tpl
            foreach ($p in $script:ALL_PERMISSIONS) { $perms[$p] = $tplPerms[$p] }
            Write-Host "  Template '$tpl' applied." -ForegroundColor Gray
        }
        elseif ($tpl -eq 'Custom') {
            foreach ($p in $script:ALL_PERMISSIONS) { $perms[$p] = $false }
            Write-Host '  Starting from all-false.' -ForegroundColor Gray
        }

        Write-Host ''
        Write-Host '  Modify individual permissions (y=true, n=false, Enter=keep):' -ForegroundColor DarkCyan
        foreach ($p in $script:ALL_PERMISSIONS) {
            $cur = if ($perms[$p]) { 'y' } else { 'n' }
            $raw = Read-Prompt -Message "    $p" -Default $cur -ValidValues @('', 'y', 'n')
            if (-not [string]::IsNullOrEmpty($raw)) { $perms[$p] = ($raw -eq 'y') }
        }
    }
    else {
        if (-not [string]::IsNullOrEmpty($RoleTemplate) -and $RoleTemplate -ne 'Custom') {
            $tplPerms = Get-RoleTemplatePermission -Template $RoleTemplate
            foreach ($p in $script:ALL_PERMISSIONS) { $perms[$p] = $tplPerms[$p] }
        }
        elseif ($RoleTemplate -eq 'Custom') {
            foreach ($p in $script:ALL_PERMISSIONS) { $perms[$p] = $false }
        }
        if (-not [string]::IsNullOrEmpty($PermissionsJson)) {
            try {
                $overrides = $PermissionsJson | ConvertFrom-Json
                foreach ($prop in $overrides.PSObject.Properties) {
                    if ($prop.Name -in $script:ALL_PERMISSIONS) { $perms[$prop.Name] = [bool]$prop.Value }
                }
            }
            catch { Write-Warning "Invalid PermissionsJson — ignored: $($_.Exception.Message)" }
        }
    }
    $rcs[$SetName] = $perms
}

#endregion

#region Validate operation

function Invoke-ValidateConfig {
    <#
    .SYNOPSIS Validates the loaded JSON data and reports errors and warnings.
    #>
    param(
        [Parameter(Mandatory = $true)] [System.Collections.Specialized.OrderedDictionary]$JsonData,
        [Parameter(Mandatory = $true)] [string]$FilePath
    )
    $errors   = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()

    foreach ($key in $JsonData.Keys) {
        if ($key -notin @('SafeConfigSet', 'UserConfigSet', 'RoleConfigSet')) {
            $warnings.Add("Unknown top-level key: '$key'")
        }
    }

    if ($JsonData.Contains('SafeConfigSet') -and $null -ne $JsonData['SafeConfigSet']) {
        foreach ($name in $JsonData['SafeConfigSet'].Keys) {
            $set = $JsonData['SafeConfigSet'][$name]
            if (-not ($set -is [System.Collections.Specialized.OrderedDictionary] -or $set -is [hashtable])) {
                $errors.Add("SafeConfigSet.$name is not an object"); continue
            }
            if (-not $set.Contains('Options'))    { $warnings.Add("SafeConfigSet.$name is missing 'Options' sub-key") }
            if (-not $set.Contains('Properties')) { $warnings.Add("SafeConfigSet.$name is missing 'Properties' sub-key") }
            $props = if ($set.Contains('Properties') -and $null -ne $set['Properties']) { $set['Properties'] } else { [ordered]@{} }
            if ($props.Contains('SafeNamePattern') -and $props['SafeNamePattern'] -notmatch '\*') {
                $warnings.Add("SafeConfigSet.$name.Properties.SafeNamePattern '$($props['SafeNamePattern'])' does not contain *")
            }
            $hasDays = $props.Contains('NumberOfDaysRetention') -and $null -ne $props['NumberOfDaysRetention']
            $hasVer  = $props.Contains('NumberOfVersionsRetention') -and $null -ne $props['NumberOfVersionsRetention']
            if ($hasDays -and $hasVer) { $warnings.Add("SafeConfigSet.$name.Properties has both NumberOfDaysRetention and NumberOfVersionsRetention set") }
            if ($props.Contains('SafeEndUserRole') -and $props.Contains('SafeEndUserRoleConfigSet') -and
                -not [string]::IsNullOrEmpty($props['SafeEndUserRole']) -and -not [string]::IsNullOrEmpty($props['SafeEndUserRoleConfigSet'])) {
                $warnings.Add("SafeConfigSet.$name.Properties has both SafeEndUserRole and SafeEndUserRoleConfigSet set")
            }
            if ($props.Contains('DefaultSafeMembers') -and $null -ne $props['DefaultSafeMembers']) {
                $i = 0
                foreach ($member in @($props['DefaultSafeMembers'])) {
                    if ([string]::IsNullOrEmpty($member['Name'])) { $errors.Add("SafeConfigSet.$name.Properties.DefaultSafeMembers[$i] missing 'Name'") }
                    $hasRole  = -not [string]::IsNullOrEmpty($member['Role'])
                    $hasRCS   = -not [string]::IsNullOrEmpty($member['RoleConfigSet'])
                    $hasPerms = $null -ne $member['Permissions']
                    if (-not $hasRole -and -not $hasRCS -and -not $hasPerms) {
                        $warnings.Add("SafeConfigSet.$name.Properties.DefaultSafeMembers[$i] ($($member['Name'])) has no Role, RoleConfigSet, or Permissions")
                    }
                    if ($member.Contains('MemberType') -and -not [string]::IsNullOrEmpty($member['MemberType']) -and
                        $member['MemberType'] -notin @('User', 'Group', 'Role')) {
                        $warnings.Add("SafeConfigSet.$name.Properties.DefaultSafeMembers[$i] ($($member['Name'])) has invalid MemberType '$($member['MemberType'])' — expected User, Group, or Role")
                    }
                    $i++
                }
            }
            if ($props.Contains('SafeEndUserMemberType') -and -not [string]::IsNullOrEmpty($props['SafeEndUserMemberType']) -and
                $props['SafeEndUserMemberType'] -notin @('User', 'Group', 'Role')) {
                $warnings.Add("SafeConfigSet.$name.Properties.SafeEndUserMemberType '$($props['SafeEndUserMemberType'])' is not a valid value — expected User, Group, or Role")
            }
        }
    }

    if ($JsonData.Contains('UserConfigSet') -and $null -ne $JsonData['UserConfigSet']) {
        foreach ($name in $JsonData['UserConfigSet'].Keys) {
            $set = $JsonData['UserConfigSet'][$name]
            if (-not ($set -is [System.Collections.Specialized.OrderedDictionary] -or $set -is [hashtable])) {
                $errors.Add("UserConfigSet.$name is not an object"); continue
            }
            if (-not $set.Contains('Options'))    { $warnings.Add("UserConfigSet.$name is missing 'Options' sub-key") }
            if (-not $set.Contains('Properties')) { $warnings.Add("UserConfigSet.$name is missing 'Properties' sub-key") }
        }
    }

    if ($JsonData.Contains('RoleConfigSet') -and $null -ne $JsonData['RoleConfigSet']) {
        foreach ($name in $JsonData['RoleConfigSet'].Keys) {
            $set = $JsonData['RoleConfigSet'][$name]
            if ($set -is [System.Collections.Specialized.OrderedDictionary] -or $set -is [hashtable]) {
                if ($set.Contains('Options') -or $set.Contains('Properties')) {
                    $warnings.Add("RoleConfigSet.$name should be flat (no Options/Properties sub-keys)")
                }
                foreach ($k in $set.Keys) {
                    if ($k -notin $script:ALL_PERMISSIONS) { $warnings.Add("RoleConfigSet.$name has unknown permission key '$k'") }
                }
            }
            else { $errors.Add("RoleConfigSet.$name is not an object") }
        }
    }

    Write-Host ''
    Write-Host ('─' * 60) -ForegroundColor Cyan
    Write-Host "  Validation: $FilePath" -ForegroundColor Cyan
    Write-Host ('─' * 60) -ForegroundColor Cyan
    if ($errors.Count -eq 0 -and $warnings.Count -eq 0) {
        Write-Host '  No errors or warnings found.' -ForegroundColor Green
    }
    if ($errors.Count -gt 0) {
        Write-Host "  ERRORS ($($errors.Count)):" -ForegroundColor Red
        foreach ($e in $errors) { Write-Host "    [ERROR] $e" -ForegroundColor Red }
    }
    if ($warnings.Count -gt 0) {
        Write-Host "  WARNINGS ($($warnings.Count)):" -ForegroundColor Yellow
        foreach ($w in $warnings) { Write-Host "    [WARN]  $w" -ForegroundColor Yellow }
    }
    Write-Host ('─' * 60) -ForegroundColor Cyan
    Write-Host ''
    return ($errors.Count -eq 0)
}

#endregion

#region Main entry point

# ── Resolve FilePath ──────────────────────────────────────────────────────────
if ([string]::IsNullOrEmpty($FilePath)) {
    $FilePath = Read-Prompt -Message 'Config file path' -Required
}

# ── Resolve Operation ─────────────────────────────────────────────────────────
if ([string]::IsNullOrEmpty($Operation)) {
        $Operation = Read-Selection -Message 'Operation' `
            -Choices @('Create', 'Set', 'Remove', 'Validate') `
            -Labels  @('Create  — new JSON config file from scratch',
                       'Set     — add or update a named config set',
                       'Remove  — delete a named config set',
                       'Validate — check schema and report errors') `
            -Default 'Set' -Indent '  '
    }

# ── Load existing JSON ────────────────────────────────────────────────────────
$jsonData = [ordered]@{
    SafeConfigSet = [ordered]@{}
    UserConfigSet = [ordered]@{}
    RoleConfigSet = [ordered]@{}
}
$fileExists = Test-Path -Path $FilePath -PathType Leaf

if ($fileExists -and $Operation -ne 'Create') {
    try {
        $loaded = Get-Content -Path $FilePath -Raw -ErrorAction Stop | ConvertFrom-Json
        $converted = ConvertTo-OrderedHashtable -InputObject $loaded
        if ($null -ne $converted) {
            $jsonData = $converted
            if (-not $jsonData.Contains('SafeConfigSet')) { $jsonData['SafeConfigSet'] = [ordered]@{} }
            if (-not $jsonData.Contains('UserConfigSet')) { $jsonData['UserConfigSet'] = [ordered]@{} }
            if (-not $jsonData.Contains('RoleConfigSet')) { $jsonData['RoleConfigSet'] = [ordered]@{} }
        }
    }
    catch {
        Write-Output "ERROR: Failed to load '$FilePath': $($_.Exception.Message)"
        exit 1
    }

    if ($Operation -eq 'Set' -or $Operation -eq 'Remove') {
        $doBackup = Read-Selection -Message 'Back up current file before making changes?' `
            -Choices @('y', 'n') `
            -Labels  @('yes — save a dated backup copy', 'no  — skip backup') `
            -Default 'y' -Indent '  '
        if ($doBackup -eq 'y') {
            $fileItem   = Get-Item -Path $FilePath
            $stamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
            $backupName = "$($fileItem.BaseName)_$stamp$($fileItem.Extension)"
            $backupPath = Join-Path -Path $fileItem.DirectoryName -ChildPath $backupName
            Copy-Item -Path $FilePath -Destination $backupPath -ErrorAction Stop
            Write-Host "  Backup saved: $backupPath" -ForegroundColor Gray
        }
    }
}
elseif ($fileExists -and $Operation -eq 'Create') {
    $overwrite = Read-Prompt -Message "File '$FilePath' already exists. Overwrite? (y/N)" -Default 'n' -ValidValues @('y', 'n')
    if ($overwrite -ne 'y') { Write-Output 'Aborted.'; exit 0 }
}
elseif (-not $fileExists -and $Operation -notin @('Create', 'Set')) {
    Write-Output "ERROR: File not found: $FilePath"
    exit 1
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
switch ($Operation) {

    'Create' {
        Write-Host ''
        Write-Host ('─' * 60) -ForegroundColor Cyan
        Write-Host '  Creating new config file' -ForegroundColor Cyan
        Write-Host ('─' * 60) -ForegroundColor Cyan

        $addSafe = Read-Prompt -Message '  Add a default SafeConfigSet? (Y/n)' -Default 'y' -ValidValues @('y', 'n')
        if ($addSafe -eq 'y') {
            Invoke-SetSafeConfigSet -JsonData $jsonData -SetName 'default' -Interactive $true
        }
        $addUser = Read-Prompt -Message '  Add a default UserConfigSet? (Y/n)' -Default 'y' -ValidValues @('y', 'n')
        if ($addUser -eq 'y') {
            Invoke-SetUserConfigSet -JsonData $jsonData -SetName 'default' -Interactive $true
        }
    }

    'Set' {
        if ([string]::IsNullOrEmpty($ConfigSetType)) {
            $ConfigSetType = Read-Selection -Message 'ConfigSetType' `
                -Choices @('SafeConfigSet', 'UserConfigSet', 'RoleConfigSet') `
                -Labels  @('SafeConfigSet — safe creation and membership defaults',
                           'UserConfigSet — account field and behaviour defaults',
                           'RoleConfigSet — custom permission set') `
                -Default 'SafeConfigSet' -Indent '  '
        }
        if ([string]::IsNullOrEmpty($SetName)) {
            Write-Host ''
            $existingSection = if ($jsonData.Contains($ConfigSetType) -and $null -ne $jsonData[$ConfigSetType]) { $jsonData[$ConfigSetType] } else { $null }
            if ($null -ne $existingSection -and $existingSection.Count -gt 0) {
                Write-Host "  Existing $ConfigSetType sets: $($existingSection.Keys -join ', ')" -ForegroundColor Gray
            }
            $SetName = Read-Prompt -Message "Set name (e.g. 'default', 'prod')" -Default 'default' -Required
        }

        $needsInteractive = switch ($ConfigSetType) {
            'SafeConfigSet' { -not $explicitSafe }
            'UserConfigSet' { -not $explicitUser }
            'RoleConfigSet' { -not $explicitRole }
            default         { $true }
        }

        switch ($ConfigSetType) {
            'SafeConfigSet' { Invoke-SetSafeConfigSet -JsonData $jsonData -SetName $SetName -Interactive $needsInteractive }
            'UserConfigSet' { Invoke-SetUserConfigSet -JsonData $jsonData -SetName $SetName -Interactive $needsInteractive }
            'RoleConfigSet' { Invoke-SetRoleConfigSet -JsonData $jsonData -SetName $SetName -Interactive $needsInteractive }
        }
    }

    'Remove' {
        if ([string]::IsNullOrEmpty($ConfigSetType)) {
            $ConfigSetType = Read-Selection -Message 'ConfigSetType' `
                -Choices @('SafeConfigSet', 'UserConfigSet', 'RoleConfigSet') `
                -Labels  @('SafeConfigSet — safe creation and membership defaults',
                           'UserConfigSet — account field and behaviour defaults',
                           'RoleConfigSet — custom permission set') `
                -Default 'SafeConfigSet' -Indent '  '
        }
        if ([string]::IsNullOrEmpty($SetName)) {
            Write-Host ''
            $existingSection = if ($jsonData.Contains($ConfigSetType) -and $null -ne $jsonData[$ConfigSetType]) { $jsonData[$ConfigSetType] } else { $null }
            if ($null -ne $existingSection -and $existingSection.Count -gt 0) {
                Write-Host "  Existing $ConfigSetType sets: $($existingSection.Keys -join ', ')" -ForegroundColor Gray
            }
            $SetName = Read-Prompt -Message '  Set name to remove' -Required
        }
        if ($jsonData.Contains($ConfigSetType) -and
            $null -ne $jsonData[$ConfigSetType] -and
            $jsonData[$ConfigSetType].Contains($SetName)) {
            $jsonData[$ConfigSetType].Remove($SetName)
            Write-Output "Removed $ConfigSetType.$SetName"
        }
        else {
            Write-Warning "$ConfigSetType.$SetName not found in '$FilePath'"
            exit 0
        }
    }

    'Validate' {
        $valid = Invoke-ValidateConfig -JsonData $jsonData -FilePath $FilePath
        exit $(if ($valid) { 0 } else { 1 })
    }
}

# ── Preview and save ──────────────────────────────────────────────────────────
$outputJson = $jsonData | ConvertTo-Json -Depth 10

Write-Host ''
Write-Host '  Preview (first 40 lines):' -ForegroundColor Gray
$lines     = $outputJson -split "`n"
$showCount = [Math]::Min(40, $lines.Count)
for ($i = 0; $i -lt $showCount; $i++) { Write-Host "  $($lines[$i])" -ForegroundColor DarkGray }
if ($lines.Count -gt 40) { Write-Host "  ... ($($lines.Count - 40) more lines — use Validate to check the full file)" -ForegroundColor DarkGray }
Write-Host ''

if ($PSCmdlet.ShouldProcess($FilePath, 'Write config file')) {
    $parentDir = Split-Path -Parent $FilePath
    if (-not [string]::IsNullOrEmpty($parentDir) -and -not (Test-Path -Path $parentDir)) {
        $null = New-Item -ItemType Directory -Path $parentDir -Force
    }
    $outputJson | Out-File -FilePath $FilePath -Encoding utf8 -Force
    Write-Output "Saved: $FilePath"
}

#endregion
