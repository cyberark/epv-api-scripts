<###########################################################################
NAME: Get Safe Report

AUTHOR: Brian Bors

COMMENT:
Reports on CyberArk safes and/or safe members using REST API directly.
No external module dependencies.

Modes (default is safe inventory):
  (default)                       : safeName, description, managingCPM, retention
  -AllSafeDetails                 : All safe API fields
  -IncludeMembers                 : Member rows with basic safe context + permissions
  -IncludeMembers -AllSafeDetails : Member rows with all safe fields + permissions
  -MembersOnly                    : Member rows only (cleanest Safe-Management.ps1 format)

-IncludeMembers and -MembersOnly are both Safe-Management.ps1 compatible.
  -ReportPath     : CSV file path (omit to write to pipeline)
  -EPVFormat       : Output EPV-API-Common format instead of Safe-Management.ps1 format
                     Safe mode   : Import-Safe  | New-Safe / Set-Safe
                     Member modes: Import-SafeMember | Add-SafeMember

Authentication:
  -logonToken    : Pre-existing token (Privilege Cloud or any pre-authenticated session)
  (omit)         : Self-hosted PVWA - credentials prompted or supplied via -PVWACredentials

SUPPORTED VERSIONS:
CyberArk PVWA v12.1 and above
CyberArk Privilege Cloud

VERSION HISTORY:
2.0.0   2026-07-22  Removed PSPAS dependency; raw REST implementation
                    Dual output format (Safe-Management and EPV-API-Common)
########################################################################### #>
[CmdletBinding()]
param
(
    #region Authentication
    [Parameter(Mandatory = $true, HelpMessage = 'Enter PVWA URL (e.g. https://pvwa.domain.com/PasswordVault or https://subdomain.privilegecloud.cyberark.cloud/PasswordVault)')]
    [Alias('PCloudURL')]
    [String]$PVWAURL,

    # For Privilege Cloud, supply the token from Get-IdentityHeader or New-Session.
    # Omit for self-hosted PVWA (credentials will be used instead).
    [Parameter(Mandatory = $false)]
    $logonToken,

    [Parameter(Mandatory = $false, HelpMessage = 'PVWA credentials for self-hosted authentication')]
    [PSCredential]$PVWACredentials,

    [Parameter(Mandatory = $false, HelpMessage = 'Authentication type for self-hosted PVWA')]
    [ValidateSet('CyberArk', 'LDAP', 'RADIUS')]
    [String]$PVWAAuthType = 'CyberArk',
    #endregion

    #region Mode
    # Add all safe API fields to safe inventory or member rows
    [Parameter(Mandatory = $false)]
    [Switch]$AllSafeDetails,

    # Member rows with safe context columns (Safe-Management.ps1 compatible, extra columns ignored)
    [Parameter(Mandatory = $false)]
    [Switch]$IncludeMembers,

    # Member rows only - minimal safe context, cleanest Safe-Management.ps1 format
    [Parameter(Mandatory = $false)]
    [Switch]$MembersOnly,
    #endregion

    #region Output paths
    # Safe-Management.ps1 compatible CSV - omit to pipe objects to the pipeline instead
    [Parameter(Mandatory = $false)]
    [ValidatePattern('^\.csv$|.*\.csv$')]
    [Alias('Report')]
    [String]$ReportPath,

    # Switch to EPV-API-Common output format instead of Safe-Management.ps1 format
    # Safe mode   : Import-Safe  | New-Safe / Set-Safe
    # Member modes: Import-SafeMember | Add-SafeMember
    [Parameter(Mandatory = $false)]
    [Switch]$EPVFormat,
    #endregion

    #region Filtering
    # One or more safe names to target. Omit to report on all safes.
    [Parameter(Mandatory = $false)]
    [string[]]$SafeName,

    [Parameter(Mandatory = $false)]
    [array]$UserTypes = @('EPVUser', 'BasicUser'),

    [Parameter(Mandatory = $false)]
    [Switch]$ExcludeUsers,

    [Parameter(Mandatory = $false)]
    [Switch]$IncludeGroups,

    [Parameter(Mandatory = $false)]
    [Switch]$IncludeApps,

    [Parameter(Mandatory = $false)]
    [Switch]$IncludePredefinedUsers,

    # Suppress all permission columns
    [Parameter(Mandatory = $false)]
    [Switch]$HidePerms,

    # Include only these specific permission columns
    [Parameter(Mandatory = $false)]
    $PermList
    #endregion
)

#region Setup
$script:DoLogoff = $false
$script:LastHttpError = $null

if ($PVWAURL.EndsWith('/')) {
    $PVWAURL = $PVWAURL.TrimEnd('/')
}

$URL_PVWAAPI = "$PVWAURL/api"
$URL_Logon = "${URL_PVWAAPI}/auth/$PVWAAuthType/Logon"
$URL_Logoff = "${URL_PVWAAPI}/Auth/Logoff"
$URL_Safes = "${URL_PVWAAPI}/Safes"
$URL_Users = "${URL_PVWAAPI}/Users"
Write-Verbose "Setup: URL_Safes = $URL_Safes"
Write-Verbose "Setup: URL_Users = $URL_Users"
#endregion

#region Functions
function Invoke-Rest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PUT', 'DELETE', 'PATCH')]
        [String]$Command,

        [Parameter(Mandatory)]
        [String]$URI,

        [Parameter()]
        $Header,

        [Parameter()]
        [String]$Body,

        [Parameter()]
        [String]$ContentType = 'application/json',

        [Parameter()]
        [String]$ErrAction = 'Stop'
    )

    try {
        Write-Verbose "Invoke-Rest: $Command $URI"
        if ([string]::IsNullOrEmpty($Body)) {
            $restParams = @{
                Uri         = $URI
                Method      = $Command
                Headers     = $Header
                ContentType = $ContentType
                ErrorAction = $ErrAction
                Verbose     = $false
                Debug       = $false
            }
        }
        else {
            $restParams = @{
                Uri         = $URI
                Method      = $Command
                Headers     = $Header
                ContentType = $ContentType
                Body        = $Body
                ErrorAction = $ErrAction
                Verbose     = $false
                Debug       = $false
            }
        }
        $response = Invoke-RestMethod @restParams
        Write-Verbose "Invoke-Rest: Response type=$($response.GetType().Name) keys=[$($response.PSObject.Properties.Name -join ', ')]"
        return $response
    }
    catch {
        if ($ErrAction -ne 'SilentlyContinue') {
            throw
        }
        # Surface the error in verbose even when suppressed
        Write-Verbose "Invoke-Rest: Caught error (SilentlyContinue) - $($_.Exception.Message)"
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            Write-Verbose "Invoke-Rest: HTTP $statusCode $($_.Exception.Response.StatusDescription)"
            if ($statusCode -eq 401) {
                $script:LastHttpError = 401
            }
        }
        return $null
    }
}

function ConvertTo-URL {
    param([String]$Text)
    if (-not [string]::IsNullOrWhiteSpace($Text)) {
        return [URI]::EscapeDataString($Text)
    }
    return $Text
}

function ConvertTo-AuthLevel {
    param($Permissions)
    if ($Permissions.requestsAuthorizationLevel2 -eq $true) { return 2 }
    if ($Permissions.requestsAuthorizationLevel1 -eq $true) { return 1 }
    return 0
}
#endregion

#region Authentication
try {
    if ($null -ne $logonToken) {
        if ($logonToken.GetType().Name -eq 'String') {
            if ($logonToken.StartsWith('Bearer ')) {
                # Identity/PCloud Bearer token - Privilege Cloud also requires X-IDAP-NATIVE-CLIENT
                Write-Verbose 'Auth: logonToken is a Bearer string; adding X-IDAP-NATIVE-CLIENT header'
                $g_LogonHeader = @{
                    Authorization          = $logonToken
                    'X-IDAP-NATIVE-CLIENT' = 'true'
                }
            }
            else {
                # Self-hosted PVWA token - raw opaque value, passed straight as the Authorization header value
                Write-Verbose 'Auth: logonToken is a raw string; using as-is for Authorization header value'
                $g_LogonHeader = @{Authorization = $logonToken }
            }
        }
        else {
            # Hashtable already (e.g. from Get-IdentityHeader or New-Session when working correctly)
            Write-Verbose "Auth: logonToken is $($logonToken.GetType().Name); using directly as header"
            Write-Verbose "Auth: Header keys = [$($logonToken.Keys -join ', ')]"
            $g_LogonHeader = $logonToken
        }
    }
    else {
        Write-Verbose 'No logon token provided; performing self-hosted PVWA authentication'
        if ($null -eq $PVWACredentials) {
            $PVWACredentials = Get-Credential -Message 'Enter PVWA credentials'
            if ($null -eq $PVWACredentials) {
                Write-Error 'Credentials are required for self-hosted authentication'
                return
            }
        }
        $logonBody = @{
            username = $PVWACredentials.UserName.Replace('\', '')
            password = $PVWACredentials.GetNetworkCredential().Password
        } | ConvertTo-Json
        $logonTokenStr = Invoke-Rest -Command POST -URI $URL_Logon -Body $logonBody
        $logonBody = $null
        if ([string]::IsNullOrEmpty($logonTokenStr)) {
            Write-Error 'Authentication failed: empty token returned'
            return
        }
        $g_LogonHeader = @{Authorization = $logonTokenStr }
        $script:DoLogoff = $true
    }
}
catch {
    Write-Error "Authentication failed: $($_.Exception.Message)"
    return
}
#endregion

#region Data Collection
Write-Verbose "Data: PVWAURL = $PVWAURL"
Write-Verbose "Data: URL_PVWAAPI = $URL_PVWAAPI"

Write-Verbose 'Retrieving safes...'
[array]$allSafes = @()
# Skip safe API when MembersOnly + SafeName provided: names known, no safe details needed
$skipSafeAPI = $MembersOnly.IsPresent -and ($null -ne $SafeName)

if ($skipSafeAPI) {
    Write-Verbose "Safes: MembersOnly with named safes - skipping safe API ($($SafeName.Count) safe(s))"
    $allSafes = $SafeName | ForEach-Object { [pscustomobject]@{ SafeName = $_ } }
}
elseif ($SafeName) {
    Write-Verbose "Safes: Targeted mode - $($SafeName.Count) safe(s) requested"
    foreach ($name in $SafeName) {
        $encodedName = ConvertTo-URL -Text $name
        Write-Verbose "Safes: GET ${URL_Safes}/$encodedName"
        $safeResponse = Invoke-Rest -Command GET -URI "${URL_Safes}/$encodedName" -Header $g_LogonHeader -ErrAction SilentlyContinue
        if ($null -eq $safeResponse) {
            Write-Verbose "Safes: No response for '$name' - skipping"
        }
        else {
            Write-Verbose "Safes: Found safe '$($safeResponse.SafeName)'"
            $allSafes += $safeResponse
        }
    }
}
else {
    Write-Verbose 'Safes: Listing all safes (paginated)'
    $safeUrl = "${URL_Safes}?limit=1000"
    do {
        Write-Verbose "Safes: GET $safeUrl"
        $safeResponse = Invoke-Rest -Command GET -URI $safeUrl -Header $g_LogonHeader -ErrAction SilentlyContinue
        if ($null -eq $safeResponse) {
            Write-Verbose 'Safes: Response is null - API call failed (check verbose error above)'
        }
        elseif (-not $safeResponse.value) {
            Write-Verbose 'Safes: Response received but .value is empty'
            Write-Verbose "Safes: Response properties = [$($safeResponse.PSObject.Properties.Name -join ', ')]"
            Write-Verbose "Safes: Full response = $($safeResponse | ConvertTo-Json -Compress -Depth 3)"
        }
        else {
            Write-Verbose "Safes: Page returned $($safeResponse.value.Count) safes (total so far: $($allSafes.Count + $safeResponse.value.Count))"
            $allSafes += $safeResponse.value
        }
        $safeUrl = if ($safeResponse -and $safeResponse.nextLink) { "$PVWAURL/$($safeResponse.nextLink)" } else { $null }
        if ($safeUrl) { Write-Verbose 'Safes: nextLink found, continuing pagination' }
    } while ($safeUrl)
}

if ($allSafes.Count -eq 0) {
    if ($script:LastHttpError -eq 401) {
        Write-Error 'Authentication failed (HTTP 401). The logon token has expired or is invalid. Obtain a new token and try again.'
    } else {
        Write-Warning 'No safes retrieved. Verify permissions and PVWA URL.'
    }
    if ($script:DoLogoff) {
        Invoke-Rest -Command POST -URI $URL_Logoff -Header $g_LogonHeader -ErrAction SilentlyContinue | Out-Null
    }
    return
}
Write-Verbose "Retrieved $($allSafes.Count) safes total"

#region Output: Safe inventory (default - no -IncludeMembers or -MembersOnly)
if (-not $IncludeMembers.IsPresent -and -not $MembersOnly.IsPresent) {
    Write-Verbose 'Safe inventory mode'
    [array]$safeInvProps = @(
        'safeName', 'description', 'managingCPM', 'numberOfVersionsRetention',
        @{Name = 'numDaysRetention'; Expression = { $_.numberOfDaysRetention }}
    )
    if ($AllSafeDetails) {
        $safeInvProps += @(
            'safeUrlId', 'safeNumber', 'location', 'creator',
            @{Name = 'EnableOLAC'; Expression = { $_.olacEnabled }},
            'autoPurgeEnabled', 'creationTime', 'lastModificationTime', 'isExpiredMember'
        )
    }
    $safeInvRows = $allSafes | Select-Object -Property $safeInvProps
    if ($EPVFormat) {
        Write-Verbose 'Safe inventory: EPV-API-Common format (Import-Safe | New-Safe / Set-Safe)'
        $epvSafeRows = $allSafes | ForEach-Object {
            [pscustomobject]@{
                'Safe Name'                   = $_.safeName
                'Description'                 = $_.description
                'Managing CPM'                = $_.managingCPM
                'Number of Versions Retained' = $_.numberOfVersionsRetention
                'DaysRetention'               = $_.numberOfDaysRetention
                'OLAC Enabled'                = $_.olacEnabled
                'AutoPurgeEnabled'            = $_.autoPurgeEnabled
                'Location'                    = $_.location
            }
        }
        if (-not [string]::IsNullOrEmpty($ReportPath)) {
            $epvSafeRows | Export-Csv -Path $ReportPath -NoTypeInformation
            Write-Host "EPV-API-Common safe inventory written to: $ReportPath ($($allSafes.Count) safes)"
        } else {
            $epvSafeRows
        }
    } else {
        if (-not [string]::IsNullOrEmpty($ReportPath)) {
            $safeInvRows | Export-Csv -Path $ReportPath -NoTypeInformation
            Write-Host "Safe inventory written to: $ReportPath ($($allSafes.Count) safes)"
        } else {
            $safeInvRows
        }
    }
    if ($script:DoLogoff) {
        Invoke-Rest -Command POST -URI $URL_Logoff -Header $g_LogonHeader -ErrAction SilentlyContinue | Out-Null
    }
    return
}
#endregion

[hashtable]$safesHT = @{}
$allSafes | ForEach-Object { $safesHT[$_.SafeName] = $_ }

Write-Verbose 'Retrieving users for UserType/Source enrichment...'
[hashtable]$usersHT = @{}
$userUrl = "${URL_Users}?limit=1000"
do {
    Write-Verbose "Users: GET $userUrl"
    $userResponse = Invoke-Rest -Command GET -URI $userUrl -Header $g_LogonHeader -ErrAction SilentlyContinue
    if ($null -eq $userResponse) {
        Write-Verbose 'Users: Response is null - UserType/Source enrichment will be unavailable'
    }
    elseif (-not $userResponse.Users) {
        Write-Verbose "Users: Response received but .Users is empty"
        Write-Verbose "Users: Response properties = [$($userResponse.PSObject.Properties.Name -join ', ')]"
    }
    else {
        Write-Verbose "Users: Page returned $($userResponse.Users.Count) users"
        $userResponse.Users | ForEach-Object {
            if (-not $usersHT.ContainsKey($_.username)) {
                $usersHT[$_.username] = $_
            }
        }
    }
    $userUrl = if ($userResponse -and $userResponse.nextLink) { "$PVWAURL/$($userResponse.nextLink)" } else { $null }
} while ($userUrl)
Write-Verbose "Users: $($usersHT.Count) total users loaded"

[array]$includedUserTypes = @()
if (-not $ExcludeUsers) {
    $includedUserTypes += $UserTypes
}
if ($IncludeApps) {
    $includedUserTypes = @('AppProvider', 'AIMAccount') + $includedUserTypes
}

$inclPred = if ($IncludePredefinedUsers) { 'true' } else { 'false' }

Write-Verbose 'Retrieving safe members...'
[array]$allSafeMembers = @()
foreach ($safe in $allSafes) {
    $encodedName = ConvertTo-URL -Text $safe.SafeName
    $memberUrl = "$URL_Safes/$encodedName/Members?includePredefinedUsers=$inclPred&limit=500"
    Write-Verbose "Members: Processing safe '$($safe.SafeName)'"
    do {
        Write-Verbose "Members: GET $memberUrl"
        $memberResponse = Invoke-Rest -Command GET -URI $memberUrl -Header $g_LogonHeader -ErrAction SilentlyContinue
        if ($null -eq $memberResponse) {
            Write-Verbose "Members: Response null for safe '$($safe.SafeName)' - skipping"
        }
        elseif (-not $memberResponse.value) {
            Write-Verbose "Members: No members returned for safe '$($safe.SafeName)'"
        }
        else {
            Write-Verbose "Members: $($memberResponse.value.Count) members returned for safe '$($safe.SafeName)'"
            foreach ($member in $memberResponse.value) {
                $member | Add-Member -MemberType NoteProperty -Name 'SafeInfo' -Value $safesHT[$safe.SafeName] -Force
                $member | Add-Member -MemberType NoteProperty -Name 'UserInfo' -Value $usersHT[$member.memberName] -Force
                $allSafeMembers += $member
            }
        }
        $memberUrl = if ($memberResponse -and $memberResponse.nextLink) { "$PVWAURL/$($memberResponse.nextLink)" } else { $null }
    } while ($memberUrl)
}
Write-Verbose "Members: $($allSafeMembers.Count) total safe member records retrieved"
#endregion

#region Filtering
[array]$filteredMembers = $allSafeMembers | Where-Object {
    ($_.UserInfo.UserType -in $includedUserTypes) -or ($IncludeGroups.IsPresent -and $_.memberType -eq 'Group')
}

if ($filteredMembers.Count -eq 0) {
    Write-Warning 'No safe members found matching the specified filters. Expand search parameters and try again.'
    if ($script:DoLogoff) {
        Invoke-Rest -Command POST -URI $URL_Logoff -Header $g_LogonHeader -ErrAction SilentlyContinue | Out-Null
    }
    return
}
Write-Verbose "Filtered to $($filteredMembers.Count) members"
#endregion

#region Output: Member format (-IncludeMembers / -MembersOnly)
# Both modes are Safe-Management.ps1 compatible (-AddMembers / -UpdateMembers -FilePath)
Write-Verbose 'Building member output...'

# MembersOnly: lean - safename + member identity + permissions
# IncludeMembers: adds safe context (extra columns ignored by Safe-Management.ps1)
if ($MembersOnly) {
    [array]$smBaseProps = @('safename', 'member', 'MemberLocation', 'MemberType')
} else {
    # IncludeMembers
    [array]$smBaseProps = @('safename', 'description', 'managingCPM', 'numberOfVersionsRetention', 'numDaysRetention', 'member', 'MemberLocation', 'MemberType', 'Source', 'UserType')
    if ($AllSafeDetails) {
        $smBaseProps += @('safeLocation', 'EnableOLAC', 'autoPurgeEnabled', 'creationTime', 'lastModificationTime')
    }
}

[array]$smPermProps = @(
    'UseAccounts', 'RetrieveAccounts', 'ListAccounts', 'AddAccounts',
    'UpdateAccountContent', 'UpdateAccountProperties',
    'InitiateCPMAccountManagementOperations', 'SpecifyNextAccountContent',
    'RenameAccounts', 'DeleteAccounts', 'UnlockAccounts',
    'ManageSafe', 'ManageSafeMembers', 'BackupSafe',
    'ViewAuditLog', 'ViewSafeMembers', 'RequestsAuthorizationLevel',
    'AccessWithoutConfirmation', 'CreateFolders', 'DeleteFolders',
    'MoveAccountsAndFolders'
)

if ($HidePerms) {
    [array]$smOutputProps = $smBaseProps
}
elseif (-not [string]::IsNullOrEmpty($PermList)) {
    [array]$smOutputProps = $smBaseProps + $PermList
}
else {
    [array]$smOutputProps = $smBaseProps + $smPermProps
}

$smRows = $filteredMembers | ForEach-Object {
    $p = $_.permissions
    [pscustomobject]@{
        safename                               = $_.SafeName
        member                                 = $_.memberName
        MemberLocation                         = $_.location
        MemberType                             = $_.memberType
        Source                                 = $_.UserInfo.Source
        UserType                               = $_.UserInfo.UserType
        Description                            = $_.SafeInfo.description
        safeLocation                           = $_.SafeInfo.location
        managingCPM                            = $_.SafeInfo.managingCPM
        numDaysRetention                       = $_.SafeInfo.numberOfDaysRetention
        numberOfVersionsRetention              = $_.SafeInfo.numberOfVersionsRetention
        EnableOLAC                             = $_.SafeInfo.olacEnabled
        autoPurgeEnabled                       = $_.SafeInfo.autoPurgeEnabled
        creationTime                           = $_.SafeInfo.creationTime
        lastModificationTime                   = $_.SafeInfo.lastModificationTime
        UseAccounts                            = $p.useAccounts
        RetrieveAccounts                       = $p.retrieveAccounts
        ListAccounts                           = $p.listAccounts
        AddAccounts                            = $p.addAccounts
        UpdateAccountContent                   = $p.updateAccountContent
        UpdateAccountProperties                = $p.updateAccountProperties
        InitiateCPMAccountManagementOperations = $p.initiateCPMAccountManagementOperations
        SpecifyNextAccountContent              = $p.specifyNextAccountContent
        RenameAccounts                         = $p.renameAccounts
        DeleteAccounts                         = $p.deleteAccounts
        UnlockAccounts                         = $p.unlockAccounts
        ManageSafe                             = $p.manageSafe
        ManageSafeMembers                      = $p.manageSafeMembers
        BackupSafe                             = $p.backupSafe
        ViewAuditLog                           = $p.viewAuditLog
        ViewSafeMembers                        = $p.viewSafeMembers
        RequestsAuthorizationLevel             = ConvertTo-AuthLevel -Permissions $p
        AccessWithoutConfirmation              = $p.accessWithoutConfirmation
        CreateFolders                          = $p.createFolders
        DeleteFolders                          = $p.deleteFolders
        MoveAccountsAndFolders                 = $p.moveAccountsAndFolders
    }
}

$smExportParams = @{
    Path              = $ReportPath
    NoTypeInformation = $true
}
if ($EPVFormat) {
    Write-Verbose 'Member output: EPV-API-Common format (Import-SafeMember | Add-SafeMember)'
    $epvRows = $filteredMembers | ForEach-Object {
        $p = $_.permissions
        $mt = if ($_.memberType -eq 'User') { 'User' }
              elseif ($_.memberType -eq 'Group' -and $_.memberName -match '.+@.+') { 'Group' }
              else { 'Role' }
        [pscustomobject]@{
            'Safe Name'                                  = $_.SafeName
            'Member Name'                                = $_.memberName
            'Member Type'                                = $mt
            'List Accounts'                              = $p.listAccounts
            'Use Accounts'                               = $p.useAccounts
            'Retrieve Accounts'                          = $p.retrieveAccounts
            'Add Accounts'                               = $p.addAccounts
            'Update Account Properties'                  = $p.updateAccountProperties
            'Update Account Content'                     = $p.updateAccountContent
            'Initiate CPM Account Management Operations' = $p.initiateCPMAccountManagementOperations
            'Specify Next Account Content'               = $p.specifyNextAccountContent
            'Rename Account'                             = $p.renameAccounts
            'Delete Account'                             = $p.deleteAccounts
            'Unlock Account'                             = $p.unlockAccounts
            'Manage Safe'                                = $p.manageSafe
            'View Safe Members'                          = $p.viewSafeMembers
            'Manage Safe Members'                        = $p.manageSafeMembers
            'View Audit Log'                             = $p.viewAuditLog
            'Backup Safe'                                = $p.backupSafe
            'Level 1 Confirmer'                          = $p.requestsAuthorizationLevel1
            'Level 2 Confirmer'                          = $p.requestsAuthorizationLevel2
            'Access Safe Without Confirmation'           = $p.accessWithoutConfirmation
            'Move Accounts / Folders'                    = $p.moveAccountsAndFolders
            'Create Folders'                             = $p.createFolders
            'Delete Folders'                             = $p.deleteFolders
        }
    }
    if (-not [string]::IsNullOrEmpty($ReportPath)) {
        $epvRows | Sort-Object -Property 'Safe Name', 'Member Name' | Export-Csv @smExportParams
        Write-Host "EPV-API-Common member report written to: $ReportPath ($($epvRows.Count) records)"
    } else {
        $epvRows | Sort-Object -Property 'Safe Name', 'Member Name'
    }
} else {
    if (-not [string]::IsNullOrEmpty($ReportPath)) {
        $smRows | Select-Object -Property $smOutputProps | Sort-Object -Property member, safename | Export-Csv @smExportParams
        Write-Host "Safe-Management report written to: $ReportPath ($($smRows.Count) records)"
    } else {
        Write-Verbose 'ReportPath not specified - writing to pipeline'
        $smRows | Select-Object -Property $smOutputProps | Sort-Object -Property member, safename
    }
}
#endregion

#region Logoff
if ($script:DoLogoff) {
    Write-Verbose 'Logging off self-hosted PVWA session'
    Invoke-Rest -Command POST -URI $URL_Logoff -Header $g_LogonHeader -ErrAction SilentlyContinue | Out-Null
}
#endregion

