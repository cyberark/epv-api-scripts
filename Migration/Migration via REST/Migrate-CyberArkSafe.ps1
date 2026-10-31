#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'psPAS'; ModuleVersion = '6.0.0' }
<#
.SYNOPSIS
    Interactively migrates a CyberArk safe, its properties, its memberships and
    (optionally) its accounts from a source vault to a destination vault.

.DESCRIPTION
    Workflow (every step is logged):

      1.  Operator enters the source safe name.
      2.  Operator chooses: (1) Safe only, or (2) Safe with accounts.
      3.  Script authenticates to the source PVWA (psPAS / REST API) and reads:
            - the safe and all of its properties
            - all safe memberships and their permissions
          and prints a summary of the safe details and memberships.
      4.  If "Safe with accounts" was chosen, the operator chooses to export ALL
          accounts, or to review them ONE AT A TIME (Y = include, N = skip).
          Each included account (including its secret, retrieved securely as a
          SecureString) is stored in an in-memory array of accounts to migrate.
      5.  The source session is closed.
      6.  Operator enters the target safe name in the destination vault (defaults to the source name).
      7.  Script authenticates to the destination PVWA and searches for that safe:
            - Found     -> the safe is NOT re-created (optionally sync missing members).
            - Not found -> the safe is created with the same properties and the
                           same (non-built-in) members and permissions.
          The safe and its members are then read back and validated against the source.
      8.  If accounts were exported, the operator chooses to import ALL of them,
          or ONE AT A TIME (Y/N). Every created account is read back and validated
          against the source values (and, with -ValidateSecrets, the secret too).
      9.  A final summary is printed, and results are exported to CSV.

    LOGGING
      Log file : <ScriptFolder>\Logs\<ScriptName>_<SourceSafeName>_<yyyyMMdd_HHmmss>.log
      Results  : same base name with a .csv extension
      Secrets are NEVER written to the log or CSV.

.PARAMETER SourcePVWAUrl
    Base URL of the source PVWA (for example https://pvwa-source.corp.local).

.PARAMETER SourceAuthType
    Authentication method for the source vault: CyberArk, LDAP or RADIUS.

.PARAMETER DestinationPVWAUrl
    Base URL of the destination PVWA.

.PARAMETER DestinationAuthType
    Authentication method for the destination vault: CyberArk, LDAP or RADIUS.

.PARAMETER DestinationDirectoryName
    Optional. The LDAP directory name (as configured in the destination vault) to use as "SearchIn"
    for safe members that do not yet exist as objects in the destination vault. If not
    supplied, the operator is prompted for each such member.

.PARAMETER RetrievalReason
    Reason text sent when retrieving account secrets (needed if the source safe
    requires a reason for access).

.PARAMETER ValidateSecrets
    After each account is created in the destination vault, retrieve its secret and compare it with
    the source secret. This produces an extra retrieval audit record in the destination vault.

.PARAMETER SkipCertificateCheck
    Passes -SkipCertificateCheck to New-PASSession (lab use only).

.EXAMPLE
    .\Migrate-CyberArkSafe.ps1 -SourcePVWAUrl https://pvwa-source.corp.local `
        -DestinationPVWAUrl https://pvwa-destination.corp.local -SourceAuthType LDAP -DestinationAuthType LDAP `
        -DestinationDirectoryName corp.local -ValidateSecrets -Verbose

.NOTES
    Requirements
      - psPAS 6.x (uses the Gen2 / v12.2+ Safes, Safe Members and Accounts APIs).
      - Source operator     : List accounts, Retrieve accounts, View safe members on the source safe.
      - Destination operator: Add Safes (vault authorization), Manage safe members, Add accounts,
                                plus Retrieve accounts on the new safe if -ValidateSecrets is used.
    Known limitations
      - Built-in / predefined members (Administrator, Auditors, Backup Users, etc.) are not
        copied; the destination vault adds its own predefined members automatically.
      - Linked accounts (logon / reconcile / extra passwords), account version history,
        dependencies, and folders are not migrated.
      - RADIUS challenge/response (OTP) logins are not handled; use LDAP or CyberArk auth.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^https://')]
    [string]$SourcePVWAUrl = 'https://pvwa-source.corp.local',

    [ValidateSet('CyberArk', 'LDAP', 'RADIUS')]
    [string]$SourceAuthType = 'LDAP',

    [ValidatePattern('^https://')]
    [string]$DestinationPVWAUrl = 'https://pvwa-destination.corp.local',

    [ValidateSet('CyberArk', 'LDAP', 'RADIUS')]
    [string]$DestinationAuthType = 'LDAP',

    [string]$DestinationDirectoryName,

    [string]$RetrievalReason = 'Safe migration from source vault to destination vault',

    [switch]$ValidateSecrets,

    [switch]$SkipCertificateCheck
)

#==============================================================================================
#region SCRIPT-LEVEL SETUP
#==============================================================================================

# Stop on any non-handled error so every failure is caught by a try/catch block
# and logged, rather than silently continuing with bad data.
$ErrorActionPreference = 'Stop'

# Capture the moment the script started. This one timestamp is used in the log
# file name so the log reflects when the script was run, not when logging began.
$script:ScriptStart  = Get-Date
$script:RunTimestamp = $script:ScriptStart.ToString('yyyyMMdd_HHmmss')

# Work out the script's own name (without .ps1) for the log file name.
# $PSCommandPath is empty when code is pasted into a console, so fall back to a fixed name.
$script:ScriptName = if ($PSCommandPath) {
    [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
} else {
    'Migrate-CyberArkSafe'
}

# Work out the folder the script lives in; the "Logs" folder is created beneath it.
# Falls back to the current directory when run interactively without a script file.
$script:ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$script:LogFolder  = Join-Path -Path $script:ScriptRoot -ChildPath 'Logs'

# The log file path is only known after the operator enters the safe name.
# Until then, log lines are held in memory and flushed to disk once the file exists.
$script:LogFile   = $null
$script:LogBuffer = [System.Collections.Generic.List[string]]::new()

# Tracks which vault (if any) currently has an open psPAS session, so the
# finally block can always log off cleanly.
$script:CurrentVault = $null

# Collects one result row per account (and per member) for the final summary and CSV.
$script:Results = [System.Collections.Generic.List[object]]::new()

# Caches destination platform lookups so each platform is only queried once.
$script:PlatformCache = @{}

# Overall exit code: 0 = everything succeeded, 1 = at least one failure or mismatch.
$script:ExitCode = 0

# The complete list of Gen2 safe-member permissions. These names match both the
# properties returned by Get-PASSafeMember (.permissions.<name>) and the parameter
# names of Add-PASSafeMember (PowerShell parameter names are case-insensitive).
$script:SafePermissionNames = @(
    'useAccounts'
    'retrieveAccounts'
    'listAccounts'
    'addAccounts'
    'updateAccountContent'
    'updateAccountProperties'
    'initiateCPMAccountManagementOperations'
    'specifyNextAccountContent'
    'renameAccounts'
    'deleteAccounts'
    'unlockAccounts'
    'manageSafe'
    'manageSafeMembers'
    'backupSafe'
    'viewAuditLog'
    'viewSafeMembers'
    'accessWithoutConfirmation'
    'createFolders'
    'deleteFolders'
    'moveAccountsAndFolders'
    'requestsAuthorizationLevel1'
    'requestsAuthorizationLevel2'
)

#endregion

#==============================================================================================
#region LOGGING FUNCTIONS
#==============================================================================================

function Write-Log {
    <#
        Writes one timestamped line to the log (or to the in-memory buffer if the log
        file has not been created yet) and, unless -NoConsole is used, to the console
        in a colour that matches the severity.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'DEBUG', 'PROMPT')]
        [string]$Level = 'INFO',
        [switch]$NoConsole
    )

    # Build the line: "2026-10-07 14:03:22.511 [INFO   ] message"
    $line = '{0} [{1,-7}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message

    # Write to the file if it exists, otherwise buffer it until Initialize-Log runs.
    if ($script:LogFile) {
        Add-Content -Path $script:LogFile -Value $line -Encoding UTF8
    } else {
        $script:LogBuffer.Add($line)
    }

    # Echo to the console unless suppressed. DEBUG lines only show when -Verbose is used.
    if (-not $NoConsole) {
        if ($Level -eq 'DEBUG' -and $VerbosePreference -ne 'Continue') { return }
        $colour = switch ($Level) {
            'ERROR'   { 'Red' }
            'WARN'    { 'Yellow' }
            'SUCCESS' { 'Green' }
            'DEBUG'   { 'DarkGray' }
            'PROMPT'  { 'Cyan' }
            default   { 'White' }
        }
        Write-Host $line -ForegroundColor $colour
    }
}

function Write-LogBlock {
    <#
        Writes a multi-line block of text (such as a formatted table) to the console
        as-is, and to the log file line by line so the log keeps its timestamp format.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [string]$Level = 'INFO'
    )
    Write-Host $Text
    foreach ($l in ($Text -split "`r?`n")) {
        if ($l.Trim()) { Write-Log -Message $l -Level $Level -NoConsole }
    }
}

function Initialize-Log {
    <#
        Creates the "Logs" folder (if needed) and the log file named
        <ScriptName>_<SafeName>_<Timestamp>.log, then flushes buffered lines into it.
    #>
    param([Parameter(Mandatory)][string]$SafeName)

    # Create the Logs folder next to the script if it doesn't already exist.
    if (-not (Test-Path -Path $script:LogFolder)) {
        New-Item -Path $script:LogFolder -ItemType Directory -Force | Out-Null
    }

    # Replace any characters that are not valid in a file name with an underscore.
    $invalid     = [System.IO.Path]::GetInvalidFileNameChars()
    $safeForFile = -join ($SafeName.ToCharArray() | ForEach-Object {
            if ($invalid -contains $_) { '_' } else { $_ }
        })

    # Build the full log path and create the file with a header.
    $script:LogFile = Join-Path -Path $script:LogFolder -ChildPath (
        '{0}_{1}_{2}.log' -f $script:ScriptName, $safeForFile, $script:RunTimestamp)

    Set-Content -Path $script:LogFile -Encoding UTF8 -Value @(
        ('=' * 100)
        "  $($script:ScriptName) - CyberArk safe migration log"
        "  Started : $($script:ScriptStart.ToString('yyyy-MM-dd HH:mm:ss'))"
        "  Host    : $env:COMPUTERNAME   Operator (Windows): $env:USERDOMAIN\$env:USERNAME"
        ('=' * 100)
    )

    # Move everything logged before the file existed into the file, in order.
    if ($script:LogBuffer.Count -gt 0) {
        Add-Content -Path $script:LogFile -Value $script:LogBuffer.ToArray() -Encoding UTF8
        $script:LogBuffer.Clear()
    }

    Write-Log "Log file created: $($script:LogFile)"
}

function Add-Result {
    <# Adds one row to the results collection used for the summary table and CSV export. #>
    param(
        [string]$Phase, [string]$ObjectType, [string]$Name, [string]$UserName,
        [string]$Address, [string]$Platform, [string]$Status,
        [string]$DestinationId, [string]$Details
    )
    $script:Results.Add([pscustomobject]@{
            Time          = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            Phase         = $Phase
            ObjectType    = $ObjectType
            Name          = $Name
            UserName      = $UserName
            Address       = $Address
            Platform      = $Platform
            Status        = $Status
            DestinationId = $DestinationId
            Details       = $Details
        })
}

#endregion

#==============================================================================================
#region OPERATOR PROMPT FUNCTIONS
#==============================================================================================

function Read-RequiredValue {
    <#
        Prompts until the operator enters a non-blank value that passes an optional
        validation script block. Every prompt and answer is written to the log.
    #>
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [scriptblock]$Validator,
        [string]$ValidationMessage = 'The value entered is not valid.'
    )
    while ($true) {
        $value = (Read-Host -Prompt $Prompt).Trim()
        Write-Log "PROMPT: '$Prompt' -> operator entered '$value'" -Level PROMPT -NoConsole

        if ([string]::IsNullOrWhiteSpace($value)) {
            Write-Log 'A value is required. Please try again.' -Level WARN
            continue
        }
        if ($Validator -and -not (& $Validator $value)) {
            Write-Log $ValidationMessage -Level WARN
            continue
        }
        return $value
    }
}

function Read-ValueWithDefault {
    <#
        Prompts for a value and returns the default if the operator presses Enter.
        Typing a single "-" returns an empty string (used to clear a value).
    #>
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [AllowEmptyString()][string]$Default = '',
        [scriptblock]$Validator,
        [string]$ValidationMessage = 'The value entered is not valid.'
    )
    $shown = if ([string]::IsNullOrEmpty($Default)) { '(none)' } else { $Default }
    while ($true) {
        $raw = Read-Host -Prompt "$Prompt [Enter = '$shown', '-' = none]"
        $value = if ([string]::IsNullOrWhiteSpace($raw)) { $Default }
                 elseif ($raw.Trim() -eq '-') { '' }
                 else { $raw.Trim() }
        Write-Log "PROMPT: '$Prompt' -> resolved value '$value'" -Level PROMPT -NoConsole

        if ($Validator -and -not (& $Validator $value)) {
            Write-Log $ValidationMessage -Level WARN
            continue
        }
        return $value
    }
}

function Read-Choice {
    <#
        Prompts until the operator types one of the allowed choices (case-insensitive)
        and returns the choice in upper case.
    #>
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][string[]]$Choices
    )
    while ($true) {
        $value = (Read-Host -Prompt "$Prompt [$($Choices -join '/')]").Trim().ToUpper()
        Write-Log "PROMPT: '$Prompt' -> operator entered '$value'" -Level PROMPT -NoConsole
        if ($Choices -contains $value) { return $value }
        Write-Log "Invalid choice '$value'. Valid options: $($Choices -join ', ')." -Level WARN
    }
}

function Test-SafeNameFormat {
    <#
        Checks CyberArk safe-name rules before any API call: 1-28 characters,
        no leading/trailing spaces, and none of the characters \ / : * ? " < > |
    #>
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name.Length -gt 28) { return $false }
    if ($Name -ne $Name.Trim()) { return $false }
    if ($Name -match '[\\/:*?"<>|]') { return $false }
    return $true
}

#endregion

#==============================================================================================
#region GENERAL HELPER FUNCTIONS
#==============================================================================================

function Test-CommandParameter {
    <#
        Returns $true if the installed psPAS command supports the given parameter.
        Different psPAS releases expose slightly different parameters, so optional
        properties are only sent when the installed version supports them.
    #>
    param([Parameter(Mandatory)][string]$Command, [Parameter(Mandatory)][string]$Parameter)
    $cmd = Get-Command -Name $Command -ErrorAction Stop
    return $cmd.Parameters.ContainsKey($Parameter)
}

function ConvertFrom-UnixTime {
    <#
        Gen2 APIs return dates as Unix epoch seconds. Converts them to local DateTime.
        Returns $null for empty or zero values, and passes real DateTime values through.
    #>
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '' -or "$Value" -eq '0') { return $null }
    if ($Value -is [datetime]) { return $Value }
    $epoch = 0L
    if ([long]::TryParse("$Value", [ref]$epoch)) {
        # Values above ~10^11 are in milliseconds rather than seconds.
        if ($epoch -gt 100000000000) { return [DateTimeOffset]::FromUnixTimeMilliseconds($epoch).LocalDateTime }
        return [DateTimeOffset]::FromUnixTimeSeconds($epoch).LocalDateTime
    }
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse("$Value", [ref]$parsed)) { return $parsed }
    return $null
}

function ConvertTo-PlainHashtable {
    <#
        Converts a PSCustomObject (such as an account's platformAccountProperties)
        into a hashtable, the format Add-PASAccount expects.
    #>
    param($InputObject)
    $hash = @{}
    if ($null -eq $InputObject) { return $hash }
    if ($InputObject -is [hashtable]) { return $InputObject.Clone() }
    foreach ($p in $InputObject.PSObject.Properties) { $hash[$p.Name] = $p.Value }
    return $hash
}

function ConvertFrom-SecureStringToPlain {
    <#
        Converts a SecureString to plain text ONLY for an in-memory comparison.
        The unmanaged copy is zeroed immediately. The result is never logged.
    #>
    param([Parameter(Mandatory)][securestring]$Secure)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Compare-Value {
    <#
        Compares an expected value with an actual value as normalised strings
        ($null and '' are treated as equal) and records any difference in the
        supplied mismatch list.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Mismatches,
        [Parameter(Mandatory)][string]$Name,
        $Expected,
        $Actual
    )
    $e = if ($null -eq $Expected) { '' } else { "$Expected".Trim() }
    $a = if ($null -eq $Actual)   { '' } else { "$Actual".Trim() }
    if ($e -ne $a) {
        $Mismatches.Add("$Name : expected '$e' but found '$a'")
        Write-Log "  MISMATCH  $Name : expected '$e' / actual '$a'" -Level WARN -NoConsole
    } else {
        Write-Log "  OK        $Name = '$a'" -Level DEBUG -NoConsole
    }
}

function Format-AccountLine {
    <# Builds a one-line, human-readable description of an account (no secret). #>
    param($Account)
    $auto = if ($Account.secretManagement) { $Account.secretManagement.automaticManagementEnabled } else { $Account.AutomaticManagementEnabled }
    $user = if ($Account.userName) { $Account.userName } else { $Account.UserName }
    $platform = if ($Account.platformId) { $Account.platformId } else { $Account.PlatformId }
    '{0} | {1}@{2} | Platform: {3} | Type: {4} | CPM managed: {5}' -f
        $Account.name, $user, $Account.address, $platform, $Account.secretType, $auto
}

#endregion

#==============================================================================================
#region VAULT SESSION FUNCTIONS
#==============================================================================================

function Connect-Vault {
    <#
        Prompts the operator for credentials and opens a psPAS session to the given PVWA.
        Returns the user name that was authenticated (used later to recognise the
        creating user that CyberArk automatically adds to new safes).
    #>
    param(
        [Parameter(Mandatory)][string]$VaultLabel,
        [Parameter(Mandatory)][string]$BaseURI,
        [Parameter(Mandatory)][string]$AuthType
    )

    Write-Log "Authenticating to the $VaultLabel vault at $BaseURI using $AuthType authentication..."

    # Prompt for credentials (the password is held as a SecureString by Get-Credential).
    $credential = Get-Credential -Message "Enter your credentials for the $VaultLabel vault ($BaseURI)"
    if (-not $credential) { throw "No credentials were supplied for the $VaultLabel vault. Aborting." }
    Write-Log "Credentials supplied for user '$($credential.UserName)'." -Level DEBUG

    # Build the New-PASSession parameters.
    $sessionParams = @{
        BaseURI     = $BaseURI
        Credential  = $credential
        type        = $AuthType
        ErrorAction = 'Stop'
    }
    if ($SkipCertificateCheck) {
        $sessionParams['SkipCertificateCheck'] = $true
        Write-Log 'Certificate validation is DISABLED for this session (-SkipCertificateCheck).' -Level WARN
    }

    try {
        $null = New-PASSession @sessionParams
    }
    catch {
        Write-Log "Authentication to the $VaultLabel vault FAILED: $($_.Exception.Message)" -Level ERROR
        throw
    }

    # Read the session back to confirm it is active and record the version for troubleshooting.
    $session = Get-PASSession
    $script:CurrentVault = $VaultLabel
    Write-Log ("Authenticated to the {0} vault as '{1}'. PVWA version: {2}" -f
        $VaultLabel, $session.User, $session.ExternalVersion) -Level SUCCESS

    return [string]$session.User
}

function Disconnect-Vault {
    <# Logs off the current psPAS session (if one is open). Safe to call more than once. #>
    if ($script:CurrentVault) {
        $label = $script:CurrentVault
        try {
            Close-PASSession -ErrorAction Stop
            Write-Log "Logged off from the $label vault."
        }
        catch {
            Write-Log "Log-off from the $label vault reported an error: $($_.Exception.Message)" -Level WARN
        }
        finally {
            $script:CurrentVault = $null
        }
    }
}

#endregion

#==============================================================================================
#region SOURCE FUNCTIONS
#==============================================================================================

function Get-SourceSafe {
    <# Reads the source safe and its properties. Throws if the safe is missing or not accessible. #>
    param([Parameter(Mandatory)][string]$SafeName)
    Write-Log "Reading safe '$SafeName' and its properties from the source vault..."
    try {
        $safe = Get-PASSafe -SafeName $SafeName -ErrorAction Stop
    }
    catch {
        Write-Log "Safe '$SafeName' was not found in the source vault, or you lack access: $($_.Exception.Message)" -Level ERROR
        throw
    }
    if (-not $safe) { throw "Safe '$SafeName' returned no data from the source vault." }
    Write-Log "Safe '$($safe.safeName)' found in the source vault." -Level SUCCESS
    return $safe
}

function Get-SourceSafeMembers {
    <# Reads every member of the source safe and logs each member's full permission set. #>
    param([Parameter(Mandatory)][string]$SafeName)
    Write-Log "Reading safe memberships for '$SafeName' from the source vault..."
    try {
        $members = @(Get-PASSafeMember -SafeName $SafeName -ErrorAction Stop)
    }
    catch {
        Write-Log "Unable to read members of '$SafeName': $($_.Exception.Message)" -Level ERROR
        throw
    }
    Write-Log "Found $($members.Count) member(s) on the source safe." -Level SUCCESS

    # Record the full permission list for each member (log only, to keep the console readable).
    foreach ($m in $members) {
        $granted = @($script:SafePermissionNames | Where-Object { [bool]$m.permissions.$_ })
        Write-Log ("  Member '{0}' ({1}) Predefined={2} Granted: {3}" -f
            $m.memberName, $m.memberType, [bool]$m.isPredefinedUser, ($granted -join ', ')) -NoConsole
    }
    return $members
}

function Show-SafeSummary {
    <# Prints (and logs) a summary of the safe's properties and a table of its members. #>
    param(
        [Parameter(Mandatory)]$Safe,
        [AllowEmptyCollection()][object[]]$Members = @(),
        [Parameter(Mandatory)][string]$Title
    )

    # --- Safe properties ---
    $summary = [pscustomobject][ordered]@{
        'Safe Name'          = $Safe.safeName
        'Description'        = $Safe.description
        'Location'           = $Safe.location
        'Managing CPM'       = $Safe.managingCPM
        'OLAC Enabled'       = $Safe.olacEnabled
        'Versions Retention' = $Safe.numberOfVersionsRetention
        'Days Retention'     = $Safe.numberOfDaysRetention
        'Auto Purge Enabled' = $Safe.autoPurgeEnabled
        'Creator'            = $Safe.creator.name
        'Created'            = ConvertFrom-UnixTime $Safe.creationTime
    }
    Write-LogBlock -Text ("`n===== $Title : SAFE DETAILS =====" + ($summary | Format-List | Out-String))

    # --- Members ---
    if ($Members.Count -eq 0) {
        Write-Log 'No members were returned for this safe.' -Level WARN
        return
    }
    $memberRows = foreach ($m in $Members) {
        $granted = @($script:SafePermissionNames | Where-Object { [bool]$m.permissions.$_ })
        [pscustomobject]@{
            Member      = $m.memberName
            Type        = $m.memberType
            BuiltIn     = [bool]$m.isPredefinedUser
            List        = [bool]$m.permissions.listAccounts
            Use         = [bool]$m.permissions.useAccounts
            Retrieve    = [bool]$m.permissions.retrieveAccounts
            ManageSafe  = [bool]$m.permissions.manageSafe
            ManageMbrs  = [bool]$m.permissions.manageSafeMembers
            Perms       = "$($granted.Count)/$($script:SafePermissionNames.Count)"
            Expires     = ConvertFrom-UnixTime $m.membershipExpirationDate
        }
    }
    Write-LogBlock -Text ("===== $Title : SAFE MEMBERS =====" +
        ($memberRows | Sort-Object Type, Member | Format-Table -AutoSize | Out-String -Width 4096))
}

function Get-AccountSecret {
    <#
        Retrieves an account's secret and returns it as a SecureString.
        Handles the different return shapes of Get-PASAccountPassword across psPAS versions.
        The plain-text value is never logged and is discarded as soon as possible.
    #>
    param([Parameter(Mandatory)][string]$AccountId)

    $response = Get-PASAccountPassword -AccountID $AccountId -Reason $RetrievalReason -ErrorAction Stop

    if ($response -is [securestring]) { return $response }

    $plain = if ($response -is [string]) { $response }
             elseif ($response.PSObject.Properties['Password']) { $response.Password }
             else { "$response" }

    if ([string]::IsNullOrEmpty($plain)) { throw 'The vault returned an empty secret.' }

    $secure = ConvertTo-SecureString -String $plain -AsPlainText -Force
    $plain = $null
    $response = $null
    return $secure
}

function New-AccountSnapshot {
    <#
        Copies every property needed to re-create an account into a standalone object.
        This object is what goes into the "accounts to be migrated" array.
    #>
    param([Parameter(Mandatory)]$Account)
    [pscustomobject]@{
        SourceId                         = $Account.id
        Name                             = $Account.name
        Address                          = $Account.address
        UserName                         = $Account.userName
        PlatformId                       = $Account.platformId
        SecretType                       = if ($Account.secretType) { $Account.secretType } else { 'password' }
        PlatformAccountProperties        = ConvertTo-PlainHashtable $Account.platformAccountProperties
        AutomaticManagementEnabled       = [bool]$Account.secretManagement.automaticManagementEnabled
        ManualManagementReason           = $Account.secretManagement.manualManagementReason
        RemoteMachines                   = $Account.remoteMachinesAccess.remoteMachines
        AccessRestrictedToRemoteMachines = [bool]$Account.remoteMachinesAccess.accessRestrictedToRemoteMachines
        Secret                           = $null     # SecureString, filled in after retrieval
        SecretRetrieved                  = $false
    }
}

#endregion

#==============================================================================================
#region DESTINATION FUNCTIONS
#==============================================================================================

function Find-DestinationSafe {
    <#
        Searches the destination vault for a safe with exactly this name (case-insensitive, as in the Vault).
        Returns the safe object, or $null if no exact match exists.
    #>
    param([Parameter(Mandatory)][string]$SafeName)
    Write-Log "Searching the destination vault for safe '$SafeName'..."
    $candidates = @(Get-PASSafe -search $SafeName -ErrorAction Stop)
    Write-Log "Search returned $($candidates.Count) candidate safe(s)." -Level DEBUG
    $match = $candidates | Where-Object { $_.safeName -eq $SafeName } | Select-Object -First 1
    if ($match) { Write-Log "Safe '$SafeName' already EXISTS in the destination vault." -Level SUCCESS }
    else { Write-Log "Safe '$SafeName' was NOT found in the destination vault." }
    return $match
}

function New-DestinationSafe {
    <#
        Creates the target safe with the same properties as the source safe.
        Lets the operator confirm or override the Managing CPM and Location, since
        those names may differ between vaults. Returns the hashtable of values that
        were requested, used afterwards to validate the safe.
    #>
    param(
        [Parameter(Mandatory)][string]$SafeName,
        [Parameter(Mandatory)]$SourceSafe
    )

    Write-Log "Preparing to create safe '$SafeName' in the destination vault using the source safe's properties..."

    # The Managing CPM and Location must exist in the destination vault; confirm them with the operator.
    $cpm = Read-ValueWithDefault -Prompt 'Managing CPM user in the destination vault' -Default ([string]$SourceSafe.managingCPM)
    $sourceLocation = if ([string]::IsNullOrWhiteSpace($SourceSafe.location)) { '\' } else { [string]$SourceSafe.location }
    $location = Read-ValueWithDefault -Prompt 'Safe location in the destination vault' -Default $sourceLocation

    # Required and always-supported properties.
    $safeParams = @{
        SafeName    = $SafeName
        ErrorAction = 'Stop'
    }
    # Only send a Managing CPM if one was chosen (blank = safe not managed by a CPM).
    if (-not [string]::IsNullOrWhiteSpace($cpm)) { $safeParams['ManagingCPM'] = $cpm }
    if (-not [string]::IsNullOrWhiteSpace($SourceSafe.description)) {
        $safeParams['Description'] = [string]$SourceSafe.description
    }

    # Retention: a safe uses EITHER a number of versions OR a number of days, never both.
    if ($null -ne $SourceSafe.numberOfVersionsRetention -and [int]$SourceSafe.numberOfVersionsRetention -gt 0) {
        $safeParams['NumberOfVersionsRetention'] = [int]$SourceSafe.numberOfVersionsRetention
    }
    elseif ($null -ne $SourceSafe.numberOfDaysRetention) {
        $safeParams['NumberOfDaysRetention'] = [int]$SourceSafe.numberOfDaysRetention
    }

    # Optional properties: only sent if this psPAS version supports them.
    $optional = [ordered]@{
        OLACEnabled      = [bool]$SourceSafe.olacEnabled
        AutoPurgeEnabled = [bool]$SourceSafe.autoPurgeEnabled
    }
    # Only send a location if it isn't the root ('\'); root is the default.
    if ($location -and $location -ne '\') { $optional['Location'] = $location }

    foreach ($key in $optional.Keys) {
        if (Test-CommandParameter -Command 'Add-PASSafe' -Parameter $key) {
            $safeParams[$key] = $optional[$key]
        } else {
            Write-Log "Installed psPAS Add-PASSafe does not support -$key; it will not be set." -Level WARN
        }
    }

    # Log exactly what will be sent (no sensitive data in safe properties).
    $logView = $safeParams.GetEnumerator() | Where-Object { $_.Key -ne 'ErrorAction' } |
        ForEach-Object { "$($_.Key)='$($_.Value)'" }
    Write-Log "Add-PASSafe parameters: $($logView -join '; ')"

    try {
        $created = Add-PASSafe @safeParams
        Write-Log "Safe '$($created.safeName)' CREATED in the destination vault." -Level SUCCESS
        Add-Result -Phase 'Destination' -ObjectType 'Safe' -Name $SafeName -Status 'Created'
    }
    catch {
        Write-Log "Failed to create safe '$SafeName' in the destination vault: $($_.Exception.Message)" -Level ERROR
        Add-Result -Phase 'Destination' -ObjectType 'Safe' -Name $SafeName -Status 'Failed' -Details $_.Exception.Message
        throw
    }

    # Return what was requested (plus location for validation even when it is root).
    $expected = @{} + $safeParams
    $expected.Remove('ErrorAction')
    $expected['Location'] = $location
    return $expected
}

function Test-DestinationSafe {
    <#
        Reads the destination safe back and compares each property with what was requested.
        Returns $true when everything matches.
    #>
    param(
        [Parameter(Mandatory)][string]$SafeName,
        [Parameter(Mandatory)][hashtable]$Expected
    )
    Write-Log "Validating the properties of destination safe '$SafeName'..."
    $actual = Get-PASSafe -SafeName $SafeName -ErrorAction Stop
    $mismatches = [System.Collections.Generic.List[string]]::new()

    Compare-Value $mismatches 'safeName'    $Expected.SafeName    $actual.safeName
    Compare-Value $mismatches 'description' $Expected.Description $actual.description
    Compare-Value $mismatches 'managingCPM' $Expected.ManagingCPM $actual.managingCPM
    if ($Expected.ContainsKey('NumberOfVersionsRetention')) {
        Compare-Value $mismatches 'numberOfVersionsRetention' $Expected.NumberOfVersionsRetention $actual.numberOfVersionsRetention
    }
    if ($Expected.ContainsKey('NumberOfDaysRetention')) {
        Compare-Value $mismatches 'numberOfDaysRetention' $Expected.NumberOfDaysRetention $actual.numberOfDaysRetention
    }
    if ($Expected.ContainsKey('OLACEnabled')) {
        Compare-Value $mismatches 'olacEnabled' ([bool]$Expected.OLACEnabled) ([bool]$actual.olacEnabled)
    }
    if ($Expected.ContainsKey('AutoPurgeEnabled')) {
        Compare-Value $mismatches 'autoPurgeEnabled' ([bool]$Expected.AutoPurgeEnabled) ([bool]$actual.autoPurgeEnabled)
    }
    if ($Expected.Location -and $Expected.Location -ne '\') {
        Compare-Value $mismatches 'location' $Expected.Location $actual.location
    }

    if ($mismatches.Count -eq 0) {
        Write-Log "Safe '$SafeName' VALIDATED: all properties match the source." -Level SUCCESS
        Add-Result -Phase 'Validation' -ObjectType 'Safe' -Name $SafeName -Status 'Validated'
        return $true
    }
    foreach ($m in $mismatches) { Write-Log "Safe property mismatch -> $m" -Level ERROR }
    Add-Result -Phase 'Validation' -ObjectType 'Safe' -Name $SafeName -Status 'Mismatch' -Details ($mismatches -join ' | ')
    $script:ExitCode = 1
    return $false
}

function Resolve-MemberSearchIn {
    <#
        Works out the "SearchIn" value Add-PASSafeMember needs in the destination vault:
          - If the user/group already exists as a destination vault object -> 'Vault'
          - Otherwise -> -DestinationDirectoryName if supplied, else ask the operator
        Returns $null if the operator chooses to skip the member.
    #>
    param([Parameter(Mandatory)]$Member)

    $name = [string]$Member.memberName
    $found = $null
    try {
        if ($Member.memberType -eq 'Group') {
            $found = @(Get-PASGroup -search $name -ErrorAction Stop) |
                Where-Object { $_.groupName -eq $name } | Select-Object -First 1
        } else {
            $found = @(Get-PASUser -Search $name -ErrorAction Stop) |
                Where-Object { $_.username -eq $name } | Select-Object -First 1
        }
    }
    catch {
        Write-Log "Lookup of '$name' in the destination vault failed: $($_.Exception.Message)" -Level WARN
    }

    if ($found) {
        Write-Log "Member '$name' exists in the destination vault; SearchIn = 'Vault'." -Level DEBUG
        return 'Vault'
    }
    if ($DestinationDirectoryName) {
        Write-Log "Member '$name' not yet in the destination vault; using directory '$DestinationDirectoryName'."
        return $DestinationDirectoryName
    }

    Write-Log "Member '$name' ($($Member.memberType)) was not found in the destination vault." -Level WARN
    $answer = Read-ValueWithDefault -Prompt "Enter SearchIn for '$name' (directory name or 'Vault'), or '-' to SKIP this member" -Default 'Vault'
    if ([string]::IsNullOrWhiteSpace($answer)) { return $null }
    return $answer
}

function Add-DestinationSafeMembers {
    <#
        Adds each source member to the destination safe with identical permissions and
        membership expiration. Members already present in the destination vault are not changed.
        Returns the list of member names that were requested (for validation).
    #>
    param(
        [Parameter(Mandatory)][string]$SafeName,
        [AllowEmptyCollection()][object[]]$Members = @(),
        [AllowEmptyCollection()][string[]]$ExistingMemberNames = @()
    )

    # Determine once which permission parameters this psPAS version supports.
    $supportedPerms = @($script:SafePermissionNames | Where-Object {
            Test-CommandParameter -Command 'Add-PASSafeMember' -Parameter $_ })
    $unsupported = @($script:SafePermissionNames | Where-Object { $supportedPerms -notcontains $_ })
    if ($unsupported.Count -gt 0) {
        Write-Log "Installed psPAS Add-PASSafeMember does not support: $($unsupported -join ', ')" -Level WARN
    }

    $processed = [System.Collections.Generic.List[string]]::new()

    foreach ($member in $Members) {
        $name = [string]$member.memberName

        # Members already on an existing destination safe are left alone (validated later).
        if ($ExistingMemberNames -contains $name) {
            Write-Log "Member '$name' is already on destination safe '$SafeName'; not re-added."
            Add-Result -Phase 'Destination' -ObjectType 'SafeMember' -Name $name -Status 'AlreadyExists'
            $processed.Add($name)
            continue
        }

        # Handle membership expiration: expired memberships are not copied.
        $expiry = ConvertFrom-UnixTime $member.membershipExpirationDate
        if ($expiry -and $expiry -lt (Get-Date)) {
            Write-Log "Member '$name' membership expired on $expiry in the source vault; NOT copied." -Level WARN
            Add-Result -Phase 'Destination' -ObjectType 'SafeMember' -Name $name -Status 'Skipped' -Details "Expired $expiry"
            continue
        }

        # Work out where the destination vault should look for this user/group.
        $searchIn = Resolve-MemberSearchIn -Member $member
        if (-not $searchIn) {
            Write-Log "Member '$name' skipped by operator." -Level WARN
            Add-Result -Phase 'Destination' -ObjectType 'SafeMember' -Name $name -Status 'Skipped' -Details 'Skipped by operator'
            continue
        }

        # Build the parameter set: identity, location, expiration, and every permission.
        $memberParams = @{
            SafeName    = $SafeName
            MemberName  = $name
            SearchIn    = $searchIn
            ErrorAction = 'Stop'
        }
        if ($expiry) { $memberParams['MembershipExpirationDate'] = $expiry }
        foreach ($perm in $supportedPerms) {
            $memberParams[$perm] = [bool]$member.permissions.$perm
        }

        $granted = @($supportedPerms | Where-Object { $memberParams[$_] })
        Write-Log "Adding member '$name' (SearchIn '$searchIn') with permissions: $($granted -join ', ')"

        try {
            $null = Add-PASSafeMember @memberParams
            Write-Log "Member '$name' ADDED to destination safe '$SafeName'." -Level SUCCESS
            Add-Result -Phase 'Destination' -ObjectType 'SafeMember' -Name $name -Status 'Added' -Details "SearchIn=$searchIn"
            $processed.Add($name)
        }
        catch {
            Write-Log "FAILED to add member '$name': $($_.Exception.Message)" -Level ERROR
            Add-Result -Phase 'Destination' -ObjectType 'SafeMember' -Name $name -Status 'Failed' -Details $_.Exception.Message
            $script:ExitCode = 1
        }
    }
    return , $processed.ToArray()
}

function Test-DestinationSafeMembers {
    <#
        Reads the destination members back and compares every permission of every migrated
        member with the source. Also reports destination-only members (normally just the
        user who created the safe).
    #>
    param(
        [Parameter(Mandatory)][string]$SafeName,
        [AllowEmptyCollection()][object[]]$SourceMembers = @(),
        [AllowEmptyCollection()][string[]]$MemberNamesToCheck = @()
    )

    Write-Log "Validating memberships on destination safe '$SafeName'..."
    $destinationMembers = @(Get-PASSafeMember -SafeName $SafeName -ErrorAction Stop)
    $allOk = $true

    foreach ($src in $SourceMembers | Where-Object { $MemberNamesToCheck -contains $_.memberName }) {
        $tgt = $destinationMembers | Where-Object { $_.memberName -eq $src.memberName } | Select-Object -First 1
        if (-not $tgt) {
            Write-Log "Member '$($src.memberName)' is MISSING from the destination safe." -Level ERROR
            Add-Result -Phase 'Validation' -ObjectType 'SafeMember' -Name $src.memberName -Status 'Missing'
            $allOk = $false
            continue
        }

        Write-Log "Comparing permissions for '$($src.memberName)'..." -Level DEBUG
        $mismatches = [System.Collections.Generic.List[string]]::new()
        foreach ($perm in $script:SafePermissionNames) {
            Compare-Value $mismatches $perm ([bool]$src.permissions.$perm) ([bool]$tgt.permissions.$perm)
        }

        if ($mismatches.Count -eq 0) {
            Write-Log "Member '$($src.memberName)' VALIDATED: permissions match." -Level SUCCESS
            Add-Result -Phase 'Validation' -ObjectType 'SafeMember' -Name $src.memberName -Status 'Validated'
        } else {
            foreach ($m in $mismatches) { Write-Log "Member '$($src.memberName)' mismatch -> $m" -Level ERROR }
            Add-Result -Phase 'Validation' -ObjectType 'SafeMember' -Name $src.memberName -Status 'Mismatch' -Details ($mismatches -join ' | ')
            $allOk = $false
        }
    }

    # Report anything on the destination safe that is not on the source (informational).
    $sourceNames = @($SourceMembers | ForEach-Object { $_.memberName })
    foreach ($extra in $destinationMembers | Where-Object { $sourceNames -notcontains $_.memberName }) {
        Write-Log "Destination-only member '$($extra.memberName)' (normally the safe creator or a built-in member)." -Level INFO
    }

    if (-not $allOk) { $script:ExitCode = 1 }
    return $allOk
}

function Test-DestinationPlatform {
    <#
        Checks (once per platform) that the account's platform exists in the destination vault.
        A failed lookup is logged but does not block creation; Add-PASAccount will
        give the definitive error if the platform is truly missing.
    #>
    param([Parameter(Mandatory)][string]$PlatformId)
    if ($script:PlatformCache.ContainsKey($PlatformId)) { return $script:PlatformCache[$PlatformId] }
    try {
        $null = Get-PASPlatform -PlatformID $PlatformId -ErrorAction Stop
        Write-Log "Platform '$PlatformId' exists in the destination vault." -Level DEBUG
        $script:PlatformCache[$PlatformId] = $true
    }
    catch {
        Write-Log "Platform '$PlatformId' could not be confirmed in the destination vault ($($_.Exception.Message)). Creation will still be attempted." -Level WARN
        $script:PlatformCache[$PlatformId] = $false
    }
    return $script:PlatformCache[$PlatformId]
}

function Import-DestinationAccount {
    <#
        Creates one account in the destination safe from a snapshot, then reads it back and
        validates every property (and optionally the secret).
    #>
    param(
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][string]$SafeName
    )

    $label = "$($Snapshot.UserName)@$($Snapshot.Address) [$($Snapshot.Name)]"
    Write-Log "---- Importing account $label ----"

    # 1. Platform check (informational).
    $null = Test-DestinationPlatform -PlatformId $Snapshot.PlatformId

    # 2. Duplicate check: skip if an account with the same name or user+address is already in the safe.
    try {
        $existing = @(Get-PASAccount -safeName $SafeName -search "$($Snapshot.UserName) $($Snapshot.Address)" -ErrorAction Stop) |
            Where-Object {
                $_.name -eq $Snapshot.Name -or
                ($_.userName -eq $Snapshot.UserName -and $_.address -eq $Snapshot.Address)
            } | Select-Object -First 1
    }
    catch {
        Write-Log "Duplicate check failed for $label : $($_.Exception.Message)" -Level WARN
        $existing = $null
    }
    if ($existing) {
        Write-Log "Account $label already exists in the destination vault (id $($existing.id)); not re-created." -Level WARN
        Add-Result -Phase 'Destination' -ObjectType 'Account' -Name $Snapshot.Name -UserName $Snapshot.UserName `
            -Address $Snapshot.Address -Platform $Snapshot.PlatformId -Status 'AlreadyExists' -DestinationId $existing.id
        return
    }

    # 3. Build the Add-PASAccount parameters (Gen2 parameter set).
    $acctParams = @{
        SafeName    = $SafeName
        platformID  = $Snapshot.PlatformId
        address     = $Snapshot.Address
        userName    = $Snapshot.UserName
        name        = $Snapshot.Name
        secretType  = $Snapshot.SecretType
        ErrorAction = 'Stop'
    }
    if ($Snapshot.Secret) { $acctParams['secret'] = $Snapshot.Secret }
    if ($Snapshot.PlatformAccountProperties.Count -gt 0) {
        $acctParams['platformAccountProperties'] = $Snapshot.PlatformAccountProperties
    }

    $optional = [ordered]@{ automaticManagementEnabled = $Snapshot.AutomaticManagementEnabled }
    if (-not $Snapshot.AutomaticManagementEnabled -and $Snapshot.ManualManagementReason) {
        $optional['manualManagementReason'] = $Snapshot.ManualManagementReason
    }
    if ($Snapshot.RemoteMachines) {
        $optional['remoteMachines'] = $Snapshot.RemoteMachines
        $optional['accessRestrictedToRemoteMachines'] = $Snapshot.AccessRestrictedToRemoteMachines
    }
    foreach ($key in $optional.Keys) {
        if (Test-CommandParameter -Command 'Add-PASAccount' -Parameter $key) {
            $acctParams[$key] = $optional[$key]
        } else {
            Write-Log "Installed psPAS Add-PASAccount does not support -$key; it will not be set." -Level WARN
        }
    }

    # Log the parameters WITHOUT the secret.
    $logView = $acctParams.GetEnumerator() | Where-Object { $_.Key -notin 'secret', 'ErrorAction' } | ForEach-Object {
        if ($_.Value -is [hashtable]) {
            "$($_.Key)={" + (($_.Value.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ') + '}'
        } else { "$($_.Key)='$($_.Value)'" }
    }
    Write-Log "Add-PASAccount parameters: $($logView -join '; '); secret supplied: $([bool]$Snapshot.Secret)"

    # 4. Create the account.
    try {
        $new = Add-PASAccount @acctParams
        Write-Log "Account $label CREATED in the destination vault with id $($new.id)." -Level SUCCESS
    }
    catch {
        Write-Log "FAILED to create account $label : $($_.Exception.Message)" -Level ERROR
        Add-Result -Phase 'Destination' -ObjectType 'Account' -Name $Snapshot.Name -UserName $Snapshot.UserName `
            -Address $Snapshot.Address -Platform $Snapshot.PlatformId -Status 'Failed' -Details $_.Exception.Message
        $script:ExitCode = 1
        return
    }

    # 5. Read the account back and compare every property with the source.
    $mismatches = [System.Collections.Generic.List[string]]::new()
    try {
        $actual = Get-PASAccount -id $new.id -ErrorAction Stop
        Compare-Value $mismatches 'name'       $Snapshot.Name       $actual.name
        Compare-Value $mismatches 'address'    $Snapshot.Address    $actual.address
        Compare-Value $mismatches 'userName'   $Snapshot.UserName   $actual.userName
        Compare-Value $mismatches 'platformId' $Snapshot.PlatformId $actual.platformId
        Compare-Value $mismatches 'safeName'   $SafeName            $actual.safeName
        Compare-Value $mismatches 'secretType' $Snapshot.SecretType $actual.secretType
        if ($acctParams.ContainsKey('automaticManagementEnabled')) {
            Compare-Value $mismatches 'automaticManagementEnabled' $Snapshot.AutomaticManagementEnabled ([bool]$actual.secretManagement.automaticManagementEnabled)
        }
        if ($acctParams.ContainsKey('manualManagementReason')) {
            Compare-Value $mismatches 'manualManagementReason' $Snapshot.ManualManagementReason $actual.secretManagement.manualManagementReason
        }
        if ($acctParams.ContainsKey('remoteMachines')) {
            Compare-Value $mismatches 'remoteMachines' $Snapshot.RemoteMachines $actual.remoteMachinesAccess.remoteMachines
            Compare-Value $mismatches 'accessRestrictedToRemoteMachines' $Snapshot.AccessRestrictedToRemoteMachines ([bool]$actual.remoteMachinesAccess.accessRestrictedToRemoteMachines)
        }
        foreach ($key in $Snapshot.PlatformAccountProperties.Keys) {
            Compare-Value $mismatches "platformAccountProperties.$key" $Snapshot.PlatformAccountProperties[$key] $actual.platformAccountProperties.$key
        }
    }
    catch {
        $mismatches.Add("Could not read the account back for validation: $($_.Exception.Message)")
    }

    # 6. Optional secret validation (compared in memory only, never logged).
    if ($ValidateSecrets -and $Snapshot.Secret) {
        try {
            $destinationSecret = Get-AccountSecret -AccountId $new.id
            $a = ConvertFrom-SecureStringToPlain $Snapshot.Secret
            $b = ConvertFrom-SecureStringToPlain $destinationSecret
            if ($a -cne $b) { $mismatches.Add('secret : destination secret does NOT match the source secret') }
            else { Write-Log "Secret for $label VALIDATED (matches source)." -Level SUCCESS }
            $a = $null; $b = $null; $destinationSecret.Dispose()
        }
        catch {
            $mismatches.Add("secret : could not be retrieved for validation ($($_.Exception.Message))")
        }
    }
    elseif (-not $Snapshot.Secret) {
        Write-Log "Account $label was created WITHOUT a secret; set or reconcile it in the destination vault." -Level WARN
    }

    # 7. Record the outcome.
    if ($mismatches.Count -eq 0) {
        $status  = if ($Snapshot.Secret) { 'Validated' } else { 'Validated (no secret)' }
        Write-Log "Account $label VALIDATED: all properties match the source." -Level SUCCESS
        Add-Result -Phase 'Destination' -ObjectType 'Account' -Name $Snapshot.Name -UserName $Snapshot.UserName `
            -Address $Snapshot.Address -Platform $Snapshot.PlatformId -Status $status -DestinationId $new.id
    } else {
        foreach ($m in $mismatches) { Write-Log "Account $label mismatch -> $m" -Level ERROR }
        Add-Result -Phase 'Destination' -ObjectType 'Account' -Name $Snapshot.Name -UserName $Snapshot.UserName `
            -Address $Snapshot.Address -Platform $Snapshot.PlatformId -Status 'Mismatch' -DestinationId $new.id `
            -Details ($mismatches -join ' | ')
        $script:ExitCode = 1
    }
}

#endregion

#==============================================================================================
#region MAIN SCRIPT
#==============================================================================================

# The in-memory list of accounts selected for migration. Declared outside the
# try block so the finally block can always dispose of any secrets it holds.
$accountsToMigrate = [System.Collections.Generic.List[object]]::new()
$sourceSafeName    = $null

try {
    #--- Banner and run parameters -----------------------------------------------------------
    Write-Log ('=' * 80)
    Write-Log "$($script:ScriptName) started"
    Write-Log "Source PVWA      : $SourcePVWAUrl ($SourceAuthType)"
    Write-Log "Destination PVWA : $DestinationPVWAUrl ($DestinationAuthType)"
    Write-Log "Destination directory for new members : $(if ($DestinationDirectoryName) { $DestinationDirectoryName } else { '(prompt per member)' })"
    Write-Log "Validate secrets after import  : $([bool]$ValidateSecrets)"
    Write-Log ('=' * 80)

    #--- Module check ------------------------------------------------------------------------
    Import-Module psPAS -ErrorAction Stop
    $psPASVersion = (Get-Module psPAS).Version
    Write-Log "psPAS module loaded, version $psPASVersion."

    #--- STEP 1: Source safe name ------------------------------------------------------------
    $sourceSafeName = Read-RequiredValue -Prompt "Enter the name of the safe in the source vault"

    # Now that the safe name is known, create the log file and flush the buffered lines.
    Initialize-Log -SafeName $sourceSafeName

    #--- STEP 2: Migration mode --------------------------------------------------------------
    Write-Host "`nMigration mode:`n  1 = Safe only (properties and memberships)`n  2 = Safe WITH accounts" -ForegroundColor Cyan
    $mode = Read-Choice -Prompt 'Select migration mode' -Choices '1', '2'
    $withAccounts = ($mode -eq '2')
    Write-Log "Migration mode selected: $(if ($withAccounts) { 'Safe WITH accounts' } else { 'Safe only' })"

    #--- STEP 3: Read the source safe --------------------------------------------------------
    $null = Connect-Vault -VaultLabel 'source' -BaseURI $SourcePVWAUrl -AuthType $SourceAuthType

    $sourceSafe    = Get-SourceSafe -SafeName $sourceSafeName
    $sourceMembers = @(Get-SourceSafeMembers -SafeName $sourceSafeName)
    Show-SafeSummary -Safe $sourceSafe -Members $sourceMembers -Title 'SOURCE'

    # Built-in members are created automatically in the destination vault, so only custom members are copied.
    $membersToMigrate = @($sourceMembers | Where-Object { -not $_.isPredefinedUser })
    foreach ($b in $sourceMembers | Where-Object { $_.isPredefinedUser }) {
        Write-Log "Built-in member '$($b.memberName)' will not be copied (the destination vault adds its own)."
    }
    Write-Log "$($membersToMigrate.Count) member(s) selected for migration."

    #--- STEP 4: Export accounts (Safe WITH accounts only) -----------------------------------
    if ($withAccounts) {
        Write-Log "Reading accounts in source safe '$sourceSafeName'..."
        $sourceAccounts = @(Get-PASAccount -safeName $sourceSafeName -ErrorAction Stop)
        Write-Log "Found $($sourceAccounts.Count) account(s) in the source safe." -Level SUCCESS

        if ($sourceAccounts.Count -eq 0) {
            Write-Log 'The source safe contains no accounts; continuing with the safe only.' -Level WARN
            $withAccounts = $false
        }
        else {
            Write-Host "`nAccount export:`n  A = Export ALL accounts`n  O = Review accounts ONE AT A TIME (Y/N each)" -ForegroundColor Cyan
            $exportMode = Read-Choice -Prompt 'Select export mode' -Choices 'A', 'O'
            Write-Log "Export mode: $(if ($exportMode -eq 'A') { 'ALL accounts' } else { 'One at a time' })"

            $i = 0
            foreach ($acct in $sourceAccounts) {
                $i++
                $line = Format-AccountLine $acct
                Write-Log "[$i/$($sourceAccounts.Count)] $line"

                # One-at-a-time: operator confirms each account.
                if ($exportMode -eq 'O') {
                    $ans = Read-Choice -Prompt '  Include this account in the migration?' -Choices 'Y', 'N'
                    if ($ans -eq 'N') {
                        Write-Log "  Skipped by operator: $($acct.name)"
                        Add-Result -Phase 'Export' -ObjectType 'Account' -Name $acct.name -UserName $acct.userName `
                            -Address $acct.address -Platform $acct.platformId -Status 'Skipped' -Details 'Skipped by operator at export'
                        continue
                    }
                }

                # Copy the account's properties into a snapshot object.
                $snap = New-AccountSnapshot -Account $acct

                # Retrieve the secret as a SecureString.
                try {
                    $snap.Secret = Get-AccountSecret -AccountId $acct.id
                    $snap.SecretRetrieved = $true
                    Write-Log "  Secret retrieved for '$($acct.name)'." -Level SUCCESS
                }
                catch {
                    Write-Log "  Could NOT retrieve the secret for '$($acct.name)': $($_.Exception.Message)" -Level ERROR
                    $ans = Read-Choice -Prompt '  Migrate this account WITHOUT its secret (to be set/reconciled in the destination vault)?' -Choices 'Y', 'N'
                    if ($ans -eq 'N') {
                        Add-Result -Phase 'Export' -ObjectType 'Account' -Name $acct.name -UserName $acct.userName `
                            -Address $acct.address -Platform $acct.platformId -Status 'Failed' -Details "Secret retrieval failed: $($_.Exception.Message)"
                        $script:ExitCode = 1
                        continue
                    }
                }

                # Add the snapshot to the array of accounts to be migrated.
                $accountsToMigrate.Add($snap)
                Add-Result -Phase 'Export' -ObjectType 'Account' -Name $snap.Name -UserName $snap.UserName `
                    -Address $snap.Address -Platform $snap.PlatformId -Status 'Exported' -Details "SecretRetrieved=$($snap.SecretRetrieved)"
            }
            Write-Log "$($accountsToMigrate.Count) account(s) selected for migration." -Level SUCCESS
        }
    }

    # Close the source session before touching the destination vault.
    Disconnect-Vault

    #--- STEP 5: Target safe name in the destination vault -----------------------------------
    $destinationSafeName = Read-ValueWithDefault -Prompt 'Enter the safe name to use in the destination vault' `
        -Default $sourceSafe.safeName -Validator { param($v) Test-SafeNameFormat $v } `
        -ValidationMessage 'Safe names must be 1-28 characters, have no leading/trailing spaces, and not contain \ / : * ? " < > |'
    Write-Log "Destination safe name: '$destinationSafeName'"

    #--- STEP 6: Connect to the destination vault and find or create the safe ----------------
    $destinationUser  = Connect-Vault -VaultLabel 'destination' -BaseURI $DestinationPVWAUrl -AuthType $DestinationAuthType
    $destinationSafe  = Find-DestinationSafe -SafeName $destinationSafeName
    $syncMembers = $false

    # Show the operator what is about to happen and get a final go-ahead.
    Write-Host "`n===== PLANNED CHANGES IN DESTINATION =====" -ForegroundColor Cyan
    Write-Host "  Target safe : $destinationSafeName ($(if ($destinationSafe) { 'EXISTS - will not be created' } else { 'will be CREATED' }))"
    Write-Host "  Members     : $($membersToMigrate.Count)"
    Write-Host "  Accounts    : $($accountsToMigrate.Count)"
    $go = Read-Choice -Prompt 'Proceed with changes in the destination vault?' -Choices 'Y', 'N'
    if ($go -eq 'N') {
        Write-Log 'Operator cancelled before any changes were made in the destination vault.' -Level WARN
        return
    }

    if ($destinationSafe) {
        # The safe exists, so it is not created. Optionally add any missing members.
        Show-SafeSummary -Safe $destinationSafe -Members @(Get-PASSafeMember -SafeName $destinationSafeName) -Title 'DESTINATION EXISTING'
        $ans = Read-Choice -Prompt 'The destination safe already exists. Add any members that are missing compared to the source?' -Choices 'Y', 'N'
        $syncMembers = ($ans -eq 'Y')
        Add-Result -Phase 'Destination' -ObjectType 'Safe' -Name $destinationSafeName -Status 'AlreadyExists'
    }
    else {
        # Create the safe and validate its properties.
        $expectedSafe = New-DestinationSafe -SafeName $destinationSafeName -SourceSafe $sourceSafe
        $null = Test-DestinationSafe -SafeName $destinationSafeName -Expected $expectedSafe
        $syncMembers = $true
    }

    #--- STEP 7: Members ---------------------------------------------------------------------
    if ($syncMembers -and $membersToMigrate.Count -gt 0) {
        $existingNames = @(Get-PASSafeMember -SafeName $destinationSafeName -ErrorAction Stop | ForEach-Object { $_.memberName })
        $processedNames = Add-DestinationSafeMembers -SafeName $destinationSafeName -Members $membersToMigrate -ExistingMemberNames $existingNames
        $null = Test-DestinationSafeMembers -SafeName $destinationSafeName -SourceMembers $membersToMigrate -MemberNamesToCheck $processedNames
        Show-SafeSummary -Safe (Get-PASSafe -SafeName $destinationSafeName) `
            -Members @(Get-PASSafeMember -SafeName $destinationSafeName) -Title 'DESTINATION RESULT'
    }
    elseif (-not $syncMembers) {
        Write-Log 'Member synchronisation skipped.'
    }

    #--- STEP 8: Import accounts -------------------------------------------------------------
    if ($withAccounts -and $accountsToMigrate.Count -gt 0) {
        Write-Host "`nAccount import:`n  A = Import ALL $($accountsToMigrate.Count) exported account(s)`n  O = Import ONE AT A TIME (Y/N each)" -ForegroundColor Cyan
        $importMode = Read-Choice -Prompt 'Select import mode' -Choices 'A', 'O'
        Write-Log "Import mode: $(if ($importMode -eq 'A') { 'ALL accounts' } else { 'One at a time' })"

        $i = 0
        foreach ($snap in $accountsToMigrate) {
            $i++
            Write-Log ("[{0}/{1}] {2} | {3}@{4} | Platform: {5} | Secret: {6}" -f
                $i, $accountsToMigrate.Count, $snap.Name, $snap.UserName, $snap.Address, $snap.PlatformId, $snap.SecretRetrieved)

            if ($importMode -eq 'O') {
                $ans = Read-Choice -Prompt '  Import this account into the destination vault?' -Choices 'Y', 'N'
                if ($ans -eq 'N') {
                    Write-Log "  Skipped by operator: $($snap.Name)"
                    Add-Result -Phase 'Destination' -ObjectType 'Account' -Name $snap.Name -UserName $snap.UserName `
                        -Address $snap.Address -Platform $snap.PlatformId -Status 'Skipped' -Details 'Skipped by operator at import'
                    continue
                }
            }
            Import-DestinationAccount -Snapshot $snap -SafeName $destinationSafeName
        }
    }

    Disconnect-Vault
    Write-Log 'Migration workflow complete.' -Level SUCCESS
}
catch {
    # Any unhandled error ends up here: log the message and where it happened.
    Write-Log "FATAL ERROR: $($_.Exception.Message)" -Level ERROR
    Write-Log "At: $($_.InvocationInfo.PositionMessage)" -Level ERROR
    Write-Log "Stack: $($_.ScriptStackTrace)" -Level ERROR -NoConsole
    $script:ExitCode = 1
}
finally {
    # Always log off, whatever happened.
    Disconnect-Vault

    # If the script failed before a safe name was entered, still write the log file.
    if (-not $script:LogFile) { Initialize-Log -SafeName 'NoSafeSpecified' }

    # Dispose of every secret held in memory.
    foreach ($s in $accountsToMigrate) {
        if ($s.Secret) { $s.Secret.Dispose(); $s.Secret = $null }
    }
    Write-Log 'In-memory secrets cleared.' -Level DEBUG

    #--- STEP 9: Final summary and CSV export ------------------------------------------------
    if ($script:Results.Count -gt 0) {
        Write-LogBlock -Text ("`n===== MIGRATION RESULTS =====" +
            ($script:Results | Format-Table Phase, ObjectType, Name, UserName, Address, Status, DestinationId -AutoSize | Out-String -Width 4096))

        $counts = $script:Results | Group-Object ObjectType, Status | Sort-Object Name |
            ForEach-Object { "$($_.Name): $($_.Count)" }
        Write-Log "Totals -> $($counts -join ' | ')"

        $csvPath = [System.IO.Path]::ChangeExtension($script:LogFile, '.csv')
        try {
            $script:Results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Log "Results exported to $csvPath"
        }
        catch {
            Write-Log "Could not export results CSV: $($_.Exception.Message)" -Level WARN
        }
    }

    $elapsed = (Get-Date) - $script:ScriptStart
    $finalLevel = if ($script:ExitCode -eq 0) { 'SUCCESS' } else { 'WARN' }
    Write-Log ("Script finished in {0:hh\:mm\:ss}. Exit code {1}. Log: {2}" -f $elapsed, $script:ExitCode, $script:LogFile) -Level $finalLevel
}

exit $script:ExitCode

#endregion
