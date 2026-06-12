#Requires -Version 5.1
<#
.SYNOPSIS
    Creates personal privileged accounts and their dedicated safes in CyberArk using the v2 REST API.
.DESCRIPTION
    Reads a CSV of privileged accounts, creates a personal safe per user (if it does not already
    exist), adds the account owner and any configured default members, then bulk-onboards all
    accounts via the CyberArk Bulk Accounts API.

    Configuration is layered (lowest to highest priority):
      1. Script baseline defaults
      2. PersonalPrivilegedAccounts.json — SafeConfigSet.default / UserConfigSet.default
      3. Named config sets  (-SafeConfigSet / -UserConfigSet)
      4. Explicit parameters (always win)

    Supports CyberArk on-premises (cyberark / ldap / radius) and Privilege Cloud
    (pass a pre-obtained PCloud token via -logonToken).
.PARAMETER PVWAURL
    Base URL of the CyberArk PVWA (e.g. https://pvwa.company.com/PasswordVault).
    Always required. The URL is never embedded in a logon token and must be supplied separately.
.PARAMETER AuthenticationType
    Authentication type for on-premises logon: cyberark | ldap | radius. Default: cyberark.
.PARAMETER OTP
    RADIUS one-time password. Appended to the password with a comma delimiter.
.PARAMETER PVWACredentials
    PSCredential for on-premises authentication. If omitted, an interactive prompt is shown.
.PARAMETER logonToken
    Pre-obtained logon token (string or hashtable). When supplied, logon/logoff are skipped.
    Use for Privilege Cloud tokens obtained from Get-IdentityHeader.
.PARAMETER DisableCertificateValidation
    Bypasses SSL certificate validation. Use only in test environments.
.PARAMETER SafeNamePattern
    Safe name pattern containing exactly one wildcard (*). The asterisk is replaced by the user
    name from each CSV row. Default: *_ADM. Overrides the config file value.
.PARAMETER PlatformID
    Default platform ID for accounts that do not specify one in the CSV. Default: WinDomain.
    Overrides the config file value.
.PARAMETER CSVPath
    Path to the accounts CSV file. If omitted, a file picker dialog is shown.
.PARAMETER ConfigPath
    Path to PersonalPrivilegedAccounts.json. If omitted, the script looks in its own directory.
.PARAMETER SafeConfigSet
    Named set within SafeConfigSet in the config file to apply. Defaults to the "default" set.
.PARAMETER UserConfigSet
    Named set within UserConfigSet in the config file to apply. Defaults to the "default" set.
.PARAMETER CPMName
    CPM name for new safes. Overrides the config file value.
.PARAMETER NumberOfVersionsRetention
    Number of password versions to retain. Mutually exclusive with -NumberOfDaysRetention.
    Overrides the config file value.
.PARAMETER NumberOfDaysRetention
    Number of days to retain passwords. Mutually exclusive with -NumberOfVersionsRetention.
    Wins when both are supplied. Overrides the config file value.
.PARAMETER FallbackOnInvalidConfigSet
    When a CSV row specifies a SafeConfigSet or UserConfigSet that does not exist in the
    config file, log a warning and fall back to the base resolved config instead of skipping
    the row. By default (without this switch) an invalid set name is treated as an error
    and the row is skipped.
.PARAMETER AllowDuplicateAccounts
    When an existing safe already contains an account with the same userName, address and
    platformId, allow a second account to be created. Without this switch (the default)
    the script checks for a matching account in any existing safe before onboarding; if a
    duplicate is found it logs a warning and skips that row.
    Note: this check is only performed for safes that already exist. When the safe is newly
    created there can be no existing accounts, so no check is needed.
.PARAMETER CreateSafeOnly
    Create the safe and add all configured members, but do not onboard any account.
    The userName column is still required to set the safe name pattern and safe owner.
    Can also be set per-row via a CSV 'createSafeOnly' column, or per UserConfigSet via
    Options.createSafeOnly in the config file.
.OUTPUTS
    None. Progress and results are written to the log file and console.
.EXAMPLE
    .\Create-PersonalPrivilgedAccounts.ps1 -PVWAURL https://pvwa.company.com -CSVPath .\accounts.csv

    Authenticates interactively and onboards accounts using baseline defaults.
.EXAMPLE
    $params = @{
        PVWAURL         = 'https://pvwa.company.com'
        SafeConfigSet   = 'prod'
        UserConfigSet   = 'prod'
        CSVPath         = '.\accounts.csv'
        PVWACredentials = (Get-Credential)
    }
    .\Create-PersonalPrivilgedAccounts.ps1 @params

    Applies the "prod" named config sets for safe and user settings.
.EXAMPLE
    $PCloudURL = 'https://tenant.privilegecloud.cyberark.cloud/PasswordVault'
    $identityParams = @{
        IdentityTenantURL  = 'https://tenant.id.cyberark.cloud'
        PCloudTenantAPIURL = 'https://tenant.privilegecloud.cyberark.cloud'
    }
    $token = Get-IdentityHeader @identityParams
    .\Create-PersonalPrivilgedAccounts.ps1 -logonToken $token -PVWAURL $PCloudURL -CSVPath .\accounts.csv

    Uses a pre-obtained Privilege Cloud token; no logon/logoff is performed.
    PVWAURL must always be supplied — it is never embedded in the token.
.NOTES
    Version:       2.0
    Requires:      PowerShell 5.1+, CyberArk PVWA v12.1+ (v2 REST API)
    Related files: PersonalPrivilegedAccounts.json (config), accounts CSV
#>
[CmdletBinding()]
param
(
    #region Connection parameters
    [Parameter(Mandatory = $false, HelpMessage = 'Please enter your PVWA address (e.g. https://pvwa.mydomain.com/PasswordVault)')]
    [Alias('url')]
    [ValidateNotNullOrEmpty()]
    [String]$PVWAURL,

    [Parameter(Mandatory = $false, HelpMessage = 'Enter the Authentication type (Default:CyberArk)')]
    [ValidateSet('cyberark', 'ldap', 'radius')]
    [String]$AuthenticationType = 'cyberark',

    [Parameter(Mandatory = $false, HelpMessage = 'Enter the RADIUS OTP')]
    [String]$OTP,

    [Parameter(Mandatory = $false, HelpMessage = 'PSCredential for on-prem authentication. If omitted, will prompt interactively.')]
    [PSCredential]$PVWACredentials,

    [Parameter(Mandatory = $false, HelpMessage = 'Pre-obtained logon token (string or hashtable). Skips logon/logoff. Use for PCloud tokens from Get-IdentityHeader.')]
    $logonToken,

    # Use this switch to Disable SSL verification (NOT RECOMMENDED)
    [Parameter(Mandatory = $false)]
    [Switch]$DisableCertificateValidation,
    #endregion

    #region Safe / Account parameters
    [Parameter(Mandatory = $false, HelpMessage = 'Enter the safe name pattern to use (must contain exactly one *)')]
    [Alias('pattern')]
    [ValidateScript({ ($_.ToCharArray() | Where-Object { $PSItem -eq '*' } | Measure-Object).Count -eq 1 })]
    [string]$SafeNamePattern = '*_ADM',

    [Parameter(Mandatory = $false, HelpMessage = 'Enter the Platform ID (Default:WinDomain)')]
    [string]$PlatformID = 'WinDomain',

    [Parameter(Mandatory = $false, HelpMessage = 'Enter the Accounts CSV path')]
    [ValidateScript( { Test-Path -Path $_ -PathType Leaf -IsValid })]
    [Alias('path')]
    [string]$CSVPath,
    #endregion

    #region Config / retention overrides
    [Parameter(Mandatory = $false, HelpMessage = 'Path to PersonalPrivilegedAccounts.json config file. If omitted, looks for the file in the script directory.')]
    [string]$ConfigPath,

    [Parameter(Mandatory = $false, HelpMessage = 'Named set within SafeConfigSet to use. Defaults to the "default" set.')]
    [string]$SafeConfigSet,

    [Parameter(Mandatory = $false, HelpMessage = 'Named set within UserConfigSet to use. Defaults to the "default" set.')]
    [string]$UserConfigSet,

    [Parameter(Mandatory = $false, HelpMessage = 'CPM name override. Overrides config file value.')]
    [string]$CPMName,

    [Parameter(Mandatory = $false, HelpMessage = 'Number of password versions to retain. Mutually exclusive with NumberOfDaysRetention. Overrides config.')]
    [ValidateRange(1, 999)]
    [int]$NumberOfVersionsRetention,

    [Parameter(Mandatory = $false, HelpMessage = 'Number of days to retain passwords. Mutually exclusive with NumberOfVersionsRetention. Overrides config. Wins if both supplied.')]
    [ValidateRange(1, 3650)]
    [int]$NumberOfDaysRetention,
    #endregion

    [Parameter(Mandatory = $false,
        HelpMessage = 'When a CSV row names a SafeConfigSet or UserConfigSet that does not exist, warn and fall back to base config instead of skipping the row.')]
    [switch]$FallbackOnInvalidConfigSet,

    [Parameter(Mandatory = $false,
        HelpMessage = 'Allow a second account with the same userName/address/platformId to be onboarded into an existing safe. By default duplicates are detected and skipped.')]
    [switch]$AllowDuplicateAccounts,

    [Parameter(Mandatory = $false,
        HelpMessage = 'Create the safe and members only; do not onboard any account. userName is still required for safe naming and ownership. Can also be set per-row (CSV column) or per UserConfigSet (Options.createSafeOnly).')]
    [switch]$CreateSafeOnly,

    #region Troubleshooting parameters
    [Parameter(Mandatory = $false, DontShow = $true,
        HelpMessage = 'Write a separate verbose log file alongside the main log. Intended for deep troubleshooting only.')]
    [switch]$UseVerboseFile
    #endregion
)

# Get Script Location
$ScriptFullPath = $MyInvocation.MyCommand.Path
$ScriptLocation = Split-Path -Parent $ScriptFullPath
$scriptParamsStr = ($PSBoundParameters.GetEnumerator() | ForEach-Object { '-{0} ''{1}''' -f $PSItem.Key, $PSItem.Value }) -join ' '
$script:g_ScriptCommand = '{0} {1}' -f $ScriptFullPath, $scriptParamsStr

# Script Version
$ScriptVersion = '2.0'

# Set Log file path
$LOG_FILE_PATH = "$ScriptLocation\PersonalPrivilegedAccounts.log"

$InDebug = $PSBoundParameters.Debug.IsPresent
$InVerbose = $PSBoundParameters.Verbose.IsPresent

# Baseline defaults (lowest priority - overridden by config then by parameters)
$script:DEFAULT_CPM_NAME = 'PasswordManager'
$script:DEFAULT_DAYS_RETENTION = 7
$script:DEFAULT_SAFE_PATTERN = '*_ADM'
$script:DEFAULT_PLATFORM_ID = 'WinDomain'

# Global script state
$script:g_LogonHeader = $null
$script:g_SSLChanged = $false
$script:g_LogAccountName = ''
$script:g_CsvDefaultPath = Join-Path -Path ([Environment]::GetFolderPath('UserProfile')) -ChildPath 'Downloads'
$script:g_DefaultUsers = @('Master', 'Batch', 'Backup Users', 'Auditors', 'Operators', 'DR Users',
    'Notification Engines', 'PVWAGWAccounts', 'PVWAGWUser', 'PVWAAppUser', 'PasswordManager')
$script:g_ShouldLogoff = $true   # set to $false when $logonToken is passed in
$script:Config = $null   # populated by Import-ScriptConfig
$script:g_JsonContent = $null   # raw parsed JSON; retained for per-row config lookups

# Global URLs - populated by Initialize-ScriptURLs after PVWA URL is normalized
$script:URL_PVWAAPI = $null
$script:URL_Logon = $null
$script:URL_Logoff = $null
$script:URL_Safes = $null
$script:URL_SafeDetails = $null
$script:URL_SafeMembers = $null
$script:URL_BulkAccounts = $null
$script:URL_BulkAccountsTask = $null
$script:URL_Accounts = $null

#region Functions

#region Writer Functions
function Remove-SensitiveData {
    <#
.SYNOPSIS
    Masks sensitive field values in a log message string.
.DESCRIPTION
    Replaces values of known sensitive fields (password, secret, access_token,
    Authorization, Token, etc.) with ****.
    Set $global:LogSensitiveData = $true to bypass masking for debugging.
.PARAMETER message
    The message string to sanitize.
#>
    [CmdletBinding()]
    param (
        [Alias('MSG', 'value', 'string')]
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$message
    )
    begin {
        $cleanedMessage = $message
    }
    process {
        if ($global:LogSensitiveData -eq $true) {
            return $message
        }
        $checkFor = @('password', 'secret', 'NewCredentials', 'access_token', 'client_secret', 'auth', 'Authorization', 'Answer', 'Token')
        $checkFor | ForEach-Object {
            if ($cleanedMessage -imatch "[{\\""']{2,}\s{0,}$PSitem\s{0,}[\\""']{2,}\s{0,}[:=][\\""']{2,}\s{0,}(?<Sensitive>.*?)\s{0,}[\\""']{2,}(?=[,:;])") {
                $cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
            } elseif ($cleanedMessage -imatch "[""']{1,}\s{0,}$PSitem\s{0,}[""']{1,}\s{0,}[:=][""']{1,}\s{0,}(?<Sensitive>.*?)\s{0,}[""']{1,}") {
                $cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
            } elseif ($cleanedMessage -imatch "(?:\s{0,}$PSitem\s{0,}[:=])\s{0,}(?<Sensitive>.*?)(?=; |:|,|}|\))") {
                $cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
            }
        }
    }
    end {
        return $cleanedMessage
    }
}

function Write-LogMessage {
    <#
.SYNOPSIS
    Method to log a message on screen and in a log file.
.DESCRIPTION
    Logs to file and writes coloured output to the screen.
    Supports verbose file, call stack tracing, and sensitive data masking.
.PARAMETER MSG
    The message to log.
.PARAMETER Header
    Write a header separator before the message.
.PARAMETER SubHeader
    Write a sub-header separator before the message.
.PARAMETER Footer
    Write a footer separator after the message.
.PARAMETER type
    Info | Warning | Error | Debug | Verbose  (default: Info)
.PARAMETER LogFile
    Log file path. Defaults to $LOG_FILE_PATH.
.PARAMETER pad
    Column width for verbose alignment (default: 20).
#>
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [Switch]$Header,
        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory = $false)]
        [Switch]$Footer,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Debug', 'Verbose')]
        [String]$type = 'Info',
        [Parameter(Mandatory = $false)]
        [int]$pad = 20
    )

    $verboseFile = $($LOG_FILE_PATH.replace('.log', '_Verbose.log'))
    try {
        if ($Header) {
            '=======================================' | Out-File -Append -FilePath $LOG_FILE_PATH
            Write-Host '======================================='
        } elseif ($SubHeader) {
            '------------------------------------' | Out-File -Append -FilePath $LOG_FILE_PATH
            Write-Host '------------------------------------'
        }

        $LogTime = "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')]`t"
        $msgToWrite = "$LogTime"
        $writeToFile = $true

        if ([string]::IsNullOrEmpty($Msg)) {
            $Msg = 'N/A'
        }
        $Msg = Remove-SensitiveData -message $Msg

        switch ($type) {
            'Info' {
                Write-Host $MSG
                $msgToWrite += "[INFO]`t`t$Msg"
            }
            'Warning' {
                Write-Host $MSG -ForegroundColor DarkYellow
                $msgToWrite += "[WARNING]`t$Msg"
                if ($UseVerboseFile) {
                    $msgToWrite | Out-File -Append -FilePath $verboseFile
                }
            }
            'Error' {
                Write-Host $MSG -ForegroundColor Red
                $msgToWrite += "[ERROR]`t`t$Msg"
                if ($UseVerboseFile) {
                    $msgToWrite | Out-File -Append -FilePath $verboseFile
                }
            }
            'Debug' {
                if ($InDebug -or $InVerbose) {
                    Write-Debug $MSG
                    $writeToFile = $true
                    $msgToWrite += "[DEBUG]`t`t$Msg"
                } else {
                    $writeToFile = $false
                }
            }
            'Verbose' {
                if ($InVerbose -or $UseVerboseFile) {
                    $arrMsg = $Msg.split(":`t", 2)
                    if ($arrMsg.Count -gt 1) {
                        $Msg = $arrMsg[0].PadRight($pad) + $arrMsg[1]
                    }
                    $msgToWrite += "[VERBOSE]`t$Msg"
                    if ($global:IncludeCallStack) {
                        function Get-CallStack {
                            $stack = ''
                            $excludeItems = @('Write-LogMessage', 'Get-CallStack', '<ScriptBlock>')
                            Get-PSCallStack | ForEach-Object {
                                if ($PSItem.Command -notin $excludeItems) {
                                    $command = $PSItem.Command
                                    if ($command -eq $Global:scriptName) {
                                        $command = 'Base'
                                    } elseif ([string]::IsNullOrEmpty($command)) {
                                        $command = '**Blank**'
                                    }
                                    $stack = $stack + "$command $($PSItem.Location); "
                                }
                            }
                            return $stack
                        }
                        $stack = Get-CallStack
                        $stackMsg = "CallStack:`t$stack"
                        $arrStack = $stackMsg.split(":`t", 2)
                        if ($arrStack.Count -gt 1) {
                            $stackMsg = $arrStack[0].PadRight($pad) + $arrStack[1].trim()
                        }
                        Write-Verbose $stackMsg
                        $msgToWrite += "`n$LogTime[STACK]`t`t$stackMsg"
                    }
                    if ($InVerbose) {
                        Write-Verbose $MSG
                    } else {
                        $writeToFile = $false
                    }
                    if ($UseVerboseFile) {
                        $msgToWrite | Out-File -Append -FilePath $verboseFile
                    }
                } else {
                    $writeToFile = $false
                }
            }
        }
        if ($writeToFile) {
            $msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH
        }
        if ($Footer) {
            '=======================================' | Out-File -Append -FilePath $LOG_FILE_PATH
            Write-Host '======================================='
        }
    } catch {
        Write-Error "Error writing log: $($PSItem.Exception.Message)"
    }
}

function Join-ExceptionMessage {
    <#
.SYNOPSIS
    Formats an exception and all inner exceptions into a single readable string.
.DESCRIPTION
    Walks the InnerException chain and appends each level with arrow notation
    (->Source; Message) for easy log output.
.PARAMETER e
    The Exception object to format.
.OUTPUTS
    System.String
#>
    param (
        [Parameter(Mandatory = $true)]
        [Exception]$e
    )
    $msg = 'Source:{0}; Message: {1}' -f $e.Source, $e.Message
    while ($e.InnerException) {
        $e = $e.InnerException
        $msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
    }
    return $msg
}
#endregion Writer Functions

#region Helper Functions
function Format-PVWAURL {
    <#
.SYNOPSIS
    Normalizes a PVWA URL ensuring correct scheme and /PasswordVault/ path.
.DESCRIPTION
    - Upgrades http:// to https://
    - Corrects malformed Privilege Cloud URLs (.cyberark.cloud/privilegecloud/...)
    - Appends /PasswordVault/ if missing
.PARAMETER PVWAURL
    The raw PVWA URL to normalize.
#>
    param (
        [Parameter(Mandatory = $true)]
        [string]$PVWAURL
    )
    if ($PVWAURL -match '^(?<scheme>https:\/\/|http:\/\/|).*$') {
        if ('http://' -eq $Matches['scheme']) {
            $PVWAURL = $PVWAURL.Replace('http://', 'https://')
            Write-LogMessage -type Warning -MSG "Detected insecure URL scheme. Updated to: $PVWAURL"
        } elseif ([string]::IsNullOrEmpty($Matches['scheme'])) {
            $PVWAURL = "https://$PVWAURL"
            Write-LogMessage -type Warning -MSG "Detected missing URL scheme. Updated to: $PVWAURL"
        }
    }
    if ($PVWAURL -match '^(?:https|http):\/\/(?<sub>.*).cyberark.(?<top>cloud|com)\/privilegecloud.*$') {
        $PVWAURL = "https://$($Matches['sub']).privilegecloud.cyberark.$($Matches['top'])/PasswordVault/"
        Write-LogMessage -type Warning -MSG "Detected improperly formatted Privilege Cloud URL. Updated to: $PVWAURL"
    } elseif ($PVWAURL -notmatch '^.*PasswordVault(?:\/|)$') {
        $PVWAURL = "$PVWAURL/PasswordVault/"
        Write-LogMessage -type Warning -MSG "Detected missing /PasswordVault/. Updated to: $PVWAURL"
    }
    # Ensure URL always ends with a trailing slash so URL concatenation works correctly
    if (-not $PVWAURL.EndsWith('/')) {
        $PVWAURL = "$PVWAURL/"
    }
    return $PVWAURL
}

function Initialize-ScriptURLs {
    <#
.SYNOPSIS
    Initializes all REST API URL variables from the normalized $PVWAURL.
.DESCRIPTION
    Populates script-scoped URL variables used by all Invoke-Rest calls.
    Must be called after $PVWAURL has been normalized by Format-PVWAURL.
#>
    $script:URL_PVWAAPI = $PVWAURL + 'api/'
    $authBase = $script:URL_PVWAAPI + 'auth'
    $script:URL_Logon = $authBase + "/$AuthenticationType/Logon"
    $script:URL_Logoff = $authBase + '/Logoff'
    $script:URL_Safes = $script:URL_PVWAAPI + 'Safes'
    $script:URL_SafeDetails = $script:URL_Safes + '/{0}'
    $script:URL_SafeMembers = $script:URL_SafeDetails + '/Members'
    $script:URL_BulkAccounts = $script:URL_PVWAAPI + 'BulkActions/Accounts'
    $script:URL_BulkAccountsTask = $script:URL_PVWAAPI + 'BulkActions/Accounts/{0}'
    $script:URL_Accounts = $script:URL_PVWAAPI + 'Accounts'
    Write-LogMessage -type Debug -MSG "URLs initialized. Base API: $($script:URL_PVWAAPI)"
}

function Import-ScriptConfig {
    <#
.SYNOPSIS
    Loads PersonalPrivilegedAccounts.json and resolves the active named sets.
.DESCRIPTION
    The config file has two independent top-level sections: SafeConfigSet and
    UserConfigSet. Each section has its own "default" named set plus any number
    of additional named sets.

    Resolution order (lowest to highest priority):
      1. Script baseline defaults
      2. SafeConfigSet.default  /  UserConfigSet.default
      3. SafeConfigSet.<name>   (if -SafeConfigSet supplied)
         UserConfigSet.<name>   (if -UserConfigSet supplied)
      4. Explicit command-line parameters (always win)

    NumberOfVersionsRetention and NumberOfDaysRetention are mutually exclusive.
    If both are present after all layers are merged, NumberOfDaysRetention wins
    and a warning is emitted. DefaultSafeMembers is replaced wholesale by the
    named set when it defines the key; otherwise falls back to the default set.
#>
    # Start with baseline defaults
    $resolved = @{
        CPMName                   = $script:DEFAULT_CPM_NAME
        NumberOfVersionsRetention = $null
        NumberOfDaysRetention     = $script:DEFAULT_DAYS_RETENTION
        SafeNamePattern           = $script:DEFAULT_SAFE_PATTERN
        UserDefaults              = @{ accountPlatform = $script:DEFAULT_PLATFORM_ID }
        DefaultSafeMembers        = @()
        RoleConfigSets            = @{}
        SafeEndUserRole           = 'EndUser'
        SafeEndUserRoleConfigSet  = $null
        SafeEndUserSearchIn       = ''
        SafeEndUserMemberType     = ''
        SafeOptions               = @{ useExisting = $true }
        UserOptions               = @{ accountUserPattern = $null; allowDuplicateAccounts = $false; createSafeOnly = $false }
    }

    # Locate config file
    $effectiveConfigPath = $null
    if (-not [string]::IsNullOrEmpty($ConfigPath) -and (Test-Path -Path $ConfigPath -PathType Leaf)) {
        $effectiveConfigPath = $ConfigPath
    } else {
        $autoConfig = Join-Path -Path $ScriptLocation -ChildPath 'PersonalPrivilegedAccounts.json'
        if (Test-Path -Path $autoConfig -PathType Leaf) {
            $effectiveConfigPath = $autoConfig
        }
    }

    if (-not [string]::IsNullOrEmpty($effectiveConfigPath)) {
        Write-LogMessage -type Info -MSG "Loading config from: $effectiveConfigPath"
        try {
            $jsonContent = Get-Content -Path $effectiveConfigPath -Raw | ConvertFrom-Json
            $script:g_JsonContent = $jsonContent   # retained for per-row SafeConfigSet / UserConfigSet lookups

            # Load all RoleConfigSet entries (flat dictionary - no named-set layering)
            if ($null -ne $jsonContent.RoleConfigSet) {
                $jsonContent.RoleConfigSet.PSObject.Properties | ForEach-Object {
                    $roleName = $PSItem.Name
                    $rolePerms = @{}
                    $PSItem.Value.PSObject.Properties | ForEach-Object { $rolePerms[$PSItem.Name] = $PSItem.Value }
                    $resolved.RoleConfigSets[$roleName] = $rolePerms
                    Write-LogMessage -type Verbose -MSG "Import-ScriptConfig:`tLoaded RoleConfigSet: $roleName"
                }
            }

            function Merge-SafeSet {
                param([Parameter(Mandatory = $true)] $Set)
                $props = $Set.Properties
                $opts = $Set.Options
                if ($null -ne $props) {
                    if (-not [string]::IsNullOrEmpty($props.CPMName)) {
                        $resolved.CPMName = $props.CPMName
                    }
                    if ($null -ne $props.NumberOfVersionsRetention) {
                        $resolved.NumberOfVersionsRetention = $props.NumberOfVersionsRetention
                        $resolved.NumberOfDaysRetention = $null
                    }
                    if ($null -ne $props.NumberOfDaysRetention) {
                        $resolved.NumberOfDaysRetention = $props.NumberOfDaysRetention
                        $resolved.NumberOfVersionsRetention = $null
                    }
                    if (-not [string]::IsNullOrEmpty($props.SafeNamePattern)) {
                        $resolved.SafeNamePattern = $props.SafeNamePattern
                    }
                    if ($null -ne $props.DefaultSafeMembers) {
                        $resolved.DefaultSafeMembers = $props.DefaultSafeMembers
                    }
                    if (-not [string]::IsNullOrEmpty($props.SafeEndUserRoleConfigSet)) {
                        $resolved.SafeEndUserRoleConfigSet = $props.SafeEndUserRoleConfigSet
                        $resolved.SafeEndUserRole = $null
                    } elseif (-not [string]::IsNullOrEmpty($props.SafeEndUserRole)) {
                        $resolved.SafeEndUserRole = $props.SafeEndUserRole
                        $resolved.SafeEndUserRoleConfigSet = $null
                    }
                    if (-not [string]::IsNullOrEmpty($props.SafeEndUserSearchIn)) {
                        $resolved.SafeEndUserSearchIn = $props.SafeEndUserSearchIn
                    }
                    if (-not [string]::IsNullOrEmpty($props.SafeEndUserMemberType)) {
                        $resolved.SafeEndUserMemberType = $props.SafeEndUserMemberType
                    }
                }
                if ($null -ne $opts -and $null -ne $opts.useExisting) {
                    $resolved.SafeOptions['useExisting'] = [bool]$opts.useExisting
                }
            }

            # Properties keys match CSV column names (account field defaults).
            # Options keys are behavioral settings (accountUserPattern, allowDuplicateAccounts).
            function Merge-UserSet {
                param([Parameter(Mandatory = $true)] $Set)
                if ($null -ne $Set.Properties) {
                    $Set.Properties.PSObject.Properties | ForEach-Object {
                        $resolved.UserDefaults[$PSItem.Name] = $PSItem.Value
                    }
                }
                if ($null -ne $Set.Options) {
                    if (-not [string]::IsNullOrEmpty($Set.Options.accountUserPattern)) {
                        $resolved.UserOptions['accountUserPattern'] = $Set.Options.accountUserPattern
                    }
                    if ($null -ne $Set.Options.allowDuplicateAccounts) {
                        $resolved.UserOptions['allowDuplicateAccounts'] = [bool]$Set.Options.allowDuplicateAccounts
                    }
                    if ($null -ne $Set.Options.createSafeOnly) {
                        $resolved.UserOptions['createSafeOnly'] = [bool]$Set.Options.createSafeOnly
                    }
                }
            }

            # Layer 2: SafeConfigSet.default
            if ($null -ne $jsonContent.SafeConfigSet -and $null -ne $jsonContent.SafeConfigSet.default) {
                Write-LogMessage -type Verbose -MSG 'Import-ScriptConfig:`tApplying SafeConfigSet.default'
                Merge-SafeSet -Set $jsonContent.SafeConfigSet.default
            }

            # Layer 2: UserConfigSet.default
            if ($null -ne $jsonContent.UserConfigSet -and $null -ne $jsonContent.UserConfigSet.default) {
                Write-LogMessage -type Verbose -MSG 'Import-ScriptConfig:`tApplying UserConfigSet.default'
                Merge-UserSet -Set $jsonContent.UserConfigSet.default
            }

            # Layer 3: SafeConfigSet named set (if -SafeConfigSet supplied)
            if (-not [string]::IsNullOrEmpty($SafeConfigSet)) {
                $safeSet = $jsonContent.SafeConfigSet.PSObject.Properties[$SafeConfigSet]
                if ($null -ne $safeSet) {
                    Write-LogMessage -type Info -MSG "Applying SafeConfigSet: $SafeConfigSet"
                    Merge-SafeSet -Set $safeSet.Value
                } else {
                    Write-LogMessage -type Warning -MSG "SafeConfigSet '$SafeConfigSet' not found in config. Using 'default'."
                }
            }

            # Layer 3: UserConfigSet named set (if -UserConfigSet supplied)
            if (-not [string]::IsNullOrEmpty($UserConfigSet)) {
                $userSet = $jsonContent.UserConfigSet.PSObject.Properties[$UserConfigSet]
                if ($null -ne $userSet) {
                    Write-LogMessage -type Info -MSG "Applying UserConfigSet: $UserConfigSet"
                    Merge-UserSet -Set $userSet.Value
                } else {
                    Write-LogMessage -type Warning -MSG "UserConfigSet '$UserConfigSet' not found in config. Using 'default'."
                }
            }
        } catch {
            Write-LogMessage -type Warning -MSG "Failed to load config '$effectiveConfigPath': $($PSItem.Exception.Message). Using baseline defaults."
        }
    } else {
        Write-LogMessage -type Info -MSG 'No config file found. Using baseline defaults.'
    }

    # Layer 4: explicit parameter overrides (always win)
    if ($PSBoundParameters.ContainsKey('CPMName')) {
        $resolved.CPMName = $CPMName
    }
    if ($PSBoundParameters.ContainsKey('SafeNamePattern')) {
        $resolved.SafeNamePattern = $SafeNamePattern
    }
    if ($PSBoundParameters.ContainsKey('PlatformID')) {
        $resolved.UserDefaults['accountPlatform'] = $PlatformID
    }
    if ($PSBoundParameters.ContainsKey('NumberOfVersionsRetention')) {
        $resolved.NumberOfVersionsRetention = $NumberOfVersionsRetention
        $resolved.NumberOfDaysRetention = $null
    }
    if ($PSBoundParameters.ContainsKey('NumberOfDaysRetention')) {
        $resolved.NumberOfDaysRetention = $NumberOfDaysRetention
        $resolved.NumberOfVersionsRetention = $null
    }

    # Mutual-exclusion final guard: if somehow both survived, NumberOfDaysRetention wins
    if ($null -ne $resolved.NumberOfVersionsRetention -and $null -ne $resolved.NumberOfDaysRetention) {
        Write-Warning "Both NumberOfVersionsRetention ($($resolved.NumberOfVersionsRetention)) and NumberOfDaysRetention ($($resolved.NumberOfDaysRetention)) are set. NumberOfDaysRetention wins. NumberOfVersionsRetention will be ignored."
        $resolved.NumberOfVersionsRetention = $null
    }

    # Fallback: if neither retention value is set, use baseline default
    if ($null -eq $resolved.NumberOfVersionsRetention -and $null -eq $resolved.NumberOfDaysRetention) {
        $resolved.NumberOfDaysRetention = $script:DEFAULT_DAYS_RETENTION
    }

    $script:Config = $resolved
    Write-LogMessage -type Debug -MSG "Resolved config: CPM=$($script:Config.CPMName), VersionsRetention=$($script:Config.NumberOfVersionsRetention), DaysRetention=$($script:Config.NumberOfDaysRetention), SafePattern=$($script:Config.SafeNamePattern), UserDefaults=$($script:Config.UserDefaults.Keys -join ','), DefaultMembers=$($script:Config.DefaultSafeMembers.Count), CustomRoles=$($script:Config.RoleConfigSets.Count), SafeOptions=[$($script:Config.SafeOptions.GetEnumerator() | ForEach-Object {"$($PSItem.Key)=$($PSItem.Value)"} | Join-String -Separator ',')], UserOptions=[$($script:Config.UserOptions.GetEnumerator() | ForEach-Object {"$($PSItem.Key)=$($PSItem.Value)"} | Join-String -Separator ',')]"
}

function Get-RowConfig {
    <#
.SYNOPSIS
    Returns a per-row config hashtable by overlaying named SafeConfigSet / UserConfigSet entries
    from the parsed JSON on top of the base resolved config.
.DESCRIPTION
    Called once per CSV row when that row has a non-blank SafeConfigSet or UserConfigSet value.
    Starts from a shallow copy of $script:Config (so CLI param overrides are preserved as the
    base), then merges the named set(s) from $script:g_JsonContent on top.

    When a named set is not found in the JSON:
      - Default behaviour  : returns $null  (caller logs Error and skips the row)
      - -FallbackOnInvalidConfigSet switch : logs Warning and returns the unmodified base config
.PARAMETER RowSafeConfigSet
    Value of the SafeConfigSet column for this CSV row. May be empty.
.PARAMETER RowUserConfigSet
    Value of the UserConfigSet column for this CSV row. May be empty.
.OUTPUTS
    System.Collections.Hashtable, or $null when an invalid set name is encountered and
    -FallbackOnInvalidConfigSet was not specified.
#>
    param(
        [Parameter(Mandatory = $false)] [string]$RowSafeConfigSet = '',
        [Parameter(Mandatory = $false)] [string]$RowUserConfigSet = ''
    )

    # Shallow copy of the base config so we never mutate $script:Config
    $resolved = @{
        CPMName                   = $script:Config.CPMName
        NumberOfVersionsRetention = $script:Config.NumberOfVersionsRetention
        NumberOfDaysRetention     = $script:Config.NumberOfDaysRetention
        SafeNamePattern           = $script:Config.SafeNamePattern
        UserDefaults              = $script:Config.UserDefaults.Clone()
        DefaultSafeMembers        = $script:Config.DefaultSafeMembers   # replaced wholesale; never mutated
        RoleConfigSets            = $script:Config.RoleConfigSets        # read-only reference
        SafeEndUserRole           = $script:Config.SafeEndUserRole
        SafeEndUserRoleConfigSet  = $script:Config.SafeEndUserRoleConfigSet
        SafeEndUserSearchIn       = $script:Config.SafeEndUserSearchIn
        SafeEndUserMemberType     = $script:Config.SafeEndUserMemberType
        SafeOptions               = $script:Config.SafeOptions.Clone()
        UserOptions               = $script:Config.UserOptions.Clone()
    }

    # Apply SafeConfigSet override
    if (-not [string]::IsNullOrEmpty($RowSafeConfigSet)) {
        if ($null -eq $script:g_JsonContent) {
            Write-LogMessage -type Warning -MSG "Get-RowConfig: SafeConfigSet '$RowSafeConfigSet' requested but no config file was loaded — using base config"
        } else {
            $safeSet = $script:g_JsonContent.SafeConfigSet.PSObject.Properties[$RowSafeConfigSet]
            if ($null -eq $safeSet) {
                if ($FallbackOnInvalidConfigSet) {
                    Write-LogMessage -type Warning -MSG "Get-RowConfig: SafeConfigSet '$RowSafeConfigSet' not found in config — falling back to base config"
                } else {
                    Write-LogMessage -type Error -MSG "Get-RowConfig: SafeConfigSet '$RowSafeConfigSet' not found in config — row will be skipped. Use -FallbackOnInvalidConfigSet to fall back instead."
                    return $null
                }
            } else {
                $setProps = $safeSet.Value.Properties
                $setOpts = $safeSet.Value.Options
                if ($null -ne $setProps) {
                    if (-not [string]::IsNullOrEmpty($setProps.CPMName)) {
                        $resolved.CPMName = $setProps.CPMName
                    }
                    if ($null -ne $setProps.NumberOfVersionsRetention) {
                        $resolved.NumberOfVersionsRetention = $setProps.NumberOfVersionsRetention
                        $resolved.NumberOfDaysRetention = $null
                    }
                    if ($null -ne $setProps.NumberOfDaysRetention) {
                        $resolved.NumberOfDaysRetention = $setProps.NumberOfDaysRetention
                        $resolved.NumberOfVersionsRetention = $null
                    }
                    if (-not [string]::IsNullOrEmpty($setProps.SafeNamePattern)) {
                        $resolved.SafeNamePattern = $setProps.SafeNamePattern
                    }
                    if ($null -ne $setProps.DefaultSafeMembers) {
                        $resolved.DefaultSafeMembers = $setProps.DefaultSafeMembers
                    }
                    if (-not [string]::IsNullOrEmpty($setProps.SafeEndUserRoleConfigSet)) {
                        $resolved.SafeEndUserRoleConfigSet = $setProps.SafeEndUserRoleConfigSet
                        $resolved.SafeEndUserRole = $null
                    } elseif (-not [string]::IsNullOrEmpty($setProps.SafeEndUserRole)) {
                        $resolved.SafeEndUserRole = $setProps.SafeEndUserRole
                        $resolved.SafeEndUserRoleConfigSet = $null
                    }
                    if (-not [string]::IsNullOrEmpty($setProps.SafeEndUserSearchIn)) {
                        $resolved.SafeEndUserSearchIn = $setProps.SafeEndUserSearchIn
                    }
                    if (-not [string]::IsNullOrEmpty($setProps.SafeEndUserMemberType)) {
                        $resolved.SafeEndUserMemberType = $setProps.SafeEndUserMemberType
                    }
                }
                if ($null -ne $setOpts -and $null -ne $setOpts.useExisting) {
                    $resolved.SafeOptions['useExisting'] = [bool]$setOpts.useExisting
                }
                Write-LogMessage -type Verbose -MSG "Get-RowConfig: Applied SafeConfigSet '$RowSafeConfigSet'"
            }
        }
    }

    # Apply UserConfigSet override
    if (-not [string]::IsNullOrEmpty($RowUserConfigSet)) {
        if ($null -eq $script:g_JsonContent) {
            Write-LogMessage -type Warning -MSG "Get-RowConfig: UserConfigSet '$RowUserConfigSet' requested but no config file was loaded — using base config"
        } else {
            $userSet = $script:g_JsonContent.UserConfigSet.PSObject.Properties[$RowUserConfigSet]
            if ($null -eq $userSet) {
                if ($FallbackOnInvalidConfigSet) {
                    Write-LogMessage -type Warning -MSG "Get-RowConfig: UserConfigSet '$RowUserConfigSet' not found in config — falling back to base config"
                } else {
                    Write-LogMessage -type Error -MSG "Get-RowConfig: UserConfigSet '$RowUserConfigSet' not found in config — row will be skipped. Use -FallbackOnInvalidConfigSet to fall back instead."
                    return $null
                }
            } else {
                if ($null -ne $userSet.Value.Properties) {
                    $userSet.Value.Properties.PSObject.Properties | ForEach-Object {
                        $resolved.UserDefaults[$PSItem.Name] = $PSItem.Value
                    }
                }
                if ($null -ne $userSet.Value.Options) {
                    if (-not [string]::IsNullOrEmpty($userSet.Value.Options.accountUserPattern)) {
                        $resolved.UserOptions['accountUserPattern'] = $userSet.Value.Options.accountUserPattern
                    }
                    if ($null -ne $userSet.Value.Options.allowDuplicateAccounts) {
                        $resolved.UserOptions['allowDuplicateAccounts'] = [bool]$userSet.Value.Options.allowDuplicateAccounts
                    }
                }
                Write-LogMessage -type Verbose -MSG "Get-RowConfig: Applied UserConfigSet '$RowUserConfigSet'"
            }
        }
    }

    return $resolved
}

function ConvertTo-URL {
    <#
.SYNOPSIS
    RFC 3986-encodes a string for safe use in a URL path segment.
.PARAMETER sText
    The text to encode. Empty or null values are returned unchanged.
.OUTPUTS
    System.String
#>
    param (
        [Parameter(Mandatory = $false)]
        [string]$sText
    )
    if (-not [string]::IsNullOrEmpty($sText)) {
        Write-LogMessage -type Verbose -MSG "ConvertTo-URL:`tEncoding: $sText"
        return [URI]::EscapeDataString($sText)
    } else {
        return $sText
    }
}

function ConvertTo-Bool {
    <#
.SYNOPSIS
    Converts a CSV string value to a Boolean.
.DESCRIPTION
    Accepts yes/y ($true) and no/n ($false) in addition to the standard true/false
    values accepted by [bool]::TryParse(). Case-insensitive.
    Returns $false for any unrecognized value.
.PARAMETER txt
    The string value to convert.
.OUTPUTS
    System.Boolean
#>
    param (
        [Parameter(Mandatory = $false)]
        [string]$txt
    )
    $retBool = $false
    if ($txt -match '^y$|^yes$') {
        $retBool = $true
    } elseif ($txt -match '^n$|^no$') {
        $retBool = $false
    } else {
        [bool]::TryParse($txt, [ref]$retBool) | Out-Null
    }
    return $retBool
}

function Get-TrimmedString {
    <#
.SYNOPSIS
    Returns a trimmed string; passes $null through unchanged.
.PARAMETER sText
    The string to trim. $null is returned as-is.
.OUTPUTS
    System.String
#>
    param (
        [Parameter(Mandatory = $false)]
        [string]$sText
    )
    if ($null -ne $sText) {
        return $sText.Trim()
    }
    return $sText
}

function Get-PersonalSafeNameFromPattern {
    <#
.SYNOPSIS
    Returns the personal safe name by substituting a user name into the active safe name pattern.
.DESCRIPTION
    Replaces the single wildcard (*) in $SafeNamePattern with the supplied user name.
    For example, pattern *_ADM with user jsmith yields jsmith_ADM.
.PARAMETER userName
    The user name to substitute for the * placeholder in the pattern.
.OUTPUTS
    System.String
#>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$userName
    )
    return $SafeNamePattern.Replace('*', $userName)
}

function Disable-SSLVerification {
    <#
.SYNOPSIS
    Bypasses SSL certificate validation. Use only in test environments.
#>
    [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    if (-not ('DisableCertValidationCallback' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class DisableCertValidationCallback {
    public static bool ReturnTrue(object sender, X509Certificate certificate,
        X509Chain chain, SslPolicyErrors sslPolicyErrors) { return true; }
    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(DisableCertValidationCallback.ReturnTrue);
    }
}
'@
    }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [DisableCertValidationCallback]::GetDelegate()
}

function Invoke-Rest {
    <#
.SYNOPSIS
    Invokes a REST method with CyberArk-aware error handling.
.DESCRIPTION
    Wraps Invoke-RestMethod and handles:
      - HTTP 401/403: exits script with code 5
      - DNS resolution failure: exits script with code 1
      - PASWS006E / PASWS013E (auth errors): exits script with code 5
      - SFWS0002 (safe already exists): throws message string
      - SFWS0007 (safe deleted/not found): re-throws exception
      - SFWS0012 (already a member): logs verbose, re-throws
      - SFWS0013 (you cannot update your own account): logs warning, returns null (safe creator has full access implicitly)
      - All others: logs and re-throws
.PARAMETER Command
    HTTP method: GET, POST, DELETE, PATCH, PUT
.PARAMETER URI
    The REST endpoint URI.
.PARAMETER Header
    Request headers hashtable.
.PARAMETER Body
    Optional request body (string or object).
.PARAMETER ErrAction
    ErrorAction preference (default: Continue).
.PARAMETER TimeoutSec
    Request timeout in seconds (default: 2700).
.PARAMETER ContentType
    Content-Type header (default: application/json).
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'DELETE', 'PATCH', 'PUT')]
        [Alias('Method')]
        [String]$Command,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$URI,
        [Parameter(Mandatory = $false)]
        [Alias('Headers')]
        $Header,
        [Parameter(Mandatory = $false)]
        $Body,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Continue', 'Ignore', 'Inquire', 'SilentlyContinue', 'Stop', 'Suspend')]
        [String]$ErrAction = 'Continue',
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSec = 2700,
        [Parameter(Mandatory = $false)]
        [string]$ContentType = 'application/json'
    )
    Write-LogMessage -type Verbose -MSG 'Invoke-Rest:`tStart'
    $restResponse = $null
    try {
        if ([string]::IsNullOrEmpty($Body)) {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tGET/no-body $URI"
            $restParams = @{
                Uri         = $URI
                Method      = $Command
                Header      = $Header
                ContentType = $ContentType
                TimeoutSec  = $TimeoutSec
                ErrorAction = $ErrAction
                Verbose     = $InVerbose
                Debug       = $InDebug
            }
            $restResponse = Invoke-RestMethod @restParams
        } else {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$Command $URI"
            $restParams = @{
                Uri         = $URI
                Method      = $Command
                Header      = $Header
                ContentType = $ContentType
                Body        = $Body
                TimeoutSec  = $TimeoutSec
                ErrorAction = $ErrAction
                Verbose     = $InVerbose
                Debug       = $InDebug
            }
            $restResponse = Invoke-RestMethod @restParams
        }
        Write-LogMessage -type Verbose -MSG 'Invoke-Rest:`tCompleted without error'
    } catch {
        if ($PSItem.ErrorDetails.Message -notmatch '.*ErrorCode[\s\S]*ErrorMessage.*') {
            if ($PSItem.Exception.response.StatusCode.value__ -eq 401) {
                Write-LogMessage -type Error -MSG 'Received error 401 - Unauthorized access'
                Write-LogMessage -type Error -MSG '**** Exiting script ****' -Footer -Header
                exit 5
            } elseif ($PSItem.Exception.response.StatusCode.value__ -eq 403) {
                Write-LogMessage -type Error -MSG 'Received error 403 - Forbidden access'
                Write-LogMessage -type Error -MSG '**** Exiting script ****' -Footer -Header
                exit 5
            } elseif ($PSItem.Exception -match 'The remote name could not be resolved:') {
                Write-LogMessage -type Error -MSG 'Received error - The remote name could not be resolved'
                Write-LogMessage -type Error -MSG '**** Exiting script ****' -Footer -Header
                exit 1
            } else {
                throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $PSItem.Exception))
            }
        }
        $Details = ($PSItem.ErrorDetails.Message | ConvertFrom-Json)
        if ('PASWS006E' -eq $Details.ErrorCode -or 'PASWS013E' -eq $Details.ErrorCode) {
            Write-LogMessage -type Error -MSG "$($Details.ErrorMessage)"
            Write-LogMessage -type Error -MSG '**** Exiting script ****' -Footer -Header
            exit 5
        } elseif ('SFWS0007' -eq $Details.ErrorCode) {
            # Safe not found — return $null when caller requested silent handling, otherwise throw
            if ($ErrAction -in @('SilentlyContinue', 'Ignore')) {
                return $null
            }
            throw $PSItem.Exception
        } elseif ('SFWS0002' -eq $Details.ErrorCode) {
            Write-LogMessage -type Warning -MSG "$($Details.ErrorMessage)"
            throw "$($Details.ErrorMessage)"
        } elseif ('SFWS0012' -eq $Details.ErrorCode) {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.ErrorMessage)"
            throw $PSItem
        } elseif ('SFWS0013' -eq $Details.ErrorCode) {
            # "You cannot update your own account" -- safe creator already has full access;
            # downgrade to warning so Add-SafeOwner callers can continue to Add-DefaultSafeMembers.
            Write-LogMessage -type Warning -MSG "Invoke-Rest:`t$($Details.ErrorMessage) (SFWS0013 -- safe creator skipped)"
            return $null
        } else {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tError running $Command on '$URI'"
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tMessage: $PSItem"
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tException: $($PSItem.Exception.Message)"
            $silentErrAction = $ErrAction -in @('SilentlyContinue', 'Ignore')
            if ($PSItem.Exception.Response) {
                $statusLogType = if ($silentErrAction) {
                    'Verbose' 
                } else {
                    'Error' 
                }
                Write-LogMessage -type $statusLogType -MSG "Status Code: $($PSItem.Exception.Response.StatusCode.value__)"
                Write-LogMessage -type $statusLogType -MSG "Status Description: $($PSItem.Exception.Response.StatusDescription)"
            }
            if ($($PSItem.ErrorDetails.Message | ConvertFrom-Json).ErrorMessage) {
                $msgLogType = if ($silentErrAction) {
                    'Verbose' 
                } else {
                    'Error' 
                }
                Write-LogMessage -type $msgLogType -MSG "Error Message: $($($PSItem.ErrorDetails.Message | ConvertFrom-Json).ErrorMessage)"
            }
            $restResponse = $null
            throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $PSItem.Exception))
        }
    }
    Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tResponse: $restResponse"
    return $restResponse
}

function Invoke-Logon {
    <#
.SYNOPSIS
    Authenticates to PVWA and returns an Authorization header hashtable.
.PARAMETER Credentials
    PSCredential for authentication.
.PARAMETER RadiusOTP
    Optional RADIUS one-time password (appended to password with comma delimiter).
#>
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials,
        [Parameter(Mandatory = $false)]
        [string]$RadiusOTP
    )
    $BSTR = $null
    try {
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credentials.Password)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        $logonBody = @{
            username          = $Credentials.UserName.Replace('\', '')
            password          = $plainPassword
            concurrentSession = $true
        } | ConvertTo-Json -Compress

        if (-not [string]::IsNullOrEmpty($RadiusOTP)) {
            $logonBodyObj = $logonBody | ConvertFrom-Json
            $logonBodyObj.password = "$plainPassword,$RadiusOTP"
            $logonBody = $logonBodyObj | ConvertTo-Json -Compress
        }

        $logonToken = Invoke-Rest -Command POST -URI $script:URL_Logon -Body $logonBody
        $logonBody = ''
    } catch {
        throw $(New-Object System.Exception ("Invoke-Logon: $($PSItem.Exception.Response.StatusDescription)", $PSItem.Exception))
    } finally {
        if ($null -ne $BSTR) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        }
        $plainPassword = $null
    }

    if ([string]::IsNullOrEmpty($logonToken)) {
        throw 'Invoke-Logon: Logon Token is Empty - Cannot login'
    }

    if ($logonToken.PSObject.Properties.Name -contains 'CyberArkLogonResult') {
        return @{Authorization = $($logonToken.CyberArkLogonResult) }
    } else {
        return @{Authorization = $logonToken }
    }
}

function Invoke-Logoff {
    <#
.SYNOPSIS
    Logs off a PVWA session.
.DESCRIPTION
    Posts to the Logoff endpoint and clears $script:g_LogonHeader.
    No-ops silently when Header is $null.
.PARAMETER Header
    The logon header to use for logoff. Defaults to $script:g_LogonHeader.
#>
    param(
        [Parameter(Mandatory = $false)]
        $Header = $script:g_LogonHeader
    )
    try {
        if ($null -ne $Header) {
            Write-LogMessage -type Info -MSG 'Logoff Session...'
            Invoke-Rest -Command POST -URI $script:URL_Logoff -Header $Header | Out-Null
            $script:g_LogonHeader = $null
        }
    } catch {
        throw $(New-Object System.Exception ('Invoke-Logoff: Failed to logoff session', $PSItem.Exception))
    }
}

function Get-LogonHeader {
    <#
.SYNOPSIS
    Returns a valid logon header. For RADIUS auth, reuses an existing session.
.PARAMETER Credentials
    PSCredential for authentication.
.PARAMETER RadiusOTP
    Optional RADIUS OTP.
#>
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials,
        [Parameter(Mandatory = $false)]
        [string]$RadiusOTP
    )
    try {
        if ([string]::IsNullOrEmpty($RadiusOTP)) {
            return $(Invoke-Logon -Credentials $Credentials)
        } else {
            if ([string]::IsNullOrEmpty($script:g_LogonHeader)) {
                $script:g_LogonHeader = $(Invoke-Logon -Credentials $Credentials -RadiusOTP $RadiusOTP)
            }
            return $script:g_LogonHeader
        }
    } catch {
        throw $(New-Object System.Exception ('Get-LogonHeader: Error returning the logon header.', $PSItem.Exception))
    }
}

function Open-FileDialog {
    <#
.SYNOPSIS
    Opens a Windows file picker dialog to select a CSV file.
.PARAMETER LocationPath
    The initial directory shown when the dialog opens.
.OUTPUTS
    System.String — the selected file path, or empty string if cancelled.
#>
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$LocationPath
    )
    [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $LocationPath
    $OpenFileDialog.filter = 'CSV (*.csv)| *.csv'
    $OpenFileDialog.ShowDialog() | Out-Null
    return $OpenFileDialog.filename
}
function Get-AuthHeader {
    if ($null -ne $script:g_LogonHeader) {
        return $script:g_LogonHeader
    }
    return Get-LogonHeader -Credentials $PVWACredentials -RadiusOTP $OTP
}
#endregion Helper Functions

#region Accounts and Safes Functions
function Get-Safe {
    <#
.SYNOPSIS
    Returns an existing safe object via the v2 REST API (/api/Safes).
.DESCRIPTION
    The v2 API returns a flat object — there is no .GetSafeResult wrapper as in v1.
    Returns $null when the safe is not found and -ErrAction SilentlyContinue is used.
.PARAMETER Header
    Logon header hashtable.
.PARAMETER safeName
    Name of the safe to retrieve.
.PARAMETER ErrAction
    ErrorAction preference for the underlying REST call. Default: Continue.
.OUTPUTS
    PSCustomObject — the safe details object, or $null if not found.
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $Header,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$safeName,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Continue', 'Ignore', 'Inquire', 'SilentlyContinue', 'Stop', 'Suspend')]
        [String]$ErrAction = 'Continue'
    )
    $_safe = $null
    try {
        $accSafeURL = $script:URL_SafeDetails -f $(ConvertTo-URL $safeName)
        $_safe = $(Invoke-Rest -URI $accSafeURL -Header $Header -Command 'GET' -ErrAction $ErrAction)
    } catch {
        throw $(New-Object System.Exception ("Get-Safe: Error getting safe '$safeName' details.", $PSItem.Exception))
    }
    return $_safe
}

function Test-Safe {
    <#
.SYNOPSIS
    Returns $true if the named safe exists, $false otherwise.
.PARAMETER Header
    Logon header hashtable.
.PARAMETER safeName
    Name of the safe to test.
.OUTPUTS
    System.Boolean
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $Header,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$safeName
    )
    try {
        if ($null -eq $(Get-Safe -SafeName $safeName -Header $Header -ErrAction 'SilentlyContinue')) {
            Write-LogMessage -type Info -MSG "Safe '$safeName' does not exist"
            return $false
        } else {
            Write-LogMessage -type Verbose -MSG "Safe '$safeName' exists"
            return $true
        }
    } catch {
        throw $(New-Object System.Exception ("Test-Safe: Error testing safe '$safeName' existence.", $PSItem.Exception))
    }
}

function Add-Safe {
    <#
.SYNOPSIS
    Creates a new safe using the v2 REST API (/api/Safes).
.DESCRIPTION
    Sends a flat JSON body (no { safe: {} } wrapper, as required by v2).
    CPM name and retention settings are read from $script:Config.
    Only one of numberOfVersionsRetention / numberOfDaysRetention is sent
    (mutual exclusion is resolved by Import-ScriptConfig).
.PARAMETER Header
    Logon header hashtable.
.PARAMETER safeName
    Name of the safe to create.
.PARAMETER description
    Optional safe description.
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $Header,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$safeName,
        [Parameter(Mandatory = $false)]
        [String]$description = ''
    )
    Write-LogMessage -type Info -MSG "Creating safe '$safeName'"

    $bodySafe = @{
        safeName    = $safeName
        description = $description
        olacEnabled = $false
        managingCPM = $script:Config.CPMName
    }

    if ($null -ne $script:Config.NumberOfDaysRetention) {
        $bodySafe.numberOfDaysRetention = $script:Config.NumberOfDaysRetention
    } else {
        $bodySafe.numberOfVersionsRetention = $script:Config.NumberOfVersionsRetention
    }

    $restBody = $bodySafe | ConvertTo-Json -Depth 3 -Compress

    try {
        $createSafeResult = $(Invoke-Rest -URI $script:URL_Safes -Header $Header -Command 'POST' -Body $restBody)
        if ($createSafeResult) {
            Write-LogMessage -type Debug -MSG "Safe '$safeName' created"
            return $true
        } else {
            Write-LogMessage -type Error -MSG 'Safe creation failed - skipping account creation'
            return $false
        }
    } catch {
        throw $(New-Object System.Exception ("Add-Safe: Failed to create safe '$safeName'", $PSItem.Exception))
    }
}

function Add-SafeOwner {
    <#
.SYNOPSIS
    Adds a member to a safe using a named role or custom permissions (v2 REST API flat permissions object).
.DESCRIPTION
    Permission source priority (highest wins):
      1. -CustomPermissions hashtable  — inline permissions object passed directly
      2. -ownerRole named role         — one of the 5 built-in roles:
           ConnectOnly, ReadOnly, Approver, AccountsManager, Full

    Uses v2 flat permissions object. requestsAuthorizationLevel1 and
    requestsAuthorizationLevel2 are separate boolean fields.
.PARAMETER Header
    Logon header hashtable.
.PARAMETER safeName
    Name of the safe to add the member to.
.PARAMETER ownerName
    Vault or LDAP user/group name.
.PARAMETER ownerRole
    ConnectOnly | ReadOnly | Approver | AccountsManager | Full
    Not required when -CustomPermissions is supplied.
.PARAMETER CustomPermissions
    Hashtable of all 22 permission fields. Overrides -ownerRole when supplied.
    Can come from a RoleConfigSet entry or an inline Permissions block.
.PARAMETER memberSearchInLocation
    LDAP directory to search (default: Vault).
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $Header,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$safeName,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ownerName,
        [Parameter(Mandatory = $false)]
        [ValidateSet('ConnectOnly', 'ReadOnly', 'EndUser', 'Approver', 'AccountsManager', 'Full')]
        [string]$ownerRole,
        [Parameter(Mandatory = $false)]
        [hashtable]$CustomPermissions,
        [Parameter(Mandatory = $false)]
        [string]$memberSearchInLocation = 'Vault',
        [Parameter(Mandatory = $false)]
        [ValidateSet('', 'User', 'Group', 'Role')]
        [string]$memberType = ''
    )

    if ($null -eq $CustomPermissions -and [string]::IsNullOrEmpty($ownerRole)) {
        throw "Add-SafeOwner: Either -ownerRole or -CustomPermissions must be supplied for '$ownerName' on '$safeName'."
    }

    Write-LogMessage -type Verbose -MSG "Adding member '$ownerName' to safe '$safeName' (role: $(if ($CustomPermissions) { 'Custom' } else { $ownerRole }))..."

    if ($null -ne $CustomPermissions) {
        $permissions = $CustomPermissions
    } else {
        switch ($ownerRole) {
            'ConnectOnly' {
                $permissions = @{
                    useAccounts  = $true
                    listAccounts = $true
                }
            }
            'ReadOnly' {
                $permissions = @{
                    useAccounts      = $true
                    retrieveAccounts = $true
                    listAccounts     = $true
                }
            }
            'EndUser' {
                $permissions = @{
                    useAccounts      = $true
                    retrieveAccounts = $true
                    listAccounts     = $true
                    viewAuditLog     = $true
                    viewSafeMembers  = $true
                }
            }
            'Approver' {
                $permissions = @{
                    listAccounts                = $true
                    manageSafeMembers           = $true
                    viewSafeMembers             = $true
                    requestsAuthorizationLevel1 = $true
                }
            }
            'AccountsManager' {
                $permissions = @{
                    useAccounts                            = $true
                    retrieveAccounts                       = $true
                    listAccounts                           = $true
                    addAccounts                            = $true
                    updateAccountContent                   = $true
                    updateAccountProperties                = $true
                    initiateCPMAccountManagementOperations = $true
                    specifyNextAccountContent              = $true
                    renameAccounts                         = $true
                    deleteAccounts                         = $true
                    unlockAccounts                         = $true
                    manageSafeMembers                      = $true
                    viewAuditLog                           = $true
                    viewSafeMembers                        = $true
                    accessWithoutConfirmation              = $true
                    requestsAuthorizationLevel1            = $true
                }
            }
            'Full' {
                $permissions = @{
                    useAccounts                            = $true
                    retrieveAccounts                       = $true
                    listAccounts                           = $true
                    addAccounts                            = $true
                    updateAccountContent                   = $true
                    updateAccountProperties                = $true
                    initiateCPMAccountManagementOperations = $true
                    specifyNextAccountContent              = $true
                    renameAccounts                         = $true
                    deleteAccounts                         = $true
                    unlockAccounts                         = $true
                    manageSafe                             = $true
                    manageSafeMembers                      = $true
                    backupSafe                             = $true
                    viewAuditLog                           = $true
                    viewSafeMembers                        = $true
                    accessWithoutConfirmation              = $true
                    createFolders                          = $true
                    deleteFolders                          = $true
                    moveAccountsAndFolders                 = $true
                    requestsAuthorizationLevel1            = $true
                }
            }
        }   # end switch
    }   # end else / end if CustomPermissions

    if ($ownerName -notin $script:g_DefaultUsers) {
        try {
            $safeMembersBody = @{
                memberName               = $ownerName
                searchIn                 = $memberSearchInLocation
                membershipExpirationDate = $null
                permissions              = $permissions
            }
            if (-not [string]::IsNullOrEmpty($memberType)) {
                $safeMembersBody.memberType = $memberType
            }
            $safeMembersBodyJson = $safeMembersBody | ConvertTo-Json -Depth 5 -Compress

            Write-LogMessage -type Verbose -MSG "Adding '$ownerName' (searchIn: $memberSearchInLocation) to '$safeName'..."
            $setSafeMember = Invoke-Rest -Command POST -URI ($script:URL_SafeMembers -f $(ConvertTo-URL $safeName)) -Body $safeMembersBodyJson -Header $Header
            if ($null -ne $setSafeMember) {
                Write-LogMessage -type Verbose -MSG "Member '$ownerName' successfully added to '$safeName' (role: $(if ($CustomPermissions) { 'Custom' } else { $ownerRole }))"
            }
        } catch {
            throw $(New-Object System.Exception ("Add-SafeOwner: Error setting membership for '$ownerName' on '$safeName'.", $PSItem.Exception))
        }
    } else {
        Write-LogMessage -type Info -MSG "Skipping default vault user '$ownerName'"
    }
}

function Add-DefaultSafeMembers {
    <#
.SYNOPSIS
    Adds all DefaultSafeMembers from the resolved config to a safe.
.DESCRIPTION
    Each DefaultSafeMembers entry supports three permission sources (priority order):
      1. Permissions  — inline permissions object (PSCustomObject or hashtable)
      2. RoleConfigSet — name of a custom role defined in the RoleConfigSet section
      3. Role          — one of the 5 built-in named roles
    A failed individual member add is logged as a warning but does not stop the loop.
.PARAMETER Header
    Logon header hashtable.
.PARAMETER safeName
    Name of the safe to add default members to.
#>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $Header,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$safeName
    )
    if ($null -eq $script:Config.DefaultSafeMembers -or $script:Config.DefaultSafeMembers.Count -eq 0) {
        Write-LogMessage -type Verbose -MSG "No DefaultSafeMembers configured - skipping for safe '$safeName'"
        return
    }
    foreach ($member in $script:Config.DefaultSafeMembers) {
        try {
            $searchIn = if ([string]::IsNullOrEmpty($member.SearchIn)) {
                'Vault'
            } else {
                $member.SearchIn
            }
            $mType = if ([string]::IsNullOrEmpty($member.MemberType)) {
                'User'
            } else {
                $member.MemberType
            }

            # Resolve permissions source (priority: Permissions > RoleConfigSet > Role)
            if ($null -ne $member.Permissions) {
                # Inline permissions object — convert PSCustomObject to hashtable if needed
                $customPerms = @{}
                $member.Permissions.PSObject.Properties | ForEach-Object { $customPerms[$_.Name] = $_.Value }
                Write-LogMessage -type Info -MSG "Adding default member '$($member.Name)' (inline permissions) to safe '$safeName'"
                $ownerParams = @{
                    Header                 = $Header
                    safeName               = $safeName
                    ownerName              = $member.Name
                    CustomPermissions      = $customPerms
                    memberSearchInLocation = $searchIn
                    memberType             = $mType
                }
                Add-SafeOwner @ownerParams
            } elseif (-not [string]::IsNullOrEmpty($member.RoleConfigSet)) {
                $customPerms = $script:Config.RoleConfigSets[$member.RoleConfigSet]
                if ($null -eq $customPerms) {
                    Write-LogMessage -type Warning -MSG "RoleConfigSet '$($member.RoleConfigSet)' not found for member '$($member.Name)' - skipping"
                    continue
                }
                Write-LogMessage -type Info -MSG "Adding default member '$($member.Name)' (RoleConfigSet: $($member.RoleConfigSet)) to safe '$safeName'"
                $ownerParams = @{
                    Header                 = $Header
                    safeName               = $safeName
                    ownerName              = $member.Name
                    CustomPermissions      = $customPerms
                    memberSearchInLocation = $searchIn
                    memberType             = $mType
                }
                Add-SafeOwner @ownerParams
            } else {
                Write-LogMessage -type Info -MSG "Adding default member '$($member.Name)' (role: $($member.Role)) to safe '$safeName'"
                $ownerParams = @{
                    Header                 = $Header
                    safeName               = $safeName
                    ownerName              = $member.Name
                    ownerRole              = $member.Role
                    memberSearchInLocation = $searchIn
                    memberType             = $mType
                }
                Add-SafeOwner @ownerParams
            }
        } catch {
            Write-LogMessage -type Warning -MSG "Failed to add default member '$($member.Name)' to '$safeName': $($PSItem.Exception.Message)"
        }
    }
}

function New-AccountObject {
    <#
.SYNOPSIS
    Builds a CyberArk account object from a CSV row for bulk onboarding.
.DESCRIPTION
    Maps standard CSV columns (accountUser, accountAddress, safeName, accountPlatform,
    enableAutoMgmt, networkId, etc.) to the v2 Bulk Accounts API shape.
    Missing optional fields fall back to UserDefaults from $script:Config.
    If accountUser is blank, it is derived from the accountUserPattern in UserDefaults
    (replace * with userName). If no pattern is set, userName is used as-is.
    If accountAddress is blank, accountAddress from UserDefaults is used.
    If networkId is blank in the CSV, it falls back to networkId in UserDefaults.
    networkId is required by CyberArk Secrets Rotation (SRS); omit for CPM/on-prem.
    Unknown CSV columns are promoted to platformAccountProperties.
    Unrecognised UserConfigSet keys (anything not in the reserved list) are also
    promoted to platformAccountProperties; a CSV column for the same key takes priority.
.PARAMETER AccountLine
    A single row from the accounts CSV, as a PSObject from Import-Csv.
.OUTPUTS
    PSCustomObject — account object ready for the CyberArk Bulk Accounts API.
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject]$AccountLine
    )
    try {
        # Helper: return CSV field value, falling back to UserDefaults if empty
        function Get-UserDefault {
            param([string]$fieldValue, [string]$fieldName)
            if (-not [string]::IsNullOrEmpty($fieldValue)) {
                return $fieldValue
            }
            if ($null -ne $script:Config -and $script:Config.UserDefaults.ContainsKey($fieldName)) {
                return [string]$script:Config.UserDefaults[$fieldName]
            }
            return $null
        }

        $_safeName = $_platformID = ''
        # Resolve accountUser: CSV value → accountUserPattern from config → userName as fallback
        $_accountUser = Get-TrimmedString $AccountLine.accountUser
        if ([string]::IsNullOrEmpty($_accountUser)) {
            $_pattern = $script:Config.UserOptions['accountUserPattern']
            $_accountUser = if (-not [string]::IsNullOrEmpty($_pattern)) {
                $_pattern.Replace('*', (Get-TrimmedString $AccountLine.userName))
            } else {
                Get-TrimmedString $AccountLine.userName
            }
        }
        if ([string]::IsNullOrEmpty($_accountUser)) {
            throw 'Missing mandatory field: Account User Name'
        }
        # Resolve accountAddress: CSV value -> accountAddress in UserDefaults -> error
        $_accountAddress = Get-TrimmedString $AccountLine.accountAddress
        if ([string]::IsNullOrEmpty($_accountAddress)) {
            $_accountAddress = Get-UserDefault -fieldValue '' -fieldName 'accountAddress'
        }
        if ([string]::IsNullOrEmpty($_accountAddress)) {
            throw 'Missing mandatory field: Account Address'
        }
        if ([string]::IsNullOrEmpty($AccountLine.safeName)) {
            $_safeName = Get-PersonalSafeNameFromPattern -userName $AccountLine.userName
        } else {
            $_safeName = $AccountLine.safeName
        }
        if ([string]::IsNullOrEmpty($AccountLine.accountPlatform)) {
            $_platformID = Get-UserDefault -fieldValue '' -fieldName 'accountPlatform'
        } else {
            $_platformID = $AccountLine.accountPlatform
        }
        if ([string]::IsNullOrEmpty($_platformID)) {
            $_platformID = $script:DEFAULT_PLATFORM_ID
        }

        $excludedProperties = @('accountuser', 'accountaddress', 'accountplatform', 'accountuserpattern',
            'name', 'username', 'address', 'safename', 'platformid', 'password', 'key',
            'enableautomgmt', 'manualmgmtreason', 'groupname', 'groupplatformid',
            'remotemachineaddresses', 'restrictmachineaccesstolist', 'sshkey',
            'safeconfigset', 'userconfigset', 'cpmname', 'numberofdaysretention', 'numberofversionsretention',
            'safenamepattern', 'networkid', 'createsafeonly')
        $customProps = $($AccountLine.PSObject.Properties | Where-Object { $_.Name.ToLower() -notin $excludedProperties })

        $_Account = [PSCustomObject]@{
            address                   = $_accountAddress
            userName                  = $_accountUser
            platformId                = (Get-TrimmedString $_platformID)
            safeName                  = (Get-TrimmedString $_safeName)
            secret                    = $AccountLine.password
            networkId                 = $null
            platformAccountProperties = $null
            secretManagement          = [PSCustomObject]@{
                automaticManagementEnabled = $null
                manualManagementReason     = $null
            }
            remoteMachinesAccess      = $null
        }

        if (-not [string]::IsNullOrEmpty($customProps)) {
            $_Account.platformAccountProperties = [PSCustomObject]@{}
            foreach ($prop in $customProps) {
                if (-not [string]::IsNullOrEmpty($prop.Value)) {
                    $_Account.platformAccountProperties | Add-Member -MemberType NoteProperty -Name $prop.Name -Value (Get-TrimmedString $prop.Value)
                }
            }
        }

        # Promote unrecognised UserDefaults keys to platformAccountProperties.
        # Reserved keys are handled explicitly above; CSV columns take priority (already set).
        if ($null -ne $script:Config -and $script:Config.UserDefaults.Count -gt 0) {
            foreach ($udKey in $script:Config.UserDefaults.Keys) {
                if ($udKey.ToLower() -notin $excludedProperties) {
                    $_udVal = [string]$script:Config.UserDefaults[$udKey]
                    if (-not [string]::IsNullOrEmpty($_udVal)) {
                        if ($null -eq $_Account.platformAccountProperties) {
                            $_Account.platformAccountProperties = [PSCustomObject]@{}
                        }
                        if ($null -eq $_Account.platformAccountProperties.PSObject.Properties[$udKey]) {
                            $_Account.platformAccountProperties | Add-Member -MemberType NoteProperty -Name $udKey -Value $_udVal
                        }
                    }
                }
            }
        }

        $_networkId = Get-UserDefault -fieldValue $AccountLine.networkId -fieldName 'networkId'
        $_enableAutoMgmt = Get-UserDefault -fieldValue $AccountLine.enableAutoMgmt -fieldName 'enableAutoMgmt'
        $_manualMgmtReason = Get-UserDefault -fieldValue $AccountLine.manualMgmtReason -fieldName 'manualMgmtReason'
        $_remoteMachines = Get-UserDefault -fieldValue $AccountLine.remoteMachineAddresses -fieldName 'remoteMachineAddresses'
        $_restrictMachines = Get-UserDefault -fieldValue $AccountLine.restrictMachineAccessToList -fieldName 'restrictMachineAccessToList'

        if (-not [string]::IsNullOrEmpty($_networkId)) {
            $_Account.networkId = $_networkId
        }

        if (-not [String]::IsNullOrEmpty($_enableAutoMgmt)) {
            $_Account.secretManagement.automaticManagementEnabled = ConvertTo-Bool $_enableAutoMgmt
            if ($_Account.secretManagement.automaticManagementEnabled -eq $false) {
                $_Account.secretManagement.manualManagementReason = $_manualMgmtReason
            }
        }

        $_Account.remoteMachinesAccess = [PSCustomObject]@{
            remoteMachines                   = $null
            accessRestrictedToRemoteMachines = $null
        }
        if (-not [String]::IsNullOrEmpty($_remoteMachines)) {
            $_Account.remoteMachinesAccess.remoteMachines = $_remoteMachines
            $_Account.remoteMachinesAccess.accessRestrictedToRemoteMachines = ConvertTo-Bool $_restrictMachines
        }

        if ($null -eq $_Account.networkId) {
            $_Account.PSObject.Properties.Remove('networkId')
        }
        if ($null -eq $_Account.platformAccountProperties) {
            $_Account.PSObject.Properties.Remove('platformAccountProperties')
        }
        if ($null -eq $_Account.remoteMachinesAccess.remoteMachines) {
            $_Account.PSObject.Properties.Remove('remoteMachinesAccess')
        }
        if ($null -eq $_Account.secretManagement.automaticManagementEnabled) {
            $_Account.PSObject.Properties.Remove('secretManagement')
        }

        if (([string]::IsNullOrEmpty($_Account.userName) -or [string]::IsNullOrEmpty($_Account.Address)) -and
            (-not [string]::IsNullOrEmpty($_Account.name))) {
            $script:g_LogAccountName = $_Account.name
        } else {
            $script:g_LogAccountName = '{0}@{1}' -f $_Account.userName, $_Account.Address
        }

        return $_Account
    } catch {
        throw $(New-Object System.Exception ('New-AccountObject: Error creating account object.', $PSItem.Exception))
    }
}
#endregion Accounts and Safes Functions

#endregion Functions

#region Main Execution

Write-LogMessage -type Verbose -MSG $script:g_ScriptCommand
Write-LogMessage -type Info -MSG "Starting script (v$ScriptVersion)" -Header
if ($InDebug) {
    Write-LogMessage -type Info -MSG 'Running in Debug Mode'
}
if ($InVerbose) {
    Write-LogMessage -type Info -MSG 'Running in Verbose Mode'
}
Write-LogMessage -type Debug -MSG "Running PowerShell version $($PSVersionTable.PSVersion.Major) compatible of versions $($PSVersionTable.PSCompatibleVersions -join ', ')"

if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-LogMessage -type Error -MSG "PowerShell is running in $($ExecutionContext.SessionState.LanguageMode) mode which limits API methods used by this script."
    Write-LogMessage -type Info -MSG 'Script ended' -Footer
    return
}

if ([string]::IsNullOrEmpty($PVWAURL) -and [string]::IsNullOrEmpty($logonToken)) {
    Write-LogMessage -type Error -MSG 'PVWAURL is required when not using a pre-obtained logonToken.'
    Write-LogMessage -type Info -MSG 'Script ended' -Footer
    return
}

if (-not [string]::IsNullOrEmpty($PVWAURL)) {
    $PVWAURL = Format-PVWAURL -PVWAURL $PVWAURL
}

Initialize-ScriptURLs

# Load and resolve config (baseline defaults -> config file -> parameter overrides)
Import-ScriptConfig

# Apply config-resolved values to script parameters (only when not explicitly supplied)
if (-not $PSBoundParameters.ContainsKey('SafeNamePattern')) {
    $SafeNamePattern = $script:Config.SafeNamePattern
}

if ($DisableCertificateValidation -and -not $script:g_SSLChanged) {
    Disable-SSLVerification
    $script:g_SSLChanged = $true
    Write-Warning 'Certificate validation is disabled. This should only be used for testing!'
}

# Resolve authentication
# Priority: $logonToken (pass-through, no logoff) -> $PVWACredentials -> interactive prompt
if (-not [string]::IsNullOrEmpty($logonToken)) {
    Write-LogMessage -type Info -MSG 'Using provided logon token. Session logoff will be skipped.'
    if ($logonToken.GetType().Name -eq 'String') {
        $script:g_LogonHeader = @{Authorization = $logonToken }
    } else {
        $script:g_LogonHeader = $logonToken
    }
    $script:g_ShouldLogoff = $false
} elseif ($null -eq $PVWACredentials) {
    $PVWACredentials = $Host.UI.PromptForCredential(
        'Personal Privileged Accounts',
        "Enter your CyberArk credentials ($AuthenticationType)",
        '', '')
    if ($null -eq $PVWACredentials) {
        Write-LogMessage -type Error -MSG 'Credentials are required to proceed.'
        Write-LogMessage -type Info -MSG 'Script ended' -Footer
        return
    }
}

if ([string]::IsNullOrEmpty($CSVPath)) {
    $CSVPath = Open-FileDialog -LocationPath $script:g_CsvDefaultPath
}
if ([string]::IsNullOrEmpty($CSVPath)) {
    Write-LogMessage -type Error -MSG 'No CSV file selected. Exiting.'
    Write-LogMessage -type Info -MSG 'Script ended' -Footer
    return
}

# Read CSV and process each account
$accountsCSV = Import-Csv $CSVPath
$personalPrivAccounts = @()
$counter = 1

# Saved before the loop so per-row overrides can be cleanly restored
$baseConfig = $script:Config
$baseSafeNamePattern = $SafeNamePattern

Write-LogMessage -type Info -MSG 'Creating needed personal safes and collecting accounts for onboard' -SubHeader

foreach ($account in $accountsCSV) {
    $rowHasOverride = $false
    try {
        # Per-row SafeConfigSet / UserConfigSet override
        $rowSafeSet = if ($null -ne $account.PSObject.Properties['SafeConfigSet']) {
            $account.SafeConfigSet
        } else {
            ''
        }
        $rowUserSet = if ($null -ne $account.PSObject.Properties['UserConfigSet']) {
            $account.UserConfigSet
        } else {
            ''
        }
        $rowHasOverride = (-not [string]::IsNullOrEmpty($rowSafeSet)) -or (-not [string]::IsNullOrEmpty($rowUserSet))

        if ($rowHasOverride) {
            $rowConfig = Get-RowConfig -RowSafeConfigSet $rowSafeSet -RowUserConfigSet $rowUserSet
            if ($null -eq $rowConfig) {
                # Invalid set name and -FallbackOnInvalidConfigSet not set — skip row
                $rowHasOverride = $false   # nothing to restore
                continue
            }
            $script:Config = $rowConfig
            $SafeNamePattern = $script:Config.SafeNamePattern
        }

        # Inline safe-field overrides: CSV columns CPMName, NumberOfDaysRetention,
        # NumberOfVersionsRetention and SafeNamePattern (if present and non-blank) take
        # priority over anything resolved from config sets, but are still below CLI params.
        # We make a shallow copy only when at least one column has a value.
        $_rowCPM = if ($null -ne $account.PSObject.Properties['CPMName']) {
            $account.CPMName
        } else {
            ''
        }
        $_rowDays = if ($null -ne $account.PSObject.Properties['NumberOfDaysRetention']) {
            $account.NumberOfDaysRetention
        } else {
            ''
        }
        $_rowVersions = if ($null -ne $account.PSObject.Properties['NumberOfVersionsRetention']) {
            $account.NumberOfVersionsRetention
        } else {
            ''
        }
        $_rowSafePattern = if ($null -ne $account.PSObject.Properties['SafeNamePattern']) {
            $account.SafeNamePattern
        } else {
            ''
        }
        $_rowCreateSafeOnly = if ($null -ne $account.PSObject.Properties['createSafeOnly']) {
            $account.createSafeOnly
        } else {
            ''
        }
        if (-not [string]::IsNullOrEmpty($_rowCPM) -or -not [string]::IsNullOrEmpty($_rowDays) -or
            -not [string]::IsNullOrEmpty($_rowVersions) -or -not [string]::IsNullOrEmpty($_rowSafePattern) -or
            -not [string]::IsNullOrEmpty($_rowCreateSafeOnly)) {
            # Clone config if we haven't already (rowHasOverride handles full sets; this is inline only)
            if (-not $rowHasOverride) {
                $script:Config = @{
                    CPMName                   = $script:Config.CPMName
                    NumberOfVersionsRetention = $script:Config.NumberOfVersionsRetention
                    NumberOfDaysRetention     = $script:Config.NumberOfDaysRetention
                    SafeNamePattern           = $script:Config.SafeNamePattern
                    UserDefaults              = $script:Config.UserDefaults.Clone()
                    DefaultSafeMembers        = $script:Config.DefaultSafeMembers
                    RoleConfigSets            = $script:Config.RoleConfigSets
                    SafeEndUserRole           = $script:Config.SafeEndUserRole
                    SafeEndUserRoleConfigSet  = $script:Config.SafeEndUserRoleConfigSet
                    SafeEndUserSearchIn       = $script:Config.SafeEndUserSearchIn
                    SafeEndUserMemberType     = $script:Config.SafeEndUserMemberType
                    SafeOptions               = $script:Config.SafeOptions.Clone()
                    UserOptions               = $script:Config.UserOptions.Clone()
                }
                $rowHasOverride = $true
            }
            if (-not [string]::IsNullOrEmpty($_rowCPM)) {
                $script:Config.CPMName = $_rowCPM
            }
            if (-not [string]::IsNullOrEmpty($_rowDays)) {
                $script:Config.NumberOfDaysRetention = [int]$_rowDays
                $script:Config.NumberOfVersionsRetention = $null
            } elseif (-not [string]::IsNullOrEmpty($_rowVersions)) {
                $script:Config.NumberOfVersionsRetention = [int]$_rowVersions
                $script:Config.NumberOfDaysRetention = $null
            }
            if (-not [string]::IsNullOrEmpty($_rowSafePattern)) {
                $script:Config.SafeNamePattern = $_rowSafePattern
                $SafeNamePattern = $_rowSafePattern
            }
            if (-not [string]::IsNullOrEmpty($_rowCreateSafeOnly)) {
                $script:Config.UserOptions['createSafeOnly'] = (ConvertTo-Bool $_rowCreateSafeOnly)
            }
        }

        $objAccount = (New-AccountObject -AccountLine $account)

        $authHeader = Get-AuthHeader

        Write-LogMessage -type Info -MSG "Checking if safe '$($objAccount.safeName)' exists..."
        $safeIsNew = $false
        $skipAccount = $false
        if (-not $(Test-Safe -safeName $objAccount.safeName -Header $authHeader)) {
            # Safe does not exist — create it. A new safe cannot contain any accounts.
            $safeIsNew = $true
            Write-LogMessage -type Info -MSG "Creating safe '$($objAccount.safeName)' and adding '$($account.userName)' as owner"
            try {
                if ($(Add-Safe -safeName $objAccount.safeName -Header $authHeader)) {
                    # Resolve owner permissions: SafeOwnerRoleConfigSet > SafeOwnerRole > 'AccountsManager'
                    $_ownerCustomPerms = $null
                    $_ownerRole = if (-not [string]::IsNullOrEmpty($script:Config.SafeEndUserRole)) {
                        $script:Config.SafeEndUserRole
                    } else {
                        'EndUser'
                    }
                    if (-not [string]::IsNullOrEmpty($script:Config.SafeEndUserRoleConfigSet)) {
                        $_ownerCustomPerms = $script:Config.RoleConfigSets[$script:Config.SafeEndUserRoleConfigSet]
                        if ($null -eq $_ownerCustomPerms) {
                            Write-LogMessage -type Warning -MSG "SafeEndUserRoleConfigSet '$($script:Config.SafeEndUserRoleConfigSet)' not found in RoleConfigSets - falling back to '$_ownerRole'"
                        }
                    }
                    $ownerParams = @{
                        Header    = $authHeader
                        safeName  = $objAccount.safeName
                        ownerName = $account.userName
                    }
                    if (-not [string]::IsNullOrEmpty($script:Config.SafeEndUserSearchIn)) {
                        $ownerParams.memberSearchInLocation = $script:Config.SafeEndUserSearchIn
                    }
                    if (-not [string]::IsNullOrEmpty($script:Config.SafeEndUserMemberType)) {
                        $ownerParams.memberType = $script:Config.SafeEndUserMemberType
                    }
                    if ($null -ne $_ownerCustomPerms) {
                        $ownerParams.CustomPermissions = $_ownerCustomPerms
                    } else {
                        $ownerParams.ownerRole = $_ownerRole
                    }
                    Add-SafeOwner @ownerParams
                    Add-DefaultSafeMembers -Header $authHeader -safeName $objAccount.safeName
                }
            } catch {
                throw $(New-Object System.Exception ('Error creating safe or adding safe members', $PSItem.Exception))
            }
        } elseif (-not $script:Config.SafeOptions['useExisting']) {
            Write-LogMessage -type Error -MSG "Safe '$($objAccount.safeName)' already exists and SafeConfigSet option useExisting=false — row skipped."
            $skipAccount = $true
        }

        # createSafeOnly: safe + members created above; skip account onboarding
        $effectiveCreateSafeOnly = $CreateSafeOnly -or $script:Config.UserOptions['createSafeOnly']
        if ($effectiveCreateSafeOnly) {
            Write-LogMessage -type Info -MSG "createSafeOnly: safe '$($objAccount.safeName)' created/verified; skipping account onboard for '$($account.userName)'"
            $skipAccount = $true
        }

        # Duplicate account check — only for existing safes (new safes cannot have accounts)
        $effectiveAllowDup = $AllowDuplicateAccounts -or $script:Config.UserOptions['allowDuplicateAccounts']
        if (-not $skipAccount -and -not $safeIsNew -and -not $effectiveAllowDup) {
            $dupFilter = "safeName eq $($objAccount.safeName) AND userName eq $($objAccount.userName) AND address eq $($objAccount.address) AND platformId eq $($objAccount.platformId)"
            $dupURL = $script:URL_Accounts + '?filter=' + [URI]::EscapeDataString($dupFilter)
            Write-LogMessage -type Verbose -MSG "Checking for duplicate account: $dupFilter"
            try {
                $dupResult = Invoke-Rest -Command GET -URI $dupURL -Header $authHeader -ErrAction 'SilentlyContinue'
                if ($null -ne $dupResult -and $dupResult.count -gt 0) {
                    Write-LogMessage -type Warning -MSG "Duplicate account detected — safe '$($objAccount.safeName)' already contains an account for '$($objAccount.userName)' @ '$($objAccount.address)' (platform: '$($objAccount.platformId)'). Skipping. Use -AllowDuplicateAccounts or set allowDuplicateAccounts=true in UserConfigSet.Options to override."
                    $skipAccount = $true
                }
            } catch {
                # Multi-field AND filter may not be supported (e.g. PCloud) — fall back to safeName-only
                Write-LogMessage -type Verbose -MSG 'Multi-field filter unsupported, falling back to safeName-only duplicate check'
                try {
                    $fallbackFilter = "safeName eq $($objAccount.safeName)"
                    $fallbackURL = $script:URL_Accounts + '?filter=' + [URI]::EscapeDataString($fallbackFilter) + '&limit=1000'
                    $fallbackResult = Invoke-Rest -Command GET -URI $fallbackURL -Header $authHeader -ErrAction 'SilentlyContinue'
                    if ($null -ne $fallbackResult -and $fallbackResult.count -gt 0) {
                        $dupMatch = $fallbackResult.value | Where-Object {
                            $PSItem.userName -eq $objAccount.userName -and
                            $PSItem.address -eq $objAccount.address -and
                            $PSItem.platformId -eq $objAccount.platformId
                        }
                        if ($null -ne $dupMatch) {
                            Write-LogMessage -type Warning -MSG "Duplicate account detected — safe '$($objAccount.safeName)' already contains an account for '$($objAccount.userName)' @ '$($objAccount.address)' (platform: '$($objAccount.platformId)'). Skipping. Use -AllowDuplicateAccounts or set allowDuplicateAccounts=true in UserConfigSet.Options to override."
                            $skipAccount = $true
                        }
                    }
                } catch {
                    Write-LogMessage -type Warning -MSG "Could not verify duplicates for '$($objAccount.userName)' in '$($objAccount.safeName)': $($PSItem.Exception.Message). Proceeding with onboard."
                }
            }
        }

        if (-not $skipAccount) {
            $objAccount | Add-Member -NotePropertyName uploadIndex -NotePropertyValue $counter
            $personalPrivAccounts += $objAccount
            $counter++
        }

        # Logoff per-iteration session only when we own it and are not using RADIUS
        if ($script:g_ShouldLogoff -and $AuthenticationType -ne 'radius') {
            Invoke-Logoff -Header $authHeader
        }
    } catch {
        Write-LogMessage -type Error -MSG "Error onboarding '$($script:g_LogAccountName)' into the Vault. Error: $(Join-ExceptionMessage $PSItem.Exception)"
    } finally {
        # Restore base config so the next row starts clean
        if ($rowHasOverride) {
            $script:Config = $baseConfig
            $SafeNamePattern = $baseSafeNamePattern
        }
    }
}

# Bulk onboard all collected accounts
$authHeader = $null
try {
    if ($personalPrivAccounts.Count -gt 0) {
        Write-LogMessage -type Info -MSG "Starting bulk onboard of $($personalPrivAccounts.Count) personal privileged accounts"

        $authHeader = Get-AuthHeader

        $bulkBody = @{
            source       = $(Split-Path -Resolve $CSVPath -Leaf)
            accountsList = $personalPrivAccounts
        }
        $bulkID = Invoke-Rest -Command POST -URI $script:URL_BulkAccounts -Body ($bulkBody | ConvertTo-Json -Depth 5) -Header $authHeader

        if ($null -ne $bulkID) {
            $bulkResult = Invoke-Rest -Command GET -URI ($script:URL_BulkAccountsTask -f $bulkID) -Header $authHeader
            while (($bulkResult.Status -eq 'inProgress') -or ($bulkResult.Status -eq 'Pending')) {
                Start-Sleep -Seconds 5
                Write-LogMessage -type Info -MSG "Current onboarding status: $($bulkResult.Status -creplace '([A-Z])','$1')"
                $bulkResult = Invoke-Rest -Command GET -URI ($script:URL_BulkAccountsTask -f $bulkID) -Header $authHeader
            }

            Write-LogMessage -type Info -MSG "Onboarding $($bulkResult.Status -creplace '([A-Z])','$1')"
            switch ($bulkResult.Status) {
                'completedWithErrors' {
                    Write-LogMessage -type Info -MSG ('{0} accounts onboarded successfully; {1} failed' -f $bulkResult.Result.succeeded, $bulkResult.Result.failed)
                    foreach ($item in $bulkResult.FailedItems.Items) {
                        $failedAccount = '{0}@{1} (index: {2})' -f $item.userName, $item.address, $item.uploadIndex
                        Write-LogMessage -type Info -MSG ('Account {0} failed: {1}' -f $failedAccount, $item.error)
                    }
                }
                'failed' {
                    Write-LogMessage -type Info -MSG ('Onboarding failed: {0}' -f $bulkResult.Result.Error)
                }
                'completed' {
                    Write-LogMessage -type Info -MSG ('{0} accounts successfully onboarded' -f $bulkResult.Result.succeeded)
                }
            }
        } else {
            throw 'The Bulk Account Upload ID returned empty'
        }
    } else {
        Write-LogMessage -type Info -MSG 'No personal privileged accounts to onboard'
    }
} catch {
    Write-LogMessage -type Error -MSG "Error during bulk onboarding: $(Join-ExceptionMessage $_.Exception)"
} finally {
    # Logoff only if we own the session
    if ($script:g_ShouldLogoff -and $null -ne $authHeader) {
        Invoke-Logoff -Header $authHeader
    }
    Write-LogMessage -type Info -MSG 'Script Ended' -Footer
}

#endregion Main Execution
