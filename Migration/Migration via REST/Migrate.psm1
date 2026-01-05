if ($PSVersionTable.PSVersion -lt [System.Version]'6.0') {
    Write-Host -ForegroundColor Red "This module must be run in PowerShell 6 or greater required`nUse the following link for instructions on how to download and install the current version of PowerShell`nhttps://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows"
    Throw
}
# Script Version

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('UseDeclaredVarsMoreThanAssignments', '')]
$ScriptVersion = '0.20'

New-Variable -Name LOG_FILE_PATH -Value "$(($Script:MyInvocation.MyCommand.Name).Replace('psm1','log'))" -Scope Global -Force

$global:LOG_DATE = $(Get-Date -Format yyyyMMdd) + '-' + $(Get-Date -Format HHmmss)

[String[]]$script:objectSafesToRemove = @('System', 'VaultInternal', 'Notification Engine', 'SharedAuth_Internal', 'PVWAUserPrefs',
    'PVWAConfig', 'PVWAReports', 'PVWATaskDefinitions', 'PVWAPrivateUserPrefs', 'PVWAPublicData', 'PVWATicketingSystem',
    'AccountsFeed', 'PSM', 'xRay', 'PIMSuRecordings', 'xRay_Config', 'AccountsFeedADAccounts', 'AccountsFeedDiscoveryLogs', 'PSMSessions', 'PSMLiveSessions', 'PSMUniversalConnectors',
    'PSMNotifications', 'PSMUnmanagedSessionAccounts', 'PSMRecordings', 'PSMPADBridgeConf', 'PSMPADBUserProfile', 'PSMPADBridgeCustom',
    'AppProviderConf', 'PasswordManagerTemp', 'PasswordManager_Pending', 'PasswordManagerShared', 'TelemetryConfig')

[String[]]$script:CPMSafes = @('PasswordManager', 'PasswordManager_workspace', 'PasswordManager_ADInternal', 'PasswordManager_Info')

[String[]]$script:ownersToRemove = @('Auditors', 'Backup Users', 'Batch', 'PasswordManager', 'DR Users', 'Master', 'Notification Engines', 'Notification Engine',
    'Operators', 'PTAAppUsers', 'PTAAppUser', 'PVWAGWAccounts', 'PVWAAppUsers', 'PVWAAppUser', 'PVWAAppUser1', 'PVWAAppUser2', 'PVWAAppUser3', 'PVWAAppUser4', 'PVWAAppUser5',
    'PVWAAppUser6', 'PVWAUsers', 'PVWAMonitor', 'PSMUsers', 'PSMAppUsers', 'PTAUser', 'Administrator', 'PSMAppUsers', 'Export')

Import-Module -Name '.\CyberArk-Migration.psm1' -Force
. .\Invoke-Process.ps1

function Initialize-Function {
    [CmdletBinding()]
    param ()
    $global:InDebug = $PSBoundParameters.Debug.IsPresent
    $global:InVerbose = $PSBoundParameters.Verbose.IsPresent
    IF (2 -lt (Get-PSCallStack).count) {
        IF (!$global:InDebug) {
            Set-Variable -Scope Global -Name InDebug -Value (Get-Variable -Scope 1 -Name PSBoundParameters -ValueOnly).Debug.IsPresent
        }
        If (!$global:InVerbose) {
            Set-Variable -Scope Global -Name InVerbose -Value (Get-Variable -Scope 1 -Name PSBoundParameters -ValueOnly).Verbose.IsPresent -ErrorAction SilentlyContinue
        }
    }
    Import-Module -Name '.\CyberArk-Migration.psm1' -Force

}

Function Get-CPMUsers {
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    [OutputType([String[]])]
    param([switch]$SuppressCPMWarning)
    $URL_GetCPMList = "$script:srcPVWAURL/API/ComponentsMonitoringDetails/CPM/"
    Try {
        $CPMList = Invoke-RestMethod -Method Get -Uri $URL_GetCPMList -Headers $Script:srcToken -ErrorVariable ErrorCPMList
        IF ([string]::IsNullOrEmpty($CPMList.ComponentsDetails.ComponentUSername)) {
            If (!$SuppressCPMWarning) {
                Write-Warning "Unable to retrieve list of CPM users. Ensure that CPMList parameter has been passed or source CPM is named `"PasswordManager`"" -WarningAction Inquire
            }
            return @()
        }
        else {
            Write-LogMessage -type Debug "$($($CPMList.ComponentsDetails.ComponentUSername).count) CPM users found"
            Write-LogMessage -type Verbose "List of CPM users found: $($($CPMList.ComponentsDetails.ComponentUSername)|ConvertTo-Json -Depth 9 -Compress)"
            return $($CPMList.ComponentsDetails.ComponentUSername)
        }
    }
    catch [Microsoft.PowerShell.Commands.HttpResponseException] {
        If ($PSitem.Exception.Response.StatusCode -eq 'Forbidden') {
            $URL_Verify = "$script:srcPVWAURL/API/Verify/"
            $ReturnResultUser = Invoke-RestMethod -Method Get -Uri $URL_Verify -Headers $logonToken -ErrorVariable RestErrorUser
            IF ([string]::IsNullOrEmpty($ReturnResultUser.ServerName) -or [string]::IsNullOrEmpty(!$RestErrorUser)) {
                If (!$SuppressCPMWarning) {
                    Write-Warning "Unable to retrieve list of CPM users. Ensure that CPMList parameter has been passed or source CPM is named `"PasswordManager`"" -WarningAction Inquire
                }
                return @()
            }
            else {
                Write-Warning "Connected with a account that is not a member of `"vault admins`""
                If (!$SuppressCPMWarning) {
                    Write-Warning "Unable to retrieve list of CPM users. Ensure that CPMList parameter has been passed or source CPM is named `"PasswordManager`"" -WarningAction Inquire
                }
                return @()
            }
        }
    }
}

Function Test-Session {
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param(
        $logonToken,
        $url
    )
    Function Invoke-Report {
        Write-LogMessage -type Debug -MSG "Error Message attempting to do admin connection: $($RestErrorAdmin.ErrorRecord)"
        IF ([string]::IsNullOrEmpty(!$($RestErrorUser))) {
            Write-LogMessage -type Debug -MSG "Error Message attempting to do user connection: $($RestErrorUser.ErrorRecord)"
        }
    }

    $URL_GetHealthSummery = "$url/API/ComponentsMonitoringSummary/"
    Try {
        $ReturnResultAdmin = Invoke-RestMethod -Method Get -Uri $URL_GetHealthSummery -Headers $logonToken -ErrorVariable RestErrorAdmin
        Write-LogMessage -type Verbose -MSG "Test-Session:ReturnResult: $($ReturnResultAdmin|ConvertTo-Json -Depth 9 -Compress)"
        if ((![string]::IsNullOrEmpty($ReturnResultAdmin.Components)) -and ($ReturnResultAdmin.Components.Count -ne 0)) {
            Return $true
        }
        else {
            Invoke-Report
            return $false
        }
    }
    catch [Microsoft.PowerShell.Commands.HttpResponseException] {
        If ($PSitem.Exception.Response.StatusCode -eq 'Forbidden') {
            $URL_Verify = "$url/API/Verify/"
            $ReturnResultUser = Invoke-RestMethod -Method Get -Uri $URL_Verify -Headers $logonToken -ErrorVariable RestErrorUser
            IF ([string]::IsNullOrEmpty($ReturnResultUser.ServerName) -or [string]::IsNullOrEmpty(!$RestErrorUser)) {
                Invoke-Report
                Return $false
            }
            else {
                Invoke-Report
                Write-LogMessage -type Warning -MSG "`tConnected with a account that is not a member of `"vault admins`". Access to some functions may be restricted."
                Return $true
            }
        }
    }
}
function Test-AccountList {
    If ([string]::IsNullOrEmpty($($script:AccountList))) {
        Write-LogMessage -type Warning -MSG 'No accounts found, attempting import of accounts using default settings'
        Import-Accounts
        If ([string]::IsNullOrEmpty($($script:AccountList))) {
            Write-LogMessage -type ErrorThrow -MSG 'No accounts found after import attempt'
            Throw 'No accounts found after import attempt'
        }
    }
}
function Test-SessionsValid {
    If (!(Test-SourceSession)) {
        $SessionFailed = $true
        Write-LogMessage -type Error -MSG "Source Session Test Failed. Run `"New-SourceSession`" to create a new session to the source environment"
    }
    IF (!(Test-DestinationSession)) {
        $SessionFailed = $true
        Write-LogMessage -type Error -MSG "Destination Session Test Failed. Run `"New-DestinationSession`" to create a new session to the destination environment"
    }
    If ($SessionFailed) {
        Throw 'Tests to environment(s) failed'
    }
}
function New-SourceSession {

    # .SYNOPSIS
    # Established a new session to the source environment
    # .DESCRIPTION
    # Established a new session to the source environment. This can be either on-premie or Privileged Cloud environment
    [CmdletBinding()]
    param (

        <#
    URL for the environment
    - HTTPS://Source.lab.local/PasswordVault
    #>
        [Parameter(Mandatory = $true)]
        [Alias('srcURL', 'PVWAURL', 'URL')]
        [String]$srcPVWAURL,
        <#
    Authentication types for logon.
	- Available values: _CyberArk, LDAP, RADIUS_
	- Default value: _CyberArk_
    #>
        [Parameter(Mandatory = $false)]
        [ValidateSet('cyberark', 'ldap', 'radius')]
        [String]$srcAuthType = 'cyberark',

        <#
    One Time Password for the environment when used with RADIUS
    #>
        [Parameter(Mandatory = $false)]
        [ValidateScript({ $AuthType -eq 'radius' })]
        [String]$srcOTP,

        <#
    Stored credentials for source environment
    #>
        [Parameter(Mandatory = $false)]
        [PSCredential]$srcPVWACredentials,

        <#
    Headers for use with environment
    - Used with Privileged Cloud environment
    - When used, log off is suppressed in the source environment
    #>
        [Parameter(Mandatory = $false)]
        $srcLogonToken,
        <#
            Use this switch to Disable SSL verification (NOT RECOMMENDED)
            #>
        [Parameter(Mandatory = $false)]
        [Switch]$DisableSSLVerify
    )

    Initialize-Function
    Set-SSLVerify($DisableSSLVerify)

    # Check that the PVWA URL is OK
    Test-PVWA -PVWAURL $srcPVWAURL

    Write-LogMessage -type Info -MSG 'Getting Source Logon Tokens'
    If (![string]::IsNullOrEmpty($srcLogonToken)) {
        if ($srcLogonToken.GetType().name -eq 'String') {
            $logonHeader = @{Authorization = $srcLogonToken }
            Set-Variable -Scope script -Name srcToken -Value $logonHeader
        }
        else {
            Set-Variable -Scope script -Name srcToken -Value $srcLogonToken
        }
    }
    else {
        If (![string]::IsNullOrEmpty($srcPVWACredentials)) {
            $creds = $srcPVWACredentials
        }
        else {
            $msg = "Enter your source $srcAuthType User name and Password"
            $creds = $Host.UI.PromptForCredential($caption, $msg, '', '')
        }
        New-Variable -Name AuthType -Value $srcAuthType -Scope script -Force
        Import-Module -Name '.\CyberArk-Migration.psm1' -Force

        if ($AuthType -eq 'radius' -and ![string]::IsNullOrEmpty($srcOTP)) {
            Set-Variable -Scope Script -Name srcToken -Value $(Get-Logon -Credentials $creds -AuthType $srcAuthType -URL $srcPVWAURL -OTP $OTP)
        }
        else {
            Set-Variable -Scope Script -Name srcToken -Value $(Get-Logon -Credentials $creds -AuthType $srcAuthType -URL $srcPVWAURL )
        }
        # Verify that we successfully logged on
        If ([string]::IsNullOrEmpty($srcToken)) {
            Write-LogMessage -type Error -MSG 'No Source Credentials were entered' -Footer
            return # No logon header, end script
        }
        $creds = $null
    }
    Set-Variable -Scope Script -Name srcPVWAURL -Value $srcPVWAURL
    if (Test-Session -logonToken $script:srcToken -url $script:srcPVWAURL) {
        Write-LogMessage -type Info -MSG 'Source session successfully configured and tested'
        Write-LogMessage -type Debug -MSG "Source Token set to $($srcToken|ConvertTo-Json -Depth 10)"
    }
    else {
        Throw 'Source session failed to connect successfully'
    }
}
Function Close-SourceSession {
    Initialize-Function
    Invoke-Logoff -url $srcPVWAURL -logonHeader $srcToken -ErrorAction SilentlyContinue
}
Function Test-SourceSession {
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param()
    If ([string]::IsNullOrEmpty($Script:srcToken) -or [string]::IsNullOrEmpty($Script:srcPVWAURL)) {
        return $false
    }
    else {
        Return Test-Session -logonToken $Script:srcToken -url $Script:srcPVWAURL
    }
}
function New-DestinationSession {
    # .SYNOPSIS
    # Established a new session to the destination environment
    # .DESCRIPTION
    # Established a new session to the destination environment. This can be either on-premie or Privileged Cloud environment

    [CmdletBinding()]
    param (

        <#
    URL for the destination environment
    - HTTPS://Source.lab.local/PasswordVault
    #>
        [Parameter(Mandatory = $true)]
        [Alias('dstURL', 'PVWAURL', 'URL')]
        [String]$dstPVWAURL,

        <#
    Authentication types for logon.
	- Available values: _CyberArk, LDAP, RADIUS_
	- Default value: _CyberArk_
    #>
        [Parameter(Mandatory = $false)]
        [ValidateSet('cyberark', 'ldap', 'radius')]
        [String]$dstAuthType = 'cyberark',

        <#
    One Time Password for the environment when used with RADIUS
    #>
        [Parameter(Mandatory = $false)]
        [ValidateScript({ $AuthType -eq 'radius' })]
        [String]$dstOTP,

        <#
    Stored credentials for environment
    #>
        [Parameter(Mandatory = $false)]
        [PSCredential]$dstPVWACredentials,

        <#
    Headers for use with environment
    - Used with Privileged Cloud environment
    - When used, log off is suppressed in the environment
    #>
        [Parameter(Mandatory = $false)]
        $dstLogonToken,

        <#
            Use this switch to Disable SSL verification (NOT RECOMMENDED)
            #>
        [Parameter(Mandatory = $false)]
        [Switch]$DisableSSLVerify
    )
    Initialize-Function
    Set-SSLVerify($DisableSSLVerify)

    # Check that the PVWA URL is OK
    Test-PVWA -PVWAURL $dstPVWAURL

    Write-LogMessage -type Info -MSG 'Getting Destination Logon Tokens'
    If (![string]::IsNullOrEmpty($dstlogonToken)) {
        if ($dstlogonToken.GetType().name -eq 'String') {
            $logonHeader = @{Authorization = $dstlogonToken }
            Set-Variable -Scope Script -Name dstToken -Value $logonHeader
        }
        else {
            Set-Variable -Scope Script -Name dstToken -Value $dstlogonToken
        }
    }
    else {
        If (![string]::IsNullOrEmpty($dstPVWACredentials)) {
            $creds = $dstPVWACredentials
        }
        else {
            $msg = "Enter your source $dstAuthType User name and Password"
            $creds = $Host.UI.PromptForCredential($caption, $msg, '', '')
        }
        New-Variable -Name AuthType -Value $dstAuthType -Scope Global -Force
        Import-Module -Name '.\CyberArk-Migration.psm1' -Force

        if ($AuthType -eq 'radius' -and ![string]::IsNullOrEmpty($OTP)) {
            Set-Variable -Scope script -Name dstToken -Value $(Get-Logon -Credentials $creds -AuthType $dstAuthType -URL $dstPVWAURL -OTP $OTP)
        }
        else {
            Set-Variable -Scope script -Name dstToken -Value $(Get-Logon -Credentials $creds -AuthType $dstAuthType -URL $dstPVWAURL )
        }
        # Verify that we successfully logged on
        If ($null -eq $script:dstToken) {
            Write-LogMessage -type Error -MSG 'No Destination Credentials were entered' -Footer
            return # No logon header, end script
        }
        $creds = $null
    }

    Set-Variable -Scope Script -Name dstPVWAURL -Value $dstPVWAURL
    if (Test-Session -logonToken $Script:dstToken -url $Script:dstPVWAURL) {
        Write-LogMessage -type Info -MSG 'Destination session successfully configured and tested'
        Write-LogMessage -type Debug -MSG "Destination Token set to $($script:dstToken |ConvertTo-Json -Depth 10)"
    }
    else {
        Write-LogMessage -type Error -MSG 'Destination session failed to connect successfully'
    }
}
function Close-DestinationSession {
    Invoke-Logoff -url $dstPVWAURL -logonHeader $dstToken -ErrorAction SilentlyContinue
}
Function Test-DestinationSession {
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param()
    If ([string]::IsNullOrEmpty($Script:dstToken) -or [string]::IsNullOrEmpty($Script:dstPVWAURL)) {
        return $false
    }
    else {
        Return Test-Session -logonToken $Script:dstToken -url $Script:dstPVWAURL
    }
}
function Export-Accounts {
    # .SYNOPSIS
    # Exports accounts from the source environment
    # .DESCRIPTION
    # Exports accounts from the source environment and stores them in a variable called AccountList to be used by Sync-Safe and Sync-Accounts. Generates a feed file called ExportOfAccounts.csv
    param (
        <#
    Path and filename for use by Export
    #>
        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        $exportCSV = '.\ExportOfAccounts.csv'
    )
    Initialize-Function

    Write-LogMessage -type Info -MSG 'Starting export of accounts'
    $srcAccounts = Get-Accounts -url $srcPVWAURL -logonHeader $srcToken -limit 1000
    Write-LogMessage -type Info -MSG "Found $($srcAccounts.count) accounts"
    $remove = $srcAccounts | Where-Object { $_.safename -In $objectSafesToRemove }
    Write-LogMessage -type Info -MSG "Found $($remove.count) accounts in excluded safes and removing from list"
    $srcAccounts = $srcAccounts | Where-Object { $_.safename -notIn $objectSafesToRemove }
    Write-LogMessage -type Info -MSG "Starting export to CSV of $($srcAccounts.count) accounts"
    $srcAccounts | `
        Where-Object { $_.safename -notIn $objectSafesToRemove } | `
        Select-Object 'name', 'address', 'userName', 'safeName', 'platformId', 'id', @{ name = 'PasswordLastChangeUTC'; Expression = { "$((([System.DateTimeOffset]::FromUnixTimeSeconds($_.secretManagement.lastModifiedTime)).DateTime).ToString())" } } |`
        Export-Csv -Path $exportCSV -NoTypeInformation
    Write-LogMessage -type Info -MSG "Export of $($srcAccounts.count) accounts completed. All other switches will be ignored"
}
Function Import-Accounts {
    # .SYNOPSIS
    # Import a list of accounts to be used by Sync-Safe and Sync-Accounts
    # .DESCRIPTION
    # Import accounts from a CSV and stores them in a variable called AccountList to be used by Sync-Safe and Sync-Accounts. Default name of feed file called ExportOfAccounts.csv
    param (
        <#
    Path and filename for use by Export
    #>
        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        [string]$importCSV = '.\ExportOfAccounts.csv'
    )
    [array]$script:AccountList = Import-Csv $importCSV -ErrorAction SilentlyContinue
    Write-LogMessage -type Info -MSG "Imported $($script:AccountList.count) accounts from `"$importCSV`""
    IF ($global:SuperVerbose) {
        Write-LogMessage -type Verbose -MSG "SuperVerbose: Imported Accounts: $($script:AccountList |ConvertTo-Json -Depth 9 -Compress)"
    }
}
Function Get-Accountlist {
    $script:AccountList
}
Function Set-AccountList {
    param (
        <#
    New Account list
    #>
        [Parameter(Mandatory = $true, ValueFromPipeline)]
        [PSCustomObject]$newAccountList
    )
    Set-Variable -Scope Script -Name AccountList -Value $newAccountList

}
Function Clear-Accountlist {
    Remove-Variable -Scope Script -Name AccountList -ErrorAction SilentlyContinue
}

Function Sync-Safes {
    <#
    .SYNOPSIS
    Synchronizes the safes between the two environments
    .DESCRIPTION
Using the variable AccountList to target specific safes connects to the two environments does the following process
- Determines if the safe already exists in the destination environment
	- If the safe does not exist, create the safe if CreateSafes switch is passed
- Updates safe ownerships on newly created safes based on the ownership in the source environment
- If the safe does exist and UpdateSafeMembers switch is passed updates safe ownerships on safes based on the ownership in the source environment

Prior to running ensure the following items in both environments are set
- The user that is running the command has direct access to all in scope safes in both environments
	- In the source environment the minimum ownerships are the following
		- List Accounts, Retrieve Accounts, View Safe members, Access Safe without confirmation (If dual control active)
	- In the destination environment the minimum ownerships are the following
		- Full Permission required
			- This is due to the requirement that you must have the permissions to be able to grant the permissions
	- Group membership in "Vault Admins" or "Auditors" will cause all accounts to be exported, including system level accounts which should not be migrated

Prior to running it is recommended that the following items in both environments are set.
- A dedicated "Export" and "Import" users are created

After running the following items are recommended
- After beginning use of the destination environment and verifications have been completed, delete the user account used to import safes
- The import user will retain full permissions to any safe it created, the easiest and most secure method to ensure that access is removed is to delete the user.

To get further information about the paramaters use "Get-Help Sync-Safes -full"
            #>
    [CmdletBinding(PositionalBinding = $false)]
    param (
        <#
        Automatically create safes in destination environment if not found.
        #>
        [Parameter(ValueFromPipelineByPropertyName)]
        [Switch]$CreateSafes,
        <#
        Automatically update safe members permissions in destination environment to match source environment.
        - May result in loss of permissions
        #>
        [Parameter(ValueFromPipelineByPropertyName)]
        [Switch]$UpdateSafeMembers,
        <#
        Name of the old CPM which will be replaced
        #>
        [Parameter(ValueFromPipelineByPropertyName)]
        [String]$CPMOld,
        <#
        Name of the new CPM which will be used in place of CPMOld
        #>
        [Parameter(ValueFromPipelineByPropertyName)]
        [String]$CPMNew,
        <#
        Name of CPM to be used in all creation
        - Overrides CPMOld and CPMNew
        #>
        [Parameter(ValueFromPipelineByPropertyName)]
        [String]$CPMOverride,
        <#
        Array of strings with the names of CPM servers currently in the source environment so they can be skipped during ownership processing
        #>
        [Parameter(ValueFromPipelineByPropertyName)]
        [String[]]$CPMList,
        <#
        Array of strings with the names of owners that should not be migrated
        #>
        [Parameter(ValueFromPipelineByPropertyName)]
        [String[]]$OwnersToExclude,
        <#
        Name of directory in the destination
        For PCloud destinations this should be the DirectoryServiceUuid
        #>
        [Parameter(ValueFromPipelineByPropertyName)]
        [String]$newDir,
        <#
        Domain name to be added to safe owners who are memberType of "user" when searching the destination environment
        - Should be added when going from a environment not using UPN names to PCloud
        - Example:
            - dstDomainSuffix = Lab.local
            - SourceUsername = Admin
            - End result of username
                Admin@lab.local
        #>
        [Parameter(ValueFromPipelineByPropertyName)]
        [String]$dstDomainSuffix,
        <#
	Removes the prior domain by doing a match to "@" and using everything to the left
        #>
        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]$srcRemoveDomain,
        <#
        The amount of jobs that should be running at one time
        #>
        [Parameter(ValueFromPipelineByPropertyName)]
        [String]$maxJobCount = 10,
        <#
        Display details of jobs in progress bar
        Not recommended if maxJobCount is higher then 5
        #>
        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]$ProgressDetails,
        <#
        Suppress Progress bar being displayed
        #>
        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]$SuppressProgress,
        <#
Switch to prevent running in powershell job
#>
        [switch]$RunSingle,
        [switch]$SuppressCPMWarning
    )

    Write-LogMessage -type Info -MSG "Starting safe processing at $(Get-Date -Format 'HH:mm:ss')"

    Initialize-Function
    Test-SessionsValid
    Test-AccountList
    $global:DomainList = $script:DomainList
    #region Safe Work

    $cpmUsers = Get-CPMUsers -SuppressCPMWarning:$SuppressCPMWarning
    $cpmSafes = @()
    $cpmUsers | ForEach-Object {
        $cpmSafes += "$($PSitem)"
        $cpmSafes += "$($PSitem)_Accounts"
        $cpmSafes += "$($PSitem)_ADInternal"
        $cpmSafes += "$($PSitem)_Info"
        $cpmSafes += "$($PSitem)_workspace"
    }

    $SafesToRemove = $cpmSafes
    $SafesToRemove += $script:objectSafesToRemove
    Write-LogMessage -type Debug "$($SafesToRemove.Count) safes in safes to remove list"


    [array]$safeobjects += $script:AccountList | `
        Select-Object -Property safeName -Unique | `
        Where-Object { $_.safename -notIn $SafesToRemove } | `
        ForEach-Object { $PSItem }

    Write-LogMessage -type Info -MSG "Found $($safeobjects.count) unique safes for processing"

    $safeobjects | Add-Member -MemberType NoteProperty -Name ID -Value $null -Force

    $i = 0
    foreach ($id in $safeobjects) {
        $safeobjects[$i].id = $i + 1
        $i++
    }

    $ownersToRemove = $script:ownersToRemove
    $ownersToRemove += $CPMList
    $ownersToRemove += $cpmUsers
    If (![String]::IsNullOrEmpty($OwnersToExclude)) {
        $ownersToRemove += $OwnersToExclude
    }

    Write-LogMessage -type Debug "$($ownersToRemove.Count) owners in owners to remove list"
    Write-LogMessage -type Verbose "$($ownersToRemove|ConvertTo-Json -Depth 9 -Compress)"

    New-Item -ItemType Directory -Force -Path .\LogFiles-Safes\ | Out-Null
    $safeProgress = @{}
    $safeobjects | ForEach-Object { $safeProgress.($_.id) = @{} }
    $safeProgressSync = [System.Collections.Hashtable]::Synchronized($safeProgress)
    Write-LogMessage -type Info -MSG "Setup of safe job object completed. Starting to submit jobs at $(Get-Date -Format 'HH:mm:ss')."
    #region ForEach-Object
    If (($([Version]$PSVersionTable.PSVersion).Major -le 5) -or $RunSingle ) {
        Write-LogMessage -type Info -MSG 'Processing Safes one at a a time'
        $safeobjects | ForEach-Object {
            Invoke-ProcessSafe -SafeName $PSItem.Safename
        }
    }
    else {
        Write-LogMessage -type Info -MSG 'Processing Safes using PowerShell Jobs'
        If ([string]::IsNullOrEmpty($SuperVerbose)) {
            $SuperVerbose = $false
        }
        $safeJob = $safeobjects | ForEach-Object -ThrottleLimit $maxJobCount -AsJob -Parallel {

            #region Setup for Using
            $global:InDebug = $Using:InDebug
            $global:InVerbose = $Using:InVerbose
            $global:SuperVerbose = $using:SuperVerbose
            $srcToken = $using:srcToken
            $srcPVWAURL = $using:srcPVWAURL
            $dstToken = $using:dstToken
            $dstPVWAURL = $using:dstPVWAURL
            $objectSafesToRemove = $Using:objectSafesToRemove
            $ownersToRemove = $using:ownersToRemove
            $DomainList = $using:DomainList

            $CreateSafes = $using:CreateSafes
            $UpdateSafeMembers = $using:UpdateSafeMembers
            $srcRemoveDomain = $using:srcRemoveDomain
            $dstDomainSuffix = $using:dstDomainSuffix
            $newDir = $using:newDir
            $CPMnew = $using:CPMnew
            $CPMOld = $using:CPMOld
            $CPMOverride = $using:CPMOverride


            $syncCopy = $using:safeProgressSync


            $global:safename = $($PSItem.safeName)
            $global:LOG_FILE_PATH = ".\LogFiles-Safes\$safename.log"

            Import-Module -Name '.\CyberArk-Migration.psm1' -Force
            . '.\Invoke-Process.ps1'
            Function Write-LogMessage {
                param(
                    [String]$MSG,
                    [Switch]$NoWrite,
                    [String]$type
                )
                $SafeStatus.log += "`[$safename`] $msg"
                If ('error' -eq $type) {
                    $SafeStatus.Error += $MSG
                }
                if (!$NoWrite) {
                    CyberArk-Migration\Write-LogMessage -MSG $MSG -type $type -LogFile $LOG_FILE_PATH @Args
                    $process.Status = $msg
                }
            }


            #region Setup Progress
            $process = $syncCopy.$($PSItem.Id)
            $process.Id = $PSItem.Id
            $process.Activity = "Processing safe $($PSItem.safeName)"
            $process.Status = 'Starting'
            #endregion Setup Progress
            #region Setup Logging
            [hashtable]$SafeStatus = @{
                id                = $PSItem.id
                safeName          = $PSItem.safeName
                success           = $false
                createSkip        = $false
                UpdateMembersFail = $false
                safeData          = $PSItem
                Log               = @()
                Error             = @()
            }
            #endregion Setup Logging
            #endregion Setup for Using
            Try {
                #region Actual work
                Invoke-ProcessSafe -SafeName $safename -SafeStatus $SafeStatus
                #endregion Actual work
                #endregion ForEach-Object
            }
            Finally {
                Write-LogMessage -type Info -MSG "Completed work with safe `"$safename`""
                If ($SuperVerbose) {
                    Write-LogMessage -type Verbose -MSG "SuperVerbose: Final `$SafeStatus $($SafeStatus | ConvertTo-Json -Compress)"
                }
                else {
                    Write-LogMessage -type Verbose -MSG "Final `$SafeStatus $($SafeStatus |Select-Object -Property Id,SafeName,createSkip,Success,UpdateMembersFail | ConvertTo-Json -Depth 1 -Compress)"
                }
                $SafeStatus
                $process.Completed = $true
            }
        }
        Write-LogMessage -type Info -MSG "Submission of $($safeJob.ChildJobs.Count) jobs completed at $(Get-Date -Format 'HH:mm:ss'). Maxiumn running PowerShell jobs set to $maxJobCount."
        $PSStyle.Progress.View = 'Classic'
        while ($safeJob.State -eq 'Running') {
            $safeProgressSync.Keys | ForEach-Object {
                if (![string]::IsNullOrEmpty($safeProgressSync.$_.keys)) {
                    if (!$SuppressProgress) {
                        $completed = $($safeJob.ChildJobs | Where-Object { $_.State -eq 'Completed' }).count
                        $total = $safeJob.ChildJobs.count
                        $Precent = ($completed / $total) * 100
                        $process = @{}
                        $process.Id = 0
                        $process.Activity = 'Processing Safes'
                        $process.Status = "$completed out of $total jobs completed"
                        $process.PercentComplete = $Precent
                        Write-Progress @process
                        if ($ProgressDetails.IsPresent) {
                            $param = $safeProgressSync.$_
                            $param.ParentId = 0
                            Write-Progress @param
                        }
                    }
                }
            }
            Start-Sleep -Seconds 0.5
        }
        Write-Progress -Id 0 -Completed $true
        # Wait to refresh to not overload gui
        Write-LogMessage -type Info 'All safes processed, generating results'

        $($SafeReport = Receive-Job $Safejob -Keep) 6> $null 5> $null 4> $null 3> $null 2> $null 1> $null
        $SafeSuccess = $SafeReport | Where-Object { ($PSItem.success -EQ $true) -and ($PSItem.createSkip -eq $false) }
        $SafeCreateSkip = $SafeReport | Where-Object { ($PSItem.success -EQ $true) -and ($PSItem.createSkip -eq $true) }
        $SafeFailed = $SafeReport | Where-Object { $PSItem.success -EQ $false }
        $SafeUpdateMembersFail = $SafeReport | Where-Object { $PSItem.UpdateMembersFail -EQ $true }
        If (![string]::IsNullOrEmpty($SafeFailed)) {
            $SafeFailed.SafeData | Add-Member -MemberType NoteProperty -Name FailReason -Value $null -Force
            If ($SafeFailed.SafeData.count -eq 1) {
                $SafeFailed.SafeData.FailReason = $SafeFailed.Error
            }
            else {
                $i = 0
                foreach ($id in $SafeFailed) {
                    $SafeFailed[$i].SafeData.FailReason = $SafeFailed[$i].Error
                    $i++
                }
            }

            $SafeFailed.SafeData | Export-Csv .\FailedSafes.csv
        }
        Write-LogMessage -type Info "Safes succesfully processed: $($SafeSuccess.success.count)"
        Write-LogMessage -type Info "Safes creation skipped: $($SafeCreateSkip.success.count)"
        Write-LogMessage -type Info "Safes processing failed: $($SafeFailed.success.count)"
        Write-LogMessage -type Info "Safes membership add or updates failed: $($SafeUpdateMembersFail.success.count)"
    }
    Write-LogMessage -type Info "Processing of safes completed at $(Get-Date -Format 'HH:mm:ss')"
}
function Sync-Accounts {
    <#
    .SYNOPSIS
    Synchronizes the accounts between the two environments
    .DESCRIPTION
Using the variable AccountList to target specific accounts connects to two environments does the following process
- If VerifyPlatform is passed get a list of all platforms on destination environment
    - For each future create verify that the platform from the source environment exist in the destination environment, if it doesn't fail the create
    - For each future create update the platformID casing to match the casing in the destination environment
- Determines if the account already exists in the destination environment and the source account has a secret set
    - If the account does not exist create the account unless NoCreate is passed
    - If the account does not have a secret set, do not create the account unless allowEmpty is passed
- Unless SkipCheckSecret is passed, for each existing account found, verify that the secret matches between the source and destination
    - Whenever possible ensures that secrets for both the source and destination are stored in variables as SecureStrings and only retained for as long as needed and then removed.
- If getRemoteMachines is passed, update the destination account with the values from the source account

Prior to running ensure the following items in both environments are set
- CPMs stopped in both environments
  - This is to prevent password from being locked due to CPM initiated changes and password unexpectedly changing
- "Enforce check-in/check-out exclusive access" is inactive
  - Due to the command reading the secret in both environments if Exclusive use is enabled all accounts will become locked to the user running the command
- "Enforce one-time password access" is inactive
  - If enabled all secrets will change based on the platform MinValidityPeriod and exclusive access settings
- "Require dual control password access approval" is inactive or the user running the commands has "Access Safe without Confirmation" for all in scope safes
  - If "DisableDualControlForPSMConnections" is set to "Yes" on the platform either "dual controls" must be set to inactive or the platform updated to have "DisableDualControlForPSMConnections" set to "No".
    - This is due to a limitation in the REST interface
- Ensure all in scope accounts are unlocked
  - This can easiest be done by using PrivateArk Client.
    - After logging in "CTRL + F", select "Advanced" tab, check only "Locked", and clicking "Find".
    - All locked accounts will be displayed in the results pane, click in this pane and then select "Edit", "Select All".
      - With everything highlighted, right click and then select "Unlock File"
      - All locked files will now be unlocked.
        - Unlocking this way will NOT trigger the CPM to change the password when restarted.

Prior to running it is recommended that the following items in both environments are set.
- A dedicated "Export" and "Import" users are created
- "NFNotifyOnPasswordUsed" is set to "No" to ensure a large amount of emails are not generated
  - If "Yes", ensure that "Event Notification Engine" is stopped and you delete "\PrivateArk\Safes\ENE\ENELastEventID.dat" prior to restarting.
    - In Privilege Cloud environments clients do not have access to the ENE.
- "EnforcePasswordPolicyOnManualChange" is set to "No"
  - This will allow for the currently in use secrets, and prior secrets, to be used to ensure they are synchronized between environments
- "AutoChangeOnAdd" are set to "No"
  - The will prevent the secrets from automatically changing when the CPM in the destination is turned on
- "AutoVerifyOnAdd" are set to "No"
  - This will prevent the CPM from having a large workload on initial startup after work

After running the following items are recommended
- Any "Master Policy" or "Platform" settings adjusted to allow for export and import are reset back to standard values
- Only the environment that is currently being actively used has a running CPM.
- IF CPMs are required to be running in both environments, ensure each safe has a CPM assigned in only one environment at a time.
- Prior to beginning use of the destination environment, verify no password have changed in the source environment that have not been synchronized.
  - You can see the data of last secret change of the source account by running "Export-Accounts" and reviewing the column titled "PasswordLastChangeUTC".
    - The time zone used to display the date and time of last password change is UTC (+0)
  - If secretes have changed remove all other entries in the CSV, leaving on the accounts with secret changes, and use "Import-Account" to target those accounts specifically
- After beginning use of the destination environment and verifications have been completed, delete the user account used to import safes
  - The import user will retain full permissions to any safe it created, the easiest and most secure method to ensure that access is removed is to delete the user.

To get further information about the paramaters use "Get-Help Sync-Accounts -full"
#>
    [CmdletBinding(PositionalBinding = $false)]
    param (
        <#
        Skip checking of existing secrets
        #>
        [Parameter(Mandatory = $false)]
        [Switch]$SkipCheckSecret,
        <#
        Update Allowed Remote Machines on accounts
        #>
        [Parameter(Mandatory = $false)]
        [switch]$getRemoteMachines,
        <#
        Prevent creation of accounts
        #>
        [Parameter(Mandatory = $false)]
        [Switch]$noCreate,
        <#
        Allow Create eation of accounts with empty secrets
        #>
        [Parameter(Mandatory = $false)]
        [Switch]$allowEmpty,
        <#
        Verify platform exists in destination and if needed correct casing to prevent creation error
        #>
        [Parameter(Mandatory = $false)]
        [Switch]$VerifyPlatform,
        <#
        The amount of jobs that should be running at one time
        #>
        [Parameter(Mandatory = $false)]
        [String]$maxJobCount = 10,
        <#
        Display details of jobs in progress bar
        Not recommended if maxJobCount is higher then 5
        #>
        [Parameter(Mandatory = $false)]
        [switch]$ProgressDetails,
        <#
        Suppress Progress bar being displayed
        #>
        [Parameter(Mandatory = $false)]
        [switch]$SuppressProgress
    )
    Write-LogMessage -type Info -MSG "Starting account processing at $(Get-Date -Format 'HH:mm:ss')"

    Initialize-Function
    Test-SessionsValid
    Test-AccountList
    Write-LogMessage -type debug -MSG 'All tests passed'

    IF ($VerifyPlatform) {
        Write-LogMessage -type Info -MSG 'VerifyPlatform set, retriving platforms for destination environment'
        $platforms = (Get-Platforms -url $dstPVWAURL -logonHeader $dstToken)
        Write-LogMessage -type debug -MSG "$($platforms.count) platforms retrieved from destination environment"
    }
    else {
        $platforms = 'Skipped'
    }

    [array]$accountobjects = $script:AccountList | ForEach-Object { $PSItem }
    $accountobjects | Add-Member -MemberType NoteProperty -Name ProcessID -Value $null -Force

    $i = 0
    foreach ($id in $accountobjects) {
        $accountobjects[$i].ProcessID = $i + 1
        $i++
    }

    $today = Get-Date -Format 'yyyyMMdd-HHmmss'
    $AccountsLogPath = ".\LogFiles-Accounts\$today"
    New-Item -ItemType Directory -Force -Path $AccountsLogPath | Out-Null
    $accountProgress = @{}
    $accountobjects | ForEach-Object { $accountProgress.($_.ProcessID) = @{} }
    $accountProgressSync = [System.Collections.Hashtable]::Synchronized($accountProgress)
    Write-LogMessage -type Debug -MSG "Setup of account object completed. Starting to submit jobs at $(Get-Date -Format 'HH:mm:ss')."
    Try {
        $AccountJob = $accountobjects | ForEach-Object -ThrottleLimit $maxJobCount -AsJob -Parallel {


            $global:InDebug = $Using:InDebug
            $global:InVerbose = $Using:InVerbose

            $SkipCheckSecret = $Using:SkipCheckSecret
            $objectSafesToRemove = $Using:objectSafesToRemove
            $getRemoteMachines = $using:getRemoteMachines
            $noCreate = $using:noCreate
            $allowEmpty = $using:allowEmpty
            $VerifyPlatform = $using:VerifyPlatform
            If ($using:VerifyPlatform) {
                $platforms = $using:platforms
            }

            $srcToken = $using:srcToken
            $srcPVWAURL = $using:srcPVWAURL
            $dstToken = $using:dstToken
            $dstPVWAURL = $using:dstPVWAURL

            $baseAccount = $PSItem
            $global:accountID = $($PSItem.id)
            $global:accountName = $($PSItem.name)
            $global:safeName = $($PSItem.safeName)
            $global:LOG_FILE_PATH = ".\$($using:AccountsLogPath)\$safeName-$accountName-$accountID-.log"
            Import-Module .\CyberArk-Migration.psm1 -Force

            #endregion
            Function Write-LogMessage {
                param(
                    [String]$MSG,
                    [Switch]$NoWrite,
                    [String]$type
                )
                $AccountStatus.log += "`[$accountID`] $msg"
                If (('error' -eq $type) -or ('Warning' -eq $type) ) {
                    $AccountStatus.Error += $MSG
                }
                if (!$NoWrite) {
                    CyberArk-Migration\Write-LogMessage -MSG $MSG -type $type -LogFile $LOG_FILE_PATH @Args
                    $process.Status = $msg
                }
            }

            Try {

                $syncCopy = $using:accountProgressSync
                $process = $syncCopy.$($baseAccount.ProcessID)
                $process.Id = $PSItem.ProcessID
                $process.Activity = "Processing account $($baseAccount.name)"
                $process.Status = 'Starting'
                #endregion
                #region Setup Logging
                $AccountStatus = @{
                    id          = $PSItem.ProcessID
                    accountName = $PSItem.name
                    success     = $false
                    Log         = @()
                    accountData = $PSItem
                    Error       = @()
                }
                $dstAccountFound = $false

                Write-LogMessage -type Info -MSG "Working with source account with username `"$($baseAccount.userName)`" and address `"$($baseAccount.address)`" in safe `"$($baseAccount.safeName)`""
                Try {
                    $srcAccount = Get-AccountDetail -url $srcPVWAURL -logonHeader $srcToken -AccountID $baseAccount.id
                }
                catch {
                    Write-LogMessage -type Error -MSG "Unable to connect to source account to retrieve username `"$($baseAccount.userName)`" and address `"$($baseAccount.address)`" in safe `"$($baseAccount.safeName)`""
                    Write-LogMessage -type Error -MSG $PSitem
                    Write-LogMessage -type Debug -MSG "$srcAccount = Get-AccountDetail -url $srcPVWAURL -logonHeader $srcToken -AccountID $baseAccount.id"
                    continue
                }
                If ($($srcAccount.safename) -in $objectSafesToRemove) {
                    Write-LogMessage -type Info -MSG "Safe $($srcAccount.safename) is in the excluded safes list. Account with username of `"$($srcAccount.userName)`" with the address of `"$($srcAccount.address)`" will be skipped"
                    $AccountStatus.success = $true
                    continue
                }
                Write-LogMessage -type Debug -MSG 'Found source account'
                Write-LogMessage -type Verbose -MSG "Source account: $($srcAccount |ConvertTo-Json -Compress)"
                Write-LogMessage -type Debug -MSG "Searching for destination account with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`""
                # Removing and testing due to change in behavior REST API
                # If([string]::IsNullOrEmpty($srcAccount.userName) -or [string]::IsNullOrEmpty($srcAccount.address)) {
                #     Write-LogMessage -type Error -MSG "Source account with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`" is missing username or address. Skipping account."
                #     $AccountStatus.success = $false
                #     continue
                # }
                [array]$dstAccountArray = Get-Accounts -url $dstPVWAURL -logonHeader $dstToken -safename $($srcAccount.safeName) -keywords "$($srcAccount.userName) $($srcAccount.address)" -startswith $true
                if ((0 -ne $($dstAccountArray.count))) {
                    Write-LogMessage -type Verbose -MSG "Results array from destination: $($dstAccountArray | ConvertTo-Json -Compress)"
                    Write-LogMessage -type Debug -MSG "Found $($dstAccountArray.count) possible destination accounts"
                    foreach ($account in $dstAccountArray) {
                        Write-LogMessage -type Debug -MSG "Comparing found account `"$($account.name)`" to source account of `"$($srcAccount.name)`""
                        IF (($($account.name) -eq $($srcAccount.name)) -and ($($account.userName) -eq $($srcAccount.userName)) -and ($($account.address) -eq $($srcAccount.address)) -and ($($account.safeName) -eq $($srcAccount.safeName))  ) {
                            Write-LogMessage -type Debug -MSG "Found destination account with username `"$($account.userName)`" and address `"$($account.address)`" in safe `"$($account.safeName)`""
                            Write-LogMessage -type Verbose -MSG "Destination account: $($account | ConvertTo-Json -Compress)"
                            $dstAccountFound = $true
                            $dstAccount = $account
                        }
                    }
                }
                else {
                    Write-LogMessage -type Warning -MSG "Unable to locate destination account `"$($srcAccount.Name)`" in destination safe `"$($srcAccount.safeName)`""
                }

                if ($dstAccountFound) {
                    if (!$SkipCheckSecret) {
                        Write-LogMessage -type debug -MSG 'SkipCheckSecret set to false. Starting check on source and destination secrets'
                        Try {
                            Write-LogMessage -type Debug -MSG 'Getting source Secret'
                            [SecureString]$srcSecret = Get-Secret -url $srcPVWAURL -logonHeader $srcToken -id $srcAccount.id -ErrorAction SilentlyContinue
                            Write-LogMessage -type Debug -MSG "Source secret found: $(!$([string]::IsNullOrEmpty($srcSecret)))"
                            if ($null -eq $srcSecret) {
                                Write-LogMessage -type Info -MSG 'No secret found on source account. No change will be made to destination secret.'
                                $AccountStatus.success = $true
                                Continue
                            }
                            Write-LogMessage -type Debug -MSG 'Getting destination Secret'
                            [SecureString]$dstSecret = Get-Secret -url $dstPVWAURL -logonHeader $dstToken -id $dstAccount.id -ErrorAction SilentlyContinue
                            Write-LogMessage -type Debug -MSG "Destination secret found: $(!$([string]::IsNullOrEmpty($srcSecret)))"
                            If ((![string]::IsNullOrEmpty($srcSecret)) -and (![string]::IsNullOrEmpty($dstSecret)) ) {
                                Write-LogMessage -type Debug -MSG 'Comparing secrets'
                                $secretMatch = Compare-SecureString -pwd1 $srcSecret -pwd2 $dstSecret
                            }
                            if ($null -eq $dstSecret -and $null -ne $srcSecret) {
                                Write-LogMessage -type Debug -MSG "No secret found on destination account $($dstAccount.Name). Setting destination secret to match source secret."
                                Set-Secret -url $dstPVWAURL -logonHeader $dstToken -id $dstAccount.id -Secret $srcSecret
                                Write-LogMessage -type Info -MSG "Destination account with username `"$($dstAccount.userName)`" and address `"$($dstAccount.address)`" in safe `"$($dstAccount.safeName)`" secret set to match source account."
                                $AccountStatus.success = $true
                            }
                            elseif (!$secretMatch) {
                                Write-LogMessage -type Debug -MSG "The secret for ource and destination account with username `"$($dstAccount.userName)`" and address `"$($dstAccount.address)`" in safe `"$($dstAccount.safeName)`" secret do not match. Setting destination secret to match source secret."
                                Set-Secret -url $dstPVWAURL -logonHeader $dstToken -id $dstAccount.id -Secret $srcSecret
                                Write-LogMessage -type Info -MSG "Destination account secret with username `"$($dstAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`" set to match source account."
                                $AccountStatus.success = $true
                            }
                            elseif ($secretMatch) {
                                Write-LogMessage -type Info -MSG 'Source and destination account secret match. No update required'
                                $AccountStatus.success = $true
                            }
                            else {
                                Write-LogMessage -type Warning -MSG "Unknown Error encountered while working with secrets for source and destination account with username `"$($dstAccount.userName)`" and address `"$($dstAccount.address)`" in safe `"$($dstAccount.safeName)`""
                            }
                        }
                        catch [System.Management.Automation.RuntimeException] {
                            If ('Account Locked' -eq $_) {
                                Write-LogMessage -type Warning -MSG "Source Account `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`" Locked to another user, unable to update."
                                Write-LogMessage -type Debug -MSG "$($PSitem.Exception)"
                            }
                            else {
                                Write-LogMessage -type Error -MSG "Error encountered while working with acount with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `" $($srcAccount.safeName)`": $($_.Exception.Message)" -ErrorAction SilentlyContinue
                                Write-LogMessage -type LogOnly -MSG "Error encountered while working with acount with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `": $($_|ConvertTo-Json -Compress)" -ErrorAction SilentlyContinue
                            }
                        }
                    }
                    Else {
                        Write-LogMessage -type Debug -MSG 'SkipCheckSecret set to true. No checks being done on source and destination secrets'
                        $AccountStatus.success = $true
                    }
                    if ($getRemoteMachines) {
                        Write-LogMessage -type Debug -MSG "getRemoteMachines set to true. Updating remoteMachinesAccess on destination account with usernam `"$($dstAccount.userName)`" and address `"$($dstAccount.address)`" in safe `" $($srcAccount.safeName)`""
                        Update-RemoteMachine -url $dstPVWAURL -logonHeader $dstToken -dstaccount $dstAccount -srcaccount $srcAccount
                    }
                }
                elseif ($noCreate) {
                    Write-LogMessage -type Warning -MSG "Destination account with username of `"$($dstAccount.userName)`" and address `"$($dstAccount.address)`" in safe safe `" $($srcAccount.safeName)`" does not exist and account creation disabled, skipping creation of account"
                    $AccountStatus.success = $true
                }
                else {
                    try {
                        If ($VerifyPlatform) {
                            Write-LogMessage -type info -MSG "Verifying platform with ID of `"$($srcAccount.platformId)`" exists in destination enviorment for account `"$($srcAccount.Name)`" in safe `"$($srcAccount.safeName)`""
                            Write-LogMessage -type Verbose -MSG "Source Accounts: $($srcAccount |ConvertTo-Json -Compress)"

                            $srcAccount.platformId = $($platforms.Platforms.general | Where-Object { $_.id -like $srcAccount.platformId }).id
                            if ([string]::IsNullOrEmpty($srcAccount.platformId )) {
                                Write-LogMessage -type Error -MSG "Unable to locate platform in destination for account with the username `"$($dstAccount.userName)`" and address `"$($dstAccount.address)`" in safe `" $($srcAccount.safeName)`" unable to create account"
                                Continue
                            }
                        }

                        Write-LogMessage -type info -MSG "Destination account with username `"$($dstAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`" does not exist. Attempting to create account."
                        Write-LogMessage -type info -MSG "Checking for destination safe `"$($srcAccount.safeName)`""
                        $dstsafe = Get-Safe -url $dstPVWAURL -logonHeader $dstToken -safe $srcAccount.safeName -ErrorAction SilentlyContinue
                        if ([string]::IsNullOrEmpty($dstsafe)) {
                            Write-LogMessage -type error -MSG "Destination safe of `"$($srcAccount.safeName)`" does not exist, skipping creation of account with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`""
                            continue
                        }
                        Write-LogMessage -type info -MSG "Destination safe `"$($srcAccount.safeName)`" found"
                        [SecureString]$srcSecret = Get-Secret -url $srcPVWAURL -logonHeader $srcToken -id $srcAccount.id -ErrorAction SilentlyContinue
                        IF (![string]::IsNullOrEmpty($srcSecret)) {
                            Write-LogMessage -type debug -MSG "Source account with username `"$($dstAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`" has a secret. Sending creation request to destination enviorment"
                            $dstAccount = New-Account -url $dstPVWAURL -logonHeader $dstToken -account $srcAccount -secret $srcSecret
                            Write-LogMessage -type Debug -MSG "Account with username `"$($dstAccount.userName)`" and address `"$($dstAccount.address)`" in safe `"$($dstAccount.safeName)`" succefully created in destination enviorment"
                        }
                        elseif ($allowEmpty) {
                            Write-LogMessage -type debug -MSG "Source account with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`" does not have a secret, but empty secrets are allowed. Sending creation request to destination enviorment"
                            $dstAccount = New-Account -url $dstPVWAURL -logonHeader $dstToken -account $srcAccount -allowEmpty
                            Write-LogMessage -type Debug -MSG "Account with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`" succefully created in destination enviorment"
                        }
                        else {
                            Write-LogMessage -type Warning -MSG "No password set on source account with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`""
                        }
                        $AccountStatus.success = $true
                    }
                    catch [System.Management.Automation.RuntimeException] {
                        If ('Account Locked' -eq $_.Exception.Message) {
                            Write-LogMessage -type Warning -MSG "Source Account with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`" Locked, unable to update"
                            Write-LogMessage -type Debug -MSG $PSitem
                        }
                        elseIf ($_.Exception.Message -match 'Safe .* was not found') {
                            Write-LogMessage -type Warning -MSG "Source safe `"$($srcAccount.safeName)`" not found"
                            Write-LogMessage -type Debug -MSG $PSitem
                        }
                        elseIf ($_.Exception.Message -match 'Platform .* was not found') {
                            Write-LogMessage -type Warning -MSG "Platform `"$($srcAccount.platformId)`" not found. Unable to create `"$($srcAccount.Name)`" in safe `"$($srcAccount.safeName)`""
                            Write-LogMessage -type Debug -MSG $PSitem
                        }
                        else {
                            Write-LogMessage -type Error -MSG "Error encountered while working with account with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`": $($_.Exception.Message)" -ErrorAction SilentlyContinue
                            Write-LogMessage -type LogOnly -MSG "Error encountered while working with `"$($srcAccount.Name)`": $($_|ConvertTo-Json -Compress)" -ErrorAction SilentlyContinue
                            Write-LogMessage -type Debug -MSG "Caught Exception:`n$($PSitem.Exception)"
                        }
                    }
                    catch {
                        Write-LogMessage -type Error -MSG "Error encountered while working with account with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`": $($_.Exception.Message)" -ErrorAction SilentlyContinue
                        Write-LogMessage -type LogOnly -MSG "Error encountered while working with `"$($srcAccount.Name)`": $($_|ConvertTo-Json -Compress)" -ErrorAction SilentlyContinue
                        Write-LogMessage -type Debug -MSG "Caught Exception:`n$($PSitem.Exception)"
                    }
                }
            } Catch {
                Write-LogMessage -type Error -MSG "Error in account processing for account `"$($baseAccount.name)`" in safe `"$($baseAccount.safeName)`""
                Write-LogMessage -type Error -MSG $PSItem
                Write-LogMessage -type Debug -MSG "$baseAccount = $PSItem"
                continue
            }
            Finally {
                $accountStatus
                $process.Completed = $true
            }
        }

        Write-LogMessage -type Info -MSG "Submission of $($AccountJob.ChildJobs.Count) jobs completed at $(Get-Date -Format 'HH:mm:ss'). Maxiumn running PowerShell jobs set to $maxJobCount."
        $PSStyle.Progress.View = 'Classic'
        while ($AccountJob.State -eq 'Running') {
            $accountProgressSync.Keys | ForEach-Object {
                if (![string]::IsNullOrEmpty($accountProgressSync.$_.keys)) {
                    if (!$SuppressProgress) {
                        $completed = $($AccountJob.ChildJobs | Where-Object { $_.State -eq 'Completed' }).count
                        $total = $AccountJob.ChildJobs.count
                        $Precent = ($completed / $total) * 100
                        $process = @{}
                        $process.Id = 0
                        $process.Activity = 'Processing Accounts'
                        $process.Status = "$completed out of $total jobs completed"
                        $process.PercentComplete = $Precent
                        Write-Progress -Id 0 @process
                        if ($ProgressDetails.IsPresent) {
                            $param = $accountProgressSync.$_
                            $param.ParentId = 0
                            Write-Progress @param
                        }
                    }
                }
            }
            # Wait to refresh to not overload gui
            Start-Sleep -Seconds .5
        }
    }
    Finally {
        Write-Progress -Id 0 -Completed $true
        $($AccountReport = Receive-Job $accountjob) 6> $null 5> $null 4> $null 3> $null 2> $null 1> $null
        $AccountSuccess = $AccountReport | Where-Object success -EQ $true
        $AccountFailed = $AccountReport | Where-Object success -EQ $false -ErrorAction SilentlyContinue
        Write-LogMessage -type Info "Accounts succesfully updated: $($accountSuccess.success.count)"
        Write-LogMessage -type Info "Accounts failed to updated: $($AccountFailed.success.count)"
        If (![string]::IsNullOrEmpty($AccountFailed)) {
            [array]$AccountFailed.accountData | Add-Member -MemberType NoteProperty -Name FailReason -Value $null -Force
            $i = 0
            foreach ($id in $AccountFailed) {
                $AccountFailed[$i].accountData.FailReason = [string]$AccountFailed[$i].Error
                $i++
            }
            $AccountFailed.accountData | Export-Csv -Force .\FailedAccounts.csv
            Write-LogMessage -type Error -MSG "Errors found, list outputted to `".\FailedAccounts.csv`""
        }
        Write-LogMessage -type Info "Processing of accounts completed at $(Get-Date -Format 'HH:mm:ss')"
    }
}

Function Set-DomainList {
    (
        [Parameter(Mandatory)]
        $domainJSon
    )
    $script:DomainList = $domainJSon
}


Function New-DomainList
(
    [Parameter(Mandatory)]
    $DomainName,
    [Parameter(Mandatory)]
    $DomainBaseContext
) {
    [hashtable]$script:DomainList = @{}
    $script:DomainList.add($DomainBaseContext, $DomainName)
}
Function New-DomainEntry
(
    [Parameter(Mandatory)]
    $DomainName,
    [Parameter(Mandatory)]
    $DomainBaseContext
) {
    IF ([string]::IsNullOrEmpty($script:domainlist)) {
        Write-LogMessage -type Warning -MSG 'No domain list exists, creating new domain list'
        New-DomainList -DomainName $DomainName -DomainBaseContext $DomainBaseContext
    }
    elseIF ([string]::IsNullOrEmpty($script:domainlist[$DomainBaseContext])) {
        $script:DomainList.add($DomainBaseContext, $DomainName)
    }
    else {
        Write-LogMessage -type Warning -MSG 'Existing Domain Base Context found. Updated to provided domain name'
        $script:DomainList.Remove($DomainBaseContext)
        $script:DomainList.add($DomainBaseContext, $DomainName)
    }
}

Function Remove-DomainEntry
(
    [Parameter(Mandatory)]
    $DomainName,
    [Parameter(Mandatory)]
    $DomainBaseContext
) {
    IF ([string]::IsNullOrEmpty($script:domainlist[$DomainBaseContext])) {
        Write-LogMessage -type Warning -MSG 'Existing Domain Base Context not found. No Changes Made'
    }
    else {
        $script:DomainList.Remove($DomainBaseContext)
        Write-LogMessage -type Warning -MSG 'Existing Domain Base Context found and removed'

    }
}

Function Import-DomainList () {
    Try {
        $Results = Get-Directories -url $script:srcPVWAURL -logonHeader $script:srcToken
        [hashtable]$script:DomainList = @{}
        $results | ForEach-Object { New-DomainEntry -DomainName $PSitem.DomainName -DomainBaseContext $PSitem.DomainBaseContext }
    }
    catch {
        Write-LogMessage -type Warning -MSG 'Error Importing Domain List, manually load directory list using New-DomainEntry'
    }
}
