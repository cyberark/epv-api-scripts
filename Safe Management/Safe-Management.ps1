<###########################################################################

 NAME: Manage Safes using REST API

 AUTHOR: Jake DeSantis, Carl Anderson, Brian Bors

 COMMENT:
 This script will help in Safe Management tasks

 SUPPORTED VERSIONS:
 CyberArk PVWA v12.1 and above
 CyberArk Privilege Cloud

 VERSION HISTORY:
 1.0 	16/12/2018   	- Initial release
 1.1 	06/02/2019   	- Bug fix
 1.9 	09/07/2021   	- Added ability to create new members on updates.
                    	  General Format cleanup according to standards
 2.0 	15/11/2021   	- Working only with 2nd Gen REST API of Safes. Supported version 12.1 and above
 2.0.1 	02/03/2021 	- Fix for v2
 2.1 	12/04/2021     	- Added ability to create report of safes
 2.1.1 	05/02/2022	- Updated catch to capture 404 error and allow for attempting to add.
 2.1.2  16/08/2022	- Temp Bug fix for MemberType
 2.1.3  24/08/2022      - Bug fix for updating safe due to changes in APIs in version 12.5
 2.1.4  17/03/2023      - Fix for issue #317
 2.1.5  22/05/2023      - Added ability to prevent logoff
 2.1.6  2023-05-22      - Updated Write-LogMessage to force verbose and debug to log file
 2.1.7  2024-04-17      - Updated to bypass attempt to add or update safe if no safe details exist
 2.1.8  2024-04-18      - Added ability to force Safe Creations
                   	    - Added "AddMembers" back
########################################################################### #>
[CmdletBinding(DefaultParameterSetName = 'List')]
param
(
    [Parameter(Mandatory = $true, HelpMessage = 'Please enter your PVWA address (For example: https://pvwa.mydomain.com/passwordvault)')]
    [Alias('url')]
    [String]$PVWAURL,

    [Parameter(Mandatory = $false, HelpMessage = 'Enter the Authentication type (Default:CyberArk)')]
    [ValidateSet('cyberark', 'ldap', 'radius')]
    [String]$AuthType = 'cyberark',

    [Parameter(Mandatory = $false, HelpMessage = 'Enter the RADIUS OTP')]
    [ValidateScript({ $AuthType -eq 'radius' })]
    [String]$OTP,

    # Use this switch to list Safes
    [Parameter(ParameterSetName = 'List', Mandatory = $true)][switch]$List,
    # Use this switch to Add Safes
    [Parameter(ParameterSetName = 'Add', Mandatory = $true)][switch]$Add,
    # Use this switch to Update Safes
    [Parameter(ParameterSetName = 'Update', Mandatory = $true)][switch]$Update,
    # Use this switch to Update Safe Members
    [Parameter(ParameterSetName = 'AddMembers', Mandatory = $true)][switch]$AddMembers,
    # Use this switch to Update Safe Members
    [Parameter(ParameterSetName = 'UpdateMembers', Mandatory = $true)][switch]$UpdateMembers,
    # Use this switch to Delete Safe Members
    [Parameter(ParameterSetName = 'DeleteMembers', Mandatory = $true)][switch]$DeleteMembers,
    # Use this switch to Delete Safes
    [Parameter(ParameterSetName = 'Delete', Mandatory = $true)][switch]$Delete,
    # Use this switch to Add Safe Members
    [Parameter(ParameterSetName = 'Members', Mandatory = $true)][switch]$Members,

    # Safe Name
    [Parameter(ParameterSetName = 'List', Mandatory = $false, HelpMessage = 'Enter a Safe Name to filter by')]
    [Parameter(ParameterSetName = 'Add', Mandatory = $false, HelpMessage = 'Enter a Safe Name to create')]
    [Parameter(ParameterSetName = 'Update', Mandatory = $false, HelpMessage = 'Enter a Safe Name to update')]
    [Parameter(ParameterSetName = 'Delete', Mandatory = $false, HelpMessage = 'Enter a Safe Name to delete')]
    [Parameter(ParameterSetName = 'Members', Mandatory = $true, HelpMessage = 'Enter a Safe Name to add members to')]
    [ValidateScript( { $_.Length -le 28 })]
    [Alias('Safe')]
    [String]$SafeName,

    # Safe Description
    [Parameter(ParameterSetName = 'Add', Mandatory = $false, HelpMessage = 'Enter a Safe Description')]
    [Parameter(ParameterSetName = 'Update', Mandatory = $false, HelpMessage = 'Enter an updated Safe Description')]
    [Alias('Description')]
    [String]$SafeDescription,

    # Import File support
    [Parameter(ParameterSetName = 'Add', Mandatory = $false, HelpMessage = 'Enter a file path for bulk safe creation')]
    [Parameter(ParameterSetName = 'Update', Mandatory = $false, HelpMessage = 'Enter a file path for bulk safe update')]
    [Parameter(ParameterSetName = 'AddMembers', Mandatory = $false, HelpMessage = 'Enter a file path for bulk safe membership update')]
    [Parameter(ParameterSetName = 'UpdateMembers', Mandatory = $false, HelpMessage = 'Enter a file path for bulk safe membership update')]
    [Parameter(ParameterSetName = 'DeleteMembers', Mandatory = $false, HelpMessage = 'Enter a file path for bulk safe membership deletion')]
    [Parameter(ParameterSetName = 'Delete', Mandatory = $false, HelpMessage = 'Enter a file path for bulk safe deletion')]
    [ValidateScript( { Test-Path -Path $_ -PathType Leaf -IsValid })]
    [ValidatePattern( '\.csv$' )]
    [Alias('File')]
    [String]$FilePath,

    [Parameter(ParameterSetName = 'List', Mandatory = $false, HelpMessage = 'Enter a file path for report output. Must be CSV')]
    [ValidatePattern( '\.csv$' )]
    [Alias('Report')]
    [String]$ReportPath,

    # Add / Update Safe options
    [Parameter(ParameterSetName = 'Add', Mandatory = $false, HelpMessage = 'Enter the managing CPM name')]
    [Parameter(ParameterSetName = 'Update', Mandatory = $false, HelpMessage = 'Enter the updated managing CPM name')]
    [string]$ManagingCPM,

    [Parameter(ParameterSetName = 'Add', Mandatory = $false, HelpMessage = 'Enter the number of versions retention')]
    [Parameter(ParameterSetName = 'Update', Mandatory = $false, HelpMessage = 'Enter the updated number of versions retention')]
    [int]$NumVersionRetention = 7,

    # Member Roles
    [Parameter(ParameterSetName = 'Members', Mandatory = $false, HelpMessage = 'Enter a role for the member to add (Default: EndUser)')]
    [ValidateSet('Admin', 'Auditor', 'EndUser', 'Owner', 'Approver')]
    [Alias('Role')]
    [String]$MemberRole = 'EndUser',

    # User / Member name
    [Parameter(ParameterSetName = 'Members', Mandatory = $false, HelpMessage = 'Enter the user name to add as member to the safe')]
    [ValidateScript( { $_.Length -le 128 })]
    [Alias('User')]
    [String]$UserName,

    # User / Member Vault Location
    [Parameter(ParameterSetName = 'Members', Mandatory = $false, HelpMessage = 'Enter the vault-integrated LDAP directory name the vault should search for the account. Must match one of the directory names defined in the LDAP Integration page of the PVWA. (Default: Search in Vault)')]
    [Alias('Location')]
    [String]$UserLocation = 'Vault',

    [Parameter(ParameterSetName = 'Members', Mandatory = $false, HelpMessage = 'Output default users in reports')]
    [Alias('Default')]
    [switch]$IncludeDefault,

    [Parameter(ParameterSetName = 'UpdateMembers', Mandatory = $false, HelpMessage = 'If member does not exist while updating, attempt to add them.')]
    [Switch]$AddOnUpdate,

    # Support for Threading (Logon Connection Number)
    [Parameter(Mandatory = $false, HelpMessage = 'Enable conncurrent session')]
    [switch]$concurrentSession = $false,

    # Use this switch to Disable SSL verification (NOT RECOMMENDED)
    [Parameter(Mandatory = $false)]
    [Switch]$DisableSSLVerify,
    # Use this switch to prevent Invoke-Logoff (NOT RECOMMENDED)
    [Parameter(Mandatory = $false)]
    [Switch]$DisableLogoff,
    # Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off
    [Parameter(Mandatory = $false)]
    $logonToken,
    # Use this switch to create safes when only safe name provided
    [Parameter(Mandatory = $false)]
    [Switch]$CreateSafeWithNameOnly,
    # Use this switch to pass PVWA credentials via PSCredential
    [Parameter(Mandatory = $false, HelpMessage = 'Vault Stored Credentials')]
    [PSCredential]$PVWACredentials

)

# Get Script Location
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
# Get Debug / Verbose parameters for Script
$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent

# Script Version
$ScriptVersion = '2.2.0'

# ------ SET global parameters ------
# Set Log file path
$global:LOG_DATE = $(Get-Date -Format yyyyMMdd) + '-' + $(Get-Date -Format HHmmss)
$global:LOG_FILE_PATH = "$ScriptLocation\SafeManagement_$LOG_DATE.log"
# Set a global Header Token parameter
$global:g_LogonHeader = ''
# Set a global safes list to improve performance
$global:g_SafesList = $null
# Set a global list of all Default sues to ignore
$global:g_DefaultUsers = @('Master', 'Batch', 'Backup Users', 'Auditors', 'Operators', 'DR Users', 'Notification Engines', 'PVWAGWAccounts', 'PVWAGWUser', 'PVWAAppUser', 'PasswordManager')
$global:g_includeDefaultUsers = $IncludeDefault
# Global URLS
# -----------
$URL_PVWAAPI = $PVWAURL + '/api'
$URL_Authentication = $URL_PVWAAPI + '/auth'
$URL_Logon = $URL_Authentication + "/$AuthType/Logon"
$URL_Logoff = $URL_Authentication + '/Logoff'

# URL Methods
# -----------
$URL_Safes = $URL_PVWAAPI + '/Safes'
$URL_SpecificSafe = $URL_Safes + '/{0}/'
$URL_SafeMembers = $URL_SpecificSafe + '/Members'
$URL_SafeSpecificMember = $URL_SpecificSafe + '/Members/{1}/'

#region Functions
#region REST Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Invoke-Rest
# Description....: Invoke REST Method
# Parameters.....: Command method, URI, Header, Body
# Return Values..: REST response
# =================================================================================================================================
Function Invoke-Rest {
    <#
.SYNOPSIS
Invoke REST Method
.DESCRIPTION
Invoke REST Method
.PARAMETER Command
The REST Command method to run (GET, POST, PATCH, DELETE)
.PARAMETER URI
The URI to use as REST API
.PARAMETER Header
The Header as Dictionary object
.PARAMETER Body
(Optional) The REST Body
.PARAMETER ErrAction
(Optional) The Error Action to perform in case of error. By default "Continue"
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
        [Alias('ErrorAction')]
        [String]$ErrAction = 'Continue'
    )

    $restResponse = ''
    try {
        if ([string]::IsNullOrEmpty($Body)) {
            Write-LogMessage -type Verbose -MSG "Invoke-RestMethod -Uri $URI -Method $Command -Header $($Header|ConvertTo-Json -Compress) -ContentType ""application/json"" -TimeoutSec 2700"
            $restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType 'application/json' -TimeoutSec 2700 -ErrorAction $ErrAction
        }
        else {
            Write-LogMessage -type Verbose -MSG "Invoke-RestMethod -Uri $URI -Method $Command -Header $($Header|ConvertTo-Json -Compress) -ContentType ""application/json"" -Body $($Body|ConvertTo-Json -Compress) -TimeoutSec 2700"
            $restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType 'application/json' -Body $Body -TimeoutSec 2700 -ErrorAction $ErrAction
        }
    }
    catch [System.Net.WebException] {
        if ($ErrAction -match ('\bContinue\b|\bInquire\b|\bStop\b|\bSuspend\b')) {
            Write-LogMessage -type Error -MSG "Error Message: $_"
            Write-LogMessage -type Error -MSG "Exception Message: $($_.Exception.Message)"
            Write-LogMessage -type Error -MSG "Status Code: $($_.Exception.Response.StatusCode.value__)"
            Write-LogMessage -type Error -MSG "Status Description: $($_.Exception.Response.StatusDescription)"
            $restResponse = $null
            Throw
        }
    }
    catch [Microsoft.PowerShell.Commands.HttpResponseException] {
        $Details = ($PSItem.ErrorDetails.Message | ConvertFrom-Json)
        If ('SFWS0007' -eq $Details.ErrorCode) {
            Write-LogMessage -type Verbose -MSG "$($Details.ErrorMessage)"
            Throw $PSItem
        }
        elseif ('PASWS013E' -eq $Details.ErrorCode) {
            Write-LogMessage -type Error -MSG "$($Details.ErrorMessage)" -Header -Footer
            exit 5
        }
        elseif ('SFWS0002' -eq $Details.ErrorCode) {
            Write-LogMessage -type Warning -MSG "$($Details.ErrorMessage)"
            Throw "$($Details.ErrorMessage)"
        }
        Else {
            Write-LogMessage -type Error -MSG "Invoke-Rest: Error in running $Command on '$URI', $_.Exception"
            Throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $_.Exception))
        }
    }
    catch {
        Write-LogMessage -type Error -MSG "Invoke-Rest: Error in running $Command on '$URI', $_.Exception"
        Throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $_.Exception))
    }
    Write-LogMessage -type Verbose -MSG "Invoke-REST Response: $restResponse"
    return $restResponse
}


# @FUNCTION@ ======================================================================================================================
# Name...........: ConvertTo-URL
# Description....: HTTP Encode test in URL
# Parameters.....: Text to encode
# Return Values..: Encoded HTML URL text
# =================================================================================================================================
Function ConvertTo-URL($sText) {
    <#
.SYNOPSIS
	HTTP Encode test in URL
.DESCRIPTION
	HTTP Encode test in URL
.PARAMETER sText
	The text to encode
#>
    if ($sText.Trim() -ne '') {
        Write-LogMessage -type Debug -MSG "Returning URL Encode of $sText"
        return [URI]::EscapeDataString($sText)
    }
    else {
        return $sText
    }
}
Function Write-LogMessage {
    <#
.SYNOPSIS
	Method to log a message on screen and in a log file

.DESCRIPTION
	Logging The input Message to the Screen and the Log File.
	The Message Type is presented in colours on the screen based on the type

.PARAMETER LogFile
	The Log File to write to. By default using the LOG_FILE_PATH
.PARAMETER MSG
	The message to log
.PARAMETER Header
	Adding a header line before the message
.PARAMETER SubHeader
	Adding a Sub header line before the message
.PARAMETER Footer
	Adding a footer line after the message
.PARAMETER Type
	The type of the message to log (Info, Warning, Error, Debug)
#>
    param(
        [Parameter(Mandatory = $true)]
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
        [String]$LogFile = $LOG_FILE_PATH
    )
    try {
        If ($Header) {
            '=======================================' | Out-File -Append -FilePath $LOG_FILE_PATH
            Write-Host '======================================='
        }
        ElseIf ($SubHeader) {
            '------------------------------------' | Out-File -Append -FilePath $LOG_FILE_PATH
            Write-Host '------------------------------------'
        }

        $msgToWrite = "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')]`t"
        $writeToFile = $true
        # Replace empty message with 'N/A'
        if ([string]::IsNullOrEmpty($Msg)) {
            $Msg = 'N/A'
        }
        # Mask Passwords
        if ($Msg -match '((?:"password"|"secret"|"NewCredentials")\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w!@#$%^&*()-\\\/]+))') {
            $Msg = $Msg.Replace($Matches[2], '****')
        }
        # Check the message type
        switch ($type) {
            'Info' {
                Write-Host $MSG.ToString()
                $msgToWrite += "[INFO]`t$Msg"
            }
            'Warning' {
                Write-Host $MSG.ToString() -ForegroundColor DarkYellow
                $msgToWrite += "[WARNING]`t$Msg"
            }
            'Error' {
                Write-Host $MSG.ToString() -ForegroundColor Red
                $msgToWrite += "[ERROR]`t$Msg"
            }
            'Debug' {
                if ($InDebug -or $InVerbose) {
                    Write-Debug $MSG
                    $writeToFile = $true
                    $msgToWrite += "[DEBUG]`t$Msg"
                }
                else {
                    $writeToFile = $False
                }
            }
            'Verbose' {
                if ($InVerbose) {
                    Write-Verbose $MSG
                    $writeToFile = $true
                    $msgToWrite += "[VERBOSE]`t$Msg"
                }
                else {
                    $writeToFile = $False
                }
            }
        }
        If ($writeToFile) {
            $msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH
        }
        If ($Footer) {
            '=======================================' | Out-File -Append -FilePath $LOG_FILE_PATH
            Write-Host '======================================='
        }
    }
    catch {
        Write-Error "Error in writing log: $($_.Exception.Message)"
    }
}

Function Join-ExceptionMessage {
    <#
.SYNOPSIS
	Formats exception messages
.DESCRIPTION
	Formats exception messages
.PARAMETER Exception
	The Exception object to format
#>
    param(
        [Exception]$e
    )

    Begin {
    }
    Process {
        if ([string]::IsNullOrEmpty($e.Source)) {
            return $e.Message
        }
        $msg = 'Source:{0}; Message: {1}' -f $e.Source, $e.Message
        while ($e.InnerException) {
            $e = $e.InnerException
            $msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
        }
        return $msg
    }
    End {
    }
}

Function Get-LogonHeader {
    <#
.SYNOPSIS
	Get-LogonHeader
.DESCRIPTION
	Get-LogonHeader
.PARAMETER Credentials
	The REST API Credentials to authenticate
#>
    param(
        [Parameter(Mandatory = $true)]
        [pscredential]$Credentials,
        [Parameter(Mandatory = $false)]
        [string]$RadiusOTP,
        [Parameter(Mandatory = $false)]
        [boolean]$concurrentSession
    )
    if ([string]::IsNullOrEmpty($g_LogonHeader)) {
        # Disable SSL Verification to contact PVWA
        If ($DisableSSLVerify) {
            Disable-SSLVerification
        }
        # Create the POST Body for the Logon
        # ----------------------------------
        If ($concurrentSession) {
            $logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password; concurrentSession = $true } | ConvertTo-Json
        }
        else {
            $logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password } | ConvertTo-Json

        }
        # Check if we need to add RADIUS OTP
        If (![string]::IsNullOrEmpty($RadiusOTP)) {
            $logonBody.Password += ",$RadiusOTP"
        }
        try {
            # Logon
            $logonToken = Invoke-Rest -Command Post -URI $URL_Logon -Body $logonBody -ErrAction 'SilentlyContinue'

            # Clear logon body
            $logonBody = ''
        }
        catch {
            Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.Exception.Response.StatusDescription)", $_.Exception))
        }

        $logonHeader = $null
        If ([string]::IsNullOrEmpty($logonToken)) {
            Throw 'Get-LogonHeader: Logon Token is Empty - Cannot login'
        }


        try {
            # Create a Logon Token Header (This will be used through out all the script)
            # ---------------------------
            $logonHeader = @{Authorization = $logonToken }

            Set-Variable -Name g_LogonHeader -Value $logonHeader -Scope global
            Set-Variable -Name g_LogonHeader -Value $logonHeader -Scope global
        }
        catch {
            Throw $(New-Object System.Exception ('Get-LogonHeader: Could not create Logon Header Dictionary', $_.Exception))
            Throw $(New-Object System.Exception ('Get-LogonHeader: Could not create Logon Header Dictionary', $_.Exception))
        }
    }
}

Function Invoke-Logoff {
    <#
.SYNOPSIS
    <#
.SYNOPSIS
	Invoke-Logoff
.DESCRIPTION
	Logoff a PVWA session
#>
    try {
        # Logoff the session
        # ------------------
        If ($null -ne $g_LogonHeader) {
            Write-LogMessage -type Info -MSG 'Logoff Session...'
            Invoke-Rest -Method Post -Uri $URL_Logoff -Headers $g_LogonHeader -ContentType 'application/json' -TimeoutSec 2700 | Out-Null
            Set-Variable -Name g_LogonHeader -Value $null -Scope global
        }
    }
    catch {
        Throw $(New-Object System.Exception ('Invoke-Logoff: Failed to logoff session', $_.Exception))
    }
}

Function Disable-SSLVerification {
    <#
.SYNOPSIS
    <#
.SYNOPSIS
	Bypass SSL certificate validations
.DESCRIPTION
	Disables the SSL Verification (bypass self signed SSL certificates)
#>
    # Check if to disable SSL verification
    If ($DisableSSLVerify) {
        try {
            Write-Warning 'It is not Recommended to disable SSL verification' -WarningAction Inquire
            # Using Proxy Default credentials if the Server needs Proxy credentials
            [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
            # Using TLS 1.2 as security protocol verification
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            # Disable SSL Verification
            if (-not('DisableCertValidationCallback' -as [type])) {
                Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class DisableCertValidationCallback {
    public static bool ReturnTrue(object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors) { return true; }

    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(DisableCertValidationCallback.ReturnTrue);
    }
}
'@
            }

            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [DisableCertValidationCallback]::GetDelegate()
        }
        catch {
            Write-LogMessage -type Error -MSG "Could not change SSL validation. Error: $(Join-ExceptionMessage $_.Exception)"
        }
    }
    Else {
        try {
            Write-LogMessage -type Info -MSG 'Setting script to use TLS 1.2'
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        }
        catch {
            Write-LogMessage -type Error -MSG "Could not change SSL setting to use TLS 1.2. Error: $(Join-ExceptionMessage $_.Exception)"
        }
    }
}

Function Get-Safes {
    <#
.SYNOPSIS
Lists the cyberark safes that the APIUser has access to

.DESCRIPTION
Lists the cyberark safes that the APIUser has access to

.EXAMPLE
Get-Safes

#>

    [CmdletBinding()]
    [OutputType([String])]
    Param()
    try {
        If ($null -eq $g_SafesList) {
            Write-LogMessage -type Debug -MSG 'Retrieving safes from the vault...'
            $GetSafesList = @()
            $safes = (Invoke-Rest -URI $URL_Safes -Command GET -Header $g_LogonHeader)
            $safes = (Invoke-Rest -URI $URL_Safes -Command GET -Header $g_LogonHeader)
            $GetSafesList += $safes.value
            Write-LogMessage -type Debug -MSG "Total safes response: $($safes.count)"
            $nextLink = $safes.nextLink
            Write-LogMessage -type Debug -MSG $nextLink
				
            While ($nextLink -ne '' -and $null -ne $nextLink) {
                $safes = (Invoke-Rest -Command Get -Uri $("$PVWAURL/$nextLink") -Header $g_LogonHeader )
                $safes = (Invoke-Rest -Command Get -Uri $("$PVWAURL/$nextLink") -Header $g_LogonHeader )
                $nextLink = $safes.nextLink
                Write-LogMessage -type Debug -MSG $nextLink
                $GetSafesList += $safes.value
                Write-LogMessage -type Debug -MSG "Current safes collected: $($GetSafesList.count)"
            }
            Set-Variable -Name g_SafesList -Value $GetSafesList -Scope Global
        }
        return $g_SafesList
    }
    catch {
        Throw $(New-Object System.Exception ('Get-Safes: There was an error retrieving the safes from the Vault.', $_.Exception))
    }

}

Function Get-Safe {
    <#
.SYNOPSIS
Get all Safe details on a specific safe

.DESCRIPTION
Get all Safe details on a specific safe

.EXAMPLE
Get-Safe -safeName "x0-Win-S-Admins"

#>
    param (
        [ValidateScript( { $_.Length -le 28 })]
        [String]$safeName
    )
    Write-LogMessage -type Verbose -MSG "In Get-Safe"
    $_safe = @()
    try {
        $accSafeURL = $URL_SpecificSafe -f $(ConvertTo-URL $safeName)
        $_safe += $(Invoke-Rest -Uri $accSafeURL -Command 'Get' -Header $g_LogonHeader -ErrAction 'SilentlyContinue')
        $_safe += $(Invoke-Rest -Uri $accSafeURL -Command 'Get' -Header $g_LogonHeader -ErrAction 'SilentlyContinue')
        If (![string]::IsNullOrEmpty($_safe.nextLink)) {
            $nextLink = $_safe.nextLink
            While (![string]::IsNullOrEmpty($nextLink)) {
                Write-LogMessage -type Verbose -MSG "In Get-Safe: nextLink: $nextLink"
                $_safeNext = @()
                $_safeNext += $(Invoke-Rest-Uri "$PVWAURL/$nextLink" -Command 'Get' -Header $g_LogonHeader -ErrAction 'SilentlyContinue')
                $_safe += $_safeNext
                If (![string]::IsNullOrEmpty($_safeNext.nextLink)) {
                    $nextLink = $_safeNext.nextLink
                }
                else {
                    $nextLink = $null
                }
            }
        }
    }
    catch [Microsoft.PowerShell.Commands.HttpResponseException] {
        If ($_.Exception.Response.StatusCode.value__ -eq 404) {
            Write-LogMessage -type Verbose -MSG "Safe $safeName does not exist"
            return $null
        }
        else {
            Write-LogMessage -type Error -MSG "Error Message: $_"
            Write-LogMessage -type Error -MSG "Exception Message: $($_.Exception.Message)"
            Write-LogMessage -type Error -MSG "Status Code: $($_.Exception.Response.StatusCode.value__)"
            Write-LogMessage -type Error -MSG "Status Description: $($_.Exception.Response.StatusDescription)"
        }
    }
    catch {
        Throw $(New-Object System.Exception ("Get-Safe: Error retrieving safe '$safename' details.", $_.Exception))
    }
	Write-LogMessage -type Verbose -MSG "In Get-Safe: Returning count: $($_safe.count)"
    return $_safe
}

Function Test-Safe {
    <#
.SYNOPSIS
	Returns the Safe members
.DESCRIPTION
	Returns the Safe members
.PARAMETER SafeName
	The Safe Name check if exists
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$safeName
    )
    try {
        Write-LogMessage -type Verbose -MSG 'In Test-Safe'
        $chkSafeExists = $null
        $retResult = $false
        If ($null -ne $g_SafesList) {
            # Check Cached safes list first
            Write-LogMessage -type Verbose -MSG 'In Test-Safe: Cached safes list found'
            $chkSafeExists = ($g_SafesList.safename -contains $safename)
        }
        Else {
            # No cache, Get safe details from Vault
            Write-LogMessage -type Verbose -MSG 'In Test-Safe: No cached safes found'
            try {
                Write-LogMessage -type Verbose -MSG "In Test-Safe: Checking if safe $safeNam exists"
                $chkSafeExists = $null -ne $(Get-Safe -SafeName $safeName -ErrAction 'SilentlyContinue')
            }
            catch {
                Write-LogMessage -type Verbose -MSG "In Test-Safe: Error checking if safe $safeName exists, defaulting to false"
                $chkSafeExists = $false
            }
        }
        # Report on safe existence
        If ($chkSafeExists -eq $true) {
            # Safe exists
            Write-LogMessage -type Info -MSG "Safe $safeName exists"
            $retResult = $true
        }
        elseif ($chkSafeExists -eq $false) {
            # Safe does not exist
            Write-LogMessage -type Warning -MSG "Safe $safeName does not exist"
            $retResult = $false
        }
        else {
            Write-LogMessage -type Error -MSG "Error checking if safe $safeName exists"
        }
    }
    catch {
        Write-LogMessage -type Error -MSG $_.Exception -ErrorAction 'SilentlyContinue'
        $retResult = $false
    }
    return $retResult
}

Function New-Safe {
    <#
.SYNOPSIS
Allows a user to create a new cyberArk safe

.DESCRIPTION
Creates a new cyberark safe

.EXAMPLE
New-Safe -safename "x0-Win-S-Admins" -safeDescription "Safe description goes here"

#>
    [CmdletBinding()]
    [OutputType()]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$safename,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$safeDescription,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$managingCPM,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [int]$numVersionRetention = 7,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [int]$numDaysRetention = -1,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [bool]$EnableOLAC = $false
    )

    $createSafeBody = @{
        'SafeName'                  = "$safename"
        'Description'               = "$safeDescription"
        'OLACEnabled'               = $enableOLAC
        'ManagingCPM'               = "$managingCPM"
        'NumberOfVersionsRetention' = $numVersionRetention
    }

    If ($numDaysRetention -gt -1) {
        $createSafeBody.Add('NumberOfDaysRetention', $numDaysRetention)
        $createSafeBody.Remove('NumberOfVersionsRetention')
    }

    try {
        Write-LogMessage -type Debug -MSG "Adding the safe $safename to the Vault..."
        Write-LogMessage -type Debug -MSG "Create Safe Body: `n$createSafeBody" 
        $safeAdd = Invoke-Rest -Uri $URL_Safes -Body ($createSafeBody | ConvertTo-Json) -Method POST -Headers $g_LogonHeader -ContentType 'application/json' -TimeoutSec 2700
        # Reset cached Safes list
        #Set-Variable -Name g_SafesList -Value $null -Scope Global
        # Update Safes list to include new safe
        #Get-Safes | out-null
        $g_SafesList += $safeAdd
    }
    catch [System.Management.Automation.RuntimeException] {
        Throw
    }
    catch {
        Throw $(New-Object System.Exception ("New-Safe: Error adding $safename to the Vault.", $_.Exception))
    }
}

Function Update-Safe {
    <#
.SYNOPSIS
Allows a user to update an existing cyberArk safe

.DESCRIPTION
Updates a new cyberark safe

.EXAMPLE
Update-Safe -safename "x0-Win-S-Admins" -safeDescription "Updated Safe description goes here" -managingCPM "PassManagerDMZ"

#>
    [CmdletBinding()]
    [OutputType()]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$safeName,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$safeDescription,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$managingCPM,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [int]$numVersionRetention = -1,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [int]$numDaysRetention = -1,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [bool]$EnableOLAC
    )
    Write-LogMessage -type Verbose -MSG "In Update-Safe"
    try {
        # Get the current safe details and update when necessary
        $getSafe = Get-Safe -SafeName $safeName
        Write-LogMessage -type Verbose -MSG "In Update-Safe: Safe details: $getSafe"
    }
    catch {
        Throw $(New-Object System.Exception ("Update-Safe: Error getting current details on safe '$safeName'", $_.Exception))
    }
    $updateDescription = $getSafe.Description
    $updateOLAC = $getSafe.OLACEnabled
    $updateManageCPM = $getSafe.ManagingCPM
    $updateRetVersions = $getSafe.NumberOfVersionsRetention
    $updateRetDays = $getSafe.NumberOfDaysRetention
    If (![string]::IsNullOrEmpty($safeDescription) -and $getSafe.Description -ne $safeDescription) {
        $updateDescription = $safeDescription
    }
    If ($getSafe.OLACEnabled -ne $EnableOLAC) {
        $updateOLAC = $EnableOLAC
    }
    If (![string]::IsNullOrEmpty($managingCPM) -and $getSafe.ManagingCPM -ne $managingCPM) {
        If ('NULL' -eq $managingCPM) {
            $updateManageCPM = ''
        }
        else {
            $updateManageCPM = $managingCPM
        }
    }
    If ($null -ne $numVersionRetention -and $numVersionRetention -gt 0 -and $getSafe.NumberOfVersionsRetention -ne $numVersionRetention) {
        $updateRetVersions = $numVersionRetention
    }
    If ($null -ne $numDaysRetention -and $numDaysRetention -gt 0 -and $getSafe.NumberOfDaysRetention -ne $numDaysRetention) {
        $updateRetDays = $numDaysRetention
    }

    $updateSafeBody = [pscustomobject]@{
        'SafeName'    = "$safeName"
        'Description' = "$updateDescription"
        'OLACEnabled' = $updateOLAC
        'ManagingCPM' = "$updateManageCPM"
    }
    if (![string]::IsNullOrEmpty($updateRetVersions) -and $updateRetVersions -gt 0) {
        $updateSafeBody  | Add-Member -MemberType NoteProperty -Name 'NumberOfVersionsRetention' -Value $updateRetVersions
    }
    else {
        $updateSafeBody  | Add-Member -MemberType NoteProperty -Name 'NumberOfDaysRetention' -Value $updateRetDays
    }
    try {
        Write-LogMessage -type Verbose -MSG "In Update-Safe: SafeName $safeName : UpdateSafeBody:$updateSafeBody"
        Write-LogMessage -type Debug -MSG "Updating safe $safename..."
        Write-LogMessage -type Debug -MSG "Update Safe Body: $updateSafeBody" 
        Invoke-Rest -Uri ($URL_SpecificSafe -f $safeName) -Body $updateSafeBody -Method PUT -Headers $g_LogonHeader -ContentType 'application/json' -TimeoutSec 2700 | Out-Null
    }
    catch {
        Throw $(New-Object System.Exception ("Update-Safe: Error updating $safeName.", $_.Exception))
    }
}

Function Remove-Safe {
    <#
.SYNOPSIS
Allows a user to delete a cyberArk safe

.DESCRIPTION
Deletes a cyberark safe

.EXAMPLE
Remove-Safe -safename "x0-Win-S-Admins"

#>
    [CmdletBinding()]
    [OutputType()]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$safename
    )

    try {
        Write-LogMessage -type Debug -MSG "Deleting the safe $safename from the Vault..."
        $null = Invoke-Rest -Uri ($URL_SpecificSafe -f $safeName) -Method DELETE -Headers $g_LogonHeader -ContentType 'application/json' -TimeoutSec 2700
    }
    catch {
        Throw $(New-Object System.Exception ("Remove-Safe: Error deleting $safename from the Vault.", $_.Exception))
    }
}

Function Set-SafeMember {
    <#
.SYNOPSIS
Gives granular permissions to a member on a cyberark safe

.DESCRIPTION
Gives granular permission to a cyberArk safe to the particular member based on parameters sent to the command.

.EXAMPLE
Set-SafeMember -safename "Win-Local-Admins" -safeMember "Win-Local-Admins" -memberSearchInLocation "LDAP Directory Name"

.EXAMPLE
Set-SafeMember -safename "Win-Local-Admins" -safeMember "Administrator" -memberSearchInLocation vault

#>
    [CmdletBinding()]
    [OutputType()]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
                [ValidateScript( { Test-Safe -SafeName $_ })]
        $safename,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        $safeMember,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [switch]$updateMember,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [switch]$deleteMember,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Which vault-integrated LDAP directory name the vault should search for the account. Must match one of the directory names defined in the LDAP Integration page of the PVWA.',
            Position = 0)]
        $memberSearchInLocation = 'Vault',
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        #[ValidateSet("User","Group","Role")] # Removed due to causing errors
        [String]$memberType = 'User',
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permUseAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permRetrieveAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permListAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permAddAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permUpdateAccountContent = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permUpdateAccountProperties = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permInitiateCPMManagement = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permSpecifyNextAccountContent = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permRenameAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permDeleteAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permUnlockAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permManageSafe = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permManageSafeMembers = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permBackupSafe = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permViewAuditLog = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permViewSafeMembers = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [int]$permRequestsAuthorizationLevel = 0,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permAccessWithoutConfirmation = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permCreateFolders = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permDeleteFolders = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permMoveAccountsAndFolders = $false
    )

    If ($safeMember -NotIn $g_DefaultUsers) {
        $SafeMembersBody = @{
            MemberName               = "$safeMember"
            SearchIn                 = "$memberSearchInLocation"
            MembershipExpirationDate = "$null"
            MemberType               = "$memberType"
            Permissions              = @{
                useAccounts                            = $permUseAccounts
                retrieveAccounts                       = $permRetrieveAccounts
                listAccounts                           = $permListAccounts
                addAccounts                            = $permAddAccounts
                updateAccountContent                   = $permUpdateAccountContent
                updateAccountProperties                = $permUpdateAccountProperties
                initiateCPMAccountManagementOperations = $permInitiateCPMManagement
                specifyNextAccountContent              = $permSpecifyNextAccountContent
                renameAccounts                         = $permRenameAccounts
                deleteAccounts                         = $permDeleteAccounts
                unlockAccounts                         = $permUnlockAccounts
                manageSafe                             = $permManageSafe
                manageSafeMembers                      = $permManageSafeMembers
                backupSafe                             = $permBackupSafe
                viewAuditLog                           = $permViewAuditLog
                viewSafeMembers                        = $permViewSafeMembers
                accessWithoutConfirmation              = $permAccessWithoutConfirmation
                createFolders                          = $permCreateFolders
                deleteFolders                          = $permDeleteFolders
                moveAccountsAndFolders                 = $permMoveAccountsAndFolders
                requestsAuthorizationLevel1            = ($permRequestsAuthorizationLevel -eq 1)
                requestsAuthorizationLevel2            = ($permRequestsAuthorizationLevel -eq 2)
            }
        }  
        Write-LogMessage -type Verbose -MSG "In Set-SafeMember: SafeMembersBody: $SafeMembersBody"
        try {
            If ($updateMember) {
                Write-LogMessage -type Verbose -MSG 'In Set-SafeMember: in updateMember'
                Write-LogMessage -type Debug -MSG "Updating safe membership for $safeMember on $safeName in the vault..."
                $urlSafeMembers = ($URL_SafeSpecificMember -f $(ConvertTo-URL $safeName), $safeMember)
                $restMethod = 'PUT'
            }
            elseif ($deleteMember) {
                Write-LogMessage -type Verbose -MSG 'In Set-SafeMember: in deleteMember'
                Write-LogMessage -type Debug -MSG "Deleting $safeMember from $safeName in the vault..."
                $urlSafeMembers = ($URL_SafeSpecificMember -f $(ConvertTo-URL $safeName), $safeMember)
                $restMethod = 'DELETE'
            }
            else {
                # Adding a member
                Write-LogMessage -type Verbose -MSG 'In Set-SafeMember: default'
                Write-LogMessage -type Debug -MSG "Adding $safeMember located in $memberSearchInLocation to $safeName in the vault..."
                $urlSafeMembers = ($URL_SafeMembers -f $(ConvertTo-URL $safeName))
                $restMethod = 'POST'
            }
            Write-LogMessage -type Verbose -MSG "In Set-SafeMember: Invoke-Rest -Method $restMethod -Uri $urlSafeMembers -ContentType 'application/json' -TimeoutSec 2700 -ErrorVariable rMethodErr -Body ($safeMembersBody | ConvertTo-Json -Depth 5) -Headers $g_LogonHeader"
            Invoke-Rest -Method $restMethod -Uri $urlSafeMembers -ContentType 'application/json' -TimeoutSec 2700 -ErrorVariable rMethodErr -Body ($safeMembersBody | ConvertTo-Json -Depth 5) -Headers $g_LogonHeader  | Out-Null

        }
        catch {
            if ($rMethodErr.message -like '*User or Group is already a member*') {
                Write-LogMessage -type Warning -MSG "The user $safeMember is already a member. Use the update member method instead"
            }
            elseif (($rMethodErr.message -like '*User or Group was not found.*') -or ($rMethodErr.message -like '*404*') -or ($rMethodErr.message -like "*hasn't been defined.*") -or ($rMethodErr.message -like '*has not been defined.*')) {   

                If ($AddOnUpdate) {
                    # Adding a member
                    Write-LogMessage -type Verbose -MSG 'In Set-SafeMember: AddOnUpdate'
                    Write-LogMessage -type Warning -MSG "User or Group was not found. Attempting to adding $safeMember located in $memberSearchInLocation to $safeName in the vault..."
                    $urlSafeMembers = ($URL_SafeMembers -f $(ConvertTo-URL $safeName))
                    $restMethod = 'POST'
                    try {
                        Write-LogMessage -type Verbose -MSG "In Set-SafeMember: Invoke-Rest -Method $restMethod -Uri $urlSafeMembers -ContentType 'application/json' -TimeoutSec 2700 -ErrorVariable rMethodErr -Body ($safeMembersBody | ConvertTo-Json -Depth 5) -Headers $g_LogonHeader"
                        Invoke-Rest -Method $restMethod -Uri $urlSafeMembers -ContentType 'application/json' -TimeoutSec 2700 -ErrorVariable rMethodErr -Body ($safeMembersBody | ConvertTo-Json -Depth 5) -Headers $g_LogonHeader  | Out-Null
                    }
                    catch {

                        Write-LogMessage -type Error -MSG "There was an error setting the membership for $safeMember on $safeName in the Vault. The error was:"
                        Write-LogMessage -type Error -MSG ('{0} ({1})' -f $rMethodErr.message, $_.Exception.Response.StatusDescription)
                    }
                }
                else {
                    Write-LogMessage -type Warning -MSG 'User or Group was not found. To automatically attempt to add use AddOnUpdate'
                    Write-LogMessage -type Debug -MSG "There was an error setting the membership for $safeMember on $safeName in the Vault. The error was:"
                    Write-LogMessage -type Debug -MSG ('{0} ({1})' -f $rMethodErr.message, $_.Exception.Response.StatusDescription)
                }
            }
            else {
                Write-LogMessage -type Error -MSG "There was an error setting the membership for $safeMember on $safeName in the Vault. The error was:"
                Write-LogMessage -type Error -MSG ('{0} ({1})' -f $rMethodErr.message, $_.Exception.Response.StatusDescription)
            }
        }
    }
    else {
        Write-LogMessage -type Info -MSG "Skipping default user $safeMember..."
    }
}

Function Get-SafeMembers {
    <#
.SYNOPSIS
Returns the permissions of a member on a cyberark safe

.DESCRIPTION
Returns the permissions of a cyberArk safe of all members based on parameters sent to the command.

.EXAMPLE
Get-SafeMember -safename "Win-Local-Admins"

#>
    param (
        [Parameter(Mandatory = $true)]
        [String]$safeName
    )
    $_safeMembers = $null
    $_safeOwners = $null
    try {
        $accSafeMembersURL = $URL_SafeMembers -f $(ConvertTo-URL $safeName)
        $accSafeMembersURL += '?filter=includePredefinedUsers eq true'
        $_safeMembers = $(Invoke-Rest -Uri $accSafeMembersURL -Command GET -Header $g_LogonHeader -ErrorAction 'SilentlyContinue')
        # Remove default users and change UserName to MemberName
        if (!$g_includeDefaultUsers) {
            $_safeOwners = $_safeMembers.value | Where-Object { $_.MemberName -NotIn $g_DefaultUsers }
        }
    }
    catch {
        Throw $(New-Object System.Exception ("Get-SafeMembers: There was an error getting the safe $safeName Members.", $_.Exception))
    }
    return $_safeOwners
}

Function Convert-ToBool {
    param (
        [string]$txt
    )
    $retBool = $false
    if ([bool]::TryParse($txt, [ref]$retBool)) {
        # parsed to a boolean
        return [System.Convert]::ToBoolean($txt)
    }
    else {
        Write-LogMessage -type Error -MSG "The input ""$txt"" is not in the correct format (true/false), defaulting to False"
        return $false
    }
}
#endregion

Write-LogMessage -type Info -MSG "Starting script (v$ScriptVersion)" -Header -LogFile $LOG_FILE_PATH
if ($InDebug) {
    Write-LogMessage -type Info -MSG 'Running in Debug Mode' -LogFile $LOG_FILE_PATH 
}
if ($InVerbose) {
    Write-LogMessage -type Info -MSG 'Running in Verbose Mode' -LogFile $LOG_FILE_PATH 
}
Write-LogMessage -type Debug -MSG "Running PowerShell version $($PSVersionTable.PSVersion.Major) compatible of versions $($PSVersionTable.PSCompatibleVersions -join ', ')" -LogFile $LOG_FILE_PATH

# Check if Powershell is running in Constrained Language Mode
If ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-LogMessage -type Error -MSG "Powershell is currently running in $($ExecutionContext.SessionState.LanguageMode) mode which limits the use of some API methods used in this script.`
	PowerShell Constrained Language mode was designed to work with system-wide application control solutions such as CyberArk EPM or Device Guard User Mode Code Integrity (UMCI).`
	For more information: https://blogs.msdn.microsoft.com/powershell/2017/11/02/powershell-constrained-language-mode/"
    Write-LogMessage -type Info -MSG 'Script ended' -Footer -LogFile $LOG_FILE_PATH
    return
}

    # Check that the PVWA URL is OK
    If ($PVWAURL -ne '') {
        If ($PVWAURL.Substring($PVWAURL.Length - 1) -eq '/') {
            $PVWAURL = $PVWAURL.Substring(0, $PVWAURL.Length - 1)
        }
    }
    else {
        Write-LogMessage -type Error -MSG 'PVWA URL can not be empty'
        return
    }

#region [Logon]
try {
    # Get Credentials to Login
    # ------------------------
    $caption = 'Safe Management'

    If (![string]::IsNullOrEmpty($logonToken)) {
        if ($logonToken.GetType().name -eq 'String') {
            $logonHeader = @{Authorization = $logonToken }
            Set-Variable -Name g_LogonHeader -Value $logonHeader -Scope global
        }
        else {
            Set-Variable -Name g_LogonHeader -Value $logonToken -Scope global
        }
    }
    elseif (![string]::IsNullOrEmpty($PVWACredentials)) {
        Get-LogonHeader -Credentials $PVWACredentials
    }
    elseif ($null -eq $creds) {
        $msg = 'Enter your User name and Password' 
        $creds = $Host.UI.PromptForCredential($caption, $msg, '', '')
        Get-LogonHeader -Credentials $creds -concurrentSession $concurrentSession
    }
    else {
        Write-LogMessage -type Error -MSG 'No Credentials were entered'
        return
    }
}
catch {
    Write-LogMessage -type Error -MSG "Error Logging on. Error: $(Join-ExceptionMessage $_.Exception)"
    return
}
#endregion

switch ($PsCmdlet.ParameterSetName) {
    'List' {
        # List all Safes
        Write-LogMessage -type Info -MSG 'Retrieving Safes...'
        $safelist = @()
        try {
            If (![string]::IsNullOrEmpty($SafeName)) {
                $safelist += Get-Safe -SafeName $SafeName
            }
            else {
                $safelist += Get-Safe
            }
            if ([string]::IsNullOrEmpty($safelist.value)) {
                $output = $safelist
            }
            else {
                $output = $safelist.value
            }
            if ([string]::IsNullOrEmpty($ReportPath)) {
                $output 
            }
            else {
                $output | Select-Object -Property safeName, description, managingCPM, numberOfVersionsRetention, numberOfDaysRetention, EnableOLAC | ConvertTo-Csv -NoTypeInformation | Out-File $ReportPath
            }
        }
        catch {
            Write-LogMessage -type Error -MSG "Error retrieving safes. Error: $(Join-ExceptionMessage $_.Exception)"
        }
    }
    { ($_ -eq 'Add') -or ($_ -eq 'AddMembers') -or ($_ -eq 'Update') -or ($_ -eq 'UpdateMembers') -or ($_ -eq 'Delete') -or ($_ -eq 'DeleteMembers') } {
        try {
            if (![string]::IsNullOrEmpty($FilePath)) {
                # Bulk Import of Safes
                $csv = Import-Csv $FilePath
                # Sort List by Safes
                $sortedList = $csv | Sort-Object -Property safename
                # For each line in the csv, import the safe
                ForEach ($line in $sortedList) {
                    try {
                        Write-LogMessage -type Info -MSG "Importing safe $($line.safename) with safe member $($line.member)..."
                        $parameters = @{
                            safeName            = $line.safename
                            safeDescription     = $line.description
                            managingCPM         = $line.ManagingCPM
                            numVersionRetention = $line.numVersionRetention
                            numDaysRetention    = $line.numDaysRetention
                            EnableOLAC          = $line.EnableOLAC
                        }
                        if ([string]::IsNullOrEmpty($parameters.safeDescription)) {
                            $parameters.Remove('safeDescription')
                        }
                        if ([string]::IsNullOrEmpty($parameters.ManagingCPM)) {
                            $parameters.Remove('managingCPM')
                        }
                        if ([string]::IsNullOrEmpty($parameters.numVersionRetention)) {
                            $parameters.Remove('numVersionRetention')
                        }
                        if ([string]::IsNullOrEmpty($parameters.numDaysRetention)) {
                            $parameters.Remove('numDaysRetention')
                        }
                        if ([string]::IsNullOrEmpty($parameters.EnableOLAC)) {
                            $parameters.Remove('EnableOLAC')
                        }
                        Else {
                            $parameters.EnableOLAC = Convert-ToBool $parameters.EnableOLAC
                        }
                        If (($parameters.keys.count -gt 1) -or ($CreateSafeWithNameOnly)) {
                            If ($Add) {
                                # If safe doesn't exist, create the new safe
                                if ((Test-Safe -SafeName $line.safename) -eq $false) {
                                    Write-LogMessage -type Info -MSG "Adding the safe $($line.safename)..."
                                    New-Safe @parameters
                                }
                                else {
                                    # Safe exists, would create an error creating it again
                                    Write-LogMessage -type Error -MSG "Safe $($line.safename) already exists, to update it use the Update switch"
                                }
                            }
                            ElseIf ($Update) {
                                Write-LogMessage -type Info -MSG "Updating the safe $($line.safename)..."
                                Update-Safe @parameters
                            }
                            ElseIf ($Delete) {
                                Write-LogMessage -type Info -MSG "Deleting safe $($line.safename)..."
                                Remove-Safe -safename $parameters.safeName
                            }
                        }
                        else {
                            Write-LogMessage -type Info -MSG "Safe $($line.safename) has no safe details to add or update, skipping add or update."
                        }
                        If ($Delete -eq $False) {
                            If (![string]::IsNullOrEmpty($line.member)) {
                                # Add permissions to the safe
                                Set-SafeMember -SafeName $line.safename -safeMember $line.member -updateMember:$UpdateMembers -deleteMember:$DeleteMembers -memberSearchInLocation $line.MemberLocation -MemberType $line.MemberType`
                                    -permUseAccounts $(Convert-ToBool $line.UseAccounts) -permRetrieveAccounts $(Convert-ToBool $line.RetrieveAccounts) -permListAccounts $(Convert-ToBool $line.ListAccounts) `
                                    -permAddAccounts $(Convert-ToBool $line.AddAccounts) -permUpdateAccountContent $(Convert-ToBool $line.UpdateAccountContent) -permUpdateAccountProperties $(Convert-ToBool $line.UpdateAccountProperties) `
                                    -permInitiateCPMManagement $(Convert-ToBool $line.InitiateCPMAccountManagementOperations) -permSpecifyNextAccountContent $(Convert-ToBool $line.SpecifyNextAccountContent) `
                                    -permRenameAccounts $(Convert-ToBool $line.RenameAccounts) -permDeleteAccounts $(Convert-ToBool $line.DeleteAccounts) -permUnlockAccounts $(Convert-ToBool $line.UnlockAccounts) `
                                    -permManageSafe $(Convert-ToBool $line.ManageSafe) -permManageSafeMembers $(Convert-ToBool $line.ManageSafeMembers) -permBackupSafe $(Convert-ToBool $line.BackupSafe) `
                                    -permViewAuditLog $(Convert-ToBool $line.ViewAuditLog) -permViewSafeMembers $(Convert-ToBool $line.ViewSafeMembers) `
                                    -permRequestsAuthorizationLevel $line.RequestsAuthorizationLevel -permAccessWithoutConfirmation $(Convert-ToBool $line.AccessWithoutConfirmation) `
                                    -permCreateFolders $(Convert-ToBool $line.CreateFolders) -permDeleteFolders $(Convert-ToBool $line.DeleteFolders) -permMoveAccountsAndFolders $(Convert-ToBool $line.MoveAccountsAndFolders)
                            }
                        }
                    }
                    catch [System.Management.Automation.RuntimeException] {
                        If ($PSItem.Exception.Message -match 'Safe Name .* has already been defined.') {}
                    }
                    catch {
                        Write-LogMessage -type Error -MSG "Error configuring safe '$($line.SafeName)'. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                }
            }
            else {
                try {
                    $parameters = @{
                        safeName            = $SafeName
                        safeDescription     = $SafeDescription
                        managingCPM         = $ManagingCPM
                        numVersionRetention = $NumVersionRetention
                    }
                    # Keep only relevant properties (and keeping defaults when needed)
                    if ([string]::IsNullOrEmpty($SafeDescription)) {
                        $parameters.Remove('safeDescription')
                    }
                    if ([string]::IsNullOrEmpty($ManagingCPM)) {
                        $parameters.Remove('managingCPM')
                    }
                    if ([string]::IsNullOrEmpty($NumVersionRetention)) {
                        $parameters.Remove('numVersionRetention')
                    }
                    If ($Add) {
                        # Create one Safe
                        Write-LogMessage -type Info -MSG "Adding the safe $SafeName..."
                        New-Safe @parameters
                    }
                    ElseIf ($Update) {
                        # Update the Safe
                        Write-LogMessage -type Info -MSG "Updating the safe $SafeName..."
                        Update-Safe @parameters
                    }
                    ElseIf ($Delete) {
                        # Deleting one Safe
                        Write-LogMessage -type Info -MSG "Deleting the safe $SafeName..."
                        Remove-Safe -safename $parameters.safeName
                    }
                }
                catch {
                    Write-LogMessage -type Error -MSG "Error configuring safe '$SafeName'. Error: $(Join-ExceptionMessage $_.Exception)"
                }
            }
        }
        catch {
            Write-LogMessage -type Error -MSG "Error configuring safe. Error: $(Join-ExceptionMessage $_.Exception)"
        }
    }
    'Members' {
        try {
            if ([string]::IsNullOrEmpty($UserName)) {
                # List all members of a safe
                Get-SafeMembers -SafeName $SafeName
            }
            else {
                # Add a member to a safe
                $permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = `
                    $permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafe = $permManageSafeMembers = $permBackupSafe = $permViewAuditLog = `
                    $permViewSafeMembers = $permAccessWithoutConfirmation = $permCreateFolders = $permDeleteFolders = $permMoveAccountsAndFolders = $false
                [int]$permRequestsAuthorizationLevel = 0
                Write-LogMessage -type Verbose -MSG "Adding member '$UserName' to safe $SafeName with Role '$MemberRole'..."
                switch ($MemberRole) {
                    'Admin' {
                        $permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = `
                            $permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafe = $permManageSafeMembers = $permBackupSafe = `
                            $permViewAuditLog = $permViewSafeMembers = $permAccessWithoutConfirmation = $permCreateFolders = $permDeleteFolders = $permMoveAccountsAndFolders = $true
                        $permRequestsAuthorizationLevel = 1
                    }
                    'Auditor' {
                        $permListAccounts = $permViewAuditLog = $permViewSafeMembers = $true
                    }
                    'EndUser' {
                        $permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permViewAuditLog = $permViewSafeMembers = $true
                    }
                    'Approver' {
                        $permListAccounts = $permViewAuditLog = $permViewSafeMembers = $true
                        $permRequestsAuthorizationLevel = 1
                    }
                    'Owner' {
                        $permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = $permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafeMembers = $permViewAuditLog = $permViewSafeMembers = $permMoveAccountsAndFolders = $true
                        $permRequestsAuthorizationLevel = 1
                    }
                }
                Set-SafeMember -SafeName $SafeName -safeMember $UserName -memberSearchInLocation $UserLocation `
                    -permUseAccounts $permUseAccounts -permRetrieveAccounts $permRetrieveAccounts -permListAccounts $permListAccounts `
                    -permAddAccounts $permAddAccounts -permUpdateAccountContent $permUpdateAccountContent -permUpdateAccountProperties $permUpdateAccountProperties `
                    -permInitiateCPMManagement $permInitiateCPMManagement -permSpecifyNextAccountContent $permSpecifyNextAccountContent `
                    -permRenameAccounts $permRenameAccounts -permDeleteAccounts $permDeleteAccounts -permUnlockAccounts $permUnlockAccounts `
                    -permManageSafe $permManageSafe -permManageSafeMembers $permManageSafeMembers -permBackupSafe $permBackupSafe `
                    -permViewAuditLog $permViewAuditLog -permViewSafeMembers $permViewSafeMembers `
                    -permRequestsAuthorizationLevel $permRequestsAuthorizationLevel -permAccessWithoutConfirmation $permAccessWithoutConfirmation `
                    -permCreateFolders $permCreateFolders -permDeleteFolders $permDeleteFolders -permMoveAccountsAndFolders $permMoveAccountsAndFolders
            }
        }
        catch {
            Write-LogMessage -type Error -MSG "Error updating Members for safe '$SafeName'. Error: $(Join-ExceptionMessage $_.Exception)"
        }
    }
}

# Logoff the session
# ------------------

If (![string]::IsNullOrEmpty($logonToken)) {
    Write-Host 'LogonToken passed, session NOT logged off'
}
elseif ($DisableLogoff) {
    Write-Host 'Logoff has been disabled, session NOT logged off'
}
else {
    Invoke-Logoff
}

else {
    Write-LogMessage -type Error -MSG 'This script requires PowerShell version 3 or above'
}

Write-LogMessage -type Info -MSG 'Script ended' -Footer -LogFile $LOG_FILE_PATH
return