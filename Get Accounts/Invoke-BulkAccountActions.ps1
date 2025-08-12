[CmdletBinding(DefaultParameterSetName = 'Filters')]
<#
.SYNOPSIS
	Run Account Actions on a List of Accounts using CyberArk REST API.

.DESCRIPTION
	This script executes a specified account action (Verify, Change, Reconcile) on a list of accounts filtered by Safe, PlatformID, UserName, Address, or custom keywords. Supports CyberArk PVWA v10.4 and above.

.EXAMPLE
	# Verify all accounts in a specific safe
	.\Invoke-BulkAccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AccountsAction Verify -SafeName "MySafe"

.EXAMPLE
	# Change password for accounts filtered by PlatformID
	.\Invoke-BulkAccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AccountsAction Change -PlatformID "WinDomain"

.EXAMPLE
	# Reconcile accounts filtered by UserName and Address
	.\Invoke-BulkAccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AccountsAction Reconcile -UserName "svc_account" -Address "server01.example.com"

.EXAMPLE
	# Use a logon token for authentication
	.\Invoke-BulkAccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AccountsAction Verify -SafeName "MySafe" -logonToken $token

.EXAMPLE
	# Use vault stored credentials
	$cred = Get-Credential
	.\Invoke-BulkAccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AccountsAction Change -SafeName "MySafe" -PVWACredentials $cred

.EXAMPLE
	# Disable SSL verification (not recommended)
	.\Invoke-BulkAccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AccountsAction Verify -DisableSSLVerify

.EXAMPLE
	# Only include accounts with CPM disabled
	.\Invoke-BulkAccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AccountsAction Verify -CPMDisabled

.EXAMPLE
	# Only include accounts where previous action failed
	.\Invoke-BulkAccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AccountsAction Change -FailedOnly

	.EXAMPLE
	# Only include accounts with CPM disabled or where previous action failed
	.\Invoke-BulkAccountActions.ps1 -PVWAURL "https://pvwa.example.com/PasswordVault" -AccountsAction Verify -CPMDisabled  -FailedOnly

.NOTES
	Author: Assaf Miron
	CyberArk PVWA v10.4+
	For more information, see script comments and documentation.
#>
###########################################################################
[CmdletBinding(DefaultParameterSetName = 'Filters')]
param
(
	# The URL of the CyberArk PVWA instance.
	[Parameter(Mandatory = $true, HelpMessage = 'Enter the PVWA URL')]
	[ValidateScript({ Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30 })]
	[Alias('url')]
	[String]$PVWAURL,

	# Authentication type. Valid values: cyberark, ldap, radius. Default: cyberark.
	[Parameter(Mandatory = $false, HelpMessage = 'Enter the Authentication type (Default:CyberArk)')]
	[ValidateSet('cyberark', 'ldap', 'radius')]
	[String]$AuthType = 'cyberark',

	# Disable SSL certificate verification (not recommended).
	[Parameter(Mandatory = $false, HelpMessage = 'Disable SSL certificate verification (not recommended).')]
	[Switch]$DisableSSLVerify,

	# The account action to perform. Valid values: Verify, Change, Reconcile.
	[Parameter(Mandatory = $true, HelpMessage = 'The account action to perform. Valid values: Verify, Change, Reconcile.')]
	[ValidateSet('Verify', 'Change', 'Reconcile')]
	[Alias('Action')]
	[String]$AccountsAction = 'Verify',

	# Filter accounts by Safe name (max 28 chars).
	[Parameter(ParameterSetName = 'Filters', Mandatory = $false, HelpMessage = 'Enter a Safe Name to search in (max 28 chars).')]
	[ValidateScript({ $_.Length -le 28 })]
	[Alias('Safe')]
	[String]$SafeName,

	# Filter accounts by PlatformID.
	[Parameter(ParameterSetName = 'Filters', Mandatory = $false, HelpMessage = 'Enter a PlatformID to filter accounts by.')]
	[String]$PlatformID,

	# Filter accounts by UserName.
	[Parameter(ParameterSetName = 'Filters', Mandatory = $false, HelpMessage = 'Enter a UserName to filter accounts by.')]
	[String]$UserName,

	# Filter accounts by Address.
	[Parameter(ParameterSetName = 'Filters', Mandatory = $false, HelpMessage = 'Enter an Address to filter accounts by.')]
	[String]$Address,

	# Filter accounts by custom keywords (space-separated).
	[Parameter(ParameterSetName = 'Filters', Mandatory = $false, HelpMessage = 'Enter filter Keywords. List of keywords are separated with space to search in accounts.')]
	[String]$Custom,

	# Only include accounts where previous action failed.
	[Parameter(ParameterSetName = 'Filters', Mandatory = $false, HelpMessage = 'Only include accounts where previous action failed.')]
	[Switch]$FailedOnly,

	# Only include accounts with CPM disabled.
	[Parameter(ParameterSetName = 'Filters', Mandatory = $false, HelpMessage = 'Only include accounts with CPM disabled.')]
	[Switch]$CPMDisabled,

	# Provide an existing logon token for authentication.
	[Parameter(Mandatory = $false, HelpMessage = 'Provide an existing logon token for authentication.')]
	$logonToken,

	# Vault stored credentials for authentication.
	[Parameter(Mandatory = $false, HelpMessage = 'Vault Stored Credentials for authentication.')]
	[PSCredential]$PVWACredentials,

	# Include call stack information in verbose output.
	[Parameter(Mandatory = $false, DontShow, HelpMessage = 'Include Call Stack in Verbose output.')]
	[switch]$IncludeCallStack,

	# Create a separate verbose log file.
	[Parameter(Mandatory = $false, DontShow, HelpMessage = 'Create a separate verbose log file.')]
	[switch]$UseVerboseFile
)

# version 1.1
# Get Script Location
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
# Get Debug / Verbose parameters for Script
$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent
$global:IncludeCallStack = $IncludeCallStack.IsPresent
$global:UseVerboseFile = $UseVerboseFile.IsPresent


# ------ SET global parameters ------
# Set Log file path
$global:LOG_FILE_PATH = "$ScriptLocation\BulkAccountActions.log"
# Set a global Header Token parameter
$global:g_LogonHeader = $null

# Global URLS
# -----------
$URL_PVWAAPI = $PVWAURL + '/api'
$URL_Authentication = $URL_PVWAAPI + '/auth'
$URL_Logon = $URL_Authentication + "/$AuthType/Logon"
$URL_Logoff = $URL_Authentication + '/Logoff'

# URL Methods
# -----------
$URL_Accounts = $URL_PVWAAPI + '/Accounts'
$URL_AccountsDetails = $URL_PVWAAPI + '/Accounts/{0}'
$URL_AccountChange = $URL_AccountsDetails + '/Change'
$URL_AccountVerify = $URL_AccountsDetails + '/Verify'
$URL_AccountReconcile = $URL_AccountsDetails + '/Reconcile'


# Script Defaults
# ---------------

#region Writer Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Write-LogMessage
# Description....: Writes the message to log and screen
# Parameters.....: LogFile, MSG, (Switch)Header, (Switch)SubHeader, (Switch)Footer, Type
# Return Values..: None
# =================================================================================================================================
function Write-LogMessage {
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
		[String]$LogFile = $LOG_FILE_PATH,
		[Parameter(Mandatory = $false)]
		[int]$pad = 20
	)

	$verboseFile = $($LOG_FILE_PATH.replace('.log', '_Verbose.log'))
	try {
		if ($Header) {
			'=======================================' | Out-File -Append -FilePath $LOG_FILE_PATH
			Write-Host '======================================='
		}
		elseif ($SubHeader) {
			'------------------------------------' | Out-File -Append -FilePath $LOG_FILE_PATH
			Write-Host '------------------------------------'
		}

		$LogTime = "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')]`t"
		$msgToWrite += "$LogTime"
		$writeToFile = $true
		# Replace empty message with 'N/A'
		if ([string]::IsNullOrEmpty($Msg)) {
			$Msg = 'N/A'
		}
		# Mask Passwords
		$Msg = Remove-SensitiveData -Msg $Msg
		# Check the message type
		switch ($type) {
			'Info' {
				Write-Host $MSG.ToString()
				$msgToWrite += "[INFO]`t`t$Msg"
			}
			'Warning' {
				Write-Host $MSG.ToString() -ForegroundColor DarkYellow
				$msgToWrite += "[WARNING]`t$Msg"
				if ($UseVerboseFile) {
					$msgToWrite | Out-File -Append -FilePath $verboseFile
				}
			}
			'Error' {
				Write-Host $MSG.ToString() -ForegroundColor Red
				$msgToWrite += "[ERROR]`t$Msg"
				if ($UseVerboseFile) {
					$msgToWrite | Out-File -Append -FilePath $verboseFile
				}
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
				if ($InVerbose -or $VerboseFile) {
					$arrMsg = $msg.split(":`t", 2)
					if ($arrMsg.Count -gt 1) {
						$msg = $arrMsg[0].PadRight($pad) + $arrMsg[1]
					}
					$msgToWrite += "[VERBOSE]`t$Msg"
					if ($global:IncludeCallStack) {
						function Get-CallStack {
							$stack = ''
							$excludeItems = @('Write-LogMessage', 'Get-CallStack', '<ScriptBlock>')
							Get-PSCallStack | ForEach-Object {
								if ($PSItem.Command -notin $excludeItems) {
									$command = $PSitem.Command
									if ($command -eq $Global:scriptName) {
										$command = 'Base'
									}
									elseif ([string]::IsNullOrEmpty($command)) {
										$command = '**Blank**'
									}
									$Location = $PSItem.Location
									$stack = $stack + "$command $Location; "
								}
							}
							return $stack
						}
						$stack = Get-CallStack
						$stackMsg = "CallStack:`t$stack"
						$arrstackMsg = $stackMsg.split(":`t", 2)
						if ($arrMsg.Count -gt 1) {
							$stackMsg = $arrstackMsg[0].PadRight($pad) + $arrstackMsg[1].trim()
						}
						Write-Verbose $stackMsg
						$msgToWrite += "`n$LogTime"
						$msgToWrite += "[STACK]`t`t$stackMsg"
					}
					if ($InVerbose) {
						Write-Verbose $MSG
					}
					else {
						$writeToFile = $False
					}
					if ($UseVerboseFile) {
						$msgToWrite | Out-File -Append -FilePath $verboseFile
					}
				}
				else {
					$writeToFile = $False
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
	}
	catch {
		Write-Error "Error in writing log: $($_.Exception.Message)"
	}
}

function Remove-SensitiveData {
	[CmdletBinding()]
	param (
		# Parameter help description
		[Alias('MSG', 'value', 'string')]
		[Parameter(Mandatory = $true, Position = 0)]
		[string]
		$message
	)
	begin {
		$cleanedMessage = $message
	}
	process {
		if ($global:LogSensitiveData -eq $true) {
			# Allows sensitive data to be logged this is useful for debugging authentication issues
			return $message
		}
		# List of fields that contain sensitive data to check for
		$checkFor = @('password', 'secret', 'NewCredentials', 'access_token', 'client_secret', 'auth', 'Authorization', 'Answer', 'Token')
		# Check for sensitive data in the message that is escaped with quotes or double quotes
		$checkFor | ForEach-Object {
			if ($cleanedMessage -imatch "[{\\""']{2,}\s{0,}$PSitem\s{0,}[\\""']{2,}\s{0,}[:=][\\""']{2,}\s{0,}(?<Sensitive>.*?)\s{0,}[\\""']{2,}(?=[,:;])") {
				$cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
			}
			# Check for sensitive data in the message that is not escaped with quotes or double quotes
			elseif ($cleanedMessage -imatch "[""']{1,}\s{0,}$PSitem\s{0,}[""']{1,}\s{0,}[:=][""']{1,}\s{0,}(?<Sensitive>.*?)\s{0,}[""']{1,}") {
				$cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
			}
			# Check for Sensitive data in pure JSON without quotes
			elseif ( $cleanedMessage -imatch "(?:\s{0,}$PSitem\s{0,}[:=])\s{0,}(?<Sensitive>.*?)(?=; |:|,|}|\))") {
				$cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
			}
		}
	}
	end {
		# Return the modified string
		return $cleanedMessage
	}
}

function Get-LogonHeader {
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
		if ($DisableSSLVerify) {
			Disable-SSLVerification
		}
		# Create the POST Body for the Logon
		# ----------------------------------
		if ($concurrentSession) {
			$logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password; concurrentSession = $true } | ConvertTo-Json
		}
		else {
			$logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password } | ConvertTo-Json

		}
		# Check if we need to add RADIUS OTP
		if (![string]::IsNullOrEmpty($RadiusOTP)) {
			$logonBody.Password += ",$RadiusOTP"
		}
		try {
			# Logon
			$logonToken = Invoke-Rest -Command Post -URI $URL_Logon -Body $logonBody -ErrAction 'SilentlyContinue'

			# Clear logon body
			$logonBody = ''
		}
		catch {
			throw $(New-Object System.Exception ("Get-LogonHeader: $($_.Exception.Response.StatusDescription)", $_.Exception))
		}

		$logonHeader = $null
		if ([string]::IsNullOrEmpty($logonToken)) {
			throw 'Get-LogonHeader: Logon Token is Empty - Cannot login'
		}


		try {
			# Create a Logon Token Header (This will be used through out all the script)
			# ---------------------------
			$logonHeader = @{Authorization = $logonToken }

			Set-Variable -Name g_LogonHeader -Value $logonHeader -Scope global
			Set-Variable -Name g_LogonHeader -Value $logonHeader -Scope global
		}
		catch {
			throw $(New-Object System.Exception ('Get-LogonHeader: Could not create Logon Header Dictionary', $_.Exception))
			throw $(New-Object System.Exception ('Get-LogonHeader: Could not create Logon Header Dictionary', $_.Exception))
		}
	}
}

function Invoke-Logoff {
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
		if ($null -ne $g_LogonHeader) {
			Write-LogMessage -type Info -MSG 'Logoff Session...'
			Invoke-Rest -Method Post -Uri $URL_Logoff -Headers $g_LogonHeader -ContentType 'application/json' -TimeoutSec 2700 | Out-Null
			Set-Variable -Name g_LogonHeader -Value $null -Scope global
		}
	}
	catch {
		throw $(New-Object System.Exception ('Invoke-Logoff: Failed to logoff session', $_.Exception))
	}
}


# @FUNCTION@ ======================================================================================================================
# Name...........: Collect-ExceptionMessage
# Description....: Formats exception messages
# Parameters.....: Exception
# Return Values..: Formatted String of Exception messages
# =================================================================================================================================
function Collect-ExceptionMessage {
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

	begin {
	}
	process {
		$msg = 'Source:{0}; Message: {1}' -f $e.Source, $e.Message
		while ($e.InnerException) {
			$e = $e.InnerException
			$msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
		}
		return $msg
	}
	end {
	}
}
#endregion

#region Helper Functions
function Test-CommandExists {
	param ($command)
	$oldPreference = $ErrorActionPreference
	$ErrorActionPreference = 'stop'
	try { if (Get-Command $command) { return $true } }
	catch { Write-Host "$command does not exist"; return $false }
	finally { $ErrorActionPreference = $oldPreference }
} #end function test-CommandExists

# @FUNCTION@ ======================================================================================================================
# Name...........: Disable-SSLVerification
# Description....: Disables the SSL Verification (bypass self signed SSL certificates)
# Parameters.....: None
# Return Values..: None
# =================================================================================================================================
function Disable-SSLVerification {
	<#
.SYNOPSIS
	Bypass SSL certificate validations
.DESCRIPTION
	Disables the SSL Verification (bypass self signed SSL certificates)
#>
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

# @FUNCTION@ ======================================================================================================================
# Name...........: Invoke-Rest
# Description....: Invoke REST Method
# Parameters.....: Command method, URI, Header, Body
# Return Values..: REST response
# =================================================================================================================================
function Invoke-Rest {
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
		[String]$ErrAction = 'Continue',
		[Parameter(Mandatory = $false)]
		[int]$TimeoutSec = 2700,
		[Parameter(Mandatory = $false)]
		[string]$ContentType = 'application/json'

	)
	Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tStart"
	$restResponse = ''
	try {
		if ([string]::IsNullOrEmpty($Body)) {
			Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tInvoke-RestMethod -Uri $URI -Method $Command -Header $($Header|ConvertTo-Json -Compress) -ContentType $ContentType -TimeoutSec $TimeoutSec"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType $ContentType -TimeoutSec $TimeoutSec -ErrorAction $ErrAction -Verbose:$false -Debug:$false
		}
		else {
			Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tInvoke-RestMethod -Uri $URI -Method $Command -Header $($Header|ConvertTo-Json -Compress) -ContentType $ContentType -Body $($Body|ConvertTo-Json -Compress) -TimeoutSec $TimeoutSec"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType $ContentType -Body $Body -TimeoutSec $TimeoutSec -ErrorAction $ErrAction -Verbose:$false -Debug:$false
		}
		Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tInvoke-RestMethod completed without error"
	}

	catch {
		# Check if ErrorDetails.Message is JSON before attempting to convert
		if ($PSItem.ErrorDetails.Message -notmatch '.*ErrorCode[\s\S]*ErrorMessage.*') {
			if ($PSitem.Exception.response.StatusCode.value__ -eq 401) {
				Write-LogMessage -type Error -MSG 'Recieved error 401 - Unauthorized access'
				Write-LogMessage -type Error -MSG '**** Existing script ****' -Footer -Header
				exit 5
			}
			elseif ($PSitem.Exception.response.StatusCode.value__ -eq 403) {
				Write-LogMessage -type Error -MSG 'Recieved error 403 - Forbidden access'
				Write-LogMessage -type Error -MSG '**** Existing script ****' -Footer -Header
				exit 5
			}
			elseif ($PSItem.Exception -match 'The remote name could not be resolved:') {
				Write-LogMessage -type Error -MSG 'Recieved error - The remote name could not be resolved'
				Write-LogMessage -type Error -MSG '**** Existing script ****' -Footer -Header
				exit 1
			}
			else {
				throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $_.Exception))
			}
		}
		$Details = ($PSItem.ErrorDetails.Message | ConvertFrom-Json)
		#No Session token
		if ('PASWS006E' -eq $Details.ErrorCode) {
			Write-LogMessage -type Error -MSG "$($Details.ErrorMessage)"
			Write-LogMessage -type Error -MSG '**** Existing script ****' -Footer -Header
			exit 5
		}
		#Authentication failed
		elseif ('PASWS013E' -eq $Details.ErrorCode) {
			Write-LogMessage -type Error -MSG "$($Details.ErrorMessage)"
			Write-LogMessage -type Error -MSG '**** Existing script ****' -Footer -Header
			exit 5
		}
		#Safe has been deleted or does not exist
		elseif ('SFWS0007' -eq $Details.ErrorCode) {
			throw $_.Exception
		}
		#Safe has already been defined.
		elseif ('SFWS0002' -eq $Details.ErrorCode) {
			Write-LogMessage -type Warning -MSG "$($Details.ErrorMessage)"
			throw "$($Details.ErrorMessage)"
		}
		#Already a member
		elseif ('SFWS0012' -eq $Details.ErrorCode) {
			Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.ErrorMessage)"
			throw $PSItem
		}
		else {
			Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tError in running $Command on '$URI', $_.Exception"
			Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tError Message: $_"
			Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tException Message: $($_.Exception.Message)"
			if ($_.Exception.Response) {
				Write-LogMessage -type Error -MSG "Status Code: $($_.Exception.Response.StatusCode.value__)"
				Write-LogMessage -type Error -MSG "Status Description: $($_.Exception.Response.StatusDescription)"
			}
			if ($($PSItem.ErrorDetails.Message | ConvertFrom-Json).ErrorMessage) {
				Write-LogMessage -type Error -MSG "Error Message: $($($PSItem.ErrorDetails.Message |ConvertFrom-Json).ErrorMessage)"
			}
			$restResponse = $null
			throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $_.Exception))
		}
		else {

			throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $_.Exception))
		}
	}
	Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tResponse: $restResponse"
	return $restResponse
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-LogonHeader
# Description....: Invoke REST Method
# Parameters.....: Credentials
# Return Values..: Logon Header
# =================================================================================================================================
function Get-LogonHeader {
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
		[PSCredential]$Credentials
	)

	if ([string]::IsNullOrEmpty($g_LogonHeader)) {
		# Disable SSL Verification to contact PVWA
		if ($DisableSSLVerify) {
			Disable-SSLVerification
		}

		# Create the POST Body for the Logon
		# ----------------------------------
		$logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password; concurrentSession = 'true' } | ConvertTo-Json
		try {
			# Logon
			$logonToken = Invoke-Rest -Command Post -Uri $URL_Logon -Body $logonBody

			# Clear logon body
			$logonBody = ''
		}
		catch {
			throw $(New-Object System.Exception ("Get-LogonHeader: $($_.Exception.Response.StatusDescription)", $_.Exception))
		}

		$logonHeader = $null
		if ([string]::IsNullOrEmpty($logonToken)) {
			throw 'Get-LogonHeader: Logon Token is Empty - Cannot login'
		}

		# Create a Logon Token Header (This will be used through out all the script)
		# ---------------------------
		$logonHeader = New-Object 'System.Collections.Generic.Dictionary[[String],[String]]'
		$logonHeader.Add('Authorization', $logonToken)

		Set-Variable -Name g_LogonHeader -Value $logonHeader -Scope global
	}

	return $g_LogonHeader
}

function Invoke-Logoff {
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
		if ($null -ne $g_LogonHeader) {
			Write-LogMessage -type Info -MSG 'Logoff Session...'
			Invoke-Rest -Method Post -Uri $URL_Logoff -Headers $g_LogonHeader -ContentType 'application/json' -TimeoutSec 2700 | Out-Null
			Set-Variable -Name g_LogonHeader -Value $null -Scope global
		}
	}
	catch {
		throw $(New-Object System.Exception ('Invoke-Logoff: Failed to logoff session', $_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Format-URL
# Description....: Encodes a text for URL
# Parameters.....: Text
# Return Values..: Encoded Text
# =================================================================================================================================
function Format-URL($sText) {
	<#
.SYNOPSIS
	Format-URL
.DESCRIPTION
	Encodes a text for URL
#>
	if ($sText.Trim() -ne '') {
		Write-LogMessage -Type Verbose -Msg "Returning URL Encode of $sText"
		return [URI]::EscapeDataString($sText)
	}
 else {
		return ''
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-SearchCriteria
# Description....: Creates a search creteria URL for PVWA
# Parameters.....: Base URL, Search keywords, safe name
# Return Values..: None
# =================================================================================================================================
function Get-SearchCriteria {
	<#
.SYNOPSIS
	Get-SearchCriteria
.DESCRIPTION
	Creates a search creteria URL for PVWA
#>
	param ([string]$sURL, [string]$sSearch, [string]$sSafeName)
	[string]$retURL = $sURL
	$retURL += '?'

	if ($sSearch.Trim() -ne '') {
		Write-LogMessage -Type Debug -Msg "Search: $sSearch"
		$retURL += "search=$(Format-URL $sSearch)&"
	}
	if ($sSafeName.Trim() -ne '') {
		Write-LogMessage -Type Debug -Msg "Safe: $sSafeName"
		$retURL += "filter=safename eq $(Format-URL $sSafeName)&"
	}

	if ($retURL[-1] -eq '&') { $retURL = $retURL.substring(0, $retURL.length - 1) }
	Write-LogMessage -Type Debug -Msg "URL: $retURL"

	return $retURL
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-FilteredAccounts
# Description....: Returns a list of Accounts according to a filter
# Parameters.....: Safe name, Platform ID, Custom keywords, User name, address
# Return Values..: List of Filtered Accounts
# =================================================================================================================================
function Get-FilteredAccounts {
	<#
.SYNOPSIS
	Get-FilteredAccounts
.DESCRIPTION
	Returns a list of Accounts according to a filter
#>
	param (
		[Parameter(Mandatory = $false)]
		[string]$sSafeName,
		[Parameter(Mandatory = $false)]
		[string]$sPlatformID,
		[Parameter(Mandatory = $false)]
		[string]$sUserName,
		[Parameter(Mandatory = $false)]
		[string]$sAddress,
		[Parameter(Mandatory = $false)]
		[string]$sCustomKeywords,
		[Parameter(Mandatory = $false)]
		[bool]$bFailedOnly
	)

	$GetAccountsList = @()
	$FilteredAccountsList = @()
	try {
		$AccountsURLWithFilters = ''
		$Keywords = "$sPlatformID $sUserName $sAddress $sCustomKeywords"
		$AccountsURLWithFilters = "$(Get-SearchCriteria -sURL $URL_Accounts -sSearch $Keywords -sSafeName $SafeName)&limit=500"
		Write-LogMessage -Type Debug -MSG "Filter accounts using: $AccountsURLWithFilters"
	}
 catch {
		throw $(New-Object System.Exception ('Get-FilteredAccounts: Error creating filtered URL', $_.Exception))
	}
	try {
		# Get all Accounts
		$GetAccountsResponse = Invoke-Rest -Command Get -Uri $AccountsURLWithFilters -Header $Global:g_LogonHeader

		$GetAccountsList += $GetAccountsResponse.value
		Write-LogMessage -Type Info -MSG "Found $($GetAccountsList.count) accounts so far..."
		$nextLink = $GetAccountsResponse.nextLink
		Write-LogMessage -Type Debug -MSG "Getting accounts next link: $nextLink"

		while (-not [string]::IsNullOrEmpty($nextLink)) {
			$GetAccountsResponse = Invoke-Rest -Command Get -Uri $("$PVWAURL/$nextLink") -Header $Global:g_LogonHeader
			$nextLink = $GetAccountsResponse.nextLink
			Write-LogMessage -Type Debug -MSG "Getting accounts next link: $nextLink"
			$GetAccountsList += $GetAccountsResponse.value
			Write-LogMessage -Type Info -MSG "Found $($GetAccountsList.count) accounts so far..."
		}

		# Create a dynamic filter array
		$WhereArray = @()
		if (-not [string]::IsNullOrEmpty($sUserName)) { $WhereArray += '$_.userName -eq $sUserName' }
		if (-not [string]::IsNullOrEmpty($sAddress)) { $WhereArray += '$_.address -eq $sAddress' }
		if (-not [string]::IsNullOrEmpty($sPlatformID)) { $WhereArray += '$_.platformId -eq $sPlatformID' }
		if ($FailedOnly -and $CPMDisabled) { $WhereArray += '($_.secretManagement.status -eq "failure" -or $_.secretManagement.status -eq "failed" -or $_.secretManagement.manualManagementReason -like "(CPM)*")' }
		elseif ($FailedOnly) { $WhereArray += '($_.secretManagement.status -eq "failure" -or $_.secretManagement.status -eq "failed")' }
		elseif ($CPMDisabled) { $WhereArray += '$_.secretManagement.manualManagementReason -like "(CPM)*"' }

		# Filter Accounts based on input properties
		$WhereFilter = [scriptblock]::Create( ($WhereArray -join ' -and ') )
		$FilteredAccountsList = ( $GetAccountsList | Where-Object $WhereFilter )
	}
 catch {
		throw $(New-Object System.Exception ('Get-FilteredAccounts: Error Getting Accounts', $_.Exception))
	}

	return $FilteredAccountsList
}
#endregion

Write-LogMessage -Type Info -MSG 'Starting script' -Header -LogFile $LOG_FILE_PATH
if ($InDebug) { Write-LogMessage -Type Info -MSG 'Running in Debug Mode' -LogFile $LOG_FILE_PATH }
if ($InVerbose) { Write-LogMessage -Type Info -MSG 'Running in Verbose Mode' -LogFile $LOG_FILE_PATH }

# Check that the PVWA URL is OK
if ($PVWAURL -ne '') {
	if ($PVWAURL.Substring($PVWAURL.Length - 1) -eq '/') {
		$PVWAURL = $PVWAURL.Substring(0, $PVWAURL.Length - 1)
	}
}
else {
	Write-LogMessage -Type Error -MSG 'PVWA URL can not be empty'
	return
}

# Get Credentials to Login
# ------------------------
$caption = 'Bulk Account Actions'
$msg = "Enter your PAS User name and Password ($AuthType)"
try {
	if (![string]::IsNullOrEmpty($logonToken)) {
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

try {
	$accountAction = ''
	switch ($AccountsAction) {
		'Verify' {
			Write-LogMessage -Type Info -MSG 'Running Verify on all filtered accounts'
			$accountAction = $URL_AccountVerify
		}
		'Change' {
			Write-LogMessage -Type Info -MSG 'Running Change on all filtered accounts'
			$accountAction = $URL_AccountChange
		}
		'Reconcile' {
			Write-LogMessage -Type Info -MSG 'Running Reconcile on all filtered accounts'
			$accountAction = $URL_AccountReconcile
		}
	}
	# Get all Relevant Accounts
	$filteredAccounts = Get-FilteredAccounts -sSafeName $SafeName -sPlatformID $PlatformID -sUserName $UserName -sAddress $Address -sCustomKeywords $Custom -bFailedOnly $FailedOnly
	Write-LogMessage -Type Info -MSG "Going over $($filteredAccounts.Count) filtered accounts"
	# Run Account Action on relevant Accounts
	foreach ($account in $filteredAccounts) {
		Write-LogMessage -Type Debug -MSG "Submitting account `"$($account.Name)`" in safe `"$($account.safeName)`""
		try {
			$null = Invoke-Rest -Uri ($accountAction -f $account.id) -Command POST -Body '' -Header $global:g_LogonHeader
			Write-LogMessage -Type Debug -MSG "Submitted account `"$($account.Name)`" in safe `"$($account.safeName)`""
		}
		catch {
			Write-LogMessage -Type Error -MSG "Error Submitting account `"$($account.Name)`" in safe `"$($account.safeName)`""
		}
	}
}
catch {
	Write-LogMessage -Type Error -MSG "There was an Error running bulk account actions. Error: $(Collect-ExceptionMessage $_.Exception)"
}

# Logoff the session
# ------------------
if (![string]::IsNullOrEmpty($logonToken)) {
	Write-Host 'LogonToken passed, session NOT logged off'
}
elseif ($DisableLogoff) {
	Write-Host 'Logoff has been disabled, session NOT logged off'
}
else {
	Invoke-Logoff
}
Write-LogMessage -type Info -MSG 'Script ended' -Footer -LogFile $LOG_FILE_PATH
return

Write-LogMessage -Type Info -MSG 'Script ended' -Footer -LogFile $LOG_FILE_PATH
return
