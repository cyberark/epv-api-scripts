###########################################################################
#
# NAME: Create Personal Privileged Accounts
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will create personal privileged accounts according to a CSV
# The script will create the personal safe if it does not exist
# The script can create safes according to a naming pattern
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v11.6 and above
#
###########################################################################
[CmdletBinding(DefaultParameterSetName = "")]
param
(
	[Parameter(Mandatory = $true, HelpMessage = "Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[ValidateNotNullOrEmpty()]
	[String]$PVWAURL,

	[Parameter(Mandatory = $false, HelpMessage = "Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark", "ldap", "radius")]
	[String]$AuthType = "cyberark",

	[Parameter(Mandatory = $false, HelpMessage = "Enter the RADIUS OTP")]
	[ValidateScript({ $AuthType -eq "radius" })]
	[String]$OTP,

	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory = $false)]
	[Switch]$DisableSSLVerify,
    
	[Parameter(Mandatory = $false, HelpMessage = "Enter the safe pattern to use")]
	[Alias("pattern")]
	[ValidateScript({ ($_.ToCharArray() | Where-Object { $_ -eq '*' } | Measure-Object).Count -eq 1 })]
	[string]$SafeNamePattern = "*_ADM",
    
	[Parameter(Mandatory = $false, HelpMessage = "Enter the Platform ID (Default:WinDomain)")]
	[string]$PlatformID = "WinDomain",
	
	[Parameter(Mandatory = $true, HelpMessage = "Enter the Accounts CSV path")]
	[ValidateScript( { Test-Path -Path $_ -PathType Leaf -IsValid })]
	[Alias("path")]
	[string]$CSVPath
)

# Get Script Location 
$ScriptFullPath = $MyInvocation.MyCommand.Path
$ScriptLocation = Split-Path -Parent $ScriptFullPath
$ScriptParameters = @()
$PSBoundParameters.GetEnumerator() | ForEach-Object { $ScriptParameters += ("-{0} '{1}'" -f $_.Key, $_.Value) }
$script:g_ScriptCommand = "{0} {1}" -f $ScriptFullPath, $($ScriptParameters -join ' ')

# Script Version
$ScriptVersion = "1.1"

# Set Log file path
$LOG_FILE_PATH = "$ScriptLocation\PersonalPrivilegedAccounts.log"

$InDebug = $PSBoundParameters.Debug.IsPresent
$InVerbose = $PSBoundParameters.Verbose.IsPresent

# Global URLS
# -----------
$URL_PVWABaseAPI = $PVWAURL + "/WebServices/PIMServices.svc"
$URL_PVWAAPI = $PVWAURL + "/api"
$URL_Authentication = $URL_PVWAAPI + "/auth"
$URL_Logon = $URL_Authentication + "/$AuthType/Logon"
$URL_Logoff = $URL_Authentication + "/Logoff"

# URL Methods
# -----------
$URL_Safes = $URL_PVWABaseAPI + "/Safes"
$URL_SafeDetails = $URL_Safes + "/{0}"
$URL_SafeMembers = $URL_SafeDetails + "/Members"
$URL_BulkAccounts = $URL_PVWAAPI + "/BulkActions/Accounts"
$URL_BulkAccountsTask = $URL_PVWAAPI + "/BulkActions/Accounts/{0}"

# Initialize Script Variables
# ---------------------------
$script:g_LogonHeader = $null
$script:g_SSLChanged = $false
$script:g_LogAccountName = ""
$script:g_CsvDefaultPath = $Env:CSIDL_DEFAULT_DOWNLOADS
$script:g_DefaultUsers = @("Master", "Batch", "Backup Users", "Auditors", "Operators", "DR Users", "Notification Engines", "PVWAGWAccounts", "PVWAGWUser", "PVWAAppUser", "PasswordManager")

# Safe Defaults
# --------------
$CPM_NAME = "PasswordManager"
$NumberOfDaysRetention = 7

#region Functions
#region Writer Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Write-LogMessage
# Description....: Writes the message to log and screen
# Parameters.....: LogFile, MSG, (Switch)Header, (Switch)SubHeader, (Switch)Footer, Type
# Return Values..: None
# =================================================================================================================================
Function Write-LogMessage
{
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
		[ValidateSet("Info", "Warning", "Error", "Debug", "Verbose")]
		[String]$type = "Info",
		[Parameter(Mandatory = $false)]
		[String]$LogFile = $LOG_FILE_PATH
	)
	Try
	{
		If ([string]::IsNullOrEmpty($LogFile))
		{
			# Create a temporary log file
			$LogFile = "$ScriptLocation\tmp.log"
		}
		
		If ($Header)
  {
			"=======================================" | Out-File -Append -FilePath $LogFile 
		}
		ElseIf ($SubHeader)
		{ 
			"------------------------------------" | Out-File -Append -FilePath $LogFile 
		}
		
		$msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
		# Replace empty message with 'N/A'
		if ([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
		
		# Mask Passwords
		if ($Msg -match '((?:"password"|"secret"|"NewCredentials")\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w!@#$%^&*()-\\\/]+))')
		{
			$Msg = $Msg.Replace($Matches[2], "****")
		}
		$writeToFile = $true
		# Check the message type
		switch ($type)
		{
			"Info"
   { 
				Write-Host $MSG.ToString()
				$msgToWrite += "[INFO]`t$Msg"
				break
			}
			"Warning"
			{
				Write-Host $MSG.ToString() -ForegroundColor DarkYellow
				$msgToWrite += "[WARNING]`t$Msg"
				break
			}
			"Error"
			{
				Write-Host $MSG.ToString() -ForegroundColor Red
				$msgToWrite += "[ERROR]`t$Msg"
				break
			}
			"Debug"
			{ 
				if ($InDebug -or $InVerbose)
				{
					Write-Debug $MSG
					$msgToWrite += "[DEBUG]`t$Msg"
					break
				}
				else { $writeToFile = $False }
			}
			"Verbose"
			{ 
				if ($InVerbose)
				{
					Write-Verbose $MSG
					$msgToWrite += "[VERBOSE]`t$Msg"
					break
				}
				else { $writeToFile = $False }
			}
		}
		If ($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LogFile }
		If ($Footer)
		{ 
			"=======================================" | Out-File -Append -FilePath $LogFile 
		}
	}
	catch
	{
		Throw $(New-Object System.Exception ("Cannot write message '$Msg' to file '$LogFile'", $_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Join-ExceptionMessage
# Description....: Formats exception messages
# Parameters.....: Exception
# Return Values..: Formatted String of Exception messages
# =================================================================================================================================
Function Join-ExceptionMessage
{
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

	Begin
	{
	}
	Process
	{
		$msg = "Source:{0}; Message: {1}" -f $e.Source, $e.Message
		while ($e.InnerException)
		{
			$e = $e.InnerException
			$msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
		}
		return $msg
	}
	End
	{
	}
}
#endregion

#region Helper Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: ConvertTo-URL
# Description....: Encodes a text for URL
# Parameters.....: Text
# Return Values..: URL encoded text
# =================================================================================================================================
Function ConvertTo-URL($sText)
{
	<# 
.SYNOPSIS 
	HTTP Encode test in URL
.DESCRIPTION
	HTTP Encode test in URL
.PARAMETER sText
	The text to encode
#>
	if (![string]::IsNullOrEmpty($sText))
	{
		Write-Debug "Returning URL Encode of $sText"
		return [URI]::EscapeDataString($sText)
	}
	else
	{
		return $sText
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: ConvertTo-Bool
# Description....: Converts text to Bool
# Parameters.....: Text
# Return Values..: Boolean value of the text
# =================================================================================================================================
Function ConvertTo-Bool
{
	<# 
.SYNOPSIS 
	Converts text to Bool
.DESCRIPTION
	Converts text to Bool
.PARAMETER txt
	The text to convert to bool (True / False)
#>
	param (
		[string]$txt
	)
	$retBool = $false
    
	if ($txt -match "^y$|^yes$")
	{
		$retBool = $true 
	}
	elseif ($txt -match "^n$|^no$")
	{ 
		$retBool = $false 
	}
	else
	{
		[bool]::TryParse($txt, [ref]$retBool) | Out-Null
	}
    
	return $retBool
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-PersonalSafeNameFromPattern
# Description....: Get the personal safe name based on pattern
# Parameters.....: User Name
# Return Values..: The Safe name to be used
# =================================================================================================================================
Function Get-PersonalSafeNameFromPattern
{
	<# 
.SYNOPSIS 
	Get the personal safe name based on pattern
.DESCRIPTION
	Get the personal safe name based on pattern
.PARAMETER userName
    The User name to be used in the safe pattern
#>
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$userName
	)

	return $SafeNamePattern.Replace("*", $userName)
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Disable-SSLVerification
# Description....: Disables the SSL Verification (bypass self signed SSL certificates)
# Parameters.....: None
# Return Values..: None
# =================================================================================================================================
Function Disable-SSLVerification
{
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
	if (-not("DisableCertValidationCallback" -as [type]))
	{
		Add-Type -TypeDefinition @"
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
"@ 
 }

	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = [DisableCertValidationCallback]::GetDelegate()
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Invoke-Rest
# Description....: Invoke REST Method
# Parameters.....: Command method, URI, Header, Body
# Return Values..: REST response
# =================================================================================================================================
Function Invoke-Rest
{
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
		[ValidateSet("GET", "POST", "DELETE", "PATCH")]
		[String]$Command, 
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()] 
		[String]$URI, 
		[Parameter(Mandatory = $false)]
		$Header, 
		[Parameter(Mandatory = $false)]
		[String]$Body, 
		[Parameter(Mandatory = $false)]
		[ValidateSet("Continue", "Ignore", "Inquire", "SilentlyContinue", "Stop", "Suspend")]
		[String]$ErrAction = "Continue"
	)
	
	$restResponse = ""
	try
	{
		if ([string]::IsNullOrEmpty($Body))
		{
			Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -TimeoutSec 2700"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -TimeoutSec 2700 -ErrorAction $ErrAction
		}
		else
		{
			Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body -TimeoutSec 2700"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body -TimeoutSec 2700 -ErrorAction $ErrAction
		}
	}
 catch [System.Net.WebException]
	{
		if ($ErrAction -match ("\bContinue\b|\bInquire\b|\bStop\b|\bSuspend\b"))
		{
			Write-LogMessage -Type Error -Msg "Error Message: $_"
			Write-LogMessage -Type Error -Msg "Exception Message: $($_.Exception.Message)"
			Write-LogMessage -Type Error -Msg "Status Code: $($_.Exception.Response.StatusCode.value__)"
			Write-LogMessage -Type Error -Msg "Status Description: $($_.Exception.Response.StatusDescription)"
		}
		$restResponse = $null
	}
 catch
	{ 
		Throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $_.Exception))
	}
	Write-LogMessage -Type Verbose -Msg "Invoke-REST Response: $restResponse"
	return $restResponse
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-LogonHeader
# Description....: Invoke REST Method
# Parameters.....: Credentials
# Return Values..: Logon Header
# =================================================================================================================================
Function Get-LogonHeader
{
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
		[PSCredential]$Credentials,
		[Parameter(Mandatory = $false)]
		[string]$RadiusOTP
	)
	try
	{
		If ([string]::IsNullOrEmpty($RadiusOTP))
		{
			# Use a new Logon session for each request
			return $(Invoke-Logon -Credentials $Credentials)
		}
		else
		{
			# Use the same header using the RADIUS OTP (so we don't have to request the OTP every login)
			if ([string]::IsNullOrEmpty($g_LogonHeader))
			{
				Set-Variable -Name g_LogonHeader -Value $(Invoke-Logon -Credentials $Credentials -RadiusOTP $RadiusOTP) -Scope Script
			}
            
			return $g_LogonHeader
		}
	}
 catch
	{
		Throw $(New-Object System.Exception ("Get-LogonHeader: Error returning the logon header.", $_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Invoke-Logon
# Description....: Login to the system
# Parameters.....: Credentials, Radius OTP
# Return Values..: Logon Header
# =================================================================================================================================
Function Invoke-Logon
{
	<#
.SYNOPSIS
	Invoke-Logon
.DESCRIPTION
	Invoke-Logon
.PARAMETER Credentials
    The REST API Credentials to authenticate
.PARAMETER RadiusOTP
    The One Time Password for RADIUS authentication
#>
	param(
		[Parameter(Mandatory = $true)]
		[PSCredential]$Credentials,
		[Parameter(Mandatory = $false)]
		[string]$RadiusOTP
	)
	# Disable SSL Verification to contact PVWA
	If ($DisableSSLVerify -and !$g_SSLChanged)
	{
		Disable-SSLVerification
		Set-Variable -Name g_SSLChanged -Value $true -Scope Script
	}
    
	# Create the POST Body for the Logon
	# ----------------------------------
	$logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password; concurrentSession = $true } | ConvertTo-Json -Compress
	If (![string]::IsNullOrEmpty($RadiusOTP))
	{
		$logonBody.Password += ",$RadiusOTP"
	}   
                
	try
	{
		# Logon
		$logonToken = Invoke-Rest -Command Post -Uri $URL_Logon -Body $logonBody 

		# Clear logon body
		$logonBody = ""
	}
 catch
	{
		Throw $(New-Object System.Exception ("Invoke-Logon: $($_.Exception.Response.StatusDescription)", $_.Exception))
	}

	$logonHeader = $null
	If ([string]::IsNullOrEmpty($logonToken))
	{
		Throw "Invoke-Logon: Logon Token is Empty - Cannot login"
	}

	# Create a Logon Token Header (This will be used through out all the script)
	# ---------------------------
	If ($logonToken.PSObject.Properties.Name -contains "CyberArkLogonResult")
	{
		$logonHeader = @{Authorization = $($logonToken.CyberArkLogonResult) }
	}
 else
	{
		$logonHeader = @{Authorization = $logonToken }
	}
	
	return $logonHeader
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Invoke-Logoff
# Description....: Logoff PVWA
# Parameters.....: None
# Return Values..: None
# =================================================================================================================================
Function Invoke-Logoff
{
	<# 
.SYNOPSIS 
	Invoke-Logoff
.DESCRIPTION
	Logoff a PVWA session
#>
	param(
		[Parameter(Mandatory = $false)]
		$Header = $g_LogonHeader
	)
	try
	{
		# Logoff the session
		# ------------------
		If ($null -ne $Header)
		{
			Write-LogMessage -Type Info -Msg "Logoff Session..."
			Invoke-Rest -Command Post -Uri $URL_Logoff -Header $Header
			Set-Variable -Name g_LogonHeader -Value $null -Scope script
		}
	}
 catch
	{
		Throw $(New-Object System.Exception ("Invoke-Logoff: Failed to logoff session", $_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-TrimmedString
# Description....: Returns the trimmed text from a string
# Parameters.....: Text
# Return Values..: Trimmed text
# =================================================================================================================================
Function Get-TrimmedString($sText)
{
	<# 
.SYNOPSIS 
	Returns the trimmed text from a string
.DESCRIPTION
	Returns the trimmed text from a string
.PARAMETER txt
	The text to handle
#>
	if ($null -ne $sText)
	{
		return $sText.Trim()
	}
	# Else
	return $sText
}

# @FUNCTION@ ======================================================================================================================
# Name...........: New-AccountObject
# Description....: Creates a new Account object
# Parameters.....: Account line read from CSV
# Return Values..: Account Object for onboarding
# =================================================================================================================================
Function New-AccountObject
{
	<# 
.SYNOPSIS 
	Creates a new Account Object
.DESCRIPTION
	Creates a new Account Object
.PARAMETER AccountLine
	(Optional) Account Object Name
#>
	param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()] 
		[PSObject]$AccountLine
	)
	try
	{
		$_safeName = $_platformID = ""
		# Check mandatory fields for account creation
		If ([string]::IsNullOrEmpty($AccountLine.accountUser)) { throw "Missing mandatory field: Account User Name" }
		If ([string]::IsNullOrEmpty($AccountLine.accountAddress)) { throw "Missing mandatory field: Account Address" }
		If ([string]::IsNullOrEmpty($AccountLine.safeName)) { $_safeName = Get-PersonalSafeNameFromPattern -userName $AccountLine.userName }
		Else { $_safeName = $AccountLine.safeName }
		If ([string]::IsNullOrEmpty($AccountLine.accountPlatform)) { $_platformID = $PlatformID }
		Else { $_platformID = $AccountLine.accountPlatform }
		
		
		# Check if there are custom properties
		$excludedProperties = @("accountuser", "accountaddress", "accountplatform", "name", "username", "address", "safe", "platformid", "password", "key", "enableautomgmt", "manualmgmtreason", "groupname", "groupplatformid", "remotemachineaddresses", "restrictmachineaccesstolist", "sshkey")
		$customProps = $($AccountLine.PSObject.Properties | Where-Object { $_.Name.ToLower() -NotIn $excludedProperties })
		#region [Account object mapping]
		# Convert Account from CSV to Account Object (properties mapping)
		$_Account = "" | Select-Object "address", "userName", "platformId", "safeName", "secret", "platformAccountProperties", "secretManagement", "remoteMachinesAccess"
		$_Account.platformAccountProperties = $null
		$_Account.secretManagement = "" | Select-Object "automaticManagementEnabled", "manualManagementReason"
		$_Account.address = (Get-TrimmedString $AccountLine.accountAddress)
		$_Account.userName = (Get-TrimmedString $AccountLine.accountUser)
		$_Account.platformId = (Get-TrimmedString $_platformID)
		$_Account.safeName = (Get-TrimmedString $_safeName)
		$_Account.secret = $AccountLine.password
		if (![string]::IsNullOrEmpty($customProps))
		{
			# Convert any non-default property in the CSV as a new platform account property
			if ($null -eq $_Account.platformAccountProperties) { $_Account.platformAccountProperties = New-Object PSObject }
			For ($i = 0; $i -lt $customProps.count; $i++)
			{
				$prop = $customProps[$i]
				If (![string]::IsNullOrEmpty($prop.Value))
				{
					$_Account.platformAccountProperties | Add-Member -MemberType NoteProperty -Name $prop.Name -Value (Get-TrimmedString $prop.Value)
				}
			}
		}
		If (![String]::IsNullOrEmpty($AccountLine.enableAutoMgmt))
		{
			$_Account.secretManagement.automaticManagementEnabled = ConvertTo-Bool $AccountLine.enableAutoMgmt
			if ($_Account.secretManagement.automaticManagementEnabled -eq $false)
			{ $_Account.secretManagement.manualManagementReason = $AccountLine.manualMgmtReason }
		}
		$_Account.remoteMachinesAccess = "" | Select-Object "remoteMachines", "accessRestrictedToRemoteMachines"
		If (![String]::IsNullOrEmpty($AccountLine.remoteMachineAddresses))
		{
			$_Account.remoteMachinesAccess.remoteMachines = $AccountLine.remoteMachineAddresses
			$_Account.remoteMachinesAccess.accessRestrictedToRemoteMachines = ConvertTo-Bool $AccountLine.restrictMachineAccessToList
		}
		# Remove empty non-mandatory areas
		If ($null -eq $_Account.platformAccountProperties)
		{
			$_Account.PSObject.Properties.Remove('platformAccountProperties')
		}
		If ($null -eq $_Account.remoteMachinesAccess.remoteMachines)
		{
			$_Account.PSObject.Properties.Remove('remoteMachinesAccess')
		}
		If ($null -eq $_Account.secretManagement.automaticManagementEnabled)
		{
			$_Account.PSObject.Properties.Remove('secretManagement')
		}
		#endregion [Account object mapping]
		$logFormat = ""
		If (([string]::IsNullOrEmpty($_Account.userName) -or [string]::IsNullOrEmpty($_Account.Address)) -and (![string]::IsNullOrEmpty($_Account.name)))
		{
			$logFormat = $_Account.name
		}
		Else
		{
			$logFormat = ("{0}@{1}" -f $_Account.userName, $_Account.Address)
		}
		Set-Variable -Scope Global -Name g_LogAccountName -Value $logFormat
				
		return $_Account
	}
 catch
	{
		Throw $(New-Object System.Exception ("New-AccountObject: There was an error creating a new account object.", $_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: OpenFile-Dialog
# Description....: Opens a new "Open File" Dialog
# Parameters.....: LocationPath
# Return Values..: Selected file path
# =================================================================================================================================
Function Open-FileDialog
{
	<# 
.SYNOPSIS 
	Opens a new "Open File" Dialog
.DESCRIPTION
	Opens a new "Open File" Dialog
.PARAMETER LocationPath
	The Location to open the dialog in
#>
	param (
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
		[ValidateNotNullOrEmpty()] 
		[string]$LocationPath
	)
	[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    
	$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
	$OpenFileDialog.initialDirectory = $LocationPath
	$OpenFileDialog.filter = "CSV (*.csv)| *.csv"
	$OpenFileDialog.ShowDialog() | Out-Null
	return $OpenFileDialog.filename
}
#endregion

#region Accounts and Safes functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Get-Safe
# Description....: Returns an existing Safe object
# Parameters.....: Safe Name
# Return Values..: Safe object
# =================================================================================================================================
Function Get-Safe
{
	<# 
.SYNOPSIS 
	Returns an existing Safe object
.DESCRIPTION
	Returns an existing Safe object
.PARAMETER SafeName
	The Safe Name to return
#>
	param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()] 
		$Header,
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()] 
		[String]$safeName,
		[Parameter(Mandatory = $false)]
		[ValidateSet("Continue", "Ignore", "Inquire", "SilentlyContinue", "Stop", "Suspend")]
		[String]$ErrAction = "Continue"
	)
	$_safe = $null
	try
	{
		$accSafeURL = $URL_SafeDetails -f $(ConvertTo-URL $safeName)
		$_safe = $(Invoke-Rest -Uri $accSafeURL -Header $Header -Command "Get" -ErrAction $ErrAction)
	}
	catch
	{
		Throw $(New-Object System.Exception ("Get-Safe: Error getting safe '$safeName' details.", $_.Exception))
	}
	
	return $_safe.GetSafeResult
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-Safe
# Description....: Check if the safe exists
# Parameters.....: Safe name
# Return Values..: Bool
# =================================================================================================================================
Function Test-Safe
{
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
		$Header,
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()] 
		[String]$safeName
	)
		
	try
	{
		If ($null -eq $(Get-Safe -safeName $safeName -Header $Header -ErrAction "SilentlyContinue"))
		{
			# Safe does not exist
			Write-LogMessage -Type Warning -MSG "Safe $safeName does not exist"
			return $false
		}
		else
		{
			# Safe exists
			Write-LogMessage -Type Info -MSG "Safe $safeName exists"
			return $true
		}
	}
	catch
	{
		Throw $(New-Object System.Exception ("Test-Safe: Error testing safe '$safeName' existence.", $_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Add-Safe
# Description....: Creates a new Safe
# Parameters.....: Safe name, (optional) CPM name, (optional) Template Safe
# Return Values..: Bool
# =================================================================================================================================
Function Add-Safe
{
	<# 
.SYNOPSIS 
	Creates a new Safe
.DESCRIPTION
	Creates a new Safe
.PARAMETER SafeName
	The Safe Name to create
.PARAMETER CPMName
	The CPM Name to add to the safe. if not entered, the default (first) CPM will be chosen
.PARAMETER TemplateSafeObject
	The Template Safe object (returned from the Get-Safe method). If entered the new safe will be created based on this safe (including members)
#>
	param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()] 
		$Header,
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()] 
		[String]$safeName,
		[Parameter(Mandatory = $false)]
		[String]$cpmName,
		[Parameter(Mandatory = $false)]
		[String]$description
	)
	
	# Create the Target Safe
	Write-LogMessage -Type Info -MSG "Creating Safe $safeName"
	$bodySafe = @{ SafeName = $safeName; Description = $description; OLACEnabled = $false; ManagingCPM = $CPM_NAME; NumberOfDaysRetention = $NumberOfDaysRetention }
	$restBody = @{ safe = $bodySafe } | ConvertTo-Json -Depth 3 -Compress
	
	try
 {
		$createSafeResult = $(Invoke-Rest -Uri $URL_Safes -Header $Header -Command "Post" -Body $restBody)
		if ($createSafeResult)
		{
			Write-LogMessage -Type Debug -MSG "Safe $safeName created"
			return $true
		}
		else
		{ 
			# Safe creation failed
			Write-LogMessage -Type Error -MSG "Safe Creation failed - Should Skip Account Creation"
			return $false 
		}
	}
 catch
	{
		Throw $(New-Object System.Exception ("Add-Safe: Failed to create safe $safeName", $_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Add-Owner
# Description....: Add a new owner to an existing safe
# Parameters.....: Safe name, Member to add
# Return Values..: The Member object after added to the safe
# =================================================================================================================================
Function Add-SafeOwner
{
	<# 
.SYNOPSIS 
	Add a new owner to an existing safe
.DESCRIPTION
	Add a new owner to an existing safe
.PARAMETER SafeName
	The Safe Name to add a member to
.PARAMETER OwnerName
    The user name of the owner to add
.PARAMETER OwnerRole
    The role of the Owner to add
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
		[Parameter(Mandatory = $true)]
		[ValidateSet("Admin", "Auditor", "Owner", "EndUser", "Approver")]
		[string]$ownerRole,
		[Parameter(Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			HelpMessage = "Which vault-integrated LDAP directory name the vault should search for the account. Must match one of the directory names defined in the LDAP Integration page of the PVWA.",
			Position = 0)]
		$memberSearchInLocation = "Vault"
	)
	# Init all permissions
	$permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = `
		$permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafe = $permManageSafeMembers = $permBackupSafe = $permViewAuditLog = `
		$permViewSafeMembers = $permAccessWithoutConfirmation = $permCreateFolders = $permDeleteFolders = $permMoveAccountsAndFolders = $false
	[int]$permRequestsAuthorizationLevel = 0
	Write-LogMessage -Type Verbose -Msg "Adding member '$ownerName' to safe $SafeName with Role '$ownerRole'..."
	switch ($ownerRole)
	{
		"Admin"
		{
			$permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = `
				$permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafe = $permManageSafeMembers = $permBackupSafe = `
				$permViewAuditLog = $permViewSafeMembers = $permAccessWithoutConfirmation = $permCreateFolders = $permDeleteFolders = $permMoveAccountsAndFolders = $true
			$permRequestsAuthorizationLevel = 1
		}
		"Auditor"
		{
			$permListAccounts = $permViewAuditLog = $permViewSafeMembers = $true
		}
		"EndUser"
		{
			$permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permViewAuditLog = $permViewSafeMembers = $true
		}
		"Approver"
		{
			$permListAccounts = $permViewAuditLog = $permViewSafeMembers = $true
			$permRequestsAuthorizationLevel = 1
		}
		"Owner"
		{
			$permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = $permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafeMembers = $permViewAuditLog = $permViewSafeMembers = $permMoveAccountsAndFolders = $true
			$permRequestsAuthorizationLevel = 1
		}
	}

	If ($ownerName -NotIn $g_DefaultUsers)
	{
		try
		{   
			$SafeMembersBody = @{
				member = @{
					MemberName               = "$ownerName"
					SearchIn                 = "$memberSearchInLocation"
					MembershipExpirationDate = "$null"
					Permissions              = @(
						@{Key = "UseAccounts"; Value = $permUseAccounts }
						@{Key = "RetrieveAccounts"; Value = $permRetrieveAccounts }
						@{Key = "ListAccounts"; Value = $permListAccounts }
						@{Key = "AddAccounts"; Value = $permAddAccounts }
						@{Key = "UpdateAccountContent"; Value = $permUpdateAccountContent }
						@{Key = "UpdateAccountProperties"; Value = $permUpdateAccountProperties }
						@{Key = "InitiateCPMAccountManagementOperations"; Value = $permInitiateCPMManagement }
						@{Key = "SpecifyNextAccountContent"; Value = $permSpecifyNextAccountContent }
						@{Key = "RenameAccounts"; Value = $permRenameAccounts }
						@{Key = "DeleteAccounts"; Value = $permDeleteAccounts }
						@{Key = "UnlockAccounts"; Value = $permUnlockAccounts }
						@{Key = "ManageSafe"; Value = $permManageSafe }
						@{Key = "ManageSafeMembers"; Value = $permManageSafeMembers }
						@{Key = "BackupSafe"; Value = $permBackupSafe }
						@{Key = "ViewAuditLog"; Value = $permViewAuditLog }
						@{Key = "ViewSafeMembers"; Value = $permViewSafeMembers }
						@{Key = "RequestsAuthorizationLevel"; Value = $permRequestsAuthorizationLevel }
						@{Key = "AccessWithoutConfirmation"; Value = $permAccessWithoutConfirmation }
						@{Key = "CreateFolders"; Value = $permCreateFolders }
						@{Key = "DeleteFolders"; Value = $permDeleteFolders }
						@{Key = "MoveAccountsAndFolders"; Value = $permMoveAccountsAndFolders }
					)
				}  
			}
            
			# Adding the member
			Write-LogMessage -Type Verbose -Msg "Adding $ownerName located in $memberSearchInLocation to $safeName in the vault..."
			$setSafeMember = Invoke-Rest -Command POST -Uri ($URL_SafeMembers -f $(ConvertTo-URL $safeName)) -Body ($safeMembersBody | ConvertTo-Json -Depth 5) -Header $Header
			If ($null -ne $setSafeMember)
			{
				Write-LogMessage -Type Verbose -Msg "Member '$ownerName' was successfully added to safe $SafeName with Role '$ownerRole'..."
			}
		}
		catch
		{
			Throw $(New-Object System.Exception ("Add-SafeOwner: There was an error setting the membership for $ownerName on $safeName in the Vault.", $_.Exception))
		}
	}
	else
	{
		Write-LogMessage -Type Info -Msg "Skipping default user $ownerName..."
	}
}
#endregion
#endregion

#-----------------
# Write the entire script command when running in Verbose mode
Write-LogMessage -Type Verbose -Msg $g_ScriptCommand -LogFile $LOG_FILE_PATH
# Header
Write-LogMessage -Type Info -MSG "Starting script (v$ScriptVersion)" -Header -LogFile $LOG_FILE_PATH
if ($InDebug) { Write-LogMessage -Type Info -MSG "Running in Debug Mode" -LogFile $LOG_FILE_PATH }
if ($InVerbose) { Write-LogMessage -Type Info -MSG "Running in Verbose Mode" -LogFile $LOG_FILE_PATH }
Write-LogMessage -Type Debug -MSG "Running PowerShell version $($PSVersionTable.PSVersion.Major) compatible of versions $($PSVersionTable.PSCompatibleVersions -join ", ")" -LogFile $LOG_FILE_PATH
If ($PSVersionTable.PSVersion.Major -lt 3)
{
	Write-LogMessage -Type Error -Msg "This script requires PowerShell version 3 or above"
	return
}

# Check if Powershell is running in Constrained Language Mode
If ($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage")
{
	Write-LogMessage -Type Error -MSG "Powershell is currently running in $($ExecutionContext.SessionState.LanguageMode) mode which limits the use of some API methods used in this script.`
	PowerShell Constrained Language mode was designed to work with system-wide application control solutions such as CyberArk EPM or Device Guard User Mode Code Integrity (UMCI).`
	For more information: https://blogs.msdn.microsoft.com/powershell/2017/11/02/powershell-constrained-language-mode/"
	Write-LogMessage -Type Info -MSG "Script ended" -Footer -LogFile $LOG_FILE_PATH
	return
}
# Check that the PVWA URL is OK
If (![string]::IsNullOrEmpty($PVWAURL))
{
	If ($PVWAURL.Substring($PVWAURL.Length - 1) -eq "/")
	{
		$PVWAURL = $PVWAURL.Substring(0, $PVWAURL.Length - 1)
	}
}

# Get the CSV file to load
If ([string]::IsNullOrEmpty($CsvPath))
{
	$CsvPath = Open-FileDialog($g_CsvDefaultPath)
}

# Get Credentials to Login
# ------------------------
$caption = "Personal Privileged Accounts"
$msg = "Enter your PAS User name and Password ($AuthType)"; 
$creds = $Host.UI.PromptForCredential($caption, $msg, "", "")
$counter = 1
# Read the Accounts
$accountsCSV = Import-Csv $csvPath
$personalPrivAccounts = @()
Write-LogMessage -Type Info -MSG "Creating needed personal safes and collecting accounts for onboard" -SubHeader
ForEach ($account in $accountsCSV)
{
	if ($null -ne $account)
	{
		try
		{
			# Create the account object
			$objAccount = (New-AccountObject -AccountLine $account)
			# Get a new Authentication header
			$authHeader = Get-LogonHeader -Credentials $creds -RadiusOTP $RadiusOTP
			# Check if the Safe Exists
			Write-LogMessage -Type Info -Msg "Checking if safe '$($objAccount.safeName)' exists..."
			If (-not $(Test-Safe -safeName $objAccount.safeName -Header $authHeader))
			{
				# Create the Safe
				Write-LogMessage -Type Info -Msg "Creating safe '$($objAccount.safeName)' and adding '$($account.userName)' as an Owner"
				try
				{
					If ($(Add-Safe -safeName $objAccount.safeName -Header $authHeader))
					{
						# Add the user as the Owner of the safe
						Add-SafeOwner -safeName $objAccount.safeName -ownerName $account.userName -ownerRole "Owner" -Header $authHeader
					}
				}
				catch
				{
					Throw $(New-Object System.Exception ("There was an error creating the safe or adding safe members", $_.Exception))
				}
			}
			$objAccount | Add-Member -NotePropertyName uploadIndex -NotePropertyValue $counter
			$personalPrivAccounts += $objAccount
			$counter++
			# Logoff temp session (if not using Radius)
			If ($AuthType -ne "radius")
			{
				Invoke-Logoff -Header $authHeader
			}
		}
		catch
		{
			Write-LogMessage -Type Error -Msg "There was an error onboarding $g_LogAccountName into the Password Vault. Error: $(Join-ExceptionMessage $_.Exception)"
		}
	}
}

# Start Bulk onboarding all collected personal privileged accounts
try
{
	If ($personalPrivAccounts.Count -gt 0)
	{

		Write-LogMessage -Type Info -Msg "Starting onboarding $($personalPrivAccounts.Count) personal privileged accounts"
		$authHeader = Get-LogonHeader -Credentials $creds -RadiusOTP $RadiusOTP
		$bulkBody = @{
			"source"       = $(Split-Path -Resolve $CSVPath -Leaf);
			"accountsList" = $personalPrivAccounts
		}
		$bulkID = Invoke-Rest -Command POST -URI $URL_BulkAccounts -Body ($bulkBody | ConvertTo-Json -Depth 5) -Header $authHeader
		if ($null -ne $bulkID)
		{
			$bulkResult = Invoke-Rest -Command Get -URI ($URL_BulkAccountsTask -f $bulkID) -Header $authHeader
			while ( ($bulkResult.Status -eq "inProgress") -or ($bulkResult.Status -eq "Pending"))
			{
				Start-Sleep -Seconds 5
				Write-LogMessage -type Info -MSG "Current status of onboarding is: $($bulkResult.Status -creplace '([A-Z])','$1')"
				$bulkResult = Invoke-Rest -Command Get -URI ($URL_BulkAccountsTask -f $bulkID) -Header $authHeader
			}
			# Bulk action completed (no longer in progress)
			Write-LogMessage -type Info -MSG "Onboarding of personal privileged accounts $($bulkResult.Status -creplace '([A-Z])','$1')"
			Switch ($bulkResult.Status)
			{
				"completedWithErrors"
				{
					Write-LogMessage -Type Info -MSG ("There are {0} personal privileged accounts that successfully onaborded and {1} accounts that failed" -f $bulkResult.Result.succeeded, $bulkResult.Result.failed)
					ForEach ($item in $bulkResult.FailedItems.Items)
					{
						$failedAccount = "{0}@{1} (index: {2})" - $item.userName, $item.address, $item.uploadIndex
						Write-LogMessage -Type Info -Msg ("Account {0} failed with the following error {1}" -f $failedAccount, $item.error)
					}
				}
				"failed"
				{
					Write-LogMessage -Type Info -MSG ("Personal privileged accounts onboarding failed due to the following error: {0}" -f $bulkResult.Result.Error)
				}
				"completed"
				{
					Write-LogMessage -Type Info -MSG ("There are {0} personal privileged accounts that successfully onaborded" -f $bulkResult.Result.succeeded)
				}
			}
		}
		else
		{
			Throw "The Bulk Account Upload ID returned empty"
		}
	}
	else
	{
		Write-LogMessage -Type Info -Msg "No personal privileged accounts to onboard"
	}
}
catch
{
	Write-LogMessage -Type Error -Msg "There was an error running bulk onboarding of accounts. Error: $(Join-ExceptionMessage $_.Exception)"
}
finally
{
	# Logoff the session
	# ------------------
	Invoke-Logoff -Header $authHeader
	Write-LogMessage -Type Info -MSG "Script Ended" -Footer -LogFile $LOG_FILE_PATH
}

