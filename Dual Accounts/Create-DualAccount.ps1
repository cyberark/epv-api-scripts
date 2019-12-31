###########################################################################
#
# NAME: Create Dual Account
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will create two accounts to work as Dual Account for AAM
# This allows an application to work with two user accounts while one is active and the other passive
# More information here: https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/CP%20and%20ASCP/cv_Managing-Dual-Accounts.htm?tocpath=Integrations%7CCyberArk%20Vault%20Synchronizer%7CAccounts%20and%20Safes%7CManage%20Dual%20Accounts%7C_____0#ManageDualAccounts
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v10.4 and above
#
###########################################################################
[CmdletBinding(DefaultParametersetName="Interactive")]
param
(
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	#[ValidateScript({If($DisableSSLVerify) { Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30}})]
	[Alias("url")]
	[String]$PVWAURL,

	[Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark","ldap","radius")]
	[String]$AuthType="cyberark",
	
	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory=$false)]
	[Switch]$DisableSSLVerify,
	
	# Use this switch to switch to interactive mode
	[Parameter(ParameterSetName='Interactive',Mandatory=$true)]
	[Switch]$Interactive,
	
	# Use this switch to switch to non-interactive mode
	[Parameter(ParameterSetName='NonInteractive',Mandatory=$true)]
	[Switch]$NonInteractive,
	
	[Parameter(ParameterSetName='NonInteractive', Mandatory=$true,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,HelpMessage="Enter a path to a file containing relevant accounts")]
	[ValidateScript({Test-Path $_})]
	[Alias("path")]
	[String]$CsvPath,
	
	[Parameter(ParameterSetName='NonInteractive', Mandatory=$true,HelpMessage="Enter the Dual Account Platform ID")]
	[Alias("platform")]
	[String]$AccountPlatformID,
	
	[Parameter(ParameterSetName='NonInteractive', Mandatory=$true,HelpMessage="Enter the Dual Account Group Platform ID")]
	[Alias("group")]
	[String]$GroupPlatformID,
	
	[Parameter(ParameterSetName='NonInteractive', Mandatory=$true,HelpMessage="Enter the Dual Accounts Safe Name")]
	[Alias("safe")]
	[String]$AccountSafeName
)

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
# Get Debug / Verbose parameters for Script
$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent

# Script Version
$ScriptVersion = "1.0"

# ------ SET global parameters ------
# Set Log file path
$global:LOG_FILE_PATH = "$ScriptLocation\DualAccounts.log"
# Set a global Header Token parameter
$global:g_LogonHeader = ""

# Global URLS
# -----------
$URL_PVWAAPI = $PVWAURL+"/api"
$URL_Authentication = $URL_PVWAAPI+"/auth"
$URL_Logon = $URL_Authentication+"/$AuthType/Logon"
$URL_Logoff = $URL_Authentication+"/Logoff"

# URL Methods
# -----------
$URL_Accounts = $URL_PVWAAPI+"/Accounts"
$URL_AccountsDetails = $URL_Accounts+"/{0}"
$URL_AccountGroups = $URL_PVWAAPI+"/AccountGroups"
$URL_AccountGroupMembers = $URL_PVWAAPI+"/AccountGroups/{0}/Members"
$URL_PlatformDetails = $URL_PVWAAPI+"/Platforms/{0}"

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
		[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[AllowEmptyString()]
		[String]$MSG,
		[Parameter(Mandatory=$false)]
		[Switch]$Header,
		[Parameter(Mandatory=$false)]
		[Switch]$SubHeader,
		[Parameter(Mandatory=$false)]
		[Switch]$Footer,
		[Parameter(Mandatory=$false)]
		[ValidateSet("Info","Warning","Error","Debug","Verbose")]
		[String]$type = "Info",
		[Parameter(Mandatory=$false)]
		[String]$LogFile = $LOG_FILE_PATH
	)
	Try{
		If([string]::IsNullOrEmpty($LogFile))
		{
			# Create a temporary log file
			$LogFile = "$ScriptLocation\tmp.log"
		}
		
		If ($Header) {
			"=======================================" | Out-File -Append -FilePath $LogFile 
		}
		ElseIf($SubHeader) { 
			"------------------------------------" | Out-File -Append -FilePath $LogFile 
		}
		
		$msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
		# Replace empty message with 'N/A'
		if([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
		
		# Mask Passwords
		if($Msg -match '((?>password|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=(\w+))')
		{
			$Msg = $Msg.Replace($Matches[2],"****")
		}
		$writeToFile = $true
		# Check the message type
		switch ($type)
		{
			"Info" { 
				Write-Host $MSG.ToString()
				$msgToWrite += "[INFO]`t$Msg"
				break
			}
			"Warning" {
				Write-Host $MSG.ToString() -ForegroundColor DarkYellow
				$msgToWrite += "[WARNING]`t$Msg"
				break
			}
			"Error" {
				Write-Host $MSG.ToString() -ForegroundColor Red
				$msgToWrite += "[ERROR]`t$Msg"
				break
			}
			"Debug" { 
				if($InDebug -or $InVerbose)
				{
					Write-Debug $MSG
					$msgToWrite += "[DEBUG]`t$Msg"
					break
				}
				else { $writeToFile = $False }
			}
			"Verbose" { 
				if($InVerbose)
				{
					Write-Verbose $MSG
					$msgToWrite += "[VERBOSE]`t$Msg"
					break
				}
				else { $writeToFile = $False }
			}
		}
		If($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LogFile }
		If ($Footer) { 
			"=======================================" | Out-File -Append -FilePath $LogFile 
		}
	}
	catch{
		Throw $(New-Object System.Exception ("Cannot write message '$Msg' to file '$Logfile'",$_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Collect-ExceptionMessage
# Description....: Formats exception messages
# Parameters.....: Exception
# Return Values..: Formatted String of Exception messages
# =================================================================================================================================
Function Collect-ExceptionMessage
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

	Begin {
	}
	Process {
		$msg = "Source:{0}; Message: {1}" -f $e.Source, $e.Message
		while ($e.InnerException) {
		  $e = $e.InnerException
		  $msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
		}
		return $msg
	}
	End {
	}
}
#endregion

#region Helper Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Test-CommandExists
# Description....: Tests if a command exists
# Parameters.....: Command
# Return Values..: True / False
# =================================================================================================================================
Function Test-CommandExists
{
<# 
.SYNOPSIS 
	Tests if a command exists
.DESCRIPTION
	Tests if a command exists
.PARAMETER Command
	The command to test
#>

    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try { if(Get-Command $command){ return $true } }
    Catch { return $false }
    Finally {$ErrorActionPreference=$oldPreference}
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
	if (-not("DisableCertValidationCallback" -as [type])) {
    add-type -TypeDefinition @"
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
"@ }

	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = [DisableCertValidationCallback]::GetDelegate()
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Encode-URL
# Description....: HTTP Encode test in URL
# Parameters.....: Text to encode
# Return Values..: Encoded HTML URL text
# =================================================================================================================================
Function Encode-URL($sText)
{
<# 
.SYNOPSIS 
	HTTP Encode test in URL
.DESCRIPTION
	HTTP Encode test in URL
.PARAMETER sText
	The text to encode
#>
	if ($sText.Trim() -ne "")
	{
		Write-LogMessage -Type Debug -Msg "Returning URL Encode of $sText"
		return [System.Web.HttpUtility]::UrlEncode($sText)
	}
	else
	{
		return $sText
	}
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
	(Optional) The Error Action to perform in case of error. By deault "Continue"
#>
	param (
		[Parameter(Mandatory=$true)]
		[ValidateSet("GET","POST","DELETE","PATCH")]
		[String]$Command, 
		[Parameter(Mandatory=$true)]
		[String]$URI, 
		[Parameter(Mandatory=$false)]
		$Header, 
		[Parameter(Mandatory=$false)]
		[String]$Body, 
		[Parameter(Mandatory=$false)]
		[ValidateSet("Continue","Ignore","Inquire","SilentlyContinue","Stop","Suspend")]
		[String]$ErrAction="Continue"
	)
	
	If ((Test-CommandExists Invoke-RestMethod) -eq $false)
	{
	   Throw "This script requires PowerShell version 3 or above"
	}
	$restResponse = ""
	try{
		if([string]::IsNullOrEmpty($Body))
		{
			Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -TimeoutSec 36000"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -TimeoutSec 36000
		}
		else
		{
			Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body -TimeoutSec 36000"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body -TimeoutSec 36000
		}
	} catch [System.Net.WebException] {
		Write-LogMessage -Type Error -Msg "Exception Message: $($_.Exception.Message)" -ErrorAction $ErrAction
		Write-LogMessage -Type Error -Msg "Status Code: $($_.Exception.Response.StatusCode.value__)"
		Write-LogMessage -Type Error -Msg "Status Description: $($_.Exception.Response.StatusDescription)" -ErrorAction $ErrAction
		$restResponse = $null
	} catch { 
		Throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'",$_.Exception))
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
		[Parameter(Mandatory=$true)]
		[PSCredential]$Credentials
	)
	
	if([string]::IsNullOrEmpty($g_LogonHeader))
	{
		# Disable SSL Verification to contact PVWA
		If($DisableSSLVerify)
		{
			Disable-SSLVerification
		}
		
		# Create the POST Body for the Logon
		# ----------------------------------
		$logonBody = @{ username=$Credentials.username.Replace('\','');password=$Credentials.GetNetworkCredential().password } | ConvertTo-Json
		try{
			# Logon
			$logonToken = Invoke-Rest -Command Post -Uri $URL_Logon -Body $logonBody
			
			# Clear logon body
			$logonBody = ""
		} catch {
			Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.Exception.Response.StatusDescription)",$_.Exception))
		}

		$logonHeader = $null
		If ([string]::IsNullOrEmpty($logonToken))
		{
			Throw "Get-LogonHeader: Logon Token is Empty - Cannot login"
		}
		
		# Create a Logon Token Header (This will be used through out all the script)
		# ---------------------------
		$logonHeader =  New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
		$logonHeader.Add("Authorization", $logonToken)
		
		Set-Variable -Name g_LogonHeader -Value $logonHeader -Scope global		
	}
	
	return $g_LogonHeader
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Run-Logoff
# Description....: Logoff PVWA
# Parameters.....: None
# Return Values..: None
# =================================================================================================================================
Function Run-Logoff
{
<# 
.SYNOPSIS 
	Run-Logoff
.DESCRIPTION
	Logoff a PVWA session
#>
	try{
		# Logoff the session
		# ------------------
		Write-LogMessage -Type Info -Msg "Logoff Session..."
		Invoke-Rest -Command Post -Uri $URL_Logoff -Header $g_LogonHeader | out-null
		Set-Variable -Name g_LogonHeader -Value $null -Scope global
	} catch {
		Throw $(New-Object System.Exception ("Run-Logoff: Failed to logoff session",$_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Add-DualAccount
# Description....: Create a new Dual Account
# Parameters.....: User Name, User password, PlatformID, Safe Name, VirtualUserName, Index
# Return Values..: None
# =================================================================================================================================
Function Add-DualAccount
{
<# 
.SYNOPSIS 
	Add-DualAccount -UserName appUser1 -UserPassword **** -Address 10.10.2.1 -PlatformID UnixDualAccount -SafeName DualAccountSafe -VirtualUserName BillingApp -Index 1 -VaultCredentials $Creds
.DESCRIPTION
	Create a new Dual Account
.PARAMETER UserName
	The account user name
.PARAMETER UserPassword
	The account user password
.PARAMETER Address
	The account address
.PARAMETER PlatformID
	The account Platform ID
.PARAMETER SafeName
	The account Platform ID
.PARAMETER VirtualUserName
	The Virtual User Name
.PARAMETER Index
	The dual account Index
.PARAMETER VaultCredentials
	The Vault Credentials to be used
#>
	param(
		[Parameter(Mandatory=$true)]
		[string]$userName,
		[Parameter(Mandatory=$true)]
		[string]$userPassword,
		[Parameter(Mandatory=$true)]
		[string]$address,
		[Parameter(Mandatory=$true)]
		[string]$platformID,
		[Parameter(Mandatory=$true)]
		[string]$safeName,
		[Parameter(Mandatory=$true)]
		[string]$virtualUserName,
		[Parameter(Mandatory=$true)]
		[ValidateScript({$_ -ge 1})]
		[int]$index,
		[Parameter(Mandatory=$true)]
		[PSCredential]$VaultCredentials
	)

	try{
		If((Test-Account -accountName $userName -accountAddress $address -safeName $safeName -VaultCredentials $VaultCredentials) -eq $false)
		{
			$accName = ('{0}@{1}' -f $userName, $address)
			Write-LogMessage -Type Debug -Msg "Creating a new Account for $accName"
			$objAccount = "" | Select "name", "address", "userName", "platformId", "safeName", "secretType", "secret", "platformAccountProperties", "secretManagement"
			$objAccount.platformAccountProperties = New-Object PSObject
			$objAccount.secretManagement = "" | Select "automaticManagementEnabled"
			$objAccount.address = $address
			$objAccount.userName = $userName
			$objAccount.platformId = $platformID
			$objAccount.safeName = $safeName
			$objAccount.secretType = "password"
			$objAccount.secret = $userPassword
			$objAccount.secretManagement.automaticManagementEnabled = $true
			$objAccount.platformAccountProperties | Add-Member -NotePropertyName VirtualUserName -NotePropertyValue $virtualUserName
			$objAccount.platformAccountProperties | Add-Member -NotePropertyName Index -NotePropertyValue $index
			$dualAccountStatusValue = "Inactive"
			if($index -eq 1)
			{
				$dualAccountStatusValue = "Active"
			}
			$objAccount.platformAccountProperties | Add-Member -NotePropertyName DualAccountStatus -NotePropertyValue $dualAccountStatusValue
			
			$addAccountResult = $(Invoke-Rest -Uri $URL_Accounts -Header $(Get-LogonHeader -Credentials $VaultCredentials) -Body $($objAccount | ConvertTo-Json -Depth 5) -Command "Post")
			
			return $addAccountResult.id
		}
		else
		{
			return (Get-Account -accountName $userName -accountAddress $address -safeName $safeName -VaultCredentials $VaultCredentials).id
		}
	} catch {
		Throw $(New-Object System.Exception ("Add-DualAccount: Failed to add the account '$accName'",$_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-RotationalGroupIDFromSafe
# Description....: Get the rotational Group ID (if exists) from a safe
# Parameters.....: GroupPlatformID, Safe Name, GroupName
# Return Values..: Group ID
# =================================================================================================================================
Function Get-RotationalGroupIDFromSafe
{
<# 
.SYNOPSIS 
	Get-RotationalGroupIDFromSafe -GroupPlatformID GroupDualAccount -SafeName DualAccountSafe -GroupName BillingAppGroup -VaultCredentials $Creds
.DESCRIPTION
	Create a new Rotational group for Dual Accounts
.PARAMETER GroupPlatformID
	The Rotational group Platform ID
.PARAMETER SafeName
	The account Platform ID
.PARAMETER GroupName
	The Group Name
.PARAMETER VaultCredentials
	The Vault Credentials to be used
#>
	param(
		[Parameter(Mandatory=$true)]
		[string]$groupPlatformID,
		[Parameter(Mandatory=$true)]
		[string]$safeName,
		[Parameter(Mandatory=$true)]
		[string]$groupName,
		[Parameter(Mandatory=$true)]
		[PSCredential]$VaultCredentials
	)

	try{
		$groupID = $null
		# Check if this safe already has a Rotational Group for this Account
		Write-LogMessage -Type Debug -Msg "Searching for $groupName Rotational Group in safe $safeName"
		$urlSafeAccountGroups = $URL_AccountGroups + "?safe=$safeName"
		$safeAccountGroupsResult = Invoke-Rest -Command GET -Uri $urlSafeAccountGroups -Header $(Get-LogonHeader -Credentials $VaultCredentials)
		if($safeAccountGroupsResult -ne $null -or $safeAccountGroupsResult.Count -ge 1)
		{
			Write-LogMessage -Type Verbose -Msg "Going over $($safeAccountGroupsResult.Count) found Account Group"
			ForEach($group in $safeAccountGroupsResult)
			{
				if(($group.GroupPlatformID -eq $groupPlatformID) -and ($group.GroupName -eq $groupName))
				{
					# Get existing group ID
					$groupID = $group.GroupID
					Write-LogMessage -Type Debug -Msg "Found Rotational Group ID: $groupID"
				}
			}
		}
		
		return $groupID
	} catch {
		Throw $(New-Object System.Exception ("Get-RotationalGroupIDFromSafe: Failed to get Rotational Group ID",$_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Add-RotationalGroup
# Description....: Create a new Rotational group for Dual Accounts
# Parameters.....: GroupPlatformID, Safe Name, VirtualUserName, AccountID
# Return Values..: None
# =================================================================================================================================
Function Add-RotationalGroup
{
<# 
.SYNOPSIS 
	Add-RotationalGroup -GroupPlatformID GroupDualAccount -SafeName DualAccountSafe -VirtualUserName BillingApp -VaultCredentials $Creds
.DESCRIPTION
	Create a new Rotational group for Dual Accounts
.PARAMETER GroupPlatformID
	The Rotational group Platform ID
.PARAMETER SafeName
	The account Platform ID
.PARAMETER VirtualUserName
	The Virtual User Name
.PARAMETER VaultCredentials
	The Vault Credentials to be used
#>
	param(
		[Parameter(Mandatory=$true)]
		[string]$groupPlatformID,
		[Parameter(Mandatory=$true)]
		[string]$safeName,
		[Parameter(Mandatory=$true)]
		[string]$virtualUserName,
		[Parameter(Mandatory=$true)]
		[string]$accountID,
		[Parameter(Mandatory=$true)]
		[PSCredential]$VaultCredentials
	)

	try{
		$groupID = $null
		$groupName = $virtualUserName+"Group"
		$groupID = Get-RotationalGroupIDFromSafe -groupPlatformID $groupPlatformID -safeName $safeName -groupName $groupName -VaultCredentials $VaultCredentials
		Write-LogMessage -Type Verbose -Msg "Found group ID: $groupID"
		# Create a new Group
		if([string]::IsNullOrEmpty($groupID))
		{
			# If no group - create the group
			$groupBody = "" | Select GroupName, GroupPlatformId, Safe
			$groupBody.GroupName = $groupName
			$groupBody.GroupPlatformID = $groupPlatformID
			$groupBody.Safe = $safeName
			$addAccGroupResult = Invoke-Rest -Command Post -URI $URL_AccountGroups -Header $(Get-LogonHeader -Credentials $VaultCredentials) -Body $($groupBody | ConvertTo-Json)
			if($addAccGroupResult -ne $null)
			{
				Write-LogMessage -Type Verbose -Msg "Rotational group created. Group ID: $($addAccGroupResult.GroupID)"
				$groupID = $addAccGroupResult.GroupID
			}
		}
		# Check that a group was creadted or found
		if(![string]::IsNullOrEmpty($groupID))
		{
			# Add the Account to the Rotational Group
			$accGroupMemberBody = "" | Select AccountID
			$accGroupMemberBody.AccountID = $accountID
			$addAccGroupMemberResult = Invoke-Rest -Command Post -URI ($URL_AccountGroupMembers -f $groupID) -Header $(Get-LogonHeader -Credentials $VaultCredentials) -Body $($accGroupMemberBody | ConvertTo-Json)
		}
		else
		{
			throw "There was an error getting the Rotational Group ID"
		}
	} catch {
		Throw $(New-Object System.Exception ("Add-RotationalGroup: Failed to add Account to Rotational Group",$_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-Account
# Description....: Returns a list of accounts based on a filter
# Parameters.....: Account name, Account address, Account Safe Name
# Return Values..: List of accounts
# =================================================================================================================================
Function Get-Account
{
<# 
.SYNOPSIS 
	Get-Account -accountName user1 -accountAddress 1.1.1.1 -safeName MySafe -VaultCredentials $Creds
.DESCRIPTION
	Creates a new Account Object
.PARAMETER AccountName
	Account user name
.PARAMETER AccountAddress
	Account address
.PARAMETER SafeName
	The Account Safe Name to search in
#>
	param (
		[Parameter(Mandatory=$true)]
		[String]$accountName, 
		[Parameter(Mandatory=$true)]
		[String]$accountAddress, 
		[Parameter(Mandatory=$true)]
		[String]$safeName,
		[Parameter(Mandatory=$true)]
		[PSCredential]$VaultCredentials
	)
	$_retaccount = $null
	$_accounts = $null
	try{
		$urlSearchAccount = $URL_Accounts+"?filter=safename eq "+$(Encode-URL $safeName)+"&search="+$(Encode-URL "$accountName $accountAddress")
		# Search for created account
		$_accounts = $(Invoke-Rest -Uri $urlSearchAccount -Header $(Get-LogonHeader -Credentials $VaultCredentials) -Command "Get")
		if($null -ne $_accounts)
		{
			foreach ($item in $_accounts.value)
			{
				if(($item -ne $null) -and ($item.username -eq $accountName) -and ($item.address -eq $accountAddress))
				{
					$_retaccount = $item
					break;
				}
			}
		}
	} catch {
		Throw $(New-Object System.Exception ("Get-Account: There was an error retreiving the account object.",$_.Exception))
	}
	
	return $_retaccount
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-Account
# Description....: Checks if an account exists
# Parameters.....: Account name, Account address, Account Safe Name
# Return Values..: True / False
# =================================================================================================================================
Function Test-Account
{
<# 
.SYNOPSIS 
	Test-Account -accountName user1 -accountAddress 1.1.1.1 -safeName MySafe -VaultCredentials $Creds
.DESCRIPTION
	Test if an accoutn exists (Search based on filters)
.PARAMETER AccountName
	Account user name
.PARAMETER AccountAddress
	Account address
.PARAMETER SafeName
	The Account Safe Name to search in
#>
	param (
		[Parameter(Mandatory=$true)]
		[String]$accountName, 
		[Parameter(Mandatory=$true)]
		[String]$accountAddress, 
		[Parameter(Mandatory=$true)]
		[String]$safeName,
		[Parameter(Mandatory=$true)]
		[PSCredential]$VaultCredentials
	)
	try {
		$accResult = $(Get-Account -accountName $accountName -accountAddress $accountAddress -safeName $safeName -VaultCredentials $VaultCredentials)
		If (($null -eq $accResult) -or ($accResult.count -eq 0))
		{
			# No accounts found
			Write-LogMessage -Type Debug -MSG "Account $accountName does not exist"
			return $false
		}
		else
		{
			# Account Exists
			Write-LogMessage -Type Info -MSG "Account $accountName exist"
			return $true
		}
	} catch {
		Throw $(New-Object System.Exception ("Test-Account: There was an error finding the account object.",$_.Exception))
	}
}
#endregion

#-----------------
Write-LogMessage -Type Info -MSG "Starting script (v$ScriptVersion)" -Header -LogFile $LOG_FILE_PATH
if($InDebug) { Write-LogMessage -Type Info -MSG "Running in Debug Mode" -LogFile $LOG_FILE_PATH }
if($InVerbose) { Write-LogMessage -Type Info -MSG "Running in Verbose Mode" -LogFile $LOG_FILE_PATH }
Write-LogMessage -Type Debug -MSG "Running PowerShell version $($PSVersionTable.PSVersion.Major) compatible of versions $($PSVersionTable.PSCompatibleVersions -join ", ")" -LogFile $LOG_FILE_PATH

# Check if Powershell is running in Constrained Language Mode
If($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage")
{
	Write-LogMessage -Type Error -MSG "Powershell is currently running in $($ExecutionContext.SessionState.LanguageMode) mode which limits the use of some API methods used in this script.`
	PowerShell Constrained Language mode was designed to work with system-wide application control solutions such as CyberArk EPM or Device Guard User Mode Code Integrity (UMCI).`
	For more information: https://blogs.msdn.microsoft.com/powershell/2017/11/02/powershell-constrained-language-mode/"
	Write-LogMessage -Type Info -MSG "Script ended" -Footer -LogFile $LOG_FILE_PATH
	return
}
# Check that the PVWA URL is OK
If ($PVWAURL -ne "")
{
	If ($PVWAURL.Substring($PVWAURL.Length-1) -eq "/")
	{
		$PVWAURL = $PVWAURL.Substring(0,$PVWAURL.Length-1)
	}
}
else
{
	Write-LogMessage -Type Error -MSG "PVWA URL can not be empty"
	return
}

# Get Credentials to Login
# ------------------------
$caption = "Create Dual Account"
$msg = "Enter your PAS User name and Password ($AuthType)"; 
$creds = $Host.UI.PromptForCredential($caption,$msg,"","")

try {
	# Check if we have a file to use
	if($NonInteractive)
	{
		# CSV format should be "UserName, Address, Password"
		$allAccounts = Import-CSV $(Resolve-Path $CsvPath)
		$ind = 1
		$arrAccountId = @()
		ForEach($account in $allAccounts)
		{
			$dualAccountParameters = @{
			vaultCredentials=$creds;
			userName=$account.UserName;
			address=$account.address;
			userPassword=$account.password;
			safeName=$AccountSafeName;
			PlatformID=$AccountPlatformID;
			VirtualUserName=$VirtualUserName;
			Index=$ind;
			}
			Write-LogMessage -Type Info -MSG "Creating Account $('{0}@{1}' -f $account.userName, $account.address)"
			$arrAccountId += Add-DualAccount @dualAccountParameters 
			$ind++
		}
		
		Write-LogMessage -Type Info -MSG "Creating the Rotational Group"
		ForEach($id in $arrAccountId)
		{
			Add-RotationalGroup -groupPlatformID $GroupPlatformID -safeName $AccountSafeName -virtualUserName $VirtualUserName -accountID $id -VaultCredentials $creds
		}
		Write-LogMessage -Type Info -MSG "Rotational Group for $VirtualUserName was successfully created"
	}
	else
	{
		$msg = "Enter the {0} account credentials.`nUser@address"
		# Interactive session
		Write-LogMessage -Type Info -MSG "Entering Interactive session mode"
		$AppVirtualUserName = Read-Host "Enter the application Virtual User Name"
		$AppSafeName = Read-Host "Enter the application Safe Name"
		$AccountPlatformID = Read-Host "Enter the Dual Account Platform ID"
		$GroupPlatformID = Read-Host "Enter the Rotational Group Platform ID"
		$user1 = $Host.UI.PromptForCredential($caption,($msg -f "first"),"","")
		$user2 = $Host.UI.PromptForCredential($caption,($msg -f "second"),"","")
		
		# Create the Accounts
		# Get User1 Details
		$userName, $address = $user1.username.Replace('\','').Split('@')
		$dualAccountParameters = @{
			vaultCredentials=$creds;
			userName=$userName;
			address=$address;
			userPassword=$user1.GetNetworkCredential().password;
			safeName=$AppSafeName;
			PlatformID=$AccountPlatformID;
			VirtualUserName=$AppVirtualUserName;
			Index=1
		}
		# Create User1
		Write-LogMessage -Type Info -MSG "Creating Account $($user1.userName)"
		$user1ID = Add-DualAccount @dualAccountParameters 
		
		# Get User2 Details
		$dualAccountParameters.userName, $dualAccountParameters.address = $user2.username.Replace('\','').Split('@')
		$dualAccountParameters.userPassword = $user2.GetNetworkCredential().password
		$dualAccountParameters.Index = 2
		# Create User2
		Write-LogMessage -Type Info -MSG "Creating Account $($user2.userName)"
		$user2ID = Add-DualAccount @dualAccountParameters 
		
		# Create the Roataional Group
		Write-LogMessage -Type Info -MSG "Creating the Rotational Group"
		Add-RotationalGroup -groupPlatformID $GroupPlatformID -safeName $AppSafeName -virtualUserName $AppVirtualUserName -accountID $user1ID -VaultCredentials $creds
		Add-RotationalGroup -groupPlatformID $GroupPlatformID -safeName $AppSafeName -virtualUserName $AppVirtualUserName -accountID $user2ID -VaultCredentials $creds
		
		Write-LogMessage -Type Info -MSG "Rotational Group for $AppVirtualUserName was successfully created"
	}	
} catch {
	Write-LogMessage -Type Error - MSG "There was an Error creating a Rotational Group for Dual Accounts. Error: $(Collect-ExceptionMessage $_.Exception)"
}

# Logoff the session
# ------------------
Run-Logoff
Write-LogMessage -Type Info -MSG "Script ended" -Footer -LogFile $LOG_FILE_PATH
return
