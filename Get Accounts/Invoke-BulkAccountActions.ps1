###########################################################################
#
# NAME: 		Invoke-BulkAccountActions.ps1
# DESCRIPTION:  Run Account Actions on a List of Accounts using REST API
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will execute a single account action on a list of accounts according to filters (optional).
# Or execute a single account action on all accounts from a file.
#
# Filter Criteria available:
# --------------------------
# Safe Name - Search for all accounts in a specific safe
# Filter by specific keywords. All following filters will be by default with OR between them
# 	PlatformID
# 	UserName
# 	Address
# 	Custom - Using this parameter will not be validate the results
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v10.4 and above
#
# USAGE:
# Invoke-BulkAccountActions.ps1 -PVWAURL <string> -AccountsAction <string {Verify | Change | Reconcile}> [-AuthType <string>] [-DisableSSLVerify] [-SafeName <string>] [-PlatformID <string>] [-UserName <string>] [-Address <string>] [-Custom <string>] [<CommonParameters>]
#
###########################################################################
[CmdletBinding(DefaultParameterSetName="Filters")]
param
(
	[Parameter(Mandatory=$true,HelpMessage="Enter the PVWA URL")]
	[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,
	
	[Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark","ldap","radius")]
	[String]$AuthType="cyberark",
	
	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory=$false)]
	[Switch]$DisableSSLVerify,
		
	# Account Actions to be used
	[Parameter(Mandatory=$true)]
	[ValidateSet('Verify',
		'Change',
		'Reconcile')]
	[Alias("Action")]
	[String]$AccountsAction = "Verify",
	
	# List accounts filters
	[Parameter(ParameterSetName='Filters',Mandatory=$false,HelpMessage="Enter a Safe Name to search in")]
	[ValidateScript({$_.Length -le 28})]
	[Alias("Safe")]
	[String]$SafeName,
	
	[Parameter(ParameterSetName='Filters',Mandatory=$false,HelpMessage="Enter a PlatformID to filter accounts by")]
	[String]$PlatformID,
	
	[Parameter(ParameterSetName='Filters',Mandatory=$false,HelpMessage="Enter a UserName to filter accounts by")]
	[String]$UserName,
	
	[Parameter(ParameterSetName='Filters',Mandatory=$false,HelpMessage="Enter a Address to filter accounts by")]
	[String]$Address,
	
	[Parameter(ParameterSetName='Filters',Mandatory=$false,HelpMessage="Enter filter Keywords. List of keywords are separated with space to search in accounts")]
	[String]$Custom,

	[Parameter(ParameterSetName='Filters',Mandatory=$false)]
	[Switch]$FailedOnly,

	[Parameter(ParameterSetName='Filters',Mandatory=$false)]
	[Switch]$CPMDisabled
)

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
# Get Debug / Verbose parameters for Script
$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent

# ------ SET global parameters ------
# Set Log file path
$global:LOG_FILE_PATH = "$ScriptLocation\BulkAccountActions.log"
# Set a global Header Token parameter
$global:g_LogonHeader = $null

# Global URLS
# -----------
$URL_PVWAAPI = $PVWAURL+"/api"
$URL_Authentication = $URL_PVWAAPI+"/auth"
$URL_Logon = $URL_Authentication+"/$AuthType/Logon"
$URL_Logoff = $URL_Authentication+"/Logoff"

# URL Methods
# -----------
$URL_Accounts = $URL_PVWAAPI+"/Accounts"
$URL_AccountsDetails = $URL_PVWAAPI+"/Accounts/{0}"
$URL_AccountChange = $URL_AccountsDetails+"/Change"
$URL_AccountVerify = $URL_AccountsDetails+"/Verify"
$URL_AccountReconcile = $URL_AccountsDetails+"/Reconcile"
$URL_Platforms = $URL_PVWAAPI+"/Platforms/{0}"

# Script Defaults
# ---------------

#region Writer Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Write-LogMessage
# Description....: Writes the message to log and screen
# Parameters.....: LogFile, MSG, (Switch)Header, (Switch)SubHeader, (Switch)Footer, Type
# Return Values..: None
# =================================================================================================================================
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
		If([string]::IsNullOrEmpty($LogFile)) {
			# Create a temporary log file
			$LogFile = "$ScriptLocation\tmp.log"
		}
		
		If ($Header) {
			"=======================================" | Out-File -Append -FilePath $LogFile 
		} ElseIf($SubHeader) { 
			"------------------------------------" | Out-File -Append -FilePath $LogFile 
		}
		
		$msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
		# Replace empty message with 'N/A'
		if([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
		
		# Mask Passwords
		if($Msg -match '((?>password|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=(\w+))') {
			$Msg = $Msg.Replace($Matches[2],"****")
		}
		$writeToFile = $true
		# Check the message type
		switch ($type) {
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
				if($InDebug -or $InVerbose) {
					Write-Debug $MSG
					$msgToWrite += "[DEBUG]`t$Msg"
					break
				} else { $writeToFile = $False }
			}
			"Verbose" { 
				if($InVerbose) {
					Write-Verbose $MSG
					$msgToWrite += "[VERBOSE]`t$Msg"
					break
				} else { $writeToFile = $False }
			}
		}
		If($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LogFile }
		If ($Footer) { 
			"=======================================" | Out-File -Append -FilePath $LogFile 
		}
	} catch{
		Throw $(New-Object System.Exception ("Cannot write message '$Msg' to file '$Logfile'",$_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Collect-ExceptionMessage
# Description....: Formats exception messages
# Parameters.....: Exception
# Return Values..: Formatted String of Exception messages
# =================================================================================================================================
Function Collect-ExceptionMessage {
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
Function Test-CommandExists {
	Param ($command)
	$oldPreference = $ErrorActionPreference
	$ErrorActionPreference = 'stop'
	try {if(Get-Command $command){RETURN $true}}
	Catch {Write-Host "$command does not exist"; RETURN $false}
	Finally {$ErrorActionPreference=$oldPreference}
} #end function test-CommandExists

# @FUNCTION@ ======================================================================================================================
# Name...........: Disable-SSLVerification
# Description....: Disables the SSL Verification (bypass self signed SSL certificates)
# Parameters.....: None
# Return Values..: None
# =================================================================================================================================
Function Disable-SSLVerification {
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
	
	If ((Test-CommandExists Invoke-RestMethod) -eq $false) {
		Throw "This script requires PowerShell version 3 or above"
	}
	$restResponse = ""
	try{
		if([string]::IsNullOrEmpty($Body)) {
			Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -TimeoutSec 2700"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -TimeoutSec 2700
		} else {
			Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body -TimeoutSec 2700"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body -TimeoutSec 2700
		}
	} catch [System.Net.WebException] {
		Write-LogMessage -Type Error -Msg "Exception Message: $($_.Exception.Message)" -ErrorAction $ErrAction
		Write-LogMessage -Type Error -Msg "Status Code: $($_.Exception.Response.StatusCode.value__)"
		Write-LogMessage -Type Error -Msg "Status Description: $($_.Exception.Response.StatusDescription)" -ErrorAction $ErrAction
		Write-LogMessage -Type Error -Msg "Error Message: $($_.ErrorDetails.Message)" -ErrorAction $ErrAction
		$restResponse = $null
		Throw
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
		[Parameter(Mandatory=$true)]
		[PSCredential]$Credentials
	)
	
	if([string]::IsNullOrEmpty($g_LogonHeader)) {
		# Disable SSL Verification to contact PVWA
		If($DisableSSLVerify) {
			Disable-SSLVerification
		}
		
		# Create the POST Body for the Logon
		# ----------------------------------
		$logonBody = @{ username=$Credentials.username.Replace('\','');password=$Credentials.GetNetworkCredential().password;concurrentSession="true" } | ConvertTo-Json
		try{
			# Logon
			$logonToken = Invoke-Rest -Command Post -Uri $URL_Logon -Body $logonBody
			
			# Clear logon body
			$logonBody = ""
		} catch {
			Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.Exception.Response.StatusDescription)",$_.Exception))
		}

		$logonHeader = $null
		If ([string]::IsNullOrEmpty($logonToken)) {
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
Function Run-Logoff {
	<# 
.SYNOPSIS 
	Run-Logoff
.DESCRIPTION
	Logoff a PVWA session
#>
	try{
		If($null -ne $g_LogonHeader) {
			# Logoff the session
			# ------------------
			Write-LogMessage -Type Info -Msg "Logoff Session..."
			Invoke-Rest -Command Post -Uri $URL_Logoff -Header $g_LogonHeader | Out-Null
			Set-Variable -Name g_LogonHeader -Value $null -Scope global
		}
	} catch {
		Throw $(New-Object System.Exception ("Run-Logoff: Failed to logoff session",$_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Encode-URL
# Description....: Encodes a text for URL
# Parameters.....: Text
# Return Values..: Encoded Text
# =================================================================================================================================
Function Encode-URL($sText) {
	<# 
.SYNOPSIS 
	Encode-URL
.DESCRIPTION
	Encodes a text for URL
#>
	if ($sText.Trim() -ne "") {
		Write-LogMessage -Type Verbose -Msg "Returning URL Encode of $sText"
		return [URI]::EscapeDataString($sText)
	} else {
		return ""
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-SearchCriteria
# Description....: Creates a search creteria URL for PVWA
# Parameters.....: Base URL, Search keywords, safe name
# Return Values..: None
# =================================================================================================================================
Function Get-SearchCriteria {
	<# 
.SYNOPSIS 
	Get-SearchCriteria
.DESCRIPTION
	Creates a search creteria URL for PVWA
#>
	param ([string]$sURL, [string]$sSearch, [string]$sSafeName)
	[string]$retURL = $sURL
	$retURL += "?"
	
	if($sSearch.Trim() -ne "") {
		Write-LogMessage -Type Debug -Msg "Search: $sSearch"
		$retURL += "search=$(Encode-URL $sSearch)&"
	}
	if($sSafeName.Trim() -ne "") {
		Write-LogMessage -Type Debug -Msg "Safe: $sSafeName"
		$retURL += "filter=safename eq $(Encode-URL $sSafeName)&"
	}
			
	if($retURL[-1] -eq '&') { $retURL = $retURL.substring(0,$retURL.length-1) }
	Write-LogMessage -Type Debug -Msg "URL: $retURL"
	
	return $retURL
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-FilteredAccounts
# Description....: Returns a list of Accounts according to a filter
# Parameters.....: Safe name, Platform ID, Custom keywords, User name, address
# Return Values..: List of Filtered Accounts
# =================================================================================================================================
Function Get-FilteredAccounts {
	<# 
.SYNOPSIS 
	Get-FilteredAccounts
.DESCRIPTION
	Returns a list of Accounts according to a filter
#>
	param (
		[Parameter(Mandatory=$true)]
		[PSCredential]$VaultCredentials,
		[Parameter(Mandatory=$false)]
		[string]$sSafeName,
		[Parameter(Mandatory=$false)]
		[string]$sPlatformID,
		[Parameter(Mandatory=$false)]
		[string]$sUserName,
		[Parameter(Mandatory=$false)]
		[string]$sAddress,
		[Parameter(Mandatory=$false)]
		[string]$sCustomKeywords,
		[Parameter(Mandatory=$false)]
		[bool]$bFailedOnly
	)
	
	$GetAccountsList = @()
	$FilteredAccountsList = @()
	try {
		$AccountsURLWithFilters = ""
		$Keywords = "$sPlatformID $sUserName $sAddress $sCustomKeywords"
		$AccountsURLWithFilters = $(Get-SearchCriteria -sURL $URL_Accounts -sSearch $Keywords -sSafeName $SafeName)
		Write-LogMessage -Type Debug -MSG "Filter accounts using: $AccountsURLWithFilters"
	} catch {
		throw $(New-Object System.Exception ("Get-FilteredAccounts: Error creating filtered URL",$_.Exception))
	}
	try{
		# Get all Accounts
		$GetAccountsResponse = Invoke-Rest -Command Get -Uri $AccountsURLWithFilters -Header (Get-LogonHeader $VaultCredentials)
		$GetAccountsList += $GetAccountsResponse.value
		Write-LogMessage -Type Debug -MSG "Found $($GetAccountsList.count) accounts so far..."
		$nextLink = $GetAccountsResponse.nextLink
		Write-LogMessage -Type Debug -MSG "Getting accounts next link: $nextLink"
		
		While (-not [string]::IsNullOrEmpty($nextLink)) {
			$GetAccountsResponse = Invoke-Rest -Command Get -Uri $("$PVWAURL/$nextLink") -Header (Get-LogonHeader $VaultCredentials)
			$nextLink = $GetAccountsResponse.nextLink
			Write-LogMessage -Type Debug -MSG "Getting accounts next link: $nextLink"
			$GetAccountsList += $GetAccountsResponse.value
			Write-LogMessage -Type Debug -MSG "Found $($GetAccountsList.count) accounts so far..."
		}
		
		# Create a dynamic filter array
		$WhereArray = @()
		If(-not [string]::IsNullOrEmpty($sUserName)) { $WhereArray += '$_.userName -eq $sUserName' }
		If(-not [string]::IsNullOrEmpty($sAddress)) { $WhereArray += '$_.address -eq $sAddress' }
		If(-not [string]::IsNullOrEmpty($sPlatformID)) { $WhereArray += '$_.platformId -eq $sPlatformID' }
		If($FailedOnly -and $CPMDisabled) { $WhereArray += '($_.secretManagement.status -eq "failure" -or $_.secretManagement.status -eq "failed" -or $_.secretManagement.manualManagementReason -like "(CPM)*")' }
		elseIf($FailedOnly) { $WhereArray += '($_.secretManagement.status -eq "failure" -or $_.secretManagement.status -eq "failed")' }
		elseIf($CPMDisabled) { $WhereArray += '$_.secretManagement.manualManagementReason -like "(CPM)*"' }

		# Filter Accounts based on input properties
		$WhereFilter = [scriptblock]::Create( ($WhereArray -join " -and ") )
		$FilteredAccountsList = ( $GetAccountsList | Where-Object $WhereFilter )
	} catch {
		throw $(New-Object System.Exception ("Get-FilteredAccounts: Error Getting Accounts",$_.Exception))
	}
	
	return $FilteredAccountsList
}
#endregion

Write-LogMessage -Type Info -MSG "Starting script" -Header -LogFile $LOG_FILE_PATH
if($InDebug) { Write-LogMessage -Type Info -MSG "Running in Debug Mode" -LogFile $LOG_FILE_PATH }
if($InVerbose) { Write-LogMessage -Type Info -MSG "Running in Verbose Mode" -LogFile $LOG_FILE_PATH }
Write-LogMessage -Type Debug -MSG "Running PowerShell version $($PSVersionTable.PSVersion.Major) compatible of versions $($PSVersionTable.PSCompatibleVersions -join ", ")" -LogFile $LOG_FILE_PATH
# Verify the Powershell version is compatible
If (!($PSVersionTable.PSCompatibleVersions -join ", ") -like "*3*") {
	Write-LogMessage -Type Error -Msg "The Powershell version installed on this machine is not compatible with the required version for this script.`
	Installed PowerShell version $($PSVersionTable.PSVersion.Major) is compatible with versions $($PSVersionTable.PSCompatibleVersions -join ", ").`
	Please install at least PowerShell version 3."
	Write-LogMessage -Type Info -Msg "Script ended"
	return
}
# Check if Powershell is running in Constrained Language Mode
If($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage") {
	Write-LogMessage -Type Error -MSG "Powershell is currently running in $($ExecutionContext.SessionState.LanguageMode) mode which limits the use of some API methods used in this script.`
	PowerShell Constrained Language mode was designed to work with system-wide application control solutions such as CyberArk EPM or Device Guard User Mode Code Integrity (UMCI).`
	For more information: https://blogs.msdn.microsoft.com/powershell/2017/11/02/powershell-constrained-language-mode/"
	Write-LogMessage -Type Info -MSG "Script ended" -Footer -LogFile $LOG_FILE_PATH
	return
}
# Check that the PVWA URL is OK
If ($PVWAURL -ne "") {
	If ($PVWAURL.Substring($PVWAURL.Length-1) -eq "/") {
		$PVWAURL = $PVWAURL.Substring(0,$PVWAURL.Length-1)
	}
} else {
	Write-LogMessage -Type Error -MSG "PVWA URL can not be empty"
	return
}

# Get Credentials to Login
# ------------------------
$caption = "Bulk Account Actions"
$msg = "Enter your PAS User name and Password ($AuthType)"; 
$creds = $Host.UI.PromptForCredential($caption,$msg,"","")

try {
	$accountAction = ""
	Switch($AccountsAction) {
		"Verify" {
			Write-LogMessage -Type Info -MSG "Running Verify on all filtered accounts"
			$accountAction = $URL_AccountVerify
		}
		"Change" {
			Write-LogMessage -Type Info -MSG "Running Change on all filtered accounts"
			$accountAction = $URL_AccountChange
		}
		"Reconcile" {
			Write-LogMessage -Type Info -MSG "Running Reconcile on all filtered accounts"
			$accountAction = $URL_AccountReconcile
		}
	}
	# Get all Relevant Accounts
	$filteredAccounts = Get-FilteredAccounts -sSafeName $SafeName -sPlatformID $PlatformID -sUserName $UserName -sAddress $Address -sCustomKeywords $Custom -bFailedOnly $FailedOnly -VaultCredentials $creds
	Write-LogMessage -Type Info -MSG "Going over $($filteredAccounts.Count) filtered accounts"
	# Run Account Action on relevant Accounts
	ForEach ($account in $filteredAccounts) {
		Write-LogMessage -Type Debug -MSG "Submitting account `"$($account.Name)`" in safe `"$($account.safeName)`""
		try {
			Invoke-Rest -Uri ($accountAction -f $account.id) -Command POST -Body "" -Header (Get-LogonHeader $creds)
			Write-LogMessage -Type Debug -MSG "Submitted account `"$($account.Name)`" in safe `"$($account.safeName)`""
		} Catch {
			Write-LogMessage -Type Error -MSG "Error Submitting account `"$($account.Name)`" in safe `"$($account.safeName)`""
		}
	}
} catch {
	Write-LogMessage -Type Error -MSG "There was an Error running bulk account actions. Error: $(Collect-ExceptionMessage $_.Exception)"
}

# Logoff the session
# ------------------
Run-Logoff
Write-LogMessage -Type Info -MSG "Script ended" -Footer -LogFile $LOG_FILE_PATH
return
