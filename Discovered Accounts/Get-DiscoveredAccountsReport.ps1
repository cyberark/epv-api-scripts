###########################################################################
#
# NAME: Get Discovered Account Report
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will create a report for all Discovered accounts according to filters (optional).
# Or get all account details for a specific account (by ID)
#
# Filter Criteria available:
# --------------------------
# Platform Type - Filter by platform types (Windows Server Local, Windows Desktop Local, Windows Domain, Unix, Unix SSH Key, AWS, AWS Access Keys)
# Privileged account - Filter only Discovered accounts that are Privileged, or only those that are not privileged
# Enabled account - Filter only enabled accounts, or only those that are not disabled
# Search - Filter by keywords (by default with OR between them)
# Search Type - the type of search to perform (contains (default) or startswith)
# Sort by - Sort by property
# Limit - Limits the number of returned accounts
# Auto Next Page - In case the limit is small or the returned number of accounts is greater than the limit, this will return all accounts from all pages
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v11.6 and above
#
###########################################################################
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
	
	# Use this switch to list accounts
	[Parameter(ParameterSetName='List',Mandatory=$true)][switch]$List,
	# Use this switch to list accounts
	[Parameter(ParameterSetName='Details',Mandatory=$true)][switch]$Details,
	# Use this switch to see the account in a Report form
	[Parameter(ParameterSetName='List',Mandatory=$false)]
	[Parameter(ParameterSetName='Details')]
	[switch]$Report,
	
	# List accounts filters
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="Enter a the platform type to filter by (Windows Server Local, Windows Desktop Local, Windows Domain, Unix, Unix SSH Key, AWS, AWS Access Keys)")]
	[ValidateSet("Windows Server Local", "Windows Desktop Local", "Windows Domain", "Unix", "Unix SSH Key", "AWS", "AWS Access Keys")]
	[Alias("type")]
	[String]$PlatformType,
	
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="Choose if you want to filter only privileged accounts")]
	[Alias("privileged")]
	[switch]$OnlyPrivilegedAccounts,
	
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="Choose if you want to filter only non-privileged accounts")]
	[Alias("nonprivileged")]
	[switch]$OnlyNonPrivilegedAccounts,
	
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="Choose if you want to filter only enabled accounts")]
	[Alias("enabled")]
	[switch]$OnlyEnabledAccounts,
	
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="Choose if you want to filter only disabled accounts")]
	[Alias("disabled")]
	[switch]$OnlyDisabledAccounts,
	
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="Enter filter Keywords. List of keywords are separated with space to search in accounts")]
	[Alias("search")]
	[String]$SearchKeywords,
	
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="Choose what type of search you would like to perform (contains, startswith). Default Contains.")]
	[ValidateSet("Contains","StartWith")]
	[String]$SearchType = "Contains",
	
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="properties by which to sort returned accounts, followed by asc (default) or desc to control sort direction. Multiple sorts are comma-separated. To sort on members of object properties. Maximum number of properties is 3")]
	[String]$SortBy,
	
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="Maximum number of returned accounts. If not specified, the default value is 50. The maximum number that can be specified is 1000")]
	[int]$Limit = 50,
	
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="If used, the next page is automatically returned")]
	[switch]$AutoNextPage,
	
	[Parameter(ParameterSetName='Details',Mandatory=$true,HelpMessage="The required Discovered Account ID")]
	[Alias("id")]
	[string]$DiscoveredAccountID,
	
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="Path to a CSV file to export data to")]
	[Parameter(ParameterSetName='Details',Mandatory=$false,HelpMessage="Path to a CSV file to export data to")]
	[Alias("path")]
	[string]$CSVPath
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
$global:LOG_FILE_PATH = "$ScriptLocation\DiscoveredAccountsReport.log"
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
$URL_DiscoveredAccounts = $URL_PVWAAPI+"/DiscoveredAccounts"
$URL_DiscoveredAccountDetails = $URL_PVWAAPI+"/DiscoveredAccounts/{0}"

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
		if($Msg -match '((?:"password"|"secret"|"NewCredentials")\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w!@#$%^&*()-\\\/]+))')
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
# Name...........: Convert-Date
# Description....: Return a Date Time from EPOCH Date
# Parameters.....: EPOCH date
# Return Values..: Date time
# =================================================================================================================================
Function Convert-Date($epochdate)
{
<# 
.SYNOPSIS 
	Convert-Date
.DESCRIPTION
	Return a Date Time from EPOCH Date
.PARAMETER epochdate
	The EPOCH date to oonvert
#>
	if (($epochdate).length -gt 10 ) {return (Get-Date -Date "01/01/1970").AddMilliseconds($epochdate)}
	else {return (Get-Date -Date "01/01/1970").AddSeconds($epochdate)}
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
		If($null -ne $g_LogonHeader)
		{
			Write-LogMessage -Type Info -Msg "Logoff Session..."
			Invoke-RestMethod -Method Post -Uri $URL_Logoff -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 3600000 | out-null
			Set-Variable -Name g_LogonHeader -Value $null -Scope global
		}
	} catch {
		Throw $(New-Object System.Exception ("Run-Logoff: Failed to logoff session",$_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-FilterParameters
# Description....: Returns the filter parameters for the required URL
# Parameters.....: URL, Platform Type, Privileged Account, Search keywords, Search Type
# Return Values..: None
# =================================================================================================================================
Function Get-FilterParameters
{
<# 
.SYNOPSIS 
	Get-FilterParameters
.DESCRIPTION
	Returns the filter parameters for the required URL
#>
	param (
		[Parameter(Mandatory=$true)]
		[string]$sURL, 
		[Parameter(Mandatory=$false)]
		[string]$sPlatformType,
		[Parameter(Mandatory=$false)]
		[bool]$bPrivileged,
		[Parameter(Mandatory=$false)]
		[bool]$bNonPrivileged,
		[Parameter(Mandatory=$false)]
		[bool]$bAccountEnabled,
		[Parameter(Mandatory=$false)]
		[bool]$bAccountDisabled,
		[Parameter(Mandatory=$false)]
		[string]$sSearch,
		[Parameter(Mandatory=$false)]
		[string]$sSearchType, 
		[Parameter(Mandatory=$false)]
		[int]$iLimitPage, 
		[Parameter(Mandatory=$false)]
		[int]$iOffsetPage
	)
	[string]$retURL = $sURL
	$retURL += "?"
	$filters = @()
	
	if(![string]::IsNullOrEmpty($sSearch))
	{
		$retURL += "search=$(Encode-URL $sSearch)&"
	}
	if(![string]::IsNullOrEmpty($sSearchType))
	{
		$retURL += "searchType=$sSearchType&"
	}
	if(![string]::IsNullOrEmpty($sPlatformType))
	{
		$filters += "platformType eq $(Encode-URL $sPlatformType)"
	}
	if(!($bPrivileged -and $bNonPrivileged))
	{
		# Filter only if the user chose privileged or non-privileged only (ignore if both)
		if($bPrivileged)
		{
			$filters += "privileged eq true"
		}
		if($bNonPrivileged)
		{
			$filters += "privileged eq false"
		}
	}
	if(!($bAccountEnabled -and $bAccountDisabled))
	{
		# Filter only if the user chose enabled or disabled accounts only (ignore if both)
		if($bAccountEnabled)
		{
			$filters += "accountEnabled eq true"
		}
		if($bAccountDisabled)
		{
			$filters += "accountEnabled eq false"
		}
	}
	if(![string]::IsNullOrEmpty($filters))
	{
		$retURL += "filter="+($filters -join " AND ")+"&"
	}
	if(![string]::IsNullOrEmpty($sSortParam))
	{
		$retURL += "sort=$(Encode-URL $sSortParam)&"
	}
	if($iLimitPage -gt 0)
	{
		$retURL += "limit=$iLimitPage&"
	}
		
	if($retURL[-1] -eq '&') { $retURL = $retURL.substring(0,$retURL.length-1) }
	Write-LogMessage -Type Verbose -Msg "Filtered URL: $retURL"
	
	return $retURL
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
$caption = "Discovered Accounts Report"
$msg = "Enter your PAS User name and Password ($AuthType)"; 
$creds = $Host.UI.PromptForCredential($caption,$msg,"","")

try {
	$response = ""
	switch($PsCmdlet.ParameterSetName)
	{
		"List"
		{
			# Get Discovered Accounts
			Write-LogMessage -Type Info -MSG "Creating a list of Discovered Accounts based on requested filters"
			try{
				$filterParameters = @{
					sURL=$URL_DiscoveredAccounts;
					sPlatformType=$PlatformType;
					bPrivileged=$OnlyPrivilegedAccounts;
					bNonPrivileged=$OnlyNonPrivilegedAccounts;
					bAccountEnabled=$OnlyEnabledAccounts;
					bAccountDisabled=$OnlyDisabledAccounts;
					sSearch=$SearchKeywords;
					sSearchType=$SearchType;
					iLimitPage=$Limit;
				}
				$urlFilteredAccounts = Get-FilterParameters @filterParameters
			} catch {
				Write-LogMessage -Type Error -MSG "There was an Error creating the filter URL. Error: $(Collect-ExceptionMessage $_.Exception)"
			}
			try{
				$GetDiscoveredAccountsResponse = Invoke-Rest -Command Get -Uri $urlFilteredAccounts -Header $(Get-LogonHeader -Credentials $creds)
			} catch {
				Write-LogMessage -Type Error -MSG "There was an Error getting filtered Discovered Accounts. Error: $(Collect-ExceptionMessage $_.Exception)"
			}
						
			If($AutoNextPage)
			{
				$GetDiscoveredAccountsList = @()
				$GetDiscoveredAccountsList += $GetDiscoveredAccountsResponse.value
				Write-LogMessage -Type Debug -MSG "$($GetDiscoveredAccountsList.count) Discovered accounts so far..."
				$nextLink =  $GetAccountsResponse.nextLink
				Write-LogMessage -Type Debug -MSG "Getting next link: $nextLink"
				
				While ($nextLink -ne "" -and $null -ne $nextLink)
				{
					$GetAccountsResponse = Invoke-Rest -Command Get -Uri $("$PVWAURL/$nextLink") -Header $(Get-LogonHeader -Credentials $creds)
					$nextLink = $GetAccountsResponse.nextLink
					Write-LogMessage -Type Debug -MSG "Getting next link: $nextLink"
					$GetDiscoveredAccountsList += $GetAccountsResponse.value
					Write-LogMessage -Type Debug -MSG "$($GetDiscoveredAccountsList.count) Discovered accounts so far..."
				}
				Write-LogMessage -Type Info -MSG "Showing $($GetDiscoveredAccountsList.count) accounts"
				$response = $GetDiscoveredAccountsList
			}
			else 
			{
				Write-LogMessage -Type Info -MSG "Showing up to $Limit Discovered Accounts" 
				$response = $GetDiscoveredAccountsResponse.value
			}
			
			If(![string]::IsNullOrEmpty($SortBy))
			{
				# Sort the list
				$sortDirection = $(If($SortBy.Contains(" dsc")) { $SortBy = $SortBy.Replace(" dsc","").Trim(); $true } else { $SortBy = $SortBy.Replace(" asc","").Trim(); $false })
				$response = $response | Sort-Object -Property $SortBy -Descending:$sortDirection
			}
		}
		"Details"
		{
			if($DiscoveredAccountID -ne "")
			{
				$GetDiscoveredAccountDetailsResponse = Invoke-Rest -Command Get -Uri $($URL_DiscoveredAccountDetails -f $DiscoveredAccountID) -Header $(Get-LogonHeader -Credentials $creds)
				$response = $GetDiscoveredAccountDetailsResponse
			}
		}
	}
	
	If($Report)
	{
		Write-LogMessage -Type Info -MSG "Generating report"
		$output = @()
		$output = $response | Select-Object id,@{Name = 'UserName'; Expression = { $_.userName}}, @{Name = 'Address'; Expression = { $_.address}}, @{Name = 'AccountEnabled'; Expression = { $_.accountEnabled}}, @{Name = 'Platform'; Expression = { $_.platformType }}, @{Name = 'Privileged'; Expression = { $_.privileged }}, @{Name = 'Dependencies'; Expression = { $_.numberOfDependencies }}, @{Name = 'LastLogonDate'; Expression = { Convert-Date $_.lastLogonDateTime}}
		
		If([string]::IsNullOrEmpty($CSVPath))
		{
			$output | Format-Table -Autosize
		}
		else
		{
			$output | Export-Csv -NoTypeInformation -UseCulture -Path $CSVPath -force
		}
	}
	else
	{
		$response
	}
} catch {
	Write-LogMessage -Type Error - MSG "There was an Error creating the Discovered Accounts report. Error: $(Collect-ExceptionMessage $_.Exception)"
}

# Logoff the session
# ------------------
Run-Logoff
Write-LogMessage -Type Info -MSG "Script ended" -Footer -LogFile $LOG_FILE_PATH
return
