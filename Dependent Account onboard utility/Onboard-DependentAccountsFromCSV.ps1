###########################################################################
#
# NAME: Onboard Dependent Accounts from CSV
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will bulk onboard Dependent Accounts from a CSV file using REST API.
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v10.8 and above
#
#
###########################################################################
[CmdletBinding()]
param
(
	[Parameter(Mandatory=$true,HelpMessage="Enter the PVWA URL")]
	[Alias("url")]
	[String]$PVWAURL,
		
	[Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark","ldap","radius")]
	[String]$AuthType="cyberark",
	
	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory=$false)]
	[Switch]$DisableSSLVerify,
	
	[Parameter(Mandatory=$false,HelpMessage="Path to a CSV file to export data to")]
	[Alias("path")]
	[string]$CSVPath
)

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path

# Set Log file path
$LOG_FILE_PATH = "$ScriptLocation\DependentAccounts_Onboard_Utility.log"

$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent


# Global URLS
# -----------
$URL_PVWAAPI = $PVWAURL+"/api"
$URL_Authentication = $URL_PVWAAPI+"/auth"
$URL_Authentication = $URL_PVWAAPI+"/auth"
$URL_Logon = $URL_Authentication+"/$AuthType/Logon"
$URL_Logoff = $URL_Authentication+"/Logoff"

# URL Methods
# -----------
$URL_Accounts = $URL_PVWAAPI+"/Accounts"
$URL_AccountsDetails = $URL_PVWAAPI+"/Accounts/{0}"
$URL_DiscoveredAccounts = $URL_PVWAAPI+"/DiscoveredAccounts"
$URL_Platforms = $URL_PVWAAPI+"/Platforms/{0}"

# Script Defaults
# ---------------

# Initialize Script Variables
# ---------------------------
$g_LogonHeader = ""

#region Functions
Function Test-CommandExists
{
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {if(Get-Command $command){RETURN $true}}
    Catch {Write-Host "$command does not exist"; RETURN $false}
    Finally {$ErrorActionPreference=$oldPreference}
} #end function test-CommandExists

Function EncodeForURL($sText)
{
	if ($sText.Trim() -ne "")
	{
		Log-Msg -Type debug -Msg "Returning URL Encode of '$sText'"
		return [System.Web.HttpUtility]::UrlEncode($sText)
	}
	else
	{
		return ""
	}
}

Function ConvertTo-Date($epochdate)
{
	if (($epochdate).length -gt 10 ) {return (Get-Date -Date "01/01/1970").AddMilliseconds($epochdate)}
	else {return (Get-Date -Date "01/01/1970").AddSeconds($epochdate)}
}

Function ConvertTo-EPOCHDate($inputDate)
{
	return (New-TimeSpan -Start (Get-Date "01/01/1970") -End ($inputDate)).TotalSeconds
}


Function Log-MSG
{
<# 
.SYNOPSIS 
	Method to log a message on screen and in a log file
.DESCRIPTION
	Logging The input Message to the Screen and the Log File. 
	The Message Type is presented in colours on the screen based on the type
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
		[Parameter(Mandatory=$true)]
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
		[String]$type = "Info"
	)
	try{
		If ($Header) {
			"=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
			Write-Host "======================================="
		}
		ElseIf($SubHeader) { 
			"------------------------------------" | Out-File -Append -FilePath $LOG_FILE_PATH 
			Write-Host "------------------------------------"
		}
	
		$msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
		$writeToFile = $true
		# Replace empty message with 'N/A'
		if([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
		# Mask Passwords
		if($Msg -match '((?:"password"|"secret"|"NewCredentials")\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w!@#$%^&*()-\\\/]+))')
		{
			$Msg = $Msg.Replace($Matches[2],"****")
		}
		# Check the message type
		switch ($type)
		{
			"Info" { 
				Write-Host $MSG.ToString()
				$msgToWrite += "[INFO]`t$Msg"
			}
			"Warning" {
				Write-Host $MSG.ToString() -ForegroundColor DarkYellow
				$msgToWrite += "[WARNING]`t$Msg"
			}
			"Error" {
				Write-Host $MSG.ToString() -ForegroundColor Red
				$msgToWrite += "[ERROR]`t$Msg"
			}
			"Debug" { 
				if($InDebug)
				{
					Write-Debug $MSG
					$msgToWrite += "[DEBUG]`t$Msg"
				}
				else { $writeToFile = $False }
			}
			"Verbose" { 
				if($InVerbose)
				{
					Write-Verbose $MSG
					$msgToWrite += "[VERBOSE]`t$Msg"
				}
				else { $writeToFile = $False }
			}
		}
		
		If($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH }
		If ($Footer) { 
			"=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
			Write-Host "======================================="
		}
	} catch { Write-Error "Error in writing log: $($_.Exception.Message)" }
}

Function OpenFile-Dialog($initialDirectory)
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter = "CSV (*.csv)| *.csv"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
}

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
			Log-Msg -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -TimeoutSec 36000"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -TimeoutSec 36000
		}
		else
		{
			Log-Msg -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body -TimeoutSec 36000"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body -TimeoutSec 36000
		}
	} catch [System.Net.WebException] {
		Log-Msg -Type Error -Msg "Exception Message: $($_.Exception.Message)" -ErrorAction $ErrAction
		Log-Msg -Type Error -Msg "Status Code: $($_.Exception.Response.StatusCode.value__)"
		Log-Msg -Type Error -Msg "Status Description: $($_.Exception.Response.StatusDescription)" -ErrorAction $ErrAction
		$restResponse = $null
	} catch { 
		Throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'",$_.Exception))
	}
	Log-Msg -Type Verbose -Msg "Invoke-REST Response: $restResponse"
	return $restResponse
}

Function Add-SearchCriteria
{
	param ([string]$sURL, [string]$sSearch, [string]$sSortParam, [string]$sSafeName, [int]$iLimitPage, [int]$iOffsetPage)
	[string]$retURL = $sURL
	$retURL += "?"
	
	if($sSearch.Trim() -ne "")
	{
		$retURL += "search=$(EncodeForURL $sSearch)&"
	}
	if($sSafeName.Trim() -ne "")
	{
		$retURL += "filter=safename eq $(EncodeForURL $sSafeName)&"
	}
	if($sSortParam.Trim() -ne "")
	{
		$retURL += "sort=$(EncodeForURL $sSortParam)&"
	}
	if($iLimitPage -gt 0)
	{
		$retURL += "limit=$iLimitPage&"
	}
		
	if($retURL[-1] -eq '&') { $retURL = $retURL.substring(0,$retURL.length-1) }
	
	return $retURL
}

Function Find-MasterAccount
{
	param ($accountName, $accountAddress, $safeName)
	$result = $null
	try{
		$AccountsURLWithFilters = ""
		$Keywords = "$($account.userName) $($account.address)"
		$AccountsURLWithFilters = $(Add-SearchCriteria -sURL $URL_Accounts -sSearch $Keywords -sSafeName $safeName)
		Log-Msg -Type Debug -Msg "Accounts Filter: $AccountsURLWithFilters"
		$GetMasterAccountsResponse = Invoke-Rest -Command Get -Uri $AccountsURLWithFilters -Header $g_LogonHeader
		If (($null -eq $GetMasterAccountsResponse) -or ($GetMasterAccountsResponse.count -eq 0))
		{
			# No accounts found
			Log-Msg -Type Debug -MSG "Account $accountName does not exist"
			$result = $null
		}
		else
		{
			ForEach($item in $GetMasterAccountsResponse.Value)
			{
				if($item.userName -eq $accountName -and $item.address -eq $accountAddress)
				{
					$result = $item.id
					break
				}
			}
			# Account Exists
			Log-Msg -Type Info -MSG "Account $accountName exist"
		}
		return $result
	}
	catch
	{
		Log-Msg -Type Error -MSG $_.Exception -ErrorAction "SilentlyContinue"
	}
}

Function Get-LogonHeader
{
	param($Credentials, $RadiusOTP)
	# Create the POST Body for the Logon
    # ----------------------------------
    $logonBody = @{ username=$Credentials.username.Replace('\','');password=$Credentials.GetNetworkCredential().password } | ConvertTo-Json
	If(![string]::IsNullOrEmpty($RadiusOTP))
	{
		$logonBody.Password += ",$RadiusOTP"
	}
	try{
	    # Logon
	    $logonToken = Invoke-Rest -Command Post -Uri $URL_Logon -Body $logonBody
		# Clear logon body
		$logonBody = ""
	}
	catch
	{
		Write-Host -ForegroundColor Red $_.Exception.Response.StatusDescription
		$logonToken = ""
	}
    If ([string]::IsNullOrEmpty($logonToken))
    {
        Write-Host -ForegroundColor Red "Logon Token is Empty - Cannot login"
        exit
    }
	
    # Create a Logon Token Header (This will be used through out all the script)
    # ---------------------------
    $logonHeader = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $logonHeader.Add("Authorization", $logonToken)
	
	return $logonHeader
}

Function Add-AccountDependency
{
	param ($dependencyObjcet, $MasterID)
	
	try{
		$retResult = $false
		if($null -ne $MasterID)
		{
			$accountDetails = $(Invoke-Rest -Uri ($URL_AccountsDetails -f $MasterID) -Header $g_LogonHeader -Command "GET")
		}
		$addDiscoveredAccountBody = @{
			"userName"=$dependencyObjcet.userName; 
			"address"=$dependencyObjcet.address; 
			"domain"=$dependencyObjcet.domain;
			"discoveryDateTime"=ConvertTo-EPOCHDate (Get-Date);
		    "accountEnabled"=$true;
		    "platformType"=$dependencyObjcet.platformType;
		    "privileged"=$true;
			"Dependencies"=@(@{
			  "name"=$dependencyObjcet.dependencyName;
			  "address"=$dependencyObjcet.dependencyAddress;
			  "type"=$dependencyObjcet.dependencyType;
			  "taskFolder"=$dependencyObjcet.taskFolder;
			});
		}
		
		If($null -ne $accountDetails)
		{
			# Verify details and complete missing ones
			if($accountDetails.useName -ne $dependencyObjcet.userName)
			{
				$addDiscoveredAccountBody.userName = $accountDetails.useName
			}
			if($accountDetails.address -ne $dependencyObjcet.address)
			{
				$addDiscoveredAccountBody.address = $accountDetails.address
			}
			if($accountDetails.address -ne $dependencyObjcet.domain)
			{
				$addDiscoveredAccountBody.domain = $accountDetails.address
			}	
		}
		$addDiscoveredAccountResult = $(Invoke-Rest -Uri $URL_DiscoveredAccounts -Header $g_LogonHeader -Command "POST" -Body $($addDiscoveredAccountBody | ConvertTo-Json))
		If ($null -eq $addDiscoveredAccountResult)
		{
			# No accounts onboarded
			throw "There was an error onboarding dependency $($dependencyObjcet.dependencyName)."
		}
		else
		{
			# Check status
			Switch($addDiscoveredAccountResult.status)
			{
				"alreadyExists" {
					Log-Msg -Type Info -MSG "Master Account ($($dependencyObjcet.userName)) or Account dependency ($($dependencyObjcet.dependencyName)) already exists and cannot be onboarded"
					break
				}
				"addedAsPending" {
					Log-Msg -Type Info -MSG "Account dependency $($dependencyObjcet.dependencyName) was successfully onboarded to Pending Accounts"
					$retResult = $true
					break
				}
				"updatedPending" {
					Log-Msg -Type Info -MSG "Account dependency $($dependencyObjcet.dependencyName) was successfully updated in Pending Accounts"
					$retResult = $true
					break
				}
				Default {
					Log-Msg -Type Info -MSG "Account dependency $($dependencyObjcet.dependencyName) status is ($addDiscoveredAccountResult.status)"
					break
				}
			}
		}
	}
	catch
	{
		Log-Msg -Type Error -MSG $_.Exception.Message -ErrorAction "SilentlyContinue"
	}
	return $retResult
}

#endregion

# Check if Powershell is running in Constrained Language Mode
If($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage")
{
	Log-Msg -Type Error -MSG "Powershell is currently running in $($ExecutionContext.SessionState.LanguageMode) mode which limits the use of some API methods used in this script.`
	PowerShell Constrained Language mode was designed to work with system-wide application control solutions such as CyberArk EPM or Device Guard User Mode Code Integrity (UMCI).`
	For more information: https://blogs.msdn.microsoft.com/powershell/2017/11/02/powershell-constrained-language-mode/"
	Log-Msg -Type Info -MSG "Script ended" -Footer -LogFile $LOG_FILE_PATH
	return
}


# Check if to disable SSL verification
If($DisableSSLVerify)
{
	try{
		Write-Warning "It is not Recommended to disable SSL verification" -WarningAction Inquire
		# Using Proxy Default credentials if the Server needs Proxy credentials
		[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
		# Using TLS 1.2 as security protocol verification
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
		# Disable SSL Verification
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
	} catch {
		Log-Msg -Type Error -MSG "Could not change SSL validation"
		Log-Msg -Type Error -MSG $_.Exception -ErrorAction "SilentlyContinue"
		return
	}
}
Else
{
	try{
		Log-Msg -Type Debug -MSG "Setting script to use TLS 1.2"
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
	} catch {
		Log-Msg -Type Error -MSG "Could not change SSL settings to use TLS 1.2"
		Log-Msg -Type Error -MSG $_.Exception -ErrorAction "SilentlyContinue"
	}
}

If ((Test-CommandExists Invoke-RestMethod) -eq $false)
{
   Log-Msg -Type Error -MSG  "This script requires PowerShell version 3 or above"
   return
}	

# Check that the PVWA URL is OK
If (![string]::IsNullOrEmpty($PVWAURL))
{
	If ($PVWAURL.Substring($PVWAURL.Length-1) -eq "/")
	{
		$PVWAURL = $PVWAURL.Substring(0,$PVWAURL.Length-1)
	}
	
	try{
		# Validate PVWA URL is OK
		Log-Msg -Type Debug -MSG  "Trying to validate URL: $PVWAURL"
		Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $PVWAURL -Method 'Head' -TimeoutSec 30 | Out-Null
	} catch [System.Net.WebException] {
		If(![string]::IsNullOrEmpty($_.Exception.Response.StatusCode.Value__))
		{
			Log-Msg -Type Error -MSG $_.Exception.Response.StatusCode.Value__
		}
	}
	catch {		
		Log-Msg -Type Error -MSG "PVWA URL could not be validated"
		Log-Msg -Type Error -MSG $_.Exception -ErrorAction "SilentlyContinue"
	}
}
else
{
	Log-Msg -Type Error -MSG "PVWA URL can not be empty"
	exit
}

# Header
Log-Msg -Type Info -MSG "Welcome to Accounts Dependencies Onboard Utility" -Header
Log-Msg -Type Info -MSG "Getting PVWA Credentials to start Onboarding Dependencies" -SubHeader


#region [Logon]
	# Get Credentials to Login
	# ------------------------
	$caption = "Accounts Onboard Utility"
	$msg = "Enter your User name and Password"; 
	$creds = $Host.UI.PromptForCredential($caption,$msg,"","")
	if ($creds -ne $null)
	{
		if($AuthType -eq "radius" -and ![string]::IsNullOrEmpty($OTP))
		{
			$g_LogonHeader = $(Get-LogonHeader -Credentials $creds -RadiusOTP $OTP)
		}
		else
		{
			$g_LogonHeader = $(Get-LogonHeader -Credentials $creds)
		}
	}
	else { 
		Log-Msg -Type Error -MSG "No Credentials were entered" -Footer
		exit
	}
#endregion

#region [Read Accounts CSV file and Create Accounts]
	If([string]::IsNullOrEmpty($CsvPath))
	{
		$CsvPath = OpenFile-Dialog($g_CsvDefaultPath)
	}
	$delimiter = $((Get-Culture).TextInfo.ListSeparator)
	$accountsCSV = Import-CSV $csvPath -Delimiter $delimiter
	$rowCount = $accountsCSV.Count
	$counter = 0
	Log-Msg -Type Info -MSG "Starting to Onboard $rowCount accounts" -SubHeader
	# Read Account dependencies
	ForEach ($account in $accountsCSV)
	{
		if (![string]::IsNullOrEmpty($account))
		{
			# username,address,platformType,domain,dependencyName,dependencyAddress,dependencyType,taskFolder
			# Search for Master Account
			$foundMasterAccount = $null
			try {
				$foundMasterAccount = (Find-MasterAccount -accountName $account.userName -accountAddress $account.address).id
			} catch {
				Log-MSG -Type Error -Msg "Error searching for Master Account. Error: $(Join-Exception $_.Exception)"
			}
			# If($null -eq $foundMasterAccount)
			# {
				# Log-MSG -Type Warning -Msg "No Master Account found, onboarding to pending account"
				if(Add-AccountDependency -dependencyObjcet $account -MasterID $foundMasterAccount) { $counter++ }
			# }
			# else
			# {
				# Log-MSG -Type Info -Msg "Master Account found, Checking if we can onboard"
				# $MasterAccountDetails = Invoke-Rest -Command Get -Uri ($URL_AccountsDetails -f $foundMasterAccount) -Header $g_LogonHeader
				# $MasterAccountDetails
			# }
		}
	}

#endregion

#region [Logoff]
	# Logoff the session
    # ------------------
    Write-Host "Logoff Session..."
    Invoke-Rest -Uri $URL_Logoff -Header $g_LogonHeader -Command "Post"
	# Footer
	Log-Msg -Type Info -MSG "Vaulted ${counter} out of ${rowCount} accounts successfully." -Footer
#endregion
