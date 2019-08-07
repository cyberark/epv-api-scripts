###########################################################################
#
# NAME: Get Accounts Risks by Security Events
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will create a report for all accounts that 
# have a security event realted to them.
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v10.6 and above
#
###########################################################################
param
(
	[Parameter(Mandatory=$true,HelpMessage="Enter the PVWA URL")]
	#[ValidateScript({If($DisableSSLVerify) { Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30}})]
	[Alias("url")]
	[String]$PVWAURL,

	[Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark","ldap","radius")]
	[String]$AuthType="cyberark",
	
	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory=$false)]
	[Switch]$DisableSSLVerify,
	
	# Security Events Days filter
	[Parameter(Mandatory=$false,HelpMessage="Enter the number of days to filter the security events (default: 30 days)")]
	[Alias("Days")]
	[int]$EventsDaysFilter=30,
	
	[Parameter(Mandatory=$false,HelpMessage="Path to a CSV file to export data to")]
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
$global:LOG_FILE_PATH = "$ScriptLocation\Get-AccoutnsRiskReport.log"
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
$URL_SecurityEvents = $URL_PVWAAPI+"/pta/API/Events"
$URL_Accounts = $URL_PVWAAPI+"/Accounts"
$URL_Platforms = $URL_PVWAAPI+"/Platforms/{0}"

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
# Name...........: Encode-URL
# Description....: Encodes a text for HTTP URL
# Parameters.....: text to encode
# Return Values..: Encoded text for URL
# =================================================================================================================================
Function Encode-URL($sText)
{
	if ($sText.Trim() -ne "")
	{
		Write-LogMessage -Type Verbose -Msg "Returning URL Encode of '$sText'"
		return [System.Web.HttpUtility]::UrlEncode($sText)
	}
	else
	{
		return $sText
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: ConvertTo-EPOCHDate
# Description....: Converts a Date Time to EPOCH Date
# Parameters.....: Date time
# Return Values..: EPOCH date
# =================================================================================================================================
Function ConvertTo-EPOCHDate($inputDate)
{
<# 
.SYNOPSIS 
	ConvertTo-EPOCHDate
.DESCRIPTION
	Converts a Date Time to EPOCH Date
.PARAMETER inputDate
	The date time to oonvert to EPOCH
#>
	return (New-TimeSpan -Start (Get-Date "01/01/1970") -End ($inputDate)).TotalSeconds
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
		$logonHeader.Add("lastUpdatedEventDate",$(ConvertTo-EPOCHDate ((Get-Date).AddDays($EventsDaysFilter * -1))))
		
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
# Name...........: Get-AccountFromEvent
# Description....: Return an Account object from a Security Event
# Parameters.....: Vault Credentials, Security Event object
# Return Values..: Account ID
# =================================================================================================================================
Function Get-AccountFromEvent
{
<# 
.SYNOPSIS 
	Get-AccountFromEvent
.DESCRIPTION
	Return an Account object from a Security Event
.PARAMETER VaultCredentials
	The Vault Credentials to be used
.PARAMETER SecurityEvent
	The input Security Event object that contains the Account refrence
#>
	param(
		[Parameter(Mandatory=$true)]
		[PSCredential]$VaultCredentials,
		[Parameter(Mandatory=$true)]
		[PSObject]$SecurityEvent
	)

	try{
		Write-LogMessage -Type Verbose -Msg "Finding Account from Event..."
		If($SecurityEvent.Audits.count -gt 0)
		{
			$output = @()
			ForEach($item in $SecurityEvent.Audits)
			{
				If($null -ne $item.Account)
				{
					Write-LogMessage -Type Verbose -Msg "Found account data for $($item.Account.accountAsStr)"
					[string]$AccountsURLWithFilters = $URL_Accounts
					$targetUser = $(Encode-URL $item.Account.Account.mUser)
					if($null -ne $item.Account.Account.mTarget)
					{
						if($null -ne $item.Account.Account.mTarget.mOriginalAddress)
						{
							$targetMachine = $(Encode-URL $item.Account.Account.mTarget.mOriginalAddress)
						}
						else
						{
							$targetMachine = $(Encode-URL $item.Account.accountAsStr.Split('@')[1])
						}
					}
					$AccountsURLWithFilters += "?search=$targetUser $targetMachine"			
					$GetAccountsResponse = $(Invoke-Rest -Command "GET" -Uri $AccountsURLWithFilters -Header $(Get-LogonHeader -Credentials $VaultCredentials))
					Write-LogMessage -Type Verbose -Msg "Found $($GetAccountsResponse.count) accounts for $($item.Account.accountAsStr)"
					$output += $GetAccountsResponse.value
				}
				else
				{
					Write-LogMessage -Type Verbose -Msg "No account data found"
				}
			}
			
			# Return uniqe Accounts only
			return ($output | Get-Unique)
		}
		else
		{
			Write-LogMessage -Type Debug -Msg "No audit data found"
			return $null
		}
	} catch {
		Throw $(New-Object System.Exception ("Get-AccountFromEvent: Failed to find account from Event",$_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-LastChangeDate
# Description....: Return the last change or reconcile date of an account
# Parameters.....: Account
# Return Values..: the UNIX date time
# =================================================================================================================================
Function Get-LastChangeDate
{
<# 
.SYNOPSIS 
	Get-LastChangeDate -Account $accountData
.DESCRIPTION
	Return the last change or reconcile date of an account
.PARAMETER Account
	The Account to get the last change / reconcile date from
#>
	param(
		[Parameter(Mandatory=$true)]
		[PSObject]$Account
	)
	
	try{
		Write-LogMessage -Type Debug -Msg "Retrieving last Change date time for Account $("{0}@{1}" -f $Account.userName,$Account.Address)..."
		$lastChange = $Account.secretManagement.lastModifiedTime
		$lastReconcile = $Account.secretManagement.lastReconciledTime
		If(lastChange -gt $lastReconcile)
		{
			return $lastChange
		}
		Else
		{
			return $lastReconcile
		}		
	} catch {
		Throw $(New-Object System.Exception ("Get-LastChangeDate: Failed to get the last Change Date of the account",$_.Exception))
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
$caption = "Accounts Risk Report"
$msg = "Enter your PAS User name and Password"; 
$creds = $Host.UI.PromptForCredential($caption,$msg,"","")

try {
	# Get all Security Events
	Write-LogMessage -Type Info -MSG "Getting all Security Events in the last $EventsDaysFilter days"
	try{
		$GetEventsResponse = Invoke-Rest -Command Get -Uri $URL_SecurityEvents -Header $(Get-LogonHeader -Credentials $creds)
	} catch {
		Write-LogMessage -Type Error -MSG "There was an error Listing Security Events. Error: $(Collect-ExceptionMessage $_.Exception)"
		Write-LogMessage -Type Info -MSG "Script ended" -Footer -LogFile $LOG_FILE_PATH
		return
	}
	$AccountRiskReport = New-Object "System.Collections.Generic.Dictionary[[String],[PSObject]]"
	# Find relevant Accounts
	$accountEvent = @()
	Write-LogMessage -Type Info -MSG "Finding Account information from $($GetEventsResponse.count) events"
	Foreach ($event in $GetEventsResponse)
	{
		try{
			$accountEvent += Get-AccountFromEvent -VaultCredentials $creds -SecurityEvent $event
		} catch {
			Write-LogMessage -Type Error -MSG "There was an Error getting event data for account. Error: $(Collect-ExceptionMessage $_.Exception)"
		}
	}
	Write-LogMessage -Type Info -MSG "Retrieving Account information and calculating Risks"
	Foreach($Account in $accountEvent)
	{
		try{
			Write-LogMessage -Type Debug -MSG $("Retrieving Account information and calculating Risk for {0}@{1}" -f $Account.userName,$Account.Address)
			# Get the Platform Name
			$platformName = Invoke-Rest -Command Get -Uri $($URL_Platforms -f $Account.platformId) -Header $(Get-LogonHeader -Credentials $creds)
			$output = $Account | Select-Object @{Name = 'UserName'; Expression = { $_.userName}}, @{Name = 'Address'; Expression = { $_.address}}, @{Name = 'SafeName'; Expression = { $_.safeName}}, @{Name = 'Platform'; Expression = { $platformName.Details.PolicyName}}, @{Name = 'Risk'; Expression = { $event.score }}, 'NumberOfEvents', @{Name = 'AccountCreateDate'; Expression = { Convert-Date $_.createdTime}}, @{Name = 'LastAccountChangeDate'; Expression = { Convert-Date $(Get-LastChangeDate -Account $Account) }}
			$accountName = $("{0}@{1}" -f $Account.userName,$Account.Address)
			if (!$AccountRiskReport.ContainsKey($accountName))
			{
				Write-LogMessage -Type Verbose -MSG "Adding Account to output report"
				$output.NumberOfEvents = 1
				$AccountRiskReport.Add($("{0}@{1}" -f $Account.userName,$Account.Address),$output)
			}
			else
			{
				Write-LogMessage -Type Verbose -MSG "Assigning highest Account risk score"
				if ($output.Risk -gt $AccountRiskReport[$accountName].Risk)
				{
					$AccountRiskReport[$accountName].Risk = $output.Risk
				}
				$AccountRiskReport[$accountName].NumberOfEvents++
			}
		} catch {
			Write-LogMessage -Type Error -MSG "There was an Error getting event data. Error: $(Collect-ExceptionMessage $_.Exception)"
		}
	}
	# Report on all Accounts Risks
	Write-LogMessage -Type Info -MSG "Generating report"
	If([string]::IsNullOrEmpty($CSVPath))
	{
		$AccountRiskReport.Values | Select-Object UserName, Address, SafeName, Risk, @{Name = 'NumEvents'; Expression = { $_.NumberOfEvents}}, @{Name = 'Create'; Expression = { $_.AccountCreateDate}}, @{Name = 'Change'; Expression = { $_.LastAccountChangeDate}} | FT -Autosize
	}
	else
	{
		$AccountRiskReport.Values | Export-Csv -NoTypeInformation -UseCulture -Path $CSVPath -force
	}	
} catch {
	Write-LogMessage -Type Error - MSG "There was an Error creating Account Risk report. Error: $(Collect-ExceptionMessage $_.Exception)"
}

# Logoff the session
# ------------------
Run-Logoff
Write-LogMessage -Type Info -MSG "Script ended" -Footer -LogFile $LOG_FILE_PATH
return
