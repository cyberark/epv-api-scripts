###########################################################################
#
# NAME: Get Platforms Report
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will Create a report of all active platforms and their connection components
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v11.6 and above
#
#
###########################################################################

param
(
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,
	
	[Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark","ldap","radius")]
	[String]$AuthType="cyberark",
	
	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory=$false)]
	[Switch]$DisableSSLVerify,
	
	# Use this switch to get an extended report
	[Parameter(Mandatory=$false)]
	[Switch]$ExtendedReport,
	
	[Parameter(Mandatory=$false,HelpMessage="Path to a CSV file to export data to")]
	[Alias("path")]
	[string]$CSVPath
)

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path

# Script Version
$ScriptVersion = "1.0"

# Set Log file path
$LOG_FILE_PATH = "$ScriptLocation\PlatformsReport.log"

$InDebug = $PSBoundParameters.Debug.IsPresent
$InVerbose = $PSBoundParameters.Verbose.IsPresent

# Global URLS
# -----------
$URL_PVWAAPI = $PVWAURL+"/api"
$URL_Authentication = $URL_PVWAAPI+"/auth"
$URL_Logon = $URL_Authentication+"/$AuthType/Logon"
$URL_Logoff = $URL_Authentication+"/Logoff"

# URL Methods
# -----------
$URL_Platforms = $URL_PVWAAPI+"/Platforms"
$URL_PlatformDetails = $URL_Platforms+"/{0}"
$URL_TargetPlatforms = $URL_Platforms+"/Targets"
$URL_TargetPlatformPSMConnectors = $URL_TargetPlatforms+"/{0}/PrivilegedSessionManagement"
$URL_PSMConnectors = $URL_PVWAAPI+"/PSM/Connectors"

# Initialize Script Variables
# ---------------------------
$global:g_LogonHeader = ""

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
    try {if(Get-Command $command){RETURN $true}}
    Catch {Write-Host "$command does not exist"; RETURN $false}
    Finally {$ErrorActionPreference=$oldPreference}
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
		Log-Msg -Type Debug -Msg "Returning URL Encode of $sText"
		return [System.Web.HttpUtility]::UrlEncode($sText)
	}
	else
	{
		return $sText
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-PlatformException
# Description....: Tests if a platform configuration is an exception and return the relevant value
# Parameters.....: Platform configuration
# Return Values..: Relevant Platform Value
# =================================================================================================================================
Function Test-PlatformException
{
<# 
.SYNOPSIS 
	Test-PlatformException -Config Platform.RequireDualControlPasswordAccessApproval
.DESCRIPTION
	Tests if a platform configuration is an exception and return the relevant value
.PARAMETER Config
	The configuration to test
#>
    Param ($Config)
	$retValue = ""
    If($Config.IsAnException)
	{
		$retValue += "*"
	}
	$retValue += $Config.IsActive
	
	return $retValue
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
			Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -TimeoutSec 2700"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -TimeoutSec 2700
		}
		else
		{
			Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body -TimeoutSec 2700"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body -TimeoutSec 2700
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
			Invoke-Rest -Command Post -Uri $URL_Logoff -Header $g_LogonHeader
			Set-Variable -Name g_LogonHeader -Value $null -Scope global
		}
	} catch {
		Throw $(New-Object System.Exception ("Run-Logoff: Failed to logoff session",$_.Exception))
	}
}
#endregion

#-----------------
Write-LogMessage -Type Info -MSG "Starting script (v$ScriptVersion)" -Header -LogFile $LOG_FILE_PATH
if($InDebug) { Write-LogMessage -Type Info -MSG "Running in Debug Mode" -LogFile $LOG_FILE_PATH }
if($InVerbose) { Write-LogMessage -Type Info -MSG "Running in Verbose Mode" -LogFile $LOG_FILE_PATH }
Write-LogMessage -Type Debug -MSG "Running PowerShell version $($PSVersionTable.PSVersion.Major) compatible of versions $($PSVersionTable.PSCompatibleVersions -join ", ")" -LogFile $LOG_FILE_PATH
If($PSVersionTable.PSVersion.Major -lt 3)
{
	Write-LogMessage -Type Error -Msg "This script requires PowerShell version 3 or above"
	return
}

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
$caption = "Platforms Report"
$msg = "Enter your PAS User name and Password ($AuthType)"; 
$creds = $Host.UI.PromptForCredential($caption,$msg,"","")


#region Get all active Platforms
try{
	Write-LogMessage -Type Info -Msg "Retrieving active Platform..."
	# Get the active Platforms
	$urlActivePlatforms = $URL_TargetPlatforms+"?active eq true"
	$activePlatforms = Invoke-Rest -Command Get -Uri $urlActivePlatforms -Header $(Get-LogonHeader -Credentials $creds)
	If($activePlatforms)
	{
		Write-LogMessage -Type Info -Msg "Found $($activePlatforms.Total) active Platforms"
		$reportPlatforms = @()
		Write-LogMessage -Type Debug -Msg "Getting Platfroms PSM Connectors information"
		ForEach($platform in $activePlatforms.Platforms)
		{
			$psmServerTargetInfo = Invoke-REST -Command Get -Uri ($URL_TargetPlatformPSMConnectors -f $platform.id) -Header (Get-LogonHeader -Credentials $creds)
			if($null -ne $platform.PrivilegedSessionManagement)
			{
				$platform.PrivilegedSessionManagement | Add-Member -NotePropertyName PSMConnectors -NotePropertyValue $psmServerTargetInfo.PSMConnectors
			}
			$reportPlatforms += $platform
		}
		
		Write-LogMessage -Type Info -Msg "Generating report..."
		
		$output = @()
		$outputFields = @(
			"id",`
			@{Name = 'PlatformName'; Expression = { $_.Name}},`
			"AllowedSafes",`
			@{Name = 'PeriodicVerify'; Expression = { $_.CredentialsManagementPolicy.Verification.PerformAutomatic}},`
			@{Name = 'VerifyEveryXDays'; Expression = {$_.CredentialsManagementPolicy.Verification.RequirePasswordEveryXDays}},`
			@{Name = 'PeriodicChange'; Expression = {$_.CredentialsManagementPolicy.Change.PerformAutomatic}},`
			@{Name = 'ChangeEveryXDays'; Expression = {$_.CredentialsManagementPolicy.Change.RequirePasswordEveryXDays}},`
			@{Name = 'PeriodicReconcile'; Expression = {$_.CredentialsManagementPolicy.Reconcile.PerformAutomatic}},`
			@{Name = 'ReconcileEveryXDays'; Expression = {$_.CredentialsManagementPolicy.Reconcile.RequirePasswordEveryXDays}},`
			@{Name = 'PSMConnectors'; Expression = { ($_.PrivilegedSessionManagement.PSMConnectors | Where-Object { $_.Enabled }).PSMConnectorID  -join ';' }}
		)
		If($ExtendedReport)
		{
			$outputFields += @(
				@{Name = 'RequireUsersToSpecifyReasonForAccess'; Expression = { (Test-PlatformException -Config $_.PrivilegedAccessWorkflows.RequireUsersToSpecifyReasonForAccess) }},`
				@{Name = 'EnforceOnetimePasswordAccess'; Expression = { (Test-PlatformException -Config $_.PrivilegedAccessWorkflows.EnforceOnetimePasswordAccess) }},`
				@{Name = 'EnforceCheckinCheckoutExclusiveAccess'; Expression = { (Test-PlatformException -Config $_.PrivilegedAccessWorkflows.EnforceCheckinCheckoutExclusiveAccess) }},`
				@{Name = 'RequireDualControlPasswordAccessApproval'; Expression = { (Test-PlatformException -Config $_.PrivilegedAccessWorkflows.RequireDualControlPasswordAccessApproval) }}
			)
		}
		
		$output = $reportPlatforms | Select-Object $outputFields
		
		If([string]::IsNullOrEmpty($CSVPath))
		{
			$output | Format-Table -Autosize
		}
		else
		{
			$output | Export-Csv -NoTypeInformation -UseCulture -Path $CSVPath -force
		}
	}
	Else
	{
		Throw "There was a problem getting Active Platforms"
	}
} catch {
	Write-LogMessage -Type Error -Msg "Error creating Platfomrs report. Error: $(Collect-ExceptionMessage $_.Exception)"
}
#endregion
# Logoff the session
Run-Logoff