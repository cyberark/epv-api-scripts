###########################################################################
#
# NAME: OPM Rule Onboarding Utility
#
# AUTHOR:  Jeff Rechten
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will import OPM rules from a CSV file using REST API
#
# SUPPORTED CYBERARK VERSIONS:
# CyberArk PVWA v10.4 and above
#
# UTILITY VERSION LIMITATIONS:
# - No validation checking on PlatformID
# - No validation checking on existing rules
# - No validation checking on command restrictions
# - Capability to add OPM rules only, no update OPM rule capability
#
###########################################################################
[CmdletBinding(DefaultParametersetName="Create")]
param
(
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,
	
	[Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark","ldap","radius")]
	[String]$AuthType="cyberark",
	
	[Parameter(Mandatory=$false,HelpMessage="Enter the RADIUS OTP")]
	[ValidateScript({$AuthType -eq "radius"})]
	[String]$OTP,
	
	[Parameter(Mandatory=$false,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true)]
	[ValidateScript( { Test-Path -Path $_ -PathType Leaf -IsValid})]
	[Alias("path")]
	[String]$CsvPath,
	
	[Parameter(Mandatory=$false,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true)]
	[ValidateSet("Comma","Tab")]
	[Alias("delim")]
	[String]$CsvDelimiter = "Comma",
	
	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory=$false)]
	[Switch]$DisableSSLVerify
)

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path

# Set Log file path
$LOG_FILE_PATH = "$ScriptLocation\OPM_Rule_Onboarding_Utility.log"

$InDebug = $PSBoundParameters.Debug.IsPresent
$InVerbose = $PSBoundParameters.Verbose.IsPresent

# Global URLS
# -----------
$URL_PVWABaseAPI = $PVWAURL+"/WebServices/PIMServices.svc"
$URL_PVWAAPI = $PVWAURL+"/api"
$URL_Authentication = $URL_PVWAAPI+"/auth"
$URL_Logon = $URL_Authentication+"/$AuthType/Logon"
$URL_Logoff = $URL_Authentication+"/Logoff"

# URL Methods
# -----------
$URL_PlatformCommands = $URL_PVWABaseAPI+"/Policy/{0}/PrivilegedCommands"


# Script Defaults
# ---------------
$g_CsvDefaultPath = $Env:CSIDL_DEFAULT_DOWNLOADS


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

Function Encode-URL($sText)
{
	if ($sText.Trim() -ne "")
	{
		Log-Msg -Type Debug -Msg "Returning URL Encode of $sText"
		return [URI]::EscapeDataString($sText)
	}
	else
	{
		return $sText
	}
}

Function Get-TrimmedString($sText)
{
	if($null -ne $sText)
	{
		return $sText.Trim()
	}
	# Else
	return $sText
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

Function OpenFile-Dialog($initialDirectory)
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter = "CSV (*.csv)| *.csv"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
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
			Log-Msg -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -TimeoutSec 36000"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -TimeoutSec 36000 -ErrorAction $ErrAction
		}
		else
		{
			Log-Msg -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body -TimeoutSec 36000"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body -TimeoutSec 36000 -ErrorAction $ErrAction
		}
	} catch [System.Net.WebException] {
		if($ErrAction -match ("\bContinue\b|\bInquire\b|\bStop\b|\bSuspend\b")){
			Log-Msg -Type Error -Msg "Error Message: $_"
			Log-Msg -Type Error -Msg "Exception Message: $($_.Exception.Message)"
			Log-Msg -Type Error -Msg "Status Code: $($_.Exception.Response.StatusCode.value__)"
			Log-Msg -Type Error -Msg "Status Description: $($_.Exception.Response.StatusDescription)"
		}
		$restResponse = $null
	} catch { 
		Throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'",$_.Exception))
	}
	Log-Msg -Type Verbose -Msg "Invoke-REST Response: $restResponse"
	return $restResponse
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
	write-Verbose $logonBody
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
    $logonHeader =  New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $logonHeader.Add("Authorization", $logonToken)
	
	return $logonHeader
}
#endregion

# Header
Log-Msg -Type Info -MSG "Welcome to OPM Rule Onboard Utility" -Header

# Check if Powershell is running in Constrained Language Mode
If($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage")
{
	Log-Msg -Type Error -MSG "Powershell is currently running in $($ExecutionContext.SessionState.LanguageMode) mode which limits the use of some API methods used in this script.`
	PowerShell Constrained Language mode was designed to work with system-wide application control solutions such as CyberArk EPM or Device Guard User Mode Code Integrity (UMCI).`
	For more information: https://blogs.msdn.microsoft.com/powershell/2017/11/02/powershell-constrained-language-mode/"
	Log-Msg -Type Info -MSG "Script ended" -Footer -LogFile $LOG_FILE_PATH
	return
}

# Check SSL verification
If($DisableSSLVerify)
{
	try{
		Write-Warning "It is not recommended to disable SSL verification." -WarningAction Inquire
		# Using Proxy Default credentials if the Server needs Proxy credentials
		[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
		# Using TLS 1.2 as security protocol verification
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
		# Disable SSL Verification
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
	} catch {
		Log-Msg -Type Error -MSG "Could not change SSL validation"
		Log-Msg -Type Error -MSG (Collect-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
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
		Log-Msg -Type Error -MSG (Collect-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
	}
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
		Log-Msg -Type Error -MSG (Collect-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
	}
	
}
else
{
	Log-Msg -Type Error -MSG "PVWA URL cannot be empty."
	exit
}

Log-Msg -Type Info -MSG "Getting PVWA Credentials to start Onboarding OPM Rules" -SubHeader


#region [Logon]
	# Get Credentials to Login
	# ------------------------
	$caption = "OPM Rule Onboarding Utility"
	$msg = "Enter your User name and Password"; 
	$creds = $Host.UI.PromptForCredential($caption,$msg,"","")
	if ($null -ne $creds)
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
		Log-Msg -Type Error -MSG "No credentials were entered." -Footer
		exit
	}
#endregion

#region [Read Accounts CSV file and Create Accounts]
	If([string]::IsNullOrEmpty($CsvPath))
	{
		$CsvPath = OpenFile-Dialog($g_CsvDefaultPath)
	}
	$delimiter = $(If ($CsvDelimiter -eq "Comma") { "," } else { "`t" } )
	$rulesCSV = Import-CSV $csvPath -Delimiter $delimiter
	$rowCount = $($rulesCSV.Safe.Count)
	$counter = 0
	$successCounter = 0
	Log-Msg -Type Info -MSG "Starting to Onboard $rowCount rules." -SubHeader
	ForEach ($rule in $rulesCSV)
	{
		if ($null -ne $rule)
		{
			try {
				# Check mandatory fields
				If([string]::IsNullOrEmpty($rule.PlatformId)) { throw "Missing mandatory field: Platform ID" }
				If([string]::IsNullOrEmpty($rule.Command)) { throw "Missing mandatory field: Command" }
				If([string]::IsNullOrEmpty($rule.UserName)) { throw "Missing mandatory field: UserName" }
				
				$rule.PlatformId = (Get-TrimmedString $rule.PlatformID)
				$objRule = "" | Select-Object "Command", "CommandGroup", "PermissionType", "Restrictions", "UserName"
				$objRule.Command = (Get-TrimmedString $rule.Command)
				$objRule.CommandGroup = (Get-TrimmedString $rule.CommandGroup)
				$objRule.PermissionType = (Get-TrimmedString $rule.PermissionType)
				$objRule.Restrictions = (Get-TrimmedString $rule.Restrictions)
				$objRule.UserName = (Get-TrimmedString $rule.UserName)
				
				if ([string]::IsNullOrEmpty($objRule.CommandGroup)) { 
					$objRule.CommandGroup = $false
				} elseif ($objRule.CommandGroup.ToLower() -eq "yes" -or $objRule.CommandGroup.ToLower() -eq "true") {
					$objRule.CommandGroup = $true
				} else {
					$objRule.CommandGroup = $false
				}
				
				if ([string]::IsNullOrEmpty($objRule.PermissionType)) { 
					$objRule.PermissionType = "Allow"
				} elseif ($objRule.permissionType.ToLower() -eq "allow" -or $objRule.permissionType.ToLower() -eq "deny") {
					$objRule.PermissionType = (Get-Culture).TextInfo.ToTitleCase($objRule.PermissionType)
				} else {
					throw "Invalid field: PermissionType"
				}
				
				if ($objRule.commandGroup -eq $false -and -Not $objRule.command.StartsWith("/") -and -Not $objRule.command -eq ".*") {
					Log-Msg -Type Warning -Msg "Rule Number $counter : It is a recommended security best practice to define commands with an absolute path. Please reconfigure rules like (cat /etc/passwd) to (/usr/bin/cat /etc/passwd)"
				}
				try {
					# Create the rule
					$restBody = $objRule | ConvertTo-Json -Depth 5
					$URL_PlatformCommands = $URL_PlatformCommands -f $rule.platformID
					Log-Msg -Type Debug -Msg $restBody
					$addRuleResult = $(Invoke-RestMethod -Method Put -Uri $URL_PlatformCommands -Headers $g_LogonHeader -Body $restBody -ContentType "application/json" -TimeoutSec 60)
					if($null -ne $addRuleResult) {
						Log-Msg -Type Info -Msg "Rule Onboarded Successfully"
						# Increment counter
						$successCounter++
						Log-Msg -Type Info -Msg "Row [$counter/$rowCount] Added successfully."  
					}
				} catch {
					if ($_.Exception.Response.StatusDescription.StartsWith("ITATS903E OlacObjectRuleAdd failed, because the same rule already exists")) {
						Log-Msg -Type Warning -Msg "Skipping rule $counter. Rule already exists."
					} else {
						Log-Msg -Type Error -Msg "There was an error onboarding $counter rule into the Password Vault."
						Log-Msg -Type Error -Msg "StatusCode: $($_.Exception.Response.StatusCode.value__) "
						Log-Msg -Type Error -Msg "StatusDescription: $($_.Exception.Response.StatusDescription)"
					}
				}
			} catch {
				$l_c = $_.InvocationInfo.ScriptLineNumber
				Log-Msg -Type Error -Msg "Line $l_c : Skipping onboarding rule into the Password Vault. Error: $(Collect-ExceptionMessage $_.Exception)"
			}
		}
		$counter++
	}	
#endregion

#region [Logoff]
	# Logoff the session
    # ------------------
    Write-Host "Logoff Session..."
    $logoffResponse = Invoke-Rest -Uri $URL_Logoff -Header $g_LogonHeader -Command "Post"
	# Footer
	Log-Msg -Type Info -MSG "Vaulted $successCounter out of $counter accounts successfully." -Footer
#endregion
