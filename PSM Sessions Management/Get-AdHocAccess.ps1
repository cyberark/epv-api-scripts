###########################################################################
#
# NAME: Just-In-Time Ad-Hoc PSM Connection
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script can be used to connect using Ad-Hoc PSM Connection 
# to a remote machine using Just-In-time action
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v10.6 and above
#
###########################################################################
param
(
	[Parameter(Mandatory=$true,HelpMessage="Enter the PVWA URL")]
	[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,

	# LDAP authentication is mandatory to use JIT Get Access connection
	[Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:LDAP)")]
	[ValidateSet("ldap","radius")]
	[String]$AuthType="ldap",
	
	# Remote Machine
	[Parameter(Mandatory=$true,HelpMessage="Enter a remote machine to connect to")]
	[Alias("Computer")]
	[String]$RemoteMachine,
	
	[Parameter(Mandatory=$true,HelpMessage="Enter a path to a file (.txt) containing list of machines to connect to")]
	[ValidateScript( { Test-Path -Path $_ -PathType Leaf -IsValid})]
	[Alias("path")]
	[String]$MachinesFilePath
)

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
# Get Debug / Verbose parameters for Script
$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent

# Script Version
$ScriptVersion = "1.1"

# ------ SET global parameters ------
# Set Log file path
$global:LOG_FILE_PATH = "$ScriptLocation\Get-AdHocAccess.log"
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
$URL_PSMAdHocConnect = $URL_PVWAAPI+"/Accounts/AdHocConnect"
$URL_GrantAccess = $URL_PVWAAPI+"/Accounts/{0}/GrantAdministrativeAccess"
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
		Write-LogMessage -Type Debug -Msg "Returning URL Encode of '$sText'"
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
# Name...........: Get-AccountByMachine
# Description....: Return an Account ID by machine name
# Parameters.....: Vault Credentials, Remote Machine Name
# Return Values..: Account ID
# =================================================================================================================================
Function Get-AccountByMachine
{
<# 
.SYNOPSIS 
	Get-AccountByMachine
.DESCRIPTION
	Return an Account ID by machine name
.PARAMETER VaultCredentials
	The Vault Credentials to be used
.PARAMETER RemoteMachine
	The Remote Machine Name you want to get the account by
#>
	param(
		[Parameter(Mandatory=$true)]
		[PSCredential]$VaultCredentials,
		[Parameter(Mandatory=$true)]
		[String]$RemoteMachine
	)

	try{
		Write-LogMessage -Type Debug -Msg "Finding Account for '$RemoteMachine'..."
		[string]$AccountsURLWithFilters = $URL_Accounts
		$AccountsURLWithFilters += "?search=$(Encode-URL $RemoteMachine)"
		$GetAccountsResponse = $(Invoke-Rest -Uri $AccountsURLWithFilters -Header $(Get-LogonHeader -Credentials $VaultCredentials) -Command "GET")
		return $GetAccountsResponse.value
	} catch {
		Throw $(New-Object System.Exception ("Get-AccountByMachine: Failed to find account for '$RemoteMachine'",$_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-AdminAccess
# Description....: Return true or false if the process of Granting Administrative Access on a machine worked
# Parameters.....: Vault Credentials, Account ID
# Return Values..: True / False
# =================================================================================================================================
Function Get-AdminAccess
{
<# 
.SYNOPSIS 
	Get-AdminAccess
.DESCRIPTION
	Return true or false if the process of Granting Administrative Access on a machine worked
.PARAMETER VaultCredentials
	The Vault Credentials to be used
.PARAMETER AccountID
	The Account ID you want to grant administrative access to
#>
	param(
		[Parameter(Mandatory=$true)]
		[PSCredential]$VaultCredentials,
		[Parameter(Mandatory=$true)]
		[String]$AccountID
	)
	
	try{
		Write-LogMessage -Type Debug -Msg "Granting Administrative Access..."
		$grantAccessBody = @{ accountId=$AccountID } | ConvertTo-Json
		$getAccessResult = $(Invoke-Rest -Uri ($URL_GrantAccess -f $AccountID) -Header $(Get-LogonHeader -Credentials $VaultCredentials) -Command "POST" -Body $grantAccessBody)
		return $true
	} catch {
		Throw $(New-Object System.Exception ("Get-AdminAccess: Failed to grant administrative access",$_.Exception))
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Init-AdHocConnection
# Description....: Returns RDP file content for Ad-Hoc PSM Connection
# Parameters.....: Vault Credentials, RemoteMachine
# Return Values..: Connection Type (RDP / HTML5)
# =================================================================================================================================
Function Init-AdHocConnection
{
<# 
.SYNOPSIS 
	Init-AdHocConnection
.DESCRIPTION
	Returns RDP file content for Ad-Hoc PSM Connection
.PARAMETER VaultCredentials
	The Vault Credentials to be used, Assumed also to be the credentials of the user to be used
.PARAMETER RemoteMachine
	The Remote Machine to connect to using PSM Ad-Hoc Connection
#>
	param(
		[Parameter(Mandatory=$true)]
		[PSCredential]$VaultCredentials,
		[Parameter(Mandatory=$true)]
		[String]$RemoteMachine,
		[Parameter(Mandatory=$true)]
		[String]$outFilePath
	)
	
	try{
		$retConnectionType = "RDP"
		Write-LogMessage -Type Debug -Msg "Initiating Ad-Hoc Connection Access for '$RemoteMachine'..."
		$_domainName = $_userName = ""
		if($VaultCredentials.username.Contains('\'))
		{
			$_domainName = $VaultCredentials.username.Split('\')[0]
			$_userName = $VaultCredentials.username.Split('\')[1]
		}
		else
		{
			$_userName = $VaultCredentials.username.Replace('\','');
		}
		$adHocAccessBody = @{
			  secret=$VaultCredentials.GetNetworkCredential().password;
			  address=$RemoteMachine;
			  platformId="PSMSecureConnect";
			  userName=$VaultCredentials.username.Replace('\','');
			  PSMConnectPrerequisites=@{
				Reason="Get-AdHocAccess script";
				ConnectionComponent="PSM-RDP";
				ConnectionType="RDPFile";
			  }
			  extraFields=@{
				Port=3389;
				AllowMappingLocalDrives="No";
				AllowConnectToConsole="No";
				LogonDomain=$_domainName;
			}
		} | ConvertTo-Json
		$adHocAccessResult = $(Invoke-Rest -Uri $URL_PSMAdHocConnect -Header $(Get-LogonHeader -Credentials $creds) -Command "POST" -Body $adHocAccessBody)
		If($adHocAccessResult -contains "PSMGWURL")
		{
			$retConnectionType = "HTML5"
			$adHocAccessResult | out-File $(Join-Path -Path $outFilePath -ChildPath "$RemoteMachine.txt")
		}
		Else
		{
			$retConnectionType = "RDP"
			$adHocAccessResult | out-File $(Join-Path -Path $outFilePath -ChildPath "$RemoteMachine.rdp")
		}
		
		return $retConnectionType
	} catch {
		Throw $(New-Object System.Exception ("Init-AdHocConnection: Failed to initiate Ad-Hoc Connection Access for '$RemoteMachine'",$_.Exception))
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
If (Test-CommandExists Invoke-RestMethod)
{
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
        Write-Host -ForegroundColor Red "PVWA URL can not be empty"
        return
    }
	
	$machinesList = @()
    # Get Credentials to Login
    # ------------------------
	If([string]::IsNullOrEmpty($MachinesFilePath))
	{
		$caption = "Ad-Hoc Access to machine $RemoteMachine"
		$machinesList += $RemoteMachine
	}
	else
	{
		$caption = "Ad-Hoc Access to list of machines"
		$machinesList += (Get-Content $MachinesFilePath)
	}
    $msg = "Enter your LDAP User name and Password"; 
    $creds = $Host.UI.PromptForCredential($caption,$msg,"","")

	ForEach ($machine in $machinesList)
	{
		try {
			# Find the relevant Account
			$accountsList = Get-AccountByMachine -VaultCredentials $creds -RemoteMachine $machine
			if($accountsList.Count -gt 1)
			{
				Write-LogMessages -Type Error -Msg "There are too many results for '$machine' ($($accountsList.Count) results)"
			}
			else
			{
				# Get Administrative Access for the Machine
				If (Get-AdminAccess -AccountID $accountsList.id -VaultCredentials $creds)
				{
					# Wait for 5 seconds
					Start-Sleep -seconds 5
					# Initiate PSM AD-Hoc Connection to the machine
					If((Init-AdHocConnection -VaultCredentials $creds -RemoteMachine $machine -outFilePath $ScriptLocation) -eq "RDP")
					{
						# Run the RDP File
						Mstsc $(Join-Path -Path $ScriptLocation -ChildPath "$machine.rdp")
					}
					Else
					{
						Write-LogMessages -Type Error -Msg "The current PSM server is configured to work with HTML5 Gateway which is not supported by this script"
					}
				}
				Else
				{
					Write-LogMessages -Type Error -Msg "Could not get Administrative access for '$machine'"
				}
				
			}
		} catch {
			Write-LogMessage -Type Error - MSG "There was an Error connecting to Remote Machine: $machine. Error: $(Collect-ExceptionMessage $_.Exception)"
		}
	}

    # Logoff the session
    # ------------------
    Write-Host "Logoff Session..."
    Run-Logoff
	Write-LogMessage -Type Info -MSG "Script ended" -Footer -LogFile $LOG_FILE_PATH
	return
}
else
{
    Write-Error "This script requires PowerShell version 3 or above"
}
