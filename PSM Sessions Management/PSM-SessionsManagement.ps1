###########################################################################
#
# NAME: PSM Session Management
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script can be used to list and drain a PSM server from active sessions
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v10.4 and above
#
###########################################################################
[CmdletBinding(DefaultParameterSetName="List")]
param
(
	[Parameter(Mandatory=$true,HelpMessage="Enter the PVWA URL")]
	[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,

	[Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark","ldap","radius")]
	[String]$AuthType="cyberark",
		
	# Use this switch to list all active sessions on a PSM server
	[Parameter(ParameterSetName='List',Mandatory=$false)][switch]$List,
	# Use this switch to Terminate all sessions from a PSM server
	[Parameter(ParameterSetName='Terminate',Mandatory=$false)][switch]$Terminate,
	
	# Additional optional parameters
	[Parameter(Mandatory=$false,HelpMessage="Enter a PSM server name to list")]
	[Alias("PSM")]
	[String]$PSMServerName,
	
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="Path to a CSV file to export data to")]
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
$global:LOG_FILE_PATH = "$ScriptLocation\PSM-SessionsManagement.log"
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
$URL_LiveSessions = $URL_PVWAAPI+"/livesessions"
$URL_TerminateSession = $URL_LiveSessions+"/{0}/Terminate"

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
		# Check the message type
		switch ($type)
		{
			"Info" { 
				Write-Host $MSG.ToString()
				$msgToWrite += "[INFO]`t$Msg"
				$msgToWrite | Out-File -Append -FilePath $LogFile
				break
			}
			"Warning" {
				Write-Host $MSG.ToString() -ForegroundColor DarkYellow
				$msgToWrite += "[WARNING]`t$Msg"
				$msgToWrite | Out-File -Append -FilePath $LogFile
				break
			}
			"Error" {
				Write-Host $MSG.ToString() -ForegroundColor Red
				$msgToWrite += "[ERROR]`t$Msg"
				$msgToWrite | Out-File -Append -FilePath $LogFile
				break
			}
			"Debug" { 
				if($InDebug -or $InVerbose)
				{
					Write-Debug $MSG
					$msgToWrite += "[DEBUG]`t$Msg"
					$msgToWrite | Out-File -Append -FilePath $LogFile
				}
				break
			}
			"Verbose" { 
				if($InVerbose)
				{
					Write-Verbose $MSG
					$msgToWrite += "[VERBOSE]`t$Msg"
					$msgToWrite | Out-File -Append -FilePath $LogFile
				}
				break
			}
		}
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
# Name...........: Get-PSMSessions
# Description....: Return a list of PSM Server sessions
# Parameters.....: Vault Credentials, PSM Server Name
# Return Values..: List of PSM Server Live Sessions
# =================================================================================================================================
Function Get-PSMSessions
{
<# 
.SYNOPSIS 
	Get-PSMSessions
.DESCRIPTION
	Return a list of PSM Server sessions
.PARAMETER VaultCredentials
	The Vault Credentials to be used
.PARAMETER ServerName
	The PSM Server Name you need to filter the sessions by
#>
	param(
		[Parameter(Mandatory=$true)]
		[PSCredential]$VaultCredentials,
		[Parameter(Mandatory=$true)]
		[String]$ServerName
	)

	try{
		Write-LogMessage -Type Debug -Msg "Retrieving sessions for PSM Server $ServerName..."
		$listSessionsResult = $(Invoke-Rest -Uri $URL_LiveSessions -Header $(Get-LogonHeader -Credentials $VaultCredentials) -Command "GET") 
		$output = @()
		ForEach($item in $listSessionsResult.LiveSessions)
		{
			If(($item.IsLive) -and ($item.RawProperties.ProviderID -like $ServerName.Insert(0,'*')))
			{
				$output += $item
			}
		}
		return $output
	} catch {
		Throw $(New-Object System.Exception ("Get-PSMSessions: Failed to list PSM Server $ServerName sessions",$_.Exception))
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
	
    # Get Credentials to Login
    # ------------------------
    $caption = "PSM Sessions Management"
    $msg = "Enter your CyberArk User name and Password"; 
    $creds = $Host.UI.PromptForCredential($caption,$msg,"","")

	try {
		$sessionsList = Get-PSMSessions -VaultCredentials $creds -ServerName $PSMServerName
	}
	catch {
		Write-LogMessage -Type Error -MSG "There was an error Listing PSM sessions. Error: $(Collect-ExceptionMessage $_.Exception)"
		Write-LogMessage -Type Info -MSG "Script ended" -Footer -LogFile $LOG_FILE_PATH
		return
	}

	switch($PsCmdlet.ParameterSetName)
	{
		"List"
		{
			try {
				# List all PSM server sessions
				Write-LogMessage -Type Info -Msg "Retrieving sessions for PSM Server $PSMServerName..."
				$output = @()
				Foreach ($item in $sessionsList)
				{
					$output += $item | Select-Object SessionID,User,FromIP,@{Name = 'SessionStart'; Expression = { Convert-Date $_.Start}},@{Name = 'SessionDuration'; Expression = { $_.Duration}},RemoteMachine,AccountUsername,AccountAddress,Protocol,Client
				}
				If([string]::IsNullOrEmpty($CSVPath))
				{	
					Write-LogMessage -Type Info -Msg $($output | out-String).Trim()
				}
				else
				{
					Write-LogMessage -Type Info -Msg "Exporting the output to $CSVPath"
					$output | Export-Csv -NoTypeInformation -UseCulture -Path $CSVPath -force
				}
				Write-LogMessage -Type Info -Msg "Finished retrieving sessions for PSM Server $PSMServerName"
			}
			catch {
				Write-LogMessage -Type Error - MSG "There was an Error when listing all sessions from $PSMServerName. Error: $(Collect-ExceptionMessage $_.Exception)"
			}
		}
		"Terminate"
		{
			try {
				ForEach ($item in $sessionsList)
				{
					If($item.CanTerminate -eq $true)
					{
						$msg = "Terminating {0} Session to {1} (more details: {2})" -f $item.User, $item.RemoteMachine, $("From IP: $($item.FromIP); Account User: $($item.AccountUsername); Account Address: $($tem.AccountAddress)")
						Write-LogMessage -Type Warning -Msg $msg
						$TerminateSessionResponse = Invoke-Rest -Command "POST" -Header $(Get-LogonHeader -Credentials $creds) -Body $( @{liveSessionId=$item.SessionID} | ConvertTo-Json )
					}
					else
					{
						Write-LogMessage -Type Warning -Msg $("Session cannot be terminated. More details: User: {0}; Account: {1}@{2}" -f $item.User, $item.AccountUsername, $item.AccountAddress)
					}
				}
			}
			catch {
				Write-LogMessage -Type Error - MSG "There was an Error Terminating one or more of the sessions. Error: $(Collect-ExceptionMessage $_.Exception)"
			}
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
