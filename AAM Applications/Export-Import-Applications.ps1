###########################################################################
#
# NAME: Export / Import Applications
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will Export or Import all AAM applications using REST API
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v9.10 and above
#
###########################################################################
[CmdletBinding(DefaultParameterSetName="Export")]
param
(
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
    [Alias("url")]
    [ValidateNotNullOrEmpty()]
	[String]$PVWAURL,

	[Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark","ldap","radius")]
    [String]$AuthType="cyberark",

    # Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory=$false)]
	[Switch]$DisableSSLVerify,
	
	# Use this switch to Import all applications
	[Parameter(ParameterSetName='Import',Mandatory=$true)][switch]$Import,
	# Use this switch to Export all applications
	[Parameter(ParameterSetName='Export',Mandatory=$true)][switch]$Export,
	
	[Parameter(ParameterSetName='Export',Mandatory=$false,HelpMessage="Enter the application ID to export")]
	[Alias("id")]
	[string]$AppID,
	
	[Parameter(ParameterSetName='Import',Mandatory=$true,HelpMessage="Enter the CSV path for import")]
	[Parameter(ParameterSetName='Export',Mandatory=$true,HelpMessage="Enter the CSV path to export")]
	[Alias("path")]
	[string]$CSVPath,

	[Parameter(Mandatory = $false, HelpMessage = "Vault Stored Credentials")]
	[PSCredential]$PVWACredentials,

  [Parameter(Mandatory = $false)]
	[Switch]$concurrentSession,

	# Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off
	[Parameter(Mandatory = $false)]
	$logonToken
)

# Get Script Location 
$ScriptFullPath = $MyInvocation.MyCommand.Path
$ScriptLocation = Split-Path -Parent $ScriptFullPath
$ScriptParameters = @()
$PSBoundParameters.GetEnumerator() | ForEach-Object { $ScriptParameters += ("-{0} '{1}'" -f $_.Key, $_.Value) }
$global:g_ScriptCommand = "{0} {1}" -f $ScriptFullPath, $($ScriptParameters -join ' ')

# Script Version
$ScriptVersion = "1.0"

# Set Log file path
$LOG_FILE_PATH = "$ScriptLocation\Applications.log"

$InDebug = $PSBoundParameters.Debug.IsPresent
$InVerbose = $PSBoundParameters.Verbose.IsPresent

# Global URLS
# -----------
$URL_PVWAWebServices = $PVWAURL+"/WebServices"
$URL_PVWABaseAPI = $URL_PVWAWebServices+"/PIMServices.svc"
$URL_PVWAAPI = $PVWAURL + "/api"
$URL_Authentication = $URL_PVWAAPI + "/auth"
$URL_Logon = $URL_Authentication + "/$AuthType/Logon"
$URL_Logoff = $URL_Authentication + "/Logoff"

# URL Methods
# -----------
$URL_Applications = $URL_PVWABaseAPI+"/Applications"
$URL_SpecificApplication = $URL_Applications+"/{0}"
$URL_ApplicationAuthMethod = $URL_SpecificApplication+"/Authentications"

# Initialize Script Variables
# ---------------------------
$global:g_LogonHeader = $null

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
# Name...........: TryConvertTo-Bool
# Description....: Converts text to Bool if it is Bool, if not returns the text as is
# Parameters.....: Text
# Return Values..: Boolean value of the text (if a boolean), the input text if not
# =================================================================================================================================
Function TryConvertTo-Bool
{
<# 
.SYNOPSIS 
	Converts text to Bool
.DESCRIPTION
	Converts text to Bool if it is Bool, if not returns the text as is
.PARAMETER txt
	The text to convert to bool (True / False)
#>
	param (
		[string]$txt
	)
	$retBool = $false
	$changed = $false
	if($txt -match "^y$|^yes$") {
        $retBool = $true 
        $changed = $true
    }
	elseif ($txt -match "^n$|^no$") { 
        $retBool = $false 
        $changed = $true
    }
	else {
        $changed = [bool]::TryParse($txt, [ref]$retBool)
    }

    if($changed)
    {
        return $retBool
    }
    else {
        return $txt
    }
}
    
# @FUNCTION@ ======================================================================================================================
# Name...........: Convert-ObjectToString
# Description....: Converts an object to a string
# Parameters.....: Object
# Return Values..: String of the object
# =================================================================================================================================
Function Convert-ObjectToString
{
    param(
        [PSCustomObject]$Object
    )
    $retString = [string]::Empty
    If($null -ne $Object)
    {
		$retString += "{"
		$arrItems = @()
		$arrItems += $Object.PSObject.Properties | ForEach-Object { "{0}={1}" -f $_.Name,$_.Value }
        $retString += $arrItems -join ','
        $retString += "}"
    }

    return $retString
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Convert-StringToObject
# Description....: Converts a string to an object
# Parameters.....: String
# Return Values..: Object
# =================================================================================================================================
Function Convert-StringToObject
{
    param(
        [string]$String
    )
    $retObject = New-Object PSCustomObject
    If(![string]::IsNullOrEmpty($String))
    {
        $escapedString = $String.Replace('{',"").Replace('}',"")
        ForEach($item in $escapedString.Split(','))
        {
			# Skip authID parameter
            $KeyValue = $item.Split('=')
			If($KeyValue[0].Trim() -ne "authID"){
				# Skip empty values
				If(![string]::IsNullOrEmpty($KeyValue[1]))
				{
					$retObject | Add-Member -NotePropertyName $KeyValue[0].Trim() -NotePropertyValue $(TryConvertTo-Bool -txt $KeyValue[1].Trim())
				}
			}
        }
	}
	return $retObject
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-TrimmedString
# Description....: Returns the trimmed text from a string
# Parameters.....: Text
# Return Values..: Trimmed text
# =================================================================================================================================
Function Get-TrimmedString
{
<# 
.SYNOPSIS 
	Returns the trimmed text from a string
.DESCRIPTION
	Returns the trimmed text from a string
.PARAMETER txt
	The text to handle
#>
	param(
		[string]$sText
	)

	if ([string]::IsNullOrEmpty($sText)) {
		return $null
	}
	else
	{
		return $sText.Trim()
	}
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
		$restResponse = $null
        if($ErrAction -match ("\bContinue\b|\bInquire\b|\bStop\b|\bSuspend\b")){
			Write-LogMessage -Type Error -Msg "Error Message: $_"
			Write-LogMessage -Type Error -Msg "Exception Message: $($_.Exception.Message)"
			Write-LogMessage -Type Error -Msg "Status Code: $($_.Exception.Response.StatusCode.value__)"
			Write-LogMessage -Type Error -Msg "Status Description: $($_.Exception.Response.StatusDescription)"
        }
        else {
            Throw $_.Exception.Message
        }
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
		[Parameter(Mandatory = $true)]
		[PSCredential]$Credentials,
		[Parameter(Mandatory = $false)]
		[bool]$concurrentSession,
		[Parameter(Mandatory = $false)]
		[string]$RadiusOTP
	)
	# Create the POST Body for the Logon
	# ----------------------------------
	If ($concurrentSession) {
		$logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password; concurrentSession = "true" } | ConvertTo-Json -Compress
	} else {
		$logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password } | ConvertTo-Json -Compress
	}
	If (![string]::IsNullOrEmpty($RadiusOTP)) {
		$logonBody.Password += ",$RadiusOTP"
	}
	
	try {
		# Logon
		$logonToken = Invoke-Rest -Command Post -Uri $URL_Logon -Body $logonBody
		# Clear logon body
		$logonBody = ""
	} catch {
		Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.Exception.Response.StatusDescription)", $_.Exception))
	}
    
	$logonHeader = $null
	If ([string]::IsNullOrEmpty($logonToken)) {
		Throw "Get-LogonHeader: Logon Token is Empty - Cannot login"
	}
	
	# Create a Logon Token Header (This will be used through out all the script)
	# ---------------------------
	$logonHeader = @{Authorization = $logonToken }
	
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
	try{
		# Logoff the session
		# ------------------
		If($null -ne $g_LogonHeader)
		{
			Write-LogMessage -Type Info -Msg "Logoff Session..."
			Invoke-Rest -Command Post -Uri $URL_Logoff -Header $g_LogonHeader
			Set-Variable -Name g_LogonHeader -Value $null -Scope script
		}
	} catch {
		Throw $(New-Object System.Exception ("Invoke-Logoff: Failed to logoff session",$_.Exception))
	}
}
#endregion

#-----------------
# Write the entire script command when running in Verbose mode
Write-LogMessage -Type Verbose -Msg $g_ScriptCommand -LogFile $LOG_FILE_PATH
# Header
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
If (![string]::IsNullOrEmpty($PVWAURL))
{
	If ($PVWAURL.Substring($PVWAURL.Length-1) -eq "/")
	{
		$PVWAURL = $PVWAURL.Substring(0,$PVWAURL.Length-1)
	}
}


# Get Credentials to Login
# ------------------------
$caption = "Export/Import Applications"
$msg = "Enter your PAS User name and Password ($AuthType)"; 
If (![string]::IsNullOrEmpty($logonToken)) {
	if ($logonToken.GetType().name -eq "String") {
		$logonHeader = @{Authorization = $logonToken }
		Set-Variable -Scope Global -Name g_LogonHeader -Value $logonHeader
	} else {
		Set-Variable -Scope Global -Name g_LogonHeader -Value $logonToken
 }
	
} elseif ($null -eq $creds) {
	If (![string]::IsNullOrEmpty($PVWACredentials)) {
		$creds = $PVWACredentials
	} else {
		$msg = "Enter your $AuthType User name and Password"; 
		$creds = $Host.UI.PromptForCredential($caption, $msg, "", "")
	}
	if ($AuthType -eq "radius" -and ![string]::IsNullOrEmpty($OTP)) {
		Set-Variable -Scope Global -Name g_LogonHeader -Value $(Get-LogonHeader -Credentials $creds -concurrentSession $concurrentSession -RadiusOTP $OTP )
	} else {
		Set-Variable -Scope Global -Name g_LogonHeader -Value $(Get-LogonHeader -Credentials $creds -concurrentSession $concurrentSession)
	}
	# Verify that we successfully logged on
	If ($null -eq $g_LogonHeader) { 
		return # No logon header, end script 
	}
} else { 
	Write-LogMessage -Type Error -MSG "No Credentials were entered" -Footer
	return
}

"Header = $g_LogonHeader"


switch($PsCmdlet.ParameterSetName)
{
    "Import"
    {
        try{
            If(Test-Path $CSVPath)
            {
                $appData = Import-Csv $CSVPath
                ForEach($app in $appData)
                {
                    try{
                        # Add application
                        $appBody = @{
                            "application"=@{
                                "AppID"=$app.AppID;
                                "Description"=$app.Description;
                                "Location"=$app.Location;
                                "AccessPermittedFrom"=[int]::Parse($app.AccessPermittedFrom);
                                "AccessPermittedTo"=[int]::Parse($app.AccessPermittedTo);
                                "ExpirationDate"=(Get-TrimmedString $app.ExpirationDate);
                                "Disabled"=(TryConvertTo-Bool $app.Disabled);
                                "BusinessOwnerFName"=(Get-TrimmedString $app.BusinessOwnerFName);
                                "BusinessOwnerLName"=(Get-TrimmedString $app.BusinessOwnerLName);
                                "BusinessOwnerEmail"=(Get-TrimmedString $app.BusinessOwnerEmail);
                                "BusinessOwnerPhone"=(Get-TrimmedString $app.BusinessOwnerPhone);
                              }
                        }
                        $newApp = (Invoke-Rest -Command POST -URI $URL_Applications -Body $($appBody | ConvertTo-Json) -Header $g_LogonHeader)
                        if($null -ne $newApp)
                        {
                            # Add the Application Authentication methods
                            $arrAuths = $app.Authentications -split ';'
                            ForEach($auth in $arrAuths)
                            {
								try{
									$authBody = @{
										"authentication"=$(Convert-StringToObject -String $auth)
									}
									Write-LogMessage -Type Verbose -MSG "Adding '$($authBody.authentication.AuthType)' authentication method to '$($app.AppID)'"
									$newAuth = (Invoke-Rest -Command POST -URI ($URL_ApplicationAuthMethod -f $app.AppID) -Body $($authBody | ConvertTo-Json) -Header $g_LogonHeader)
									If($null -eq $newAuth)
									{
										Write-LogMessage -Type Error -Msg "Error adding new authentication method to application'$($app.AppID)'"
									}
								} catch {
									Write-LogMessage -Type Error -Msg "Error adding new authentication method to application'$($app.AppID)'. Error: $(Join-ExceptionMessage $_.Exception)"
								}
                            }
                        }
                    } catch {
                        Write-LogMessage -Type Error -Msg "Error adding application '$($app.AppID)'. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                }
            }
        } catch {
            Write-LogMessage -Type Error -Msg "Error importing applications. Error: $(Join-ExceptionMessage $_.Exception)"
        }
    }
    "Export"
    {
		# Check if the CSV File exists already
		If(Test-Path $CSVPath)
		{
			try{
				Write-Warning -WarningAction Inquire -Message "CSV file ($CSVPath) already exist, Continue to overwrite or Halt to enter a new CSV path"
				# User confirmed to overwrite - delete the exting file
				Remove-Item $CSVPath
			} catch {
				# User chose to Halt
				return
			}
		}
        try{
            $arrApps = @()
            if([string]::IsNullOrEmpty($AppID))
            {
                # Get all applications
                $allApps = (Invoke-Rest -Command Get -URI $URL_Applications -Header $g_LogonHeader).application
            }
            else {
                $allApps = (Invoke-Rest -Command Get -URI ($URL_SpecificApplication -f $AppID) -Header $g_LogonHeader).application
            }
            If($null -ne $allApps)
            {
                Write-LogMessage -type Info -MSG "Found $($allApps.Count) applications"
                ForEach($app in $allApps)
                {
                    $appObject = New-Object psobject
                    # Deep copy of the application
                    $app.PSobject.Properties | ForEach-Object { $appObject | Add-Member -MemberType $_.MemberType -Name $_.Name -Value $_.Value }
                    try{
                        # Get the application authentication methods
                        Write-LogMessage -Type Verbose -MSG "Getting application '$($app.AppID)' authentication methods"
                        $appAuthMethods = Invoke-Rest -Command Get -URI $($URL_ApplicationAuthMethod -f $(Convertto-URL $app.AppID)) -Header $g_LogonHeader
                    } catch {
                        Write-LogMessage -Type Error -Msg "Error getting application '$($app.AppID)' authentication methods. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    If($null -ne $appAuthMethods)
                    {
                        # Convert application auth. method to object
                        $appAuth = @()
                        ForEach($auth in $appAuthMethods.authentication)
                        {
                            $appAuth += $(Convert-ObjectToString -object $auth)
                        }
                        $appObject | Add-Member -NotePropertyName "Authentications" -NotePropertyValue $($appAuth -join ';')
                        # Add the new object to the Apps array
                        $arrApps += $appObject
                    }
                }
                # Exporting Applications to CSV
                Write-LogMessage -type Info -MSG "Exporting applications to CSV file..."
                $arrApps | Export-Csv -NoClobber -NoTypeInformation -Encoding ASCII -Path $CSVPath -Force
            }
        } catch {
            Write-LogMessage -Type Error -Msg "Error exporting applications. Error: $(Join-ExceptionMessage $_.Exception)"
        }
    }
}
# Logoff the session
# ------------------
Invoke-Logoff
Write-LogMessage -Type Info -MSG "Script Ended" -Footer -LogFile $LOG_FILE_PATH
