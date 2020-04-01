###########################################################################
#
# NAME: Convert a Platform to support Dual Account
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will convert an existing platform to support Dual Account using REST API
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v10.4 and above
#
#
###########################################################################

param
(
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,

	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory=$false)]
	[Switch]$DisableSSLVerify,
	
	[Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark","ldap","radius")]
	[String]$AuthType="cyberark",
	
	[Parameter(Mandatory=$true,HelpMessage="Enter the platform ID to convert")]
	[Alias("Platform")]
	[string]$PlatformID 
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
$global:LOG_FILE_PATH = "$ScriptLocation\Convert-Platform-DualAccount.log"
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
$URL_PlatformDetails = $URL_PVWAAPI+"/Platforms/{0}"
$URL_ImportPlatforms = $URL_PVWAAPI+"/Platforms/Import"
$URL_ExportPlatforms = $URL_PlatformDetails+"/Export"

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
		[String]$ForegroundColor = "White",
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
				Write-Host $MSG.ToString() -ForegroundColor $ForegroundColor
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
.PARAMETER OutFile
	(Optional) Output file to export the result
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
		[String]$OutFile, 
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
		$cmd = @{ Uri=$URI; Method=$Command; Header=$Header; ContentType="application/json"; TimeoutSec=36000 }
		if(![string]::IsNullOrEmpty($Body))
		{
			$cmd.Add("Body",$Body)
		}
		if(![string]::IsNullOrEmpty($OutFile))
		{
			$cmd.Add("OutFile",$OutFile)
		}
		Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod $($cmd -join '-')"
		$restResponse = Invoke-RestMethod @cmd -Debug:$InDebug -Verbose:$InVerbose
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

Function Get-ZipContent
{
	Param($zipPath)
	
	$zipContent = $null
	try{
		If(Test-Path $zipPath)
		{
			$zipContent = [System.IO.File]::ReadAllBytes($(Resolve-Path $zipPath))
		}
	} catch {
		throw "Error while reading ZIP file: $($_.Exception.Message)"
	}
	
	return $zipContent
}

Function AddPlatform-DualAccount
{
	Param($platformZipPath)
	
	try{
		If(Test-Path $platformZipPath)
		{
			$Package = Get-Item -Path $platformZipPath
			# load ZIP methods
			Add-Type -AssemblyName System.IO.Compression.FileSystem
			Write-LogMessage -Type Debug -Msg "Extracting Platform ZIP ('$platformZipPath')"
			# Extract ZIP to temp folder
			$tempFolder = Join-Path -Path $Package.Directory -ChildPath $Package.BaseName
			if(Test-Path $tempFolder)
			{
				Remove-Item -Recurse $tempFolder
			}
			[System.IO.Compression.ZipFile]::ExtractToDirectory($Package.FullName,$tempFolder)
		}
		else
		{
			throw "Could not find Platform ZIP in '$platformZipPath'"
		}
		
		Write-LogMessage -Type Debug -Msg "Adding Dual Account support to platform $PlatformID"
		# Find all XML files in the platform ZIP
		$fileEntries = Get-ChildItem -Path $tempFolder -Filter '*.xml'
		Write-LogMessage -Type Verbose -Msg $fileEntries
		# There should be only one file
		If($fileEntries.Count -ne 1)
		{ throw "Invalid Platform ZIP file" }
		[xml]$xmlContent = Get-Content $fileEntries[0].FullName
		# Add PSM details to XML
		Write-LogMessage -Type Debug -Msg "Adding Dual Account Properties"
		
		$propNode = $xmlContent.CreateNode("element","Property","")
		$propNode.SetAttribute("Name","Index")
		$xmlContent.Device.Policies.Policy.Properties.Optional.AppendChild($propNode) | Out-Null
		$propNode = $xmlContent.CreateNode("element","Property","")
		$propNode.SetAttribute("Name","DualAccountStatus")
		$xmlContent.Device.Policies.Policy.Properties.Optional.AppendChild($propNode) | Out-Null
		$propNode = $xmlContent.CreateNode("element","Property","")
		$propNode.SetAttribute("Name","VirtualUsername")
		$xmlContent.Device.Policies.Policy.Properties.Optional.AppendChild($propNode) | Out-Null
		
		$platformID = $xmlContent.Device.Policies.Policy.ID
		$newPlatformID = $platformID + "-DualAccount"
		Write-LogMessage -Type Debug -Msg "Renaming Platform for Dual Accounts - $platformID"
		$xmlContent.Device.Policies.Policy.ID = $newPlatformID
		Write-LogMessage -Type Debug -Msg "New Platform ID: $($xmlContent.Device.Policies.Policy.ID)"
		$xmlContent.Save($fileEntries[0].FullName)
		
		# Editing the Platform INI file
		# Find all ini files in the platform ZIP
		$fileEntries = Get-ChildItem -Path $tempFolder -Filter '*.ini'
		Write-LogMessage -Type Verbose -Msg $fileEntries
		# There should be only one file
		If($fileEntries.Count -ne 1)
		{ throw "Invalid Platform ZIP file" }
		$iniContent = Get-Content -Path $fileEntries[0].FullName
		$iniContent = $iniContent.Replace($platformID, $newPlatformID)
		$platformName = ($iniContent -match "PolicyName=([\w ]{1,})").Replace("PolicyName=","")
		# Found the Platform name, add Dual Accounts to it
		$iniContent = $iniContent.Replace($platformName,$platformName+" Dual Account")
		
		$iniContent | Out-File $fileEntries[0].FullName -Force
		
		Write-LogMessage -Type Debug -Msg "Delete original ZIP and Package the new Platform ZIP"
		$zipFullPath = $Package.FullName
		Remove-Item $zipFullPath
		[System.IO.Compression.ZipFile]::CreateFromDirectory($tempFolder,$zipFullPath)
		Write-LogMessage -Type Debug -Msg "Removing extracted ZIP folder"
		Remove-Item -Recurse $tempFolder
	} catch {
		throw "Error while converting platform to Dual Account platform: $($_.Exception.Message)"
	}
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

#endregion

If (-not (Test-CommandExists Invoke-RestMethod))
{
	Write-Error "This script requires PowerShell version 3 or above"
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
	Write-LogMessage -Type Error -Msg "PVWA URL can not be empty"
	return
}

Write-LogMessage -Type Info -Msg "Conevrting Platform for Dual Account support: Script Started" -ForegroundColor Cyan

#region [Logon]
# Get Credentials to Login
# ------------------------
$caption = "Convert Platform for Dual Account"
$msg = "Enter your PAS User name and Password ($AuthType)"; 
$creds = $Host.UI.PromptForCredential($caption,$msg,"","")

#endregion

# Exporting Platform
$exportPath = "$(Join-Path -Path $ENV:Temp -ChildPath $PlatformID).zip"
try{
	$exportURL = $URL_ExportPlatforms -f $PlatformID
	Invoke-Rest -Command POST -Uri $exportURL -Header $(Get-LogonHeader $creds) -OutFile $exportPath
} catch {
	Write-LogMessage -Type Error -Msg "Error exporting platform $PlatformID. Error: $(Collect-ExceptionMessage $_.Exception)"
	Run-Logoff
}
# Add Dual Account Support to platform
try{
	AddPlatform-DualAccount -platformZipPath $exportPath
} catch {
	Write-LogMessage -Type Error -Msg "Error adding Dual Account support to platform $PlatformID. Error: $(Collect-ExceptionMessage $_.Exception)"
	Run-Logoff
}
# Import new Platform
If (Test-Path $exportPath)
{
	Write-LogMessage -Type Debug -Msg "Importing new platform from '$exportPath'"
	$importBody = @{ ImportFile=$(Get-ZipContent $exportPath); } | ConvertTo-Json -Depth 5
	try{
		Write-LogMessage -Type Debug -Msg "Before import"
		$ImportPlatformResponse = Invoke-Rest -Command POST -Uri $URL_ImportPlatforms -Header $(Get-LogonHeader $creds) -Body $importBody
		Write-LogMessage -Type Info -Msg "Platform ID imported: $($ImportPlatformResponse.PlatformID)"
	} catch {
		Write-LogMessage -Type Error -Msg "Error importing the platform, Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	Write-LogMessage -Type Debug -Msg "Deleting temp file from '$exportPath'"
	# Remove the temp ZIP file
	# Remove-Item $exportPath
}

# Logoff the session
# ------------------
Run-Logoff
Write-LogMessage -Type Info -Msg "Conevrting Platform for Dual Account support: Script Ended" -ForegroundColor Cyan
