<# ###########################################################################

NAME: Export / Import Platform

AUTHOR:  Assaf Miron, Brian Bors

COMMENT: 
This script will Export or Import a platform using REST API

SUPPORTED VERSIONS:
CyberArk PVWA v10.4 and above

VERSION HISTORY:
1.0 05/07/2018 - Initial release
1.1 08/12/2021 - Added ability to do bulk export/import

########################################################################### #>
[CmdletBinding()]
param
(
	[Parameter(Mandatory = $true, HelpMessage = "Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,

	[Parameter(Mandatory = $false, HelpMessage = "Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark", "ldap", "radius")]
	[String]$AuthType = "cyberark",	
  
  [Parameter(Mandatory=$false,HelpMessage="Enter the RADIUS OTP")]
	[ValidateScript({$AuthType -eq "radius"})]
	[String]$OTP,
	
	# Use this switch to Import a Platform
	[Parameter(ParameterSetName = 'Import', Mandatory = $true)][switch]$Import,
	# Use this switch to Export a Platform
	[Parameter(ParameterSetName = 'Export', Mandatory = $true)][switch]$Export,

	# Use this switch to Import a Platform using a file
	[Parameter(ParameterSetName = 'ImportFile', Mandatory = $true)][switch]$ImportFile,
	# Use this switch to Export a Platform using a file
	[Parameter(ParameterSetName = 'ExportFile', Mandatory = $true)][switch]$ExportFile,

	[Parameter(ParameterSetName = 'ExportActive', Mandatory = $true)][switch]$ExportActive,
	[Parameter(ParameterSetName = 'ExportAll', Mandatory = $true)][switch]$ExportAll,
	
	[Parameter(ParameterSetName = 'Export', Mandatory = $true, HelpMessage = "Enter the platform ID to export")]
	[Alias("id")]
	[string]$PlatformID,
	
	[Parameter(ParameterSetName = 'Import', Mandatory = $true, HelpMessage = "Enter the platform Zip path for import")]
	[Parameter(ParameterSetName = 'Export', Mandatory = $true, HelpMessage = "Enter the platform Zip path to export")]
	[Parameter(ParameterSetName = 'ImportFile', Mandatory = $false, HelpMessage = "Enter the platform Zip path for import")]
	[Parameter(ParameterSetName = 'ExportFile', Mandatory = $true, HelpMessage = "Enter the platform Zip path to export")]
	[Parameter(ParameterSetName = 'ExportActive', Mandatory = $true, HelpMessage = "Enter the platform Zip path to export")]
	[Parameter(ParameterSetName = 'ExportAll', Mandatory = $true, HelpMessage = "Enter the platform Zip path to export")]
	[string]$PlatformZipPath,

	# Use this to specify where file to read is
	[Parameter(ParameterSetName = 'ImportFile', Mandatory = $true, HelpMessage = "Enter the import file path for import")]
	[Parameter(ParameterSetName = 'ExportFile', Mandatory = $true, HelpMessage = "Enter the export file path for export")]
	[string]$listFile,

	[Parameter(Mandatory = $false)]
	$creds,

	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory = $false)]
	[Switch]$DisableSSLVerify
)

# Get Script Location 
$ScriptFullPath = $MyInvocation.MyCommand.Path
$ScriptLocation = Split-Path -Parent $ScriptFullPath
$ScriptParameters = @()
$PSBoundParameters.GetEnumerator() | ForEach-Object { $ScriptParameters += ("-{0} '{1}'" -f $_.Key, $_.Value) }
$global:g_ScriptCommand = "{0} {1}" -f $ScriptFullPath, $($ScriptParameters -join ' ')

# Script Version
$ScriptVersion = "2.0"

# Set Log file path
$LOG_FILE_PATH = "$ScriptLocation\Export-Import-Platforms.log"

$InDebug = $PSBoundParameters.Debug.IsPresent
$InVerbose = $PSBoundParameters.Verbose.IsPresent
# Set a global Header Token parameter
$global:g_LogonHeader = ""

# Global URLS
# -----------
$URL_PVWAAPI = $PVWAURL + "/api"
$URL_Authentication = $URL_PVWAAPI + "/auth"
$URL_Logon = $URL_Authentication + "/$AuthType/Logon"
$URL_Logoff = $URL_Authentication + "/Logoff"

# URL Methods
# -----------
$URL_Platforms = $URL_PVWAAPI+"/Platforms"
$URL_PlatformDetails = $URL_Platforms+"/{0}"
$URL_ExportPlatforms = $URL_PlatformDetails+"/Export"
$URL_ImportPlatforms = $URL_Platforms+"/Import"

#region Functions
Function Test-CommandExists {
	Param ($command)
	$oldPreference = $ErrorActionPreference
	$ErrorActionPreference = 'stop'
	try { if (Get-Command $command) { RETURN $true } }
	Catch { Write-Host "$command does not exist"; RETURN $false }
	Finally { $ErrorActionPreference = $oldPreference }
} #end function test-CommandExists

#region Log Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Write-LogMessage
# Description....: Writes the message to log and screen
# Parameters.....: MSG, (Switch)Header, (Switch)SubHeader, (Switch)Footer, Type
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
		if($Msg -match '((?:"password"|"secret"|"NewCredentials")\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w!@#$%^&*()\[\]\-\\\/]+))')
		{
			$Msg = $Msg.Replace($Matches[2],"****")
		}
		# Check the message type
		switch ($type)
		{
			"Info" { 
				Write-Host $MSG.ToString()
				$msgToWrite += "[INFO]`t$Msg"
				break
			}
			"Warning" {
				Write-Host $MSG.ToString() -ForegroundColor Yellow
				$msgToWrite += "[WARNING]`t$Msg"
				break
			}
			"Error" {
				Write-Host $MSG.ToString() -ForegroundColor Red
				$msgToWrite += "[ERROR]`t$Msg"
				break
			}
			"Debug" { 
				if($InDebug)
				{
					Write-LogMessage -Type Debug -Msg $MSG
					$msgToWrite += "[DEBUG]`t$Msg"
				}
				else { $writeToFile = $False }
				break
			}
			"Verbose" { 
				if($InVerbose)
				{
					Write-Verbose $MSG
					$msgToWrite += "[VERBOSE]`t$Msg"
				}
				else { $writeToFile = $False }
				break
			}
		}
		
		If($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH }
		If ($Footer) { 
			"=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
			Write-Host "======================================="
		}
	} catch { Write-Error "Error in writing log: $($_.Exception.Message)" }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Join-ExceptionMessage
# Description....: Formats exception messages
# Parameters.....: Exception
# Return Values..: Formatted String of Exception messages
# =================================================================================================================================
Function Join-ExceptionMessage {
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
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials,
        [Parameter(Mandatory = $false)]
		    [string]$RadiusOTP
    )
	
    if ([string]::IsNullOrEmpty($g_LogonHeader))
    {
        # Disable SSL Verification to contact PVWA
        If ($DisableSSLVerify)
        {
            Disable-SSLVerification
        }
		
        # Create the POST Body for the Logon
        # ----------------------------------
        If ($ConnectionNumber -eq 0)
        {
            $logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password } | ConvertTo-Json
        }
        elseif ($ConnectionNumber -gt 0)
        {
            $logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password; connectionNumber = $ConnectionNumber } | ConvertTo-Json
        }
        try
        {
            # Logon
            $logonToken = Invoke-RestMethod -Method Post -Uri $URL_Logon -Body $logonBody -ContentType "application/json" -TimeoutSec 2700
			
            # Clear logon body
            $logonBody = ""
        }
        catch
        {
            Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.Exception.Response.StatusDescription)", $_.Exception))
        }

        $logonHeader = $null
        If ([string]::IsNullOrEmpty($logonToken))
        {
            Throw "Get-LogonHeader: Logon Token is Empty - Cannot login"
        }
		
        try
        {
            # Create a Logon Token Header (This will be used through out all the script)
            # ---------------------------
            If ($logonToken.PSObject.Properties.Name -contains "CyberArkLogonResult")
            {
                $logonHeader = @{Authorization = $($logonToken.CyberArkLogonResult) }
            }
            else
            {
                $logonHeader = @{Authorization = $logonToken }
            }	

            Set-Variable -Name g_LogonHeader -Value $logonHeader -Scope global		
        }
        catch
        {
            Throw $(New-Object System.Exception ("Get-LogonHeader: Could not create Logon Headers Dictionary", $_.Exception))
        }
    }
}

Function Invoke-Logoff
{
    <# 
.SYNOPSIS 
	Invoke-Logoff
.DESCRIPTION
	Logoff a PVWA session
#>
    try
    {
        # Logoff the session
        # ------------------
        If ($null -ne $g_LogonHeader)
        {
            Write-LogMessage -Type Info -Msg "Logoff Session..."
            Invoke-RestMethod -Method Post -Uri $URL_Logoff -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700 | Out-Null
            Set-Variable -Name g_LogonHeader -Value $null -Scope global
        }
    }
    catch
    {
        Throw $(New-Object System.Exception ("Invoke-Logoff: Failed to logoff session", $_.Exception))
    }
}

Function Disable-SSLVerification
{
    <# 
.SYNOPSIS 
	Bypass SSL certificate validations
.DESCRIPTION
	Disables the SSL Verification (bypass self signed SSL certificates)
#>
    # Check if to disable SSL verification
    If ($DisableSSLVerify)
    {
        try
        {
            Write-Warning "It is not Recommended to disable SSL verification" -WarningAction Inquire
            # Using Proxy Default credentials if the Server needs Proxy credentials
            [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
            # Using TLS 1.2 as security protocol verification
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            # Disable SSL Verification
            if (-not("DisableCertValidationCallback" -as [type]))
            {
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
        catch
        {
            Write-LogMessage -Type Error -Msg "Could not change SSL validation. Error: $(Join-ExceptionMessage $_.Exception)"
        }
    }
    Else
    {
        try
        {
            Write-LogMessage -Type Info -Msg "Setting script to use TLS 1.2"
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        }
        catch
        {
            Write-LogMessage -Type Error -Msg "Could not change SSL setting to use TLS 1.2. Error: $(Join-ExceptionMessage $_.Exception)"
        }
    }
}
#endregion

Function import-platform {

	param(
		[string]$PlatformZipPath
	)
	If (Test-Path $PlatformZipPath) {
		$zipContent = [System.IO.File]::ReadAllBytes($(Resolve-Path $PlatformZipPath))
		$importBody = @{ ImportFile = $zipContent; } | ConvertTo-Json -Depth 3 -Compress
		try {
			$ImportPlatformResponse = Invoke-RestMethod -Method POST -Uri $URL_ImportPlatforms -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700 -Body $importBody
			Write-Debug "Platform ID imported: $($ImportPlatformResponse.PlatformID)"
			Write-Host "Retrieving Platform details"
			# Get the Platform Name
			$platformDetails = Invoke-RestMethod -Method Get -Uri $($URL_PlatformDetails -f $ImportPlatformResponse.PlatformID) -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700
			If ($platformDetails) {
				Write-Debug $platformDetails
				Write-Host "$($platformDetails.Details.PolicyName) (ID: $($platformDetails.PlatformID)) was successfully imported and $(if($platformDetails.Active) { "Activated" } else { "Inactive" })"
				Write-Host "Platform details:" 
				$platformDetails.Details | Select-Object PolicyID, AllowedSafes, AllowManualChange, PerformPeriodicChange, @{Name = 'AllowManualVerification'; Expression = { $_.VFAllowManualVerification } }, @{Name = 'PerformPeriodicVerification'; Expression = { $_.VFPerformPeriodicVerification } }, @{Name = 'AllowManualReconciliation'; Expression = { $_.RCAllowManualReconciliation } }, @{Name = 'PerformAutoReconcileWhenUnsynced'; Expression = { $_.RCAutomaticReconcileWhenUnsynched } }, PasswordLength, MinUpperCase, MinLowerCase, MinDigit, MinSpecial 
			}		
		} catch {
			#Write-Error $_.Exception
			#Write-Error $_.Exception.Response
			#Write-Error $_.Exception.Response.StatusDescription
			
			($_.ErrorDetails | ConvertFrom-Json | Select-Object -Property ErrorMessage)
			"Error while attempting to export $PlatformZipPath"
			""
		}
	}
} #end function Import

Function export-platform {

	param(
		[string]$PlatformID
	)

	try {
		$exportURL = $URL_ExportPlatforms -f $PlatformID
		Invoke-RestMethod -Method POST -Uri $exportURL -Headers $g_LogonHeader -ContentType "application/zip" -TimeoutSec 2700 -OutFile "$PlatformZipPath\$PlatformID.zip" -ErrorAction SilentlyContinue
	} catch {
		#Write-Error $_.Exception.Response
		#Write-Error $_.Exception.Response.StatusDescription
		
		($_.ErrorDetails | ConvertFrom-Json | Select-Object -Property ErrorMessage)
		"Error while attempting to export $PlatformID"
		""
	}
} #end function Import

Function Get-PlatformsList {
	param(
		[switch]$GetAll
	)

	$idList = @()
	
	try {
		If ($GetAll){
			$url = $URL_GetPlatforms + "?PlatformType=Regular"
		} else {
			$url = $URL_GetPlatforms + "?Active=True&PlatformType=Regular"
		}
		
		$result = Invoke-RestMethod -Method GET -Uri $url -Headers $g_LogonHeader -ErrorAction SilentlyContinue

		foreach ($platform in $result.Platforms){
			$idList += $platform.general.id
		}

		return $idList

	} catch {
		#Write-Error $_.Exception.Response
		#Write-Error $_.Exception.Response.StatusDescription
		
		($_.ErrorDetails | ConvertFrom-Json | Select-Object -Property ErrorMessage)
		"Error while attempting to export $PlatformID"
		""
	}
} #end function Import



If (Test-CommandExists Invoke-RestMethod) {
	If ($DisableSSLVerify) {
		try {
			Write-Warning "It is not Recommended to disable SSL verification" -WarningAction Inquire
			# Using Proxy Default credentials if the Server needs Proxy credentials
			[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
			# Using TLS 1.2 as security protocol verification
			[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
			# Disable SSL Verification
			[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
		} catch {
			Write-Error "Could not change SSL validation"
			Write-Error (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
			return
		}
	} Else {
		try {
			Write-Debug "Setting script to use TLS 1.2"
			[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
		} catch {
			Write-Error "Could not change SSL settings to use TLS 1.2"
			Write-Error (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
		}
	}

	# Check that the PVWA URL is OK
	If ($PVWAURL -ne "") {
		If ($PVWAURL.Substring($PVWAURL.Length - 1) -eq "/") {
			$PVWAURL = $PVWAURL.Substring(0, $PVWAURL.Length - 1)
		}
	} else {
		Write-Host -ForegroundColor Red "PVWA URL can not be empty"
		return
	}

	Write-Host "Export / Import Platform: Script Started" -ForegroundColor Cyan

	#region [Logon]
	# Get Credentials to Login
	# ------------------------
	$caption = "Export / Import Platform"
	$msg = "Enter your User name and Password"; 
	if ($Null -eq $creds) {$creds = $Host.UI.PromptForCredential($caption, $msg, "", "")}
	if ($null -ne $creds) {
		Get-LogonHeader $creds -RadiusOTP $OTP
	} else { return }
	#endregion

	switch ($PsCmdlet.ParameterSetName) {
		"Import" {
			import-platform $PlatformZipPath -error
		}

		"ImportFile" {
			foreach ($line in Get-Content $listFile) {
				Write-Debug "Trying to import $line" 
				if (![string]::IsNullOrEmpty($line)) { import-platform $line }
			} 
		}

		"Export" {
			if (![string]::IsNullOrEmpty($PlatformID)) { export-platform $PlatformID}
			
		}

		"ExportFile" {
			foreach ($line in Get-Content $listFile) {
				Write-Debug "Trying to export $line" 
				if (![string]::IsNullOrEmpty($line)) { export-platform $line }		
			} 
	
		}
		{"ExportActive" -or "ExportAll"} {
			$platforms = Get-PlatformsList -GetAll:$(($PsCmdlet.ParameterSetName -eq "ExportAll"))
			$null | Out-File -FilePath "$PlatformZipPath\_Export.txt" -Force
			foreach ($line in $platforms) {
				Write-Debug "Trying to export $line" 
				("$PlatformZipPath\$line.zip").Replace("\\","\").Replace("/","\") | Out-File -FilePath "$PlatformZipPath\_Export.txt" -Append
				if (![string]::IsNullOrEmpty($line)) { export-platform $line }		
			} 

		}
	}
	# Logoff the session
	Invoke-Logoff
} else {
	Write-Error "This script requires PowerShell version 3 or above"
}

Write-Host "Export / Import Platform: Script Finished" -ForegroundColor Cyan
