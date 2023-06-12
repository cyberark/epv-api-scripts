<# ###########################################################################

NAME: Export / Import Platform

AUTHOR:  Assaf Miron, Brian Bors

COMMENT: 
This script will Export or Import a platform using REST API

SUPPORTED VERSIONS:
CyberArk PVWA v10.4 and above

VERSION HISTORY:
1.0 05/07/2018 - Initial release
1.1 08/12/2018 - Added ability to do bulk export/import

########################################################################### #>

param
(
	[Parameter(Mandatory = $true, HelpMessage = "Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,

	[Parameter(Mandatory = $false, HelpMessage = "Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark", "ldap", "radius")]
	[String]$AuthType = "cyberark",	
	
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
	[PScredential]$creds,

	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory = $false)]
	[Switch]$DisableSSLVerify,

	# Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off
	[Parameter(Mandatory = $false)]
	$logonToken
)

# Global URLS
# -----------
$URL_PVWAAPI = $PVWAURL + "/api"
$URL_Authentication = $URL_PVWAAPI + "/auth"
$URL_Logon = $URL_Authentication + "/$AuthType/Logon"
$URL_Logoff = $URL_Authentication + "/Logoff"

# URL Methods
# -----------
$URL_GetPlatforms = $URL_PVWAAPI + "/Platforms"
$URL_PlatformDetails = $URL_PVWAAPI + "/Platforms/{0}"
$URL_ExportPlatforms = $URL_PVWAAPI + "/Platforms/{0}/Export"
$URL_ImportPlatforms = $URL_PVWAAPI + "/Platforms/Import"

# Initialize Script Variables
# ---------------------------
$rstusername = $rstpassword = ""

$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent

$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
$global:LOG_DATE = $(Get-Date -Format yyyyMMdd) + "-" + $(Get-Date -Format HHmmss)
$global:LOG_FILE_PATH = "$ScriptLocation\Export-Import-Platform_$LOG_DATE.log"

#region Functions
Function Test-CommandExists {
	Param ($command)
	$oldPreference = $ErrorActionPreference
	$ErrorActionPreference = 'stop'
	try {
		if (Get-Command $command) {
			RETURN $true 
		} 
 } Catch {
		Write-LogMessage -Type Info -Msg "$command does not exist"; RETURN $false 
 } Finally {
		$ErrorActionPreference = $oldPreference 
 }
} #end function test-CommandExists
Function Write-LogMessage {
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
		[Parameter(Mandatory = $true)]
		[AllowEmptyString()]
		[String]$MSG,
		[Parameter(Mandatory = $false)]
		[Switch]$Header,
		[Parameter(Mandatory = $false)]
		[Switch]$SubHeader,
		[Parameter(Mandatory = $false)]
		[Switch]$Footer,
		[Parameter(Mandatory = $false)]
		[ValidateSet("Info", "Warning", "Error", "Debug", "Verbose")]
		[String]$type = "Info",
		[Parameter(Mandatory = $false)]
		[String]$LogFile = $LOG_FILE_PATH
	)
	try {
		If ($Header) {
			"=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
			Write-Host "======================================="
		} ElseIf ($SubHeader) { 
			"------------------------------------" | Out-File -Append -FilePath $LOG_FILE_PATH 
			Write-Host "------------------------------------"
		}
	
		$msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
		$writeToFile = $true
		# Replace empty message with 'N/A'
		if ([string]::IsNullOrEmpty($Msg)) {
			$Msg = "N/A" 
		}
		# Mask Passwords
		if ($Msg -match '((?:"password"|"secret"|"NewCredentials")\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w!@#$%^&*()-\\\/]+))') {
			$Msg = $Msg.Replace($Matches[2], "****")
		}
		# Check the message type
		switch ($type) {
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
				if ($InDebug -or $InVerbose) {
					Write-Debug $MSG
					$msgToWrite += "[DEBUG]`t$Msg"
				} else {
					$writeToFile = $False 
				}
			}
			"Verbose" { 
				if ($InVerbose) {
					Write-Verbose $MSG
					$msgToWrite += "[VERBOSE]`t$Msg"
				} else {
					$writeToFile = $False 
				}
			}
		}
		
		If ($writeToFile) {
			$msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH 
		}
		If ($Footer) { 
			"=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
			Write-Host "======================================="
		}
	} catch {
		Write-Error "Error in writing log: $($_.Exception.Message)" 
	}
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

Function import-platform {

	param(
		[string]$PlatformZipPath
	)
	If (Test-Path $PlatformZipPath) {
		Write-LogMessage -Type Debug -Msg "PlatformZipPath: `"$PlatformZipPath`""
		$zipContent = [System.IO.File]::ReadAllBytes($(Resolve-Path $PlatformZipPath))
		$importBody = @{ ImportFile = $zipContent; } | ConvertTo-Json -Depth 3 -Compress
		Write-LogMessage -Type Debug -Msg "importBody first 50: $($importBody.Substring(0,50))"
		try {
			$ImportPlatformResponse = Invoke-RestMethod -Method POST -Uri $URL_ImportPlatforms -Headers $logonHeader -ContentType "application/json" -TimeoutSec 2700 -Body $importBody
			# Get the Platform Name
			$platformDetails = Invoke-RestMethod -Method Get -Uri $($URL_PlatformDetails -f $ImportPlatformResponse.PlatformID) -Headers $logonHeader -ContentType "application/json" -TimeoutSec 2700
			If ($platformDetails) {
				Write-LogMessage -Type Debug -Msg "PlatformID: `"$($platformDetails.PlatformID)`""
				Write-LogMessage -Type Debug -Msg "PlatformDetails: "
				ForEach ($detail in $platformDetails.Details.PSObject.Properties) {
					Write-LogMessage -Type Debug -Msg "		$($detail.name): `"$($detail.value)`""
				}
				Write-LogMessage -Type Info -Msg "Platform named `"$($platformDetails.Details.PolicyName)`" with PlatformID `"$($platformDetails.PlatformID)`" was successfully imported and is $(if($platformDetails.Active) { "active" } else { "inactive" })"				
			}		
		} catch {
			IF ($($($_.ErrorDetails | ConvertFrom-Json).ErrorMessage) -match "ITAPS016E" ){
				Write-LogMessage -Type Info -Msg "Platform in file `"$PlatformZipPath`" already exists. To update, delete existing version and import again."
			} else {
				Write-LogMessage -Type Error -Msg "Error while attempting to import `"$PlatformZipPath`""
				Write-LogMessage -Type Error -Msg "Error Code: `"$($($_.ErrorDetails | ConvertFrom-Json).ErrorCode)`""
				Write-LogMessage -Type Error -Msg "Error Message: `"$($($_.ErrorDetails | ConvertFrom-Json).ErrorMessage)`""
				Out-Null
			}
		}
	}
} #end function Import

Function export-platform {

	param(
		[string]$PlatformID
	)

	try {
		$exportURL = $URL_ExportPlatforms -f $PlatformID
		Write-LogMessage -Type Debug -Msg "Using URL: $exportURL"
		Write-LogMessage -Type Debug -Msg "Exporting to: $PlatformZipPath\$PlatformID.zip"
		Invoke-RestMethod -Method POST -Uri $exportURL -Headers $logonHeader -ContentType "application/zip" -TimeoutSec 2700 -OutFile "$PlatformZipPath\$PlatformID.zip" -ErrorAction SilentlyContinue
		Write-LogMessage -Type Info -Msg "Successfully exported platform `"$PlatformID"`"
	} catch {
		Write-LogMessage -Type Error -Msg "Error while attempting to export platformID `"$PlatformID`""
		Write-LogMessage -Type Error -Msg "Error Code: `"$($($_.ErrorDetails | ConvertFrom-Json).ErrorCode)`""
		Write-LogMessage -Type Error -Msg "Error Message: `"$($($_.ErrorDetails | ConvertFrom-Json).ErrorMessage)`""
		Out-Null
	}
} #end function Import

Function Get-PlatformsList {
	param(
		[switch]$GetAll
	)

	$idList = @()
	
	try {
		If ($GetAll) {
			$url = $URL_GetPlatforms + "?PlatformType=Regular"
		} else {
			$url = $URL_GetPlatforms + "?Active=True&PlatformType=Regular"
		}
		Write-LogMessage -Type Debug -Msg "Using URL: $url"
		$result = Invoke-RestMethod -Method GET -Uri $url -Headers $logonHeader -ErrorAction SilentlyContinue

		foreach ($platform in $result.Platforms) {
			$idList += $platform.general.id
		}

		return $idList

	} catch {
		Write-LogMessage -Type Error -Msg "Error while attempting to Get-PlatformsList with `"GetAll`" equal `"$GetAll`""
		Write-LogMessage -Type Error -Msg "Error Code: `"$($($_.ErrorDetails | ConvertFrom-Json).ErrorCode)`""
		Write-LogMessage -Type Error -Msg "Error Message: `"$($($_.ErrorDetails | ConvertFrom-Json).ErrorMessage)`""
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
			Write-LogMessage -Type Error -Msg "Could not change SSL validation"
			Write-LogMessage -Type Error -Msg (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
			return
		}
	} Else {
		try {
			Write-LogMessage -Type Verbose -Msg "Setting script to use TLS 1.2"
			[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
		} catch {
			Write-LogMessage -Type Error -Msg "Could not change SSL settings to use TLS 1.2"
			Write-LogMessage -Type Error -Msg (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
		}
	}

	# Check that the PVWA URL is OK
	If ($PVWAURL -ne "") {
		If ($PVWAURL.Substring($PVWAURL.Length - 1) -eq "/") {
			$PVWAURL = $PVWAURL.Substring(0, $PVWAURL.Length - 1)
		}
	} else {
		Write-LogMessage -Type Info -Msg "PVWA URL can not be empty"
		return
	}

	Write-LogMessage -Type Info -Msg "Export / Import Platform: Script Started"

	#region [Logon]
	# Get Credentials to Login
	# ------------------------
	$caption = "Export / Import Platform"

	If (![string]::IsNullOrEmpty($logonToken)) {
		if ($logonToken.GetType().name -eq "String") {
			$logonHeader = @{Authorization = $logonToken }
		} else {
			$logonHeader = $logonToken
  }
	} else {
		$msg = "Enter your User name and Password" 
		if ($Null -eq $creds) {
			$creds = $Host.UI.PromptForCredential($caption, $msg, "", "")
		}
		if ($null -ne $creds) {
			$rstusername = $creds.username.Replace('\', '')    
			$rstpassword = $creds.GetNetworkCredential().password

		} else {
			return 
		}

		# Create the POST Body for the Logon
		# ----------------------------------
		$logonBody = @{ username = $rstusername; password = $rstpassword; concurrentSession = 'true' }
		$logonBody = $logonBody | ConvertTo-Json
		try {
			# Logon
			Write-LogMessage -Type Debug -Msg "Logon URL: $URL_Logon" 
			Write-LogMessage -Type Debug -Msg "Logon Body: $logonBody" 
			$logonToken = Invoke-RestMethod -Method Post -Uri $URL_Logon -Body $logonBody -ContentType "application/json"
			Write-LogMessage -Type Debug -Msg "Logon token: $logonToken" 
		} catch {
			Write-LogMessage -Type Error -Msg $_.Exception.Response.StatusDescription
			$logonToken = ""
		}
		If ($logonToken -eq "") {
			Write-LogMessage -Type Error -Msg "Logon Token is Empty - Cannot login"
			return
		}
	
		# Create a Logon Token Header (This will be used through out all the script)
		# ---------------------------
		$logonHeader = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
		$logonHeader.Add("Authorization", $logonToken)
		#endregion
	}
	switch ($PsCmdlet.ParameterSetName) {
		"Import" {
			Write-LogMessage -Type Debug -Msg "In `"Import`" PlatformZipPath : $PlatformZipPath"
			import-platform $PlatformZipPath -error
		}

		"ImportFile" {
			Write-LogMessage -Type Debug -Msg "In `"ImportFile`" listFile : $listFile"
			foreach ($line in Get-Content $listFile) {
				Write-LogMessage -Type Verbose -Msg "Trying to import $line" 
				if (![string]::IsNullOrEmpty($line)) {
					import-platform $line 
    }
			} 
		}

		"Export" {
			Write-LogMessage -Type Debug -Msg "In `"Export`" PlatformID : $PlatformID"
			if (![string]::IsNullOrEmpty($PlatformID)) {
				export-platform $PlatformID
   }
			
		}

		"ExportFile" {
			Write-LogMessage -Type Debug -Msg "In `"ExportFile`" PlatformZipPath : $PlatformZipPath"
			$null | Out-File -FilePath "$PlatformZipPath\_Exported.txt" -Force
			foreach ($line in Get-Content $listFile) {
				Write-LogMessage -Type Verbose -Msg "Trying to export PlatformID `"$line`"" 
				if (![string]::IsNullOrEmpty($line)) { 
					export-platform $line
					("$PlatformZipPath\$line.zip").Replace("\\", "\").Replace("/", "\") | Out-File -FilePath "$PlatformZipPath\_Exported.txt" -Append
				}
			} 
	
		}
		{ ($_ -eq "ExportActive") -or ($_ -eq "ExportAll") } {
			Write-LogMessage -Type Debug -Msg "In `"ExportActive or ExportAll`" PlatformZipPath : $PlatformZipPath"
			$platforms = Get-PlatformsList -GetAll:$(($PsCmdlet.ParameterSetName -eq "ExportAll"))
			$null | Out-File -FilePath "$PlatformZipPath\_Exported.txt" -Force
			foreach ($line in $platforms) {
				Write-LogMessage -Type Verbose -Msg "Trying to export PlatformID `"$line`"" 
				if (![string]::IsNullOrEmpty($line)) { 
					export-platform $line 
					("$PlatformZipPath\$line.zip").Replace("\\", "\").Replace("/", "\") | Out-File -FilePath "$PlatformZipPath\_Exported.txt" -Append
				}		
			} 

		}
	}
	# Logoff the session

	# ------------------
	Write-LogMessage -Type Info -Msg "Logoff Session..."
	If ([string]::IsNullOrEmpty($logonToken)) {
		Write-LogMessage -Type Info -Msg "LogonToken passed, session NOT logged off"
	} else {
		Invoke-RestMethod -Method Post -Uri $URL_Logoff -Headers $logonHeader -ContentType "application/json" | Out-Null
	}
	
} else {
	Write-LogMessage -Type Error -Msg "This script requires PowerShell version 3 or above"
}

Write-LogMessage -Type Info -Msg "Export / Import Platform: Script Finished" 
