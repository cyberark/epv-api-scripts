###########################################################################
#
# NAME: Import Connection Components
#
# AUTHOR:  Assaf Miron
#
# COMMENT:
# This script will Import a single or multiple connection components using REST API
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v10.4 and above
#
#
###########################################################################

param
(
	[Parameter(Mandatory = $true, HelpMessage = 'Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)')]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias('url')]
	[String]$PVWAURL,

	[Parameter(Mandatory = $false, HelpMessage = 'Enter the Authentication type (Default:CyberArk)')]
	[ValidateSet('cyberark', 'ldap', 'radius')]
	[String]$AuthType = 'cyberark',

	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory = $false)]
	[Switch]$DisableSSLVerify,

	[Parameter(Mandatory = $false, HelpMessage = 'Enter the Connection Component Zip path to import')]
	[Alias('ConnectionComponent')]
	[string]$ConnectionComponentZipPath,

	[Parameter(Mandatory = $false, HelpMessage = 'Enter a folder path for Connection Components Zip files to import')]
	[Alias('Folder')]
	[string]$ConnectionComponentFolderPath,

	# Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off
	[Parameter(Mandatory = $false)]
	$logonToken

)

# Get Script Location
$ScriptFullPath = $MyInvocation.MyCommand.Path
$ScriptLocation = Split-Path -Parent $ScriptFullPath
$ScriptParameters = @()
$PSBoundParameters.GetEnumerator() | ForEach-Object { $ScriptParameters += ("-{0} '{1}'" -f $_.Key, $_.Value) }
$global:g_ScriptCommand = '{0} {1}' -f $ScriptFullPath, $($ScriptParameters -join ' ')

# Script Version
$ScriptVersion = '1.0.1'

# Set Log file path
$global:LOG_DATE = $(Get-Date -Format yyyyMMdd) + '-' + $(Get-Date -Format HHmmss)
$global:LOG_FILE_PATH = "$ScriptLocation\Import-ConnectionComponents-$LOG_DATE.log"

$InDebug = $PSBoundParameters.Debug.IsPresent
$InVerbose = $PSBoundParameters.Verbose.IsPresent
$global:IncludeCallStack = $IncludeCallStack.IsPresent
$global:UseVerboseFile = $UseVerboseFile.IsPresent

#region Functions
function Format-PVWAURL {
	param (
		[Parameter()]
		[string]
		$PVWAURL
	)
	#check url scheme to ensure it's secure and add https if not present
	IF ($PVWAURL -match '^(?<scheme>https:\/\/|http:\/\/|).*$') {
		if ('http://' -eq $matches['scheme'] -and $AllowInsecureURL -eq $false) {
			$PVWAURL = $PVWAURL.Replace('http://', 'https://')
			Write-LogMessage -type Warning -MSG "Detected inscure scheme in URL `nThe URL was automaticly updated to: $PVWAURL `nPlease ensure you are using the correct scheme in the url"
		}
		elseif ([string]::IsNullOrEmpty($matches['scheme'])) {
			$PVWAURL = "https://$PVWAURL"
			Write-LogMessage -type Warning -MSG "Detected no scheme in URL `nThe URL was automaticly updated to: $PVWAURL `nPlease ensure you are using the correct scheme in the url"
		}
	}

	#check url for improper Privilege Cloud URL and add /PasswordVault/ if not present
	if ($PVWAURL -match '^(?:https|http):\/\/(?<sub>.*).cyberark.(?<top>cloud|com)\/privilegecloud.*$') {
		$PVWAURL = "https://$($matches['sub']).privilegecloud.cyberark.$($matches['top'])/PasswordVault/"
		Write-LogMessage -type Warning -MSG "Detected improperly formated Privilege Cloud URL `nThe URL was automaticly updated to: $PVWAURL `nPlease ensure you are using the correct URL. Pausing for 10 seconds to allow you to copy correct url.`n"
		Start-Sleep 10
	}
	elseif ($PVWAURL -notmatch '^.*PasswordVault(?:\/|)$') {
		$PVWAURL = "$PVWAURL/PasswordVault/"
		Write-LogMessage -type Warning -MSG "Detected improperly formated Privileged Access Manager URL `nThe URL was automaticly updated to: $PVWAURL `nPlease ensure you are using the correct URL. Pausing for 10 seconds to allow you to copy correct url.`n"
		Start-Sleep 10
	}
	return $PVWAURL
}

Function Disable-SSLVerification {
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
	if (-not('DisableCertValidationCallback' -as [type])) {
		Add-Type -TypeDefinition @'
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
'@
 }

	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = [DisableCertValidationCallback]::GetDelegate()
}

Function Get-ZipContent {
	Param($zipPath)

	$zipContent = $null
	try {
		If (Test-Path $zipPath) {
			Write-Debug 'Reading ZIP file...'
			$zipContent = [System.IO.File]::ReadAllBytes($(Resolve-Path $zipPath))
			If ([string]::IsNullOrEmpty($zipContent)) { throw 'Zip file empty or error reading it' }
			Write-Debug "Zip file size read $($zipContent.Length)"
			# Converting to Base64, following bug 00015428
			$zipContent = [Convert]::ToBase64String($zipContent)
		}
	}
 catch {
		throw "Error while reading ZIP file: $($_.Exception.Message)"
	}

	return $zipContent
}

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
		[ValidateSet('Info', 'Warning', 'Error', 'Debug', 'Verbose')]
		[String]$type = 'Info',
		[Parameter(Mandatory = $false)]
		[String]$LogFile = $LOG_FILE_PATH,
		[Parameter(Mandatory = $false)]
		[int]$pad = 20
	)

	$verboseFile = $($LOG_FILE_PATH.replace('.log', '_Verbose.log'))
	try {
		If ($Header) {
			'=======================================' | Out-File -Append -FilePath $LOG_FILE_PATH
			Write-Host '======================================='
		}
		ElseIf ($SubHeader) {
			'------------------------------------' | Out-File -Append -FilePath $LOG_FILE_PATH
			Write-Host '------------------------------------'
		}

		$LogTime = "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')]`t"
		$msgToWrite += "$LogTime"
		$writeToFile = $true
		# Replace empty message with 'N/A'
		if ([string]::IsNullOrEmpty($Msg)) {
			$Msg = 'N/A'
		}
		# Mask Passwords
		if ($Msg -match '((?:"password"|"secret"|"NewCredentials")\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w!@#$%^&*()-\\\/]+))') {
			$Msg = $Msg.Replace($Matches[2], '****')
		}
		# Check the message type
		switch ($type) {
			'Info' {
				Write-Host $MSG.ToString()
				$msgToWrite += "[INFO]`t`t$Msg"
			}
			'Warning' {
				Write-Host $MSG.ToString() -ForegroundColor DarkYellow
				$msgToWrite += "[WARNING]`t$Msg"
				if ($UseVerboseFile) {
					$msgToWrite | Out-File -Append -FilePath $verboseFile
				}
			}
			'Error' {
				Write-Host $MSG.ToString() -ForegroundColor Red
				$msgToWrite += "[ERROR]`t`t$Msg"
				if ($UseVerboseFile) {
					$msgToWrite | Out-File -Append -FilePath $verboseFile
				}
			}
			'Debug' {
				if ($InDebug -or $InVerbose) {
					Write-Debug $MSG
					$writeToFile = $true
					$msgToWrite += "[DEBUG]`t`t$Msg"
				}
				else {
					$writeToFile = $False
				}
			}
			'Verbose' {
				if ($InVerbose -or $VerboseFile) {
					$arrMsg = $msg.split(":`t", 2)
					if ($arrMsg.Count -gt 1) {
						$msg = $arrMsg[0].PadRight($pad) + $arrMsg[1]
					}
					$msgToWrite += "[VERBOSE]`t$Msg"
					if ($global:IncludeCallStack) {
						function Get-CallStack {
							$stack = ''
							$excludeItems = @('Write-LogMessage', 'Get-CallStack', '<ScriptBlock>')
							Get-PSCallStack | ForEach-Object {
								If ($PSItem.Command -notin $excludeItems) {
									$command = $PSitem.Command
									If ($command -eq $Global:scriptName) {
										$command = 'Base'
									}
									elseif ([string]::IsNullOrEmpty($command)) {
										$command = '**Blank**'
									}
									$Location = $PSItem.Location
									$stack = $stack + "$command $Location; "
								}
							}
							return $stack
						}
						$stack = Get-CallStack
						$stackMsg = "CallStack:`t$stack"
						$arrstackMsg = $stackMsg.split(":`t", 2)
						if ($arrMsg.Count -gt 1) {
							$stackMsg = $arrstackMsg[0].PadRight($pad) + $arrstackMsg[1].trim()
						}
						Write-Verbose $stackMsg
						$msgToWrite += "`n$LogTime"
						$msgToWrite += "[STACK]`t`t$stackMsg"
					}
					if ($InVerbose) {
						Write-Verbose $MSG
					}
					else {
						$writeToFile = $False
					}
					if ($UseVerboseFile) {
						$msgToWrite | Out-File -Append -FilePath $verboseFile
					}
				}
				else {
					$writeToFile = $False
				}
			}
		}
		If ($writeToFile) {
			$msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH
		}
		If ($Footer) {
			'=======================================' | Out-File -Append -FilePath $LOG_FILE_PATH
			Write-Host '======================================='
		}
	}
	catch {
		Write-Error "Error in writing log: $($_.Exception.Message)"
	}
}

Function Invoke-Rest {
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
(Optional) The Error Action to perform in case of error. By default "Continue"
#>
	param (
		[Parameter(Mandatory = $true)]
		[ValidateSet('GET', 'POST', 'DELETE', 'PATCH', 'PUT')]
		[Alias('Method')]
		[String]$Command,
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String]$URI,
		[Parameter(Mandatory = $false)]
		[Alias('Headers')]
		$Header,
		[Parameter(Mandatory = $false)]
		$Body,
		[Parameter(Mandatory = $false)]
		[ValidateSet('Continue', 'Ignore', 'Inquire', 'SilentlyContinue', 'Stop', 'Suspend')]
		[String]$ErrAction = 'Continue',
		[Parameter(Mandatory = $false)]
		[int]$TimeoutSec = 2700,
		[Parameter(Mandatory = $false)]
		[string]$ContentType = 'application/json'

	)
	Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tStart"
	$restResponse = ''
	try {
		if ([string]::IsNullOrEmpty($Body)) {
			Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tInvoke-RestMethod -Uri $URI -Method $Command -Header $($Header|ConvertTo-Json -Compress) -ContentType $ContentType -TimeoutSec $TimeoutSec"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType $ContentType -TimeoutSec $TimeoutSec -ErrorAction $ErrAction -Verbose:$false -Debug:$false
		}
		else {
			Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tInvoke-RestMethod -Uri $URI -Method $Command -Header $($Header|ConvertTo-Json -Compress) -ContentType $ContentType -Body $($Body|ConvertTo-Json -Compress) -TimeoutSec $TimeoutSec"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType $ContentType -Body $Body -TimeoutSec $TimeoutSec -ErrorAction $ErrAction -Verbose:$false -Debug:$false
		}
		Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tInvoke-RestMethod completed without error"
	}
	catch [System.Net.WebException] {
		Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tCaught WebException"
		if ($ErrAction -match ('\bContinue\b|\bInquire\b|\bStop\b|\bSuspend\b')) {
			Write-LogMessage -type Error -MSG "Error Message: $_"
			Write-LogMessage -type Error -MSG "Exception Message: $($_.Exception.Message)"
			Write-LogMessage -type Error -MSG "Status Code: $($_.Exception.Response.StatusCode.value__)"
			Write-LogMessage -type Error -MSG "Status Description: $($_.Exception.Response.StatusDescription)"
			$restResponse = $null
			Throw
		}
		Else {
			Throw $PSItem
		}
	}

	catch [Microsoft.PowerShell.Commands.HttpResponseException] {
		Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tCaught HttpResponseException"
		$Details = ($PSItem.ErrorDetails.Message | ConvertFrom-Json)
		If ('SFWS0007' -eq $Details.ErrorCode) {
			Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.ErrorMessage)"
			Throw $PSItem
		}
		elseif ('PASWS013E' -eq $Details.ErrorCode) {
			Write-LogMessage -type Error -MSG "$($Details.ErrorMessage)" -Header -Footer
			Throw "$($Details.ErrorMessage)"
		}
		elseif ('SFWS0002' -eq $Details.ErrorCode) {
			Write-LogMessage -type Warning -MSG "$($Details.ErrorMessage)"
			Throw "$($Details.ErrorMessage)"
		}
		elseif ('SFWS0012' -eq $Details.ErrorCode) {
			Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.ErrorMessage)"
			Throw $PSItem
		}
		elseif ('PASWS011E' -eq $Details.Details.Errorcode) {
			Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.Details.ErrorMessage)"
			Throw $PSItem
		}
		IF ($null -eq $Details.Details.Errorcode) {
			Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tError in running $Command on '$URI', $_.Exception"
			Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.ErrorMessage)"
			Throw $PSItem.Exception
		}
		Else {
			Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tError in running $Command on '$URI', $($($Details.Details.ErrorMessage) -Join ';')"
			Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.Details.ErrorMessage)"
			Throw $($Details.Details.ErrorMessage)
		}
	}
	catch {
		Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tCaught Exception"
		Write-LogMessage -type Error -MSG "Error in running $Command on '$URI', $_.Exception"
		Throw $(New-Object System.Exception ("Error in running $Command on '$URI'", $_.Exception))
	}
	Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tResponse: $restResponse"
	return $restResponse
}

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
		$logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password; concurrentSession = 'true' } | ConvertTo-Json -Compress
	}
	else {
		$logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password } | ConvertTo-Json -Compress
	}
	If (![string]::IsNullOrEmpty($RadiusOTP)) {
		$logonBody.Password += ",$RadiusOTP"
	}

	try {
		# Logon
		$logonToken = Invoke-Rest -Command Post -Uri $URL_Logon -Body $logonBody
		# Clear logon body
		$logonBody = ''
	}
	catch {
		Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.Exception.Response.StatusDescription)", $_.Exception))
	}

	$logonHeader = $null
	If ([string]::IsNullOrEmpty($logonToken)) {
		Throw 'Get-LogonHeader: Logon Token is Empty - Cannot login'
	}

	# Create a Logon Token Header (This will be used through out all the script)
	# ---------------------------
	$logonHeader = @{Authorization = $logonToken }

	return $logonHeader
}

#endregion

Write-LogMessage -type Info -MSG 'Import Connection Component: Script Started'
# Disable SSL Verification to contact PVWA
If ($DisableSSLVerify) {
	Disable-SSLVerification
}


# Global URLS
# -----------

$URL_PVWAURL = Format-PVWAURL($PVWAURL)
$URL_PVWAAPI = $URL_PVWAURL + '/api'
$URL_Authentication = $URL_PVWAAPI + '/auth'
$URL_Logon = $URL_Authentication + "/$AuthType/Logon"
$URL_Logoff = $URL_Authentication + '/Logoff'


# URL Methods
# -----------
$URL_ImportConnectionComponent = $URL_PVWAAPI + '/ConnectionComponents/Import'

# Initialize Script Variables
# ---------------------------
$global:g_LogonHeader = ''


#region [Logon]
# Get Credentials to Login
# ------------------------
$caption = 'Import Connection Component'
If (![string]::IsNullOrEmpty($logonToken)) {
	if ($logonToken.GetType().name -eq 'String') {
		$logonHeader = @{Authorization = $logonToken }
		Set-Variable -Scope Global -Name g_LogonHeader -Value $logonHeader
	}
	else {
		Set-Variable -Scope Global -Name g_LogonHeader -Value $logonToken
	}
}
else {
	If (![string]::IsNullOrEmpty($PVWACredentials)) {
		$creds = $PVWACredentials
	}
	else {
		$msg = "Enter your $AuthType User name and Password"
		$creds = $Host.UI.PromptForCredential($caption, $msg, '', '')
	}
	if ($AuthType -eq 'radius' -and ![string]::IsNullOrEmpty($OTP)) {
		Set-Variable -Scope Global -Name g_LogonHeader -Value $(Get-LogonHeader -Credentials $creds -concurrentSession $true -RadiusOTP $OTP )
	}
	else {
		Set-Variable -Scope Global -Name g_LogonHeader -Value $(Get-LogonHeader -Credentials $creds -concurrentSession $true)
	}
	# Verify that we successfully logged on
	If ($null -eq $g_LogonHeader) {
		return # No logon header, end script
	}
}
#endregion

$arrConCompToImport = @()

If (([string]::IsNullOrEmpty($ConnectionComponentZipPath)) -and (![string]::IsNullOrEmpty($ConnectionComponentFolderPath))) {
	# Get all Connection Components from a folder
	$arrConCompToImport += (Get-ChildItem -Path $ConnectionComponentFolderPath -Filter '*.zip' | Select-Object -ExpandProperty FullName)
}
ElseIf ((![string]::IsNullOrEmpty($ConnectionComponentZipPath)) -and ([string]::IsNullOrEmpty($ConnectionComponentFolderPath))) {
	# Get the entered Connection Component ZIP
	$arrConCompToImport = $ConnectionComponentZipPath
}
Else {
	Write-LogMessage -type Info -MSG 'No Connection Component path was entered.'
	$arrConCompToImport = Read-Host 'Please enter a Connection Component ZIP path'
}

ForEach ($connCompItem in $arrConCompToImport) {
	If (Test-Path $connCompItem) {
		$importBody = @{ ImportFile = $(Get-ZipContent $connCompItem); } | ConvertTo-Json -Depth 3 -Compress
		try {
			$ImportCCResponse = Invoke-Rest -Method POST -Uri $URL_ImportConnectionComponent -Headers $g_LogonHeader -ContentType 'application/json' -TimeoutSec 2700 -Body $importBody
			$connectionComponentID = ($ImportCCResponse.ConnectionComponentID)
			Write-LogMessage -type Info -MSG  "Connection Component ID imported: $connectionComponentID"
		}
		catch {
			if ($_.Exception.Response.StatusCode -like '*Conflict*') {
				Write-LogMessage -type Warning -MSG "Connection component `"$connCompItem`" already exists in the vault. Manually delete the connection component from the vault and re-run the script to import it again."
			}
			Else {
				Write-LogMessage -type Error -MSG  "Error importing connection component `"$connCompItem`", Error: $($_.Exception.Message)"
			}
		}
	}
}

#region [Logoff]
# Logoff the session
# ------------------
If (![string]::IsNullOrEmpty($logonToken)) {
	Write-Host 'LogonToken passed, session NOT logged off'
}
else {
	Write-Host 'Logoff Session...'
	Invoke-Rest -Uri $URL_Logoff -Header $g_LogonHeader -Command 'Post'
}


Write-Host 'Import Connection Component: Script Ended' -ForegroundColor Cyan
