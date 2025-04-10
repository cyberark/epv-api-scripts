<# ###########################################################################

NAME: Account Link Utility

AUTHOR: Assaf Miron, Brian Bors

COMMENT:
This script will bulk Link Accounts from a CSV file using REST API.

SUPPORTED VERSIONS:
CyberArk Privilege Cloud
CyberArk PVWA v12.1 and above

VERSION HISTORY:
1.0 	0000-00-00	Initial version
1.1 	2025-04-09	New functionality and made add ability to change csv delimiter
########################################################################### #>
[CmdletBinding()]
param
(
	[Parameter(Mandatory = $true, HelpMessage = 'Enter the PVWA URL')]
	[Alias('url')]
	[String]$PVWAURL,

	[Parameter(Mandatory = $false, HelpMessage = 'Enter the Authentication type (Default:CyberArk)')]
	[ValidateSet('cyberark', 'ldap', 'radius')]
	[String]$AuthType = 'cyberark',

	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory = $false)]
	[Switch]$DisableSSLVerify,

	[Parameter(Mandatory = $true, HelpMessage = 'Path to a CSV file to export data to')]
	[Alias('path')]
	[string]$CSVPath,

	[Parameter(Mandatory = $false)]
	[switch]$concurrentSession,

	# Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off
	[Parameter(Mandatory = $false)]
	$logonToken,

	# Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off
	[Parameter(Mandatory = $false)]
	[string]$delimiter = ',',

	[Parameter(Mandatory = $false, HelpMessage = 'Vault Stored Credentials')]
	[PSCredential]$PVWACredentials,

	[Parameter(Mandatory = $false, DontShow, HelpMessage = 'Include Call Stack in Verbose output')]
	[switch]$IncludeCallStack,

	[Parameter(Mandatory = $false, DontShow)]
	[switch]$UseVerboseFile

)

# Get Script Location
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path

# Set Log file path
$StartTime = $(Get-Date -Format yyyyMMdd) + '-' + $(Get-Date -Format HHmmss)
$LOG_FILE_PATH = "$ScriptLocation\Link_Accounts_Utility-$StartTime.log"

$Global:ScriptName = $MyInvocation.MyCommand.Path.Replace("$ScriptLocation\", '')
$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent
$global:IncludeCallStack = $IncludeCallStack.IsPresent
$global:UseVerboseFile = $UseVerboseFile.IsPresent

# Global URLS
# -----------
$URL_PVWAAPI = $PVWAURL + '/api'
$URL_Authentication = $URL_PVWAAPI + '/auth'
$URL_Authentication = $URL_PVWAAPI + '/auth'
$URL_Logon = $URL_Authentication + "/$AuthType/Logon"
$URL_Logoff = $URL_Authentication + '/Logoff'

# URL Methods
# -----------
$URL_Accounts = $URL_PVWAAPI + '/Accounts'
$URL_LinkAccounts = $URL_PVWAAPI + '/Accounts/{0}/LinkAccount'

# Script Defaults
# ---------------

# Initialize Script Variables
# ---------------------------
$g_LogonHeader = ''

#region Functions
Function ConvertTo-URL($sText) {
	<#
.SYNOPSIS
	HTTP Encode test in URL
.DESCRIPTION
	HTTP Encode test in URL
.PARAMETER sText
	The text to encode
#>
	if (![string]::IsNullOrEmpty($sText)) {
		Write-LogMessage -type Verbose -MSG "Returning URL Encode of $sText"
		return [URI]::EscapeDataString($sText)
	}
	else {
		return $sText
	}
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
				$msgToWrite += "[ERROR]`t$Msg"
				if ($UseVerboseFile) {
					$msgToWrite | Out-File -Append -FilePath $verboseFile
				}
			}
			'Debug' {
				if ($InDebug -or $InVerbose) {
					Write-Debug $MSG
					$writeToFile = $true
					$msgToWrite += "[DEBUG]`t$Msg"
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
		[System.Management.Automation.ErrorRecord]$e
	)

	Begin {

	}
	Process {
		$Exception = $e.Exception
		$msg = 'Message: {0}' -f $Exception.Message
		while ($Exception.InnerException) {
			$Exception = $Exception.InnerException
			$msg = 'Message: {0}' -f $Exception.Message
		}
		return $msg
	}
	End {
	}
}
Function Join-ExceptionDetails {
	<#
.SYNOPSIS
	Formats exception messages
.DESCRIPTION
	Formats exception messages
.PARAMETER Exception
	The Exception object to format
#>
	param(
		[System.Management.Automation.ErrorRecord]$e
	)
	Begin {
	}
	Process {
		$Exception = $e.Exception
		$msg = 'Source:{0}; Message: {1}' -f $Exception.Source, $Exception.Message
		while ($Exception.InnerException) {
			$e = $Exception.InnerException
			$msg += "`n`t->Source:{0}; Message: {1}" -f $Exception.Source, $Exception.Message
		}
		return $msg
	}
	End {
	}
}

Function Open-FileDialog($initialDirectory) {
	[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null

	$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
	$OpenFileDialog.initialDirectory = $initialDirectory
	$OpenFileDialog.filter = 'CSV (*.csv)| *.csv'
	$OpenFileDialog.ShowDialog() | Out-Null
	$OpenFileDialog.filename
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
		[ValidateSet('GET', 'POST', 'DELETE', 'PATCH', 'PUT','HEAD')]
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
		[string]$ContentType = 'application/json',
		[switch]$UseBasicParsing,
		[switch]$DisableKeepAlive

	)
	Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tStart"
	$restResponse = ''
	try {
		if ([string]::IsNullOrEmpty($Body)) {
			Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tInvoke-RestMethod -Uri $URI -Method $Command -Header $($Header|ConvertTo-Json -Compress) -ContentType $ContentType -TimeoutSec $TimeoutSec -UseBasicParsing:$UseBasicParsing -DisableKeepAlive:$DisableKeepAlive"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType $ContentType -TimeoutSec $TimeoutSec -ErrorAction $ErrAction -Verbose:$false -Debug:$false -UseBasicParsing:$UseBasicParsing -DisableKeepAlive:$DisableKeepAlive
		}
		else {
			Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tInvoke-RestMethod -Uri $URI -Method $Command -Header $($Header|ConvertTo-Json -Compress) -ContentType $ContentType -Body $($Body|ConvertTo-Json -Compress) -TimeoutSec $TimeoutSec -UseBasicParsing:$UseBasicParsing -DisableKeepAlive:$DisableKeepAlive"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType $ContentType -Body $Body -TimeoutSec $TimeoutSec -ErrorAction $ErrAction -Verbose:$false -Debug:$false -UseBasicParsing:$UseBasicParsing -DisableKeepAlive:$DisableKeepAlive
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
			Else {
				Throw $PSItem
			}
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
			Write-LogMessage -type Error -MSG "$($Details.ErrorMessage)"
			exit 5
		}
		elseif ('SFWS0002' -eq $Details.ErrorCode) {
			Write-LogMessage -type Warning -MSG "$($Details.ErrorMessage)"
			Throw "$($Details.ErrorMessage)"
		}
		If ('SFWS0012' -eq $Details.ErrorCode) {
			Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.ErrorMessage)"
			Throw $PSItem
		}
		Else {
			Write-LogMessage -type Error -MSG "Error in running $Command on '$URI', $_.Exception"
			Throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $_.Exception))
		}
	}
	catch {
		Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tCaught Exception"
		Write-LogMessage -type Error -MSG "Error in running $Command on '$URI', $_.Exception"
		Throw $(New-Object System.Exception ("Error in running $Command on '$URI'", $_.Exception))
	}
	Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tResponse: $($restResponse|ConvertTo-Json -Compress)"
	return $restResponse
}
Function Add-SearchCriteria {
	param ([string]$sURL, [string]$sSearch, [string]$sSortParam, [string]$sSafeName, [int]$iLimitPage, [int]$iOffsetPage)
	[string]$retURL = $sURL
	$retURL += '?'

	if ($sSearch.Trim() -ne '') {
		$retURL += "search=$(ConvertTo-URL $sSearch)&"
	}
	if ($sSafeName.Trim() -ne '') {
		$retURL += "filter=safename eq $(ConvertTo-URL $sSafeName)&"
	}
	if ($sSortParam.Trim() -ne '') {
		$retURL += "sort=$(ConvertTo-URL $sSortParam)&"
	}
	if ($iLimitPage -gt 0) {
		$retURL += "limit=$iLimitPage&"
	}

	if ($retURL[-1] -eq '&') {
		$retURL = $retURL.substring(0, $retURL.length - 1)
	}

	return $retURL
}

Function Find-MasterAccount {
	param ($accountName, $accountAddress, $safeName)
	$result = $null
	try {
		$AccountsURLWithFilters = ''
		$Keywords = "$($accountName) $($accountAddress)"
		$AccountsURLWithFilters = $(Add-SearchCriteria -sURL $URL_Accounts -sSearch $Keywords -sSafeName $safeName)
		Write-LogMessage -type Verbose -MSG "Accounts Filter: $AccountsURLWithFilters"
		$GetMasterAccountsResponse = Invoke-Rest -Command Get -Uri $AccountsURLWithFilters -Header $global:g_LogonHeader
		If (($null -eq $GetMasterAccountsResponse) -or ($GetMasterAccountsResponse.count -eq 0)) {
			# No accounts found
			Write-LogMessage -type Verbose -MSG "Account `"$accountName`" does not exist"
			$result = $null
		}
		else {
			ForEach ($item in $GetMasterAccountsResponse.Value) {
				if ($item.userName -eq $accountName -and $item.address -eq $accountAddress) {
					$result = $item.id
					Write-LogMessage -type Verbose -MSG "Account `"$accountName`" with address of `"$accountAddress`" in safe `"$safeName`" has account ID of `"$result`""
					break
				}
			}
			# Account Exists
			Write-LogMessage -type Info -MSG "Account `"$accountName`" with address of `"$accountAddress`" in safe `"$safeName`" has account ID of `"$result`""
		}
		return $result
	}
	catch {
		Write-LogMessage -type Error -MSG $PSitem.Exception -ErrorAction 'SilentlyContinue'
	}
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
		[PSCredential] $Credentials,
		[Parameter(Mandatory = $false)]
		[string]$RadiusOTP,
		[Parameter(Mandatory = $false)]
		[boolean]$concurrentSession
	)

	if ([string]::IsNullOrEmpty($g_LogonHeader)) {
		# Disable SSL Verification to contact PVWA
		If ($DisableSSLVerify) {
			Disable-SSLVerification
		}

		# Create the POST Body for the Logon
		# ----------------------------------
		If ($concurrentSession) {
			$logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password; concurrentSession = $true } | ConvertTo-Json
		}
		else {
			$logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password } | ConvertTo-Json

		}
		# Check if we need to add RADIUS OTP
		If (![string]::IsNullOrEmpty($RadiusOTP)) {
			$logonBody.Password += ",$RadiusOTP"
		}
		try {
			# Logon
			$logonToken = Invoke-Rest -Method Post -Uri $URL_Logon -Body $logonBody -ContentType 'application/json' -TimeoutSec 2700

			# Clear logon body
			$logonBody = ''
		}
		catch {
			Throw $(New-Object System.Exception ("Get-LogonHeader: $($PSitem.Exception.Response.StatusDescription)", $PSitem.Exception))
		}

		$logonHeader = $null
		If ([string]::IsNullOrEmpty($logonToken)) {
			Throw 'Get-LogonHeader: Logon Token is Empty - Cannot login'
		}

		try {
			# Create a Logon Token Header (This will be used through out all the script)
			# ---------------------------
			$logonHeader = @{Authorization = $logonToken }

			Set-Variable -Name g_LogonHeader -Value $logonHeader -Scope global
		}
		catch {
			Throw $(New-Object System.Exception ('Get-LogonHeader: Could not create Logon Headers Dictionary', $PSitem.Exception))
		}
	}
}

Function Invoke-Logoff {
	<#
.SYNOPSIS
	Invoke-Logoff
.DESCRIPTION
	Logoff a PVWA session
#>
	try {
		# Logoff the session
		# ------------------
		If (![string]::IsNullOrEmpty($global:g_LogonHeader)) {
			Write-LogMessage -type Info -MSG 'Logoff Session...'
			Invoke-Rest -Method Post -Uri $URL_Logoff -Headers $global:g_LogonHeader -ContentType 'application/json' -TimeoutSec 2700 | Out-Null
			Set-Variable -Name g_LogonHeader -Value $null -Scope global
			Remove-Variable -Name g_LogonHeader -Scope Global
		}
	}
	catch {
		Throw $(New-Object System.Exception ('Invoke-Logoff: Failed to logoff session', $PSitem.Exception))
	}
}
Function Add-AccountLink {
	param ($linkBody, $MasterID)
	try {
		$retResult = $false

		Write-LogMessage -type Verbose -MSG "Invoke-Rest -Uri ($URL_LinkAccounts -f $MasterID) -Header $global:g_LogonHeader -Command 'POST' -Body $($linkBody | ConvertTo-Json -Compress)"
		$addLinkAccountBodyResult = $(Invoke-Rest -Uri $($URL_LinkAccounts -f $MasterID) -Header $global:g_LogonHeader -Command 'POST' -Body $($linkBody | ConvertTo-Json))
		If ($null -eq $addLinkAccountBodyResult) {
			# No accounts onboarded
			throw "There was an error linking account `"$($linkBody.name)`" to account ID `"$($MasterID)`"."
		}
		else {
			Write-LogMessage -type Info -MSG "Account `"$($linkBody.name)`" was successfully linked as ExtraPass$($linkBody.extraPasswordIndex)"
			$retResult = $true
		}
	}
	catch {
		Throw $PSitem
	}
	return $retResult
}

#endregion

# Check if to disable SSL verification
If ($DisableSSLVerify) {
	try {
		Write-Warning 'It is not Recommended to disable SSL verification' -WarningAction Inquire
		# Using Proxy Default credentials if the Server needs Proxy credentials
		[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
		# Using TLS 1.2 as security protocol verification
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
		# Disable SSL Verification
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
	}
	catch {
		Write-LogMessage -type Error -MSG 'Could not change SSL validation'
		Write-LogMessage -type Error -MSG $(Join-ExceptionMessage -e $PSitem) -ErrorAction 'SilentlyContinue'
		return
	}
}
Else {
	try {
		Write-LogMessage -type Verbose -MSG 'Setting script to use TLS 1.2'
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
	}
	catch {
		Write-LogMessage -type Error -MSG 'Could not change SSL settings to use TLS 1.2'
		Write-LogMessage -type Error -MSG $(Join-ExceptionMessage -e $PSitem)-ErrorAction 'SilentlyContinue'
	}
}

# Check that the PVWA URL is OK
If (![string]::IsNullOrEmpty($PVWAURL)) {
	If ($PVWAURL.Substring($PVWAURL.Length - 1) -eq '/') {
		$PVWAURL = $PVWAURL.Substring(0, $PVWAURL.Length - 1)
	}

	try {
		# Validate PVWA URL is OK
		Write-LogMessage -type Verbose -MSG "Trying to validate URL: $PVWAURL"
		Invoke-Rest -UseBasicParsing -DisableKeepAlive -Uri $PVWAURL -Method 'Head' -TimeoutSec 30 | Out-Null
	}
	catch [System.Net.WebException] {
		If (![string]::IsNullOrEmpty($PSitem.Exception.Response.StatusCode.Value__)) {
			Write-LogMessage -type Error -MSG $PSitem.Exception.Response.StatusCode.Value__
		}
	}
	catch {
		Write-LogMessage -type Error -MSG 'PVWA URL could not be validated'
		Write-LogMessage -type Error -MSG $(Join-ExceptionMessage -e $PSitem) -ErrorAction 'SilentlyContinue'
		Write-LogMessage -type Verbose -MSG $(Join-ExceptionDetails -e $PSitem) -ErrorAction 'SilentlyContinue'
	}
}
else {
	Write-LogMessage -type Error -MSG 'PVWA URL can not be empty'
	return
}

# Header
Write-LogMessage -type Info -MSG 'Welcome to the Account Link Utility' -Header
Write-LogMessage -type Info -MSG 'Getting PVWA Credentials to start Linking accounts' -SubHeader

#region [Logon]
try {
	# Get Credentials to Login
	# ------------------------
	$caption = 'Safe Management'

	If (![string]::IsNullOrEmpty($logonToken)) {
		if ($logonToken.GetType().name -eq 'String') {
			$logonHeader = @{Authorization = $logonToken }
			Set-Variable -Name g_LogonHeader -Value $logonHeader -Scope global
		}
		else {
			Set-Variable -Name g_LogonHeader -Value $logonToken -Scope global
		}
	}
	elseif (![string]::IsNullOrEmpty($PVWACredentials)) {
		Get-LogonHeader -Credentials $PVWACredentials
	}
	elseif ($null -eq $creds) {
		$msg = 'Enter your User name and Password'
		$creds = $Host.UI.PromptForCredential($caption, $msg, '', '')
		Get-LogonHeader -Credentials $creds -concurrentSession $concurrentSession
	}
	else {
		Write-LogMessage -type Error -MSG 'No Credentials were entered'
		return
	}
}
catch {
	Write-LogMessage -type Error -MSG "Error Logging on. Error: $(Join-ExceptionMessage $_.Exception)"
	return
}
#endregion

#region [Read Accounts CSV file and link Accounts]
If ([string]::IsNullOrEmpty($CsvPath)) {
	$CsvPath = Open-FileDialog($g_CsvDefaultPath)
}

Write-LogMessage -type Info -MSG 'Importing accounts to link'
[PSCustomObject[]]$accountsCSV = Import-Csv $csvPath -Delimiter $delimiter
$badAccounts = "$csvPath.bad.csv"
Remove-Item $csvPathBad -Force -ErrorAction SilentlyContinue

$masterCount = @($accountsCSV | Select-Object -Property userName, address, safe -Unique).Count
Write-LogMessage -type Info -MSG "Found a total of $masterCount accounts with links"

$ExtraPass1Count = @($accountsCSV | Where-Object ExtraPass1Name -NE '' ).count
Write-LogMessage -type Info -MSG "A total of $ExtraPass1Count ExtraPass1 accounts found"
$ExtraPass2Count = @($accountsCSV | Where-Object ExtraPass2Name -NE '' ).count
Write-LogMessage -type Info -MSG "A total of $ExtraPass2Count ExtraPass2 accounts found"
$ExtraPass3Count = @($accountsCSV | Where-Object ExtraPass3Name -NE '' ).count
Write-LogMessage -type Info -MSG "A total of $ExtraPass3Count ExtraPass3 accounts found"
$linkCount = $ExtraPass1Count + $ExtraPass2Count + $ExtraPass3Count
Write-LogMessage -type Info -MSG "A total of $linkCount account links found"

$counterMaster = 0
$ExtraPass1Succes = 0
$ExtraPass1Failed = 0
$ExtraPass2Succes = 0
$ExtraPass2Failed = 0
$ExtraPass3Succes = 0
$ExtraPass3Failed = 0
Write-LogMessage -type Info -MSG "Starting to add links to $masterCount master accounts"
ForEach ($account in $accountsCSV) {
	if (![string]::IsNullOrEmpty($account)) {
		# Search for Master Account
		$foundMasterAccountID = $null
		try {
			Write-LogMessage -type Info -MSG "Searching for Master Account with username `"$($account.userName)`" with address `"$($account.address)`" in safe `"$($account.safe)`"."
			$foundMasterAccountID = Find-MasterAccount -accountName $($account.userName) -accountAddress $($account.address) -safeName $($account.safe)
			if ([string]::IsNullOrEmpty($foundMasterAccountID))
			{ Throw 'No Master Account Found' }
		}
		catch {
			$bad = $account | Select-Object -Property *, 'Fail'
			$bad.Fail = $PSitem.Exception.Message
			$bad | Export-Csv -Append -NoTypeInformation -Path $badAccounts
			Write-LogMessage -type Error -MSG "Error searching for Master Account with username `"$($account.userName)`" with address `"$($account.address)`" in safe `"$($account.safe)`"."
			Write-LogMessage -type Error -MSG $(Join-ExceptionMessage -e $PSitem) -ErrorAction 'SilentlyContinue'
			Write-LogMessage -type Verbose -MSG $(Join-ExceptionDetails -e $PSitem) -ErrorAction 'SilentlyContinue'
			continue
		}
		Try {
			#If logon account is found link
			if (![string]::IsNullOrEmpty($account.ExtraPass1Name)) {
				Try {
					if ([string]::IsNullOrEmpty($account.ExtraPass1Safe)) {
						Write-LogMessage -type Error -MSG "ExtraPass1Safe is empty for account with username `"$($account.userName)`" with address `"$($account.address)`" in safe `"$($account.safe)`" and unable to continue."
						$ExtraPass1Failed++
						$bad = $account | Select-Object -Property *, 'Fail'
						$bad.Fail = 'ExtraPass1Safe is not populated'
						$bad | Export-Csv -Append -NoTypeInformation -Path $badAccounts
					}
					$addLinkAccountBody = @{
						'safe'               = $account.ExtraPass1Safe.Trim()
						'name'               = $account.ExtraPass1Name.Trim()
						'folder'             = if ([string]::IsNullOrEmpty($account.ExtraPass1Folder)) { 'Root' } else { $account.ExtraPass1Folder.Trim() }
						'extraPasswordIndex' = '1'
					}
					if (Add-AccountLink -linkBody $addLinkAccountBody -MasterID $foundMasterAccountID) {
						$ExtraPass1Succes++
					}
				}
				Catch {
					$bad = $account | Select-Object -Property *, 'Fail'
					$bad.Fail = "$(Join-ExceptionMessage $PSitem)"
					$bad | Export-Csv -Append -NoTypeInformation -Path $badAccounts
					Write-LogMessage -type Error -MSG "Error adding ExtraPass1 with name of `"$($account.ExtraPass1Name)`" in safe `"$($account.ExtraPass1Safe)`" to Account with username `"$($account.userName)`" with address `"$($account.address)`" in safe `"$($account.safe)`""
					Write-LogMessage -type Error -MSG "$(Join-ExceptionMessage $PSitem)"
					Write-LogMessage -type Verbose -MSG "$(Join-ExceptionDetails $PSitem)"
					$ExtraPass1Failed++
				}
			}
			#If enable account is found link
			if (![string]::IsNullOrEmpty($account.ExtraPass2Name)) {
				Try {
					$addLinkAccountBody = @{
						'safe'               = $account.ExtraPass2Safe.Trim()
						'name'               = $account.ExtraPass2Name.Trim()
						'folder'             = if ([string]::IsNullOrEmpty($account.ExtraPass2Folder)) { 'Root' } else { $account.ExtraPass2Folder.Trim() }
						'extraPasswordIndex' = '2'
					}
					if (Add-AccountLink -linkBody $addLinkAccountBody -MasterID $foundMasterAccountID) {
						$ExtraPass2Succes++
					}
				}
				Catch {
					$bad = $account | Select-Object -Property *, 'Fail'
					$bad.Fail = "$(Join-ExceptionMessage $PSitem)"
					$bad | Export-Csv -Append -NoTypeInformation -Path $badAccounts
					Write-LogMessage -type Error -MSG "Error adding ExtraPass2 with name of `"$($account.ExtraPass2Name)`" in safe `"$($account.ExtraPass2Safe)`" to Account with username `"$($account.userName)`" with address `"$($account.address)`" in safe `"$($account.safe)`""
					Write-LogMessage -type Error -MSG "$(Join-ExceptionMessage $PSitem)"
					Write-LogMessage -type Verbose -MSG "$(Join-ExceptionDetails $PSitem)"
					$ExtraPass2failed++
				}
			}

			#If reconcile account is found link
			if (![string]::IsNullOrEmpty($account.ExtraPass3Name)) {
				Try {
					$addLinkAccountBody = @{
						'safe'               = $account.ExtraPass3Safe.Trim()
						'name'               = $account.ExtraPass3Name.Trim()
						'folder'             = if ([string]::IsNullOrEmpty($account.ExtraPass3Folder)) { 'Root' } else { $account.ExtraPass3Folder.Trim() }
						'extraPasswordIndex' = '3'
					}
					if (Add-AccountLink -linkBody $addLinkAccountBody -MasterID $foundMasterAccountID) {
						$ExtraPass3Succes++
					}
				}
				Catch {
					$bad = $account | Select-Object -Property *, 'Fail'
					$bad.Fail = "$(Join-ExceptionMessage $PSitem)"
					$bad | Export-Csv -Append -NoTypeInformation -Path $badAccounts
					Write-LogMessage -type Error -MSG "Error adding ExtraPass2 with name of `"$($account.ExtraPass3Name)`" in safe `"$($account.ExtraPass3safe)`" to Account with username `"$($account.userName)`" with address `"$($account.address)`" in safe `"$($account.safe)`""
					Write-LogMessage -type Error -MSG "$(Join-ExceptionMessage $PSitem)"
					Write-LogMessage -type Verbose -MSG "$(Join-ExceptionDetails $PSitem)"
					$ExtraPass3Failed++
				}
			}
		}
		Catch {
			$bad = $account | Select-Object -Property *, 'Fail'
			$bad.Fail = "$(Join-ExceptionMessage $PSitem)"
			$bad | Export-Csv -Append -NoTypeInformation -Path $badAccounts
			Write-LogMessage -type Error -MSG "Error linking Master Account - Username: `"$($account.userName)`" Address: `"$($account.address)`" Safe: `"$($account.safe)`""
			Write-LogMessage -type Verbose -MSG "$(Join-ExceptionDetails $PSItem)"
		}
		$counterMaster++

	}
}

#endregion

#region [Logoff]
# Logoff the session
# ------------------

If (![string]::IsNullOrEmpty($logonToken)) {
	Write-Host 'LogonToken passed, session NOT logged off'
}
elseIf ($concurrentSession) {
	Write-Host 'concurrentSession passed, session NOT logged off'
}
else {
	Invoke-Logoff
}

# Footer
Write-LogMessage -type Info -MSG "A total of $counterMaster accounts with $masterCount links imported"
Write-LogMessage -type Info -MSG "A total of $ExtraPass1Succes ExtraPass1 links out of $ExtraPass1Count links where created successfully."
Write-LogMessage -type Info -MSG "A total of $ExtraPass2Succes ExtraPass2 links out of $ExtraPass2Count links where created successfully."
Write-LogMessage -type Info -MSG "A total of $ExtraPass3Succes ExtraPass3 links out of $ExtraPass3Count links where created successfully."
Write-LogMessage -type Info -MSG "A total of $($ExtraPass1Succes + $ExtraPass2Succes + $ExtraPass3Succes) individual links out of $linkCount links where created successfully."
#endregion
