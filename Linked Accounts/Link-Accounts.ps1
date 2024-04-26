###########################################################################
#
# NAME: Account Link Utility
#
# AUTHOR:  Assaf Miron, Brian Bors
#
# COMMENT:
# This script will bulk Link Accounts from a CSV file using REST API.
#
# SUPPORTED VERSIONS:
# CyberArk Privilege Cloud
# CyberArk PVWA v12.1 and above
#
#
###########################################################################
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
	$logonToken
	
)


# Get Script Location
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path

# Set Log file path
$LOG_DATE = $(Get-Date -Format yyyyMMdd) + '-' + $(Get-Date -Format HHmmss)
$LOG_FILE_PATH = "$ScriptLocation\Link_Accounts_Utility-$Log_Date.log"

$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent

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
$URL_Server = $URL_PVWAAPI + '/Server'

# Script Defaults
# ---------------

# Initialize Script Variables
# ---------------------------
$g_LogonHeader = ''

#region Functions
Function Test-CommandExists {
	Param ($command)
	$oldPreference = $ErrorActionPreference
	$ErrorActionPreference = 'stop'
	try {
		if (Get-Command $command) {
			RETURN $true
		}
	}
 Catch {
		Write-Host "$command does not exist"; RETURN $false
	}
 Finally {
		$ErrorActionPreference = $oldPreference
	}
} #end function test-CommandExists

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
		Write-Debug "Returning URL Encode of $sText"
		return [URI]::EscapeDataString($sText)
	}
 else {
		return $sText
	}
}
Function Test-Unicode {
	param (
		[string]
		$inputText 
	)
	IF ([string]::IsNullOrEmpty($inputText)) {
		Return $inputText
	}
	$nonASCII = '[^\x00-\x7F]'
	if ($inputText -cmatch $nonASCII) {
		$output = ''
		$inputText.ToCharArray() | ForEach-Object { 
			if ($PSItem -cmatch $nonASCII) {
				$UniCode = "{$(([uint16] [char]$psitem).ToString('X4'))}"
				$output = "$output$($UniCode)"
			}
			else { $output = "$output$($PSitem)" }
		}
		return $output
	}
	else { 
		return $inputText
	}
}

Function Test-RESTVersion {
	<#
.SYNOPSIS
Tests if the requested version exists in the PVWA REST API
.DESCRIPTION
Tests if the requested version exists in the PVWA REST API
.PARAMETER Version
A string of the requested PVWA REST version to test
#>

	param (
		[Parameter(Mandatory = $true)]
		[string]$version
	)

	$retVersionExists = $false
	try {
		Write-LogMessage -Type debug -Msg "Testing to see if the PVWA is at least in version $version"
		$serverResponse = Invoke-REST -Command GET -URI $URL_Server
		if ($null -ne $serverResponse) {
			Write-LogMessage -Type debug -Msg "The current PVWA is in version $($serverResponse.ExternalVersion)"
			If ([version]($serverResponse.InternalVersion) -ge [version]$version) { $retVersionExists = $true }
		}
		else {
			Throw 'An error occurred while testing the PVWA version'
		}

		return $retVersionExists
	}
 catch {
		# Check the error code returned from the REST call
		$innerExcp = $_.Exception.InnerException
		Write-LogMessage -Type Verbose -Msg "Status Code: $($innerExcp.StatusCode); Status Description: $($innerExcp.StatusDescription); REST Error: $($innerExcp.CyberArkErrorMessage)"
		if ($innerExcp.StatusCode -eq 'NotFound') {
			return $false
		}
		else {
			Throw $(New-Object System.Exception ("Test-RESTVersion: There was an error checking for REST version $version.", $PSitem.Exception))
		}
	}
}
Function ConvertTo-Date($epochdate) {
	if (($epochdate).length -gt 10 ) {
		return (Get-Date -Date '01/01/1970').AddMilliseconds($epochdate)
 }
 else {
		return (Get-Date -Date '01/01/1970').AddSeconds($epochdate)
 }
}

Function ConvertTo-EPOCHDate($inputDate) {
	return (New-TimeSpan -Start (Get-Date '01/01/1970') -End ($inputDate)).TotalSeconds
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
		[String]$LogFile = $LOG_FILE_PATH
	)
	$MSG = Test-Unicode -inputTest $MSG
	Try {
		If ($Header) {
			'=======================================' | Out-File -Append -FilePath $LogFile
			Write-Output '======================================='
		}
		ElseIf ($SubHeader) {
			'------------------------------------' | Out-File -Append -FilePath $LogFile
			Write-Output '------------------------------------'
		}

		$msgToWrite = "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')]`t"
		$writeToFile = $true
		# Replace empty message with 'N/A'
		if ([string]::IsNullOrEmpty($Msg)) {
			$Msg = 'N/A' 
  }

		# Mask Passwords
		if ($Msg -match '((?:"password":|password=|"secret":|"NewCredentials":|"credentials":)\s{0,}["]{0,})(?=([\w`~!@#$%^&*()-_\=\+\\\/|;:\.,\[\]{}]+))') {
			$Msg = $Msg.Replace($Matches[2], '****')
		}
		# Check the message type
		switch ($type) {

			'Info' {
				Write-Host $MSG.ToString()
				$msgToWrite += "[INFO]`t$Msg"
			}
			'Warning' {
				Write-Warning $MSG.ToString() -WarningAction ([System.Management.Automation.ActionPreference]::Continue)
				$msgToWrite += "[WARNING]`t$Msg"
			}
			'Error' {
				Write-Host $MSG.ToString() -ForegroundColor Red
				$msgToWrite += "[ERROR]`t$Msg"
			}
			'Debug' {
				if ($InDebug -or $InVerbose) {
					Write-Debug -Message $MSG
					$msgToWrite += "[DEBUG]`t$Msg"
				}
				else {
					$writeToFile = $False 
    }
			}
			'Verbose' {
				if ($InVerbose) {
					Write-Verbose -Message $MSG
					$msgToWrite += "[VERBOSE]`t$Msg"
				}
				else {
					$writeToFile = $False 
    }
			}
		}

		If ($writeToFile) {
			$msgToWrite | Out-File -Append -FilePath $LogFile 
  }
		If ($Footer) {
			'=======================================' | Out-File -Append -FilePath $LogFile
			Write-Output '======================================='
		}
	}
 catch {
		Throw $(New-Object System.Exception ('Cannot write message'), $PSitem.Exception)
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
		[Exception]$e
	)

	Begin {
	}
	Process {
		$msg = 'Source:{0}; Message: {1}' -f $e.Source, $e.Message
		while ($e.InnerException) {
			$e = $e.InnerException
			$msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
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
		[ValidateSet('GET', 'POST', 'DELETE', 'PATCH')]
		[String]$Command,
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String]$URI,
		[Parameter(Mandatory = $false)]
		$Header,
		[Parameter(Mandatory = $false)]
		[String]$Body,
		[Parameter(Mandatory = $false)]
		[ValidateSet('Continue', 'Ignore', 'Inquire', 'SilentlyContinue', 'Stop', 'Suspend')]
		[String]$ErrAction = 'Continue'
	)

	If ((Test-CommandExists Invoke-RestMethod) -eq $false) {
		Throw 'This script requires PowerShell version 3 or above'
	}
	$restResponse = ''
	try {
		if ([string]::IsNullOrEmpty($Body)) {
			Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -TimeoutSec 2700"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType 'application/json' -TimeoutSec 2700 -ErrorAction $ErrAction
		}
		else {
			Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body -TimeoutSec 2700"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType 'application/json' -Body $Body -TimeoutSec 2700 -ErrorAction $ErrAction
		}
	}
 catch [System.Net.WebException] {
		if ($ErrAction -match ('\bContinue\b|\bInquire\b|\bStop\b|\bSuspend\b')) {
			Write-LogMessage -Type Error -Msg "Error Message: $PSitem"
			Write-LogMessage -Type Error -Msg "Exception Message: $($PSitem.Exception.Message)"
			Write-LogMessage -Type Error -Msg "Status Code: $($PSitem.Exception.Response.StatusCode.value__)"
			Write-LogMessage -Type Error -Msg "Status Description: $($PSitem.Exception.Response.StatusDescription)"
		}
		$restResponse = $null
	}
 catch {
		Throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $PSitem.Exception))
	}
	Write-LogMessage -Type Verbose -Msg "Invoke-REST Response: $restResponse"
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
		Write-LogMessage -Type Debug -Msg "Accounts Filter: $AccountsURLWithFilters"
		$GetMasterAccountsResponse = Invoke-Rest -Command Get -Uri $AccountsURLWithFilters -Header $global:g_LogonHeader
		If (($null -eq $GetMasterAccountsResponse) -or ($GetMasterAccountsResponse.count -eq 0)) {
			# No accounts found
			Write-LogMessage -Type Debug -MSG "Account $accountName does not exist"
			$result = $null
		}
		else {
			ForEach ($item in $GetMasterAccountsResponse.Value) {
				if ($item.userName -eq $accountName -and $item.address -eq $accountAddress) {
					$result = $item.id
					Write-LogMessage -Type Debug -MSG "Account $accountName with address of $accountAddress in safe $safeName has account ID of $result"
					break
				}
			}
			# Account Exists
			Write-LogMessage -Type Info -MSG "Account $accountName exist"
		}
		return $result
	}
 catch {
		Write-LogMessage -Type Error -MSG $PSitem.Exception -ErrorAction 'SilentlyContinue'
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
			$logonToken = Invoke-RestMethod -Method Post -Uri $URL_Logon -Body $logonBody -ContentType 'application/json' -TimeoutSec 2700
			
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
		If ($null -ne $g_LogonHeader) {
			Write-LogMessage -Type Info -Msg 'Logoff Session...'
			Invoke-RestMethod -Method Post -Uri $URL_Logoff -Headers $g_LogonHeader -ContentType 'application/json' -TimeoutSec 2700 | Out-Null
			Set-Variable -Name g_LogonHeader -Value $null -Scope global
		}
	}
	catch {
		Throw $(New-Object System.Exception ('Invoke-Logoff: Failed to logoff session', $PSitem.Exception))
	}
}
Function Add-AccountLink {
	param ($linkBody, $MasterID)
	try {

		$Replace = @{
			"`u{00a0}" = ''
		}
		$Replace.Keys | ForEach-Object {
			$linkBody = $linkBody.Replace("$($PSitem)", "$($replace[$PSItem])")
		}
		
		$retResult = $false

		$addLinkAccountBodyResult = $(Invoke-Rest -Uri ($URL_LinkAccounts -f $MasterID) -Header $global:g_LogonHeader -Command 'POST' -Body $($linkBody | ConvertTo-Json))
		If ($null -eq $addLinkAccountBodyResult) {
			# No accounts onboarded
			throw "There was an error linking account $($linkBody.name) to account ID $($MasterID)."
		}
		else {
			Write-LogMessage -Type Info -MSG "Account link $($linkBody.name) was successfully linked as ExtraPass$($linkBody.extraPasswordIndex)"
			$retResult = $true
		}
	}
 catch {
		Write-LogMessage -Type Error -MSG $PSitem.Exception.Message -ErrorAction 'SilentlyContinue'
		Throw 
	}
	return $retResult
}

#endregion

# Check if Powershell is running in Constrained Language Mode
If ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
	Write-LogMessage -Type Error -MSG "Powershell is currently running in $($ExecutionContext.SessionState.LanguageMode) mode which limits the use of some API methods used in this script.`
	PowerShell Constrained Language mode was designed to work with system-wide application control solutions such as CyberArk EPM or Device Guard User Mode Code Integrity (UMCI).`
	For more information: https://blogs.msdn.microsoft.com/powershell/2017/11/02/powershell-constrained-language-mode/"
	Write-LogMessage -Type Info -MSG 'Script ended' -Footer -LogFile $LOG_FILE_PATH
	return
}


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
		Write-LogMessage -Type Error -MSG 'Could not change SSL validation'
		Write-LogMessage -Type Error -MSG $PSitem.Exception -ErrorAction 'SilentlyContinue'
		return
	}
}
Else {
	try {
		Write-LogMessage -Type Debug -MSG 'Setting script to use TLS 1.2'
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
	}
 catch {
		Write-LogMessage -Type Error -MSG 'Could not change SSL settings to use TLS 1.2'
		Write-LogMessage -Type Error -MSG $PSitem.Exception -ErrorAction 'SilentlyContinue'
	}
}

If ((Test-CommandExists Invoke-RestMethod) -eq $false) {
	Write-LogMessage -Type Error -MSG 'This script requires PowerShell version 3 or above'
	return
}

# Check that the PVWA URL is OK
If (![string]::IsNullOrEmpty($PVWAURL)) {
	If ($PVWAURL.Substring($PVWAURL.Length - 1) -eq '/') {
		$PVWAURL = $PVWAURL.Substring(0, $PVWAURL.Length - 1)
	}

	try {
		# Validate PVWA URL is OK
		Write-LogMessage -Type Debug -MSG "Trying to validate URL: $PVWAURL"
		Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $PVWAURL -Method 'Head' -TimeoutSec 30 | Out-Null
	}
 catch [System.Net.WebException] {
		If (![string]::IsNullOrEmpty($PSitem.Exception.Response.StatusCode.Value__)) {
			Write-LogMessage -Type Error -MSG $PSitem.Exception.Response.StatusCode.Value__
		}
	}
 catch {
		Write-LogMessage -Type Error -MSG 'PVWA URL could not be validated'
		Write-LogMessage -Type Error -MSG $PSitem.Exception -ErrorAction 'SilentlyContinue'
	}
}
else {
	Write-LogMessage -Type Error -MSG 'PVWA URL can not be empty'
	return
}

# Header
Write-LogMessage -Type Info -MSG 'Welcome to the Account Link Utility' -Header
Write-LogMessage -Type Info -MSG 'Getting PVWA Credentials to start Linking accounts' -SubHeader

#region [Logon]
try {
	# Get Credentials to Login
	# ------------------------
	$caption = 'Link Accounts'

	If (![string]::IsNullOrEmpty($logonToken)) {
		if ($logonToken.GetType().name -eq 'String') {
			$logonHeader = @{Authorization = $logonToken }
			Set-Variable -Name g_LogonHeader -Value $logonHeader -Scope global	
		}
		else {
			Set-Variable -Name g_LogonHeader -Value $logonToken -Scope global
		}
	}
	elseif ($null -eq $creds) {
		$msg = 'Enter your User name and Password'; 
		$creds = $Host.UI.PromptForCredential($caption, $msg, '', '')
		Get-LogonHeader -Credentials $creds -concurrentSession $concurrentSession
	}
	else { 
		Write-LogMessage -Type Error -Msg 'No Credentials were entered'
		return
	}
}
catch {
	Write-LogMessage -Type Error -Msg "Error Logging on. Error: $(Join-ExceptionMessage $_.Exception)"
	return
}
#endregion

If (Test-RESTVersion -version '11.7') { $extraPass = 'extraPasswordIndex' } else { $extraPass = 'extraPasswordID' }

#region [Read Accounts CSV file and link Accounts]
If ([string]::IsNullOrEmpty($CsvPath)) {
	$CsvPath = Open-FileDialog($g_CsvDefaultPath)
}
$delimiter = $((Get-Culture).TextInfo.ListSeparator)
$accountsCSV = Import-Csv $csvPath -Delimiter $delimiter
$badAccounts = "Bad-$($(Get-Item -Path $csv).Name)"

$masterCount = @($accountsCSV | Select-Object -Property userName, address -Unique).Count
Write-LogMessage -Type Info -MSG "Found a total of $masterCount accounts with links" -SubHeader

$ExtraPass1Count = @($accountsCSV | Where-Object ExtraPass1Name -NE '' ).count
Write-LogMessage -Type Info -MSG "A total of $ExtraPass1Count ExtraPass1 accounts found" -SubHeader
$ExtraPass2Count = @($accountsCSV | Where-Object ExtraPass2Name -NE '' ).count
Write-LogMessage -Type Info -MSG "A total of $ExtraPass2Count ExtraPass2 accounts found" -SubHeader
$ExtraPass3Count = @($accountsCSV | Where-Object ExtraPass3Name -NE '' ).count
Write-LogMessage -Type Info -MSG "A total of $ExtraPass3Count ExtraPass3 accounts found" -SubHeader
$linkCount = $ExtraPass1Count + $ExtraPass2Count + $ExtraPass3Count
Write-LogMessage -Type Info -MSG "A total of $linkCount account links found" -SubHeader

$counterMaster = 0
$ExtraPass1Succes = 0
$ExtraPass1Failed = 0
$ExtraPass2Succes = 0
$ExtraPass2Failed = 0
$ExtraPass3Succes = 0
$ExtraPass3Failed = 0
Write-LogMessage -Type Info -MSG "Starting to add links to $masterCount master accounts" -SubHeader
# Read Account dependencies
ForEach ($account in $accountsCSV) {
	if (![string]::IsNullOrEmpty($account)) {
		# Search for Master Account
		$foundMasterAccountID = $null
		try {
			$foundMasterAccountID = Find-MasterAccount -accountName $account.userName -accountAddress $account.address -safeName $account.safe
			if ([string]::IsNullOrEmpty($foundMasterAccountID)) { Throw 'No Master Account Found' }
		}
		catch {
			Write-LogMessage -Type Error -Msg "Error searching for Master Account with username `"$($account.userName)`" with address `"$($account.address)`" in safe `"$($account.safe)`"."
			Write-LogMessage -Type Verbose -MSG "Error Message: $(Join-ExceptionMessage $PSitem.Exception)"
			continue
		}
		Try {
			#If logon account is found link
			if (![string]::IsNullOrEmpty($account.ExtraPass1Name)) {
				Try {
					$addLinkAccountBody = @{
						'safe'       = $account.ExtraPass1Safe.Trim(); 
						'name'       = $account.ExtraPass1Name.Trim(); 
						'folder'     = $account.ExtraPass1Folder.Trim();
						"$extraPass" = '1';
					}
					if (Add-AccountLink -linkBody $addLinkAccountBody -MasterID $foundMasterAccountID) {
						$ExtraPass1Succes++ 
					}
				}
				Catch {
					Write-LogMessage -Type Error -Msg "Error adding ExtraPass1 with name of `"$($account.ExtraPass1Name)`" in safe `"$($account.ExtraPass1Safe)`" to Account with username `"$($account.userName)`" with address `"$($account.address)`" in safe `"$($account.safe)`""
					$account | Export-Csv -Append -Path $badAccounts
					$ExtraPass1Failed++
				}
			}

			#If enable account is found link
			if (![string]::IsNullOrEmpty($account.ExtraPass2Name)) {
				Try {
					$addLinkAccountBody = @{
						'safe'       = $account.ExtraPass2Safe.Trim(); 
						'name'       = $account.ExtraPass2Name.Trim(); 
						'folder'     = $account.ExtraPass2Folder.Trim();
						"$extraPass" = '2';
					}
					if (Add-AccountLink -linkBody $addLinkAccountBody -MasterID $foundMasterAccountID) {
						$ExtraPass2Succes++ 
					}
				}
				Catch {
					Write-LogMessage -Type Error -Msg "Error adding ExtraPass2 with name of `"$($account.ExtraPass2Name)`" in safe `"$($account.ExtraPass2Safe)`" to Account with username `"$($account.userName)`" with address `"$($account.address)`" in safe `"$($account.safe)`""
					$ExtraPass2failed++
					$account | Export-Csv -Append -Path $badAccounts
				}
			}

			#If reconcile account is found link
			if (![string]::IsNullOrEmpty($account.ExtraPass3Name)) {
				Try {
					$addLinkAccountBody = @{
						'safe'       = $account.ExtraPass3Safe.Trim(); 
						'name'       = $account.ExtraPass3Name.Trim(); 
						'folder'     = $account.ExtraPass3Folder.Trim();
						"$extraPass" = '3';
					}
					if (Add-AccountLink -linkBody $addLinkAccountBody -MasterID $foundMasterAccountID) {
						$ExtraPass3Succes++ 
					}
				}
				Catch {
					Write-LogMessage -Type Error -Msg "Error adding ExtraPass2 with name of `"$($account.ExtraPass3Name)`" in safe `"$($account.ExtraPass3safe)`" to Account with username `"$($account.userName)`" with address `"$($account.address)`" in safe `"$($account.safe)`""
					$ExtraPass3Failed++ 
					$account | Export-Csv -Append -Path $badAccounts
				}
			}
		}
		Catch {
			Write-LogMessage -Type Error -Msg "Error linking Master Account - Username: `"$($account.userName)`" Address: `"$($account.address)`" Safe: `"$($account.safe)`"" 
			Write-LogMessage -Type Error -Msg "$(Join-ExceptionMessage $PSitem.Exception)"
			$account | Export-Csv -Append -Path $badAccounts
		}
		$counterMaster++
	}
}

#endregion

#region [Logoff]
# Logoff the session
# ------------------

If ([string]::IsNullOrEmpty($logonToken)) {
	Write-Host 'LogonToken passed, session NOT logged off'
}
else {
	Invoke-Logoff
}

# Footer
Write-LogMessage -Type Info -MSG "A total of $counterMaster accounts out of $masterCount accounts had links processed" -Footer
Write-LogMessage -Type Info -MSG "A total of $ExtraPass1Succes ExtraPass1 links out of $ExtraPass1Count links where created successfully." -Footer
Write-LogMessage -Type Info -MSG "A total of $ExtraPass2Succes ExtraPass2 links out of $ExtraPass2Count links where created successfully." -Footer
Write-LogMessage -Type Info -MSG "A total of $ExtraPass3Succes ExtraPass3 links out of $ExtraPass3Count links where created successfully." -Footer
Write-LogMessage -Type Info -MSG "A total of $($ExtraPass1Succes + $ExtraPass2Succes + $ExtraPass3Succes) individual links out of $linkCount links where created successfully." -Footer
#endregion
