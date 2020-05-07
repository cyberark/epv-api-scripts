###########################################################################
#
# NAME: Accounts Onboard Utility
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will bulk onboard all accounts from a CSV file using REST API
# This script will use the optimal REST API commands based on the installed PVWA server
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v9.8 and above
#
###########################################################################
[CmdletBinding(DefaultParametersetName="Create")]
param
(
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com/passwordvault)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,
	
	[Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark","ldap","radius")]
	[String]$AuthType="cyberark",
	
	[Parameter(Mandatory=$false,HelpMessage="Please enter Safe Template Name")]
	[Alias("safe")]
	[String]$TemplateSafe,
	
	[Parameter(Mandatory=$false,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true)]
	[ValidateScript({Test-Path $_})]
	[Alias("path")]
	[String]$CsvPath,
	
	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory=$false)]
	[Switch]$DisableSSLVerify,
	
	
	# Use this switch to Create accounts and Safes (no update)
	[Parameter(ParameterSetName='Create',Mandatory=$false)]
	[Switch]$Create,
	
	
	# Use this switch to Create and Update accounts and Safes
	[Parameter(ParameterSetName='Update',Mandatory=$false)]
	[Switch]$Update,
	
	# Use this switch to disable Safes creation
	[Parameter(ParameterSetName='Create',Mandatory=$false)]
	[Parameter(ParameterSetName='Update')]
	[Switch]$NoSafeCreation
)

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path

# Set Log file path
$global:LOG_FILE_PATH = "$ScriptLocation\Account_Onboarding_Utility.log"

$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent

# Script Defaults
# ---------------
$g_CsvDefaultPath = $Env:CSIDL_DEFAULT_DOWNLOADS
# Script Version
$ScriptVersion = "1.0"

# Global URLS
# -----------
$global:URL_PVWAAPI = $PVWAURL+"/api"
$global:URL_PVWAWebServices = $PVWAURL+"/WebServices"
$global:URL_PVWABaseAPI = $URL_PVWAWebServices+"/PIMServices.svc"

# Safe Defaults
# --------------
$CPM_NAME = "PasswordManager"
$NumberOfDaysRetention = 7
$NumberOfVersionsRetention = 0

# Set modules paths
$MODULE_BIN_PATH = "$ScriptLocation\bin"
$MODULE_COMMON_UTIL = "$MODULE_BIN_PATH\CommonUtil.psd1"
$MODULE_ACCOUNTS_SAFES_V98 = "$MODULE_BIN_PATH\Accounts_Safes_v98.psd1"
$MODULE_ACCOUNTS_SAFES_V103 = "$MODULE_BIN_PATH\Accounts_Safes_v103.psd1"

#region Helper Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Load-Modules
# Description....: Load the relevant modules into the script
# Parameters.....: None
# Return Values..: None
# =================================================================================================================================
Function Load-Modules
{
<# 
.SYNOPSIS 
	Load hardening modules
.DESCRIPTION
	Load all relevant hardening modules for the script
#>
	param(
		$modulePath
	)

	Begin {
	}
	Process {
		$moduleInfo = Import-Module $modulePath -Force -DisableNameChecking -PassThru -ErrorAction Stop 
	}
	End {
		return $moduleInfo
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: UnLoad-Modules
# Description....: UnLoad the relevant modules into the script
# Parameters.....: Module Info
# Return Values..: None
# =================================================================================================================================
Function UnLoad-Modules
{
<# 
.SYNOPSIS 
	UnLoad hardening modules
.DESCRIPTION
	UnLoad all relevant hardening modules for the script
#>
	param(
		$moduleInfo
	)

	Begin {
	}
	Process {
		ForEach ($info in [array]::Reverse($moduleInfo))
		{
			Remove-Module -ModuleInfo $info -ErrorAction Stop | out-Null
		}
	}
	End {
	}
}
#endregion

#---------------
# Check if Powershell is running in Constrained Language Mode
If($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage")
{
	Write-Host "Powershell is currently running in $($ExecutionContext.SessionState.LanguageMode) mode which limits the use of some API methods used in this script.`
	PowerShell Constrained Language mode was designed to work with system-wide application control solutions such as CyberArk EPM or Device Guard User Mode Code Integrity (UMCI).`
	For more information: https://blogs.msdn.microsoft.com/powershell/2017/11/02/powershell-constrained-language-mode/"
	Write-Host "Script ended" 
	return
}

# Load all relevant modules
$moduleInfos = @()
$moduleInfos += Load-Modules -modulePath $MODULE_COMMON_UTIL
# Set the selected Authentication Type
Set-Variable -Scope global -Name AuthType -Value $AuthType

Write-LogMessage -Type Info -MSG "Starting script (v$ScriptVersion)" -Header -LogFile $LOG_FILE_PATH
if($InDebug) { Write-LogMessage -Type Info -MSG "Running in Debug Mode" -LogFile $LOG_FILE_PATH }
if($InVerbose) { Write-LogMessage -Type Info -MSG "Running in Verbose Mode" -LogFile $LOG_FILE_PATH }
Write-LogMessage -Type Debug -MSG "Running PowerShell version $($PSVersionTable.PSVersion.Major) compatible of versions $($PSVersionTable.PSCompatibleVersions -join ", ")" -LogFile $LOG_FILE_PATH
# Verify the Powershell version is compatible
If (!($PSVersionTable.PSCompatibleVersions -join ", ") -like "*3*")
{
	Write-LogMessage -Type Error -Msg "The Powershell version installed on this machine is not compatible with the required version for this script.`
	Installed PowerShell version $($PSVersionTable.PSVersion.Major) is compatible with versions $($PSVersionTable.PSCompatibleVersions -join ", ").`
	Please install at least PowerShell version 3."
	Write-LogMessage -Type Info -Msg "Script ended"
	return
}

# Check if to disable SSL verification
If($DisableSSLVerify)
{
	try {
		Disable-SSLVerification
	} catch {
		Write-LogMessage -Type "Error" -Msg "Could not disable SSL verification settings.  Error: $(Join-ExceptionMessage $_.Exception)"
	}
}
Else
{
	try{
		Write-LogMessage -Type Debug -MSG "Setting script to use TLS 1.2"
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
	} catch {
		Write-LogMessage -Type "Error" -Msg "Could not change SSL settings to use TLS 1.2.  Error: $(Join-ExceptionMessage $_.Exception)"
	}
}

try{
	#Load Specific REST modules
	Write-LogMessage -Type Debug -Msg "Loading REST Commands for version 9.8 and above"
	$moduleInfos += Load-Modules -modulePath $MODULE_ACCOUNTS_SAFES_V98
	If(Test-RESTVersion -version "10.3")
	{
		Write-LogMessage -Type Debug -Msg "Loading REST Commands for version 10.3 and above"
		$moduleInfos += Load-Modules -modulePath $MODULE_ACCOUNTS_SAFES_V103
	}
} catch {
	Write-LogMessage -Type "Error" -Msg "Problem loading relevant modules.  Error: $(Join-ExceptionMessage $_.Exception)"
}

$accountsList = [System.Collections.ArrayList]@()
$delimiter = $((Get-Culture).TextInfo.ListSeparator)
If([string]::IsNullOrEmpty($CsvPath))
{
	$CsvPath = OpenFile-Dialog -LocationPath $g_CsvDefaultPath
}
$accountsCSV = Import-CSV -Path $CSVPath -Delimiter $delimiter
$rowCount = $accountsCSV.Count
$counter = 0
Write-LogMessage -Type Info -MSG "Reading $rowCount accounts" -SubHeader
ForEach ($account in $accountsCSV)
{
	try{
		if (![string]::IsNullOrEmpty($account))
		{
			$accountsList += New-AccountObject -AccountLine $account
		}
	} catch {
		Write-LogMessage -Type "Error" -Msg "Problem adding account for onboarding list.  Error: $(Join-ExceptionMessage $_.Exception)"
	}
}
Write-LogMessage -Type Info -MSG "Finished reading $rowCount accounts"
Write-LogMessage -Type Info -MSG "Onboarding $($accountsList.Count) accounts" -SubHeader

#region [Logon]
	# Get Credentials to Login
	# ------------------------
	$caption = "Accounts Onboard Utility"
	$msg = "Enter your '$AuthType' User name and Password"; 
	$creds = $Host.UI.PromptForCredential($caption,$msg,"","")
	if($null -ne $creds)
	{
		Invoke-Logon -Credentials $creds
	}
	else
	{
		Write-LogMessage -Type Warning -Msg "No Credentials entered"
		Write-LogMessage -Type Info -Msg "Script ended"
		return
	}
#endregion

ForEach ($accountItem in $accountsList)
{
	# Create some internal variables
	$safeExists = $accExists = $createAccount = $shouldSkipAccount = $false
	
	try {
		# Check if the Safe Exists
		$safeExists = $(Test-Safe -safeName $accountItem.safeName)
		# Check if we can create safes or not
		If (($NoSafeCreation -eq $False) -and ($safeExists -eq $false))
		{
			# The target safe does not exist
			# The user chose to create safes during this process
			Write-LogMessage -Type Debug -MSG "Creating new Safe ($($accountItem.SafeName))"
			$shouldSkipAccount = -not (New-Safe -SafeName $accountItem.SafeName -TemplateSafe $TemplateSafe)
		}
		elseif (($NoSafeCreation -eq $True) -and ($safeExists -eq $false))
		{
			# The target safe does not exist
			# The user chose not to create safes during this process
			Write-LogMessage -Type Info -MSG "Target Safe ($($accountItem.SafeName)) does not exist, No Safe creation requested - Will Skip account Creation"
			$shouldSkipAccount = $true
		}
	} catch {
		Write-LogMessage -Type Debug -MSG "There was an error creating Safe $($account.SafeName). Error: $(Join-ExceptionMessage $_.Exception)"
		$safeExists = $false
		$shouldSkipAccount = $true
	}
	
	If($shouldSkipAccount -eq $False)
	{
		# Check if the Account exists
		$accExists = $(Test-Account -safeName $accountItem.safeName -accountName $accountItem.userName -accountAddress $accountItem.Address)
				
		try {
			If($accExists)
			{
				If($Update)
				{
					$updateAccountResult = Update-Account -AccountObject $accountItem
					if($updateAccountResult -ne $null)
					{
						Write-LogMessage -Type Info -MSG "Account Updated Successfully"
						# Increment counter
						$counter++
						Write-LogMessage -Type Info -MSG "[$counter/$rowCount] Updated $($accountItem.userName)@$($accountItem.address) successfully."
					}
				}
				ElseIf($Create)
				{
					# Account Exists, Creating the same account again will cause duplications - Verify with user
					Write-LogMessage -Type Warning "The Account Exists, Creating the same account twice will cause duplications. Skipping Account."
					$createAccount = $false
				}
			}
			else {
				# Create the Account
				$addAccountResult = New-Account -AccountObject $accountItem
				if($addAccountResult -ne $null)
				{
					Write-LogMessage -Type Info -MSG "Account Onboarded Successfully"
					# Increment counter
					$counter++
					Write-LogMessage -Type Info -MSG "[$counter/$rowCount] Added $($accountItem.userName)@$($accountItem.address) successfully."  
				}
			}
		} catch {
			Write-LogMessage -Type Error -MSG "There was an error onboarding $($accountItem.userName)@$($accountItem.address) into PAS. Error: $(Join-ExceptionMessage $_.Exception)"
		}
	}
	else
	{
		Write-LogMessage -Type Info -MSG "Skipping onboarding $($accountItem.userName)@$($accountItem.address) into PAS."
	}
}

Invoke-Logoff
Write-LogMessage -Type Info -MSG "Script ended" -Footer -LogFile $LOG_FILE_PATH

# UnLoad loaded modules
UnLoad-Modules $moduleInfos

