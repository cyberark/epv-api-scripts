###########################################################################
#
# NAME: Accounts Onboard Utility
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will onboard all accounts from a CSV file using REST API
#
# VERSION HISTORY:
# 1.0 17/07/2017 - Initial release
# 1.5 25/07/2017 - Including Safe Creation and Update Account
# 1.6 02/08/2017 - Fixed Update Account
# 1.7 08/08/2017 - Support for Template Safe (General) and Fixing Disable SSL Verification issues
# 1.8 27/08/2017 - Support accepting Account and Safe objects as input parameters
#
###########################################################################
[CmdletBinding(DefaultParametersetName="Create")]
param
(
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,
	
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
$LOG_FILE_PATH = "$ScriptLocation\Account_Onboarding_Utility.log"

$InDebug = $PSBoundParameters.Debug.IsPresent
$InVerbose = $PSBoundParameters.Verbose.IsPresent

# Global URLS
# -----------
$URL_PVWAWebServices = $PVWAURL+"/WebServices"
$URL_PVWABaseAPI = $URL_PVWAWebServices+"/PIMServices.svc"
$URL_CyberArkAuthentication = $URL_PVWAWebServices+"/auth/Cyberark/CyberArkAuthenticationService.svc"
$URL_CyberArkLogon = $URL_CyberArkAuthentication+"/Logon"
$URL_CyberArkLogoff = $URL_CyberArkAuthentication+"/Logoff"

# URL Methods
# -----------
$URL_Safes = $URL_PVWABaseAPI+"/Safes"
$URL_SafeDetails = $URL_PVWABaseAPI+"/Safes/{0}"
$URL_SafeMembers = $URL_PVWABaseAPI+"/Safes/{0}/Members"
$URL_Account = $URL_PVWABaseAPI+"/Account"
$URL_Accounts = $URL_PVWABaseAPI+"/Accounts"
$URL_AccountDetails = $URL_Accounts+"/{0}"


# Script Defaults
# ---------------
$g_CsvDefaultPath = $Env:CSIDL_DEFAULT_DOWNLOADS

# Safe Defaults
# --------------
$CPM_NAME = "PasswordManager"
$NumberOfDaysRetention = 7
$NumberOfVersionsRetention = 0

# Template Safe parameters
# ------------------------
$TemplateSafeDetails = ""
$TemplateSafeMembers = ""

# Initialize Script Variables
# ---------------------------
$g_LogonHeader = ""

#region Functions
Function Test-CommandExists
{
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {if(Get-Command $command){RETURN $true}}
    Catch {Write-Host "$command does not exist"; RETURN $false}
    Finally {$ErrorActionPreference=$oldPreference}
} #end function test-CommandExists

Function Encode-URL($sText)
{
	if ($sText.Trim() -ne "")
	{
		Write-Debug "Returning URL Encode of $sText"
		return [System.Web.HttpUtility]::UrlEncode($sText)
	}
	else
	{
		return $sText
	}
}

Function Log-MSG
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
	# Check the message type
	switch ($type)
	{
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
			if($InDebug)
			{
				Write-Debug $MSG
				$msgToWrite += "[DEBUG]`t$Msg"
			}
			else { $writeToFile = $False }
		}
		"Verbose" { 
			if($InVerbose)
			{
				Write-Verbose $MSG
				$msgToWrite += "[VERBOSE]`t$Msg"
			}
			else { $writeToFile = $False }
		}
	}
	
	If($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH }
	If ($Footer) { 
		"=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
		Write-Host "======================================="
	}
}

Function OpenFile-Dialog($initialDirectory)
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter = "CSV (*.csv)| *.csv"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
}

Function Invoke-Rest
{
	param ($Command, $URI, $Header, $Body, $ErrorAction="Continue")
	
	$restResponse = ""
	try{
		Log-Msg -Type Verbose -MSG "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body"
		$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body
	} catch {
		If($_.Exception.Response.StatusDescription -ne $null)
		{
			Log-Msg -Type Error -MSG $_.Exception.Response.StatusDescription -ErrorAction $ErrorAction
		}
		else
		{
			Log-Msg -Type Error -Msg "StatusCode: $_.Exception.Response.StatusCode.value__"
		}
		$restResponse = $null
	}
	Log-Msg -Type Verbose -MSG $restResponse
	return $restResponse
}

Function Get-Safe
{
	param ($safeName)
	$_safe = $null
	try{
		$accSafeURL = $URL_SafeDetails -f $safeName
		$_safe = $(Invoke-Rest -Uri $accSafeURL -Header $g_LogonHeader -Command "Get" -ErrorAction "SilentlyContinue")
	}
	catch
	{
		Log-Msg -Type Error -MSG $_.Exception.Response.StatusDescription
	}
	
	return $_safe
}

Function Get-SafeMembers
{
	param (
		[Parameter(Mandatory=$true)]
		[String]$safeName
		)
	$_safeMembers = $null
	try{
		$accSafeMembersURL = $URL_SafeMembers -f $safeName
		$_safeMembers = $(Invoke-Rest -Uri $accSafeMembersURL -Header $g_LogonHeader -Command "Get" -ErrorAction "SilentlyContinue")
	}
	catch
	{
		Log-Msg -Type Error -MSG $_.Exception.Response.StatusDescription
	}
	
	return $_safeMembers
}

Function Test-Safe
{
	param (
		[Parameter(Mandatory=$true)]
		[String]$safeName
		)
		
	try{
		If ($null -eq $(Get-Safe -safeName $safeName))
		{
			# Safe does not exist
			Log-Msg -Type Warning -MSG "Safe $safeName does not exist"
			return $false
		}
		else
		{
			# Safe exists
			Log-Msg -Type Info -MSG "Safe $safeName exists"
			return $true
		}
	}
	catch
	{
		Log-Msg -Type Error -MSG $_.Exception
	}
}

Function Create-Safe
{
	param (
		[Parameter(Mandatory=$true)]
		[String]$safeName,
		[Parameter(Mandatory=$false)]
		[String]$cpmName,
		[Parameter(Mandatory=$false)]
		[PSObject]$templateSafeObject
		)
	
	# Check if Template Safe is in used
	If(![String]::IsNullOrEmpty($templateSafeObject))
	{
		# Using Template Safe
		Log-Msg -Type Info -MSG "Creating Safe $safeName according to Tempalte"
		$restBody = @{ safe=$templateSafeObject } | ConvertTo-Json -Depth 3
	}
	else
	{
		# Create the Target Safe
		Log-Msg -Type Info -MSG "Creating Safe $safeName"
		$bodySafe = @{ SafeName=$safeName;Description="$safeName - Created using Accounts Onboard Utility";OLACEnabled=$false;ManagingCPM=$CPM_NAME;NumberOfDaysRetention=$NumberOfDaysRetention }
		$restBody = @{ safe=$bodySafe } | ConvertTo-Json -Depth 3
	}				
	$createSafeResult = $(Invoke-Rest -Uri $URL_Safes -Header $g_LogonHeader -Command "Post" -Body $restBody)
	if ($createSafeResult)
	{
		Log-Msg -Type Debug -MSG "Safe $($account.Safe) created"
		return $false
	}
	else { 
		# Safe creation failed
		Log-Msg -Type Error -MSG "Safe Creation failed - Should Skip Account Creation"
		return $true 
	}
}

Function Get-Account
{
	param ($accountName, $safeName)
	$_account = $null
	try{
		# Search for created account
		$urlSearchAccount = $URL_Accounts+"?Safe="+$(Encode-URL $safeName)+"&Keywords="+$(Encode-URL $accountName)
		$_account = $(Invoke-Rest -Uri $urlSearchAccount -Header $g_LogonHeader -Command "Get")
		if($null -ne $_account)
		{
			$_account = $_account.accounts
		}
	}
	catch
	{
		Log-Msg -Type Error -MSG $_.Exception.Response.StatusDescription
	}
	
	return $_account
}

Function Test-Account
{
	param ($accountName, $safeName)
	try{
		If ($null -eq $(Get-Account -accountName $accountName -safeName $safeName))
		{
			# No accounts found
			Log-Msg -Type Debug -MSG "Account $accountName does not exist"
			return $false
		}
		else
		{
			# Account Exists
			Log-Msg -Type Info -MSG "Account $accountName exist"
			return $true
		}
	}
	catch
	{
		Log-Msg -Type Error -MSG $_.Exception
	}
}

Function Get-LogonHeader
{
	param($User, $Password)
	# Create the POST Body for the Logon
    # ----------------------------------
    $logonBody = @{ username=$User;password=$Password } | ConvertTo-Json
	try{
	    # Logon
	    $logonResult = Invoke-Rest -Command Post -Uri $URL_CyberArkLogon -Body $logonBody
	    # Save the Logon Result - The Logon Token
	    $logonToken = $logonResult.CyberArkLogonResult
		Log-Msg -Type Debug -MSG "Got logon token: $logonToken"
	}
	catch
	{
		Log-Msg -Type Error -MSG $_.Exception.Response.StatusDescription
		$logonToken = ""
	}
    If ([string]::IsNullOrEmpty($logonToken))
    {
        Log-Msg -Type Error -MSG "Logon Token is Empty - Cannot login"
        exit
    }
	
    # Create a Logon Token Header (This will be used through out all the script)
    # ---------------------------
    $logonHeader =  New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $logonHeader.Add("Authorization", $logonToken)
	
	return $logonHeader
}
#endregion

# Check if to disable SSL verification
If($DisableSSLVerify)
{
	try{
		Write-Warning "It is not Recommended to disable SSL verification" -WarningAction Inquire
		# Using Proxy Default credentials if the Sevrer needs Proxy credentials
		[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
		# Using TLS 1.2 as security protocol verification
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
		# Disable SSL Verification
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
	} catch {
		Log-Msg -Type Error -MSG "Could not change SSL validation"
		Log-Msg -Type Error -MSG $_.Exception
		exit
	}
}

If ((Test-CommandExists Invoke-RestMethod) -eq $false)
{
   Log-Msg -Type Error -MSG  "This script requires Powershell version 3 or above"
   exit
}	

# Check that the PVWA URL is OK
If (![string]::IsNullOrEmpty($PVWAURL))
{
	If ($PVWAURL.Substring($PVWAURL.Length-1) -eq "/")
	{
		$PVWAURL = $PVWAURL.Substring(0,$PVWAURL.Length-1)
	}
	
	try{
		# Validate PVWA URL is OK
		Log-Msg -Type Debug -MSG  "Trying to validate URL: $PVWAURL"
		Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $PVWAURL -Method 'Head' -TimeoutSec 30 | Out-Null
	} catch [System.Net.WebException] {
		If(![string]::IsNullOrEmpty($_.Exception.Response.StatusCode.Value__))
		{
			Log-Msg -Type Error -MSG $_.Exception.Response.StatusCode.Value__
		}
	}
	catch {		
		Log-Msg -Type Error -MSG "PVWA URL could not be validated"
		Log-Msg -Type Error -MSG $_.Exception
	}
	
}
else
{
	Log-Msg -Type Error -MSG "PVWA URL can not be empty"
	exit
}

# Header
Log-Msg -Type Info -MSG "Welcome to Accounts Onboard Utility" -Header
Log-Msg -Type Info -MSG "Getting PVWA Credentials to start Onboarding Accounts" -SubHeader


#region [Logon]
	# Get Credentials to Login
	# ------------------------
	$caption = "Accounts Onboard Utility"
	$msg = "Enter your User name and Password"; 
	$creds = $Host.UI.PromptForCredential($caption,$msg,"","")
	if ($creds -ne $null)
	{
		$UserName = $creds.username.Replace('\','');    
		$UserPassword = $creds.GetNetworkCredential().password
	}
	else { 
		Log-Msg -Type Error -MSG "No Credentials were entered" -Footer
		exit
	}
	
	$g_LogonHeader = $(Get-LogonHeader -User $UserName -Password $UserPassword)
#endregion

#region Template Safe
	If(![string]::IsNullOrEmpty($TemplateSafe) -and !$NoSafeCreation)
	{
		# Using Template Safe to create any new safe
		If ((Test-Safe -safeName $TemplateSafe))
		{
			# Safe Exists
			$TemplateSafeDetails = (Get-Safe -safeName $TemplateSafe)
			$TemplateSafeDetails.Description = "Template Safe Created using Accounts Onboard Utility"
			$TemplateSafeMembers = (Get-SafeMembers -safeName $TemplateSafe)
		}
		else
		{
			Log-MSG -Type Error -Msg "Template Safe does not exist" -Footer
			exit			
		}
	}
#endregion

#region [Read Accounts CSV file and Create Accounts]
	If([string]::IsNullOrEmpty($CsvPath))
	{
		$CsvPath = OpenFile-Dialog($g_CsvDefaultPath)
	}
	$accountsCSV = Import-CSV $csvPath
	$rowCount = $accountsCSV.Count
	$counter = 0
	Log-Msg -Type Info -MSG "Starting to Onboard $rowCount accounts" -SubHeader
	ForEach ($account in $accountsCSV)
	{
		# Create some internal variables
		$shouldSkip = $false
		$safeExists = $false
		$createAccount = $false
		# Convert DisableAutoMgmt from yes / true to $true
		if ($account.disableAutoMgmt -eq "yes" -or $account.disableAutoMgmt -eq "true") 
		{
			$account.disableAutoMgmt = $true
		} else {
			$account.disableAutoMgmt = $false
		}
		# Check if the Safe Exists
		$safeExists = $(Test-Safe -safeName $account.Safe)
		# Check if we can create safes or not
		If (($NoSafeCreation -eq $False) -and ($safeExists -eq $false))
		{
			try{
				# The target safe does not exist
				# The user chose to create safes during this process
				$shouldSkip = Create-Safe -TemplateSafe $TemplateSafeDetails -Safe $account.Safe
			}
			catch{
				Log-Msg -Type Debug -MSG "There was an error creating Safe $($account.Safe)"
			}
		}
		elseif (($NoSafeCreation -eq $True) -and ($safeExists -eq $false))
		{
			# The target safe does not exist
			# The user chose not to create safes during this process
			Log-Msg -Type Info -MSG "Target Safe does not exist, No Safe creation requested - Will Skip account Creation"
			$shouldSkip = $true
		}
		If($shouldSkip -eq $False)
		{
			# Check if the Account exists
			$accExists = $(Test-Account -safeName $account.Safe -accountName $account.username)
			
			try{
				If($accExists)
				{
					If($Update)
					{
						# Get Existing Account Details
						$s_Account = $(Get-Account -safeName $account.Safe -accountName $account.username)
						
						# Create the Account to update with current properties
						$updateAccount = "" | select Safe,Folder,PlatformID,Address,UserName,DeviceType,AccountName,Properties
						
						ForEach($sProp in $s_Account.Properties)
						{
							if($sProp.Key -eq "Safe")
							{ 
								$updateAccount.Safe = $sProp.Value
								If(![string]::IsNullOrEmpty($account.Safe) -and $account.Safe -ne $updateAccount.Safe)
								{
									$updateAccount.Safe = $account.Safe	
								}
							}	
							if($sProp.Key -eq "Folder")
							{ 
								$updateAccount.Folder = $sProp.Value 
								If(![string]::IsNullOrEmpty($account.Folder) -and $account.Folder -ne $updateAccount.Folder)
								{
									$updateAccount.Folder = $account.Folder	
								}
							}
							if($sProp.Key -eq "PolicyID")
							{ 
								write-host $sProp.Value
								$updateAccount.PlatformID = $sProp.Value
								If(![string]::IsNullOrEmpty($account.PlatformID) -and $account.PlatformID -ne $updateAccount.PlatformID)
								{
									$updateAccount.PlatformID = $account.PlatformID	
								}
							}
							if($sProp.Key -eq "DeviceType")
							{ 
								$updateAccount.DeviceType = $sProp.Value
								#If(![string]::IsNullOrEmpty($account.DeviceType) -and $account.DeviceType -ne $updateAccount.DeviceType)
								#{
								#	$updateAccount.DeviceType = $account.DeviceType	
								#}
							}
							if($sProp.Key -eq "Address")
							{ 
								$updateAccount.Address = $sProp.Value
								If(![string]::IsNullOrEmpty($account.Address) -and $account.Address -ne $updateAccount.Address)
								{
									$updateAccount.Address = $account.Address	
								}
							}
							if($sProp.Key -eq "Name")
							{ 
								write-host $sProp.Value
								$updateAccount.AccountName = $sProp.Value
								If(![string]::IsNullOrEmpty($account.AccountName) -and $account.AccountName -ne $updateAccount.AccountName)
								{
									$updateAccount.AccountName = $account.AccountName	
								}
							}
							if($sProp.Key -eq "UserName")
							{ 
								$updateAccount.UserName = $sProp.Value
								If(![string]::IsNullOrEmpty($account.UserName) -and $account.UserName -ne $updateAccount.UserName)
								{
									$updateAccount.UserName = $account.UserName	
								}
							}
						}
						
						# Update the existing account
						$restBody = @{ Accounts=$updateAccount } | ConvertTo-Json -depth 3
						$urlUpdateAccount = $URL_AccountDetails -f $s_Account.AccountID
						$UpdateAccountResult = $(Invoke-Rest -Uri $urlUpdateAccount -Header $g_LogonHeader -Body $restBody -Command "PUT")
						Log-Msg -Type Info -MSG "Account Updated Successfully"
						# Increment counter
						$counter++
						Log-Msg -Type Info -MSG "[$counter/$rowCount] Updated $($account.username)@$($account.address) successfully."
					}
					ElseIf($Create)
					{
						# Account Exists, Creating the same account again will cause duplications - Verify with user
						Write-Warning "The Account Exists, Creating the same account twice will cause duplications" -WarningAction Inquire
						# If the user clicked yes, the account will be created
						$createAccount = $true
					}
				}
				Else
				{
					If($Create)
					{
						$createAccount = $true
					}
				}
				if($createAccount)
				{
					# Create the Account
					$restBody = @{ account=$account } | ConvertTo-Json -Depth 2
					Log-Msg -Type Debug -Msg $restBody
					$addAccountResult = $(Invoke-Rest -Uri $URL_Account -Header $g_LogonHeader -Body $restBody -Command "Post")
					if($addAccountResult -ne $null)
					{
						Log-Msg -Type Info -MSG "Account Onboarded Successfully"
						# Increment counter
						$counter++
						Log-Msg -Type Info -MSG "[$counter/$rowCount] Added $($account.username)@$($account.address) successfully."  
					}
				}
			}
			catch{
				Log-Msg -Type Error -MSG "There was an error onboarding $($account.username)@$($account.address) into the Password Vault."
			}
		}
		else
		{
			Log-Msg -Type Info -MSG "Skipping onboarding $($account.username)@$($account.address) into the Password Vault."
		}
	}	
#endregion

#region [Logoff]
	# Logoff the session
    # ------------------
    Write-Host "Logoff Session..."
    Invoke-Rest -Uri $URL_CyberArkLogoff -Header $g_LogonHeader -Command "Post"
	# Footer
	Log-Msg -Type Info -MSG "Vaulted ${counter} out of ${rowCount} accounts successfully." -Footer
#endregion