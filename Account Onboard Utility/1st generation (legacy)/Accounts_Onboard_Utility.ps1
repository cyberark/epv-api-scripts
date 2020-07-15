###########################################################################
#
# NAME: Accounts Onboard Utility
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will onboard all accounts from a CSV file using REST API
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
	# Mask Passwords
	if($Msg -match '(password\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=(\w+))')
	{
		$Msg = $Msg.Replace($Matches[2],"****")
	}
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
		Log-Msg -Type Verbose -MSG "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body -TimeoutSec 36000"
		$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body -TimeoutSec 36000
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
	
	return $_safe.GetSafeResult
}

Function Get-SafeMembers
{
	param (
		[Parameter(Mandatory=$true)]
		[String]$safeName
		)
	$_safeMembers = $null
	$_safeOwners = $null
	try{
		$_defaultUsers = @("Master","Batch","Backup Users","Auditors","Operators","DR Users","Notification Engines","PVWAGWAccounts","PasswordManager")
		$accSafeMembersURL = $URL_SafeMembers -f $safeName
		$_safeMembers = $(Invoke-Rest -Uri $accSafeMembersURL -Header $g_LogonHeader -Command "Get" -ErrorAction "SilentlyContinue")
		$_safeOwners = $_safeMembers.members | Where {$_.UserName -notin $_defaultUsers} | Select-Object -Property @{Name = 'MemberName'; Expression = { $_.UserName }}, Permissions
	}
	catch
	{
		Log-Msg -Type Error -MSG $_.Exception.Response.StatusDescription
	}
	
	return $_safeOwners
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
	If($templateSafeObject -ne $null)
	{
		# Using Template Safe
		Log-Msg -Type Info -MSG "Creating Safe $safeName according to Template"
		# Update the safe name in the Safe Template Object
		$templateSafeObject.SafeName = $safeName
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

Function Add-Owner
{
	param ($safeName, $members)
	$urlOwnerAdd = $URL_SafeMembers -f $safeName
	ForEach ($bodyMember in $members)
	{
		$restBody = @{ member=$bodyMember } | ConvertTo-Json -Depth 3
		# Add the Safe Owner
		try {
			# Add the Safe Owner
			$restResponse = Invoke-Rest -Uri $urlOwnerAdd -Header $g_LogonHeader -Command "Post" -Body $restBody
		} catch {
			Log-Msg -Type Error -MSG "Failed to add Owner to safe $safeName with error: $($_.Exception.Response.StatusDescription)"
		}
	}
}

Function Get-Account
{
	param ($accountName, $accountAddress, $safeName)
	$_account = $null
	try{
		# Search for created account
		$urlSearchAccount = $URL_Accounts+"?Safe="+$(Encode-URL $safeName)+"&Keywords="+$(Encode-URL "$accountName $accountAddress")
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
	param ($accountName, $accountAddress, $safeName)
	try{
		If ($null -eq $(Get-Account -accountName $accountName -accountAddress $accountAddress -safeName $safeName))
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

# Check if Powershell is running in Constrained Language Mode
If($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage")
{
	Log-Msg -Type Error -MSG "Powershell is currently running in $($ExecutionContext.SessionState.LanguageMode) mode which limits the use of some API methods used in this script.`
	PowerShell Constrained Language mode was designed to work with system-wide application control solutions such as CyberArk EPM or Device Guard User Mode Code Integrity (UMCI).`
	For more information: https://blogs.msdn.microsoft.com/powershell/2017/11/02/powershell-constrained-language-mode/"
	Log-Msg -Type Info -MSG "Script ended" -Footer -LogFile $LOG_FILE_PATH
	return
}

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
Else
{
	try{
		Log-Msg -Type Debug -Msg "Setting script to use TLS 1.2"
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
	} catch {
		Log-Msg -Type Error -Msg "Could not change SSL validation"
		Log-Msg -Type Error -Msg $_.Exception
		return
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
	$TemplateSafeDetails = $null
	If(![string]::IsNullOrEmpty($TemplateSafe) -and !$NoSafeCreation)
	{
		Log-Msg -Type Info -Msg "Checking Template Safe..."
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
		# Check if there are custom properties
		$customProps = $($account.PSObject.Properties | Where { $_.Name -notin "username","address","safe","platformID","password","disableAutoMgmt","disableAutoMgmtReason","groupName","groupPlatformID" })
		if($customProps -ne $null)
		{
			$account | Add-Member properties @()
			# Convert any non-default property in the CSV as a new account property
			ForEach ($prop in $customProps)
			{
				If(![string]::IsNullOrEmpty($prop.Value))
				{ $account.properties += @{"Key"=$prop.Name; "Value"=$prop.Value} }
				$account.PSObject.Properties.Remove($prop.Name)
			}
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
				if ($TemplateSafeDetails -ne $null -and $TemplateSafeMembers -ne $null)
				{
					Add-Owner -Safe $account.Safe -Members $TemplateSafeMembers
				}
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
			$accExists = $(Test-Account -safeName $account.Safe -accountName $account.username -accountAddress $accountAddress)
			
			try{
				If($accExists)
				{
					If($Update)
					{
						# Get Existing Account Details
						$s_Account = $(Get-Account -safeName $account.Safe -accountName $account.username -accountAddress $accountAddress)
						
						# Create the Account to update with current properties
						$updateAccount = "" | select Safe,Folder,PlatformID,Address,UserName,DeviceType,AccountName,Properties
						$updateAccount.Properties = @()
						$updateAccount.Properties += $account.properties
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
							elseif($sProp.Key -eq "Folder")
							{ 
								$updateAccount.Folder = $sProp.Value 
								If(![string]::IsNullOrEmpty($account.Folder) -and $account.Folder -ne $updateAccount.Folder)
								{
									$updateAccount.Folder = $account.Folder	
								}
							}
							elseif($sProp.Key -eq "PolicyID")
							{ 
								$updateAccount.PlatformID = $sProp.Value
								If(![string]::IsNullOrEmpty($account.PlatformID) -and $account.PlatformID -ne $updateAccount.PlatformID)
								{
									$updateAccount.PlatformID = $account.PlatformID	
								}
							}
							elseif($sProp.Key -eq "DeviceType")
							{ 
								$updateAccount.DeviceType = $sProp.Value
								#If(![string]::IsNullOrEmpty($account.DeviceType) -and $account.DeviceType -ne $updateAccount.DeviceType)
								#{
								#	$updateAccount.DeviceType = $account.DeviceType	
								#}
							}
							elseif($sProp.Key -eq "Address")
							{ 
								$updateAccount.Address = $sProp.Value
								If(![string]::IsNullOrEmpty($account.Address) -and $account.Address -ne $updateAccount.Address)
								{
									$updateAccount.Address = $account.Address	
								}
							}
							elseif($sProp.Key -eq "Name")
							{ 
								$updateAccount.AccountName = $sProp.Value
								If(![string]::IsNullOrEmpty($account.AccountName) -and $account.AccountName -ne $updateAccount.AccountName)
								{
									$updateAccount.AccountName = $account.AccountName	
								}
							}
							elseif($sProp.Key -eq "UserName")
							{ 
								$updateAccount.UserName = $sProp.Value
								If(![string]::IsNullOrEmpty($account.UserName) -and $account.UserName -ne $updateAccount.UserName)
								{
									$updateAccount.UserName = $account.UserName	
								}
							}
							else
							{
								# Check other properties on the account to update
								ForEach($uProp in $updateAccount.Properties)
								{
									if($uProp.ContainsValue($sProp.Name))
									{
										$uProp.Value = $sProp.Value
									}
								}
							}
						}
						
						# Check if we need to add more properties to the updated account
						If ($account.disableAutoMgmt)
						{
							$updateAccount.Properties += @{"Key"="CPMDisabled"; "Value"="yes"}
						}
						if($InDebug)
						{$updateAccount}
						# Update the existing account
						$restBody = @{ Accounts=$updateAccount } | ConvertTo-Json -depth 5
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
					$restBody = @{ account=$account } | ConvertTo-Json -Depth 5
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
