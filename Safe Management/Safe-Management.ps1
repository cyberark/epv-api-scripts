###########################################################################
#
# NAME: Manage Safes using REST API
#
# AUTHOR:  Jake DeSantis, Carl Anderson
#
# COMMENT: 
# This script will help in Safe Management tasks
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v9.8 and above
#
# VERSION HISTORY:
# 1.0 16/12/2018 - Initial release
# 1.1 06/02/2019 - Bug fix
#
###########################################################################
[CmdletBinding(DefaultParameterSetName="List")]
param
(
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com/passwordvault)")]
	[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,
		
	# Use this switch to list Safes
	[Parameter(ParameterSetName='List',Mandatory=$true)][switch]$List,
	# Use this switch to Add Safes
	[Parameter(ParameterSetName='Add',Mandatory=$true)][switch]$Add,
	# Use this switch to Add Safe Members
	[Parameter(ParameterSetName='Members',Mandatory=$true)][switch]$Members,
		
	# Safe Name
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="Enter a Safe Name to filter by")]
	[Parameter(ParameterSetName='Add',Mandatory=$false,HelpMessage="Enter a Safe Name to create")]
	[Parameter(ParameterSetName='Members',Mandatory=$true,HelpMessage="Enter a Safe Name to add members to")]
	[ValidateScript({$_.Length -le 28})]
	[Alias("Safe")]
	[String]$SafeName,
	
	# Safe Description
	[Parameter(ParameterSetName='Add',Mandatory=$false,HelpMessage="Enter a Safe Description")]
	[Alias("Description")]
	[String]$SafeDescription,
	
	# Import File support
	[Parameter(ParameterSetName='Add',Mandatory=$false,HelpMessage="Enter a file path for bulk safe creation")]
	[ValidateScript( { Test-Path -Path $_ -PathType Leaf -IsValid})]
	[ValidatePattern( '\.csv$' )]
	[Alias("File")]
	[String]$FilePath,
	
	# Member Roles 
	[Parameter(ParameterSetName='Members',Mandatory=$false,HelpMessage="Enter a role for the member to add (Default: EndUser)")]
	[ValidateSet("Admin", "Auditor", "EndUser", "Owner")]
	[Alias("Role")]
	[String]$MemberRole = "EndUser",
	
	# User / Member name 
	[Parameter(ParameterSetName='Members',Mandatory=$false,HelpMessage="Enter the user name to add as member to the safe")]
	[ValidateScript({$_.Length -le 128})]
	[Alias("User")]
	[String]$UserName,
	
	# User / Member Vault Location
	[Parameter(ParameterSetName='Members',Mandatory=$false,HelpMessage="Enter the vault-integrated LDAP directory name the vault should search for the account. Must match one of the directory names defined in the LDAP Integration page of the PVWA. (Default: Search in Vault)")]
	[Alias("Location")]
	[String]$UserLocation = "Vault"
)

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path

$URL_PVWAWebServices = $PVWAURL+"/WebServices"
$URL_PVWABaseAPI = $URL_PVWAWebServices+"/PIMServices.svc"
$URL_CyberArkAuthentication = $URL_PVWAWebServices+"/auth/cyberark/CyberArkAuthenticationService.svc"
$URL_CyberArkLogon = $URL_CyberArkAuthentication+"/Logon"
$URL_CyberArkLogoff = $URL_CyberArkAuthentication+"/Logoff"

# URL Methods
# -----------
$URL_Safes = $URL_PVWABaseAPI+"/Safes"
$URL_SpecificSafe = $URL_PVWABaseAPI+"/Safes/{0}"
$URL_SafeMembers = $URL_SpecificSafe+"/Members"

# Script Defaults
# ---------------

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
		write-debug "Returning URL Encode of $sText"
		return [System.Web.HttpUtility]::UrlEncode($sText)
	}
	else
	{
		return ""
	}
}

Function Get-LogonHeader
{
	param(
		[System.Management.Automation.CredentialAttribute()]$Credentials
	)
	# Create the POST Body for the Logon
    # ----------------------------------
    $logonBody = @{ username=$Credentials.username.Replace('\','');password=$Credentials.GetNetworkCredential().password } | ConvertTo-Json
	try{
		# Logon
		Write-Debug "Invoke-RestMethod -Method Post -Uri $URL_CyberArkLogon -ContentType 'application/json' -Body $($logonBody.Replace($Credentials.GetNetworkCredential().password,"****"))"
	    $logonToken = (Invoke-RestMethod -Method Post -Uri $URL_CyberArkLogon -ContentType "application/json" -Body $logonBody).CyberArkLogonResult
				
		# Clear logon body
		$logonBody = ""
	}
	catch
	{
		Write-Host -ForegroundColor Red $_.Exception.Message
		$logonToken = ""
	}

    If ([string]::IsNullOrEmpty($logonToken))
    {
        Write-Host -ForegroundColor Red "Logon Token is Empty - Cannot login"
        break
    }
	
    # Create a Logon Token Header (This will be used through out all the script)
    # ---------------------------
    $logonHeader =  New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $logonHeader.Add("Authorization", $logonToken)
	
	return $logonHeader
}

Function Get-Safes 
{
<#
.SYNOPSIS
Lists the cyberark safes that the APIUser has access to

.DESCRIPTION
Lists the cyberark safes that the APIUser has access to

.EXAMPLE
Get-Safes

#>

    [CmdletBinding()]
    [OutputType([String])]
    Param
    (
    )

try {
        Write-Host "Retrieving safes from the $caEnv vault..." -ForegroundColor Yellow #DEBUG
        $safes = (Invoke-RestMethod -Uri $URL_Safes -Method GET -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 3600000).GetSafesResult
        return $safes
    }catch{
        Write-Host "There was an error retrieving the safes from the Vault. The error was:" -ForegroundColor Red #ERROR
        Write-Error $_.Exception.Response.StatusDescription
    }

}

Function Get-Safe
{
	param ($safeName)
	$_safe = $null
	try{
		$accSafeURL = $URL_SpecificSafe -f $(Encode-URL $safeName)
		$_safe = $(Invoke-RestMethod -Uri $accSafeURL -Method "Get" -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 3600000 -ErrorAction "SilentlyContinue").GetSafeResult
	}
	catch
	{
		Write-Error $_.Exception.Response.StatusDescription
	}
	
	return $_safe
}

Function Create-Safe
{
<#
.SYNOPSIS
Allows a user to create a new cyberArk safe

.DESCRIPTION
Creates a new cyberark safe

.EXAMPLE
New-CyberArkSafe -safename "x0-Win-S-Admins" -safeDescription "Safe description goes here"

#>
    [CmdletBinding()]
    [OutputType()]
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$safename,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string]$safedescription,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string]$managingCPM="PasswordManager",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [int]$numVersionRetention=7,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [int]$numDaysRetention=5,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [bool]$EnableOLAC=$false
    )


$createSafeBody =@"
{
"safe":
    { 
    "SafeName":"$safename", 
    "Description":"$safeDescription", 
    "OLACEnabled":"$enableOLAC", 
    "ManagingCPM":"$managingCPM", 
    "NumberOfVersionsRetention":$numVersionRetention,
    } 
}
"@

	try {
        Write-Host "Adding the safe $safename to the Vault..." -ForegroundColor Yellow #DEBUG
        $safeadd = Invoke-RestMethod -Uri $URL_Safes -Body $createSafeBody -Method POST -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 3600000
    }catch{
        Write-Host "Error adding $safename to the Vault. The error was:" -ForegroundColor Red #ERROR
        Write-Error $_.Exception.Response.StatusDescription
    }
}

Function Set-SafeMember 
{
<#
.SYNOPSIS
Gives granular permissions to a member on a cyberark safe

.DESCRIPTION
Gives granular permission to a cyberArk safe to the particular member based on parameters sent to the command.

.EXAMPLE
Set-SafeMember -safename "Win-Local-Admins" -safemember "Win-Local-Admins" -memberSearchInLocation "LDAP Directory Name"

.EXAMPLE
Set-SafeMember -safename "Win-Local-Admins" -safemember "Administrator" -memberSearchInLocation vault

#>
    [CmdletBinding()]
    [OutputType()]
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({((Get-Safes).safename) -contains $_})]
        $safename,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        $safeMember,
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Which vault-integrated LDAP directory name the vault should search for the account. Must match one of the directory names defined in the LDAP Integration page of the PVWA.",
                   Position=0)]
        $memberSearchInLocation,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permUseAccounts = "false",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permRetrieveAccounts = "false",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permListAccounts = "false",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permAddAccounts = "false",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permUpdateAccountContent = "false",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permUpdateAccountProperties = "false",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permInitiateCPMManagement = "false",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permSpecifyNextAccountContent = "false",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permRenameAccounts = "false",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permDeleteAccounts = "false",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permUnlockAccounts = "false",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permManageSafe = "false",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permManageSafeMembers = "false",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permBackupSafe = "false",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permViewAuditLog = "false",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permViewSafeMembers = "false",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [int]$permRequestsAuthorizationLevel = 0,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permAccessWithoutConfirmation = "false",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permCreateFolders = "false",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permDeleteFolders = "false",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$permMoveAccountsAndFolders = "false"
    )

$SafeMembersBody =@"
{

"member":{
    "MemberName":"$safeMember",
    "SearchIn":"$memberSearchInLocation",
    "MembershipExpirationDate":null,
    "Permissions":[
        {"Key":"UseAccounts", "Value":$permUseAccounts},
        {"Key":"RetrieveAccounts", "Value":$permRetrieveAccounts},
        {"Key":"ListAccounts", "Value":$permListAccounts},
        {"Key":"AddAccounts", "Value":$permAddAccounts},
        {"Key":"UpdateAccountContent", "Value":$permUpdateAccountContent},
        {"Key":"UpdateAccountProperties", "Value":$permUpdateAccountProperties},
        {"Key":"InitiateCPMAccountManagementOperations","Value":$permInitiateCPMManagement},
        {"Key":"SpecifyNextAccountContent", "Value":$permSpecifyNextAccountContent},
        {"Key":"RenameAccounts", "Value":$permRenameAccounts},
        {"Key":"DeleteAccounts", "Value":$permDeleteAccounts},
        {"Key":"UnlockAccounts", "Value":$permUnlockAccounts},
        {"Key":"ManageSafe", "Value":$permManageSafe},
        {"Key":"ManageSafeMembers", "Value":$permManageSafeMembers},
        {"Key":"BackupSafe", "Value":$permBackupSafe},
        {"Key":"ViewAuditLog", "Value":$permViewAuditLog},
        {"Key":"ViewSafeMembers", "Value":$permViewSafeMembers},
        {"Key":"RequestsAuthorizationLevel", "Value":$permRequestsAuthorizationLevel},
        {"Key":"AccessWithoutConfirmation", "Value":$permAccessWithoutConfirmation},
        {"Key":"CreateFolders", "Value":$permCreateFolders},
        {"Key":"DeleteFolders", "Value":$permDeleteFolders},
        {"Key":"MoveAccountsAndFolders", "Value":$permMoveAccountsAndFolders}
        ]
    }
}
"@

    try {
        Write-Host "Setting safe membership for $safeMember located in $memberSearchInLocation on $safeName in the $caEnv vault..." -ForegroundColor Yellow #DEBUG
        $setSafeMembers = Invoke-RestMethod -Uri $($URL_SafeMembers -f $(Encode-URL $safeName)) -Body $safeMembersBody -Method POST -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 3600000
    }catch{
        Write-Host "There was an error setting the membership for $safeMember on $safeName in the Vault. The error was:" -ForegroundColor Red #ERROR
        Write-Error $_.Exception.Response.StatusDescription
    }
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
		$accSafeMembersURL = $URL_SafeMembers -f $(Encode-URL $safeName)
		$_safeMembers = $(Invoke-RestMethod -Uri $accSafeMembersURL-Method POST -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 3600000 -ErrorAction "SilentlyContinue")
		# Remove default users and change UserName to MemberName
		$_safeOwners = $_safeMembers.members | Where {$_.UserName -notin $_defaultUsers} | Select-Object -Property @{Name = 'MemberName'; Expression = { $_.UserName }}, Permissions
	}
	catch
	{
		Write-Host "There was an error getting the safe $safeName Members. The error was:" -ForegroundColor Red #ERROR
        Write-Error $_.Exception.Response.StatusDescription
	}
	
	return $_safeOwners
}

Function Convert-ToBool
{
	param (
		[string]$txt
	)
	$retBool = $false
	
if ([bool]::TryParse($txt, [ref]$retBool)) {
    # parsed to a boolean
    return $retBool.ToString().ToLower()
	} else {
		Write-Host "The input ""$txt"" is not in the correct format (true/false), defaulting to False" -ForegroundColor Red
		return "false"
	}
}
#endregion

If (Test-CommandExists Invoke-RestMethod)
{

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
        Write-Host -ForegroundColor Red "PVWA URL can not be empty"
        break
    }

#region [Logon]
	# Get Credentials to Login
	# ------------------------
	$caption = "Safe Management"
	$msg = "Enter your User name and Password"; 
	$creds = $Host.UI.PromptForCredential($caption,$msg,"","")
	if ($creds -ne $null)
	{
		$g_LogonHeader = $(Get-LogonHeader -Credentials $creds)
		if([string]::IsNullOrEmpty($g_LogonHeader)) { break }
	}
	else { 
		Write-Error "No Credentials were entered"
		break
	}
#endregion

	$response = ""
	switch($PsCmdlet.ParameterSetName)
	{
		"List"
		{
			# List all Safes
			Write-Host "Retrieving Safes..." -ForegroundColor Yellow
			
			try{
				If (![string]::IsNullOrEmpty($SafeName))
				{
					Get-Safe -SafeName $SafeName
				}
				else
				{
					Get-Safes
				}
			} catch {
				Write-Host "Error retrieving safes" -ForegroundColor Red #ERROR
				Write-Error $_.Exception.Message
			}
		}
		"Add"
		{
			try{
				if(![string]::IsNullOrEmpty($FilePath))
				{
					# Bulk Import of Safes
					$csv = Import-Csv $FilePath

					# For each line in the csv, import the safe
					ForEach ($line in $csv)
					{
						Write-Host "Importing safe $($line.safename) with safe member $($line.member)..." -ForegroundColor Yellow #DEBUG
						#If safe doesn't exist, create the new safe
						if (((Get-Safes).safename) -notcontains $line.safename) {
							Create-Safe -safename $line.safename -safedescription $line.description
						}
							
						# Add permissions to the safe
						Set-SafeMember -safename $line.safename -safeMember $line.member -memberSearchInLocation $line.MemberLocation `
							-permUseAccounts $(Convert-ToBool $line.UseAccounts) -permRetrieveAccounts $(Convert-ToBool $line.RetrieveAccounts) -permListAccounts $(Convert-ToBool $line.ListAccounts) `
							-permAddAccounts $(Convert-ToBool $line.AddAccounts) -permUpdateAccountContent $(Convert-ToBool $line.UpdateAccountContent) -permUpdateAccountProperties $(Convert-ToBool $line.UpdateAccountProperties) `
							-permInitiateCPMManagement $(Convert-ToBool $line.InitiateCPMAccountManagementOperations) -permSpecifyNextAccountContent $(Convert-ToBool $line.SpecifyNextAccountContent) `
							-permRenameAccounts $(Convert-ToBool $line.RenameAccounts) -permDeleteAccounts $(Convert-ToBool $line.DeleteAccounts) -permUnlockAccounts $(Convert-ToBool $line.UnlockAccounts) `
							-permManageSafe $(Convert-ToBool $line.ManageSafe) -permManageSafeMembers $(Convert-ToBool $line.ManageSafeMembers) -permBackupSafe $(Convert-ToBool $line.BackupSafe) `
							-permViewAuditLog $(Convert-ToBool $line.ViewAuditLog) -permViewSafeMembers $(Convert-ToBool $line.ViewSafeMembers) `
							-permRequestsAuthorizationLevel $line.RequestsAuthorizationLevel -permAccessWithoutConfirmation $(Convert-ToBool $line.AccessWithoutConfirmation) `
							-permCreateFolders $(Convert-ToBool $line.CreateFolders) -permDeleteFolders $(Convert-ToBool $line.DeleteFolders) -permMoveAccountsAndFolders $(Convert-ToBool $line.MoveAccountsAndFolders)
					}
				}
				else
				{
					# Create one Safe
					Write-Host "Adding the safe $SafeName..." -ForegroundColor Yellow
					Create-Safe -SafeName $SafeName
				}			
			}catch{
				Write-Host "Error adding $SafeName" -ForegroundColor Red #ERROR
				Write-Error $_.Exception.Message
			}
		}
		"Members"
		{
			if([string]::IsNullOrEmpty($UserName))
			{
				# List all members of a safe
				Get-SafeMembers -SafeName $SafeName
			}
			else
			{
				# Add a member to a safe
				[bool]$permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = `
					$permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafe = $permManageSafeMembers = $permBackupSafe = $permViewAuditLog = `
					$permViewSafeMembers = $permAccessWithoutConfirmation = $permCreateFolders = $permDeleteFolders = $permMoveAccountsAndFolders = $false
				[int]$permRequestsAuthorizationLevel = 0
				switch($MemberRole)
				{
					"Admin"
					{
						$permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = `
							$permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafe = $permManageSafeMembers = $permBackupSafe = `
							$permViewAuditLog = $permViewSafeMembers = $permAccessWithoutConfirmation = $permCreateFolders = $permDeleteFolders = $permMoveAccountsAndFolders = $true
						$permRequestsAuthorizationLevel = 1
					}
					"Auditor"
					{
						$permListAccounts = $permViewAuditLog = $permViewSafeMembers = $true
					}
					"EndUser"
					{
						$permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permViewAuditLog = $permViewSafeMembers = $true
					}
					"Approver"
					{
						$permListAccounts = $permViewAuditLog = $permViewSafeMembers = $true
						$permRequestsAuthorizationLevel = 1
					}
					"Owner"
					{
						$permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = $permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafeMembers = $permViewAuditLog = $permViewSafeMembers = $permMoveAccountsAndFolders = $true
						$permRequestsAuthorizationLevel = 1
					}
				}
				Set-SafeMember -safename $SafeName -safeMember $UserName -memberSearchInLocation $UserLocation `
								-permUseAccounts $permUseAccounts -permRetrieveAccounts $permRetrieveAccounts -permListAccounts $permListAccounts `
								-permAddAccounts $permAddAccounts -permUpdateAccountContent $permUpdateAccountContent -permUpdateAccountProperties $permUpdateAccountProperties `
								-permInitiateCPMManagement $permInitiateCPMManagement -permSpecifyNextAccountContent $permSpecifyNextAccountContent `
								-permRenameAccounts $permRenameAccounts -permDeleteAccounts $permDeleteAccounts -permUnlockAccounts $permUnlockAccounts `
								-permManageSafe $permManageSafe -permManageSafeMembers $permManageSafeMembers -permBackupSafe $permBackupSafe `
								-permViewAuditLog $permViewAuditLog -permViewSafeMembers $permViewSafeMembers `
								-permRequestsAuthorizationLevel $permRequestsAuthorizationLevel -permAccessWithoutConfirmation $permAccessWithoutConfirmation `
								-permCreateFolders $permCreateFolders -permDeleteFolders $permDeleteFolders -permMoveAccountsAndFolders $permMoveAccountsAndFolders
			}
		}
	}
	
    # Logoff the session
    # ------------------
    Write-Host "Logoff Session..."
    Invoke-RestMethod -Method Post -Uri $URL_CyberArkLogoff -Headers $g_LogonHeader -ContentType "application/json" | Out-Null
}
else
{
    Write-Error "This script requires PowerShell version 3 or above"
}
