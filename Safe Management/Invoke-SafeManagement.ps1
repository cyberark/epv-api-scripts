###########################################################################
#
# NAME: Manage Safes using REST API
#
# AUTHOR:  Jake DeSantis, Carl Anderson, Assaf Miron
#
# COMMENT: 
# This script will help in Safe Management tasks
# This script also supports multi-threading 
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v11.3 and above
#
# VERSION HISTORY:
# 1.0 10/03/2020 - Initial release
#
###########################################################################
[CmdletBinding(DefaultParameterSetName="List")]
param
(
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com/passwordvault)")]
	[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,
	
	[Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark","ldap","radius")]
	[String]$AuthType="cyberark",
		
	# Use this switch to list Safes
	[Parameter(ParameterSetName='List',Mandatory=$true)][switch]$List,
	# Use this switch to Add Safes
	[Parameter(ParameterSetName='Add',Mandatory=$true)][switch]$Add,
	# Use this switch to Update Safes
	[Parameter(ParameterSetName='Update',Mandatory=$true)][switch]$Update,
	# Use this switch to Delete Safes
	[Parameter(ParameterSetName='Delete',Mandatory=$true)][switch]$Delete,
	# Use this switch to Add Safe Members
	[Parameter(ParameterSetName='Members',Mandatory=$true)][switch]$Members,
		
	# Safe Name
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="Enter a Safe Name to filter by")]
	[Parameter(ParameterSetName='Add',Mandatory=$false,HelpMessage="Enter a Safe Name to create")]
	[Parameter(ParameterSetName='Update',Mandatory=$false,HelpMessage="Enter a Safe Name to update")]
	[Parameter(ParameterSetName='Delete',Mandatory=$true,HelpMessage="Enter a Safe Name to delete")]
	[Parameter(ParameterSetName='Members',Mandatory=$true,HelpMessage="Enter a Safe Name to add members to")]
	[ValidateScript({$_.Length -le 28})]
	[Alias("Safe")]
	[String]$SafeName,
	
	# Safe Description
	[Parameter(ParameterSetName='Add',Mandatory=$false,HelpMessage="Enter a Safe Description")]
	[Parameter(ParameterSetName='Update',Mandatory=$false,HelpMessage="Enter an updated Safe Description")]
	[Alias("Description")]
	[String]$SafeDescription,
	
	# Import File support
	[Parameter(ParameterSetName='Add',Mandatory=$false,HelpMessage="Enter a file path for bulk safe creation")]
	[Parameter(ParameterSetName='Update',Mandatory=$false,HelpMessage="Enter a file path for bulk safe update")]
	[Parameter(ParameterSetName='Delete',Mandatory=$false,HelpMessage="Enter a file path for bulk safe deletion")]
	[ValidateScript( { Test-Path -Path $_ -PathType Leaf -IsValid})]
	[ValidatePattern( '\.csv$' )]
	[Alias("File")]
	[String]$FilePath,
	
	# Add / Update Safe options
	[Parameter(ParameterSetName='Add',Mandatory=$false,HelpMessage="Enter the managing CPM name")]
	[Parameter(ParameterSetName='Update',Mandatory=$false,HelpMessage="Enter the updated managing CPM name")]
	[string]$ManagingCPM,
	
	[Parameter(ParameterSetName='Add',Mandatory=$false,HelpMessage="Enter the number of versions retention")]
	[Parameter(ParameterSetName='Update',Mandatory=$false,HelpMessage="Enter the updated number of versions retention")]
	[int]$NumVersionRetention,
	
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
	[String]$UserLocation = "Vault",
	
	# Support for Threading (Logon Connection Number)
	[Parameter(Mandatory=$false)]
	[Switch]$Threaded,
	
	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory=$false)]
	[Switch]$DisableSSLVerify
)

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path

$URL_PVWAWebServices = $PVWAURL+"/WebServices"
$URL_PVWABaseAPI = $URL_PVWAWebServices+"/PIMServices.svc"
$URL_PVWAAPI = $PVWAURL+"/api"
$URL_Authentication = $URL_PVWAAPI+"/auth"
$URL_Logon = $URL_Authentication+"/$AuthType/Logon"
$URL_Logoff = $URL_Authentication+"/Logoff"

# URL Methods
# -----------
$URL_Safes = $URL_PVWABaseAPI+"/Safes"
$URL_SpecificSafe = $URL_PVWABaseAPI+"/Safes/{0}"
$URL_SafeMembers = $URL_SpecificSafe+"/Members"

# Script Defaults
# ---------------

# Initialize Script Variables
# ---------------------------
# Set a global Header Token parameter
$global:g_LogonHeader = ""

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
		[Parameter(Mandatory=$true)]
		[System.Management.Automation.CredentialAttribute()]$Credentials,
		[Parameter(Mandatory=$false)]
		[bool]$UseConcurrentSessions = $false
	)
	# Create the POST Body for the Logon
    # ----------------------------------
	$logonBody = @{ username=$Credentials.username.Replace('\',''); password=$Credentials.GetNetworkCredential().password; concurrentSession=$UseConcurrentSessions } | ConvertTo-Json
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
		[Parameter(Mandatory=$false)]
		$_LogonHeader = $g_LogonHeader
    )

try {
        Write-Host "Retrieving safes from the vault..." -ForegroundColor Yellow #DEBUG
        $safes = (Invoke-RestMethod -Uri $URL_Safes -Method GET -Headers $_LogonHeader -ContentType "application/json" -TimeoutSec 3600000).GetSafesResult
        return $safes
    }catch{
        Write-Host "There was an error retrieving the safes from the Vault. The error was:" -ForegroundColor Red #ERROR
        Write-Error $_.Exception.Response.StatusDescription
    }

}

Function Get-Safe
{
<#
.SYNOPSIS
Get all Safe details on a specific safe

.DESCRIPTION
Get all Safe details on a specific safe

.EXAMPLE
Get-Safe -safeName "x0-Win-S-Admins"

#>
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
Create-Safe -safename "x0-Win-S-Admins" -safeDescription "Safe description goes here"

#>
    [CmdletBinding()]
    [OutputType()]
    Param
    (
		[Parameter(Mandatory=$false)]
		$_LogonHeader = $g_LogonHeader,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$safename,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string]$safedescription,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string]$managingCPM="PasswordManager",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [int]$numVersionRetention=7,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [int]$numDaysRetention=-1,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [bool]$EnableOLAC=$false
    )

$createSafeBody=@{
            safe=@{
            "SafeName"="$safename"; 
            "Description"="$safeDescription"; 
            "OLACEnabled"=$enableOLAC; 
            "ManagingCPM"="$managingCPM";
            "NumberOfVersionsRetention"=$numVersionRetention;
            }
}

If($numDaysRetention -gt -1)
{
	$createSafeBody.Safe.Add("NumberOfDaysRetention",$numDaysRetention)
	$createSafeBody.Safe.Remove("NumberOfVersionsRetention")
}

	try {
        Write-Host "Adding the safe $safename to the Vault..." -ForegroundColor Yellow #DEBUG
        $safeadd = Invoke-RestMethod -Uri $URL_Safes -Body ($createSafeBody | ConvertTo-Json) -Method POST -Headers $_LogonHeader -ContentType "application/json" -TimeoutSec 3600000
    }catch{
        Write-Host "Error adding $safename to the Vault. The error was:" -ForegroundColor Red #ERROR
        Write-Error $_.Exception.Response.StatusDescription
    }
}

Function Update-Safe
{
<#
.SYNOPSIS
Allows a user to update an existing cyberArk safe

.DESCRIPTION
Updates a new cyberark safe

.EXAMPLE
Update-Safe -safename "x0-Win-S-Admins" -safeDescription "Updated Safe description goes here" -managingCPM "PassManagerDMZ"

#>
    [CmdletBinding()]
    [OutputType()]
    Param
    (
		[Parameter(Mandatory=$false)]
		$_LogonHeader = $g_LogonHeader,
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
	
	# Get the current safe details and update when necessary
	$getSafe = Get-Safe -safeName $safeName
	$updateDescription = $getSafe.Description
	$updateOLAC = $getSafe.OLACEnabled
	$updateManageCPM = $getSafe.ManagingCPM
	$updateRetVersions = $getSafe.NumberOfVersionsRetention
	$updateRetDays = $getSafe.NumberOfDaysRtention
	
	If($getSafe.Description -ne $safeDescription)
	{
		$updateDescription = $safeDescription
	}
	If($getSafe.OLACEnabled -ne $EnableOLAC)
	{
		$updateOLAC = $EnableOLAC
	}
	If($getSafe.ManagingCPM -ne $managingCPM)
	{
		$updateManageCPM = $managingCPM
	}
	If($getSafe.NumberOfVersionsRetention -ne $numVersionRetention)
	{
		$updateRetVersions = $numVersionRetention
	}
	If($getSafe.NumberOfDaysRtention -ne $numDaysRetention)
	{
		$updateRetDays = $numDaysRetention
	}
	
$updateSafeBody=@{
            safe=@{
            "SafeName"="$safename"; 
            "Description"="$updateDescription"; 
            "OLACEnabled"="$updateOLAC"; 
            "ManagingCPM"="$updateManageCPM";
            "NumberOfVersionsRetention"=$updateRetVersions;
            "NumberOfDaysRtention"=$updateRetDays;
            }
} | ConvertTo-Json

	try {
        Write-Host "Updating safe $safename..." -ForegroundColor Yellow #DEBUG
        $safeupdate = Invoke-RestMethod -Uri ($URL_SpecificSafe -f $safeName) -Body $updateSafeBody -Method PUT -Headers $_LogonHeader -ContentType "application/json" -TimeoutSec 3600000
    }catch{
        Write-Host "Error updating $safename. The error was:" -ForegroundColor Red #ERROR
        Write-Error $_.Exception.Response.StatusDescription
    }
}

Function Delete-Safe
{
<#
.SYNOPSIS
Allows a user to delete a cyberArk safe

.DESCRIPTION
Deletes a cyberark safe

.EXAMPLE
Delete-Safe -safename "x0-Win-S-Admins"

#>
    [CmdletBinding()]
    [OutputType()]
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$safename
    )

	try {
        Write-Host "Deleting the safe $safename from the Vault..." -ForegroundColor Yellow #DEBUG
        $safedelete = Invoke-RestMethod -Uri ($URL_SpecificSafe -f $safeName) -Method DELETE -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 3600000
    }catch{
        Write-Host "Error deleting $safename from the Vault. The error was:" -ForegroundColor Red #ERROR
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
		[Parameter(Mandatory=$false)]
		$_LogonHeader = $g_LogonHeader,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({((Get-Safes -_LogonHeader $_LogonHeader).safename) -contains $_})]
        $safename,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        $safeMember,
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Which vault-integrated LDAP directory name the vault should search for the account. Must match one of the directory names defined in the LDAP Integration page of the PVWA.",
                   Position=0)]
        $memberSearchInLocation,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permUseAccounts = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permRetrieveAccounts = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permListAccounts = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permAddAccounts = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permUpdateAccountContent = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permUpdateAccountProperties = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permInitiateCPMManagement = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permSpecifyNextAccountContent = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permRenameAccounts = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permDeleteAccounts = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permUnlockAccounts = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permManageSafe = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permManageSafeMembers = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permBackupSafe = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permViewAuditLog = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permViewSafeMembers = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [int]$permRequestsAuthorizationLevel = 0,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permAccessWithoutConfirmation = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permCreateFolders = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permDeleteFolders = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permMoveAccountsAndFolders = $false
    )

$SafeMembersBody = @{
        member = @{
            MemberName = "$safeMember"
            SearchIn = "$memberSearchInLocation"
            MembershipExpirationDate = "$null"
            Permissions = @(
                @{Key="UseAccounts";Value=$permUseAccounts}
                @{Key="RetrieveAccounts";Value=$permRetrieveAccounts}
                @{Key="ListAccounts";Value=$permListAccounts}
                @{Key="AddAccounts";Value=$permAddAccounts}
                @{Key="UpdateAccountContent";Value=$permUpdateAccountContent}
                @{Key="UpdateAccountProperties";Value=$permUpdateAccountProperties}
                @{Key="InitiateCPMAccountManagementOperations";Value=$permInitiateCPMManagement}
                @{Key="SpecifyNextAccountContent";Value=$permSpecifyNextAccountContent}
                @{Key="RenameAccounts";Value=$permRenameAccounts}
                @{Key="DeleteAccounts";Value=$permDeleteAccounts}
                @{Key="UnlockAccounts";Value=$permUnlockAccounts}
                @{Key="ManageSafe";Value=$permManageSafe}
                @{Key="ManageSafeMembers";Value=$permManageSafeMembers}
                @{Key="BackupSafe";Value=$permBackupSafe}
                @{Key="ViewAuditLog";Value=$permViewAuditLog}
                @{Key="ViewSafeMembers";Value=$permViewSafeMembers}
                @{Key="RequestsAuthorizationLevel";Value=$permRequestsAuthorizationLevel}
                @{Key="AccessWithoutConfirmation";Value=$permAccessWithoutConfirmation}
                @{Key="CreateFolders";Value=$permCreateFolders}
                @{Key="DeleteFolders";Value=$permDeleteFolders}
                @{Key="MoveAccountsAndFolders";Value=$permMoveAccountsAndFolders}
            )
        }  
    }

    try {
        Write-Host "Setting safe membership for $safeMember located in $memberSearchInLocation on $safeName in the vault..." -ForegroundColor Yellow #DEBUG
        $setSafeMembers = Invoke-RestMethod -Uri $($URL_SafeMembers -f $(Encode-URL $safeName)) -Body ($safeMembersBody | ConvertTo-Json -Depth 5) -Method POST -Headers $_LogonHeader -ContentType "application/json" -TimeoutSec 3600000 -ErrorVariable rMethodErr
    }catch{
		if ($rmethodErr.message -like "*User or Group is already a member*"){
			Write-Host "The user $safeMember is already a member. Use the update member method instead" -ForegroundColor Red #ERROR
		}else{
			Write-Host "There was an error setting the membership for $safeMember on $safeName in the Vault. The error was:" -ForegroundColor Red #ERROR
			Write-Host ("{0} ({1})" -f $rMethodErr.message, $_.Exception.Response.StatusDescription) -ForegroundColor Red #Error
		}
    }
}

Function Get-SafeMembers
{
<#
.SYNOPSIS
Returns the permissions of a member on a cyberark safe

.DESCRIPTION
Returns the permissions of a cyberArk safe of all members based on parameters sent to the command.

.EXAMPLE
Get-SafeMember -safename "Win-Local-Admins" 

#> 
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
    return [System.Convert]::ToBoolean($txt)
	} else {
		Write-Host "The input ""$txt"" is not in the correct format (true/false), defaulting to False" -ForegroundColor Red
		return $false
	}
}

Function Create-TaskSafeImport
{
<#
.SYNOPSIS
Creates a threaded task to run for Safe Creation / Update

.DESCRIPTION
Creates a threaded task to run for Safe Creation / Update

#> 
	param (
		[Parameter(Mandatory=$true)]
		[object[]]$safeLines,
		$Credentials
		)
	
	return Start-Job -ScriptBlock {
		$sessionHeader = Get-LogonHeader $Credentials -UseConcurrentSessions $true
		ForEach ($line in $safeLines)
		{
			Write-Host "Importing safe $($line.safename) with safe member $($line.member)..." -ForegroundColor Yellow #DEBUG
			#If safe doesn't exist, create the new safe
			if (((Get-Safes -_LogonHeader $sessionHeader).safename) -notcontains $line.safename) {
				If($Add)
				{
					Write-Host "Adding the safe $SafeName..." -ForegroundColor Yellow
					Create-Safe -_LogonHeader $sessionHeader -safename $line.safename -safedescription $line.description
				}
				ElseIf($Update)
				{
					Write-Host "Updating the safe $SafeName..." -ForegroundColor Yellow
					Update-Safe -_LogonHeader $sessionHeader -safename $line.safename -safedescription $line.description
				}
			}
			# Add permissions to the safe
			Set-SafeMember -_LogonHeader $sessionHeader -safename $line.safename -safeMember $line.member -memberSearchInLocation $line.MemberLocation `
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
}
#endregion

Write-Host "Script Started"

# Check if Powershell is running in Constrained Language Mode
If($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage")
{
	Write-Host -ForegroundColor Red "Powershell is currently running in $($ExecutionContext.SessionState.LanguageMode) mode which limits the use of some API methods used in this script.`
	PowerShell Constrained Language mode was designed to work with system-wide application control solutions such as CyberArk EPM or Device Guard User Mode Code Integrity (UMCI).`
	For more information: https://blogs.msdn.microsoft.com/powershell/2017/11/02/powershell-constrained-language-mode/"
	Write-Host "Script ended"
	return
}


# Check if to disable SSL verification
If($DisableSSLVerify)
{
	try{
		Write-Warning "It is not Recommended to disable SSL verification" -WarningAction Inquire
		# Using Proxy Default credentials if the Server needs Proxy credentials
		[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
		# Using TLS 1.2 as security protocol verification
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
		# Disable SSL Verification
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
	} catch {
		Write-Host -ForegroundColor Red "Could not change SSL validation"
		Write-Host -ForegroundColor Red $_.Exception -ErrorAction "SilentlyContinue"
		return
	}
}
Else
{
	try{
		Write-Host -ForegroundColor Yellow "Setting script to use TLS 1.2"
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
	} catch {
		Write-Host -ForegroundColor Red "Could not change SSL settings to use TLS 1.2"
		Write-Host -ForegroundColor Red $_.Exception -ErrorAction "SilentlyContinue"
	}
}

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
		Set-Variable -Name g_LogonHeader -Value $(Get-LogonHeader -Credentials $creds -UseConcurrentSessions $Threaded) -Scope global
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
		{($_ -eq "Add") -or ($_ -eq "Update")} 
		{
			try{
				if(![string]::IsNullOrEmpty($FilePath))
				{
					# Bulk Import of Safes
					$csv = Import-Csv $FilePath
					# Sort List by Safes
					$sortedList = $csv | Sort-Object -Property safename
					# Safe a Jobs List
					$arrJobs = @()
					# For each Safe, Run a thread to Create the safe
					$i = 1
					$uniqueSafesList = ($sortedList | Sort-Object -Property safename -Unique | select safename)
					ForEach ($safeNameLine in $uniqueSafesList)
					{
						Write-Host "Handling Safe '$safeNameLine'..." -ForegroundColor Yellow #DEBUG
						$safeLineItems = $sortedList | Where { $_.safename -eq $safeNameLine }
						$arrJobs += Create-TaskSafeImport -SafeLines $safeLineItems -Credentials $creds
						Write-Host "Created a task for handling all Safe '$safeNameLine' tasks (Task $i/$($uniqueSafesList.count))"
					}
					Write-Host "Waiting for all tasks to finish"
					Recieve-Job $arrJobs
					Write-Host "All tasks finished!"
				}
				else
				{
					$parameters = "" | select safeName, safeDescription, managingCPM, numVersionRetention
					$parameters = New-Object -TypeName PSObject -Property @{ 
						safeName=$SafeName; 
						safeDescription=$SafeDescription;
						managingCPM=$ManagingCPM;
						numVersionRetention=$NumVersionRetention
					}
					# Keep only relevant properties (and keeping defaults when needed)
					if([string]::IsNullOrEmpty($SafeDescription))
					{
						$parameters.PSObject.Properties.Remove('safeDescription')
					}
					if([string]::IsNullOrEmpty($ManagingCPM))
					{
						$parameters.PSObject.Properties.Remove('managingCPM')
					}
					if([string]::IsNullOrEmpty($NumVersionRetention))
					{
						$parameters.PSObject.Properties.Remove('numVersionRetention')
					}
					If($Add)
					{
						# Create one Safe
						Write-Host "Adding the safe $SafeName..." -ForegroundColor Yellow
						Create-Safe @parameters
					}
					ElseIf($Update)
					{
						# Update the Safe
						Write-Host "Updating the safe $SafeName..." -ForegroundColor Yellow
						Update-Safe @parameters
					}
				}			
			}catch{
				Write-Host "Error adding/updating safe '$($line.SafeName)'" -ForegroundColor Red #ERROR
				Write-Error $_.Exception.Message
			}
		}
		"Delete"
		{
			try{
				if(![string]::IsNullOrEmpty($FilePath))
				{
					# Bulk Import of Safes
					$csv = Import-Csv $FilePath

					# For each line in the csv, import the safe
					ForEach ($line in $csv)
					{
						Write-Host "Deleting safe $($line.safename)..." -ForegroundColor Yellow #DEBUG
						Delete-Safe -safename $line.safename
					}
				}
				else
				{
					# Deleting one Safe
					Write-Host "Deleting the safe $SafeName..." -ForegroundColor Yellow
					Delete-Safe -SafeName $SafeName
				}
			}catch{
				Write-Host "Error deleting safe '$SafeName'" -ForegroundColor Red #ERROR
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
				$permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = `
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
							-permUseAccounts $($line.UseAccounts | Convert-ToBool) -permRetrieveAccounts $(Convert-ToBool $line.RetrieveAccounts) -permListAccounts $(Convert-ToBool $line.ListAccounts) `
							-permAddAccounts $(Convert-ToBool $line.AddAccounts) -permUpdateAccountContent $(Convert-ToBool $line.UpdateAccountContent) -permUpdateAccountProperties $(Convert-ToBool $line.UpdateAccountProperties) `
							-permInitiateCPMManagement $(Convert-ToBool $line.InitiateCPMAccountManagementOperations) -permSpecifyNextAccountContent $(Convert-ToBool $line.SpecifyNextAccountContent) `
							-permRenameAccounts $(Convert-ToBool $line.RenameAccounts) -permDeleteAccounts $(Convert-ToBool $line.DeleteAccounts) -permUnlockAccounts $(Convert-ToBool $line.UnlockAccounts) `
							-permManageSafe $(Convert-ToBool $line.ManageSafe) -permManageSafeMembers $(Convert-ToBool $line.ManageSafeMembers) -permBackupSafe $(Convert-ToBool $line.BackupSafe) `
							-permViewAuditLog $(Convert-ToBool $line.ViewAuditLog) -permViewSafeMembers $(Convert-ToBool $line.ViewSafeMembers) `
							-permRequestsAuthorizationLevel $line.RequestsAuthorizationLevel -permAccessWithoutConfirmation $(Convert-ToBool $line.AccessWithoutConfirmation) `
							-permCreateFolders $(Convert-ToBool $line.CreateFolders) -permDeleteFolders $(Convert-ToBool $line.DeleteFolders) -permMoveAccountsAndFolders $(Convert-ToBool $line.MoveAccountsAndFolders)
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

Write-Host "Script ended"