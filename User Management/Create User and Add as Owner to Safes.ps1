###########################################################################
#
# NAME: Create User and Add as Owner to Safes
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will create a CyberArk User and add it as Owner to a safe (or a list of safes)
# Prerequisites: Network access to the PVWA server
#				 The user running the script needs to have "Add Users" permissions on the CyberArk Vault
#				 The user running the script needs to have "Add Owner" permissions on all the input safes
#
# VERSION HISTORY:
# 1.0 24/10/2017 - Initial release
#
###########################################################################
param
(
	[Parameter(Mandatory=$true,HelpMessage="Enter the PVWA URL")]
	[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,
		
	[Parameter(Mandatory=$true,HelpMessage="Enter the Target User Name")]
	[Alias("user")]
	[String]$TargetUserName,
	[Parameter(Mandatory=$true,HelpMessage="Enter the Target Safe(s)")]
	[Alias("safes")]
	[String[]]$TargetSafes
)
# Global URLS
# -----------
$URL_PVWAWebServices = $PVWAURL+"/WebServices"
$URL_PVWABaseAPI = $URL_PVWAWebServices+"/PIMServices.svc"
$URL_PVWAAPI = $PVWAURL+"/api"
$URL_CyberArkAuthentication = $URL_PVWAWebServices+"/auth/Cyberark/CyberArkAuthenticationService.svc"
$URL_CyberArkLogon = $URL_CyberArkAuthentication+"/Logon"
$URL_CyberArkLogoff = $URL_CyberArkAuthentication+"/Logoff"


# URL Methods
# -----------
$URL_Safes = $URL_PVWABaseAPI+"/Safes"
$URL_SafeDetails = $URL_Safes+"/{0}"
$URL_SafeMembers = $URL_SafeDetails+"/Members"
$URL_Users = $URL_PVWABaseAPI+"/Users"
$URL_UserDetails = $URL_PVWABaseAPI+"/Users/{0}"


# Initialize Script Variables
# ---------------------------
# Save Global Logon Token
$g_LogonHeader = ""

# Script Defaults
# ---------------
$DEFAULT_PASSWORD = "Cyberark1"
$USER_TYPE = "EPVUser"
# Define the Basic User Permissions that we want/need
$USER_PERMISSIONS = @{ UseAccounts=$true;RetrieveAccounts=$true;ListAccounts=$true;ViewAuditLog=$true;ViewSafeMembers=$true;AddAccounts=$true;UpdateAccountContent=$true;UpdateAccountProperties=$true;InitiateCPMAccountManagementOperations=$true;DeleteAccounts=$true;RenameAccounts=$true;"SpecifyNextAccountContent"=$false;;"UnlockAccounts"=$false;"ManageSafe"=$false;"ManageSafeMembers"=$false;"BackupSafe"=$false;"RequestsAuthorizationLevel"=0;"AccessWithoutConfirmation"=$false;"CreateFolders"=$false;"DeleteFolders"=$false;"MoveAccountsAndFolders"=$false }
# Define the Vault Admin user permissions (All Permissions)
$ALL_PERMISSIONS = @{ "UseAccounts"=$true;"RetrieveAccounts"=$true;"ListAccounts"=$true;"AddAccounts"=$true;"UpdateAccountContent"=$true;"UpdateAccountProperties"=$true;"InitiateCPMAccountManagementOperations"=$true;"SpecifyNextAccountContent"=$true;"RenameAccounts"=$true;"DeleteAccounts"=$true;"UnlockAccounts"=$true;"ManageSafe"=$true;"ManageSafeMembers"=$true;"BackupSafe"=$true;"ViewAuditLog"=$true;"ViewSafeMembers"=$true;"RequestsAuthorizationLevel"=0;"AccessWithoutConfirmation"=$true;"CreateFolders"=$true;"DeleteFolders"=$true;"MoveAccountsAndFolders"=$true }


#region Helper Functions
Function Invoke-Rest
{
	param ($Command, $URI, $Header, $Body, $ErrorAction="Continue")
	
	$restResponse = ""
	try{
		Write-Verbose "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body"
		$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body
	} catch {
		If($null -ne $_.Exception.Response.StatusDescription)
		{
			Write-Error $_.Exception.Response.StatusDescription -ErrorAction $ErrorAction
		}
		else
		{
			Write-Error "StatusCode: $_.Exception.Response.StatusCode.value__"
		}
		$restResponse = $null
	}
	Write-Verbose $restResponse
	return $restResponse
}

Function Get-LogonHeader
{
	param($Credentials)
	# Create the POST Body for the Logon
    # ----------------------------------
    $logonBody = @{ username=$Credentials.username.Replace('\','');password=$Credentials.GetNetworkCredential().password } | ConvertTo-Json
	write-Verbose $logonBody
	try{
	    # Logon
	    $logonResult = Invoke-Rest -Command Post -Uri $URL_CyberArkLogon -Body $logonBody
		# Clear logon body
		$logonBody = ""
	    # Save the Logon Result - The Logon Token
	    $logonToken = $logonResult.CyberArkLogonResult
		#Write-Debug "Got logon token: $logonToken"
	}
	catch
	{
		Write-Host -ForegroundColor Red $_.Exception.Response.StatusDescription
		$logonToken = ""
	}
    If ($logonToken -eq "")
    {
        Write-Host -ForegroundColor Red "Logon Token is Empty - Cannot login"
        exit
    }
	
    # Create a Logon Token Header (This will be used through out all the script)
    # ---------------------------
    $logonHeader =  New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $logonHeader.Add("Authorization", $logonToken)
	
	return $logonHeader
}

Function Generate-Password
{
	param ( [int]$length = 10 )
	$ascii=$NULL;
	For ($a=33; $a -le 126;$a++) {$ascii+=,[char][byte]$a }
	For ($loop=1; $loop -le $length; $loop++) 
	{
		$TempPassword+=($ascii | GET-RANDOM)
	}

	return $TempPassword
}

Function Add-Owner
{
	param ($safe_Name, $user, $permissions)
	$urlOwnerAdd = $URL_SafeMembers -f $safe_Name
	$userPermissions = New-Object "System.Collections.Generic.Dictionary[[String],[Object]]"
	($permissions.GetEnumerator() | ForEach-Object { $userPermissions.Add($_.Key,$_.Value) })
	# Create the Safe Owner body with member name and required permissions
	$bodyMember = @{ MemberName=$user;Permissions=$userPermissions }
	$restBody = @{ member=$bodyMember } | ConvertTo-Json -Depth 3
	# Add the Safe Owner
	try {
        # Add the Safe Owner
		$restResponse = Invoke-Rest -Uri $urlOwnerAdd -Header $g_LogonHeader -Command "Post" -Body $restBody
    } catch {
        Write-Error $_.Exception.Response.StatusDescription
    }
}
#endregion

#--------- SCRIPT BEGIN ------------
#region [Validation]
# Check Powershell version
If($($PSVersionTable.PSVersion.Major) -le 2)
{
   Write-Error "This script requires Powershell version 3 or above"
   exit
}
#endregion

#region [Logon]
	# Get Credentials to Login
	# ------------------------
	$caption = "Create a Managed local user"
	$msg = "Enter your User name and Password"; 
	$creds = $Host.UI.PromptForCredential($caption,$msg,"","")
	if ($null -ne $creds)
	{
		$g_LogonHeader = $(Get-LogonHeader -Credentials $creds)
	}
	else { exit }
#endregion

#region [Create the target User]
 	$restBody = @{ UserName=$TargetUserName;InitialPassword=$DEFAULT_PASSWORD;Email=$null;FirstName=$null;LastName=$null;ChangePasswordOnTheNextLogon=$False;ExpiryDate=$null;UserTypeName=$USER_TYPE;Disabled=$False; } | ConvertTo-Json -Depth 3
	$restResult = $(Invoke-Rest -Uri $URL_Users -Header $g_LogonHeader -Command "Post" -Body $restBody)
#endregion

#region [Add the user to the Safe]
	ForEach ($safeName in $TargetSafes)
	{
		# Add the user to it's safe
		$restResult = $(Add-Owner -Safe_Name $safeName -User $TargetUserName -Permissions $USER_PERMISSIONS)
		# Add Vault Admins to the Safe
		$restResult = $(Add-Owner -Safe_Name $safeName -User "Vault Admins" -Permissions $ALL_PERMISSIONS)
	}
#endregion

#region [Logoff]
	# Logoff the session
    # ------------------
    Write-Host "Logoff Session..."
    Invoke-Rest -Uri $URL_CyberArkLogoff -Header $g_LogonHeader -Command "Post"
#endregion