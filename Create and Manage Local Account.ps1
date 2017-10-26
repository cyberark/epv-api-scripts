###########################################################################
#
# NAME: Create and Manage Local Account
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will create a local account on a server and will create the corresponding Account in CyberArk to be managed
# The script will get a target role for that account and will create it with the required permissions
# The Account will be created in a private safe of the user
# Prerequisites: Network access to the Target Machine
#				 Network Access to the PVWA server
#				 The user that will run the script needs to have Administrative permissions on the Target machine
#				 The user running the script needs to have "Create Safe" permissions on the CyberArk Vault
#
# VERSION HISTORY:
# 1.0 18/10/2017 - Initial release
#
###########################################################################
param
(
	[Parameter(Mandatory=$true,HelpMessage="Enter the PVWA URL")]
	[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,
		
	[Parameter(Mandatory=$true,HelpMessage="Enter the Target Address")]
	[Alias("address")]
	[String]$TargetAddress,
	[Parameter(Mandatory=$true,HelpMessage="Enter the Target User Name")]
	[Alias("user")]
	[String]$TargetUserName,
	[Parameter(Mandatory=$true,HelpMessage="Enter the Target User Role")]
	[ValidateSet("Administrator","User")]
	[Alias("role")]
	[String]$TargetUserRole
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
$URL_Account = $URL_PVWABaseAPI+"/Account"
$URL_Accounts = $URL_PVWABaseAPI+"/Accounts"
$URL_AccountDetails = $URL_Accounts+"/{0}"


# Initialize Script Variables
# ---------------------------
# Save Global Logon Token
$g_LogonHeader = ""

# Script Defaults
# ---------------
$DEFAUL_PLATFROM_ID = "WinServerLocal"
$SAFE_NAME_TEMPLATE = "PRIV-{0}-LCL"
$SAFE_DESCRIPTION_TEMPLATE = "Private Safe of {0} for Local Accounts created by Script"
$CPM_NAME = "PasswordManager"
$NumberOfDaysRetention = 1 # Immediate delete
$NumberOfVersionsRetention = 0
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
		If($_.Exception.Response.StatusDescription -ne $null)
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
	($permissions.GetEnumerator() | % { $userPermissions.Add($_.Key,$_.Value) })
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
$safeName = $SAFE_NAME_TEMPLATE -f $TargetUserName
$safeDescription = $SAFE_DESCRIPTION_TEMPLATE -f $TargetUserName

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
	if ($creds -ne $null)
	{
		$g_LogonHeader = $(Get-LogonHeader -Credentials $creds)
	}
	else { exit }
#endregion

#region [Create the target Account on the Server]
	# Using the entered Credentials to connect to the Target
	try{
		$target = New-Object System.DirectoryServices.DirectoryEntry("WinNT://$TargetAddress",$creds.username.Replace('\',''),$creds.GetNetworkCredential().password)
		If ($target.Name -ne $TargetAddress)
		{
			# Try connecting with current user
			$target = New-Object System.DirectoryServices.DirectoryEntry("WinNT://$TargetAddress")
		}
	}
	catch {}
	# Create the target user with a generated Password
	$tUser = $target.Create("User", $TargetUserName)
	$Password = (Generate-Password -length 24)
	$tUser.SetPassword($Password)
	$tUser.SetInfo()
	# According to the user role, add the user to the group and description
	$tUser.Put("Description", "Local $TargetUserRole Account - Created by Script")
	$tUser.SetInfo()

	# Add the User to the relevant group
	If ($TargetUserRole -eq "Administrator")
	{
		$Group = [ADSI]("WinNT://$Env:COMPUTERNAME/Administrators,Group")
	}
	If ($TargetUserRole -eq "User")
	{
		$Group = [ADSI]("WinNT://$Env:COMPUTERNAME/Remote Desktop Users,Group")
	}
	$Group.add("WinNT://$Env:COMPUTERNAME/$TargetUserName")
#endregion

#region [Create the Safe]
	# Create the safe body with the required properties
	$bodySafe = @{ SafeName=$safeName;Description=$safeDescription;OLACEnabled=$false;ManagingCPM=$CPM_NAME;NumberOfDaysRetention=$NumberOfDaysRetention }
	$restBody = @{ safe=$bodySafe } | ConvertTo-Json
	$restResult = $(Invoke-Rest -Uri $URL_Safes -Header $g_LogonHeader -Command "Post" -Body $restBody)
#endregion

#region [Create the Account]
	$bodyAccount = @{ safe=$safeName;platformID=$DEFAUL_PLATFROM_ID;address=$TargetAddress;password=$Password;username=$TargetUserName }
	$restBody = @{ account=$bodyAccount } | ConvertTo-Json
	$restResult = $(Invoke-Rest -Uri $URL_Account -Header $g_LogonHeader -Body $restBody -Command "Post")
#endregion

#region [Add the user to the Safe]
	# Add the user to it's safe
	$restResult = $(Add-Owner -Safe_Name $safeName -User $TargetUserName -Permissions $USER_PERMISSIONS)
	# Add Vault Admins to the Safe
	$restResult = $(Add-Owner -Safe_Name $safeName -User "Vault Admins" -Permissions $ALL_PERMISSIONS)
#endregion

#region [Logoff]
	# Logoff the session
    # ------------------
    Write-Host "Logoff Session..."
    Invoke-Rest -Uri $URL_CyberArkLogoff -Header $g_LogonHeader -Command "Post"
#endregion