###########################################################################
#
# NAME: Activate a suspended user
#
# AUTHORS:  Assaf Miron / Miltiadis Pistiolas
#
# COMMENT: 
# This script will activate a suspended user. It does not activate an inactive user.
# Prerequisites: Network access to the PVWA server
#                The user running this Web service must have Audit users permissions.
#                Users on the same level as your user or lower in the Vault hierarchy are retrieved.
#
# VERSION HISTORY:
# 1.0 02/02/2022 - Initial release
#
###########################################################################
param
(
	[Parameter(Mandatory=$true,HelpMessage="Enter the PVWA URL")]
	[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,

	[Parameter(Mandatory=$true,HelpMessage="Enter the EPV User Name")]
	[Alias("user")]
	[String]$EPVUserName
)
# Global URLS
# -----------
$URL_PVWAWebServices = $PVWAURL+"/WebServices"
$URL_PVWABaseAPI = $URL_PVWAWebServices+"/PIMServices.svc"
$URL_PVWAAPI = $PVWAURL+"/api"
$URL_CyberArkAuthentication = $URL_PVWAAPI+"/auth/Cyberark"
$URL_CyberArkLogon = $URL_CyberArkAuthentication+"/Logon"
$URL_CyberArkLogoff = $URL_PVWAAPI+"/auth/Logoff"

# URL Methods
# -----------
$URL_Users = $URL_PVWAAPI+"/Users"
$URL_ActivateUser = $URL_PVWAAPI+"/Users/{0}/Activate"


# Initialize Script Variables
# ---------------------------
# Save Global Logon Token
$g_LogonHeader = ""

#region Helper Functions
Function Invoke-Rest {
	param ($Command, $URI, $Header, $Body, $ErrorAction="Continue")
	
	$restResponse = ""
	try{
		Write-Verbose "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body"
		$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body
	} catch {
		If($null -ne $_.Exception.Response.StatusDescription) {
			Write-Error $_.Exception.Response.StatusDescription -ErrorAction $ErrorAction
		} else {
			Write-Error "StatusCode: $_.Exception.Response.StatusCode.value__"
		}
		$restResponse = $null
	}
	Write-Verbose $restResponse
	return $restResponse
}

Function Get-LogonHeader {
	param($Credentials)
	# Create the POST Body for the Logon
	# ----------------------------------
	$logonBody = @{ username=$Credentials.username.Replace('\','');password=$Credentials.GetNetworkCredential().password } | ConvertTo-Json
	Write-Verbose $logonBody
	try{
		# Logon
		$logonResult = Invoke-Rest -Command Post -Uri $URL_CyberArkLogon -Body $logonBody
		# Clear logon body
		$logonBody = ""
	} catch {
		Write-Host -ForegroundColor Red $_.Exception.Response.StatusDescription
		$logonToken = ""
	}
	If ($logonToken -eq "") {
		Write-Host -ForegroundColor Red "Logon Token is Empty - Cannot login"
		exit
	}
	
	# Create a Logon Token Header (This will be used through out all the script)
	# ---------------------------
	$logonHeader =  New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$logonHeader.Add("Authorization", $logonResult)
	
	return $logonHeader
}

#endregion

#--------- SCRIPT BEGIN ------------
#region [Validation]
# Check Powershell version
If($($PSVersionTable.PSVersion.Major) -le 2) {
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
if ($null -ne $creds) {
	$g_LogonHeader = $(Get-LogonHeader -Credentials $creds)
} else { exit }
#endregion

#region [Find user ID and unsuspend the user]
$restResult = $(Invoke-Rest -Uri $URL_Users -Header $g_LogonHeader -Command "GET")
$user = $restResult | Select-Object -Expand Users | Where-Object username -EQ "$EPVUserName"

if ($user.id -ne $null) {

	Write-Host "Activating" $user.userType $user.username -ForegroundColor Green
	$(Invoke-Rest -Uri ($URL_ActivateUser -f $user.id) -Header $g_LogonHeader -Command "POST")
  
} else {
  
	Write-Host "User $EPVUserName not found" -ForegroundColor Red
  
}
    
#region [Logoff]
# Logoff the session
# ------------------
Write-Host "Logoff Session..."
Invoke-Rest -Uri $URL_CyberArkLogoff -Header $g_LogonHeader -Command "Post"
#endregion