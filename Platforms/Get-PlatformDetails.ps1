###########################################################################
#
# NAME: Get Platform details
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will get a platform details using REST API
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v10.2 and above
#
# VERSION HISTORY:
# 1.0 09/07/2018 - Initial release
#
###########################################################################

param
(
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,

	[Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark","ldap","radius")]
	[String]$AuthType="cyberark",	
	
	[Parameter(Mandatory=$true,HelpMessage="Enter the platform ID to export")]
	[Alias("id")]
	[string]$PlatformID,

	# Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off
	[Parameter(Mandatory = $false)]
	$logonToken
)

# Global URLS
# -----------
$URL_PVWAAPI = $PVWAURL+"/api"
$URL_Authentication = $URL_PVWAAPI+"/auth"
$URL_Logon = $URL_Authentication+"/$AuthType/Logon"
$URL_Logoff = $URL_Authentication+"/Logoff"

# URL Methods
# -----------
$URL_PlatformDetails = $URL_PVWAAPI+"/Platforms/{0}"

# Initialize Script Variables
# ---------------------------
$rstusername = $rstpassword = ""

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

Function EncodeForURL($sText)
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
        exit
    }

#region [Logon]
    $caption = "Get accounts"
	if (![string]::IsNullOrEmpty($logonToken)) {
        if ($logonToken.GetType().name -eq 'String') {
            $logonHeader = @{Authorization = $logonToken }
        }
        else {
            $logonHeader = $logonToken
        }
    }
	else
	{
		# Get Credentials to Login
    	# ------------------------
		$msg = "Enter your User name and Password";
		$creds = $Host.UI.PromptForCredential($caption, $msg, "", "")
		if ($null -ne $creds)
		{
			$rstusername = $creds.username.Replace('\', '');
			$rstpassword = $creds.GetNetworkCredential().password
		}
		else { exit }

		# Create the POST Body for the Logon
		# ----------------------------------
		$logonBody = @{ username = $rstusername; password = $rstpassword }
		$logonBody = $logonBody | ConvertTo-Json
		try{
			# Logon
			$logonToken = Invoke-RestMethod -Method Post -Uri $URL_Logon -Body $logonBody -ContentType "application/json"
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
		$logonHeader = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
		$logonHeader.Add("Authorization", $logonToken)
	}
#endregion

#region Get Platform details
	try{
		Write-Host "Retrieving Platform details"
		# Get the Platform Name
		Write-verbose "RestMethod -Method Get -Uri $($URL_PlatformDetails -f $PlatformID)"
		$platformDetails = Invoke-RestMethod -Method Get -Uri $($URL_PlatformDetails -f $PlatformID) -Headers $logonHeader -ContentType "application/json" -TimeoutSec 2700
		If($platformDetails)
		{
			Write-verbose $platformDetails
			Write-Host "$($platformDetails.Details.PolicyName) (ID: $($platformDetails.PlatformID)) is currently $(if($platformDetails.Active) { "Activated" } else { "Inactive" })"
			Write-Host "Platform details:"
			$platformDetails.Details | Select-Object PolicyID, AllowedSafes, AllowManualChange, PerformPeriodicChange, @{Name = 'AllowManualVerification'; Expression = { $_.VFAllowManualVerification}}, @{Name = 'PerformPeriodicVerification'; Expression = { $_.VFPerformPeriodicVerification}}, @{Name = 'AllowManualReconciliation'; Expression = { $_.RCAllowManualReconciliation}}, @{Name = 'PerformAutoReconcileWhenUnsynced'; Expression = { $_.RCAutomaticReconcileWhenUnsynched}}, PasswordLength, MinUpperCase, MinLowerCase, MinDigit, MinSpecial
		}
	} catch {
		Write-Error $_.Exception.Response
		Write-Error $_.Exception.Response.StatusDescription
	}
#endregion
	# Logoff the session
	If (![string]::IsNullOrEmpty($logonToken)) {
		Write-Host 'LogonToken passed, session NOT logged off'
	}
	else {
		# Logoff the session
		# ------------------
		Write-Host "Logoff Session..."
		Invoke-RestMethod -Method Post -Uri $URL_Logoff -Headers $logonHeader -ContentType "application/json" | Out-Null
	}
}
else
{
    Write-Error "This script requires PowerShell version 3 or above"
}
