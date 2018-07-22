###########################################################################
#
# NAME: Export / Import Platform
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will Export or Import a platform using REST API
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v10.4 and above
#
# VERSION HISTORY:
# 1.0 05/07/2018 - Initial release
#
###########################################################################

param
(
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,
	
	# Use this switch to Import a Platform
	[Parameter(ParameterSetName='Import',Mandatory=$true)][switch]$Import,
	# Use this switch to Export a Platform
	[Parameter(ParameterSetName='Export',Mandatory=$true)][switch]$Export,
	
	[Parameter(ParameterSetName='Export',Mandatory=$true,HelpMessage="Enter the platform ID to export")]
	[Alias("id")]
	[string]$PlatformID,
	
	[Parameter(ParameterSetName='Import',Mandatory=$true,HelpMessage="Enter the platform Zip path for import")]
	[Parameter(ParameterSetName='Export',Mandatory=$true,HelpMessage="Enter the platform Zip path to export")]
	[Alias("path")]
	[string]$PlatformZipPath
)

# Global URLS
# -----------
$URL_PVWAAPI = $PVWAURL+"/api"
$URL_Authentication = $URL_PVWAAPI+"/auth"
$URL_CyberArkLogon = $URL_Authentication+"/cyberark/Logon"
$URL_CyberArkLogoff = $URL_Authentication+"/Logoff"

# URL Methods
# -----------
$URL_PlatformDetails = $URL_PVWAAPI+"/Platforms/{0}"
$URL_ExportPlatforms = $URL_PVWAAPI+"/Platforms/{0}/Export"
$URL_ImportPlatforms = $URL_PVWAAPI+"/Platforms/Import"

# Initialize Script Variables
# ---------------------------
$rstusername = $rstpassword = ""
$logonToken  = ""

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
    # Get Credentials to Login
    # ------------------------
    $caption = "Get accounts"
    $msg = "Enter your User name and Password"; 
    $creds = $Host.UI.PromptForCredential($caption,$msg,"","")
	if ($creds -ne $null)
	{
		$rstusername = $creds.username.Replace('\','');    
		$rstpassword = $creds.GetNetworkCredential().password
	}
	else { exit }

    # Create the POST Body for the Logon
    # ----------------------------------
    $logonBody = @{ username=$rstusername;password=$rstpassword }
    $logonBody = $logonBody | ConvertTo-Json
	try{
	    # Logon
	    $logonToken = Invoke-RestMethod -Method Post -Uri $URL_CyberArkLogon -Body $logonBody -ContentType "application/json"
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
#endregion

	switch($PsCmdlet.ParameterSetName)
	{
		"Import"
		{
			If (Test-Path $PlatformZipPath)
			{
				$zipContent = [System.IO.File]::ReadAllBytes($(Resolve-Path $PlatformZipPath))
				$importBody = @{ ImportFile=$zipContent; } | ConvertTo-Json -Depth 3
				try{
					$ImportPlatformResponse = Invoke-RestMethod -Method POST -Uri $URL_ImportPlatforms -Headers $logonHeader -ContentType "application/json" -TimeoutSec 3600000 -Body $importBody
					Write-Debug "Platform ID imported: $($ImportPlatformResponse.PlatformID)"
					Write-Host "Retrieving Platform details"
					# Get the Platform Name
					$platformDetails = Invoke-RestMethod -Method Get -Uri $($URL_PlatformDetails -f $ImportPlatformResponse.PlatformID) -Headers $logonHeader -ContentType "application/json" -TimeoutSec 3600000
					If($platformDetails)
					{
						Write-Debug $platformDetails
						Write-Host "$($platformDetails.Details.PolicyName) (ID: $($platformDetails.PlatformID)) was successfully imported and $(if($platformDetails.Active) { "Activated" } else { "Inactive" })"
						Write-Host "Platform details:" 
						$platformDetails.Details | select PolicyID, AllowedSafes, AllowManualChange, PerformPeriodicChange, @{Name = 'AllowManualVerification'; Expression = { $_.VFAllowManualVerification}}, @{Name = 'PerformPeriodicVerification'; Expression = { $_.VFPerformPeriodicVerification}}, @{Name = 'AllowManualReconciliation'; Expression = { $_.RCAllowManualReconciliation}}, @{Name = 'PerformAutoReconcileWhenUnsynced'; Expression = { $_.RCAutomaticReconcileWhenUnsynched}}, PasswordLength, MinUpperCase, MinLowerCase, MinDigit, MinSpecial 
					}		
				} catch {
					#Write-Error $_.Exception
					Write-Error $_.Exception.Response
					Write-Error $_.Exception.Response.StatusDescription
				}
			}
		}
		"Export"
		{
			try{
				$exportURL = $URL_ExportPlatforms -f $PlatformID
				Invoke-RestMethod -Method POST -Uri $exportURL -Headers $logonHeader -ContentType "application/zip" -TimeoutSec 3600000 -OutFile $PlatformZipPath 
			} catch {
					Write-Error $_.Exception.Response.StatusDescription
				}
		}
	}
	# Logoff the session
    # ------------------
    Write-Host "Logoff Session..."
    Invoke-RestMethod -Method Post -Uri $URL_CyberArkLogoff -Headers $logonHeader -ContentType "application/json" | Out-Null
}
else
{
    Write-Error "This script requires PowerShell version 3 or above"
}
