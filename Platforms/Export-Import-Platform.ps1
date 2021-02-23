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
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,

	[Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark","ldap","radius")]
	[String]$AuthType="cyberark",	
	
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
	[string]$PlatformZipPath,

	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory=$false)]
	[Switch]$DisableSSLVerify
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

#endregion

If (Test-CommandExists Invoke-RestMethod)
{
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
		Write-Error "Could not change SSL validation"
		Write-Error (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
		return
	}
}
Else
{
	try{
		Write-Debug "Setting script to use TLS 1.2"
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
	} catch {
		Write-Error "Could not change SSL settings to use TLS 1.2"
		Write-Error (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
	}
}

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
        return
    }

Write-Host "Export / Import Platform: Script Started" -ForegroundColor Cyan

#region [Logon]
    # Get Credentials to Login
    # ------------------------
    $caption = "Export / Import Platform"
    $msg = "Enter your User name and Password"; 
    $creds = $Host.UI.PromptForCredential($caption,$msg,"","")
	if ($null -ne $creds)
	{
		$rstusername = $creds.username.Replace('\','');    
		$rstpassword = $creds.GetNetworkCredential().password
	}
	else { return }

    # Create the POST Body for the Logon
    # ----------------------------------
    $logonBody = @{ username=$rstusername;password=$rstpassword }
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
        return
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
				$importBody = @{ ImportFile=$zipContent; } | ConvertTo-Json -Depth 3 -Compress
				try{
					$ImportPlatformResponse = Invoke-RestMethod -Method POST -Uri $URL_ImportPlatforms -Headers $logonHeader -ContentType "application/json" -TimeoutSec 2700 -Body $importBody
					Write-Debug "Platform ID imported: $($ImportPlatformResponse.PlatformID)"
					Write-Host "Retrieving Platform details"
					# Get the Platform Name
					$platformDetails = Invoke-RestMethod -Method Get -Uri $($URL_PlatformDetails -f $ImportPlatformResponse.PlatformID) -Headers $logonHeader -ContentType "application/json" -TimeoutSec 2700
					If($platformDetails)
					{
						Write-Debug $platformDetails
						Write-Host "$($platformDetails.Details.PolicyName) (ID: $($platformDetails.PlatformID)) was successfully imported and $(if($platformDetails.Active) { "Activated" } else { "Inactive" })"
						Write-Host "Platform details:" 
						$platformDetails.Details | Select-Object PolicyID, AllowedSafes, AllowManualChange, PerformPeriodicChange, @{Name = 'AllowManualVerification'; Expression = { $_.VFAllowManualVerification}}, @{Name = 'PerformPeriodicVerification'; Expression = { $_.VFPerformPeriodicVerification}}, @{Name = 'AllowManualReconciliation'; Expression = { $_.RCAllowManualReconciliation}}, @{Name = 'PerformAutoReconcileWhenUnsynced'; Expression = { $_.RCAutomaticReconcileWhenUnsynched}}, PasswordLength, MinUpperCase, MinLowerCase, MinDigit, MinSpecial 
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
				Invoke-RestMethod -Method POST -Uri $exportURL -Headers $logonHeader -ContentType "application/zip" -TimeoutSec 2700 -OutFile $PlatformZipPath 
			} catch {
				Write-Error $_.Exception.Response
				Write-Error $_.Exception.Response.StatusDescription
			}
		}
	}
	# Logoff the session
    # ------------------
    Write-Host "Logoff Session..."
    Invoke-RestMethod -Method Post -Uri $URL_Logoff -Headers $logonHeader -ContentType "application/json" | Out-Null
}
else
{
    Write-Error "This script requires PowerShell version 3 or above"
}

Write-Host "Export / Import Platform: Script Started" -ForegroundColor Cyan
