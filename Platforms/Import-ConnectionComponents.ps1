###########################################################################
#
# NAME: Import Connection Components
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will Import a single or multiple connection components using REST API
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v10.4 and above
#
#
###########################################################################

param
(
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,
	
	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory=$false)]
	[Switch]$DisableSSLVerify,
	
	[Parameter(Mandatory=$false,HelpMessage="Enter the Connection Component Zip path to import")]
	[Alias("ConnectionComponent")]
	[string]$ConnectionComponentZipPath,
	
	[Parameter(Mandatory=$false,HelpMessage="Enter a folder path for Connection Components Zip files to import")]
	[Alias("Folder")]
	[string]$ConnectionComponentFolderPath
)

# Global URLS
# -----------
$URL_PVWAAPI = $PVWAURL+"/api"
$URL_Authentication = $URL_PVWAAPI+"/auth"
$URL_CyberArkLogon = $URL_Authentication+"/cyberark/Logon"
$URL_CyberArkLogoff = $URL_Authentication+"/Logoff"

# URL Methods
# -----------
$URL_ImportConnectionComponent = $URL_PVWAAPI+"/ConnectionComponents/Import"

# Initialize Script Variables
# ---------------------------
$rstusername = $rstpassword = ""
$logonToken  = ""

Function Disable-SSLVerification
{
<# 
.SYNOPSIS 
	Bypass SSL certificate validations
.DESCRIPTION
	Disables the SSL Verification (bypass self signed SSL certificates)
#>
	# Using Proxy Default credentials if the Server needs Proxy credentials
	[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
	# Using TLS 1.2 as security protocol verification
	[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
	# Disable SSL Verification
	if (-not("DisableCertValidationCallback" -as [type])) {
    add-type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class DisableCertValidationCallback {
    public static bool ReturnTrue(object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors) { return true; }

    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(DisableCertValidationCallback.ReturnTrue);
    }
}
"@ }

	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = [DisableCertValidationCallback]::GetDelegate()
}

Function Get-ZipContent
{
	Param($zipPath)
	
	$zipContent = $null
	try{
		If(Test-Path $zipPath)
		{
			$zipContent = [System.IO.File]::ReadAllBytes($(Resolve-Path $zipPath))
		}
	} catch {
		throw "Error while reading ZIP file: $($_.Exception.Message)"
	}
	
	return $zipContent
}

If ($($PSVersionTable.PSVersion.Major) -lt 3)
{
	Write-Error "This script requires PowerShell version 3 or above"
	return
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

Write-Host "Import Connection Component: Script Started" -ForegroundColor Cyan
# Disable SSL Verification to contact PVWA
If($DisableSSLVerify)
{
	Disable-SSLVerification
}

#region [Logon]
# Get Credentials to Login
# ------------------------
$caption = "Import Connection Component"
$msg = "Enter your User name and Password"; 
$creds = $Host.UI.PromptForCredential($caption,$msg,"","")
if ($creds -ne $null)
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
	return
}
# Create a Logon Token Header (This will be used through out all the script)
# ---------------------------
$logonHeader =  New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$logonHeader.Add("Authorization", $logonToken)
#endregion

$arrConCompToImport = @()

If (([string]::IsNullOrEmpty($ConnectionComponentZipPath)) -and (![string]::IsNullOrEmpty($ConnectionComponentFolderPath)))
{
	# Get all Connection Components from a folder
	$arrConCompToImport += (Get-ChildItem -Path $ConnectionComponentFolderPath -Filter "*.zip")
}
ElseIf ((![string]::IsNullOrEmpty($ConnectionComponentZipPath)) -and ([string]::IsNullOrEmpty($ConnectionComponentFolderPath)))
{
	# Get the entered Connection Component ZIP
	$arrConCompToImport = $ConnectionComponentZipPath
}
Else
{
	Write-Host -ForegroundColor Red "No Connection Component path was entered."
	$arrConCompToImport = Read-Host "Please enter a Connection Component ZIP path"
}

ForEach($connCompItem in $arrConCompToImport)
{
	If (Test-Path $connCompItem)
	{
		$importBody = @{ ImportFile=$(Get-ZipContent $connCompItem); } | ConvertTo-Json -Depth 3
		try{
			$ImportCCResponse = Invoke-RestMethod -Method POST -Uri $URL_ImportConnectionComponent -Headers $logonHeader -ContentType "application/json" -TimeoutSec 3600000 -Body $importBody
			$connectionComponentID = ($ImportCCResponse.ConnectionComponentID)
			Write-Host "Connection Component ID imported: $connectionComponentID"
		} catch {
			if($_.Exception.Response.StatusDescription -like "*Conflict*")
			{
				Write-Host "The requested connection component already exists" -ForegroundColor Yellow
			}
			Else{
				Write-Error "Error importing the connection ID, Error: $($_.Exception.Response.StatusDescription)"
			}
		}
	}
}

# Logoff the session
# ------------------
if($null -ne $logonHeader)
{
	Write-Host "Logoff Session..."
	Invoke-RestMethod -Method Post -Uri $URL_CyberArkLogoff -Headers $logonHeader -ContentType "application/json" | Out-Null
}

Write-Host "Import Connection Component: Script Ended" -ForegroundColor Cyan
