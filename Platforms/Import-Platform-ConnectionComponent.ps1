###########################################################################
#
# NAME: Import Platform and Connection Component
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will Import a platform and connection component using REST API
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
	
	[Parameter(Mandatory=$true,HelpMessage="Enter the platform Zip path to import")]
	[Alias("Platform")]
	[string]$PlatformZipPath,
	
	[Parameter(Mandatory=$true,HelpMessage="Enter the Connection Component Zip path to import")]
	[Alias("ConnectionComponent")]
	[string]$ConnectionComponentZipPath,
	
	[Parameter(Mandatory=$false,HelpMessage="Enter the PSM Server ID (default 'PSMServer'")]
	[Alias("PSM")]
	[string]$PSMServerID = "PSMServer"
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
$URL_ImportPlatforms = $URL_PVWAAPI+"/Platforms/Import"
$URL_ImportConnectionComponent = $URL_PVWAAPI+"/ConnectionComponents/Import"

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
		Write-Error "Error while reading ZIP file: $($_.Exception.Message)"
	}
	
	return $zipContent
}

Function AddPlatform-PSMConnectionComponent
{
	Param($platformZipPath, $psmServerID = "PSMServer", $connectionComponentID)
	
	try{
		# load ZIP methods
		Add-Type -AssemblyName System.IO.Compression.FileSystem
		Write-Debug "Extracting Platform ZIP ('$platformZipPath')"
		# open ZIP archive for reading
		$zip = [System.IO.Compression.ZipFile]::Open($platformZipPath, [System.IO.Compression.ZipArchiveMode]::Update)

		# Find all XML files in the platform ZIP
		$fileEntries = $zip.Entries | Where-Object { $_.FullName -like '*.xml' }
		# There should be only one file
		If($fileEntries -ne 1)
		{ throw "Invalid Platform ZIP file" }
		Write-Debug "Adding PSM Connection component to platform $platformID"
		# Open the XML file for read/write
		$fileMode = [System.IO.FileMode]::Open
		$fileAccess = [System.IO.FileAccess]::ReadWrite
		$fileShare = [System.IO.FileShare]::None
		$fileStream = New-Object -TypeName System.IO.FileStream $($zip.GetEntry($fileEntries[0])), $fileMode, $fileAccess, $fileShare

		$reader = New-Object -TypeName System.IO.StreamReader -ArgumentList $fileStream
		[xml]$xmlContent = $reader.ReadToEnd()
		# Add PSM details to XML
		$psmNode = $xmlContent.CreateNode("element","PrivilegedSessionManagement","")
		$psmNode.SetAttribute("Enable","Yes")
		$psmNode.SetAttribute("PSMServerID",$psmServerID)
		$xmlContent.Device.Policies.Policy.AppendChild($psmNode)
		
		$concompNode = $xmlContent.CreateNode("element","ConnectionComponent","")
		$concompNode.SetAttribute("Id",$connectionComponentID)
		$conNode = $xmlContent.CreateNode("element","ConnectionComponents","")
		$conNode.AppendChild($concompNode)
		$xmlContent.Device.Policies.Policy.AppendChild($conNode)
		
		$writer = New-Object System.IO.StreamWriter $fileStream, [System.Text.Encoding]::Unicode
		$writer.Write($xmlContent)
		
		# Cleanup
		$reader.Close()
		$writer.Dispose()
		$fileStream.Dispose()
		# close ZIP file
		$zip.Dispose()
	} catch {
		Write-Error "Error while linking connection component '$connectionComponentID' to platform: $($_.Exception.Message)"
	}
}
#endregion

If (-not (Test-CommandExists Invoke-RestMethod))
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

# Importing the Connection Component
$connectionComponentID = $null
If (Test-Path $ConnectionComponentZipPath)
{
	$importBody = @{ ImportFile=$(Get-ZipContent $ConnectionComponentZipPath); } | ConvertTo-Json -Depth 3
	try{
		$ImportCCResponse = Invoke-RestMethod -Method POST -Uri $URL_ImportConnectionComponent -Headers $logonHeader -ContentType "application/json" -TimeoutSec 3600000 -Body $importBody
		$connectionComponentID = ($ImportCCResponse.ConnectionComponentID)
		Write-Debug "Connection Component ID imported: $connectionComponentID"
	} catch {
		Write-Error $_.Exception.Response
		Write-Error $_.Exception.Response.StatusDescription
	}
}

If (Test-Path $PlatformZipPath)
{
	If([string]::IsNullOrEmpty($connectionComponentID))
	{
		throw "No Connection Component ID to link"
	}
	# Link Connection Component to Platform
	AddPlatform-PSMConnectionComponent -platformZipPath $PlatformZipPath -psmServerID $PSMServerID -connectionComponentID $connectionComponentID
	# Import Platform
	$importBody = @{ ImportFile=$(Get-ZipContent $PlatformZipPath); } | ConvertTo-Json -Depth 3
	try{
		$ImportPlatformResponse = Invoke-RestMethod -Method POST -Uri $URL_ImportPlatforms -Headers $logonHeader -ContentType "application/json" -TimeoutSec 3600000 -Body $importBody
		Write-Debug "Platform ID imported: $($ImportPlatformResponse.PlatformID)"
	} catch {
		Write-Error $_.Exception.Response
		Write-Error $_.Exception.Response.StatusDescription
	}
}

# Logoff the session
# ------------------
Write-Host "Logoff Session..."
Invoke-RestMethod -Method Post -Uri $URL_CyberArkLogoff -Headers $logonHeader -ContentType "application/json" | Out-Null

