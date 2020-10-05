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
	
	[Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark","ldap","radius")]
	[String]$AuthType="cyberark",	
	
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
$URL_Logon = $URL_Authentication+"/$AuthType/Logon"
$URL_Logoff = $URL_Authentication+"/Logoff"

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
		throw "Error while reading ZIP file: $($_.Exception.Message)"
	}
	
	return $zipContent
}

Function AddPlatform-PSMConnectionComponent
{
	Param($platformZipPath, $psmServerID = "PSMServer", $connectionComponentID)
	
	try{
		If(Test-Path $platformZipPath)
		{
			$Package = Get-Item -Path $platformZipPath
			# load ZIP methods
			Add-Type -AssemblyName System.IO.Compression.FileSystem
			Write-Debug "Extracting Platform ZIP ('$platformZipPath')"
			# Extract ZIP to temp folder
			$tempFolder = Join-Path -Path $Package.Directory -ChildPath $Package.BaseName
			if(Test-Path $tempFolder)
			{
				Remove-Item -Recurse $tempFolder
			}
			[System.IO.Compression.ZipFile]::ExtractToDirectory($Package.FullName,$tempFolder)
		}
		else
		{
			throw "Could not find Platform ZIP in '$platformZipPath'"
		}
		
		Write-Debug "Adding PSM Connection component to platform $platformID"
		# Find all XML files in the platform ZIP
		$fileEntries = Get-ChildItem -Path $tempFolder -Filter '*.xml'
		write-verbose $fileEntries
		# There should be only one file
		If($fileEntries.Count -ne 1)
		{ throw "Invalid Platform ZIP file" }
		[xml]$xmlContent = Get-Content $fileEntries[0].FullName
		write-verbose $xmlContent
		# Add PSM details to XML
		ForEach($item in $xmlContent.Device.Policies.Policy)
		{
			If($item.key -eq "PrivilegedSessionManagement")
			{
				$psmNodeExists = $true
			}
			If($item.key -eq "ConnectionComponent")
			{
				$ccNodeExists = $true
			}
		}
		if($psmNodeExists -eq $false)
		{
			Write-Verbose "Adding PSM to Platform"
			$psmNode = $xmlContent.CreateNode("element","PrivilegedSessionManagement","")
			$psmNode.SetAttribute("Enable","Yes")
			$psmNode.SetAttribute("ID",$psmServerID)
			$xmlContent.Device.Policies.Policy.AppendChild($psmNode) | Out-Null
		}
		else
		{
			Write-Verbose "PSM Node already exists"
		}
		if($ccNodeExists -eq $false)
		{
			Write-Verbose "Adding Connection Component to Platform"
			$concompNode = $xmlContent.CreateNode("element","ConnectionComponent","")
			$concompNode.SetAttribute("Id",$connectionComponentID)
			$conNode = $xmlContent.CreateNode("element","ConnectionComponents","")
			$conNode.AppendChild($concompNode)
			$xmlContent.Device.Policies.Policy.AppendChild($conNode) | Out-Null
		}
		else
		{
			Write-Verbose "Connection Component Node already exists"
		}
		write-verbose $xmlContent
		$xmlContent.Save($fileEntries[0].FullName)
		
		Write-Debug "Delete original ZIP and Package the new Platform ZIP"
		$zipFullPath = $Package.FullName
		Remove-Item $zipFullPath
		[System.IO.Compression.ZipFile]::CreateFromDirectory($tempFolder,$zipFullPath)
		Write-Debug "Removing extracted ZIP folder"
		Remove-Item -Recurse $tempFolder
	} catch {
		throw "Error while linking connection component '$connectionComponentID' to platform: $($_.Exception.Message)"
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

Write-Host "Import Platform and Connection Component: Script Started" -ForegroundColor Cyan

#region [Logon]
# Get Credentials to Login
# ------------------------
$caption = "Import Platform and Connection Component"
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

# Importing the Connection Component
$connectionComponentID = $null
If (Test-Path $ConnectionComponentZipPath)
{
	$importBody = @{ ImportFile=$(Get-ZipContent $ConnectionComponentZipPath); } | ConvertTo-Json -Depth 3 -Compress
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
		return
	}
}

If (Test-Path $PlatformZipPath)
{
	If([string]::IsNullOrEmpty($connectionComponentID))
	{
		Write-Error "No Connection Component ID to link"
		Return
	}
	# Link Connection Component to Platform
	AddPlatform-PSMConnectionComponent -platformZipPath $(Resolve-Path $PlatformZipPath) -psmServerID $PSMServerID -connectionComponentID $connectionComponentID
	# Import Platform
	$importBody = @{ ImportFile=$(Get-ZipContent $PlatformZipPath); } | ConvertTo-Json -Depth 3 -Compress
	try{
		$ImportPlatformResponse = Invoke-RestMethod -Method POST -Uri $URL_ImportPlatforms -Headers $logonHeader -ContentType "application/json" -TimeoutSec 3600000 -Body $importBody
		Write-Host "Platform ID imported: $($ImportPlatformResponse.PlatformID)"
	} catch {
		Write-Error "Error importing the platform, Error: $($_.Exception.Response.StatusDescription)"
	}
}

# Logoff the session
# ------------------
Write-Host "Logoff Session..."
Invoke-RestMethod -Method Post -Uri $URL_Logoff -Headers $logonHeader -ContentType "application/json" | Out-Null

Write-Host "Import Platform and Connection Component: Script Ended" -ForegroundColor Cyan
