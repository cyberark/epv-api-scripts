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
	[Parameter(Mandatory = $true, HelpMessage = "Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,
	
	[Parameter(Mandatory = $false, HelpMessage = "Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark", "ldap", "radius")]
	[String]$AuthType = "cyberark",	
	
	[Parameter(Mandatory = $true, HelpMessage = "Enter the platform Zip path to import")]
	[Alias("Platform")]
	[string]$PlatformZipPath,
	
	[Parameter(Mandatory = $true, HelpMessage = "Enter the Connection Component Zip path to import")]
	[Alias("ConnectionComponent")]
	[string]$ConnectionComponentZipPath,
	
	[Parameter(Mandatory = $false, HelpMessage = "Enter the PSM Server ID (default 'PSMServer')")]
	[Alias("PSM")]
	[string]$PSMServerID = "PSMServer",
	
	[Parameter(Mandatory = $false)]
	[Switch]$DisableSSLVerify
)

# Global URLS
# -----------
$URL_PVWAAPI = $PVWAURL + "/api"
$URL_Authentication = $URL_PVWAAPI + "/auth"
$URL_Logon = $URL_Authentication + "/$AuthType/Logon"
$URL_Logoff = $URL_Authentication + "/Logoff"

# URL Methods
# -----------
$URL_PlatformDetails = $URL_PVWAAPI + "/Platforms/{0}"
$URL_ImportPlatforms = $URL_PVWAAPI + "/Platforms/Import"
$URL_ImportConnectionComponent = $URL_PVWAAPI + "/ConnectionComponents/Import"

# Initialize Script Variables
# ---------------------------
$rstusername = $rstpassword = ""
$logonToken = ""

#region Functions
Function Test-CommandExists {
	Param ($command)
	$oldPreference = $ErrorActionPreference
	$ErrorActionPreference = 'stop'
	try {
		if (Get-Command $command) {
			RETURN $true
		}
	} catch {
		Write-Host "$command does not exist"; RETURN $false
	} finally {
		$ErrorActionPreference = $oldPreference
	}
} #end function test-CommandExists

Function Get-ZipContent {
	<#
	.SYNOPSIS
		Reads a ZIP file and converts it to Base64 encoding
	.DESCRIPTION
		Reads the specified ZIP file as bytes and converts to Base64 string for API upload
	.PARAMETER zipPath
		Full path to the ZIP file to read
	#>
	Param(
		[Parameter(Mandatory = $true)]
		[string]$zipPath
	)
	
	$zipContent = $null
	try {
		if (Test-Path $zipPath) {
			Write-Verbose "Reading ZIP file: $zipPath"
			# Converting to Base64 for CyberArk API compatibility
			$zipContent = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($(Resolve-Path $zipPath)))
			Write-Verbose "Successfully encoded ZIP file to Base64 (Length: $($zipContent.Length))"
		} else {
			throw "ZIP file not found at path: $zipPath"
		}
	} catch {
		throw "Error while reading ZIP file: $($_.Exception.Message)"
	}
	
	return $zipContent
}

Function AddPlatform-PSMConnectionComponent {
	<#
	.SYNOPSIS
		Modifies a platform ZIP to include PSM and Connection Component configuration
	.DESCRIPTION
		Extracts platform ZIP, modifies the XML to add PSM settings and Connection Component references, then repackages
	.PARAMETER platformZipPath
		Full path to the platform ZIP file
	.PARAMETER psmServerID
		PSM Server ID to configure (default: PSMServer)
	.PARAMETER connectionComponentID
		Connection Component ID to link to the platform
	#>
	Param(
		[Parameter(Mandatory = $true)]
		[string]$platformZipPath,
		
		[Parameter(Mandatory = $false)]
		[string]$psmServerID = "PSMServer",
		
		[Parameter(Mandatory = $true)]
		[string]$connectionComponentID
	)
	
	$tempFolder = $null
	
	try {
		if (Test-Path $platformZipPath) {
			$Package = Get-Item -Path $platformZipPath
			
			# Load ZIP methods
			Add-Type -AssemblyName System.IO.Compression.FileSystem
			Write-Verbose "Extracting Platform ZIP: '$platformZipPath'"
			
			# Extract ZIP to temp folder
			$tempFolder = Join-Path -Path $Package.Directory -ChildPath $Package.BaseName
			
			if (Test-Path $tempFolder) {
				try {
					Write-Verbose "Removing existing temp folder: $tempFolder"
					Remove-Item -Recurse -Force $tempFolder -ErrorAction Stop
				} catch {
					throw "Could not remove existing temp folder '$tempFolder': $($_.Exception.Message)"
				}
			}
			
			[System.IO.Compression.ZipFile]::ExtractToDirectory($Package.FullName, $tempFolder)
			Write-Verbose "Successfully extracted to: $tempFolder"
		} else {
			throw "Could not find Platform ZIP at path: '$platformZipPath'"
		}
		
		Write-Verbose "Adding PSM Connection component to platform"
		
		# Find all XML files in the platform ZIP
		$fileEntries = Get-ChildItem -Path $tempFolder -Filter '*.xml'
		Write-Verbose "Found $($fileEntries.Count) XML file(s)"
		
		# There should be only one XML file in a platform package
		if ($fileEntries.Count -ne 1) { 
			throw "Invalid Platform ZIP file - expected 1 XML file, found $($fileEntries.Count)" 
		}
		
		# Load and validate XML
		[xml]$xmlContent = Get-Content $fileEntries[0].FullName
		Write-Verbose "Loaded XML from: $($fileEntries[0].Name)"
		
		# Validate XML structure
		if (-not $xmlContent.Device) {
			throw "Invalid Platform XML structure - missing 'Device' root element"
		}
		
		if (-not $xmlContent.Device.Policies) {
			throw "Invalid Platform XML structure - missing 'Device.Policies' element"
		}
		
		# Initialize flags
		$psmNodeExists = $false
		$ccNodeExists = $false
		
		# Check existing nodes - iterate through all child nodes of Policies
		Write-Verbose "Checking for existing PSM and ConnectionComponent nodes..."
		ForEach ($item in $xmlContent.Device.Policies.ChildNodes) {
			if ($item.LocalName -eq "PrivilegedSessionManagement") {
				$psmNodeExists = $true
				Write-Verbose "Found existing PrivilegedSessionManagement node"
			}
			if ($item.LocalName -eq "ConnectionComponents") {
				$ccNodeExists = $true
				Write-Verbose "Found existing ConnectionComponents node"
			}
		}
		
		# Add PSM node if it doesn't exist
		if (-not $psmNodeExists) {
			Write-Verbose "Adding PrivilegedSessionManagement node to Platform"
			$psmNode = $xmlContent.CreateElement("PrivilegedSessionManagement")
			$psmNode.SetAttribute("Enable", "Yes")
			$psmNode.SetAttribute("ID", $psmServerID)
			$xmlContent.Device.Policies.AppendChild($psmNode) | Out-Null
			Write-Verbose "Successfully added PSM node with ID: $psmServerID"
		} else {
			Write-Verbose "PSM node already exists - skipping"
		}
		
		# Add Connection Component node if it doesn't exist
		if (-not $ccNodeExists) {
			Write-Verbose "Adding ConnectionComponents node to Platform"
			
			# Create ConnectionComponent child element
			$concompNode = $xmlContent.CreateElement("ConnectionComponent")
			$concompNode.SetAttribute("Id", $connectionComponentID)
			
			# Create ConnectionComponents parent element
			$conNode = $xmlContent.CreateElement("ConnectionComponents")
			$conNode.AppendChild($concompNode) | Out-Null
			
			# Append to Policies
			$xmlContent.Device.Policies.AppendChild($conNode) | Out-Null
			Write-Verbose "Successfully added ConnectionComponent node with ID: $connectionComponentID"
		} else {
			Write-Verbose "ConnectionComponents node already exists - skipping"
		}
		
		# Save modified XML
		Write-Verbose "Saving modified XML to: $($fileEntries[0].FullName)"
		$xmlContent.Save($fileEntries[0].FullName)
		
		# Repackage the platform ZIP
		Write-Verbose "Repackaging Platform ZIP"
		$zipFullPath = $Package.FullName
		Remove-Item $zipFullPath -Force
		[System.IO.Compression.ZipFile]::CreateFromDirectory($tempFolder, $zipFullPath)
		Write-Verbose "Successfully created new ZIP: $zipFullPath"
		
		# Clean up temp folder
		Write-Verbose "Cleaning up temporary folder"
		Remove-Item -Recurse -Force $tempFolder
		Write-Verbose "Cleanup complete"
	} catch {
		# Attempt cleanup on error
		if ($tempFolder -and (Test-Path $tempFolder)) {
			try {
				Remove-Item -Recurse -Force $tempFolder -ErrorAction SilentlyContinue
			} catch {
				Write-Warning "Could not clean up temp folder: $tempFolder"
			}
		}
		throw "Error while linking connection component '$connectionComponentID' to platform: $($_.Exception.Message)"
	}
}
#endregion

# Main Script
# ===========

if (-not (Test-CommandExists Invoke-RestMethod)) {
	Write-Error "This script requires PowerShell version 3 or above"
	return
}

# Configure SSL/TLS settings
if ($DisableSSLVerify) {
	try {
		Write-Warning "It is not recommended to disable SSL verification" -WarningAction Inquire
		# Using Proxy Default credentials if the Server needs Proxy credentials
		[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
		# Using TLS 1.2 as security protocol verification
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
		# Disable SSL Verification
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
	} catch {
		Write-Error "Could not change SSL validation settings"
		Write-Error $_.Exception.Message
		return
	}
} else {
	try {
		Write-Verbose "Setting script to use TLS 1.2"
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
	}
	catch {
		Write-Warning "Could not set TLS 1.2 - continuing anyway"
	}
}

# Check that the PVWA URL is OK
if ($PVWAURL -ne "") {
	if ($PVWAURL.Substring($PVWAURL.Length - 1) -eq "/") {
		$PVWAURL = $PVWAURL.Substring(0, $PVWAURL.Length - 1)
	}
} else {
	Write-Host "PVWA URL cannot be empty" -ForegroundColor Red
	return
}

Write-Host "Import Platform and Connection Component: Script Started" -ForegroundColor Cyan
Write-Host "PVWA URL: $PVWAURL" -ForegroundColor Gray
Write-Host "Auth Type: $AuthType" -ForegroundColor Gray

#region [Logon]
# Get Credentials to Login
# ------------------------
$caption = "Import Platform and Connection Component"
$msg = "Enter your User name and Password" 
$creds = $Host.UI.PromptForCredential($caption, $msg, "", "")

if ($null -ne $creds) {
	$rstusername = $creds.username.Replace('\', '')
	$rstpassword = $creds.GetNetworkCredential().password
	
	# Validate credentials are not empty
	if ([string]::IsNullOrEmpty($rstusername) -or [string]::IsNullOrEmpty($rstpassword)) {
		Write-Host "Username or password cannot be empty" -ForegroundColor Red
		return
	}
} else {
	Write-Host "Authentication cancelled by user" -ForegroundColor Yellow
	return
}

# Create the POST Body for the Logon
# ----------------------------------
$logonBody = @{ username = $rstusername; password = $rstpassword; concurrentSession = $true }
$logonBody = $logonBody | ConvertTo-Json

try {
	# Logon
	Write-Verbose "Attempting logon to: $URL_Logon"
	$logonToken = Invoke-RestMethod -Method Post -Uri $URL_Logon -Body $logonBody -ContentType "application/json" -TimeoutSec 30
	Write-Verbose "Successfully obtained logon token"
} catch {
	Write-Host "Logon failed: $($_.Exception.Message)" -ForegroundColor Red
	if ($_.Exception.Response) {
		Write-Host "Status: $($_.Exception.Response.StatusDescription)" -ForegroundColor Red
	}
	return
}

if ([string]::IsNullOrEmpty($logonToken)) {
	Write-Host "Logon Token is Empty - Cannot login" -ForegroundColor Red
	return
}

# Create a Logon Token Header (This will be used throughout the script)
# ---------------------------
$logonHeader = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$logonHeader.Add("Authorization", $logonToken)
#endregion

#region [Import Connection Component]
# Importing the Connection Component
# ----------------------------------
Write-Host "`nImporting Connection Component..." -ForegroundColor Cyan
$connectionComponentID = $null

if (Test-Path $ConnectionComponentZipPath) {
	Write-Verbose "Connection Component ZIP found at: $ConnectionComponentZipPath"
	
	try {
		$ccZipContent = Get-ZipContent -zipPath $ConnectionComponentZipPath
		$importBody = @{ ImportFile = $ccZipContent } | ConvertTo-Json -Depth 3 -Compress
		
		Write-Verbose "Sending import request to: $URL_ImportConnectionComponent"
		$ImportCCResponse = Invoke-RestMethod -Method POST -Uri $URL_ImportConnectionComponent -Headers $logonHeader -ContentType "application/json" -TimeoutSec 2700 -Body $importBody
		
		$connectionComponentID = ($ImportCCResponse.ConnectionComponentID)
		Write-Host "  Connection Component imported successfully" -ForegroundColor Green
		Write-Host "  Connection Component ID: $connectionComponentID" -ForegroundColor Gray
	} catch {
		$errorOccurred = $true
		
		# Check if component already exists (Conflict/409)
		if ($_.Exception.Response.StatusCode -eq 409 -or $_.Exception.Response.StatusDescription -like "*Conflict*") {
			Write-Host "  Connection Component already exists" -ForegroundColor Yellow
			Write-Host "  Note: The existing component ID cannot be automatically retrieved." -ForegroundColor Yellow
			Write-Host "  Options:" -ForegroundColor Yellow
			Write-Host "    1. Delete the existing component and re-run this script" -ForegroundColor Yellow
			Write-Host "    2. Manually link the component to the platform after import" -ForegroundColor Yellow
			Write-Host "    3. Provide the existing component ID and modify script to use it" -ForegroundColor Yellow
		} else {
			Write-Host "  Error importing Connection Component" -ForegroundColor Red
			Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
			
			if ($_.ErrorDetails) {
				try {
					$errorDetail = $_.ErrorDetails | ConvertFrom-Json
					Write-Host "  Error Code: $($errorDetail.ErrorCode)" -ForegroundColor Red
					Write-Host "  Error Message: $($errorDetail.ErrorMessage)" -ForegroundColor Red
				} catch {
					Write-Host "  Status: $($_.Exception.Response.StatusDescription)" -ForegroundColor Red
				}
			}
		}
		
		# Exit script if component import fails
		Write-Host "`nScript terminated - Connection Component import failed" -ForegroundColor Red
		
		# Logoff before exit
		try {
			Invoke-RestMethod -Method Post -Uri $URL_Logoff -Headers $logonHeader -ContentType "application/json" -TimeoutSec 30 | Out-Null
		} catch {
			Write-Verbose "Logoff failed (non-critical)"
		}
		return
	}
} else {
	Write-Host "  Connection Component ZIP not found at: $ConnectionComponentZipPath" -ForegroundColor Red
	
	# Logoff before exit
	try {
		Invoke-RestMethod -Method Post -Uri $URL_Logoff -Headers $logonHeader -ContentType "application/json" -TimeoutSec 30 | Out-Null
	} catch {
		Write-Verbose "Logoff failed (non-critical)"
	}
	return
}
#endregion

#region [Import Platform]
# Importing the Platform
# ----------------------
Write-Host "`nImporting Platform..." -ForegroundColor Cyan

if (Test-Path $PlatformZipPath) {
	Write-Verbose "Platform ZIP found at: $PlatformZipPath"
	
	# Validate we have a connection component ID to link
	if ([string]::IsNullOrEmpty($connectionComponentID)) {
		Write-Host "  No Connection Component ID available to link to platform" -ForegroundColor Red
		Write-Host "  Cannot proceed with platform import" -ForegroundColor Red
		
		# Logoff before exit
		try {
			Invoke-RestMethod -Method Post -Uri $URL_Logoff -Headers $logonHeader -ContentType "application/json" -TimeoutSec 30 | Out-Null
		} catch {
			Write-Verbose "Logoff failed (non-critical)"
		}
		return
	}
	
	try {
		# Link Connection Component to Platform by modifying the ZIP
		Write-Verbose "Linking Connection Component '$connectionComponentID' to Platform"
		AddPlatform-PSMConnectionComponent -platformZipPath $(Resolve-Path $PlatformZipPath) -psmServerID $PSMServerID -connectionComponentID $connectionComponentID
		Write-Host "  Platform modified to include Connection Component link" -ForegroundColor Green
		
		# Import Platform
		Write-Verbose "Reading modified platform ZIP"
		$platformZipContent = Get-ZipContent -zipPath $PlatformZipPath
		$importBody = @{ ImportFile = $platformZipContent } | ConvertTo-Json -Depth 3 -Compress
		
		Write-Verbose "Sending platform import request to: $URL_ImportPlatforms"
		$ImportPlatformResponse = Invoke-RestMethod -Method POST -Uri $URL_ImportPlatforms -Headers $logonHeader -ContentType "application/json" -TimeoutSec 2700 -Body $importBody
		
		Write-Host "  Platform imported successfully" -ForegroundColor Green
		Write-Host "  Platform ID: $($ImportPlatformResponse.PlatformID)" -ForegroundColor Gray
		
		# Get platform details
		try {
			$platformDetailsURL = $URL_PlatformDetails -f $ImportPlatformResponse.PlatformID
			$platformDetails = Invoke-RestMethod -Method Get -Uri $platformDetailsURL -Headers $logonHeader -ContentType "application/json" -TimeoutSec 30
			
			if ($platformDetails) {
				Write-Host "  Platform Name: $($platformDetails.Details.PolicyName)" -ForegroundColor Gray
				Write-Host "  Status: $(if($platformDetails.Active) { 'Active' } else { 'Inactive' })" -ForegroundColor Gray
			}
		} catch {
			Write-Verbose "Could not retrieve platform details (non-critical)"
		}
	} catch {
		Write-Host "  Error importing Platform" -ForegroundColor Red
		Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
		
		if ($_.ErrorDetails) {
			try {
				$errorDetail = $_.ErrorDetails | ConvertFrom-Json
				Write-Host "  Error Code: $($errorDetail.ErrorCode)" -ForegroundColor Red
				Write-Host "  Error Message: $($errorDetail.ErrorMessage)" -ForegroundColor Red
			} catch {
				Write-Host "  Status: $($_.Exception.Response.StatusDescription)" -ForegroundColor Red
			}
		}
	}
} else {
	Write-Host "  Platform ZIP not found at: $PlatformZipPath" -ForegroundColor Red
}
#endregion

#region [Logoff]
# Logoff the session
# ------------------
Write-Host "`nLogging off session..." -ForegroundColor Gray
try {
	Invoke-RestMethod -Method Post -Uri $URL_Logoff -Headers $logonHeader -ContentType "application/json" -TimeoutSec 30 | Out-Null
	Write-Verbose "Successfully logged off"
} catch {
	Write-Warning "Logoff failed (session may timeout automatically)"
}
#endregion

Write-Host "`nImport Platform and Connection Component: Script Ended" -ForegroundColor Cyan
