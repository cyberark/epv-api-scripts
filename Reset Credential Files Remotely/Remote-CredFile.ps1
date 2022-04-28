<# 
###########################################################################

NAME: 
    Reset Remote Cred File 

AUTHOR:  
    Brian Bors <brian.bors@cyberark.com>
    Assaf Miron<assaf.miron@cyberark.com>

COMMENT: 
    Script will attempt to regenerate the remote Applicative Cred File and Sync it in the Vault.

Version: 
    0.2

Change Log:
    2020-09-13 
        Initial Version    
    2022-04-01
        Updated to allow vault address reset
########################################################################### 
#>

[CmdletBinding()]
param(
	[Parameter(Mandatory = $true, HelpMessage = "Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,
	
	[Parameter(Mandatory = $false, HelpMessage = "Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark", "ldap", "radius")]
	[String]$AuthType = "cyberark",
	
	[Parameter(Mandatory = $false, HelpMessage = "Enter the RADIUS OTP")]
	[ValidateScript({ $AuthType -eq "radius" })]
	[String]$OTP,

	[Parameter(Mandatory = $false, HelpMessage = "Vault Stored Credentials")]
	[PSCredential]$PVWACredentials,

	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory = $false)]
	[Switch]$DisableSSLVerify,

	[Parameter(Mandatory = $false)]
	[Switch]$Jobs,

	[Parameter(Mandatory = $false)]
	[Switch]$AllComponentTypes,

	[Parameter(Mandatory = $false)]
	[Switch]$AllServers,

	[Parameter(Mandatory = $false)]
	[Switch]$DisconnectedOnly,

	[Parameter(Mandatory = $false)]
	[Switch]$ConnectedOnly,

	[Parameter(Mandatory = $false, HelpMessage = "Target Server")]
	[String]$targetServer,

	[Parameter(Mandatory = $false, HelpMessage = "Target Component")]
	[ValidateSet("CPM", "PSM", "PVWA", "CP", "AAM Credential Provider", "PSM/PSMP")]
	[String]$ComponentType,

	[Parameter(Mandatory = $false, HelpMessage = "Target Component Users")]
	[String]$ComponentUsers,
	
	[Parameter(Mandatory = $false, HelpMessage = "Target Component Users via filter")]
	[String]$ComponentUserFilter,

	[Parameter(Mandatory = $false, HelpMessage = "Mapping File")]
	[String]$MapFile,

	[Parameter(Mandatory = $false, HelpMessage = "Old Domain for FQDN")]
	[String]$OldDomain,

	[Parameter(Mandatory = $false, HelpMessage = "New Domain for FQDN")]
	[String]$newDomain,

	[Parameter(Mandatory = $false, HelpMessage = "New vault address")]
	[String]$vaultAddress,

	[Parameter(Mandatory = $false, HelpMessage = "New vault address")]
	[String]$apiAddress,

	[Parameter(Mandatory = $false, HelpMessage = "PSSession Credentials")]
	[PSCredential]$PSCredentials
)

#region Writer Functions
$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent
$oldverbose = $VerbosePreference
if ($InVerbose) {
	$VerbosePreference = "continue"
}


If ($null -ne $PSCredentials) { 
	New-Variable -Scope Global -Name G_PSCredentials -Value $PSCredentials -Force
}
else {
	New-Variable -Scope Global -Name G_PSCredentials -Value $null -Force
}
# Get Script Location 
$ScriptFullPath = $MyInvocation.MyCommand.Path
$ScriptLocation = Split-Path -Parent $ScriptFullPath
$ScriptParameters = @()
$PSBoundParameters.GetEnumerator() | ForEach-Object { $ScriptParameters += ("-{0} '{1}'" -f $_.Key, $_.Value) }
$Script:g_ScriptCommand = "{0} {1}" -f $ScriptFullPath, $($ScriptParameters -join ' ')

# Script Version
$ScriptVersion = "0.10"

# Set Log file path
New-Variable -Name LOG_FILE_PATH -Value "$ScriptLocation\Remote-CredFileReset.log" -Scope Global -Force
New-Variable -Name PVWAURL -Value $PVWAURL -Scope Global -Force 
New-Variable -Name AuthType -Value $AuthType -Scope Global -Force

$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent

Import-Module -Name ".\CyberArk-Common.psm1" -Force

If ($DisableSSLVerify) {
	try {
		Write-Warning "It is not Recommended to disable SSL verification" -WarningAction Inquire
		# Using Proxy Default credentials if the Server needs Proxy credentials
		[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
		# Using TLS 1.2 as security protocol verification
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
		# Disable SSL Verification
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
	}
 catch {
		Write-LogMessage -Type Error -MSG "Could not change SSL validation"
		Write-LogMessage -Type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
		return
	}
}
Else {
	try {
		Write-LogMessage -Type Debug -MSG "Setting script to use TLS 1.2"
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
	}
 catch {
		Write-LogMessage -Type Error -MSG "Could not change SSL settings to use TLS 1.2"
		Write-LogMessage -Type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
	}
}

# Check that the PVWA URL is OK
If (![string]::IsNullOrEmpty($PVWAURL)) {
	If ($PVWAURL.Substring($PVWAURL.Length - 1) -eq "/") {
		$PVWAURL = $PVWAURL.Substring(0, $PVWAURL.Length - 1)
	}
	try {
		# Validate PVWA URL is OK
		Write-LogMessage -Type Debug -MSG "Trying to validate URL: $PVWAURL"
		Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $PVWAURL -Method 'Head' -TimeoutSec 30 | Out-Null
	}
 catch [System.Net.WebException] {
		If (![string]::IsNullOrEmpty($_.Exception.Response.StatusCode.Value__)) {
			Write-LogMessage -Type Error -MSG "Received error $($_.Exception.Response.StatusCode.Value__) when trying to validate PVWA URL"
			Write-LogMessage -Type Error -MSG "Check your connection to PVWA and the PVWA URL"
			return
		}
	}
 catch {		
		Write-LogMessage -Type Error -MSG "PVWA URL could not be validated"
		Write-LogMessage -Type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
	}
	
}
else {
	Write-LogMessage -Type Error -MSG "PVWA URL can not be empty"
	return
}

Import-Module -Name ".\CyberArk-Common.psm1" -Force
Write-LogMessage -Type Verbose -MSG "Getting Logon Token"

Invoke-Logon -Credentials $PVWACredentials

Write-LogMessage -Type Verbose -MSG "Getting Server List"
$componentList = Get-ComponentStatus | Sort-Object $_.'Component Type'
If ($AllComponentTypes) {
	$selectedComponents = $componentList
}
elseif (![string]::IsNullOrEmpty($ComponentType)) {
	$cpSearch = ("CP").ToLower()
	$ComponentType = ($ComponentType.ToLower()) -Replace "\b$cpSearch\b", "AAM Credential Provider"
	$PSMSearch = ("PSM").ToLower()
	$ComponentType = $ComponentType.ToLower() -replace "\b$PSMSearch\b", "PSM/PSMP"

	$selectedComponents = $componentList | Where-Object 'Component Type' -EQ $ComponentType
}
else {
	$selectedComponents = $componentList | Sort-Object $_.'Component Type' | Out-GridView -OutputMode Multiple -Title "Select Component(s)"
}
If (![string]::IsNullOrEmpty($mapfile)) {
	$map = Import-Csv $mapfile
}

Write-LogMessage -Type Verbose -MSG "Getting Component List"
$targetComponents = @()
$availableServers = @()
ForEach ($comp in $selectedComponents) {
	if ($comp.'Total Amount' -gt 0) {
		If ($PVWAURL.Contains("privilegecloud.cyberark.com") -and ("PVWA" -eq $comp.'Component Type')) {
			continue
  }
		$results = Get-ComponentDetails $comp.'Component Type'
		ForEach ($result in $results) {
			$user = ($result.'Component User')
			switch ($user) {
				{ $user.Substring(0, 7) -eq "PSMPApp" } {
					$result.'Component Type' = "PSM";
					Add-Member -InputObject $result -MemberType NoteProperty -Name "OS" -Value "Linux"
					break
				}
				{ $user.Substring(0, 6) -eq "PSMApp" } {
					$result.'Component Type' = "PSM";
					Add-Member -InputObject $result -MemberType NoteProperty -Name "OS" -Value "Windows"
					break
				}
				Default {
					Add-Member -InputObject $result -MemberType NoteProperty -Name "OS" -Value "Windows"
					break
				} 
			}
			If ($null -ne $map) {
				$checkComponentUser = $map.Where({ $_.ComponentUser -eq $result.'Component User' })
				If (0 -ne $checkComponentUser.Count) {
					if (![string]::IsNullOrEmpty($checkComponentUser.'IP Address')) {
						$result.'IP Address' = $checkComponentUser.'IP Address'
					}
					if (![string]::IsNullOrEmpty($checkComponentUser.'Component Type')) {
						$result.'Component Type' = $checkComponentUser.'Component Type'
					}
					if (![string]::IsNullOrEmpty($checkComponentUser.'OS')) {
						$result.'OS' = $checkComponentUser.'OS'
					}
				}
			}
			If ("255.255.255.255" -eq $result.'IP Address') {
				continue
   }
			$availableServers += $result	
		}
	}
 else {
		Write-LogMessage -type Error -MSG "No $($comp.'Component Type') Components Found"
	}
}

If ($DisconnectedOnly) {
	$targetComponents += $availableServers | Where-Object Connected -EQ $false
}
elseif ($ConnectedOnly) {
	$targetComponents += $availableServers | Where-Object Connected -EQ $true
}
elseif ($allServers) {
	$targetComponents += $availableServers
}
elseif (![string]::IsNullOrEmpty($ComponentUsers)) {
	$ComponentUsersArr += $ComponentUsers.Split(",")
	ForEach ($user in $ComponentUsersArr) {
		$targetComponents += $availableServers | Where-Object 'Component User' -EQ $user
	}
}
elseif (![string]::IsNullOrEmpty($ComponentUserFilter)) {
	$targetComponents += $availableServers | Where-Object 'Component User' -Like $ComponentUserFilter
}
else {
	$targetComponents += $availableServers | Sort-Object -Property 'Component Type', "IP Address" | Out-GridView -OutputMode Multiple -Title "Select Server(s)"
}

Write-LogMessage -Type Verbose -MSG "Processing Lists"
Write-LogMessage -Type info -MSG "$($targetComponents.count) components selected for processing" -Footer

Get-Job | Remove-Job -Force
foreach ($target in $targetComponents | Sort-Object $comp.'Component Type') {

	$fqdn = (Resolve-DnsName $target.'IP Address' -ErrorAction SilentlyContinue).namehost
	If ([sting]::IsNullOrEmpty($fqdn)) {
		$fqdn = $target.'IP Address'
	}
	if ((![string]::IsNullOrEmpty($oldDomain)) -and (![string]::IsNullOrEmpty($newDomain)) ) {
		$fqdn = $fqdn.replace($oldDomain, $newDomain)
	}
	If ("Windows" -eq $target.os) {
		If (!(Test-TargetWinRM -server $fqdn )) {
			Write-LogMessage -Type Error -MSG "Error connecting to WinRM for Component User $($target.'Component User') on $($target.'IP Address') $fqdn" -Footer
			continue
		}
	}
 elseif ("Linux" -eq $target.os) {
		Write-LogMessage -type Error -msg "Unable to reset credentials on linux based servers at this time. Manual reset required for Component User $($target.'Component User') on $($target.'IP Address') $fqdn" -Footer
		break
	}

	if (!$jobs) {
		Try {
			Reset-Credentials -ComponentType $target.'Component Type' -Server $fqdn -OS $target.os -vault $vaultAddress -apiAddress $apiAddress
		}
		Catch {
			""
		}

	}
 else {
		$type = $target.'Component Type'
		$os = $target.os
		Write-LogMessage -Type Info -MSG "Creating Job for $Type on $fqdn"
		Start-Job -Name "$($type.Replace("AAM Credential Provider","CP")) on $fqdn" -ScriptBlock { $Script:PVWAURL = $using:PVWAURL; $Script:g_LogonHeader = $using:g_LogonHeader; $script:G_PSCredentials = $using:G_PSCredentials; Import-Module -Name $using:ScriptLocation\CyberArk-Common.psm1 -Force; Reset-Credentials -ComponentType $using:type -Server $using:fqdn -os $using:os -vault $using:vaultAddress -apiAddress $using:apiAddress } -InitializationScript { Set-Location $PSScriptRoot; } | Out-Null
		$jobsRunning = $true
	}

}

Start-Sleep -Seconds 1
$stat = 0
While ($jobsRunning) {
	$running = @(Get-Job | Where-Object { $_.State -eq 'Running' })
	$failed = @(Get-Job | Where-Object { $_.State -eq 'Failed' })
	if ($stat -ge 100) {
		$stat = 0
 }
 Else {
		$stat += 1
 }

	if ($running.Count -eq 0) {
		$jobsRunning = $false
	}
 elseif ($running.Count -eq 1 -and $failed.Count -eq 0) {
		Write-Progress -Id 1 -Activity "$($running.count) job is still running" -CurrentOperation "$($running.Name)"  
	}
 elseif ($running.Count -gt 1 -and $failed.Count -eq 0) {	
		Write-Progress -Id 1 -Activity "$($running.count) jobs are still running" -CurrentOperation "$($running.Name)"
	}
 elseif ($failed.count -eq 1) {
		Write-Progress -Id 1 -Activity "$($failed.count) job is in a failed state and $($running.count) job(s) are still running. Review logs once completed" -CurrentOperation "$($running.Name)"
	}
 elseif ($failed.count -gt 1) {
		Write-Progress -Id 1 -Activity "$($failed.count) jobs are in a failed state and $($running.count) job(s) are still running. Review logs once completed" -CurrentOperation "$($running.Name)"
	}
}
		
if ($jobs) {
	Get-Job | Receive-Job -Keep
	Remove-Job -State Completed
	"All Jobs Completed"
	Get-Job -State Failed | Receive-Job -Keep
}
#region [Logoff]
# Logoff the session
# ------------------
Write-Host "Logoff Session..."

Invoke-Logoff

Remove-Variable -Name LOG_FILE_PATH -Scope Global -Force
Remove-Variable -Name PVWAURL -Scope Global -Force
Remove-Variable -Name AuthType -Scope Global -Force
IF ($null -ne $G_PSCredentials) {
	Remove-Variable -Name G_PSCredentials -Scope Global -Force
}


#endregion

$VerbosePreference = $oldverbose
