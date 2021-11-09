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
    0.1

Change Log:
    2020-09-13 
        Initial Version    

########################################################################### 
#>


[CmdletBinding()]
param(
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,
	
	[Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark","ldap","radius")]
	[String]$AuthType="cyberark",
	
	[Parameter(Mandatory=$false,HelpMessage="Enter the RADIUS OTP")]
	[ValidateScript({$AuthType -eq "radius"})]
	[String]$OTP,

	[Parameter(Mandatory=$false,HelpMessage="Stored Credentials")]
	[PSCredential]$creds,

	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory=$false)]
	[Switch]$DisableSSLVerify,

	[Parameter(Mandatory=$false)]
	[Switch]$jobs,

	[Parameter(Mandatory=$false)]
	[Switch]$allComponents,

	[Parameter(Mandatory=$false)]
	[Switch]$allServers,

	[Parameter(Mandatory=$false)]
	[Switch]$DisconnectedOnly,

	[Parameter(Mandatory=$false,HelpMessage="Target Server")]
	[String]$targetServer,

	[Parameter(Mandatory=$false,HelpMessage="Target Component")]
	[ValidateSet("CPM","PSM","PVWA","CP")]
	[String]$Component,

	[Parameter(Mandatory=$false,HelpMessage="Mapping File")]
	[String]$mapfile
	
)

#region Writer Functions
$InDebug = $PSBoundParameters.Debug.IsPresent
$InVerbose = $PSBoundParameters.Verbose.IsPresent


#Region

#endregion

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

$InDebug = $PSBoundParameters.Debug.IsPresent
$InVerbose = $PSBoundParameters.Verbose.IsPresent



# URL Methods
# -----------



Import-Module -Name ".\CyberArk-Common.psm1" -Force

# Check that the PVWA URL is OK
If (![string]::IsNullOrEmpty($PVWAURL)) {
	If ($PVWAURL.Substring($PVWAURL.Length-1) -eq "/") {
		$PVWAURL = $PVWAURL.Substring(0,$PVWAURL.Length-1)
	}
	
	try{
		# Validate PVWA URL is OK
		Write-LogMessage -Type Debug -MSG "Trying to validate URL: $PVWAURL"
		Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $PVWAURL -Method 'Head' -TimeoutSec 30 | Out-Null
	} catch [System.Net.WebException] {
		If(![string]::IsNullOrEmpty($_.Exception.Response.StatusCode.Value__)) {
			Write-LogMessage -Type Error -MSG "Received error $($_.Exception.Response.StatusCode.Value__) when trying to validate PVWA URL"
			Write-LogMessage -Type Error -MSG "Check your connection to PVWA and the PVWA URL"
			return
		}
	} catch {		
		Write-LogMessage -Type Error -MSG "PVWA URL could not be validated"
		Write-LogMessage -Type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
	}
	
} else {
	Write-LogMessage -Type Error -MSG "PVWA URL can not be empty"
	return
}
Import-Module -Name ".\CyberArk-Common.psm1" -Force
Write-LogMessage -Type Info -MSG "Getting Logon Token"
Invoke-Logon -creds $creds

Write-LogMessage -Type Info -MSG "Getting Server List"
$components = Get-ComponentStatus | Sort-Object $_.'Component Type'
If($allComponents) {$selectedComponents = $components}
else {
	$selectedComponents = $components | Sort-Object $_.'Component Type' | Out-GridView -OutputMode Multiple -Title "Select Component(s)"
}
If (![string]::IsNullOrEmpty($mapfile)){
	$map = Import-Csv $mapfile}

Write-LogMessage -Type Info -MSG "Getting Component List"
$targetComponents = @()
$availableServers = @()
ForEach ($comp in $selectedComponents) {
	if ($comp.'Total Amount' -gt 0){
		If ($PVWAURL.Contains("privilegecloud.cyberark.com") -and ("PVWA" -eq $comp.'Component Type')) {continue}
		$results = Get-ComponentDetails $comp.'Component Type'
		ForEach ($result in $results) {
			If ($null -ne $map){
				$checkComponentUser = $map.Where({$_.ComponentUser -eq $result.'Component User'})
				If (0 -ne $checkComponentUser.Count){
					$result.'IP Address' = $checkComponentUser.'IP Address'
					
				}
			}
			If ("255.255.255.255" -eq $result.'IP Address') {continue}
			$availableServers += $result	
		}
	} else {
		Write-LogMessage -type Error -MSG "No $($comp.'Component Type') Components Found"
	}
}
If   ($DisconnectedOnly) {
	$targetComponents = $availableServers | Where-Object Connected -EQ $false
} elseif ($allServers){
	$targetComponents = $availableServers
} else {
	$targetComponents = $availableServers | Sort-Object -Property 'Component Type',"IP Address" | Out-GridView -OutputMode Multiple -Title "Select Server(s)"
}

Write-LogMessage -Type Info -MSG "Processing Lists"

Get-Job | Remove-Job -Force
foreach ($target in $targetComponents | Sort-Object $comp.'Component Type') {

	$fqdn = (Resolve-DnsName $target.'IP Address'  -ErrorAction SilentlyContinue).namehost
	If (!(Test-TargetWinRM -server $fqdn )) {"Error connectint to WinRM for Component User $($target.'Component User') on $($target.'IP Address') $fqdn";continue } 
	$type = $target.'Component Type'
	if (!$jobs){
		Try{
			Reset-Credentials -ComponentType $type -Server $fqdn
		} Catch {Write-LogMessage -type Error -MSG $_}

	} else {
		Write-LogMessage -Type Info -MSG "Creating Job for $Type on $fqdn"
		$null = Start-Job -Name "$($type.Replace("AAM Credential Provider","CP")) on $fqdn" -ScriptBlock {$Script:PVWAURL = $using:PVWAURL;$Script:g_LogonHeader = $using:g_LogonHeader;Import-Module -Name D:\GIT\Remote-CredFile\CyberArk-Common.psm1 -Force;Reset-Credentials -ComponentType $using:type -Server $using:fqdn} -InitializationScript {Set-Location $PSScriptRoot; }
		$jobsRunning=$true
	}

}

Start-Sleep -Seconds 1
$stat = 0
While ($jobsRunning) {
	$running = @(Get-Job | Where-Object { $_.State -eq 'Running' })
	$failed = @(Get-Job | Where-Object { $_.State -eq 'Failed' })
	if ($stat -ge 100){$stat = 0} Else {$stat += 1}

	if ($running.Count -eq 0){
		$jobsRunning = $false
	} elseif ($running.Count -eq 1 -and $failed.Count -eq 0) {
		Write-Progress -Id 1 -Activity "$($running.count) job is still running" -CurrentOperation "$($running.Name)"  
	} elseif($running.Count -gt 1 -and $failed.Count -eq 0) {	
		Write-Progress -Id 1 -Activity "$($running.count) jobs are still running" -CurrentOperation "$($running.Name)"
	} elseif ($failed.count -eq 1){
		Write-Progress -Id 1 -Activity "$($failed.count) job is in a failed state and $($running.count) job(s) are still running. Review logs once completed" -CurrentOperation "$($running.Name)"
	} elseif ($failed.count -gt 1) {
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

# Footer

#endregion

