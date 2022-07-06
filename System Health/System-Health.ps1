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

    [Parameter(Mandatory = $false, HelpMessage = "Mapping File")]
    [ValidateSet("Component Type", "Component Version", "IP Address", "Component User", "*")]
    [String]$DisplayFields = "*",

    [Parameter(Mandatory = $false)]
    [Switch]$Job,
    [Parameter(Mandatory = $false)]
    [Switch]$OutputObject,
    
    [Parameter(Mandatory = $false, HelpMessage = "Location of CyberArk Common module")]
    [String]$CyberArkCommon
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
$ScriptVersion = "1.0"

# Set Log file path
New-Variable -Name LOG_FILE_PATH -Value "$ScriptLocation\Remote-CredFileReset.log" -Scope Global -Force
New-Variable -Name PVWAURL -Value $PVWAURL -Scope Global -Force 
New-Variable -Name AuthType -Value $AuthType -Scope Global -Force

$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent

If (![string]::IsNullOrEmpty($CyberArkCommon)) {
    $CCModule = "$CyberArkCommon"
}
elseif ((Get-Module -name cyberark-common).count -eq 1){
    $CCModule = (Get-Module -name cyberark-common).Path
Write-LogMessage -Type debug -MSG "CyberArk-Common module already loaded"}
else {
    $CCModule = ".\CyberArk-Common.psm1"
}
Import-Module -Name "$CCModule" -Force


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

Import-Module -Name "$CCModule" -Force
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
elseif ($allComponentTypes -or $Job){
    $selectedComponents = $componentList
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
elseif (![string]::IsNullOrEmpty($ComponentUsers)) {
    $ComponentUsersArr += $ComponentUsers.Split(",")
    ForEach ($user in $ComponentUsersArr) {
        $targetComponents += $availableServers | Where-Object 'Component User' -EQ $user
    }
}
elseif (![string]::IsNullOrEmpty($ComponentUserFilter)) {
    $targetComponents += $availableServers | Where-Object 'Component User' -Like $ComponentUserFilter
}
elseif ($allServers -or $Job) {
    $targetComponents += $availableServers
}
else {
    $targetComponents += $availableServers | Sort-Object -Property 'Component Type', "IP Address" | Out-GridView -OutputMode Multiple -Title "Select Server(s)"
}

If ($OutputObject){
    $targetComponents 
}
elseIf ($DisplayFields -eq "*") {
    $targetComponents | Select-Object -Property * -ExcludeProperty "OS"| Format-Table -AutoSize
}
Else {
    $targetComponents | Select-Object -Property $DisplayFields, "Last Connection" -ExcludeProperty "OS"| Format-Table -AutoSize
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
