<#
.SYNOPSIS
    Remotely resets CyberArk component credential files and synchronises the new password in the Vault.

.DESCRIPTION
    Connects to the PVWA REST API to discover component servers (CPM, PSM, PVWA, AAM Credential Provider),
    then opens a WinRM PSSession to each selected target to:
      1. Stop the component service(s)
      2. Run CreateCredFile.exe to regenerate the credential file
      3. Optionally update vault.ini with a new Vault or API address
      4. Start the component service(s)
      5. Sync the new password to the Vault via the PVWA REST API

    All PVWA REST communication originates from the orchestrating machine only.
    Component servers require only WinRM (TCP 5985) access from the orchestrating machine.

    Supports interactive selection menus (console fallback when running via Remote SSH).
    Supports serial processing (default) or parallel processing (-Jobs).

.PARAMETER PVWAURL
    The base URL of the CyberArk PVWA.
    Example: https://pvwa.mydomain.com/PasswordVault

.PARAMETER AuthType
    Authentication type for the PVWA REST API logon.
    Valid values: cyberark, ldap, radius
    Default: cyberark

.PARAMETER OTP
    One-time password for RADIUS authentication. Only valid when -AuthType is 'radius'.

.PARAMETER PVWACredentials
    PSCredential object for PVWA REST API authentication.
    If not provided, a credential prompt will be shown.

.PARAMETER LogonToken
    A pre-existing PVWA logon token (string or header hashtable).
    When provided, the script will not log off at completion.

.PARAMETER DisableSSLVerify
    Disables SSL certificate validation. NOT recommended for production use.

.PARAMETER Jobs
    Process all selected component servers in parallel using PowerShell background jobs.
    Default (without this switch) is serial processing — one server at a time with live output.
    Use -Jobs for large deployments with many components to process simultaneously.

.PARAMETER AllComponentTypes
    Skip component type selection and process all component types returned by the PVWA.

.PARAMETER AllServers
    Skip server selection and process all servers of the selected component type(s).

.PARAMETER DisconnectedOnly
    Only process servers that are currently disconnected from the Vault.

.PARAMETER ConnectedOnly
    Only process servers that are currently connected to the Vault.

.PARAMETER targetServer
    Process only the server matching this IP address or hostname. Skips the selection menu.

.PARAMETER ComponentType
    Process only this component type. Skips the component type selection menu.
    Valid values: CPM, PSM, PVWA, CP, AAM Credential Provider, PSM/PSMP

.PARAMETER ComponentUsers
    Comma-separated list of specific component usernames to process.

.PARAMETER ComponentUserFilter
    Wildcard filter for component usernames (e.g. 'PasswordManager*').

.PARAMETER MapFile
    Path to a CSV file that maps component users to override IP addresses, component types, or OS.
    CSV columns: ComponentUser, IPAddress, ComponentType, OS

.PARAMETER OldDomain
    Domain suffix to replace in FQDNs resolved from IP addresses.
    Used together with -NewDomain to remap FQDNs in environments with split DNS.

.PARAMETER NewDomain
    Replacement domain suffix. Used together with -OldDomain.

.PARAMETER VaultAddress
    New Vault address to write into the component's vault.ini file.

.PARAMETER ApiAddress
    New API/DR Vault address to write into the component's vault.ini file.

.PARAMETER RemoteCredential
    PSCredential used for WinRM connections to component servers.
    Required when running from a Remote SSH session (SSH cannot delegate Kerberos tickets).
    Use a DOMAIN account (e.g. LAB\Admin) — domain accounts use Kerberos and require no
    TrustedHosts configuration. Local accounts require TrustedHosts to be configured.

.PARAMETER Tries
    Maximum number of attempts to start component services after credential reset.
    Default: 5

.EXAMPLE
    # Interactive — prompted for PVWA credentials, select components via menu
    .\Invoke-CredFileReset.ps1 -PVWAURL 'https://pvwa.lab.local/PasswordVault'

.EXAMPLE
    # Non-interactive serial reset of all CPM servers
    $cred = Get-Credential
    .\Invoke-CredFileReset.ps1 -PVWAURL 'https://pvwa.lab.local/PasswordVault' `
        -PVWACredentials $cred -ComponentType CPM -AllServers

.EXAMPLE
    # Parallel reset from Remote SSH using explicit WinRM credentials (domain account)
    $pvwaCred   = Get-Credential -Message 'PVWA credentials'
    $remoteCred = Get-Credential -Message 'WinRM credentials (use DOMAIN\user)'
    .\Invoke-CredFileReset.ps1 -PVWAURL 'https://pvwa.lab.local/PasswordVault' `
        -PVWACredentials $pvwaCred -RemoteCredential $remoteCred -Jobs

.EXAMPLE
    # Reset only disconnected components using a pre-existing logon token
    .\Invoke-CredFileReset.ps1 -PVWAURL 'https://pvwa.lab.local/PasswordVault' `
        -LogonToken $token -DisconnectedOnly

.EXAMPLE
    # Reset and update vault.ini to point to a new Vault address
    .\Invoke-CredFileReset.ps1 -PVWAURL 'https://pvwa.lab.local/PasswordVault' `
        -PVWACredentials $cred -VaultAddress '10.0.0.10'

.NOTES
    Version:    1.0
    Authors:    Brian Bors <brian.bors@cyberark.com>
                Assaf Miron <assaf.miron@cyberark.com>

    Requires:   PowerShell 5.1+
                WinRM (TCP 5985) access from orchestrating machine to component servers
                CyberArk Vault Administrator or equivalent REST API permissions
                Reset-ComponentCredential.ps1 in the same directory

    Change Log:
    2020-09-13  Initial version
    2022-04-01  Added vault address reset
    2026-03-27  Consolidated into two-file standalone structure; added parallel jobs,
                alternate WinRM credentials, pre-flight checks, diagnostic scripts,
                console selection menu fallback for Remote SSH sessions
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
	[Parameter(Mandatory = $true, HelpMessage = 'Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)')]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias('url')]
	[String]$PVWAURL,

	[Parameter(Mandatory = $false, HelpMessage = 'Enter the Authentication type (Default:CyberArk)')]
	[ValidateSet('cyberark', 'ldap', 'radius')]
	[String]$AuthType = 'cyberark',

	[Parameter(Mandatory = $false, HelpMessage = 'Enter the RADIUS OTP')]
	[ValidateScript({ $AuthType -eq 'radius' })]
	[String]$OTP,

	[Parameter(Mandatory = $false, HelpMessage = 'Vault Stored Credentials')]
	[PSCredential]$PVWACredentials,

	[Parameter(Mandatory = $false, HelpMessage = 'Logon Token')]
	$LogonToken,

	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory = $false)]
	[Switch]$DisableSSLVerify,

	[Parameter(Mandatory = $false, HelpMessage = 'Process all selected components in parallel using background jobs (default: serial).')]
	[Switch]$Jobs,

	[Parameter(Mandatory = $false)]
	[Switch]$AllComponentTypes,

	[Parameter(Mandatory = $false)]
	[Switch]$AllServers,

	[Parameter(Mandatory = $false)]
	[Switch]$DisconnectedOnly,

	[Parameter(Mandatory = $false)]
	[Switch]$ConnectedOnly,

	[Parameter(Mandatory = $false, HelpMessage = 'Target Server')]
	[String]$targetServer,

	[Parameter(Mandatory = $false, HelpMessage = 'Target Component')]
	[ValidateSet('CPM', 'PSM', 'PVWA', 'CP', 'AAM Credential Provider', 'PSM/PSMP')]
	[String]$ComponentType,

	[Parameter(Mandatory = $false, HelpMessage = 'Target Component Users')]
	[String]$ComponentUsers,

	[Parameter(Mandatory = $false, HelpMessage = 'Target Component Users via filter')]
	[String]$ComponentUserFilter,

	[Parameter(Mandatory = $false, HelpMessage = 'Mapping File')]
	[String]$MapFile,

	[Parameter(Mandatory = $false, HelpMessage = 'Old Domain for FQDN')]
	[String]$OldDomain,

	[Parameter(Mandatory = $false, HelpMessage = 'New Domain for FQDN')]
	[String]$newDomain,

	[Parameter(Mandatory = $false, HelpMessage = 'New vault address')]
	[String]$vaultAddress,

	[Parameter(Mandatory = $false, HelpMessage = 'New api address')]
	[String]$apiAddress,

	[Parameter(Mandatory = $false, HelpMessage = 'Credentials for WinRM connections to remote component servers (for workgroups or untrusted domains)')]
	[PSCredential]$RemoteCredential,

	[Parameter(Mandatory = $false, HelpMessage = 'Amount of attempts')]
	[int]$tries = 5
)

#region Script Init
$Script:InDebug = $PSBoundParameters.Debug.IsPresent
$Script:InVerbose = $PSBoundParameters.Verbose.IsPresent
$oldverbose = $VerbosePreference
if ($InVerbose) {
	$VerbosePreference = 'continue'
}

# Get Script Location
$ScriptFullPath = $MyInvocation.MyCommand.Path
$ScriptLocation = Split-Path -Parent $ScriptFullPath
$ScriptParameters = @()
$PSBoundParameters.GetEnumerator() | ForEach-Object { $ScriptParameters += ("-{0} '{1}'" -f $_.Key, $_.Value) }
$Script:ScriptCommand = '{0} {1}' -f $ScriptFullPath, $($ScriptParameters -join ' ')

# Script Version
$ScriptVersion = '1.0'

# Set Log file path
New-Variable -Name LOG_FILE_PATH -Value "$ScriptLocation\Remote-CredFileReset.log" -Scope Script -Force
$Script:PVWAURL = $PVWAURL
$Script:AuthType = $AuthType
#endregion

#region Script Variables
$Script:CpmServices = @("CyberArk Password Manager", "CyberArk Central Policy Manager Scanner")
$Script:PvwaServices = @("CyberArk Scheduled Tasks", "W3SVC", "IISADMIN")
$Script:PsmServices = @("*Privileged Session Manager")
$Script:AamServices = @("CyberArk Application Password Provider")

#Credential file creation commands, keyed by component type and version band
$Script:CredCommands = @{
    AIM  = @{
        Legacy           = ".\CreateCredFile.exe AppProviderUser.cred Password /AppType AppPrv /IpAddress /Hostname /Username {0} /Password {1}"
        v12              = ".\CreateCredFile.exe AppProviderUser.cred Password /AppType AppPrv /IpAddress /Hostname /EntropyFile /DPAPIMachineProtection /Username {0} /Password {1}"
        VersionThreshold = [version]'12.0'
    }
    CPM  = @{
        Legacy           = ".\CreateCredFile.exe user.ini Password /AppType CPM /IpAddress /Hostname /Username {0} /Password {1}"
        v12              = ".\CreateCredFile.exe user.ini Password /AppType CPM /EntropyFile /DPAPIMachineProtection /IpAddress /Hostname /Username {0} /Password {1}"
        VersionThreshold = [version]'12.1'
    }
    PSM  = @{
        App = @{
            Legacy           = ".\CreateCredFile.exe psmapp.cred Password /AppType PSMApp /IpAddress /Hostname /Username {0} /Password {1}"
            v12              = ".\CreateCredFile.exe psmapp.cred Password /AppType PSMApp /EntropyFile /DPAPIMachineProtection /IpAddress /Hostname /Username {0} /Password {1}"
            VersionThreshold = [version]'12.1'
        }
        GW  = @{
            Legacy           = ".\CreateCredFile.exe psmgw.cred Password /AppType PSMApp /IpAddress /Hostname /Username {0} /Password {1}"
            v12              = ".\CreateCredFile.exe psmgw.cred Password /AppType PSMApp /EntropyFile /DPAPIMachineProtection /IpAddress /Hostname /Username {0} /Password {1}"
            VersionThreshold = [version]'12.1'
        }
    }
    PVWA = @{
        App = @{
            Legacy           = ".\CreateCredFile.exe ..\CredFiles\appuser.ini Password /AppType PVWAApp /IpAddress /Hostname /ExePath `"C:\Windows\System32\inetsrv\w3wp.exe`" /Username {0} /Password {1}"
            v12              = ".\CreateCredFile.exe ..\CredFiles\appuser.ini Password /AppType PVWAApp /IpAddress /Hostname /ExePath `"C:\Windows\System32\inetsrv\w3wp.exe`" /EntropyFile /DPAPIMachineProtection /Username {0} /Password {1}"
            VersionThreshold = [version]'12.1'
        }
        GW  = @{
            Legacy           = ".\CreateCredFile.exe ..\CredFiles\gwuser.ini Password /AppType PVWAApp /IpAddress /Hostname /ExePath `"C:\Windows\System32\inetsrv\w3wp.exe`" /Username {0} /Password {1}"
            v12              = ".\CreateCredFile.exe ..\CredFiles\gwuser.ini Password /AppType PVWAApp /IpAddress /Hostname /ExePath `"C:\Windows\System32\inetsrv\w3wp.exe`" /EntropyFile /DPAPIMachineProtection /Username {0} /Password {1}"
            VersionThreshold = [version]'12.1'
        }
    }
}

$Script:PrePSSession = { $env:PSModulePath = "C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules;" }
#endregion

#region URL Variables
$URL_PVWAAPI = $Script:PVWAURL + "/api"
$URL_Authentication = $URL_PVWAAPI + "/auth"
$URL_Logon = $URL_Authentication + "/$Script:AuthType/Logon"
$URL_Logoff = $URL_Authentication + "/Logoff"

$URL_UserSearch = $URL_PVWAAPI + "/Users?filter=componentUser&search={0}"
$URL_UserResetPassword = $URL_PVWAAPI + "/Users/{0}/ResetPassword"
$URL_Activate = $URL_PVWAAPI + "/Users/{0}/Activate"

$URL_HealthSummery = $URL_PVWAAPI + "/ComponentsMonitoringSummary"
$URL_HealthDetails = $URL_PVWAAPI + "/ComponentsMonitoringDetails/{0}"
#endregion

#region Functions

. "$PSScriptRoot\Reset-ComponentCredential.ps1"

Function Test-CommandExists {
    <#
.SYNOPSIS
Tests if a command exists
.DESCRIPTION
Tests if a command exists
.PARAMETER Command
The command to test
#>
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {
        if (Get-Command $command) {
            RETURN $true
        }
    }
    Catch {
        Write-Host "$command does not exist"; RETURN $false
    }
    Finally {
        $ErrorActionPreference = $oldPreference
    }
}

Function Invoke-Rest {
    <#
.SYNOPSIS
Invoke REST Method
.DESCRIPTION
Invoke REST Method
.PARAMETER Command
The REST Command method to run (GET, POST, PATCH, DELETE)
.PARAMETER URI
The URI to use as REST API
.PARAMETER Header
The Header as Dictionary object
.PARAMETER Body
(Optional) The REST Body
.PARAMETER ErrAction
(Optional) The Error Action to perform in case of error. By default "Continue"
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("GET", "POST", "DELETE", "PATCH")]
        [String]$Command,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$URI,
        [Parameter(Mandatory = $false)]
        $Header,
        [Parameter(Mandatory = $false)]
        [String]$Body,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Continue", "Ignore", "Inquire", "SilentlyContinue", "Stop", "Suspend")]
        [String]$ErrAction = "Continue"
    )

    If ((Test-CommandExists Invoke-RestMethod) -eq $false) {
        Throw "This script requires PowerShell version 3 or above"
    }
    $restResponse = ""
    try {
        if ([string]::IsNullOrEmpty($Body)) {
            Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -TimeoutSec 2700"
            $restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -TimeoutSec 2700 -ErrorAction $ErrAction
        }
        else {
            Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body -TimeoutSec 2700"
            $restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body -TimeoutSec 2700 -ErrorAction $ErrAction
        }
    }
    catch [System.Net.WebException] {
        if ($ErrAction -match ("\bContinue\b|\bInquire\b|\bStop\b|\bSuspend\b")) {
            Write-LogMessage -Type Error -Msg "Error Message: $_"
            Write-LogMessage -Type Error -Msg "Exception Message: $($_.Exception.Message)"
            Write-LogMessage -Type Error -Msg "Status Code: $($_.Exception.Response.StatusCode.value__)"
            Write-LogMessage -Type Error -Msg "Status Description: $($_.Exception.Response.StatusDescription)"
        }
        $restResponse = $null
    }
    catch {
        Throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $_.Exception))
    }
    Write-LogMessage -Type Verbose -Msg "Invoke-REST Response: $restResponse"
    return $restResponse
}

Function Get-LogonHeader {
    <#
.SYNOPSIS
Get-LogonHeader
.DESCRIPTION
Get-LogonHeader
.PARAMETER Credentials
The REST API Credentials to authenticate
#>
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials,
        [Parameter(Mandatory = $false)]
        [bool]$concurrentSession = $true,
        [Parameter(Mandatory = $false)]
        [string]$RadiusOTP
    )
    # Create the POST Body for the Logon
    # ----------------------------------
    $logonBodyHash = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password; concurrentSession = $concurrentSession }
    If (![string]::IsNullOrEmpty($RadiusOTP)) {
        $logonBodyHash.password += ",$RadiusOTP"
    }
    $logonBody = $logonBodyHash | ConvertTo-Json -Compress
    try {
        # Logon
        $logonToken = Invoke-Rest -Command Post -Uri $URL_Logon -Body $logonBody
        # Clear logon body
        $logonBody = ""
    }
    catch {
        Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.Exception.Response.StatusDescription)", $_.Exception))
    }
    $logonHeader = $null
    If ([string]::IsNullOrEmpty($logonToken)) {
        Throw "Get-LogonHeader: Logon Token is Empty - Cannot login"
    }

    # Create a Logon Token Header (This will be used through out all the script)
    # ---------------------------
    $logonHeader = @{Authorization = $logonToken }
    return $logonHeader
}

Function Invoke-Logoff {
    $null = Invoke-Rest -Uri $URL_Logoff -Header $Script:LogonHeader -Command "Post"
}

Function Get-LogonTimeUnixTime {
    param (
        [Parameter()]
        [string]$unixTime
    )
    [datetime]$origin = '1970-01-01 00:00:00'
    return $origin.AddSeconds($unixTime).ToLocalTime()
}

Function Set-UserPassword {
    <#
.SYNOPSIS
Set-UserPassword
.DESCRIPTION
Resets a component user password via REST API
.PARAMETER Username
The username to reset
.PARAMETER Password
The new password as a SecureString
#>
    param(
        [Parameter(Mandatory = $true)]
        [String]$Username,
        [Parameter(Mandatory = $true)]
        [SecureString]$Password
    )
    Process {
        Write-LogMessage -type Verbose -MSG "URL for PVWA: $PVWAURL"
        Write-LogMessage -type Verbose -MSG "URL for PVWA API: $URL_PVWAAPI"
        $urlSearch = $Script:URL_UserSearch -f $Username
        Write-LogMessage -type Verbose -MSG "URL for user search: $urlSearch"
        $searchResult = $(Invoke-Rest -Uri $urlSearch -Header $Script:LogonHeader -Command "Get")
        if ($searchResult.Total -gt 0) {
            $userFound = $false
            foreach ($account in $searchResult.users) {
                if ($account.username -ieq $Username -and $account.componentUser) {
                    try {
                        $userFound = $true
                        $accountID = $account.id

                        $bodyActivate = @{id = $accountID } | ConvertTo-Json -Depth 3 -Compress
                        $urlActivate = $Script:URL_Activate -f $accountID
                        $null = Invoke-Rest -Uri $urlActivate -Header $Script:LogonHeader -Command "Post" -Body $bodyActivate

                        $bodyReset = @{ id = $accountID; newPassword = $(Convert-SecureString($Password)) } | ConvertTo-Json -Depth 3 -Compress
                        $urlReset = $Script:URL_UserResetPassword -f $accountID
                        $null = Invoke-Rest -Uri $urlReset -Header $Script:LogonHeader -Command "Post" -Body $bodyReset
                    }
                    catch {
                        Throw $_
                    }
                }
            }
            If (!$userFound) {
                Write-LogMessage -type Verbose -MSG "Unable to locate component account for $Username"
            }
        }
        else {
            Write-LogMessage -type Verbose -MSG "Unable to locate component account for $Username"
        }
    }
}

function Reset-Credentials {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComponentType,

        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [string]$OS,

        [Parameter(Mandatory = $false)]
        [string]$vaultAddress,

        [Parameter(Mandatory = $false)]
        [string]$apiAddress,

        [Parameter(Mandatory = $false)]
        [int]$tries = 5,
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )

    $pvwaHost = $PVWAURL.replace('\', '/').replace('https://', '').replace('http://', '').Split('/')[0].Split(':')[0].ToLower()
    $serverHost = $server.ToLower()
    # Resolve both sides to IP so the check works whether the URL uses an IP or FQDN
    $pvwaIP   = try { ([System.Net.Dns]::GetHostAddresses($pvwaHost)  | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).IPAddressToString } catch { $pvwaHost }
    $serverIP = try { ([System.Net.Dns]::GetHostAddresses($serverHost) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).IPAddressToString } catch { $serverHost }
    If ($pvwaIP -eq $serverIP -or $pvwaHost -eq $serverHost) {
        Write-LogMessage -type Warning -MSG "Skipping PVWA on $server — it is the PVWA this script is connected to. Resetting it would drop the REST session." -Footer
        return
    }
    Try {
        IF ("Windows" -eq $os) {
            switch ($ComponentType) {
                "CPM" {
                    Reset-WinComponent -Server $server -component "CPM" -componentName $ComponentType -services $Script:CpmServices -vaultaddress $vaultAddress -tries $tries -apiAddress $apiAddress -Credential $Credential; break
                }
                "PVWA" {
                    Reset-WinComponent -Server $server -component "PVWA" -componentName $ComponentType -services $Script:PvwaServices -vaultaddress $vaultAddress -tries $tries -Credential $Credential; break
                }
                "PSM" {
                    Reset-WinComponent -Server $server -component "PSM" -componentName $ComponentType -services $Script:PsmServices -vaultaddress $vaultAddress -tries $tries -apiAddress $apiAddress -Credential $Credential; break
                }
                "AAM Credential Provider" {
                    Reset-WinComponent -Server $server -component "AIM" -componentName $ComponentType -services $Script:AamServices -vaultaddress $vaultAddress -tries $tries -Credential $Credential; break
                }
                "Secrets Manager Credential Providers" {
                    Reset-WinComponent -Server $server -component "AIM" -componentName $ComponentType -services $Script:AamServices -vaultaddress $vaultAddress -tries $tries -Credential $Credential; break
                }
                default {
                    Write-LogMessage -type Error -MSG "No Component Type passed for $server"
                }
            }
        }
        elseIf ("Linux" -eq $os) {
            Write-LogMessage -type Error -msg "Unable to reset PSMP credentials at this time. Manual reset required for $server"
            Throw
        }
        else {
            Write-LogMessage -type Error -msg "Unable to determine OS type for $server"
            Throw
        }
    }
    Catch {
        Throw
    }
}

function Reset-WinComponent {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $true)]
        [string]$component,
        [Parameter(Mandatory = $true)]
        [string]$componentName,
        [Parameter(Mandatory = $false)]
        [int]$tries = 5,
        [Parameter(Mandatory = $true)]
        $services,
        [Parameter(Mandatory = $false)]
        [string]$vaultaddress,
        [Parameter(Mandatory = $false)]
        [string]$apiAddress,
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )
    $complete = $failed = $false
    $attempts = 0
    Write-LogMessage -type Verbose -MSG "Entering Reset-WinComponent"
    $complete = $failed = $updated = $false
    While (!$complete -and !$failed) {
        try {
            While (!$complete) {
                Try {
                    If ([string]::IsNullOrEmpty($session)) {
                        $session = New-PSLogon -server $server -Credential $Credential
                        Write-LogMessage -type Verbose -MSG "Got Session"
                        Write-LogMessage -type Verbose -MSG "Connected to host: $(Invoke-Command -Session $session -ScriptBlock{[System.Net.Dns]::GetHostName()})"
                        Write-LogMessage -type Verbose -MSG "Connected as user: $(Invoke-Command -Session $session -ScriptBlock{whoami.exe})"
                        Invoke-Command -Session $session -FilePath "$ScriptLocation\Reset-ComponentCredential.ps1"
                        Write-LogMessage -type Verbose -MSG "Loaded remote functions into session"
                    }
                }
                Catch {
                    break
                }
                IF (!$Updated) {
                    Write-LogMessage -type Verbose -MSG "Connected to $Server. Getting information about the installed components"

                    $compInfo = Get-ComponentInfo -Server $Server -ComponentType $component -Session $Session

                    $installLocation = $compInfo.path
                    [version]$version = $compInfo.Version
                    Write-LogMessage -type Verbose -MSG "Retrived Component Information"
                    Write-LogMessage -type Verbose -MSG "Installation path : $installLocation"
                    Write-LogMessage -type Verbose -MSG "Version: $version"

                    Write-LogMessage -type Verbose -MSG "Attempting to stop $componentName Services"
                    Stop-ComponentService -services $services -session $session -server $server
                    Write-LogMessage -type Verbose -MSG "Stopped $componentName Services"

                    $credfailed = Reset-WinCredFile -Server $server -compInfo $compInfo -session $session

                    IF (!($credfailed) -and (![string]::IsNullOrEmpty($vaultaddress))) {
                        Reset-VaultFile -Server $server -compInfo $compInfo -session $session -vaultAddres $vaultaddress -apiAddress $apiAddress | Out-Null
                    }
                    $Updated = $true
                }
                Write-LogMessage -type Verbose -MSG "Attempting to start $componentName services"
                $complete = Start-ComponentService -services $services -session $session -server $server

                $attempts += 1

                if ($attempts -gt $tries) {
                    $failed = $true;
                    Write-LogMessage -type Error -MSG "Failed on $server"
                    Throw "Failed on $componentName credentials on $server"
                }

                if ($updated -and $complete) {
                    Write-LogMessage -type Success -MSG "Update of $componentName component on `"$server`" completed successfully"
                }
                elseif ($updated -and !$complete) {
                    Write-LogMessage -type Warning -MSG "Update of $componentName component on `"$server`" completed successfully, however services did not start. Attempting to restart services"
                }
                else {
                    Write-LogMessage -type Warning -MSG "Update of $componentName component on `"$server`" failed, attempting to restart"
                }
            }
        }
        catch {
            Write-LogMessage -type Error -MSG "Error during update of $componentName on `"$server`""
            Throw
        }
        Finally {
            Write-LogMessage -type Verbose -MSG "Disconnecting from `"$server`""
            Remove-PSSession $session
            Write-LogMessage -type Verbose -MSG "Disconnected from $server" -Footer
        }
    }
}

function Get-ComponentInfo {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [string]$ComponentType,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )
    $newSession = $false
    try {
        if ($Session.State -ne "Opened") {
            $newSession = $true
            $Session = New-PSLogon $server
        }
        $ComponentsFound = Invoke-Command -Session $Session -ScriptBlock { Find-WinComponents $args[0] } -ArgumentList $ComponentType
        return $ComponentsFound
    }
    catch {
        Throw "error"
    }
    Finally {
        If ($newSession) {
            Remove-PSSession $Session
        }
    }
}

Function Get-ComponentStatus {
    try {
        $restResponse = $(Invoke-Rest -Uri $URL_HealthSummery -Header $Script:LogonHeader -Command "Get")
        $selection = $restResponse.Components | Where-Object { $_.ComponentTotalCount -gt 0 } | Select-Object @{Name = "Component Type"; Expression = { $_.'ComponentName' } }, @{Name = "Amount Connected"; Expression = { $_.'ConnectedComponentCount' } }, @{Name = "Total Amount"; Expression = { $_.'ComponentTotalCount' } } | Sort-Object -Property "Component Type"
        Return $selection
    }
    catch {
        return $null
    }
}

Function Get-ComponentDetails {
    param (
        [Parameter(Mandatory = $true)]
        $component
    )

    switch ($component) {
        "PSM/PSMP" {
            $targetComp = "SessionManagement"; break
        }
        "Secrets Manager Credential Providers" {
            $targetComp = "AIM"; break
        }
        "AAM Credential Provider" {
            $targetComp = "AIM"; break
        }
        Default {
            $targetComp = $component
        }
    }
    $URLHealthDetails = $URL_HealthDetails -f $targetComp
    Try {
        $restResponse = $(Invoke-Rest -Uri $URLHealthDetails -Header $Script:LogonHeader -Command "Get")
        $selection = $restResponse.ComponentsDetails | Select-Object @{Name = "Component Type"; Expression = { $component } }, @{Name = "Component Version"; Expression = { $_.ComponentVersion } }, @{Name = "IP Address"; Expression = { $_.'ComponentIP' } }, @{Name = "Component User"; Expression = { $_.'ComponentUserName' } }, @{Name = "Connected"; Expression = { $_.'IsLoggedOn' } }, @{Name = "Last Connection"; Expression = { Get-LogonTimeUnixTime $_.'LastLogonDate' } } | Sort-Object -Property "IP Address"
        Return $selection
    }
    Catch {
        Return $null
    }
}

Function Test-TargetWinRM {
    param (
        [Parameter(Mandatory = $true)]
        [string]$server,
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )
    Write-LogMessage -type Verbose -MSG "In Test-TargetWinRM"
    Write-LogMessage -type Verbose -MSG "Parameter passed for `'server`' is `"$server`""

    try {
        $testSession = New-PSLogon -server $server -Credential $Credential
        Remove-PSSession -Session $testSession
        Write-LogMessage -type Verbose -MSG "Test-TargetWinRM completed Successfully"
        Return $true
    }
    catch {
        Write-LogMessage -type Verbose -MSG "Test-TargetWinRM failed to connect"
        Return $false
    }
    Finally {
        Write-LogMessage -type Verbose -MSG "Existing Test-TargetWinRM"
    }
}

function New-PSLogon {
    param (
        [Parameter(Mandatory = $true)]
        [string]$server,
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )
    $psoptions = New-PSSessionOption -MaxConnectionRetryCount 2

    Write-LogMessage -type Verbose -MSG "In New-PSLogon"
    Write-LogMessage -type Verbose -MSG "Parameter passed for `'server`' is `"$server`""

    Try {
        $effectiveCred = if ($null -ne $Credential) { $Credential } else { $Script:RemoteCredential }
        If ($null -ne $effectiveCred) {
            Write-LogMessage -type Verbose -MSG "Connecting to $server with explicit credentials for $($effectiveCred.username)"
            $psSession = New-PSSession $server -Credential $effectiveCred -SessionOption $psoptions -ErrorAction SilentlyContinue -ErrorVariable psSessionError
        }
        else {
            Write-LogMessage -type Verbose -MSG "Connecting to $server using implicit (Kerberos) credentials"
            $psSession = New-PSSession $server -SessionOption $psoptions -ErrorAction SilentlyContinue -ErrorVariable psSessionError
        }
        if ([string]::IsNullOrEmpty($psSession)) {
            $reason = if ($psSessionError.Count -gt 0) { $psSessionError[0].Exception.Message } else { 'Unknown reason' }
            Write-LogMessage -type Error -MSG "Error creating PSSession to $server : $reason"
            Throw "No PSSession"
        }
        Write-LogMessage -type Verbose -MSG "Created Session successfully"
        IF (![string]::IsNullOrEmpty($Script:PrePSSession)) {
            Write-LogMessage -type Verbose -MSG "Inside PrePSSession"
            Invoke-Command -Session $psSession -ScriptBlock $Script:PrePSSession -ErrorAction SilentlyContinue
            Write-LogMessage -type Verbose -MSG "Completed PrePSSession"
        }
        return $psSession
    }
    Catch {
        Write-LogMessage -type Verbose -MSG "Catch in New-PSLogon"
        Write-LogMessage -type Verbose -MSG "$_"
        Throw "No PSSession"
    }
    Finally {
        Write-LogMessage -type Verbose -MSG "Existing New-PSLogon"
    }
}

function Invoke-SelectionMenu {
    <#
.SYNOPSIS
    Interactive selection menu with Out-GridView fallback for non-GUI sessions.
.DESCRIPTION
    Attempts to use Out-GridView for item selection. If Out-GridView is unavailable
    (e.g. VS Code Remote SSH, Server Core), falls back to a numbered console menu
    driven by Read-Host. Supports multi-select in both modes.
.PARAMETER Items
    The array of objects to select from.
.PARAMETER Title
    The title shown in the grid view or console menu header.
.PARAMETER DisplayProperties
    One or more property names to display in the console fallback menu.
    Out-GridView displays all properties automatically.
#>
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Items,
        [Parameter(Mandatory = $true)]
        [string]$Title,
        [Parameter(Mandatory = $true)]
        [string[]]$DisplayProperties
    )
    # In Remote SSH sessions, Out-GridView hangs instead of throwing — detect and skip it
    $isRemoteSession = ($null -ne $env:SSH_CLIENT -or $null -ne $env:SSH_TTY -or -not [System.Environment]::UserInteractive)
    if (-not $isRemoteSession) {
        try {
            return $Items | Out-GridView -OutputMode Multiple -Title $Title -ErrorAction Stop
        }
        catch {
            # GUI unavailable (HostException, InvalidOperationException, etc.) — fall through to console menu
        }
    }
    # Build column widths for alignment
    $colWidths = $DisplayProperties | ForEach-Object {
        $prop = $_
        $maxLen = ($Items | ForEach-Object { "$($_.$prop)".Length } | Measure-Object -Maximum).Maximum
        [Math]::Max($prop.Length, $maxLen)
    }
    Write-Host "`n=== $Title ==="
    Write-Host '  [0] Exit'
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $cols = for ($c = 0; $c -lt $DisplayProperties.Count; $c++) {
            "$($Items[$i].($DisplayProperties[$c]))".PadRight($colWidths[$c])
        }
        Write-Host "  [$($i + 1)] $($cols -join '  |  ')"
    }
    $raw = Read-Host -Prompt 'Enter comma-separated numbers (e.g. 1,3,5), * for all, or 0 to exit'
    if ($raw.Trim() -eq '0') { return @() }
    if ($raw.Trim() -eq '*') { return $Items }
    $selected = $raw.Split(',') | ForEach-Object {
        $index = [int]$_.Trim() - 1
        if ($index -ge 0 -and $index -lt $Items.Count) { $Items[$index] }
    }
    return $selected
}

#endregion

# Verify Invoke-RestMethod is available
If ((Test-CommandExists Invoke-RestMethod) -eq $false) {
    Write-LogMessage -Type Error -MSG "This script requires PowerShell version 3 or above"
    return
}

If ($DisableSSLVerify) {
	try {
		Write-Warning 'It is not Recommended to disable SSL verification' -WarningAction Inquire
		# Using Proxy Default credentials if the Server needs Proxy credentials
		[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
		# Using TLS 1.2 as security protocol verification
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
		# Disable SSL Verification
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
	}
	catch {
		Write-LogMessage -type Error -MSG 'Could not change SSL validation'
		Write-LogMessage -type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction 'SilentlyContinue'
		return
	}
}
Else {
	try {
		Write-LogMessage -type Debug -MSG 'Setting script to use TLS 1.2'
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
	}
	catch {
		Write-LogMessage -type Error -MSG 'Could not change SSL settings to use TLS 1.2'
		Write-LogMessage -type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction 'SilentlyContinue'
	}
}

# Check that the PVWA URL is OK
If (![string]::IsNullOrEmpty($PVWAURL)) {
	If ($PVWAURL.Substring($PVWAURL.Length - 1) -eq '/') {
		$PVWAURL = $PVWAURL.Substring(0, $PVWAURL.Length - 1)
	}
	try {
		# Validate PVWA URL is OK
		Write-LogMessage -type Debug -MSG "Trying to validate URL: $PVWAURL"
		Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $PVWAURL -Method 'Head' -TimeoutSec 30 | Out-Null
	}
	catch [System.Net.WebException] {
		If (![string]::IsNullOrEmpty($_.Exception.Response.StatusCode.Value__)) {
			Write-LogMessage -type Error -MSG "Received error $($_.Exception.Response.StatusCode.Value__) when trying to validate PVWA URL"
			Write-LogMessage -type Error -MSG 'Check your connection to PVWA and the PVWA URL'
			return
		}
	}
	catch {
		Write-LogMessage -type Error -MSG 'PVWA URL could not be validated'
		Write-LogMessage -type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction 'SilentlyContinue'
	}
}
else {
	Write-LogMessage -type Error -MSG 'PVWA URL can not be empty'
	return
}

Write-LogMessage -type Verbose -MSG 'Getting Logon Token'

#region [Logon]
# Get Credentials to Login
# ------------------------
$caption = 'Reset Credential Files Remotely'
If (![string]::IsNullOrEmpty($logonToken)) {
	if ($logonToken.GetType().name -eq 'String') {
		$Script:LogonHeader = @{Authorization = $logonToken }
	}
	else {
		$Script:LogonHeader = $logonToken
	}
}
else {
	If (![string]::IsNullOrEmpty($PVWACredentials)) {
		$creds = $PVWACredentials
	}
	else {
		$msg = "Enter your $AuthType User name and Password"
		$creds = $Host.UI.PromptForCredential($caption, $msg, '', '')
	}
	if ($AuthType -eq 'radius' -and ![string]::IsNullOrEmpty($OTP)) {
		$Script:LogonHeader = Get-LogonHeader -Credentials $creds -concurrentSession $true -RadiusOTP $OTP
	}
	else {
		$Script:LogonHeader = Get-LogonHeader -Credentials $creds -concurrentSession $true
	}
	# Verify that we successfully logged on
	If ($null -eq $Script:LogonHeader) {
		return # No logon header, end script
	}
}
#endregion

#region Pre-flight Checks
Write-LogMessage -type Info -MSG 'Running pre-flight checks' -Header

# Check: TrustedHosts advisory when using explicit WinRM credentials
if ($null -ne $RemoteCredential) {
	$script:preFlight_TrustedHosts = (Get-Item 'WSMan:\localhost\Client\TrustedHosts' -ErrorAction SilentlyContinue).Value
	if ([string]::IsNullOrEmpty($script:preFlight_TrustedHosts)) {
		Write-LogMessage -type Warning -MSG "-RemoteCredential provided but TrustedHosts is empty. All WinRM connections with explicit credentials will fail with 'Access Denied'."
		Write-LogMessage -type Warning -MSG "Fix (run once as admin on this machine): Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force"
		Write-LogMessage -type Warning -MSG "Or for specific hosts:  Set-Item WSMan:\localhost\Client\TrustedHosts -Value 'server1,server2' -Force"
	}
	elseif ($script:preFlight_TrustedHosts -ne '*') {
		Write-LogMessage -type Info -MSG "-RemoteCredential provided. TrustedHosts: $($script:preFlight_TrustedHosts) — verify all target servers are covered."
	}
}
else {
	$script:preFlight_TrustedHosts = $null
}

Write-LogMessage -type Info -MSG "Tip: Run .\Test-RemoteConnectivity.ps1 -ComputerName <server> to verify WinRM connectivity before processing."
Write-LogMessage -type Info -MSG 'Pre-flight checks complete' -Footer
#endregion

Write-LogMessage -type Verbose -MSG 'Getting Server List'
$componentList = Get-ComponentStatus | Sort-Object $_.'Component Type'
If ($AllComponentTypes) {
	$selectedComponents = $componentList
}
elseif (![string]::IsNullOrEmpty($ComponentType)) {
	$cpSearch = ('CP').ToLower()
	$ComponentType = ($ComponentType.ToLower()) -Replace "\b$cpSearch\b", 'AAM Credential Provider'
	$PSMSearch = ('PSM').ToLower()
	$ComponentType = $ComponentType.ToLower() -replace "\b$PSMSearch\b", 'PSM/PSMP'

	$selectedComponents = $componentList | Where-Object 'Component Type' -EQ $ComponentType
}
else {
	$selectedComponents = Invoke-SelectionMenu -Items @($componentList | Sort-Object $_.'Component Type') -Title 'Select Component(s)' -DisplayProperties 'Component Type', 'Amount Connected', 'Total Amount'
	if ($selectedComponents.Count -eq 0) {
		Write-LogMessage -type Info -MSG 'No components selected. Exiting.'
		Invoke-Logoff
		return
	}
}
If (![string]::IsNullOrEmpty($mapfile)) {
	$map = Import-Csv $mapfile
}

Write-LogMessage -type Verbose -MSG 'Getting Component List'
$targetComponents = @()
$availableServers = @()
ForEach ($comp in $selectedComponents) {
	if ($comp.'Total Amount' -gt 0) {
		If ($PVWAURL.Contains('privilegecloud') -and ('PVWA' -eq $comp.'Component Type')) {
			continue
		}
		$results = Get-ComponentDetails $comp.'Component Type'
		ForEach ($result in $results) {
			$user = ($result.'Component User')
				switch ($user) {
					{ 'PSMPApp' -eq $user.Substring(0, 7)} {
						$result.'Component Type' = 'PSM'
						Add-Member -InputObject $result -MemberType NoteProperty -Name 'OS' -Value 'Linux'
						break
					}
					{'PSMApp'  -eq $user.Substring(0, 6) } {
						$result.'Component Type' = 'PSM'
						Add-Member -InputObject $result -MemberType NoteProperty -Name 'OS' -Value 'Windows'
						break
					}
					Default {
						Add-Member -InputObject $result -MemberType NoteProperty -Name 'OS' -Value 'Windows'
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
			If ('255.255.255.255' -eq $result.'IP Address') {
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
	$ComponentUsersArr += $ComponentUsers.Split(',')
	ForEach ($user in $ComponentUsersArr) {
		$targetComponents += $availableServers | Where-Object 'Component User' -EQ $user
	}
}
elseif (![string]::IsNullOrEmpty($ComponentUserFilter)) {
	$targetComponents += $availableServers | Where-Object 'Component User' -Like $ComponentUserFilter
}
else {
	$targetComponents += Invoke-SelectionMenu -Items @($availableServers | Sort-Object -Property 'Component Type', 'IP Address') -Title 'Select Server(s)' -DisplayProperties 'Component Type', 'IP Address', 'Component User'
	if ($targetComponents.Count -eq 0) {
		Write-LogMessage -type Info -MSG 'No servers selected. Exiting.'
		Invoke-Logoff
		return
	}
}

Write-LogMessage -type Verbose -MSG 'Processing Lists'
Write-LogMessage -type info -MSG "$($targetComponents.count) components selected for processing" -Footer -Header

$credCommands = $Script:CredCommands
$logonHeader = $Script:LogonHeader
$fn_WriteLogMessage = ${function:Write-LogMessage}
$fn_JoinExceptionMessage = ${function:Join-ExceptionMessage}
$fn_TestCommandExists = ${function:Test-CommandExists}
$fn_InvokeRest = ${function:Invoke-Rest}
$fn_SetUserPassword = ${function:Set-UserPassword}
$fn_ResetCredentials = ${function:Reset-Credentials}
$fn_ResetWinComponent = ${function:Reset-WinComponent}
$fn_GetComponentInfo = ${function:Get-ComponentInfo}
$fn_TestTargetWinRM = ${function:Test-TargetWinRM}
$fn_NewPSLogon = ${function:New-PSLogon}
Get-Job | Remove-Job -Force
$FailureList = @()
foreach ($target in $targetComponents | Sort-Object $comp.'Component Type') {
	if (!$jobs) {
		Write-LogMessage -type Info "Starting work on component user `"$($target.'Component User')`" with the component type of `"$($target.'Component Type')`" at the IP Address of `"$($target.'IP Address')`""
		Write-LogMessage -type Verbose "Attempting to get FQDN of IP Address `"$($target.'IP Address')`""
		$failed = $false
		$fqdn = (Resolve-DnsName $target.'IP Address' -ErrorAction SilentlyContinue).namehost
		If ([string]::IsNullOrEmpty($fqdn)) {
			Write-LogMessage -type Warning "Unable to get FQDN of IP Address `"$($target.'IP Address')`". Using IP address for WinRM Connection."
			$fqdn = $target.'IP Address'
		}
		Else {
			Write-LogMessage -type Info "Found FQDN of `"$fqdn`" for IP Address `"$($target.'IP Address')`". Using FQDN for WinRM Connection."
		}
		if ((![string]::IsNullOrEmpty($oldDomain)) -and (![string]::IsNullOrEmpty($newDomain)) ) {
			$fqdn = $fqdn.replace($oldDomain, $newDomain)
		}
		Try {
			# If -RemoteCredential is provided, warn when the target server is not in TrustedHosts
			if ($null -ne $RemoteCredential -and $null -ne $script:preFlight_TrustedHosts -and $script:preFlight_TrustedHosts -ne '*') {
				$isCovered = ($script:preFlight_TrustedHosts.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ieq $fqdn }).Count -gt 0
				if (!$isCovered) {
					Write-LogMessage -type Warning -MSG "$fqdn is not in WSMan:\localhost\Client\TrustedHosts. WinRM with explicit credentials may fail. Remediation: Set-Item WSMan:\localhost\Client\TrustedHosts -Value '$fqdn' -Force"
				}
			}
			If ('Windows' -eq $target.os) {
				If (!(Test-TargetWinRM -server $fqdn -Credential $RemoteCredential)) {
					Write-LogMessage -type Error -MSG "WinRM connection failed for $fqdn. Run: .\Test-RemoteConnectivity.ps1 -ComputerName '$fqdn' to diagnose."
					$failed = $true
				}
			}
			elseif ('Linux' -eq $target.os) {
				Write-LogMessage -type Error -MSG "Unable to reset credentials on linux based servers at this time. Manual reset required for Component User $($target.'Component User') on $fqdn" -Footer
				$failed = $true
			}

			if ($failed) {
				$FailureList += $target
				Write-LogMessage -type Error -MSG "Manual reset required for component user `"$($target.'Component User')`" with the component type of `"$($target.'Component Type')`" with address of `"$fqdn`"." -Footer

			}
			else {
				Reset-Credentials -ComponentType $target.'Component Type' -Server $fqdn -OS $target.os -vault $vaultAddress -apiAddress $apiAddress -tries $tries -Credential $RemoteCredential
			}
		}
		Catch {
			$FailureList += $target
		}
	}
	else {
		$user = $target.'Component User'
		$type = $target.'Component Type'
		$os = $target.os
		$ipAddress = $target.'IP Address'
		Write-LogMessage -type Info -MSG "Submitting job for component user `"$($target.'Component User')`" with the component type of `"$($target.'Component Type')`" at the IP Address of `"$($target.'IP Address')`""
		Start-Job -Name "$($type.Replace('AAM Credential Provider','CP')) at $ipAddress" -ScriptBlock {
			Try {
				$Script:PVWAURL = $using:PVWAURL
				$Script:LogonHeader = $using:logonHeader
				$Script:LOG_FILE_PATH = $using:LOG_FILE_PATH
				$Script:RemoteCredential = $using:RemoteCredential
				$Script:CredCommands = $using:credCommands

				. "$using:ScriptLocation\Reset-ComponentCredential.ps1"

				${function:Write-LogMessage} = $using:fn_WriteLogMessage
				${function:Join-ExceptionMessage} = $using:fn_JoinExceptionMessage
				${function:Test-CommandExists} = $using:fn_TestCommandExists
				${function:Invoke-Rest} = $using:fn_InvokeRest
				${function:Set-UserPassword} = $using:fn_SetUserPassword
				${function:Reset-Credentials} = $using:fn_ResetCredentials
				${function:Reset-WinComponent} = $using:fn_ResetWinComponent
				${function:Get-ComponentInfo} = $using:fn_GetComponentInfo
				${function:Test-TargetWinRM} = $using:fn_TestTargetWinRM
				${function:New-PSLogon} = $using:fn_NewPSLogon
				$fqdn = (Resolve-DnsName $using:target.'IP Address' -ErrorAction SilentlyContinue).namehost
				If ([string]::IsNullOrEmpty($fqdn)) {
					$fqdn = $using:target.'IP Address'
				}
				if ((![string]::IsNullOrEmpty($using:oldDomain)) -and (![string]::IsNullOrEmpty($using:newDomain)) ) {
					$fqdn = $fqdn.replace($using:oldDomain, $using:newDomain)
				}
				If ('Windows' -eq $using:target.os) {
					If (!(Test-TargetWinRM -server $fqdn -Credential $using:RemoteCredential)) {
						Write-LogMessage -Type Error -MSG "Error connecting to WinRM for Component User $($using:target.'Component User') on $fqdn" -Footer
						Throw 'the job has failed'
					}
				}
				elseif ('Linux' -eq $using:target.os) {
					Write-LogMessage -type Error -MSG "Unable to reset credentials on linux based servers at this time. Manual reset required for Component User $($using:target.'Component User') on $fqdn" -Footer
					Throw 'the job has failed'
				}
				Reset-Credentials -ComponentType $using:type -Server $fqdn -os $using:os -vault $using:vaultAddress -apiAddress $using:apiAddress -tries $using:tries -Credential $using:RemoteCredential
			}
			Catch {
				Write-LogMessage -Type Error -MSG "Error in job for $using:Type on $fqdn" -Footer
				Throw  "Error in job for $using:Type on $fqdn"
			}
		} -InitializationScript { Set-Location $PSScriptRoot; } | Out-Null
		$jobsRunning = $true
	}
}

IF ($jobs) {
	Write-LogMessage -type info -MSG "$($targetComponents.count) jobs submitted for processing" -Footer -Header
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
			$Activity = "$($running.count) job is still running"
		}
		elseif ($running.Count -gt 1 -and $failed.Count -eq 0) {
			$Activity = "$($running.count) jobs are still running"
		}
		elseif ($failed.count -eq 1) {
			$Activity = "$($failed.count) job is in a failed state and $($running.count) job(s) are still running. Review logs once completed"
		}
		elseif ($failed.count -gt 1) {
			$Activity = "$($failed.count) jobs are in a failed state and $($running.count) job(s) are still running. Review logs once completed"
		}
		If ($jobsRunning) {
			Write-Progress -Id 1 -Activity $Activity -CurrentOperation "$($running.Name)"
		}
	}
	Write-Progress -Id 1 -Activity $Activity -CurrentOperation "$($running.Name)" -Completed

	Write-LogMessage -type Info -MSG 'All Jobs Completed' -Header -Footer
	$errorJobs = Get-Job -State Failed
	If (![string]::IsNullOrEmpty($errorJobs)) {
		Foreach ($job in $errorJobs) {
			Write-LogMessage -type Error "Log started for $($job.name)" -Header
			$child = $job.childjobs.information
			ForEach ($line in $child) {
				Write-LogMessage -type Error $line
			}
			Write-LogMessage -type Error -MSG "Log ended for $($job.name)" -Footer
		}
	}
}
Else {
	If (![string]::IsNullOrEmpty($FailureList)) {
		Write-Host "Error on the following $($FailureList.count) components" -ForegroundColor Red
		$FailureList | Select-Object -Property 'IP Address', 'Component Type', 'Component User' | Sort-Object 'IP Address', 'Component Type', 'Component User' | Format-Table -AutoSize
	}
}

#region [Logoff]
# Logoff the session
# ------------------
Write-Host 'Logoff Session...'

Invoke-Logoff

Remove-Variable -Name LOG_FILE_PATH -Scope Script -Force -ErrorAction SilentlyContinue
Remove-Variable -Name AuthType -Scope Script -Force -ErrorAction SilentlyContinue
#endregion

$VerbosePreference = $oldverbose
