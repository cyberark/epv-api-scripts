<#
Synopsis
	Resets component user passwords via PVWA REST API.
Description
	Resets component user passwords via PVWA REST API. Can be used to reset all component
passwords to a random value, or can be used to target specific components and set a specified password.
	When targeting specific components, the script will attempt to match the component user to the component type (for example, CPMApp* users will be matched to CPM components) to ensure the correct password is reset when multiple components are running on the same server. This can be overridden by providing a mapping file with component user to component type mappings.
	When run without the -AllComponentTypes or -ComponentType parameters, the script will display a list of components to select from. After selecting the components, if there are multiple servers running that component, it will display a list of servers to select from. This allows for targeting specific servers if needed.
	When targeting specific components, the script will attempt to match the component user to the component type (for example, CPMApp* users will be matched to CPM components) to ensure the correct password is reset when multiple components are running on the same server. This can be overridden by providing a mapping file with component user to component type mappings.
Parameters
	-PVWAURL <string>
		The URL for PVWA (for example: https://pvwa.mydomain.com/PasswordVault)
	-AllComponentTypes
		Select all component types
	-AllServers
		Select all servers
	-DisconnectedOnly
		Select only disconnected servers
	-ConnectedOnly
		Select only connected servers
	-ComponentType <string>
		Select a specific component type. Valid values are: CPM, PSM, PVWA, CP, AAM Credential Provider, PSM/PSMP
	-ComponentUsers <string>
		Select specific component users (comma-separated for multiple)
	-ComponentUserFilter <string>
		Select component users via filter (for example, PSMApp* to select all PSM component users)
	-MapFile <string>
		CSV file with ComponentUser to ComponentType mappings to ensure correct component is targeted when multiple components are running on the same server. The CSV file should have the following columns: ComponentUser, ComponentType, IP Address, OS. Only ComponentUser is required, the other columns are used to override the values returned by the API if needed.
Examples
	# Reset all component passwords to a random value
	PS> .\Invoke-ComponentPasswordReset.ps1 -PVWAURL https://pvwa.mydomain.com/PasswordVault -LogonToken $token -AllComponentTypes -AllServers
	# Reset only CPM component passwords to a random value
	PS> .\Invoke-ComponentPasswordReset.ps1 -PVWAURL https://pvwa.mydomain.com/PasswordVault -LogonToken $token -ComponentType CPM -AllServers
	# Reset only disconnected CPM component passwords to a random value
	PS> .\Invoke-ComponentPasswordReset.ps1 -PVWAURL https://pvwa.mydomain.com/PasswordVault -LogonToken $token -ComponentType CPM -DisconnectedOnly
	# Reset only connected CPM component passwords to a random value
	PS> .\Invoke-ComponentPasswordReset.ps1 -PVWAURL https://pvwa.mydomain.com/PasswordVault -LogonToken $token -ComponentType CPM -ConnectedOnly
	# Reset specific component user passwords to a random value
	PS> .\Invoke-ComponentPasswordReset.ps1 -PVWAURL https://pvwa.mydomain.com/PasswordVault -LogonToken $token -ComponentType CPM -ComponentUsers CPMApp1,CPMApp2
	# Reset component user passwords that match a filter to a random value
	PS> .\Invoke-ComponentPasswordReset.ps1 -PVWAURL https://pvwa.mydomain.com/PasswordVault -LogonToken $token -ComponentType PSM -ComponentUserFilter PSMApp*
	# Reset component user passwords using a mapping file to ensure correct components are targeted when multiple components are running on the same server
	PS> .\Invoke-ComponentPasswordReset.ps1 -PVWAURL https://pvwa.mydomain.com/PasswordVault -LogonToken $token -MapFile .\ComponentUserMapping.csv

#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = 'Please enter your PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)')]
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


    [Parameter(Mandatory = $false)]
    [Switch]$AllComponentTypes,

    [Parameter(Mandatory = $false)]
    [Switch]$AllServers,

    [Parameter(Mandatory = $false)]
    [Switch]$DisconnectedOnly,

    [Parameter(Mandatory = $false)]
    [Switch]$ConnectedOnly,

    [Parameter(Mandatory = $false, HelpMessage = 'Target Component')]
    [ValidateSet('CPM', 'PSM', 'PVWA', 'CP', 'AAM Credential Provider', 'PSM/PSMP')]
    [String]$ComponentType,

    [Parameter(Mandatory = $false, HelpMessage = 'Target Component Users (comma delimited for multiple users)')]
    [String]$ComponentUsers,

    [Parameter(Mandatory = $false, HelpMessage = 'Target Component Users via filter')]
    [String]$ComponentUserFilter,

    [Parameter(Mandatory = $false, HelpMessage = 'Mapping File')]
    [String]$MapFile,

    [Parameter(Mandatory = $false, HelpMessage = 'The password you want to set for the component users. If not specified, a random password will be generated, we will show you the password at the end')]
    [securestring]$password
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
New-Variable -Name LOG_FILE_PATH -Value "$ScriptLocation\Invoke-ComponentUserPasswordReset.log" -Scope Script -Force
$Script:PVWAURL = $PVWAURL
#endregion

#region Script Variables

# $Script:CredCommands, $Script:CpmServices, $Script:PvwaServices, $Script:PsmServices,
# and $Script:AamServices are defined in Reset-WinComponentCredential.ps1 (loaded below via dot-source).

$Script:PrePSSession = { $env:PSModulePath = 'C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules;' }
#endregion

#region URL Variables
$URL_PVWAAPI = $Script:PVWAURL + '/api'
$URL_Authentication = $URL_PVWAAPI + '/auth'
$URL_Logon = $URL_Authentication + "/$Script:AuthType/Logon"
$URL_Logoff = $URL_Authentication + '/Logoff'

$URL_UserSearch = $URL_PVWAAPI + '/Users?filter=componentUser&search={0}'
$URL_UserResetPassword = $URL_PVWAAPI + '/Users/{0}/ResetPassword'
$URL_Activate = $URL_PVWAAPI + '/Users/{0}/Activate'

$URL_HealthSummery = $URL_PVWAAPI + '/ComponentsMonitoringSummary'
$URL_HealthDetails = $URL_PVWAAPI + '/ComponentsMonitoringDetails/{0}'
#endregion

#region Functions

. "$PSScriptRoot\Reset-WinComponentCredential.ps1"

#region Functions
function Invoke-Rest {
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
        [ValidateSet('GET', 'POST', 'DELETE', 'PATCH')]
        [String]$Command,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$URI,
        [Parameter(Mandatory = $false)]
        $Header,
        [Parameter(Mandatory = $false)]
        [String]$Body,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Continue', 'Ignore', 'Inquire', 'SilentlyContinue', 'Stop', 'Suspend')]
        [String]$ErrAction = 'Continue'
    )

    $restResponse = ''
    try {
        if ([string]::IsNullOrEmpty($Body)) {
            Write-LogMessage -type Verbose -MSG "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -TimeoutSec 2700"
            $restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType 'application/json' -TimeoutSec 2700 -ErrorAction $ErrAction
        } else {
            Write-LogMessage -type Verbose -MSG "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body -TimeoutSec 2700"
            $restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType 'application/json' -Body $Body -TimeoutSec 2700 -ErrorAction $ErrAction
        }
    } catch [System.Net.WebException] {
        if ($ErrAction -match ('\bContinue\b|\bInquire\b|\bStop\b|\bSuspend\b')) {
            Write-LogMessage -type Error -MSG "Error Message: $_"
            Write-LogMessage -type Error -MSG "Exception Message: $($_.Exception.Message)"
            Write-LogMessage -type Error -MSG "Status Code: $($_.Exception.Response.StatusCode.value__)"
            Write-LogMessage -type Error -MSG "Status Description: $($_.Exception.Response.StatusDescription)"
        }
        $restResponse = $null
    } catch {
        throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $_.Exception))
    }
    Write-LogMessage -type Verbose -MSG "Invoke-REST Response: $restResponse"
    return $restResponse
}

function Invoke-Logoff {
    $null = Invoke-Rest -Uri $URL_Logoff -Header $Script:LogonHeader -Command 'Post'
}

function Set-UserPassword {
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
    process {
        Write-LogMessage -type Verbose -MSG "URL for PVWA: $PVWAURL"
        Write-LogMessage -type Verbose -MSG "URL for PVWA API: $URL_PVWAAPI"
        $urlSearch = $Script:URL_UserSearch -f $Username
        Write-LogMessage -type Verbose -MSG "URL for user search: $urlSearch"
        $searchResult = $(Invoke-Rest -Uri $urlSearch -Header $Script:LogonHeader -Command 'Get')
        if ($searchResult.Total -gt 0) {
            $userFound = $false
            foreach ($account in $searchResult.users) {
                if ($account.username -ieq $Username -and $account.componentUser) {
                    try {
                        $userFound = $true
                        $accountID = $account.id

                        $bodyActivate = @{id = $accountID } | ConvertTo-Json -Depth 3 -Compress
                        $urlActivate = $Script:URL_Activate -f $accountID
                        $null = Invoke-Rest -Uri $urlActivate -Header $Script:LogonHeader -Command 'Post' -Body $bodyActivate

                        $bodyReset = @{ id = $accountID; newPassword = $(Convert-SecureString($Password)) } | ConvertTo-Json -Depth 3 -Compress
                        $urlReset = $Script:URL_UserResetPassword -f $accountID
                        $null = Invoke-Rest -Uri $urlReset -Header $Script:LogonHeader -Command 'Post' -Body $bodyReset
                    } catch {
                        throw $_
                    }
                }
            }
            if (!$userFound) {
                Write-LogMessage -type Verbose -MSG "Unable to locate component account for $Username"
            }
        } else {
            Write-LogMessage -type Verbose -MSG "Unable to locate component account for $Username"
        }
    }
}
function Get-ComponentStatus {
    try {
        $restResponse = $(Invoke-Rest -Uri $URL_HealthSummery -Header $Script:LogonHeader -Command 'Get')
        $selection = $restResponse.Components | Where-Object { $_.ComponentTotalCount -gt 0 } | Select-Object @{Name = 'Component Type'; Expression = { $_.'ComponentName' } }, @{Name = 'Amount Connected'; Expression = { $_.'ConnectedComponentCount' } }, @{Name = 'Total Amount'; Expression = { $_.'ComponentTotalCount' } } | Sort-Object -Property 'Component Type'
        return $selection
    } catch {
        return $null
    }
}

function Get-ComponentDetails {
    param (
        [Parameter(Mandatory = $true)]
        $component
    )

    switch ($component) {
        'PSM/PSMP' {
            $targetComp = 'SessionManagement'; break
        }
        'Secrets Manager Credential Providers' {
            $targetComp = 'AIM'; break
        }
        'AAM Credential Provider' {
            $targetComp = 'AIM'; break
        }
        default {
            $targetComp = $component
        }
    }
    $URLHealthDetails = $URL_HealthDetails -f $targetComp
    try {
        $restResponse = $(Invoke-Rest -Uri $URLHealthDetails -Header $Script:LogonHeader -Command 'Get')
        $selection = $restResponse.ComponentsDetails | Select-Object @{Name = 'Component Type'; Expression = { $component } }, @{Name = 'Component Version'; Expression = { $_.ComponentVersion } }, @{Name = 'IP Address'; Expression = { $_.'ComponentIP' } }, @{Name = 'Component User'; Expression = { $_.'ComponentUserName' } }, @{Name = 'Connected'; Expression = { $_.'IsLoggedOn' } } | Sort-Object -Property 'IP Address'
        return $selection
    } catch {
        return $null
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
    # In Remote SSH sessions, Out-GridView hangs instead of throwing  -  detect and skip it
    $isRemoteSession = ($null -ne $env:SSH_CLIENT -or $null -ne $env:SSH_TTY -or -not [System.Environment]::UserInteractive)
    if (-not $isRemoteSession) {
        try {
            return $Items | Out-GridView -OutputMode Multiple -Title $Title -ErrorAction Stop
        } catch {
            # GUI unavailable (HostException, InvalidOperationException, etc.)  -  fall through to console menu
            Write-Verbose "Out-GridView unavailable ($($_.Exception.GetType().Name)). Falling back to console menu."
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
    if ($raw.Trim() -eq '0') {
        return @()
    }
    if ($raw.Trim() -eq '*') {
        return $Items
    }
    $selected = $raw.Split(',') | ForEach-Object {
        $index = [int]$_.Trim() - 1
        if ($index -ge 0 -and $index -lt $Items.Count) {
            $Items[$index]
        }
    }
    return $selected
}

function Get-LogonHeader {
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
    if (![string]::IsNullOrEmpty($RadiusOTP)) {
        $logonBodyHash.password += ",$RadiusOTP"
    }
    $logonBody = $logonBodyHash | ConvertTo-Json -Compress
    try {
        # Logon
        $logonToken = Invoke-Rest -Command Post -Uri $URL_Logon -Body $logonBody
        # Clear logon body
        $logonBody = ''
    } catch {
        throw $(New-Object System.Exception ("Get-LogonHeader: $($_.Exception.Response.StatusDescription)", $_.Exception))
    }
    $logonHeader = $null
    if ([string]::IsNullOrEmpty($logonToken)) {
        throw 'Get-LogonHeader: Logon Token is Empty - Cannot login'
    }

    # Create a Logon Token Header (This will be used through out all the script)
    # ---------------------------
    $logonHeader = @{Authorization = $logonToken }
    return $logonHeader
}
#endregion
#region Pre-flight Checks
Write-LogMessage -type Info -MSG "Running pre-flight checks (script v$ScriptVersion)" -Header

# Check that the PVWA URL is OK
if (![string]::IsNullOrEmpty($PVWAURL)) {
    if ($PVWAURL.Substring($PVWAURL.Length - 1) -eq '/') {
        $PVWAURL = $PVWAURL.Substring(0, $PVWAURL.Length - 1)
    }
    try {
        # Validate PVWA URL is OK
        Write-LogMessage -type Debug -MSG "Trying to validate URL: $PVWAURL"
        Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $PVWAURL -Method 'Head' -TimeoutSec 30 | Out-Null
    } catch [System.Net.WebException] {
        if (![string]::IsNullOrEmpty($_.Exception.Response.StatusCode.Value__)) {
            Write-LogMessage -type Error -MSG "Received error $($_.Exception.Response.StatusCode.Value__) when trying to validate PVWA URL"
            Write-LogMessage -type Error -MSG 'Check your connection to PVWA and the PVWA URL'
            return
        }
    } catch {
        Write-LogMessage -type Error -MSG 'PVWA URL could not be validated'
        Write-LogMessage -type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction 'SilentlyContinue'
    }
} else {
    Write-LogMessage -type Error -MSG 'PVWA URL can not be empty'
    return
}

Write-LogMessage -type Verbose -MSG 'Getting Logon Token'

#region [Logon]
# Get Credentials to Login
# ------------------------
$caption = 'Reset Credential Files Remotely'
if (![string]::IsNullOrEmpty($logonToken)) {
    if ($logonToken.GetType().name -eq 'String') {
        $Script:LogonHeader = @{Authorization = $logonToken }
    } else {
        $Script:LogonHeader = $logonToken
    }
} else {
    if (![string]::IsNullOrEmpty($PVWACredentials)) {
        $creds = $PVWACredentials
    } else {
        $msg = "Enter your $AuthType User name and Password"
        $creds = $Host.UI.PromptForCredential($caption, $msg, '', '')
    }
    if ($AuthType -eq 'radius' -and ![string]::IsNullOrEmpty($OTP)) {
        $Script:LogonHeader = Get-LogonHeader -Credentials $creds -concurrentSession $true -RadiusOTP $OTP
    } else {
        $Script:LogonHeader = Get-LogonHeader -Credentials $creds -concurrentSession $true
    }
    # Verify that we successfully logged on
    if ($null -eq $Script:LogonHeader) {
        return # No logon header, end script
    }
}
#endregion
#region Getting Component List
Write-LogMessage -type Verbose -MSG 'Getting Server List'
$componentList = Get-ComponentStatus | Sort-Object $_.'Component Type'
if ($AllComponentTypes) {
    $selectedComponents = $componentList
} elseif (![string]::IsNullOrEmpty($ComponentType)) {
    $cpSearch = ('CP').ToLower()
    $ComponentType = ($ComponentType.ToLower()) -replace "\b$cpSearch\b", 'AAM Credential Provider'
    $PSMSearch = ('PSM').ToLower()
    $ComponentType = $ComponentType.ToLower() -replace "\b$PSMSearch\b", 'PSM/PSMP'

    $selectedComponents = $componentList | Where-Object 'Component Type' -EQ $ComponentType
} else {
    $selectedComponents = Invoke-SelectionMenu -Items @($componentList | Sort-Object $_.'Component Type') -Title 'Select Component(s)' -DisplayProperties 'Component Type', 'Amount Connected', 'Total Amount'
    if ($selectedComponents.Count -eq 0) {
        Write-LogMessage -type Info -MSG 'No components selected. Exiting.'
        Invoke-Logoff
        return
    }
}
if (![string]::IsNullOrEmpty($mapfile)) {
    $map = Import-Csv $mapfile
}

Write-LogMessage -type Verbose -MSG 'Getting Component List'
$targetComponents = @()
$availableServers = @()

# Resolve ALL IPv4 addresses for the PVWA host once.
# A PVWA with multiple NICs may register components under different IPs, so we collect
# the full set here and compare each component IP against all of them.
$pvwaHost = ([System.Uri]$PVWAURL).Host.ToLower()
$pvwaIPs = try {
    [System.Net.Dns]::GetHostAddresses($pvwaHost) |
    Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
    ForEach-Object { $_.IPAddressToString }
} catch {
    @()
}

foreach ($comp in $selectedComponents) {
    if ($comp.'Total Amount' -gt 0) {
        if ($PVWAURL.Contains('privilegecloud') -and ('PVWA' -eq $comp.'Component Type')) {
            continue
        }
        $results = Get-ComponentDetails $comp.'Component Type'
        foreach ($result in $results) {
            $user = ($result.'Component User')
            switch ($user) {
                { 'PSMPApp' -eq $user.Substring(0, 7) } {
                    $result.'Component Type' = 'PSM'
                    Add-Member -InputObject $result -MemberType NoteProperty -Name 'OS' -Value 'Linux'
                    break
                }
                { 'PSMApp' -eq $user.Substring(0, 6) } {
                    $result.'Component Type' = 'PSM'
                    Add-Member -InputObject $result -MemberType NoteProperty -Name 'OS' -Value 'Windows'
                    break
                }
                default {
                    Add-Member -InputObject $result -MemberType NoteProperty -Name 'OS' -Value 'Windows'
                    break
                }
            }
            if ($null -ne $map) {
                $checkComponentUser = $map.Where({ $_.ComponentUser -eq $result.'Component User' })
                if (0 -ne $checkComponentUser.Count) {
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
            if ('255.255.255.255' -eq $result.'IP Address') {
                continue
            }
            # Skip components running on the same server as the PVWA we are connected to.
            # The PVWA only records the last IP a component connected from, which may not
            # be the component's only IP, so we apply two independent checks:
            #
            # Check 1 - IP match: compare the component's reported IP against all IPv4
            #   addresses that the PVWA hostname resolves to.  This handles the common
            #   case and also catches a multi-NIC PVWA where the component happened to
            #   connect via a different interface.
            #
            # Check 2 - FQDN match: reverse-resolve the component IP to its hostname and
            #   compare against the PVWA hostname.  This catches the case where the
            #   component registered under a different IP than the one in $PVWAURL but
            #   is still the same physical/virtual machine.
            $serverAddress = ($result.'IP Address').ToLower()
            $isSameMachine = $false

            # Check 1: IP address membership
            if ($pvwaIPs -contains $serverAddress) {
                $isSameMachine = $true
            }

            # Check 2: reverse DNS FQDN comparison (only if IP check did not already match)
            if (-not $isSameMachine) {
                $serverFQDN = try {
                    [System.Net.Dns]::GetHostEntry($serverAddress).HostName.ToLower()
                } catch {
                    $null
                }
                if ($null -ne $serverFQDN -and $serverFQDN -eq $pvwaHost) {
                    $isSameMachine = $true
                }
            }

            if ($isSameMachine) {
                Write-LogMessage -type Warning -MSG "Skipping component user $($result.'Component User') on $($result.'IP Address') - it is running on the PVWA this script is connected to. Resetting its password without updating the credential file would break the component."
                continue
            }
            $availableServers += $result
        }
    } else {
        Write-LogMessage -type Error -MSG "No $($comp.'Component Type') Components Found"
    }
}

if ($DisconnectedOnly) {
    $targetComponents += $availableServers | Where-Object Connected -EQ $false
} elseif ($ConnectedOnly) {
    $targetComponents += $availableServers | Where-Object Connected -EQ $true
} elseif ($allServers) {
    $targetComponents += $availableServers
} elseif (![string]::IsNullOrEmpty($ComponentUsers)) {
    $ComponentUsersArr = $ComponentUsers.Split(',')
    foreach ($user in $ComponentUsersArr) {
        $targetComponents += $availableServers | Where-Object 'Component User' -EQ $user
    }
} elseif (![string]::IsNullOrEmpty($ComponentUserFilter)) {
    $targetComponents += $availableServers | Where-Object 'Component User' -Like $ComponentUserFilter
} else {
    $targetComponents += Invoke-SelectionMenu -Items @($availableServers | Sort-Object -Property 'Component Type', 'IP Address') -Title 'Select Server(s)' -DisplayProperties 'Component Type', 'IP Address', 'Component User'
    if ($targetComponents.Count -eq 0) {
        Write-LogMessage -type Info -MSG 'No servers selected. Exiting.'
        Invoke-Logoff
        return
    }
}
#endregion
#Region Resetting Passwords
#Get a random password to change user passwords to
if ($null -eq $password) {
    $randomPassword = $true
    $rawPass = New-RandomPassword -Length 20 -Lowercase -Uppercase -Numbers -Symbols
    $password = ConvertTo-SecureString -String $rawPass -AsPlainText -Force
}
#reseting passwords for selected components
Write-LogMessage -type Verbose -MSG 'Resetting passwords for selected components'
foreach ($target in $targetComponents) {
    Write-LogMessage -type Verbose -MSG "Resetting password for $($target.'Component User')"
    try {
        Set-UserPassword -Username $target.'Component User' -Password $password
        Write-LogMessage -type Info -MSG "Password reset successfully for $($target.'Component User')"
    } catch {
        Write-LogMessage -type Error -MSG "Failed to reset password for $($target.'Component User')"
        Write-LogMessage -type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction 'SilentlyContinue'
    }
}
#If we generated a random password, show it to the user at the end
if ($randomPassword) {
    Write-Host "New Password: $rawPass" -ForegroundColor Green
}
#endregion

#region [Logoff]
# Logoff the session
# ------------------
Write-Host 'Logoff Session...'

Invoke-Logoff

Remove-Variable -Name LOG_FILE_PATH -Scope Script -Force -ErrorAction SilentlyContinue
#endregion

$VerbosePreference = $oldverbose
