#Requires -Version 5.1
<#
.SYNOPSIS
 This script will update the connector server to a domain user setup. It will also onboard the domain users into the portal inside the PSM safe.
.DESCRIPTION
 Configures PSM to use domain-based PSMConnect and PSMAdminConnect users instead of the default local users.
.PARAMETER PVWAUrl
 The PVWA Address. Provide the full application base URL including any virtual directory (e.g. https://pvwa.lab.local, https://pvwa.lab.local/PasswordVault, or https://pvwa.lab.local/OurVault).
.PARAMETER VaultAddress
 The Vault IP address (e.g. 192.168.1.10)
.PARAMETER DomainDNSName
 The fully qualified domain name of the domain user account(s).
.PARAMETER DomainNetbiosName
 The NETBIOS name for the domain user account(s).
.PARAMETER Safe
 The safe in which to store PSM user credentials
.PARAMETER VaultAdmin
 CyberArk vault administrator credentials
.PARAMETER PSMConnectCredentials
 PSMConnect domain user credentials
.PARAMETER PSMAdminConnectCredentials
 PSMAdminConnect domain user credentials
.PARAMETER IgnoreShadowPermissionErrors
 Ignore errors while granting PSMAdminConnect user shadow permissions
.PARAMETER PlatformName
 The name of the platform to be created for the PSM accounts
.PARAMETER PSMConnectAccountName
 The Account Name for the object in the vault which will contain the PSMConnect account. Defaults to "PSMConnect".
.PARAMETER PSMAdminConnectAccountName
 The Account Name for the object in the vault which will contain the PSMAdminConnect account. Defaults to "PSMAdminConnect".
.PARAMETER DoNotHarden
 Skip running the PSMHardening.ps1 script to speed up execution if step has already been completed.
.PARAMETER DoNotConfigureAppLocker
 Skip running the PSMConfigureAppLocker.ps1 script to speed up execution if step has already been completed.
.PARAMETER LocalConfigurationOnly
 Do not onboard accounts in the vault. Use on subsequent servers after first run.
.PARAMETER SkipPSMUserTests
 Do not check the configuration of the PSM domain users for errors
.PARAMETER SkipPSMObjectUpdate
 Do not update the PSM server object in backend
.PARAMETER SkipSecurityPolicyConfiguration
 Do not update Local Security Policy to allow PSM users to log on with Remote Desktop
.PARAMETER SkipAddingUsersToRduGroup
 Do not add PSM users to the Remote Desktop Users group
.VERSION 14.4
.AUTHOR CyberArk
#>

[CmdletBinding()]
param(
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Do not onboard accounts in the vault. Use on subsequent servers after first run.')]
    [switch]$LocalConfigurationOnly,

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Please enter the vault administrator credentials.')]
    [PSCredential]$VaultAdmin,

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Authentication type for PVWA logon (CyberArk, LDAP, Windows, RADIUS).')]
    [ValidateSet('CyberArk', 'LDAP', 'Windows', 'RADIUS')]
    [string]$AuthenticationType = 'CyberArk',

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Please enter the account credentials for the PSMConnect domain account.')]
    [PSCredential]$PSMConnectCredentials,

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Please enter the account credentials for the PSMAdminConnect domain account.')]
    [PSCredential]$PSMAdminConnectCredentials,

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Please enter the domain of the created accounts IE: lab.net')]
    [Alias('domain')]
    [string]$DomainDNSName,

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Please enter the NETBIOS of the created accounts IE: LAB')]
    [Alias('NETBIOS')]
    [string]$DomainNetbiosName,

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Do not test PSM user configurations')]
    [switch]$SkipPSMUserTests,

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Ignore errors while granting PSMAdminConnect user shadow permissions')]
    [switch]$IgnoreShadowPermissionErrors,

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Please enter the PVWA Address including any virtual directory (e.g. https://pvwa.company.com, https://pvwa.company.com/PasswordVault, or https://pvwa.company.com/OurVault)')]
    [Alias('pvwaAddress', 'PrivilegeCloudUrl')]
    [string]$PVWAUrl,

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Please enter the Vault IP address (e.g. 192.168.1.10)')]
    [string]$VaultAddress,

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Please enter the Safe to save the domain accounts in, By default it is PSM')]
    [String]$Safe = 'PSM',

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Name of Platform to be used for PSM accounts')]
    [String]$PlatformName = 'WIN-DOM-PSMADMIN-ACCOUNT',

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Account name in CyberArk of the PSMConnect user')]
    [String]$PSMConnectAccountName = 'PSMConnect',

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Account name in CyberArk of the PSMAdminConnect user')]
    [String]$PSMAdminConnectAccountName = 'PSMAdminConnect',

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Do not run Hardening script after configuration')]
    [switch]$DoNotHarden,

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Do not run AppLocker script after configuration')]
    [switch]$DoNotConfigureAppLocker,

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Do not update PSM Server Object configuration in backend')]
    [switch]$SkipPSMObjectUpdate,

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Do not update Local Security Policy to allow PSM users to log on with Remote Desktop')]
    [switch]$SkipSecurityPolicyConfiguration,

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Do not add PSM users to the Remote Desktop Users group')]
    [switch]$SkipAddingUsersToRduGroup,

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Do not restart PSM')]
    [switch]$NoPSMRestart,

    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Safe and platform configuration and account onboarding should be skipped as the script is being run on subsequent PSM servers.')]
    [switch]$NotFirstRun

)

<#
Script Order of Operations (search for a comment to find the relevant script section)
Function Definitions
Determine what operations need to be performed
Initialise variables
Perform initial checks
    Proxy configuration
    Check if domain user
    Get PVWA URL
    Identify AD domain
    Confirm VaultOperationsTester is present, and install VS redist
Validate detected AD domain details
Gather vault administrator credentials
If online, search backend for PSM user details and request credentials as required
    or, if offline
        Request user details if running in LocalConfigurationOnly mode
Test users
    Test PSM user credential format
    Test PSM user configuration
    Test PSM user credentials
List detected PSM user configuration errors
Perform Remote Configuration
    Create platform if required
    Create safe if required
    Onboard PSM users
    Configure PSMServer object
Group membership and security policy changes
Perform local configuration
    Backup files
    Update PSM configuration and scripts
    Adding PSMAdminConnect user to Terminal Services configuration
Post-configuration
    Invoke hardening scripts and restart service
    Display summary and additional tasks
#>

# Function Definitions
function Get-RestMethodError {
    <# Invoke-RestMethod can have several different possible results
    Connection failure: The connection error will be contained in $PSItem.Exception.Message
    Successful connection:
        200 result
            The request was successful: This function should not be called in this case
        Some other result
            JSON data returned: We should return the JSON, contained in $PSItem.ErrorDetails.Message
            non-JSON data returned: We should return the non-JSON data, contained in $PSItem.ErrorDetails.Message

    TODO: Convert other functions to use this function to return useful errors.
    This is lower priority as, if New-ConnectionToRestAPI and Test-PvwaToken succeed,
    others are unlikely to have issues.

    NOTE: This function should only be called if Invoke-RestMethod fails.
    Do not use it to catch errors from any other commands.
    #>
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    if ($ErrorRecord.ErrorDetails.Message) {
        # If the connection was successful but the server returned a non-200 result, Invoke-RestMethod will treat it as an error.
        # But if it's valid JSON, we'd rather know what the server said than what Invoke-RestMethod thought about it.
        try {
            return $ErrorRecord.ErrorDetails.Message | ConvertFrom-Json
        } catch {
            # Doesn't seem to have been valid JSON, so we'll construct our own object with the server's response (which is in the ErrorDetails property)
            return @{
                ErrorCode    = 'Unknown'
                ErrorMessage = $ErrorRecord.ErrorDetails.Message
            }
        }
    } else {
        # If there's no ErrorDetails.Message property, likely the connection failed entirely, so we'll return something based on the Exception.Message instead, which will be what Invoke-RestMethod thought.
        return @{
            ErrorCode    = 'Unknown'
            ErrorMessage = $ErrorRecord.Exception.Message
        }
    }
}

function Add-PsmConnectToMsLicensingKeys {
    param(
        [Parameter(Mandatory = $true)][PSCredential]$PSMConnectUser
    )
    $Paths = @(
        'HKLM:SOFTWARE\Wow6432Node\Microsoft\MSLicensing',
        'HKLM:SOFTWARE\Wow6432Node\Microsoft\MSLicensing'
    )
    $Paths | ForEach-Object {
        $FSPath = $PSItem
        if ($false -eq (Test-Path -PathType Container -Path $FSPath)) {
            $null = New-Item -ItemType Directory -Path $FSPath
        }
        $NewAcl = Get-Acl -Path $FSPath
        # Set properties
        $identity = $PSMConnectUser.UserName
        $RegistryRights = 'FullControl'
        $type = 'Allow'
        # Create new rule
        $RegistryAccessRuleArgumentList = $identity, $RegistryRights, $type
        $RegistryAccessRule = New-Object -TypeName System.Security.AccessControl.RegistryAccessRule -ArgumentList $RegistryAccessRuleArgumentList
        # Apply new rule
        $NewAcl.SetAccessRule($RegistryAccessRule)
        Set-Acl -Path $FSPath -AclObject $NewAcl
    }
}

function Stop-ScriptExecutionWithError {
    Write-LogMessage -type Error -MSG 'An error occurred and the script has stopped.'
    if ($false -eq $InVerbose) {
        Write-LogMessage -type Error -MSG 'If the reason for the error is not clear, please rerun the script with the -Verbose flag to get more information.'
    }
    exit 1
}

function Get-DifferencePosition {
    param(
        [Parameter(Mandatory = $true)][string]$String1,
        [Parameter(Mandatory = $true)][string]$String2
    )
    $DifferencePosition = $( # work out the position where the current value differs from the expected value by comparing them 1 character at a time ...
        $ExpectedValueLength = $String1.length
        $i = 0
        while ($i -le $ExpectedValueLength) {
            if ($String1[$i] -eq $String2[$i]) {
                $i++
            } else {
                $DifferencePosition = $i
                return $DifferencePosition
            }
        }
    )
}

function Write-LogMessage {
    <#
.SYNOPSIS
	Method to log a message on screen and in a log file

.DESCRIPTION
	Logging The input Message to the Screen and the Log File.
	The Message Type is presented in colours on the screen based on the type

.PARAMETER LogFile
	The Log File to write to. By default using the LOG_FILE_PATH
.PARAMETER MSG
	The message to log
.PARAMETER Header
	Adding a header line before the message
.PARAMETER SubHeader
	Adding a Sub header line before the message
.PARAMETER Footer
	Adding a footer line after the message
.PARAMETER Type
	The type of the message to log (Info, Warning, Error, Debug)
#>
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [Switch]$Header,
        [Parameter(Mandatory = $false)]
        [Switch]$Early,
        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory = $false)]
        [Switch]$Footer,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Debug', 'Verbose', 'Success', 'LogOnly')]
        [String]$type = 'Info',
        [Parameter(Mandatory = $false)]
        [String]$LogFile = $LOG_FILE_PATH
    )
    try {
        if ($Header) {
            '=======================================' | Out-File -Append -FilePath $LogFile
            Write-Host '=======================================' -ForegroundColor Magenta
        } elseif ($SubHeader) {
            '------------------------------------' | Out-File -Append -FilePath $LogFile
            Write-Host '------------------------------------' -ForegroundColor Magenta
        }

        $msgToWrite = "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')]`t"
        $writeToFile = $true
        # Replace empty message with 'N/A'
        if ([string]::IsNullOrEmpty($Msg)) {
            $Msg = 'N/A'
        }

        # Mask Passwords
        if ($Msg -match '((?:password|credentials|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()-_\=\+\\\/|;:\.,\[\]{}]+))') {
            $Msg = $Msg.Replace($Matches[2], '****')
        }
        # Check the message type
        switch ($type) {
            { ($PSItem -eq 'Info') -or ($PSItem -eq 'LogOnly') } {
                if ($PSItem -eq 'Info') {
                    Write-Host $MSG.ToString() -ForegroundColor $(if ($Header -or $SubHeader) {
                            'magenta'
                        } elseif ($Early) {
                            'DarkGray'
                        } else {
                            'White'
                        })
                }
                $msgToWrite += "[INFO]`t$Msg"
            }
            'Success' {
                Write-Host $MSG.ToString() -ForegroundColor Green
                $msgToWrite += "[SUCCESS]`t$Msg"
            }
            'Warning' {
                Write-Host $MSG.ToString() -ForegroundColor Yellow
                $msgToWrite += "[WARNING]`t$Msg"
            }
            'Error' {
                Write-Host $MSG.ToString() -ForegroundColor Red
                $msgToWrite += "[ERROR]`t$Msg"
            }
            'Debug' {
                if ($InDebug -or $InVerbose) {
                    Write-Debug $MSG
                    $msgToWrite += "[DEBUG]`t$Msg"
                } else {
                    $writeToFile = $False
                }
            }
            'Verbose' {
                if ($InVerbose) {
                    Write-Verbose -Message $MSG
                    $msgToWrite += "[VERBOSE]`t$Msg"
                } else {
                    $writeToFile = $False
                }
            }
        }

        if ($writeToFile) {
            $msgToWrite | Out-File -Append -FilePath $LogFile
        }
        if ($Footer) {
            '=======================================' | Out-File -Append -FilePath $LogFile
            Write-Host '=======================================' -ForegroundColor Magenta
        }
    } catch {
        throw $(New-Object System.Exception ('Cannot write message'), $PSItem.Exception)
    }
}

function Get-DomainDnsName {
    Write-LogMessage -Type Verbose -MSG 'Getting domain DNS name'
    if ($env:USERDNSDOMAIN) {
        Write-LogMessage -Type Verbose -MSG "Detected domain DNS name: $($env:USERDNSDOMAIN)"
        return $env:USERDNSDOMAIN
    } else {
        Write-LogMessage -Type Error -MSG 'Unable to determine domain DNS name. Please provide it on the command line with the -DomainDNSName parameter.'
        Stop-ScriptExecutionWithError
    }
}

function Get-DomainNetbiosName {
    Write-LogMessage -Type Verbose -MSG 'Getting domain NETBIOS name'
    if ($env:USERDOMAIN) {
        Write-LogMessage -Type Verbose -MSG "Detected domain NETBIOS name: $($env:USERDOMAIN)"
        return $env:USERDOMAIN
    } else {
        Write-LogMessage -Type Error -MSG 'Unable to determine domain NETBIOS name. Please provide it on the command line with the -DomainNetbiosName parameter.'
        Stop-ScriptExecutionWithError
    }
}

function Get-PvwaAddress {
    <#
    .SYNOPSIS
    Gets the PVWA address from the vault.ini file.
    .DESCRIPTION
    Reads the PSM vault.ini file and extracts the PVWA HTTPS address.
    .PARAMETER psmRootInstallLocation
    PSM root installation folder
    #>
    param (
        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation
    )
    Write-LogMessage -Type Verbose -MSG 'Getting PVWA address from vault.ini'
    try {
        $VaultIni = Get-Content "$psmRootInstallLocation\vault\vault.ini"
        $VaultIniAddressesLine = $VaultIni | Select-String '^Addresses'
        $null = $VaultIniAddressesLine -match '(https://[0-9a-zA-Z][\.\-0-9a-zA-Z]*)'
        $Address = $Matches[0]
        if (!($Address)) {
            throw
        }
        Write-LogMessage -Type Verbose -MSG "Detected PVWA URL from PSM vault.ini: $Address"
        return $Address
    } catch {
        Write-LogMessage -Type Error -MSG 'Unable to detect PVWA address automatically. Please rerun script and provide it using the -PVWAUrl parameter.'
        Stop-ScriptExecutionWithError
    }
}

function Get-CurrentSecurityPolicy {
    <#
    .SYNOPSIS
    Exports the current local security policy to a file.
    .DESCRIPTION
    Uses secedit.exe to export the current local security policy configuration.
    .PARAMETER OutFile
    The file path to export the security policy to.
    .PARAMETER LogFile
    The file path for secedit log output.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $OutFile,
        [Parameter(Mandatory = $true)]
        [string]
        $LogFile
    )

    $LogFileSplit = ($LogFile -split '\.')
    $LogFileLength = $LogFileSplit.Count
    $LogFileBase = ($LogFileSplit)[0..($LogFileLength - 2)]
    $StdOutLogFile = (($LogFileBase -join '.') + '.stdout.log')

    try {
        $SecEditExe = Get-Command secedit.exe
        $ExportArgs = @{
            Wait                   = $true
            FilePath               = $SecEditExe
            PassThru               = $true
            NoNewWindow            = $true
            RedirectStandardOutput = $StdOutLogFile
            ArgumentList           = @('/export', '/cfg', "`"$OutFile`"", '/log', "`"$LogFile`"")
        }
        $process = Start-Process @ExportArgs
        if ($process.ExitCode -eq 0) {
            return $True
        }
        return $False
    } catch {
        return $False
    }
}

function Set-CurrentSecurityPolicy {
    <#
    .SYNOPSIS
    Applies a security policy configuration file using secedit.
    .DESCRIPTION
    Uses secedit.exe to apply a security policy configuration from a file.
    .PARAMETER DatabaseFile
    The secedit database file path.
    .PARAMETER ConfigFile
    The security policy configuration file to apply.
    .PARAMETER LogFile
    The file path for secedit log output.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $DatabaseFile,
        [Parameter(Mandatory = $true)]
        [string]
        $ConfigFile,
        [Parameter(Mandatory = $true)]
        [string]
        $LogFile
    )

    $LogFileSplit = ($LogFile -split '\.')
    $LogFileLength = $LogFileSplit.Count
    $LogFileBase = ($LogFileSplit)[0..($LogFileLength - 2)]
    $StdOutLogFile = (($LogFileBase -join '.') + '.stdout.log')

    try {
        $SecEditExe = Get-Command secedit.exe
        $ConfigureArgs = @{
            Wait                   = $true
            FilePath               = $SecEditExe
            PassThru               = $true
            NoNewWindow            = $true
            RedirectStandardOutput = $StdOutLogFile
            ArgumentList           = @('/configure', '/db', "`"$DatabaseFile`"", '/cfg', "`"$ConfigFile`"", '/log', "`"$LogFile`"")
        }
        $process = Start-Process @ConfigureArgs
        if ($process.ExitCode -eq 0) {
            return $True
        }
        return $False
    } catch {
        return $False
    }
}

function Get-ProxyDetails {
    Write-LogMessage -type Verbose -MSG 'Detecting proxy from user profile'
    try {
        $ProxyStatus = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyEnable
        if ($ProxyStatus -eq 1) {
            $ProxyString = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyServer
            if ($ProxyString) {
                if ($ProxyString -match '^http://(.*)') {
                    Write-LogMessage -type Verbose -MSG "Detected proxy: $($Matches[1])"
                    return $Matches[1]
                } else {
                    Write-LogMessage -type Verbose -MSG "Detected proxy: $ProxyString"
                    return $ProxyString
                }
            } else {
                Write-LogMessage -type Verbose -MSG 'No proxy detected'
                return $false
            }
        } else {
            Write-LogMessage -type Verbose -MSG 'No proxy detected'
            return $false
        }
    } catch {
        Write-LogMessage -type Verbose -MSG 'Error detecting proxy. Proceeding with no proxy.'
        return $false
    }
}

function Get-VaultAddress {
    <#
    .SYNOPSIS
    Gets the vault address from the vault.ini file.
    .DESCRIPTION
    Reads the PSM vault.ini file and extracts the vault address from the ADDRESS setting.
    .PARAMETER psmRootInstallLocation
    PSM root installation folder
    #>
    param (
        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation
    )
    try {
        $VaultIni = Get-Content "$psmRootInstallLocation\vault\vault.ini"
        $VaultIniAddressesLine = $VaultIni | Select-String '^ADDRESS\s*='
        $VaultAddress = $VaultIniAddressesLine.toString().Split('=')[1].trim()
        Write-LogMessage -Type Verbose -MSG "Detected vault address: $VaultAddress"
        return $VaultAddress
    } catch {
        Write-LogMessage -Type Error -MSG 'Unable to detect vault address automatically. Please rerun script and provide it using the -VaultAddress parameter.'
        Stop-ScriptExecutionWithError
    }
}

function Test-UserCredential {
    <#
    .SYNOPSIS
    Tests whether the provided credentials are valid.
    .DESCRIPTION
    Returns a string result: 'Success', 'InvalidCredentials', or 'ErrorOccurred:<message>'.
    .EXAMPLE
    Test-UserCredential -domain $domain -Credential $credential
    #>
    param(
        [Parameter(Mandatory = $true)][string]$domain,
        [Parameter(Mandatory = $true)][PSCredential]$Credential
    )
    process {
        try {
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement
            $Directory = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $domain)
            if ($Directory.ValidateCredentials($Credential.UserName, $Credential.GetNetworkCredential().Password)) {
                return 'Success'
            } else {
                return 'InvalidCredentials'
            }
        } catch {
            if ($PSItem.Exception.Message -like '*The server cannot handle directory requests.*') {
                Write-LogMessage -type Info -MSG 'A bind error occurred validating credentials. Trying with other ContextOptions.'
            } else {
                return ('ErrorOccurred:' + $PSItem.Exception.Message)
            }
        }
        try {
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement
            $Directory = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $domain)
            if ($Directory.ValidateCredentials($Credential.UserName, $Credential.GetNetworkCredential().Password, 0)) {
                return 'Success'
            } else {
                return 'InvalidCredentials'
            }
        } catch {
            return ('ErrorOccurred:' + $PSItem.Exception.Message)
        }
    }
}

function Test-UserDomainJoined {
    <#
    .SYNOPSIS
    Checks if the current user is a domain user.
    .DESCRIPTION
    Verifies the current user principal context is Domain. Stops the script if not.
    .EXAMPLE
    Test-UserDomainJoined
    #>
    process {
        Write-LogMessage -Type Verbose -MSG 'Checking if user is a domain user'
        try {
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement
            $UserPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::Current
            if ($UserPrincipal.ContextType -eq 'Domain') {
                Write-LogMessage -Type Verbose -MSG 'User is a domain user'
                return
            }
        } catch {
            # fall through to error below
        }
        Write-LogMessage -Type Error -MSG 'Stopping. Please run this script as a domain user'
        Stop-ScriptExecutionWithError
    }
}

function New-ConnectionToRestAPI {
    <#
    .SYNOPSIS
    Authenticates to the PVWA REST API and returns a session token.
    .DESCRIPTION
    Authenticates using the specified authentication type and returns a session token on success.
    .PARAMETER pvwaAddress
    The PVWA server address (e.g. https://pvwa.company.com)
    .PARAMETER VaultAdmin
    Vault administrator credentials for PVWA authentication
    .PARAMETER AuthenticationType
    The authentication method to use: CyberArk, LDAP, Windows, or RADIUS. Defaults to CyberArk.
    #>
    param (
        [Parameter(Mandatory = $true)]
        $pvwaAddress,
        [Parameter(Mandatory = $true)]
        [PSCredential]$VaultAdmin,
        [Parameter(Mandatory = $false)]
        [ValidateSet('CyberArk', 'LDAP', 'Windows', 'RADIUS')]
        [string]$AuthenticationType = 'CyberArk'
    )
    $url = $pvwaAddress + ('/API/auth/{0}/Logon' -f $AuthenticationType)
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($VaultAdmin.Password)
    $headerPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $body = @{
        username = $VaultAdmin.UserName
        password = $headerPass
    }
    $json = $body | ConvertTo-Json
    try {
        $Result = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -ContentType 'application/json'
        return @{
            ErrorCode = 'Success'
            Response  = $Result
        }
    } catch {
        return Get-RestMethodError -ErrorRecord $PSItem
    } finally {
        if ($BSTR) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        }
        $headerPass = $null
    }
}

function Test-PvwaToken {
    <#
    .SYNOPSIS
    Test a PVWA token to ensure it is valid
    .DESCRIPTION
    The function receive the service name and return the path or returns NULL if not found
    .EXAMPLE
    Test-PvwaToken -Token $Token -PvwaAddress https://subdomain.pvwa.company.com
    .PARAMETER pvwaAddress
    The PVWA server address (e.g. https://subdomain.pvwa.company.com)
    .PARAMETER Token
    PVWA Token
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$pvwaAddress,
        [Parameter(Mandatory = $true)]
        [string]$Token
    )
    $url = $pvwaAddress + '/API/Accounts?limit=1'
    $Headers = @{
        Authorization = $Token
    }
    try {
        $testToken = Invoke-RestMethod -Method 'Get' -Uri $url -Headers $Headers -ContentType 'application/json'
        if ($testToken) {
            return @{
                ErrorCode = 'Success'
            }
        }
    } catch {
        return Get-RestMethodError -ErrorRecord $PSItem
    }
}

function Backup-PSMConfig {
    <#
    .SYNOPSIS
    Backs up PSMConfig ps1 scripts
    .DESCRIPTION
    Copies PSM config items to backup
    .PARAMETER psmRootInstallLocation
    PSM root installation folder
    .PARAMETER BackupPath
    Append this string to the end of backup file names
    #>
    param (
        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation,
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )
    try {
        if (!(Test-Path -Path $BackupPath -PathType Container)) {
            $null = New-Item -ItemType Directory -Path $BackupPath
        }
        $BasicPSMBackupFileName = ('{0}\basic_psm.ini' -f $BackupPath)

        Copy-Item -Path "$psmRootInstallLocation\basic_psm.ini" -Destination $BasicPSMBackupFileName

        if (!(Test-Path $BasicPSMBackupFileName)) {
            Write-LogMessage -Type Error -MSG 'Failed to backup basic_psm.ini' -ErrorAction Stop
        }
    } catch {
        Write-LogMessage -Type Error -MSG 'Could not copy one of the scripts to backup. Exiting'
        Write-LogMessage -Type Error -MSG $PSItem.Exception.Message
        Stop-ScriptExecutionWithError
    }
}

function Update-PSMConfig {
    <#
    .SYNOPSIS
    Updates basic_psm.ini to reference the PSMAdminConnect account name.
    .DESCRIPTION
    Updates the PSMServerAdminId setting in basic_psm.ini to use the specified account name.
    PSMHardening.ps1 and PSMConfigureAppLocker.ps1 are no longer modified here; domain user
    details are passed directly as parameters when those signed scripts are invoked.
    .PARAMETER psmRootInstallLocation
    PSM root installation folder
    .PARAMETER PSMAdminConnectAccountName
    PSM Admin Connect account name
    #>
    param (
        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation,
        [Parameter(Mandatory = $true)]
        $PSMAdminConnectAccountName
    )
    try {
        $psmBasicPSMContent = Get-Content -Path $psmRootInstallLocation\basic_psm.ini
        $psmBasicPSMAdminLine = "PSMServerAdminId=`"$PSMAdminConnectAccountName`""
        $newBasicPSMContent = $psmBasicPSMContent -replace 'PSMServerAdminId=".+$', $psmBasicPSMAdminLine
        $newBasicPSMContent | Set-Content -Path "$psmRootInstallLocation\test_basic_psm.ini"
        Copy-Item -Path "$psmRootInstallLocation\test_basic_psm.ini" -Destination "$psmRootInstallLocation\basic_psm.ini" -Force
    } catch {
        Write-LogMessage -Type Error -MSG 'Failed to update PSM Config, please verify the files manually.'
        Write-LogMessage -Type Error -MSG $PSItem.Exception.Message
        Stop-ScriptExecutionWithError
    }
}

function Invoke-PSMHardening {
    <#
    .SYNOPSIS
    Runs the PSMHardening script
    .DESCRIPTION
    Runs the PSMHardening script, passing domain user details as parameters.
    .PARAMETER psmRootInstallLocation
    PSM root installation folder
    .PARAMETER PSMConnectUsername
    Pre-Windows 2000 username of the PSMConnect domain user (without domain prefix).
    .PARAMETER PSMAdminConnectUsername
    Pre-Windows 2000 username of the PSMAdminConnect domain user (without domain prefix).
    .PARAMETER DomainNetbiosName
    NETBIOS name of the domain.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$PSMConnectUsername,

        [Parameter(Mandatory = $true)]
        [string]$PSMAdminConnectUsername,

        [Parameter(Mandatory = $true)]
        [string]$DomainNetbiosName,

        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation
    )
    Write-LogMessage -Type Info -MSG 'Running PSM Hardening script'
    Write-LogMessage -Type Info -MSG '---'
    $hardeningScriptRoot = "$psmRootInstallLocation\Hardening"
    $CurrentLocation = Get-Location
    Set-Location $hardeningScriptRoot
    Set-PSDebug -Strict:$False
    $PSMHardeningArgs = @{
        connectionUserName        = $PSMConnectUsername
        connectionUserDomain      = $DomainNetbiosName
        connectionAdminUserName   = $PSMAdminConnectUsername
        connectionAdminUserDomain = $DomainNetbiosName
    }
    & "$hardeningScriptRoot\PSMHardening.ps1" @PSMHardeningArgs
    Set-PSDebug -Strict:$False
    Set-Location $CurrentLocation
    Write-LogMessage -Type Info -MSG '---'
    Write-LogMessage -Type Info -MSG 'End of PSM Hardening script output'
}

function Invoke-PSMConfigureAppLocker {
    <#
    .SYNOPSIS
    Runs the AppLocker PowerShell script
    .DESCRIPTION
    Runs the PSMConfigureAppLocker script, passing domain user details as parameters.
    .PARAMETER psmRootInstallLocation
    PSM root installation folder
    .PARAMETER PSMConnectUsername
    Pre-Windows 2000 username of the PSMConnect domain user (without domain prefix).
    .PARAMETER PSMAdminConnectUsername
    Pre-Windows 2000 username of the PSMAdminConnect domain user (without domain prefix).
    .PARAMETER DomainNetbiosName
    NETBIOS name of the domain.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$PSMConnectUsername,

        [Parameter(Mandatory = $true)]
        [string]$PSMAdminConnectUsername,

        [Parameter(Mandatory = $true)]
        [string]$DomainNetbiosName,

        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation
    )
    Write-LogMessage -Type Info -MSG 'Running PSM Configure AppLocker script'
    Write-LogMessage -Type Info -MSG '---'
    $hardeningScriptRoot = "$psmRootInstallLocation\Hardening"
    $CurrentLocation = Get-Location
    Set-Location $hardeningScriptRoot
    Set-PSDebug -Strict:$False
    $PSMAppLockerArgs = @{
        connectionUserName        = $PSMConnectUsername
        connectionUserDomain      = $DomainNetbiosName
        connectionAdminUserName   = $PSMAdminConnectUsername
        connectionAdminUserDomain = $DomainNetbiosName
    }
    & "$hardeningScriptRoot\PSMConfigureAppLocker.ps1" @PSMAppLockerArgs
    Set-PSDebug -Strict:$False
    Set-Location $CurrentLocation
    Write-LogMessage -Type Info -MSG '---'
    Write-LogMessage -Type Info -MSG 'End of PSM Configure AppLocker script output'
}

function New-VaultAdminObject {
    <#
    .SYNOPSIS
    Onboards an account in the vault
    .DESCRIPTION
    Onboards an account in the vault
    .PARAMETER pvwaAddress
    Address of the PVWA
    .PARAMETER pvwaToken
    Token to log into PVWA using APIs
    .PARAMETER name
    Name of the account (PSMConnect/PSMAdminConnect)
    .PARAMETER domain
    Domain of the users needed to be onboarded
    .PARAMETER Credentials
    Credentials to be onboarded (has both the username and password)
    .PARAMETER platformID
    The Platform to onboard the account to. We will use the PlatformID in this script from what we create.
    #>
    param (
        [Parameter(Mandatory = $true)]
        $pvwaAddress,
        [Parameter(Mandatory = $true)]
        $pvwaToken,
        [Parameter(Mandatory = $true)]
        $name,
        [Parameter(Mandatory = $true)]
        [String]$domain,
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials,
        [Parameter(Mandatory = $true)]
        $platformID,
        [Parameter(Mandatory = $false)]
        $safe = 'PSM'
    )

    $username = $Credentials.username.Replace('\', '')
    $password = $Credentials.GetNetworkCredential().password
    $body = @{
        name                      = $name
        address                   = $domain
        userName                  = $username
        safeName                  = $safe
        secretType                = 'password'
        secret                    = $password
        platformID                = $platformID
        platformAccountProperties = @{'LogonDomain' = $domain }
    }
    $url = $pvwaAddress + '/api/Accounts'
    $json = $body | ConvertTo-Json
    try {
        $result = Invoke-RestMethod -Method POST -Uri $url -Body $json -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json' -ErrorVariable ResultError
        return $result
    } catch {
        try {
            $ErrorMessage = $ResultError.Message | ConvertFrom-Json
            return $ErrorMessage
        } catch {
            Write-LogMessage -Type Error -MSG ('Error creating user: {0}' -f $ResultError.Message)
            Stop-ScriptExecutionWithError
        }
    }
}

function Get-VaultAccountDetails {
    <#
    .SYNOPSIS
    Onboards an account in the vault
    .DESCRIPTION
    Onboards an account in the vault
    .PARAMETER pvwaAddress
    Address of the PVWA
    .PARAMETER pvwaToken
    Token to log into PVWA using APIs
    .PARAMETER safe
    Safe to search
    #>
    param (
        [Parameter(Mandatory = $true)]
        $pvwaAddress,
        [Parameter(Mandatory = $true)]
        $pvwaToken,
        [Parameter(Mandatory = $false)]
        $safe = 'PSM'
    )

    $url = ('{0}/api/Accounts?filter=safename eq {1}' -f $pvwaAddress, $safe)
    try {
        $result = Invoke-RestMethod -Method GET -Uri $url -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json' -ErrorVariable ResultError
        $Accounts = $result.value
        return $Accounts
    } catch {
        try {
            $ErrorMessage = $ResultError.Message | ConvertFrom-Json
            return $ErrorMessage
        } catch {
            Write-LogMessage -Type Error -MSG ('Error retrieving account details: {0}' -f $ResultError.Message)
            Stop-ScriptExecutionWithError
        }
    }
}

function Get-VaultAccountPassword {
    <#
    .SYNOPSIS
    Onboards an account in the vault
    .DESCRIPTION
    Onboards an account in the vault
    .PARAMETER pvwaAddress
    Address of the PVWA
    .PARAMETER pvwaToken
    Token to log into PVWA using APIs
    .PARAMETER safe
    Safe to search
    #>
    param (
        [Parameter(Mandatory = $true)]
        $pvwaAddress,
        [Parameter(Mandatory = $true)]
        $pvwaToken,
        [Parameter(Mandatory = $true)]
        $AccountId
    )

    $url = ('{0}/API/Accounts/{1}/Password/Retrieve/' -f $pvwaAddress, $AccountId)
    try {
        $result = Invoke-RestMethod -Method POST -Uri $url -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json' -ErrorVariable ResultError
        return $result
    } catch {
        try {
            $ErrorMessage = $ResultError.Message | ConvertFrom-Json
            return $ErrorMessage
        } catch {
            Write-LogMessage -Type Error -MSG ('Error retrieving account password: {0}' -f $ResultError.Message)
            Stop-ScriptExecutionWithError
        }
    }
}

function Add-AdminUserToTS {
    <#
    .SYNOPSIS
    Updates RDS settings to add the Admin Account.
    .DESCRIPTION
    Updates RDS settings to add the Admin Account. Ensures we can still do recording with PSMAdminConnect
    .PARAMETER NETBIOS
    NETBIOS of the domain user
    .PARAMETER Credentials
    Credential of the user to setup RDP for (mainly need the username)
    #>
    param (
        [Parameter(Mandatory = $true)]
        [String]$NETBIOS,
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials
    )
    $username = '{0}\{1}' -f $NETBIOS, $Credentials.username
    try {
        $CimInstance = Get-CimInstance -Namespace root/cimv2/terminalservices -Query "SELECT * FROM Win32_TSPermissionsSetting WHERE TerminalName = 'RDP-Tcp'"
        $result = $CimInstance | Invoke-CimMethod -MethodName AddAccount -Arguments @{AccountName = "$username"; PermissionPreSet = 0 } -ErrorAction Stop
        return $result
    } catch {
        return @{
            Error       = $PSItem.Exception.Message
            ReturnValue = 1
        }
    }
}

function Add-AdminUserTSShadowPermission {
    <#
    .SYNOPSIS
    Updates RDS settings to add the Admin Account.
    .DESCRIPTION
    Updates RDS settings to add the Admin Account. Ensures we can still do recording with PSMAdminConnect
    .PARAMETER NETBIOS
    NETBIOS of the domain user
    .PARAMETER Credentials
    Credential of the user to setup RDP for (mainly need the username)
    #>
    param (
        [Parameter(Mandatory = $true)]
        [String]$NETBIOS,
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials
    )
    $username = '{0}\{1}' -f $NETBIOS, $Credentials.username
    try {
        $CimInstance = Get-CimInstance -Namespace root/cimv2/terminalservices -Query "SELECT * FROM Win32_TSAccount WHERE TerminalName = 'RDP-Tcp'" -ErrorAction Stop | Where-Object AccountName -EQ $username
        $result = $CimInstance | Invoke-CimMethod -MethodName ModifyPermissions -Arguments @{PermissionMask = 4; Allow = $true }
        return $result
    } catch {
        return @{
            Error       = $PSItem.Exception.Message
            ReturnValue = 1
        }
    }
}

function Copy-Platform {
    <#
    .SYNOPSIS
    Duplicating the windows domain user platform so we can onboard the accounts into that platform
    .DESCRIPTION
    Duplicating the windows domain user platform so we can onboard the accounts into that platform
    .PARAMETER pvwaAddress
    PVWA address to run API commands on
    .PARAMETER pvwaToken
    Token to authenticate into the PVWA
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$pvwaAddress,
        [Parameter(Mandatory = $true)]
        [string]$pvwaToken,
        [Parameter(Mandatory = $true)]
        [string]$NewPlatformName,
        [Parameter(Mandatory = $true)]
        [string]$NewPlatformDescription,
        [Parameter(Mandatory = $true)]
        [string]$CurrentPlatformId
    )
    try {
        $url = $pvwaAddress + "/api/Platforms/Targets/$CurrentPlatformId/Duplicate"
        $body = @{
            Name        = $NewPlatformName
            Description = $NewPlatformDescription
        }
        $json = $body | ConvertTo-Json
        $null = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json'
    } catch {
        Write-LogMessage -Type Error -MSG 'Error duplicating platform'
        Write-LogMessage -Type Error -MSG $PSItem.Exception.Message
        Stop-ScriptExecutionWithError
    }
}

function Get-PlatformStatus {
    <#
    .SYNOPSIS
    Get the platform status to check whether it exists and is active
    .DESCRIPTION
    Get the platform status to check whether it exists and is active
    .PARAMETER pvwaAddress
    PVWA address to run API commands on
    .PARAMETER pvwaToken
    Token to authenticate into the PVWA
    .PARAMETER PlatformId
    ID (string) of platform to retrieve
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$pvwaAddress,
        [Parameter(Mandatory = $true)]
        [string]$pvwaToken,
        [Parameter(Mandatory = $true)]
        [string]$PlatformId

    )
    try {
        $url = $pvwaAddress + '/api/Platforms/targets?search=' + $PlatformId
        $Getresult = Invoke-RestMethod -Method 'Get' -Uri $url -Headers @{ 'Authorization' = $pvwaToken } -ErrorAction SilentlyContinue -ErrorVariable GetPlatformError
        # This query returns a list of platforms where the name contains the search string. Find and return just the one with an exactly matching name.
        $TargetPlatform = $Getresult.Platforms | Where-Object Name -EQ $PlatformId
        if ($TargetPlatform) {
            return $TargetPlatform
        } else {
            return $false
        }
    } catch {
        Write-LogMessage -Type Error -MSG 'Error getting platform status.'
        Write-LogMessage -Type Error -MSG $PSItem.ErrorDetails.Message
        Stop-ScriptExecutionWithError
    }
}

function Get-PlatformStatusById {
    <#
    .SYNOPSIS
    Get the platform status to check whether it exists and is active
    .DESCRIPTION
    Get the platform status to check whether it exists and is active
    .PARAMETER pvwaAddress
    PVWA address to run API commands on
    .PARAMETER pvwaToken
    Token to authenticate into the PVWA
    .PARAMETER PlatformId
    ID (string) of platform to retrieve
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$pvwaAddress,
        [Parameter(Mandatory = $true)]
        [string]$pvwaToken,
        [Parameter(Mandatory = $true)]
        [string]$PlatformId

    )
    try {
        $url = $pvwaAddress + '/api/Platforms/targets'
        $Getresult = Invoke-RestMethod -Method 'Get' -Uri $url -Headers @{ 'Authorization' = $pvwaToken } -ErrorAction SilentlyContinue -ErrorVariable GetPlatformError
        # This query returns a list of platforms where the name contains the search string. Find and return just the one with an exactly matching name.
        $TargetPlatform = $Getresult.Platforms | Where-Object PlatformID -EQ $PlatformId
        if ($TargetPlatform) {
            return $TargetPlatform
        } else {
            return $false
        }
    } catch {
        Write-LogMessage -Type Error -MSG 'Error getting platform status.'
        Write-LogMessage -Type Error -MSG $PSItem.ErrorDetails.Message
        Stop-ScriptExecutionWithError
    }
}

function Get-SafeStatus {
    <#
    .SYNOPSIS
    Get the safe status to check whether it exists and is active
    .DESCRIPTION
    Get the safe status to check whether it exists and is active
    .PARAMETER pvwaAddress
    PVWA address to run API commands on
    .PARAMETER pvwaToken
    Token to authenticate into the PVWA
    .PARAMETER SafeName
    Name of safe to retrieve
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$pvwaAddress,
        [Parameter(Mandatory = $true)]
        [string]$pvwaToken,
        [Parameter(Mandatory = $true)]
        [string]$SafeName

    )
    try {
        $url = $pvwaAddress + "/api/safes?search=$SafeName"
        $SafeRequest = Invoke-RestMethod -Method 'Get' -Uri $url -Headers @{ 'Authorization' = $pvwaToken } -ErrorAction SilentlyContinue
        # This query returns a list of safes where the name contains the search string. Find and return just the one with an exactly matching name.
        $Safe = $SafeRequest.Value | Where-Object safeName -EQ $SafeName
        if ($Safe) {
            return $Safe
        } else {
            return $false
        }
    } catch {
        Write-LogMessage -Type Error -MSG 'Error getting safe status.'
        Write-LogMessage -Type Error -MSG $PSItem.ErrorDetails.Message
        Stop-ScriptExecutionWithError
    }
}

function Enable-Platform {
    <#
    .SYNOPSIS
    Activate the required platform
    .DESCRIPTION
    Activate the required platform
    .PARAMETER pvwaAddress
    PVWA address to run API commands on
    .PARAMETER pvwaToken
    Token to authenticate into the PVWA
    .PARAMETER PlatformNumId
    Numeric ID of platform to activate
    #>
    param (
        [Parameter(Mandatory = $true)]
        $pvwaAddress,
        [Parameter(Mandatory = $true)]
        $pvwaToken,
        [Parameter(Mandatory = $true)]
        [string]$PlatformNumId
    )
    try {
        $url = $pvwaAddress + "/api/Platforms/Targets/$PlatformNumId/activate"
        $null = Invoke-RestMethod -Method 'Post' -Uri $url -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json'
    } catch {
        Write-LogMessage -Type Error -MSG 'Error activating platform'
        Write-LogMessage -Type Error -MSG $PSItem.ErrorDetails.Message
        Stop-ScriptExecutionWithError
    }
}

function New-PSMSafe {
    <#
    .SYNOPSIS
    Creates a new PSM Safe with correct permissions
    .DESCRIPTION
    Creates a new PSM safe with correct permissions
    .PARAMETER pvwaAddress
    PVWA address to run API commands on
    .PARAMETER pvwaToken
    Token to authenticate into the PVWA
    .PARAMETER safe
    Safe Name to create
    #>
    param (
        [Parameter(Mandatory = $true)]
        $pvwaAddress,
        [Parameter(Mandatory = $true)]
        $pvwaToken,
        [Parameter(Mandatory = $false)]
        $safe,
        [Parameter(Mandatory = $false)]
        $description = 'Safe for PSM Users'
    )
    try {
        $url = $pvwaAddress + '/api/Safes'
        $body = @{
            safeName    = $safe
            description = $description
        }
        $json = $body | ConvertTo-Json
        $null = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json'
        #Permissions for the needed accounts
        #PSMMaster full permissions
        New-SafePermissions -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -safe $safe -safeMember 'PSMMaster'
        #PVWAAppUser and PVWAAppUsers permissions
        $PVWAAppUser = @{
            useAccounts                            = $False
            retrieveAccounts                       = $True
            listAccounts                           = $True
            addAccounts                            = $False
            updateAccountContent                   = $True
            updateAccountProperties                = $False
            initiateCPMAccountManagementOperations = $False
            specifyNextAccountContent              = $False
            renameAccounts                         = $False
            deleteAccounts                         = $False
            unlockAccounts                         = $False
            manageSafe                             = $False
            manageSafeMembers                      = $False
            backupSafe                             = $False
            viewAuditLog                           = $False
            viewSafeMembers                        = $False
            accessWithoutConfirmation              = $False
            createFolders                          = $False
            deleteFolders                          = $False
            moveAccountsAndFolders                 = $False
            requestsAuthorizationLevel1            = $False
            requestsAuthorizationLevel2            = $False
        }
        New-SafePermissions -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -safe $safe -safeMember 'PVWAAppUser' -memberType 'user' -safePermissions $PVWAAppUser
        New-SafePermissions -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -safe $safe -safeMember 'PVWAAppUsers' -safePermissions $PVWAAppUser
        #PSMAppUsers
        $PSMAppUsers = @{
            useAccounts                            = $False
            retrieveAccounts                       = $True
            listAccounts                           = $True
            addAccounts                            = $False
            updateAccountContent                   = $False
            updateAccountProperties                = $False
            initiateCPMAccountManagementOperations = $False
            specifyNextAccountContent              = $False
            renameAccounts                         = $False
            deleteAccounts                         = $False
            unlockAccounts                         = $False
            manageSafe                             = $False
            manageSafeMembers                      = $False
            backupSafe                             = $False
            viewAuditLog                           = $False
            viewSafeMembers                        = $False
            accessWithoutConfirmation              = $False
            createFolders                          = $False
            deleteFolders                          = $False
            moveAccountsAndFolders                 = $False
            requestsAuthorizationLevel1            = $False
            requestsAuthorizationLevel2            = $False
        }
        Set-SafePermissions -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -safe $safe -safeMember 'PSMAppUsers' -safePermissions $PSMAppUsers
        return $true
    } catch {
        Write-LogMessage -Type Error -MSG $PSItem.ErrorDetails.Message
        return $false
    }
}

function Set-SafePermissions {
    <#
    .SYNOPSIS
    Update a member's safe permission on a specific safe
    .DESCRIPTION
    Update a member's safe permission on a specific safe
    .PARAMETER pvwaAddress
    PVWA address to run API commands on
    .PARAMETER pvwaToken
    Token to authenticate into the PVWA
    .PARAMETER safe
    Which Safe to give permission to (Default PSM)
    .PARAMETER SafeMember
    Which Member to give the safe permission
    #>
    param (
        [Parameter(Mandatory = $true)]
        $pvwaAddress,
        [Parameter(Mandatory = $true)]
        $pvwaToken,
        [Parameter(Mandatory = $false)]
        $safe = 'PSM',
        [Parameter(Mandatory = $false)]
        $safeMember = 'Vault Admins',
        [Parameter(Mandatory = $false)]
        $memberType = 'Group',
        [Parameter(Mandatory = $false)]
        $safePermissions = @{
            useAccounts                            = $True
            retrieveAccounts                       = $True
            listAccounts                           = $True
            addAccounts                            = $True
            updateAccountContent                   = $True
            updateAccountProperties                = $True
            initiateCPMAccountManagementOperations = $True
            specifyNextAccountContent              = $True
            renameAccounts                         = $True
            deleteAccounts                         = $True
            unlockAccounts                         = $True
            manageSafe                             = $True
            manageSafeMembers                      = $True
            backupSafe                             = $True
            viewAuditLog                           = $True
            viewSafeMembers                        = $True
            accessWithoutConfirmation              = $True
            createFolders                          = $True
            deleteFolders                          = $True
            moveAccountsAndFolders                 = $True
            requestsAuthorizationLevel1            = $True
            requestsAuthorizationLevel2            = $False
        }
    )
    try {
        $url = $pvwaAddress + "/api/Safes/$safe/members/$SafeMember"
        $body = @{
            permissions = $safePermissions
        }
        $json = $body | ConvertTo-Json
        $null = Invoke-RestMethod -Method 'Put' -Uri $url -Body $json -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json'
    } catch {
        Write-LogMessage -Type Error -MSG $PSItem.ErrorDetails.Message
    }
}

function Get-SafePermissions {
    <#
    .SYNOPSIS
    Adds safe permission to a specific safe
    .DESCRIPTION
    Adds safe permission to a specific safe
    .PARAMETER pvwaAddress
    PVWA address to run API commands on
    .PARAMETER pvwaToken
    Token to authenticate into the PVWA
    .PARAMETER safe
    Which Safe to give permission to (Default PSM)
    .PARAMETER SafeMember
    Which Member to give the safe permission
    .PARAMETER memberType
    What type of member to give permission to (group,role,user)
    #>
    param (
        [Parameter(Mandatory = $true)]
        $pvwaAddress,
        [Parameter(Mandatory = $true)]
        $pvwaToken,
        [Parameter(Mandatory = $false)]
        $safe = 'PSM',
        [Parameter(Mandatory = $false)]
        $safeMember = 'Vault Admins',
        [Parameter(Mandatory = $false)]
        $SearchIn = 'Vault',
        [Parameter(Mandatory = $false)]
        $memberType = 'Group'
    )
    try {
        $url = $pvwaAddress + "/api/Safes/$safe/members/$safeMember/"
        $result = Invoke-RestMethod -Method 'Get' -Uri $url -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json'
        if ($result) {
            return $result.permissions
        } else {
            throw
        }
    } catch {
        return $false
    }
}

function New-SafePermissions {
    <#
    .SYNOPSIS
    Adds safe permission to a specific safe
    .DESCRIPTION
    Adds safe permission to a specific safe
    .PARAMETER pvwaAddress
    PVWA address to run API commands on
    .PARAMETER pvwaToken
    Token to authenticate into the PVWA
    .PARAMETER safe
    Which Safe to give permission to (Default PSM)
    .PARAMETER SafeMember
    Which Member to give the safe permission
    .PARAMETER memberType
    What type of member to give permission to (group,role,user)
    #>
    param (
        [Parameter(Mandatory = $true)]
        $pvwaAddress,
        [Parameter(Mandatory = $true)]
        $pvwaToken,
        [Parameter(Mandatory = $false)]
        $safe = 'PSM',
        [Parameter(Mandatory = $false)]
        $safeMember = 'Vault Admins',
        [Parameter(Mandatory = $false)]
        $SearchIn = 'Vault',
        [Parameter(Mandatory = $false)]
        $memberType = 'Group',
        [Parameter(Mandatory = $false)]
        $safePermissions = @{
            useAccounts                            = $True
            retrieveAccounts                       = $True
            listAccounts                           = $True
            addAccounts                            = $True
            updateAccountContent                   = $True
            updateAccountProperties                = $True
            initiateCPMAccountManagementOperations = $True
            specifyNextAccountContent              = $True
            renameAccounts                         = $True
            deleteAccounts                         = $True
            unlockAccounts                         = $True
            manageSafe                             = $True
            manageSafeMembers                      = $True
            backupSafe                             = $True
            viewAuditLog                           = $True
            viewSafeMembers                        = $True
            accessWithoutConfirmation              = $True
            createFolders                          = $True
            deleteFolders                          = $True
            moveAccountsAndFolders                 = $True
            requestsAuthorizationLevel1            = $True
            requestsAuthorizationLevel2            = $False
        }
    )
    try {
        $url = $pvwaAddress + "/api/Safes/$safe/members"
        $body = @{
            memberName  = $SafeMember
            memberType  = $memberType
            searchIn    = $SearchIn
            permissions = $safePermissions
        }
        $json = $body | ConvertTo-Json
        $null = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -Headers @{ 'Authorization' = $pvwaToken } -ContentType 'application/json'
    } catch {
        Write-LogMessage -Type Error -MSG $PSItem.ErrorDetails.Message
    }
}

function Test-UM {
    <#
    .SYNOPSIS
    Checks to see if tenant is UM or not (from the connector server)
    .DESCRIPTION
    Checks to see if tenant is UM or not (from the connector server)
    .PARAMETER psmRootInstallLocation
    PSM Folder
    #>
    param (
        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation
    )
    $psmBasicPSMContent = Get-Content -Path $psmRootInstallLocation\basic_psm.ini
    $validation = $psmBasicPSMContent -match 'IdentityUM.*=.*Yes'
    return ('' -ne $validation)
}
function Get-PSMServerId {
    <#
    .SYNOPSIS
    Gets the PSM Server ID from basic_psm.ini.
    .DESCRIPTION
    Reads the PSMServerId value from the basic_psm.ini configuration file.
    .PARAMETER psmRootInstallLocation
    PSM root installation folder
    #>
    param (
        [Parameter(Mandatory = $true)]
        $psmRootInstallLocation
    )
    $PsmServerIdLine = Get-Content -Path $psmRootInstallLocation\basic_psm.ini | Where-Object { $PSItem -like 'PSMServerId="*"' }
    $null = $PsmServerIdLine -match 'PSMServerId="(.*)"$'
    return $Matches[1]
}

function Test-CredentialFormat {
    param (
        [Parameter(Mandatory = $true)][PSCredential]$Credential
    )
    if ($Credential.username -match '[/\\\[\]:;|=,+*?<>@"]') {
        return $false
    }
    if ($Credential.username.Length -gt 20) {
        return $false
    }
    return $true
}

function Test-PSMUserConfiguration {
    param (
        [Parameter(Mandatory = $true)][System.DirectoryServices.DirectoryEntry]$UserObject,
        [Parameter(Mandatory = $true)][string]$UserType,
        [Parameter(Mandatory = $true)][string]$PSMInstallLocation

    )
    # Define the settings we'll be comparing against
    $PSMComponentsPath = $PSMInstallLocation + 'Components'
    $PSMInitSessionPath = $PSMComponentsPath + '\PSMInitSession.exe'
    $SettingsToCheck = @(
        @{
            UserType      = 'All'
            Name          = 'TerminalServicesInitialProgram'
            DisplayName   = 'Initial Program'
            ExpectedValue = $PSMInitSessionPath
            SettingType   = 'StringCompare'
        },
        @{
            UserType      = 'All'
            Name          = 'TerminalServicesWorkDirectory'
            DisplayName   = 'Working Directory'
            ExpectedValue = $PSMComponentsPath
            Path          = $true
            SettingType   = 'StringCompare'
        },
        @{
            UserType      = 'All'
            Name          = 'ConnectClientDrivesAtLogon'
            DisplayName   = 'Connect client drives at logon'
            ExpectedValue = 0
            SettingType   = 'Value'
        },
        @{
            UserType      = 'All'
            Name          = 'ConnectClientPrintersAtLogon'
            DisplayName   = 'Connect client printers at logon'
            ExpectedValue = 0
            SettingType   = 'Value'
        },
        @{
            UserType      = 'All'
            Name          = 'DefaultToMainPrinter'
            DisplayName   = 'Default to main client printer'
            ExpectedValue = 0
            SettingType   = 'Value'
        },
        @{
            UserType      = 'All'
            Name          = 'EnableRemoteControl'
            DisplayName   = 'Enable remote control'
            ExpectedValue = 2, 4
            SettingType   = 'Value'
        },
        @{
            UserType      = 'PSMConnect'
            Name          = 'MaxDisconnectionTime'
            DisplayName   = 'End a disconnected session'
            ExpectedValue = 1
            SettingType   = 'Value'
        },
        @{
            UserType      = 'PSMConnect'
            Name          = 'ReconnectionAction'
            DisplayName   = 'Allow reconnection'
            ExpectedValue = 1
            SettingType   = 'Value'
        },
        @{
            UserType      = 'All'
            Name          = 'userWorkstations'
            DisplayName   = "`"Log On To`" Restrictions"
            ExpectedValue = $env:computername
            SettingType   = 'LogOnTo'
        }
    )
    $AllUserConfigurationErrors = @()
    $UserName = $UserObject.Name
    $SettingsToCheck | ForEach-Object { # For each aspect of the configuration
        $SettingName = $PSItem.Name
        $SettingUserType = $PSItem.UserType
        $SettingDisplayName = $PSItem.DisplayName
        $SettingExpectedValue = $PSItem.ExpectedValue
        $SettingCurrentValue = Get-UserProperty -UserObject $UserObject -Property $SettingName
        $SettingType = $PSItem.SettingType

        if ($PSItem.Path) {
            # If the value we're checking is a directory, trim training backslashes as they don't matter
            $SettingCurrentValue = ($SettingCurrentValue -replace '\\*$', '')
        }

        if ($SettingUserType -in 'All', $UserType) {
            # If the setting that we are checking applies to the user we're checking, or all users
            if ($SettingType -eq 'LogOnTo') {
                # split $SettingCurrentValue into an array
                $SettingCurrentValue = $SettingCurrentValue -split ','
            }
            if (
                (
                    ($SettingType -in 'Value', 'StringCompare') -and
                    ($SettingCurrentValue -notin $SettingExpectedValue)
                    # For Value and StringCompare setting types, we check if the current value is one of the expected values
                ) -or
                (
                    ($SettingType -eq 'LogOnTo') -and (
                        ($SettingCurrentValue) -and
                        ($SettingExpectedValue -notin $SettingCurrentValue)
                    )
                    # but for Log On To, it's the other way round - the expected value must be in the current value (or be empty - "all workstations")
                )
            ) {
                $ThisUserConfigurationError = [PSCustomObject]@{ # Store the details of this misconfiguration
                    Username    = $Username
                    User        = $UserType
                    SettingName = $SettingDisplayName
                    Current     = $SettingCurrentValue
                    Expected    = $SettingExpectedValue
                    SettingType = $SettingType
                }
                if ($SettingType -eq 'LogOnTo') {
                    $ThisUserConfigurationError.Expected = "Must include `"$SettingExpectedValue`""
                }
                # and add it to the array containing the list of misconfigurations
                $AllUserConfigurationErrors += $ThisUserConfigurationError
            }
        }
    }
    return $AllUserConfigurationErrors
}

function Test-PasswordCharactersValid {
    param (
        [Parameter(Mandatory = $true)][PSCredential]$Credential
    )
    if ($Credential.GetNetworkCredential().Password -match '^[A-Za-z0-9~!@#$%^&*_\-+=`|\(){}[\]:;"''<>,.?\\\/ ]+$') {
        # The above special characters without escape characters:      ~!@#$%^&*_ -+=`| (){}[ ]:;" '<>,.? \ /
        # space character is also valid
        return $true
    }
    return $false
}



function Get-UserDNFromSamAccountName {
    param (
        [Parameter(Mandatory = $True)]
        [string]
        $Username
    )
    $Searcher = [adsisearcher]"samaccountname=$Username"
    $Result = $Searcher.FindAll()
    if ($Result) {
        return $Result.Path
    }
    return $False
}

function Get-UserObjectFromDN {
    param (
        [Parameter(Mandatory = $True)]
        [string]
        $DistinguishedName
    )
    $UserObject = [adsi]"$DistinguishedName"
    if ($UserObject) {
        return $UserObject
    }
    return $False
}

function Get-UserProperty {
    param (
        [Parameter(Mandatory = $True)]
        [System.DirectoryServices.DirectoryEntry]
        $UserObject,
        [Parameter(Mandatory = $True)]
        [string]
        $Property
    )
    try {
        $Result = $UserObject.InvokeGet($Property)
    } catch {
        $Result = 'Unset'
    }
    return $Result
}

function Set-PSMServerObject {
    <#
    .SYNOPSIS
    Configures the PSM server object in the vault via VaultOperationsTester.
    .DESCRIPTION
    Runs VaultOperationsTester.exe to update the PSM server configuration with the
    specified safe, PSMConnect, and PSMAdminConnect account names. Logs all errors
    and stops the script if configuration fails.
    #>
    param (
        [Parameter(Mandatory = $True)]
        [String]
        $VaultOperationsFolder,
        [Parameter(Mandatory = $True)]
        [String]
        $VaultAddress,
        [Parameter(Mandatory = $True)]
        [PSCredential]
        $VaultCredentials,
        [Parameter(Mandatory = $True)]
        [String]
        $PSMServerId,
        [Parameter(Mandatory = $True)]
        [String]
        $PSMSafe,
        [Parameter(Mandatory = $True)]
        [String]
        $PSMConnectAccountName,
        [Parameter(Mandatory = $True)]
        [String]
        $PSMAdminConnectAccountName,
        [Parameter(Mandatory = $False)]
        [string]
        $Proxy
    )

    $VaultOperationsExe = "$VaultOperationsFolder\VaultOperationsTester.exe"
    $stdoutFile = "$VaultOperationsFolder\Log\stdout.log"
    $LOG_FILE_PATH_CasosArchive = "$VaultOperationsFolder\Log\old"

    #Cleanup log file if it gets too big
    if (Test-Path $LOG_FILE_PATH_CasosArchive) {
        if (Get-ChildItem $LOG_FILE_PATH_CasosArchive | Measure-Object -Property length -Sum | Where-Object { $PSItem.sum -gt 5MB }) {
            Write-LogMessage -type Verbose -MSG 'Archive log folder is getting too big, deleting it.'
            Write-LogMessage -type Verbose -MSG "Deleting $LOG_FILE_PATH_CasosArchive"
            Remove-Item $LOG_FILE_PATH_CasosArchive -Recurse -Force
        }
    }

    #create log file
    New-Item -Path $stdoutFile -Force | Out-Null

    # Create vault.ini
    New-Item -Path "$VaultOperationsFolder\Vault.ini" -Force
    Add-Content -Path "$VaultOperationsFolder\Vault.ini" -Force -Value ('VAULT = "Vault"')

    if ('None' -ne $Proxy) {
        $ProxyAddress = $Proxy.Split(':')[0]
        $ProxyPort = $Proxy.Split(':')[1]
        Add-Content -Path "$VaultOperationsFolder\Vault.ini" -Force -Value ('PROXYADDRESS = {0}' -f $ProxyAddress)
        Add-Content -Path "$VaultOperationsFolder\Vault.ini" -Force -Value ('PROXYPORT = {0}' -f $ProxyPort)
        Add-Content -Path "$VaultOperationsFolder\Vault.ini" -Force -Value ('PROXYTYPE = https')
    }

    #Get Credentials
    $VaultUser = $VaultCredentials.UserName
    $VaultPass = $VaultCredentials.GetNetworkCredential().Password
    $Operation = 'EditConfigNode'
    $ConfigString = (
        "//PSMServer[@ID='{0}']/ConnectionDetails/Server Safe={1},Object={2},AdminObject={3}" -f
        $PSMServerId, $PSMSafe, $PSMConnectAccountName, $PSMAdminConnectAccountName
    )
    $StartProcessArgs = @{
        FilePath               = $VaultOperationsExe
        WorkingDirectory       = $VaultOperationsFolder
        NoNewWindow            = $true
        PassThru               = $true
        Wait                   = $true
        RedirectStandardOutput = $stdoutFile
        ArgumentList           = @($VaultUser, $VaultPass, $VaultAddress, $Operation, $ConfigString)
    }
    Write-LogMessage -type Verbose -MSG 'Configuring PSM server object in vault'
    try {
        $VaultOperationsTesterProcess = Start-Process @StartProcessArgs
    } catch {
        Write-LogMessage -type Error -MSG 'Failed to configure PSM Server object in vault. Please review the VaultOperationsTester log and resolve any errors'
        Write-LogMessage -type Error -MSG '  or run this script with the -SkipPSMObjectUpdate option and perform the required configuration manually.'
        Stop-ScriptExecutionWithError
    }

    if ($VaultOperationsTesterProcess.ExitCode -ne 0) {
        $ErrorLine = Get-Content $stdoutFile | Select-String '^Extra details:'
        $ErrorString = ($ErrorLine -split ':')[1].Trim()
        $null = $ErrorString -match '([A-Z0-9]*) (.*)'
        $ErrorCode = if ($Matches[1]) {
            $Matches[1]
        } else {
            'Unknown'
        }
        $ErrorDetails = if ($Matches[2]) {
            $Matches[2]
        } else {
            'Unknown'
        }
        Write-LogMessage -type Error -MSG 'Failed to configure PSM Server object in vault. Please review the VaultOperationsTester log and resolve any errors'
        Write-LogMessage -type Error -MSG '  or run this script with the -SkipPSMObjectUpdate option and perform the required configuration manually.'
        Write-LogMessage -type Error -MSG ('Error Code:    {0}' -f $ErrorCode)
        Write-LogMessage -type Error -MSG ('Error Details: {0}' -f $ErrorDetails)
        Stop-ScriptExecutionWithError
    }
}

function Get-VaultOperationsTesterPath {
    <#
    .SYNOPSIS
    Locates the VaultOperationsTester executable and verifies prerequisites.
    .DESCRIPTION
    Searches standard locations for VaultOperationsTester.exe and checks that the
    Visual Studio 2015-2022 x86 Redistributable is installed.
    .PARAMETER ScriptLocation
    The directory where Set-DomainUser.ps1 is located, used as the base for relative searches.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$ScriptLocation
    )
    $PossibleLocations = @(
        "$ScriptLocation\VaultOperationsTester\VaultOperationsTester.exe",
        "$ScriptLocation\..\VaultOperationsTester\VaultOperationsTester.exe",
        "$ScriptLocation\..\..\VaultOperationsTester\VaultOperationsTester.exe"
    )
    $VaultOperationsTesterExe = $null
    foreach ($Possibility in $PossibleLocations) {
        if (Test-Path -PathType Leaf -Path $Possibility) {
            $VaultOperationsTesterExe = Get-Item $Possibility
            break
        }
    }
    if ($null -eq $VaultOperationsTesterExe) {
        Write-LogMessage -type Error -MSG "VaultOperationsTester.exe not found. Please ensure it's present in one of the following locations:"
        Write-LogMessage -type Error -MSG ('  - ' + (((Get-Item $ScriptLocation\..\..).FullName) + '\VaultOperationsTester'))
        Write-LogMessage -type Error -MSG ('  - ' + (((Get-Item $ScriptLocation\..).FullName) + '\VaultOperationsTester'))
        Write-LogMessage -type Error -MSG ('  - ' + (((Get-Item $ScriptLocation).FullName) + '\VaultOperationsTester'))
        Write-LogMessage -type Error -MSG '  or run this script with the -SkipPSMObjectUpdate option and perform the required configuration manually.'
        Stop-ScriptExecutionWithError
    }
    $VaultOperationsTesterDir = (Get-Item $VaultOperationsTesterExe).Directory
    if ($false -eq (Test-Path -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x86' -PathType Container)) {
        $RedistLocation = ($VaultOperationsTesterDir.ToString() + '\vc_redist.x86.exe')
        Write-LogMessage -type Error -MSG 'Visual Studio 2015-2022 x86 Runtime not installed.'
        Write-LogMessage -type Error -MSG ("Please install from `"{0}`" and run this script again." -f $RedistLocation)
        Stop-ScriptExecutionWithError
    }
    return $VaultOperationsTesterDir
}

function Confirm-AutodetectedDomainDetails {
    <#
    .SYNOPSIS
    Prompts the user to confirm auto-detected domain DNS and NETBIOS names.
    .DESCRIPTION
    Returns $true if the user confirms the detected names, $false if rejected.
    .PARAMETER DomainDNSName
    The auto-detected DNS domain name.
    .PARAMETER DomainNetbiosName
    The auto-detected NETBIOS domain name.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$DomainDNSName,
        [Parameter(Mandatory = $true)]
        [string]$DomainNetbiosName
    )
    Write-LogMessage -Type Verbose -MSG 'Confirming auto-detected domain details'
    $DomainInfo = ''
    $DomainInfo += ("--------------------------------------------------------`n")
    $DomainInfo += ("Detected the following domain names:`n")
    $DomainInfo += ("  DNS name:     {0}`n" -f $DomainDNSName)
    $DomainInfo += ("  NETBIOS name: {0}`n" -f $DomainNetbiosName)
    $DomainInfo += ('Is this correct?')
    $PromptOptions = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
    $PromptOptions.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes', 'Confirm the domain details are correct'))
    $PromptOptions.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No', 'Exit the script so correct domain details can be provided'))
    $DomainPromptSelection = $Host.UI.PromptForChoice('', $DomainInfo, $PromptOptions, 1)
    if ($DomainPromptSelection -eq 0) {
        Write-LogMessage -Type Info -MSG 'Domain details confirmed'
        return $true
    } else {
        Write-LogMessage -Type Error -MSG 'Please rerun the script and provide the correct domain DNS and NETBIOS names on the command line.'
        return $false
    }
}

function Connect-PVWAAndGetToken {
    <#
    .SYNOPSIS
    Authenticates to PVWA and returns a validated session token.
    .DESCRIPTION
    Logs into the PVWA, validates the token, and returns it. Logs all errors and
    stops the script if authentication fails.
    .PARAMETER pvwaAddress
    The PVWA base URL.
    .PARAMETER VaultAdmin
    Vault administrator credentials.
    .PARAMETER AuthenticationType
    Authentication method: CyberArk, LDAP, Windows, or RADIUS.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$pvwaAddress,
        [Parameter(Mandatory = $true)]
        [PSCredential]$VaultAdmin,
        [Parameter(Mandatory = $true)]
        [ValidateSet('CyberArk', 'LDAP', 'Windows', 'RADIUS')]
        [string]$AuthenticationType
    )
    Write-LogMessage -type Info -MSG 'Validating vault administrator credentials'
    Write-LogMessage -type Verbose -MSG "Connecting to PVWA at $pvwaAddress"
    $LogonErrors = @()
    try {
        $pvwaTokenResponse = New-ConnectionToRestAPI -pvwaAddress $pvwaAddress -VaultAdmin $VaultAdmin -AuthenticationType $AuthenticationType
        if ($pvwaTokenResponse.ErrorCode -ne 'Success') {
            $NewError = "Logon to PVWA failed while authenticating to $pvwaAddress. Result:`n"
            $NewError += ("Error code: {0}`n" -f $pvwaTokenResponse.ErrorCode)
            $NewError += ('Error message: {0}' -f $pvwaTokenResponse.ErrorMessage)
            $LogonErrors += $NewError
        } else {
            $PVWATokenIsValid = ($pvwaTokenResponse.Response -match '[0-9a-zA-Z]{200,256}')
            if ($false -eq $PVWATokenIsValid) {
                $NewError = 'Response from server was not a valid token:'
                $NewError += $pvwaTokenResponse.Response
                $LogonErrors += $NewError
            } else {
                $PvwaTokenTestResponse = Test-PvwaToken -Token $pvwaTokenResponse.Response -pvwaAddress $pvwaAddress
                if ($PvwaTokenTestResponse.ErrorCode -eq 'Success') {
                    return $pvwaTokenResponse.Response
                } else {
                    $NewError = 'PVWA Token validation failed. Result:'
                    $NewError += $PvwaTokenTestResponse.Response
                    $LogonErrors += $NewError
                }
            }
        }
    } catch {
        $LogonErrors += $PSItem.Exception.Message
    }
    Write-LogMessage -type Error -MSG $SectionSeparator
    Write-LogMessage -type Error -MSG 'The following errors occurred while validating vault administrator credentials:'
    foreach ($LogonError in $LogonErrors) {
        Write-LogMessage -type Error -MSG $StandardSeparator
        Write-LogMessage -type Error -MSG $LogonError
    }
    Stop-ScriptExecutionWithError
}

function Resolve-PSMAccountsFromVault {
    <#
    .SYNOPSIS
    Resolves PSM account details from the vault.
    .DESCRIPTION
    Searches the vault for existing PSMConnect and PSMAdminConnect accounts. If found with
    matching domain, marks them as not requiring onboarding. If not found, prompts for
    credentials. Returns the resolved accounts and any conflict errors.
    .PARAMETER pvwaAddress
    PVWA base URL.
    .PARAMETER pvwaToken
    Session token for PVWA API calls.
    .PARAMETER Safe
    The safe to search for PSM accounts.
    .PARAMETER AccountSearchProperties
    Array of hashtables with AccountName and UserType.
    .PARAMETER DomainDNSName
    The expected domain DNS name for account address matching.
    .PARAMETER PSMConnectCredentials
    Optional pre-supplied credentials for PSMConnect.
    .PARAMETER PSMAdminConnectCredentials
    Optional pre-supplied credentials for PSMAdminConnect.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$pvwaAddress,
        [Parameter(Mandatory = $true)]
        [string]$pvwaToken,
        [Parameter(Mandatory = $true)]
        [string]$Safe,
        [Parameter(Mandatory = $true)]
        [array]$AccountSearchProperties,
        [Parameter(Mandatory = $true)]
        [string]$DomainDNSName,
        [Parameter(Mandatory = $false)]
        [PSCredential]$PSMConnectCredentials,
        [Parameter(Mandatory = $false)]
        [PSCredential]$PSMAdminConnectCredentials
    )
    $Accounts = @()
    $ConflictErrors = @()
    Write-LogMessage -Type Verbose -MSG "Retrieving stored accounts in `"$Safe`" safe from vault"
    $ExistingAccountsObj = Get-VaultAccountDetails -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -safe $Safe
    $MatchingAccounts = $ExistingAccountsObj | Where-Object name -In $AccountSearchProperties.AccountName
    Write-LogMessage -type Verbose -MSG ('Found the following existing accounts in the backend: {0}' -f ($MatchingAccounts | Out-String))
    Write-LogMessage -Type Verbose -MSG 'Checking if the found accounts have the correct details'
    foreach ($AccountToCheck in $AccountSearchProperties) {
        $AccountObj = $null
        $AccountType = $AccountToCheck.UserType
        $AccountName = $AccountToCheck.AccountName
        $VaultedAccount = $MatchingAccounts | Where-Object name -EQ $AccountName
        if ($VaultedAccount) {
            $VaultedAccountUsername = $VaultedAccount.userName
            $VaultedAccountAddress = $VaultedAccount.address
            if ($DomainDNSName -eq $VaultedAccountAddress) {
                $VaultedAccountPassword = ConvertTo-SecureString -String 'NoPassword' -AsPlainText -Force
                $AccountObj = [PSCustomObject]@{
                    AccountName = $AccountName
                    UserType    = $AccountType
                    Credentials = New-Object System.Management.Automation.PSCredential($VaultedAccount.userName, $VaultedAccountPassword)
                    Onboard     = $false
                }
            } else {
                Write-LogMessage -type Verbose -MSG "Account with name $AccountName does not have the correct address"
                $NewError = ("An object with Account Name `"{0}`" already exists in the safe `"{1}`" and`n" -f $AccountName, $Safe)
                $NewError += "  its details do not match the specified user details. Its details are shown below.`n"
                $ExistingAccountInfo = @(
                    [PSCustomObject]@{
                        AccountName = $AccountName
                        Username    = $VaultedAccountUsername
                        Address     = $VaultedAccountAddress
                    }
                )
                $NewError += ($ExistingAccountInfo | Format-List | Out-String).Trim()
                $NewError += "`n"
                $ConflictErrors += $NewError
            }
        } else {
            if (($AccountType -eq 'PSMConnect') -and ($PSMConnectCredentials)) {
                $Credentials = $PSMConnectCredentials
            } elseif (($AccountType -eq 'PSMAdminConnect') -and ($PSMAdminConnectCredentials)) {
                $Credentials = $PSMAdminConnectCredentials
            } else {
                $Credentials = Get-Credential -Message "$AccountType account"
            }
            if (-not $Credentials) {
                Write-LogMessage -type Error -MSG "No $AccountType credentials provided. Exiting."
                Stop-ScriptExecutionWithError
            }
            $AccountObj = [PSCustomObject]@{
                AccountName = $AccountName
                UserType    = $AccountType
                Credentials = $Credentials
                Onboard     = $true
            }
        }
        if ($AccountObj) {
            $Accounts += $AccountObj
        }
    }
    return @{
        Accounts       = $Accounts
        ConflictErrors = $ConflictErrors
    }
}

function Resolve-PSMAccountsOffline {
    <#
    .SYNOPSIS
    Collects PSM account usernames interactively when running in LocalConfigurationOnly mode.
    .DESCRIPTION
    Prompts for PSMConnect and PSMAdminConnect usernames when running offline
    (without vault connectivity). Returns account objects with placeholder passwords.
    .PARAMETER AccountSearchProperties
    Array of hashtables with AccountName and UserType.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [array]$AccountSearchProperties
    )
    $Accounts = @()
    $AccountSearchProperties | ForEach-Object {
        $UserType = $PSItem.UserType
        $AccountName = $PSItem.AccountName
        $Username = Read-Host -Prompt ("Pre-Windows 2000 username of the {0} account (without domain, e.g. `"{0}`")" -f $UserType)
        $Password = ConvertTo-SecureString -String 'NoPassword' -AsPlainText -Force
        $AccountObj = [PSCustomObject]@{
            Username    = $Username
            AccountName = $AccountName
            UserType    = $UserType
            Credentials = New-Object System.Management.Automation.PSCredential($Username, $Password)
            Onboard     = $false
        }
        if (-not ($AccountObj.Credentials.Username)) {
            Write-LogMessage -type Error -MSG "$UserType username not provided. Exiting."
            Stop-ScriptExecutionWithError
        }
        $Accounts += $AccountObj
    }
    return $Accounts
}

function Test-PSMUserCredentialFormat {
    <#
    .SYNOPSIS
    Validates the username and password format for all PSM accounts.
    .DESCRIPTION
    Checks each account for invalid username characters/length and invalid password
    characters. Returns an array of error strings. Stops the script if a password
    error is detected (malformed passwords prevent further testing).
    .PARAMETER PSMAccountDetailsArray
    Array of PSM account detail objects, each with UserType and Credentials properties.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [array]$PSMAccountDetailsArray
    )
    $Errors = @()
    foreach ($CurrentUser in $PSMAccountDetailsArray) {
        $UserType = $CurrentUser.UserType
        $Credential = $CurrentUser.Credentials
        Write-LogMessage -type Verbose -MSG "Testing $UserType credential format"

        if (!(Test-CredentialFormat -Credential $Credential)) {
            $NewError = ''
            $NewError += "Username provided for $UserType user contained invalid characters or is too long.`n"
            $NewError += "Please provide the pre-Windows 2000 username without DOMAIN\ or @domain, and ensure`n"
            $NewError += 'the username is no more than 20 characters long'
            $Errors += $NewError
        }

        if (!(Test-PasswordCharactersValid -Credential $Credential)) {
            $NewError = ''
            $NewError += "Password provided for $($Credential.Username) user contained invalid characters.`n"
            $NewError += '  Please include only alphanumeric and the following characters: ~!@#$%^&*_-+=`|(){}[]:;"''<>,.?\/'
            $Errors += $NewError
            return $Errors
        }
    }
    return $Errors
}

function Test-PSMAccountsBeforeOnboarding {
    <#
    .SYNOPSIS
    Tests PSM accounts slated for onboarding against Active Directory.
    .DESCRIPTION
    For each account to be onboarded, validates credentials against the domain,
    searches for the user in AD, and checks the user's PSM configuration.
    Returns user errors and configuration errors.
    .PARAMETER AccountsToOnboard
    Array of account objects with Credentials, UserType, and AccountName.
    .PARAMETER DomainDNSName
    DNS name of the domain to validate credentials against.
    .PARAMETER psmRootInstallLocation
    PSM root installation folder, used for configuration checks.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [array]$AccountsToOnboard,
        [Parameter(Mandatory = $true)]
        [string]$DomainDNSName,
        [Parameter(Mandatory = $true)]
        [string]$psmRootInstallLocation
    )
    $UserErrors = @()
    $ConfigErrors = @()
    foreach ($Account in $AccountsToOnboard) {
        $UserType = $Account.UserType
        $Credential = $Account.Credentials
        $Username = $Credential.Username
        Write-LogMessage -type Verbose -MSG "Testing $Username credentials"
        $TestResult = Test-UserCredential -domain $DomainDNSName -Credential $Credential
        if ('Success' -eq $TestResult) {
            Write-LogMessage -Type Verbose -MSG "$Username user credentials validated"
        } elseif ('InvalidCredentials' -eq $TestResult) {
            Write-LogMessage -Type Verbose -MSG "$Username user credentials incorrect"
            $UserErrors += "Incorrect credentials provided for $Username."
        } elseif ($TestResult -match 'ErrorOccurred.*') {
            $CaughtError = $TestResult -replace '^ErrorOccurred:', ''
            Write-LogMessage -Type Verbose -MSG ("Error occurred while validating $Username user credentials: {0}" -f $CaughtError)
            $UserErrors += ("The following error occurred while validating credentials for $Username against the domain: {0}" -f $CaughtError)
        }
        Write-LogMessage -Type Verbose -MSG ("Searching AD for $Username")
        $UserDN = Get-UserDNFromSamAccountName -Username $Username
        if ($UserDN) {
            Write-LogMessage -Type Verbose -MSG ("Getting $Username user object")
            $UserObject = Get-UserObjectFromDN -DistinguishedName $UserDN
        } else {
            Write-LogMessage -Type Verbose -MSG ("$Username was not found on the domain")
            $NewError = ("User {0} not found in the domain. Please ensure the user exists and`n" -f $Username)
            $NewError += '  that you have provided the pre-Windows 2000 logon name.'
            $UserErrors += $NewError
            continue
        }
        if ($UserObject) {
            Write-LogMessage -Type Verbose -MSG ("Checking $Username user configuration")
            $PSMUserConfigTestResult = Test-PSMUserConfiguration -UserType $UserType -UserObject $UserObject -PSMInstallLocation $psmRootInstallLocation
            Write-LogMessage -Type Verbose -MSG "Successfully checked $Username user configuration"
            if ($PSMUserConfigTestResult) {
                $ConfigErrors += $PSMUserConfigTestResult
            }
        }
    }
    return @{
        UserErrors   = $UserErrors
        ConfigErrors = $ConfigErrors
    }
}

function Format-PSMUserConfigurationErrors {
    <#
    .SYNOPSIS
    Formats PSM user configuration errors into human-readable error messages.
    .DESCRIPTION
    Takes raw configuration error objects and produces formatted error strings showing
    expected vs actual values for each misconfigured setting.
    .PARAMETER UserConfigurationErrors
    Array of configuration error objects returned by Test-PSMUserConfiguration.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [array]$UserConfigurationErrors
    )
    $FormattedErrors = @()
    $UsersWithConfigurationErrors = $UserConfigurationErrors.UserName | Select-Object -Unique
    $UsersWithConfigurationErrors | ForEach-Object {
        $User = $PSItem
        $NewError = ("Configuration errors for {0} in Active Directory user properties:`n" -f $User)
        $ErrorTableSettings = $UserConfigurationErrors | Where-Object UserName -EQ $user | Where-Object SettingType -In 'Value', 'LogOnTo'
        if ($ErrorTableSettings) {
            $NewError += "---------`n"
            $NewError += "Settings:`n"
            $NewError += "---------`n"
            $TableProperties = @(
                @{Name = 'SettingName'; Expression = { $PSItem.SettingName }; Alignment = 'Left' }
                @{Name = 'Expected'; Expression = { $PSItem.Expected }; Alignment = 'Left' }
                @{Name = 'Current'; Expression = { $PSItem.Current }; Alignment = 'Left' }
            )
            $NewError += ($ErrorTableSettings | Format-Table -Wrap -Property $TableProperties | Out-String).Trim()
            $NewError += "`n`n"
        }
        $ListUserConfigurationErrors = $UserConfigurationErrors | Where-Object UserName -EQ $user | Where-Object SettingType -EQ 'StringCompare'
        if ($ListUserConfigurationErrors) {
            $NewError += "------`n"
            $NewError += "Paths:`n"
            $NewError += "------`n"
            foreach ($ConfigErrorSetting in $ListUserConfigurationErrors) {
                $NewError += ("Setting: {0}`n" -f $ConfigErrorSetting.SettingName)
                $NewError += ("Expected value: `"{0}`"`n" -f $ConfigErrorSetting.Expected)
                if ($ConfigErrorSetting.Current -eq 'Unset') {
                    $NewError += "Detected value: Unset`n"
                } else {
                    $DifferencePosition = Get-DifferencePosition -String1 $ConfigErrorSetting.Expected -String2 $ConfigErrorSetting.Current
                    $NewError += ("Detected value: `"{0}`"`n" -f $ConfigErrorSetting.Current)
                    $NewError += ("                ` {0}^`n" -f (' ' * $DifferencePosition))
                    $NewError += "`n`n"
                }
            }
        }
        $FormattedErrors += $NewError.trim()
    }
    if ('Unset' -in $UserConfigurationErrors.Current) {
        $FormattedErrors += "Errors occurred while retrieving some user properties, which usually means they do not exist. These will show as `"Unset`" above.`n"
    }
    return $FormattedErrors
}

function Initialize-VaultResources {
    <#
    .SYNOPSIS
    Creates the PSM platform, safe, and onboards PSM accounts in the vault.
    .DESCRIPTION
    Ensures the PSM platform exists (creating from WinDomain if needed), the PSM safe
    exists, Vault Admins has permissions, and all pending accounts are onboarded.
    Returns tasks that require manual follow-up.
    .PARAMETER pvwaAddress
    PVWA base URL.
    .PARAMETER pvwaToken
    Session token for PVWA API calls.
    .PARAMETER PlatformName
    Platform name for PSM accounts.
    .PARAMETER Safe
    Safe name for PSM accounts.
    .PARAMETER AccountsToOnboard
    Array of account objects with Credentials, AccountName, and UserType.
    .PARAMETER DomainDNSName
    DNS name of the domain.
    .PARAMETER PSMConnectAccountName
    Account name used for the PSMConnect object in the vault.
    .PARAMETER PSMAdminConnectAccountName
    Account name used for the PSMAdminConnect object in the vault.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$pvwaAddress,
        [Parameter(Mandatory = $true)]
        [string]$pvwaToken,
        [Parameter(Mandatory = $true)]
        [string]$PlatformName,
        [Parameter(Mandatory = $true)]
        [string]$Safe,
        [Parameter(Mandatory = $true)]
        [array]$AccountsToOnboard,
        [Parameter(Mandatory = $true)]
        [string]$DomainDNSName,
        [Parameter(Mandatory = $true)]
        [string]$PSMConnectAccountName,
        [Parameter(Mandatory = $true)]
        [string]$PSMAdminConnectAccountName
    )
    $Tasks = @()
    Write-LogMessage -type Info -MSG 'Starting backend configuration'
    # Create platform if required
    Write-LogMessage -Type Verbose -MSG 'Checking current platform status'
    $platformStatus = Get-PlatformStatus -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -PlatformId $PlatformName
    if ($platformStatus -eq $false) {
        $WinDomainPlatform = Get-PlatformStatusById -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -PlatformId WinDomain
        if ($WinDomainPlatform) {
            Write-LogMessage -Type Verbose -MSG 'Checking Windows Domain platform status'
            $WinDomainPlatformId = $WinDomainPlatform.Id
        } else {
            Write-LogMessage -type Error -MSG 'Could not find Windows Domain platform to duplicate. Please import it from the marketplace.'
            Stop-ScriptExecutionWithError
        }
        Write-LogMessage -Type Verbose -MSG 'Creating new platform'
        Copy-Platform -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -CurrentPlatformId $WinDomainPlatformId -NewPlatformName $PlatformName -NewPlatformDescription 'Platform for PSM accounts'
        $Tasks += @{
            Message  = ("Set appropriate policies and settings on platform `"{0}`"" -f $PlatformName)
            Priority = 'Recommended'
        }
        $platformStatus = Get-PlatformStatus -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -PlatformId $PlatformName
    }
    if ($platformStatus.Active -eq $false) {
        Write-LogMessage -Type Verbose -MSG 'Platform is deactivated. Activating.'
        Enable-Platform -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -PlatformNumId $platformStatus.Id
    }
    # Create safe if required
    Write-LogMessage -Type Verbose -MSG 'Checking current safe status'
    $safeStatus = Get-SafeStatus -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -SafeName $Safe
    if ($safeStatus -eq $false) {
        Write-LogMessage -Type Verbose -MSG "Safe $Safe does not exist. Creating the safe now"
        $CreateSafeResult = New-PSMSafe -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -safe $Safe
        if ($CreateSafeResult) {
            Write-LogMessage -type Verbose -MSG "Successfully created safe $Safe"
        } else {
            Write-LogMessage -Type Error -MSG "Creating PSM safe $Safe failed. Please resolve the error and try again."
            Stop-ScriptExecutionWithError
        }
    }
    # Ensure Vault Admins has full permissions on the PSM safe
    $SafePermissions = Get-SafePermissions -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -safe $Safe -safeMember 'Vault Admins'
    if ($false -eq $SafePermissions) {
        Write-LogMessage -Type Verbose -MSG 'Granting administrators access to PSM safe'
        New-SafePermissions -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -safe $Safe -safeMember 'Vault Admins'
    }
    # Onboard PSM users
    foreach ($AccountToOnboard in $AccountsToOnboard) {
        $NewCredentials = $AccountToOnboard.Credentials
        $NewUserName = $AccountToOnboard.UserName
        $NewAccountName = $AccountToOnboard.AccountName
        Write-LogMessage -type Verbose -MSG ('Onboarding {0}' -f $NewUserName)
        Write-LogMessage -Type Verbose -MSG 'Onboarding Account'
        $OnboardResult = New-VaultAdminObject -pvwaAddress $pvwaAddress -pvwaToken $pvwaToken -name $NewAccountName -domain $DomainDNSName -Credentials $NewCredentials -platformID $PlatformName -safe $Safe
        if ($OnboardResult.name) {
            Write-LogMessage -Type Verbose -MSG 'User successfully onboarded'
        } elseif ($OnboardResult.ErrorCode -eq 'PASWS027E') {
            $UserType = $AccountToOnboard.UserType
            Write-LogMessage -Type Warning -MSG "Object with name $NewAccountName already exists. Please verify that it contains correct"
            Write-LogMessage -Type Warning -MSG "  $UserType account details, or specify an alternative account name."
            $Tasks += @{
                Message  = ('Verify that the {0} object in {1} safe contains correct {2} user details' -f $NewAccountName, $Safe, $UserType)
                Priority = 'Required'
            }
        } else {
            Write-LogMessage -Type Error -MSG ('Error onboarding account: {0}' -f $OnboardResult)
            Stop-ScriptExecutionWithError
        }
    }
    return $Tasks
}

function Update-SecurityPolicyForPSM {
    <#
    .SYNOPSIS
    Configures Local Security Policy to allow PSM users to connect via Remote Desktop.
    .DESCRIPTION
    Exports the current security policy, adds the PSM users to SeRemoteInteractiveLogonRight,
    and applies the updated policy. Returns tasks requiring manual follow-up if the
    automatic update fails.
    .PARAMETER PSMConnectDomainUser
    Full DOMAIN\Username for the PSMConnect user.
    .PARAMETER PSMAdminConnectDomainUser
    Full DOMAIN\Username for the PSMAdminConnect user.
    .PARAMETER BackupPath
    Folder to use for secedit export and working files.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$PSMConnectDomainUser,
        [Parameter(Mandatory = $true)]
        [string]$PSMAdminConnectDomainUser,
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )
    $Tasks = @()
    if (-not (Test-Path -Path $BackupPath -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $BackupPath
    }
    $CurrentSecurityPolicyFile = "$BackupPath\CurrentSecurityPolicy.cfg"
    $GetSecPolResult = Get-CurrentSecurityPolicy -OutFile $CurrentSecurityPolicyFile -LogFile $BackupPath\SeceditExport.log
    if ($false -eq $GetSecPolResult) {
        Write-LogMessage -type Verbose -MSG 'Security policy export failed, so the current policy will not be modified.'
        Write-LogMessage -type Verbose -MSG 'Please edit local security policy manually to allow PSM users to log on with Remote Desktop.'
        $Tasks += @{
            Message  = 'Configure Local Security Policy to allow PSM users to log on with Remote Desktop'
            Priority = 'Required'
        }
        return $Tasks
    }
    $Content = Get-Content $CurrentSecurityPolicyFile
    $null = $Content | Where-Object { $PSItem -match '^SeRemoteInteractiveLogonRight = (.*)' }
    $SecPolCurrentUsersString = $Matches[1]
    $SecPolUsersArray = ($SecPolCurrentUsersString -split ',')
    $SecPolUsersArray += @($PSMConnectDomainUser, $PSMAdminConnectDomainUser)
    $SecPolNewUsersString = $SecPolUsersArray -join ','
    $null = New-Item -Path "$BackupPath\newsecpol.cfg" -ItemType File -Force
    Add-Content -Path "$BackupPath\newsecpol.cfg" -Value '[Version]'
    Add-Content -Path "$BackupPath\newsecpol.cfg" -Value 'signature="$CHICAGO$"'
    Add-Content -Path "$BackupPath\newsecpol.cfg" -Value 'Revision=1'
    Add-Content -Path "$BackupPath\newsecpol.cfg" -Value '[Privilege Rights]'
    Add-Content -Path "$BackupPath\newsecpol.cfg" -Value ('SeRemoteInteractiveLogonRight = {0}' -f $SecPolNewUsersString)
    $SetSecPolResult = Set-CurrentSecurityPolicy -DatabaseFile $BackupPath\SecurityPolicy.sdb -ConfigFile $BackupPath\newsecpol.cfg -LogFile $BackupPath\SecPolImport.log
    if ($false -eq $SetSecPolResult) {
        Write-LogMessage -type Error -MSG 'Failed to configure local security policy.'
        Write-LogMessage -type Warning -MSG 'Please edit local security policy manually to allow PSM users to log on with Remote Desktop.'
        $Tasks += @{
            Message  = 'Configure Local Security Policy to allow PSM users to log on with Remote Desktop'
            Priority = 'Required'
        }
    }
    return $Tasks
}

function Add-PSMUsersToRemoteDesktopUsers {
    <#
    .SYNOPSIS
    Adds PSM domain users to the local Remote Desktop Users group.
    .DESCRIPTION
    Attempts to add the PSMConnect and PSMAdminConnect users to the Remote Desktop Users
    group. Returns tasks requiring manual follow-up if the operation fails.
    .PARAMETER PSMConnectDomainUser
    Full DOMAIN\Username for the PSMConnect user.
    .PARAMETER PSMAdminConnectDomainUser
    Full DOMAIN\Username for the PSMAdminConnect user.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$PSMConnectDomainUser,
        [Parameter(Mandatory = $true)]
        [string]$PSMAdminConnectDomainUser
    )
    $Tasks = @()
    try {
        $Members = (Get-LocalGroupMember -Group 'Remote Desktop Users').Name
        if ($PSMConnectDomainUser -notin $Members) {
            try {
                Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $PSMConnectDomainUser -ErrorAction Stop
            } catch {
                Write-LogMessage -type Error -MSG "An error occured while adding $PSMConnectDomainUser to the `"Remote Desktop Users`" group. Please add it manually."
            }
        }
        if ($PSMAdminConnectDomainUser -notin $Members) {
            try {
                Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $PSMAdminConnectDomainUser -ErrorAction Stop
            } catch {
                Write-LogMessage -type Error -MSG "An error occured while adding $PSMAdminConnectDomainUser to the `"Remote Desktop Users`" group. Please add it manually."
            }
        }
    } catch {
        Write-LogMessage -type Error -MSG $PSItem.Exception.Message
        Write-LogMessage -type Error -MSG 'Failed to add PSM users to Remote Desktop Users group. Please add these users manually.'
        $Tasks += @{
            Message  = 'Add PSM users to Remote Desktop Users group'
            Priority = 'Required'
        }
    }
    return $Tasks
}

function Invoke-LocalPSMConfiguration {
    <#
    .SYNOPSIS
    Performs local PSM configuration: stops the service, backs up files, updates config,
    and configures Terminal Services for PSMAdminConnect.
    .DESCRIPTION
    Backs up and updates PSMHardening.ps1, PSMConfigureAppLocker.ps1, and basic_psm.ini,
    then configures Terminal Services to allow PSMAdminConnect to shadow sessions.
    Returns tasks requiring manual follow-up on partial failures.
    .PARAMETER psmRootInstallLocation
    PSM root installation folder.
    .PARAMETER DomainDNSName
    DNS name of the domain.
    .PARAMETER DomainNetbiosName
    NETBIOS name of the domain.
    .PARAMETER PSMConnectCredentials
    Credentials for the PSMConnect user.
    .PARAMETER PSMAdminConnectCredentials
    Credentials for the PSMAdminConnect user.
    .PARAMETER PSMAdminConnectAccountName
    Account name for PSMAdminConnect in basic_psm.ini.
    .PARAMETER IgnoreShadowPermissionErrors
    When set, warnings are issued for TS shadow errors instead of failing.
    .PARAMETER REGKEY_PSMSERVICE
    Service name for the PSM Windows service.
    .PARAMETER BackupPath
    Folder to use for PSM configuration file backups.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$psmRootInstallLocation,
        [Parameter(Mandatory = $true)]
        [string]$DomainDNSName,
        [Parameter(Mandatory = $true)]
        [string]$DomainNetbiosName,
        [Parameter(Mandatory = $true)]
        [PSCredential]$PSMConnectCredentials,
        [Parameter(Mandatory = $true)]
        [PSCredential]$PSMAdminConnectCredentials,
        [Parameter(Mandatory = $true)]
        [string]$PSMAdminConnectAccountName,
        [Parameter(Mandatory = $false)]
        [switch]$IgnoreShadowPermissionErrors,
        [Parameter(Mandatory = $true)]
        [string]$REGKEY_PSMSERVICE,
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )
    $Tasks = @()
    Write-LogMessage -Type Info -MSG 'Performing local configuration and restarting service'
    Write-LogMessage -Type Verbose -MSG 'Stopping CyberArk Privileged Session Manager Service'
    Stop-Service $REGKEY_PSMSERVICE
    Write-LogMessage -Type Verbose -MSG 'Backing up PSM configuration files and scripts'
    Backup-PSMConfig -psmRootInstallLocation $psmRootInstallLocation -BackupPath $BackupPath
    Write-LogMessage -Type Verbose -MSG 'Updating PSM configuration files and scripts'
    Update-PSMConfig -psmRootInstallLocation $psmRootInstallLocation -PSMAdminConnectAccountName $PSMAdminConnectAccountName
    Write-LogMessage -Type Verbose -MSG 'Adding PSMAdminConnect user to Terminal Services configuration'
    $AddAdminUserToTSResult = Add-AdminUserToTS -NETBIOS $DomainNetbiosName -Credentials $PSMAdminConnectCredentials
    if ($AddAdminUserToTSResult.ReturnValue -eq 0) {
        Write-LogMessage -Type Verbose -MSG 'Successfully added PSMAdminConnect user to Terminal Services configuration'
    } else {
        if ($IgnoreShadowPermissionErrors) {
            Write-LogMessage -Type Warning -MSG 'Failed to add PSMAdminConnect user to Terminal Services configuration with error:'
            Write-LogMessage -Type Warning -MSG ('  {0}' -f $AddAdminUserToTSResult.Error)
            Write-LogMessage -Type Warning -MSG "Continuing because `"-IgnoreShadowPermissionErrors`" switch enabled"
            $Tasks += @{
                Message  = 'Resolve issue preventing PSMAdminConnect user being added to Terminal Services configuration and rerun this script'
                Priority = 'Required'
            }
        } else {
            Write-LogMessage -Type Error -MSG 'Failed to add PSMAdminConnect user to Terminal Services configuration with error:'
            Write-LogMessage -Type Error -MSG ('  {0}' -f $AddAdminUserToTSResult.Error)
            Write-LogMessage -Type Error -MSG "Run this script with the `"-IgnoreShadowPermissionErrors`" switch to ignore this error"
            Write-LogMessage -Type Error -MSG 'Exiting.'
            Stop-ScriptExecutionWithError
        }
    }
    if ($AddAdminUserToTSResult.ReturnValue -eq 0) {
        Write-LogMessage -Type Verbose -MSG 'Granting PSMAdminConnect user permission to shadow sessions'
        $AddAdminUserTSShadowPermissionResult = Add-AdminUserTSShadowPermission -NETBIOS $DomainNetbiosName -Credentials $PSMAdminConnectCredentials
        if ($AddAdminUserTSShadowPermissionResult.ReturnValue -eq 0) {
            Write-LogMessage -Type Verbose -MSG 'Successfully granted PSMAdminConnect permission to shadow sessions'
        } else {
            if ($IgnoreShadowPermissionErrors) {
                Write-LogMessage -Type Warning -MSG $AddAdminUserTSShadowPermissionResult.Error
                Write-LogMessage -Type Warning -MSG 'Failed to grant PSMAdminConnect permission to shadow sessions.'
                Write-LogMessage -Type Warning -MSG "Continuing because `"-IgnoreShadowPermissionErrors`" switch enabled"
                $Tasks += @{
                    Message  = 'Resolve issue preventing PSMAdminConnect user being granted permission to shadow sessions and rerun this script.'
                    Priority = 'Required'
                }
            } else {
                Write-LogMessage -Type Error -MSG $AddAdminUserTSShadowPermissionResult.Error
                Write-LogMessage -Type Error -MSG 'Failed to grant PSMAdminConnect permission to shadow sessions.'
                Write-LogMessage -Type Error -MSG 'Please see the following article for information on resolving this error'
                Write-LogMessage -Type Error -MSG 'https://cyberark-customers.force.com/s/article/PSM-Unable-to-run-WMIC-command'
                Write-LogMessage -Type Error -MSG "Run this script with the `"-IgnoreShadowPermissionErrors`" switch to ignore this error"
                Stop-ScriptExecutionWithError
            }
        }
    }
    return $Tasks
}

# End of function definitions

# Running Set-DomainUser script
$OperationsToPerform = @{
    GetVaultAdminCredentials        = $true
    TestVaultAdminCredentials       = $true
    UserTests                       = $true
    GetPVWAUrl                      = $true
    DomainNetbiosNameDetection      = $true
    DomainDNSNameDetection          = $true
    PsmLocalConfiguration           = $true
    SecurityPolicyConfiguration     = $true
    RemoteDesktopUsersGroupAddition = $true
    CreateSafePlatformAndAccounts   = $true
    ServerObjectConfiguration       = $true
    Hardening                       = $true
    ConfigureAppLocker              = $true
}

# Determine what operations need to be performed
switch ($PSBoundParameters) {
    { $PSItem.NotFirstRun } {
        Write-LogMessage -type Warning -MSG '-NotFirstRun is no longer recommended, as Set-DomainUser will automatically detect and skip redundant steps.'
        $OperationsToPerform.UserTests = $false
        $OperationsToPerform.CreateSafePlatformAndAccounts = $false
    }
    { $PSItem.SkipPSMUserTests } {
        $OperationsToPerform.UserTests = $false
    }
    { $PSItem.PVWAUrl } {
        $OperationsToPerform.GetPVWAUrl = $false
    }
    { $PSItem.DomainNetbiosName } {
        $OperationsToPerform.DomainNetbiosNameDetection = $false
    }
    { $PSItem.DomainDNSName } {
        $OperationsToPerform.DomainDNSNameDetection = $false
    }
    { $PSItem.LocalConfigurationOnly } {
        $OperationsToPerform.CreateSafePlatformAndAccounts = $false
        $OperationsToPerform.ServerObjectConfiguration = $false
        $OperationsToPerform.UserTests = $false
        $OperationsToPerform.GetVaultAdminCredentials = $false
        $OperationsToPerform.TestVaultAdminCredentials = $false
    }
    { $PSItem.DoNotHarden } {
        $OperationsToPerform.Hardening = $false
    }
    { $PSItem.SkipPSMObjectUpdate } {
        $OperationsToPerform.ServerObjectConfiguration = $false
    }
    { $PSItem.SkipSecurityPolicyConfiguration } {
        $OperationsToPerform.SecurityPolicyConfiguration = $false
    }
    { $PSItem.SkipAddingUsersToRduGroup } {
        $OperationsToPerform.RemoteDesktopUsersGroupAddition = $false
    }
    { $PSItem.DoNotConfigureAppLocker } {
        $OperationsToPerform.ConfigureAppLocker = $false
    }
}

if ($VaultAdmin) {
    $OperationsToPerform.GetVaultAdminCredentials = $false
}

# Initialize variables
$StandardSeparator = ('-' * 50)
$SectionSeparator = ('#' * 50)
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent
$global:InDebug = $PSBoundParameters.ContainsKey('Debug')
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
$global:LOG_FILE_PATH = "$ScriptLocation\_Set-DomainUser.log"
$PsmServiceNames = 'Cyber-Ark Privileged Session Manager', 'CyberArk Privileged Session Manager'
$PsmService = Get-CimInstance win32_service | Where-Object Name -In $PsmServiceNames
$psmRootInstallLocation = (($PsmService.PathName) -replace 'CAPSM.exe.*', '' -replace ('"', '')).Trim()
$REGKEY_PSMSERVICE = $PsmService.Name
$BackupSubDirectory = (Get-Date).ToString('yyyMMdd-HHmmss')
$BackupPath = "$psmRootInstallLocation\Backup\Set-DomainUser\$BackupSubDirectory"
$ValidationFailed = $false
$PSMServerId = Get-PSMServerId -psmRootInstallLocation $psmRootInstallLocation
$pvwaToken = ''
$PSMAccountDetailsArray = @()
$TasksTop = @()

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-LogMessage -type Info -MSG ''
Write-LogMessage -type Info -MSG 'Gathering information'

# Perform initial checks
## Proxy configuration
$Proxy = Get-ProxyDetails

if (!($Proxy)) {
    $Proxy = 'None'
}

## Check if domain user
Test-UserDomainJoined

## Get PVWA URL
if ($OperationsToPerform.GetPVWAUrl) {
    $PVWAUrl = Get-PvwaAddress -psmRootInstallLocation $psmRootInstallLocation
}
# Normalise: strip trailing slash only. The URL is used as-is as the application base.
# Accepts: https://pvwa.lab.local              (API at /api/...)
#          https://pvwa.lab.local/PasswordVault (API at /PasswordVault/api/...)
#          https://pvwa.lab.local/OurVault      (API at /OurVault/api/...)
$PVWAUrl = $PVWAUrl.TrimEnd('/')

## Identify AD domain
$DomainNameAutodetected = $false
if ($OperationsToPerform.DomainDNSNameDetection) {
    $DomainNameAutodetected = $true
    $DomainDNSName = Get-DomainDnsName
}
if ($OperationsToPerform.DomainNetbiosNameDetection) {
    $DomainNameAutodetected = $true
    $DomainNetbiosName = Get-DomainNetbiosName
}

# Confirm VaultOperationsTester and VC++ are present
if ($OperationsToPerform.ServerObjectConfiguration) {
    $VaultOperationsTesterDir = Get-VaultOperationsTesterPath -ScriptLocation $ScriptLocation
}

# Validate detected AD domain details
if ($DomainNameAutodetected) {
    if (-not (Confirm-AutodetectedDomainDetails -DomainDNSName $DomainDNSName -DomainNetbiosName $DomainNetbiosName)) {
        $ValidationFailed = $true
    }
}

# Gather vault administrator credentials
Write-LogMessage -Type Verbose -MSG 'Getting vault administrator credentials if required'
if ($OperationsToPerform.GetVaultAdminCredentials) {
    $VaultAdmin = Get-Credential -Message ('Please enter vault administrator credentials')
    if (!($VaultAdmin)) {
        Write-LogMessage -Type Error -MSG 'No vault administrator credentials provided. Exiting.'
        Stop-ScriptExecutionWithError
    }
}

## Test vault administrator credentials
if ($OperationsToPerform.TestVaultAdminCredentials) {
    $pvwaToken = Connect-PVWAAndGetToken -pvwaAddress $PVWAUrl -VaultAdmin $VaultAdmin -AuthenticationType $AuthenticationType
}

if ($ValidationFailed) {
    Write-LogMessage -type Info -MSG 'Some tests failed, and details are shown above. Please correct these and rerun Set-DomainUser.'
    Stop-ScriptExecutionWithError
}

Write-LogMessage -type Info -MSG 'Validating PSM user details'
# Create array containing PSM user details we can iterate through
$PSMAccountSearchPropertiesArray = @(
    @{
        AccountName = $PSMConnectAccountName
        UserType    = 'PSMConnect'
    },
    @{
        AccountName = $PSMAdminConnectAccountName
        UserType    = 'PSMAdminConnect'
    }
)

# If online, search backend for PSM user details and request credentials as required
if ($pvwaToken) {
    $AccountResult = Resolve-PSMAccountsFromVault -pvwaAddress $PVWAUrl -pvwaToken $pvwaToken -Safe $Safe -AccountSearchProperties $PSMAccountSearchPropertiesArray -DomainDNSName $DomainDNSName -PSMConnectCredentials $PSMConnectCredentials -PSMAdminConnectCredentials $PSMAdminConnectCredentials
    $PSMAccountDetailsArray = $AccountResult.Accounts
    $ArrayOfUserOnboardingConflictErrors = $AccountResult.ConflictErrors
    if ($ArrayOfUserOnboardingConflictErrors) {
        $ValidationFailed = $true
    }
}

# Request user details if running in LocalConfigurationOnly mode
if (-not $pvwaToken) {
    $PSMAccountDetailsArray = Resolve-PSMAccountsOffline -AccountSearchProperties $PSMAccountSearchPropertiesArray
}

# Test users
#Initialize arrays which will capture detected misconfigurations
$UserConfigurationErrors = @()
$ArrayOfUserErrors = @()

# For each user in $PSMAccountDetailsArray
## Check username format
## Check password format
## If UserTests enabled
### Check credentials
### Search for user
### ONLY IF FOUND, check user configuration

## Test PSM user credential format
$ArrayOfUserErrors += Test-PSMUserCredentialFormat -PSMAccountDetailsArray $PSMAccountDetailsArray

# Test PSM user configuration before onboarding
$AccountsToOnboard = $PSMAccountDetailsArray | Where-Object Onboard -EQ $true
if (($AccountsToOnboard) -and ($OperationsToPerform.UserTests)) {
    $UserTestResult = Test-PSMAccountsBeforeOnboarding -AccountsToOnboard $AccountsToOnboard -DomainDNSName $DomainDNSName -psmRootInstallLocation $psmRootInstallLocation
    $ArrayOfUserErrors += $UserTestResult.UserErrors
    if ($UserTestResult.UserErrors) {
        $ValidationFailed = $true
    }
    if ($UserTestResult.ConfigErrors) {
        $UserConfigurationErrors = $UserTestResult.ConfigErrors
    }
}

# List detected PSM user configuration errors
Write-LogMessage -Type Verbose -MSG 'Checking for user configuration errors'
if ($UserConfigurationErrors) {
    $ArrayOfUserErrors += Format-PSMUserConfigurationErrors -UserConfigurationErrors $UserConfigurationErrors
    $ValidationFailed = $true
}

Write-LogMessage -type Verbose -MSG 'Completed validation of PSM user configuration'

if ($ArrayOfUserErrors) {
    Write-LogMessage -type Error -MSG $SectionSeparator
    Write-LogMessage -type Error -MSG 'The following errors occurred while validating the PSM user details.'
    Write-LogMessage -type Error -MSG 'These tests may be skipped by running Set-DomainUser with the -SkipPSMUserTests parameter.'
    foreach ($UserError in $ArrayOfUserErrors) {
        Write-LogMessage -type Error -MSG $StandardSeparator
        Write-LogMessage -type Error -MSG $UserError
    }
}

if ($ArrayOfUserOnboardingConflictErrors) {
    Write-LogMessage -type Error -MSG $SectionSeparator
    Write-LogMessage -type Error -MSG 'PSM users exist in the vault with details that do not match this environment.'
    Write-LogMessage -type Error -MSG 'See below for comparisons of the conflicting users.'
    foreach ($UserConflict in $ArrayOfUserOnboardingConflictErrors) {
        Write-LogMessage -type Error -MSG $StandardSeparator
        Write-LogMessage -type Error -MSG $UserConflict
    }
    Write-LogMessage -type Error -MSG 'Use -PSMConnectAccountName, -PSMAdminConnectAccountName and -Safe parameters'
    Write-LogMessage -type Error -MSG 'to provide alternative details for this environment.'
}

if ($ValidationFailed) {
    Write-LogMessage -type Info -MSG 'Some tests failed, and details are shown above. Please correct these and rerun Set-DomainUser.'
    Stop-ScriptExecutionWithError
}

Write-LogMessage -type Verbose -MSG 'All inputs successfully passed validation'

$PSMConnectCredentials = ($PSMAccountDetailsArray | Where-Object UserType -EQ 'PSMConnect').Credentials
$PSMConnectUsername = $PSMConnectCredentials.UserName
$PSMConnectDomainBSUser = ('{0}\{1}' -f $DomainNetbiosName, $PSMConnectCredentials.UserName)

$PSMAdminConnectCredentials = ($PSMAccountDetailsArray | Where-Object UserType -EQ 'PSMAdminConnect').Credentials
$PSMAdminConnectUsername = $PSMAdminConnectCredentials.UserName
$PSMAdminConnectDomainBSUser = ('{0}\{1}' -f $DomainNetbiosName, $PSMAdminConnectCredentials.UserName)

# Perform Remote Configuration
if ($OperationsToPerform.CreateSafePlatformAndAccounts) {
    $VaultResourcesArgs = @{
        pvwaAddress                = $PVWAUrl
        pvwaToken                  = $pvwaToken
        PlatformName               = $PlatformName
        Safe                       = $Safe
        AccountsToOnboard          = $AccountsToOnboard
        DomainDNSName              = $DomainDNSName
        PSMConnectAccountName      = $PSMConnectAccountName
        PSMAdminConnectAccountName = $PSMAdminConnectAccountName
    }
    $TasksTop += Initialize-VaultResources @VaultResourcesArgs
}

# Configure PSMServer object
if ($OperationsToPerform.ServerObjectConfiguration) {
    $VaultAddress = Get-VaultAddress -psmRootInstallLocation $psmRootInstallLocation
    $VotArgs = @{
        VaultAddress               = $VaultAddress
        VaultCredentials           = $VaultAdmin
        PSMServerId                = $PSMServerId
        VaultOperationsFolder      = $VaultOperationsTesterDir
        PSMSafe                    = $Safe
        PSMConnectAccountName      = $PSMConnectAccountName
        PSMAdminConnectAccountName = $PSMAdminConnectAccountName
        Proxy                      = $Proxy
    }
    Set-PSMServerObject @VotArgs
}

## End Remote Configuration Block

# Group membership and security policy changes
if ($OperationsToPerform.SecurityPolicyConfiguration) {
    $TasksTop += Update-SecurityPolicyForPSM -PSMConnectDomainUser $PSMConnectDomainBSUser -PSMAdminConnectDomainUser $PSMAdminConnectDomainBSUser -BackupPath $BackupPath
} else {
    $TasksTop += @{
        Message  = 'Configure Local Security Policy to allow PSM users to log on with Remote Desktop'
        Priority = 'Required'
    }
}

$TasksTop += @{
    Message  = 'Configure domain GPOs to allow PSM users to log on to PSM servers with Remote Desktop'
    Priority = 'Required'
}

if ($OperationsToPerform.RemoteDesktopUsersGroupAddition) {
    $TasksTop += Add-PSMUsersToRemoteDesktopUsers -PSMConnectDomainUser $PSMConnectDomainBSUser -PSMAdminConnectDomainUser $PSMAdminConnectDomainBSUser
} else {
    $TasksTop += @{
        Message  = 'Add PSM users to Remote Desktop Users group'
        Priority = 'Required'
    }
}

# End group membership and security policy changes

# Perform local configuration
if ($OperationsToPerform.PsmLocalConfiguration) {
    $LocalConfigArgs = @{
        psmRootInstallLocation       = $psmRootInstallLocation
        DomainDNSName                = $DomainDNSName
        DomainNetbiosName            = $DomainNetbiosName
        PSMConnectCredentials        = $PSMConnectCredentials
        PSMAdminConnectCredentials   = $PSMAdminConnectCredentials
        PSMAdminConnectAccountName   = $PSMAdminConnectAccountName
        IgnoreShadowPermissionErrors = $IgnoreShadowPermissionErrors
        REGKEY_PSMSERVICE            = $REGKEY_PSMSERVICE
        BackupPath                   = $BackupPath
    }
    $TasksTop += Invoke-LocalPSMConfiguration @LocalConfigArgs
}
## End Local Configuration Block

# Post-configuration
## Invoke hardening scripts and restart service
if ($OperationsToPerform.Hardening) {
    Invoke-PSMHardening -psmRootInstallLocation $psmRootInstallLocation -DomainNetbiosName $DomainNetbiosName -PSMConnectUsername $PSMConnectUsername -PSMAdminConnectUsername $PSMAdminConnectUsername
} else {
    Write-LogMessage -Type Warning -MSG 'Skipping Hardening due to -DoNotHarden parameter'
    $TasksTop += @{
        Message  = 'Run script to perform server hardening (PSMHardening.ps1)'
        Priority = 'Required'
    }
}
if ($OperationsToPerform.ConfigureAppLocker) {
    Invoke-PSMConfigureAppLocker -psmRootInstallLocation $psmRootInstallLocation -DomainNetbiosName $DomainNetbiosName -PSMConnectUsername $PSMConnectUsername -PSMAdminConnectUsername $PSMAdminConnectUsername
} else {
    Write-LogMessage -Type Warning -MSG 'Skipping configuration of AppLocker due to -DoNotConfigureAppLocker parameter'
    $TasksTop += @{
        Message  = 'Run script to configure AppLocker (PSMConfigureAppLocker.ps1)'
        Priority = 'Required'
    }
}
Write-LogMessage -Type Verbose -MSG 'Restarting CyberArk Privileged Session Manager Service'
if ($false -eq $NoPSMRestart) {
    Restart-Service $REGKEY_PSMSERVICE
}

Write-LogMessage -Type Success -MSG 'All tasks completed.'

$RequiredTasks = @()
if ($SkipPSMObjectUpdate -or $LocalConfigurationOnly) {
    $RequiredTasks += @(
        @{
            Message  = @"
Update the PSM Server configuration:
     a. Log in to CyberArk PVWA as an administrative user
     b. Go to Administration -> Configuration Options
     c. Expand Privileged Session Management -> Configured PSM Servers -> $PSMServerId ->
          Connection Details -> Server
     d. Configure the following:
          Safe: $Safe
          Object: $PSMConnectAccountName
          AdminObject: $PSMAdminConnectAccountName
"@
            Priority = 'Required'
        }
    )
}

$TasksTop += @{
    Message  = ('Enable automatic password management for the PSM accounts')
    Priority = 'Recommended'
}

# Display summary and additional tasks
$RequiredTasks += $TasksTop | Where-Object Priority -EQ 'Required'
$RequiredTasks += @{ Message = 'Restart Server'; Priority = 'Required' }
$RecommendedTasks = $TasksTop | Where-Object Priority -NE 'Required'

# Print recommended tasks

Write-LogMessage -type Info -MSG $SectionSeparator
$string = 'The following additional steps are recommended:'
Write-LogMessage -type Info -MSG ($string)

$i = 1
foreach ($Task in $RecommendedTasks) {
    Write-LogMessage -Type Info -MSG (' {0:D2}. {1}' -f $i, $Task.Message)
    $i++
}

Write-LogMessage -type Info -MSG ' ' # Print a gap

# Print required tasks

Write-LogMessage -type Info -MSG $SectionSeparator
$string = 'The following additional tasks MUST be completed:'
Write-LogMessage -type Info -MSG ($string)

$i = 1
foreach ($Task in $RequiredTasks) {
    Write-LogMessage -Type Info -MSG (' {0:D2}. {1}' -f $i, $Task.Message)
    $i++
}

Write-LogMessage -type Info -MSG ' '
