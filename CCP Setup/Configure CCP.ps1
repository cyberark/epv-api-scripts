<# 
###########################################################################

NAME: 
    CCPSetup 

AUTHOR:  
    Brian Bors  <brian.bors@cyberark.com>

COMMENT: 
    Script used to setup and configure a CCP Post Install

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

    [Parameter(Mandatory=$false,HelpMessage="Vault Stored Credentials")]
    [PSCredential]$PVWACredentials,

    # Use this switch to Disable SSL verification (NOT RECOMMENDED)
    [Parameter(Mandatory=$false)]
    [Switch]$DisableSSLVerify
)

$AIMWebServicepath = "C:\inetpub\wwwroot\AIMWebService\bin\AIMWebService.dll"
$osuser = "IIS APPPOOL\DefaultAppPool"
$NETAIMGetAppInfo = "C:\Program Files (x86)\CyberArk\ApplicationPasswordProvider\Utils\NETAIMGetAppInfo.exe"

#region Writer Functions
$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent
$oldverbose = $VerbosePreference
if($InVerbose){
    $VerbosePreference = "continue"
}
If ($null -ne $PSCredentials) {New-Variable -Scope Global -Name G_PSCredentials -Value $PSCredentials}

# Get Script Location 
$ScriptFullPath = $MyInvocation.MyCommand.Path
$ScriptLocation = Split-Path -Parent $ScriptFullPath
$ScriptParameters = @()
$PSBoundParameters.GetEnumerator() | ForEach-Object { $ScriptParameters += ("-{0} '{1}'" -f $_.Key, $_.Value) }
$Script:g_ScriptCommand = "{0} {1}" -f $ScriptFullPath, $($ScriptParameters -join ' ')

# Script Version
$ScriptVersion = "0.10"

# Set Log file path
New-Variable -Name LOG_FILE_PATH -Value "$ScriptLocation\$(($MyInvocation.MyCommand.Name).Replace("ps1","log"))" -Scope Global -Force
New-Variable -Name PVWAURL -Value $PVWAURL -Scope Global -Force 
New-Variable -Name AuthType -Value $AuthType -Scope Global -Force

$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent

Import-Module -Name ".\CyberArk-Common.psm1" -Force

If($DisableSSLVerify) {
    try{
        Write-Warning "It is not Recommended to disable SSL verification" -WarningAction Inquire
        # Using Proxy Default credentials if the Server needs Proxy credentials
        [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
        # Using TLS 1.2 as security protocol verification
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
        # Disable SSL Verification
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
    } catch {
        Write-LogMessage -Type Error -MSG "Could not change SSL validation"
        Write-LogMessage -Type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
        return
    }
} Else {
    try{
        Write-LogMessage -Type Debug -MSG "Setting script to use TLS 1.2"
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    } catch {
        Write-LogMessage -Type Error -MSG "Could not change SSL settings to use TLS 1.2"
        Write-LogMessage -Type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
    }
}

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

Invoke-Logon -Credentials $PVWACredentials

Switch ((Get-Application "AIMWebService" -IncludeSublocations).application.count) {
    0 {
        Write-Output "==> [CREATE] Did not detect AIMWebService App ID" | Use-Color Green
        try {
            New-Application -AppID "AIMWebService" -Description "AAM CCP Web Service App ID"
            Write-Output "==> [SUCCESS] Created Application ID: AIMWebService" | Use-Color Green
        } catch {
            Write-Output "==> [FAILED] Could not create AIMWebService App ID" | Use-Color Red
            exit 1
        }
    }
    1 {Write-Output "==> [SKIPPED] Detected AIMWebService App ID" | Use-Color Yellow}
    default {Write-Output "==> [SKIPPED] Detected AIMWebService App ID" | Use-Color Yellow}
}
$getHashResponse = $(& "$NETAIMGetAppInfo" GetHash /AppExecutablesPattern="$AIMWebServicepath")
$aamHashValue = $getHashResponse.Split("`r`n")
$aamMachineIP = (Get-NetIPAddress -AddressState Preferred -AddressFamily IPv4).IPAddress

$appAuth = (Get-ApplicationAuth -appID "AIMWebService").authentication

if ([string]::IsNullOrEmpty($appAuth)){$appAuth=@{AuthValue=""}}

If (!$appAuth.AuthValue.Contains($AIMWebServicepath)){
    New-ApplicationAuth -appID "AIMWebService" -AuthType "path" -AuthValue $path -ErrorAction SilentlyContinue
    Write-Output "==> [SUCCESS] Added Path Authentication" | Use-Color Green
} Else {
    Write-Output "==> [SKIP] Path Authentication already Found" | Use-Color Yellow
}

If (!$appAuth.AuthValue.Contains($osuser)){
    New-ApplicationAuth -appID "AIMWebService" -AuthType "osUser" -AuthValue $osuser -ErrorAction SilentlyContinue
    Write-Output "==> [SUCCESS] Added OSUser Authentication" | Use-Color Green
} else {
    Write-Output "==> [SKIP] OSUser Authentication already Found" | Use-Color Yellow
}
If (!$appAuth.AuthValue.Contains($aamHashValue[0])){
    New-ApplicationAuth -appID "AIMWebService" -AuthType "hash" -AuthValue $aamHashValue[0] -ErrorAction SilentlyContinue
    Write-Output "==> [SUCCESS] Added Hash Authentication" | Use-Color Green
} else {
    Write-Output "==> [SKIP] Hash Authentication already Found" | Use-Color Yellow
}
foreach( $ip in $aamMachineIP){
    if ("127.0.0.1" -ne $ip) {
        # # # Add IP address
        If (!$appAuth.AuthValue.Contains($ip)){
            New-ApplicationAuth -appID "AIMWebService" -AuthType "machineaddress" -AuthValue $ip
            Write-Output "==> [SUCCESS] Added $ip to Machine Address Authentication" | Use-Color Green
        } else {
            Write-Output "==> [SKIP] Machine Address Authentication already Found" | Use-Color Yellow
        }
    }
}

Write-Output "`r`n`r`n*** Completed AIMWebService configuration successfully. ***" | Use-Color Cyan
#region [Logoff]
# Logoff the session
# ------------------
Write-Host "Logoff Session..."

Invoke-Logoff

Remove-Variable -Name LOG_FILE_PATH -Scope Global -Force
Remove-Variable -Name PVWAURL -Scope Global -Force
Remove-Variable -Name AuthType -Scope Global -Force

#endregion

$VerbosePreference = $oldverbose