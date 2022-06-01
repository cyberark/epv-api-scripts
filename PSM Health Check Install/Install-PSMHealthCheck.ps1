<# ###########################################################################

NAME: Install PSM Health Check

AUTHOR:  Brian Bors

COMMENT: 
This script will install the PSM Health Check service so load balancers can 
check if the service are up and running

VERSION HISTORY:
1.0 2022-06-01 - Initial release

########################################################################### #>

param
(

    [Parameter(Mandatory = $false)]
    [String]$location = "C:\Program Files (x86)\CyberArk\PSM",

    #use this switch to automatically download the required file
    [Parameter()]
    [switch]$download,
        
    #use this switch to create self signed certificate 
    [Parameter()]
    [switch]$CreateSelfSignedCert,
    
    # Use this switch to only download required files
    [Parameter()]
    [switch]$stage,
    
    #The file name for the "Microsoft .NET Core Windows Server Hosting" to use and/or download
    [Parameter(Mandatory = $false)]
    [String]$hostingFile = "dotnet-hosting-win.exe",

    # Use this switch to Disable SSL verification (NOT RECOMMENDED)
    [Parameter(Mandatory = $false)]
    [Switch]$DisableSSLVerify
)

$appsettings = "$location\healthcheck\appsettings.json"

$hosting = "https://download.visualstudio.microsoft.com/download/pr/1c12a7f4-1e3b-4d0c-a0f8-a03950187940/15abf24d5330aca4429b6212892ca2ae/dotnet-hosting-3.1.25-win.exe"

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

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


if ($download -or $stage) {
    Invoke-WebRequest $hosting -OutFile $hostingFile
}


If ($stage) {
    exit
}

Install-WindowsFeature -Name Web-Server -IncludeManagementTools

Start-Process -Wait -FilePath .\$hostingFile -ArgumentList ("/install /passive /norestart")

Import-Module WebAdministration

$httpsCheck = Get-WebBinding -Protocol https
if ($null -eq $httpsCheck) {
    New-WebBinding -Name "Default Web Site" -IP "*" -Port 443 -Protocol https HostHeader "" -Force
}
Set-WebConfiguration -Location "Default Web Site" -Filter 'system.webserver/security/access' -Value 'None'

if ($CreateSelfSignedCert) {
    $loc = Get-Location
    Set-Location IIS:\SslBindings
    $fqdn = [System.Net.Dns]::GetHostByName($env:computerName)
    $c = New-SelfSignedCertificate -DnsName "$($fqdn.HostName)" -CertStoreLocation cert:\LocalMachine\My
    $c | New-Item 0.0.0.0!443 -Force
    Set-Location IIS:\
    Set-Location $loc
}

./HealthCheck.ps1 -installPath $location -copyMode Override

((Get-Content -Path $appsettings -Raw) -replace "Classic", "CodeBased") | Set-Content -Path $appsettings


Invoke-Expression "iisreset"
