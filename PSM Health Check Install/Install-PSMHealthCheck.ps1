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
    [Switch]$DisableSSLVerify,
    
    # Use this switch to allow HTTP Connections (NOT RECOMMENDED)
    [Parameter(Mandatory = $false)]
    [Switch]$AllowHTTP
)

$appsettings = "$location\healthcheck\appsettings.json"

$hosting = "https://download.visualstudio.microsoft.com/download/pr/7ab0bc25-5b00-42c3-b7cc-bb8e08f05135/91528a790a28c1f0fe39845decf40e10/dotnet-hosting-6.0.16-win.exe"

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
        Write-Warning  "Could not change SSL validation"
        return
    }
}
Else {
    try {
        Write-LogMessage -Type Debug -MSG "Setting script to use TLS 1.2"
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    }
    catch {
        Write-Warning  "Could not change SSL settings to use TLS 1.2"

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
    New-WebBinding -Name "Default Web Site" -IP "*" -Port 443 -Protocol https -HostHeader "" -Force
}
Set-WebConfiguration -Location "Default Web Site" -Filter 'system.webserver/security/access' -Value 'None'

if ($CreateSelfSignedCert) {
    $certCheck = Get-ChildItem -path cert:\LocalMachine\My |Where {$_.Issuer -eq $_.Subject} |Where {$_.EnhancedKeyUsageList.FriendlyName -contains "Server Authentication"}
    If ($certCheck.count -eq 0) {
    $loc = Get-Location
    Set-Location IIS:\SslBindings
    $fqdn = [System.Net.Dns]::GetHostByName($env:computerName)
    $c = New-SelfSignedCertificate -DnsName "$($fqdn.HostName)" -CertStoreLocation cert:\LocalMachine\My
    $c | New-Item 0.0.0.0!443 -Force
    Set-Location IIS:\
    Set-Location $loc}
    ElseIf($certCheck.count -eq 1){
        "Self-signed certificates already exist. Using existing self-signed certificate"
        $certCheck[0] | New-Item 0.0.0.0!443 -Force
    }
    Else
    {
        "Multiple self-signed certificates already exist. Manual setup of SSL bindings required"
    }
}

./HealthCheck.ps1 -installPath $location -copyMode Override

((Get-Content -Path $appsettings -Raw) -replace "Classic", "CodeBased") | Set-Content -Path $appsettings

if ($AllowHTTP) {
    Set-WebConfiguration -Location "Default Web Site/PSM" -Filter 'system.webserver/security/access' -Value 'None'
}

Invoke-Expression "iisreset"

"Running connection Test"

$priorSSL=(get-WebConfiguration -Location "Default Web Site/PSM" -Filter 'system.webserver/security/access').sslFlags
Set-WebConfiguration -Location "Default Web Site/PSM" -Filter 'system.webserver/security/access' -Value 'None'
Start-Sleep 1
Invoke-WebRequest http://localhost/psm/api/health 
Set-WebConfiguration -Location "Default Web Site/PSM" -Filter 'system.webserver/security/access' -Value $priorSSL
