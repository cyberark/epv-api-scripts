<# ###########################################################################

NAME: Test PSM Certificate for HTML5 Use

AUTHOR:  Matthew Price

COMMENT: 
This script check the certificate installed ont he PSM to ensure it 
meets the minimum requirements to be used by at CyberArk HTML5 Gateway

SUPPORTED VERSIONS:
All versions supporting HTML5 gateway

Change Notes
2022-07-21      Initial release

########################################################################### #>

[CmdletBinding(DefaultParameterSetName = "Regular")]
param(
    # Use this switch to actually set the certificate for use in RDS
    [Parameter(ParameterSetName = 'SetCertificate', Mandatory = $false)]
    [switch]$SetCertificate
)

$ErrorActionPreference = "Stop"
Function CheckCertificate {
    param($certToCheck)
    $errorCount = 0
    $certToCheck.Thumbprint
    $hasPrivateKey = $certToCheck.HasPrivateKey
    if (!$hasPrivateKey) {
        $errorCount++
        Write-Warning "We couldn't detect a private key installed for this certificate. This certifiate can't be used."
    }

    $certHasExpired = $certToCheck.NotAfter -lt (Get-Date)
    if ($certHasExpired) {
        $errorCount++
        Write-Warning "This certificate has expired. This certificate can't be used"
    }

    $certNotValidYet = $certToCheck.NotBefore -gt (Get-Date)
    if ($certNotValidYet) {
        $errorCount++
        Write-Warning "This certificate isn't yet valid. This certificate can't be used"
    }

    $certMissingKeyUsage = $certToCheck.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.1"
    if (!$certMissingKeyUsage) {
        $errorCount++
        Write-Warning "This certificate appears to be missing the `"Server Authentication`" Enhanced Key Usage. This certificate can't be used"
    }

    $certMissingDnsName = $certToCheck.DnsNameList -contains ([system.net.dns]::GetHostByName("localhost")).hostname
    if (!$certMissingDnsName) {
        $errorCount++
        Write-Warning "This certificate doesn't appear to match the hostname of the machine. This certificate can't be used"
    }

    if ($errorCount -gt 0) {
        Write-Error "This certificate can't currently be used - please review the warning messages above"
    }
    else {
        Write-Host "This certificate passed the checks and looks ready to use."
    }
}




$selectedCert = Get-ChildItem Cert:\LocalMachine\My | Select-Object -Property * | Out-GridView -PassThru -Title "Select the certificate to use for PSM"
CheckCertificate $selectedCert

if ($SetCertificate) {
    # This won't run if errorCount is greater than 0, as that generates an Error and will end execution
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Will not attempt to set the certificate. Must be running as administrator to update the RDS certificate"
    }

    Write-Host "Attempting to set certificate for use in RDS.."
    $tsgs = Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'"
    $thumb = $selectedCert.Thumbprint
    Set-WmiInstance -Path $tsgs.__path -argument @{SSLCertificateSHA1Hash = "$thumb" }
}