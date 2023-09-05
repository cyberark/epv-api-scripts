[CmdletBinding()]
param
(
    # Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off
    [Parameter(Mandatory = $true)]
    $logonToken,

    [Parameter(Mandatory = $false)]
    [ValidatePattern( '\.csv$' )]
    [Alias("Report")]
    [String]$ReportPath = ".\AccountReport.csv",

    [Parameter(Mandatory = $true)]
    [System.Collections.ArrayList]$safes


)


function Optimize-Account {
    param (
        $target
    )
    
    $address = $target.address | Resolve-DnsName | Select-Object -Unique | `
        ForEach-Object {
        if ([string]::IsNullOrEmpty($PSItem.NameHost)) {
            if (![string]::IsNullOrEmpty($PSItem.Name)) {
                $PSItem.Name
            } Else {
                $target.address
            }
        } else {
            $PSItem.NameHost
        }
    }

    if ([string]::IsNullOrEmpty($address)) {
        Write-Host "Address Not Found for `"$($target.address)`""
    } else {
        Write-Host "Address Found for `"$($target.address)`""
    }

}

try {
    Use-PASSession $logonToken 
    Get-PASComponentSummary | Out-Null
} catch {
    Write-Host -ForegroundColor Red 'Error while attempting to connect. Please verify your $logonToken is using the PSPAS format, has the correct PCLoud Subdomain listed, and your session has not expired.' 
    Write-Host -ForegroundColor Red 'Example on how to get $logonToken'
    Write-Host -ForegroundColor Red ''
    Write-Host -ForegroundColor Red '$logonToken = Get-IDentityHeader -IdentityTenantURL https://aa12345.id.cyberark.cloud -IdentityUserName brian.bors@cyberark.cloud.xxxx -psPASFormat -PCloudSubdomain testlab'
    return
}


$ErrorActionPreference = "SilentlyContinue" 

$platforms = Get-PASPlatform -SystemType Windows      
[hashtable]$platformsht = @{}
$platforms | ForEach-Object {$platformsht.Add($_.PlatformID, $_)}

$accounts = Get-PASAccount
$accountWork = $accounts
$accountWork | Add-Member -MemberType NoteProperty -Name PlatformInfo -Value $null -Force
$accountWork | ForEach-Object {$_.PlatformInfo = $platformsht[$_.PlatformID]}

$accountWorkWindows = $accountWork | Where-Object PlatformInfo -NE $null

$accountWorkWindows = $accountWorkWindows | Where-Object SafeName -In $safes
$accountWorkWindows | ForEach-Object {

    Optimize-Account -target $PSItem

    <# 
    $target = $PSItem
    $target.address |`
     Resolve-DnsName  | `
     Select-Object -Unique | `
     ForEach-Object {
        if ([string]::IsNullOrEmpty($PSItem.NameHost)) {
            if (![string]::IsNullOrEmpty($PSItem.Name)) {
                Write-Host $PSItem.Name
            } Else {
                Write-Host $target.address
            }
        } else {
            Write-Host $PSItem.NameHost
        }
    } #>
}

