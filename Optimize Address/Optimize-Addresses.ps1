<#
    .SYNOPSIS
    Used to review and update account addresses

    .Description
    Used to query account addresses against DNS to ensure they are valid.
    Can also updates the format of the address to ensure that when account discovery is ran existing accounts are located and connected.
#>

[CmdletBinding()]
param
(
    #LogonToken to be used to connect
    [Parameter(Mandatory = $false)]
    $logonToken,
    # Username to use to connect to Identity
    [Parameter(Mandatory = $false)]
    [String]$IdentityUserName,
    # URL of the Identity Tenant
    [Parameter(Mandatory = $false)]
    [String]$IdentityTenantURL,
    # Subdomain for Privileged Cloud
    [Parameter(Mandatory = $false)]
    [String]$PCloudSubdomain,
    # Credentials to be used to authenticate stored in a PSCredential object
    [Parameter(Mandatory = $false)]
    [PSCredential]$PVWACredentials,
    # Address of the PVWA
    [Parameter(Mandatory = $false)]
    [String]$PVWAAddress,
    # List of safes that will be reviewed
    [Parameter(Mandatory = $false)]
    [System.Collections.ArrayList]$Safes,
    # Switch to enable updating of the address of accounts found to required updates
    [Parameter(Mandatory = $false)]
    [switch]$Script:UpdateAccounts,
    # Display accounts that are able to be optimized or already optimized
    [Parameter(Mandatory = $false)]
    [switch]$ShowAllResults,
    # Do NOT display the accounts that are not optimezed
    [Parameter(Mandatory = $false)]
    [switch]$SuppressErrorResults,
    # Export the accounts that where reviewed/updated to a CSV file
    [Parameter(Mandatory = $false)]
    [switch]$ExportToCSV,
    # File name and location to export results to
    [Parameter(Mandatory = $false)]
    [string]$CSVPath = ".\Optimize-Addresses-Results.csv"
)

$currentAP = $ErrorActionPreference
function Optimize-Account {
    param (
        $target
    )
    $ErrorActionPreference = "SilentlyContinue"
    $result = New-Object -TypeName PSObject -Property @{
        'AccountName' = $target.Name
        'Username'    = $target.userName
        'Address'     = $target.address
        'Status'      = "Not Proccessed"
        'Success'     = $false
        'Found'       = $false
        'Updated'     = $false
    }
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
        $result.Status = "No Address Found, manual update required"
    } else {
        $result.Found = $true
        If ($address.ToLower() -ne $target.address.ToLower()) {
            $result.status = "Address found in DNS"
            IF ($Script:UpdateAccount) {
                Try {
                    $target | Set-PASAccount -op replace -path "/address" -value "$($address.ToLower())"
                    $result.status = "Address Update to value found in DNS: Old:`"$($target.address)`" New: `"$($address.ToLower())`""
                    $result.updated = $true
                } catch {
                    $result.status = "Address Update failed: Old:`"$($target.address)`" New: `"$($address.ToLower())`""
                }
            } else {
                $result.success = $true

            }
        } else {
            $result.status = "Address on account matches DNS"
            $result.success = $true
        }
    }
    $Result
}
$funcDefOA = ${function:Optimize-Account}.ToString()

#region PAS Connection
if (!(Get-Module -ListAvailable -Name PSPAS)) {
    Install-Module PSPAS -Scope CurrentUser
}

Get-PASComponentSummary -ErrorAction SilentlyContinue -ErrorVariable TestConnect | Out-Null
if ($TestConnect.count -ne 0) {
    Close-PASSession -ErrorAction SilentlyContinue
}

If ($null -eq (Get-PASSession).User) {
    If (![string]::IsNullOrEmpty($IdentityUserName)) {
        "Identity username provided"
        IF (!(Test-Path .\IdentityAuth.psm1)) {
            Invoke-WebRequest -Uri https://raw.githubusercontent.com/cyberark/epv-api-scripts/main/Identity%20Authentication/IdentityAuth.psm1 -OutFile IdentityAuth.psm1
        }
        Import-Module .\IdentityAuth.psm1
        $header = Get-IdentityHeader -psPASFormat -IdentityUserName $IdentityUserName -IdentityTenantURL $IdentityTenantURL -PCloudTenantAPIURL "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/passwordvault/"
        if ($null -eq $header) {
            exit
        }
        Use-PASSession $header
        "Successfully Connected"
    } elseif (![string]::IsNullOrEmpty($PVWAAddress)) {
        if (![string]::IsNullOrEmpty($logonToken)) {
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
        } elseif (![string]::IsNullOrEmpty($PVWACredentials)) {
            $PVWACredentials = Get-Credential
            New-PASSession -Credential $PVWACredentials -concurrentSession $true -BaseURI $PVWAAddress
        }
    } elseif (![string]::IsNullOrEmpty($logonToken)) {
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

    } else {
        "You must enter either a PVWAAddress or IdentityURL and SubDomain or pass a pre-existing PSPAS Session Token"
        break
    }
}

#EndRegion

$ErrorActionPreference = "SilentlyContinue"
$ErrorActionPreference = "Break"
$Results = $Null

$platforms = Get-PASPlatform -SystemType Windows
[hashtable]$platformsht = @{}
$platforms | ForEach-Object {$platformsht.Add($_.PlatformID, $_)}

$accounts = Get-PASAccount
$accountWork = $accounts
$accountWork | Add-Member -MemberType NoteProperty -Name PlatformInfo -Value $null -Force
$accountWork | ForEach-Object {$_.PlatformInfo = $platformsht[$_.PlatformID]}

$accountWorkWindows = $accountWork | Where-Object PlatformInfo -NE $null
IF (![string]::IsNullOrEmpty($safes)) {
    $accountWorkWindows = $accountWorkWindows | Where-Object SafeName -In $safes
}
If (5 -lt $PSVersionTable.PSVersion.Major) {
    "PowerShell version is 6 or higher. Parallel processing enabled"
    [PSCustomObject]$Results = $accountWorkWindows | ForEach-Object -ThrottleLimit 50 -Parallel {
        ${function:Optimize-Account} = $using:funcDefOA
        Optimize-Account -target $PSItem
    }
} else {
    "PowerShell version is 5 or less. Parallel processing disabled"
    [PSCustomObject]$Results = $accountWorkWindows | ForEach-Object {
        Optimize-Account -target $PSItem
    }
}

$PropToDisplay = @("Success", "Found", "Updated", "Address", "Username", "Status", "Accountname")
$PropToSort = @("Success", "Found", "Updated", "Status", "Address", "Username")
if ($ExportToCSV) {
    $Results | Select-Object -Property $PropToDisplay | Sort-Object -Property $PropToSort | Export-Csv -Path $CSVPath
}
if ($ShowAllResults) {
    $Results | Select-Object -Property $PropToDisplay | Sort-Object -Property $PropToSort | Format-Table -GroupBy Success -AutoSize
} Elseif (!$SuppressErrorResults) {
    $Results | Where-Object Success -NE $True | Select-Object -Property $PropToDisplay | Sort-Object -Property $PropToSort | Format-Table -GroupBy Success -AutoSize
}
"$($($Results | Where-Object Found -EQ $True).Count) out of $($accountWorkWindows.Count) addresses found in DNS"
"$($($Results | Where-Object Updated -EQ $True).Count) out of $($accountWorkWindows.Count) addresses Updated"


