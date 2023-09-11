[CmdletBinding()]
param
(
    # Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off
    [Parameter(Mandatory = $false)]
    [ValidatePattern( '\.csv$' )]
    [Alias("Report")]
    [String]$ReportPath = ".\AccountPlatformReport.csv",

    # Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off
    [Parameter(Mandatory = $false)]
    $logonToken,

    [Parameter(Mandatory = $false, HelpMessage = "Enter Identity Name")]
    [String]$IdentityUserName,
    [Parameter(Mandatory = $false, HelpMessage = "Enter Identity URL")]
    [String]$IdentityURL,
    [Parameter(Mandatory = $false, HelpMessage = "Enter Privilege Cloud Subdomain")]
    [String]$SubDomain,

    [Parameter(Mandatory = $false, HelpMessage = "Pass PVWA Credentials")]
    [PSCredential]$PVWACredentials,
    [Parameter(Mandatory = $false, HelpMessage = "Enter PVWA URL")]
    [String]$PVWAAddress

)

function Convert-EpochToNow {
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $false)]
        [string]$EpochTime
    )

    If ([string]::IsNullOrEmpty($EpochTime)) {
        Return
    } else {
        return $((Get-Date -Date "01-01-1970") + ([System.TimeSpan]::FromSeconds(($EpochTime))))
    }
}

#region PAS Connection
if (!(Get-Module -ListAvailable -Name PSPAS)) {
    Try {
    Install-Module PSPAS -Scope CurrentUser
    } catch
    {
        "PSPas was not found and unable to automatically install the module. Please manually install the module and try again."
    }
} 

Get-PASComponentSummary -ErrorAction SilentlyContinue -ErrorVariable TestConnect | Out-Null
if ($TestConnect.count -ne 0) {
    Close-PASSession -ErrorAction SilentlyContinue
}
If ($null -eq (Get-PASSession).User){
    If (![string]::IsNullOrEmpty($logonToken)){
        Use-PASSession $logonToken 
    }
    elseIf (![string]::IsNullOrEmpty($IdentityUserName)) {
        "Identity username provided"  
        IF (!(Test-Path .\IdentityAuth.psm1)){
            Invoke-WebRequest -Uri https://raw.githubusercontent.com/cyberark/epv-api-scripts/main/Identity%20Authentication/IdentityAuth.psm1 -OutFile IdentityAuth.psm1
        }
        Import-Module .\IdentityAuth.psm1
        $header = Get-IdentityHeader -psPASFormat -IdentityTenantURL $IdentityURL -IdentityUserName $IdentityUserName -PCloudTenantAPIURL "https://$SubDomain.privilegecloud.cyberark.cloud/passwordvault/"
        if ($null -eq $header) {
            exit
        }
        Use-PASSession $header
        "Successfully Connected"
    } elseif (![string]::IsNullOrEmpty($PVWAAddress)){
        if ([string]::IsNullOrEmpty($PVWACredentials)) {
            $PVWACredentials = Get-Credential
        }
        New-PASSession -Credential $PVWACredentials -concurrentSession $true -BaseURI $PVWAAddress
    } else {
        "You must enter either a Logon Token, PVWAAddress, or IdentityURL and SubDomain"
        break
    }
}
#endregion

$ErrorActionPreference = "SilentlyContinue" 
   
$platforms = Get-PASPlatform -PlatformType Regular    
[hashtable]$platformsht = @{}
$platforms | ForEach-Object {$platformsht.Add($_.PlatformID, $_)}

$safes = Get-PASSafe
[hashtable]$safesht = @{}
$safes | ForEach-Object {$safesht.Add($_.SafeName, $_)}

$accounts = Get-PASAccount
$accountWork = $accounts
$accountWork | Add-Member -MemberType NoteProperty -Name PlatformInfo -Value $null -Force
$accountWork | Add-Member -MemberType NoteProperty -Name SafeInfo -Value $null -Force
$props = @("AccountManaged", "ManagingCPM", "PlatformName", "DualControl", "ExclusiveUse", "OneTime", "RequireReason", `
        "AccountNotes", "ChangeManual", "ChangeOnAdd", "ChangeAuto", "ChangeLast", "ChangeNext", "ChangeDays", "ChangeInReset", `
        "VerifyManual", "VerifyOnAdd", "VerifyAuto", "VerifyLast", "VerifyNext", "VerifyDays", `
        "ReconcileManual", "ReconcileUnSync"
)
$props | ForEach-Object {$accountWork | Add-Member -MemberType NoteProperty -Name $_ -Value $null -Force}   

$accountWork | ForEach-Object {$_.PlatformInfo = $platformsht[$_.PlatformID]}
$accountWork | ForEach-Object {$_.SafeInfo = $safesht[$_.SafeName]}
$accountWork | ForEach-Object {
    #Account information
    $_.AccountManaged = $_.secretManagement.automaticManagementEnabled
    $_.ManagingCPM = $_.safeinfo.managingCPM
    $_.AccountNotes = $_.platformAccountProperties.Notes
    
    #Infomation about Policies
    $_.PlatformName = $_.platforminfo.Details.Name
    $_.DualControl = $_.platforminfo.Details.PrivilegedAccessWorkflows.RequireDualControlPasswordAccessApproval.IsActive
    $_.ExclusiveUse = $_.platforminfo.Details.PrivilegedAccessWorkflows.EnforceCheckinCheckoutExclusiveAccess.IsActive
    $_.OneTime = $_.platforminfo.Details.PrivilegedAccessWorkflows.EnforceOnetimePasswordAccess.IsActive
    $_.RequireReason = $_.platforminfo.Details.PrivilegedAccessWorkflows.RequireUsersToSpecifyReasonForAccess.IsActive

    #Information about Changes
    $_.ChangeManual = $_.platforminfo.Details.CredentialsManagementPolicy.Change.AllowManual
    $_.ChangeOnAdd = $_.platforminfo.Details.CredentialsManagementPolicy.Change.AutoOnAdd
    $_.ChangeAuto = $_.platforminfo.Details.CredentialsManagementPolicy.Change.PerformAutomatic
    $_.ChangeDays = $_.platforminfo.Details.CredentialsManagementPolicy.Change.RequirePasswordEveryXDays
    If (![string]::IsNullOrEmpty($_.secretManagement.lastModifiedTime)) {
        $_.ChangeLast = Get-Date -UFormat "%x %r" -Date $(Convert-EpochToNow $_.secretManagement.lastModifiedTime)
    } else {
        $_.ChangeLast = "Never Changed"
    }
    If (![string]::IsNullOrEmpty($_.secretManagement.lastModifiedTime)) {
        $_.ChangeNext = Get-Date -UFormat %x -Date $($(Convert-EpochToNow $_.secretManagement.lastModifiedTime) + [system.TimeSpan]::FromDays($_.ChangeDays))
    } else {
        $_.ChangeNext = "Pending First Change"
    }
    $_.ChangeInReset = $_.platformInfo.Details.CredentialsManagementPolicy.SecretUpdateConfiguration.ChangePasswordInResetMode

    #Information about Verifications
    $_.VerifyManual = $_.platforminfo.Details.CredentialsManagementPolicy.Verification.AllowManual
    $_.VerifyOnAdd = $_.platforminfo.Details.CredentialsManagementPolicy.Verification.AutoOnAdd
    $_.VerifyAuto = $_.platforminfo.Details.CredentialsManagementPolicy.Verification.PerformAutomatic
    $_.VerifyDays = $_.platforminfo.Details.CredentialsManagementPolicy.Verification.RequirePasswordEveryXDays
    If (![string]::IsNullOrEmpty($_.secretManagement.lastVerifiedTime)) {
        $_.VerifyLast = Get-Date -UFormat "%x %r" -Date $(Convert-EpochToNow $_.secretManagement.lastVerifiedTime)
    } else {
        $_.VerifyLast = "Never Verified"
    }
    If (![string]::IsNullOrEmpty($_.secretManagement.lastVerifiedTime)) {
        $_.VerifyNext = Get-Date -UFormat %x -Date $($(Convert-EpochToNow $_.secretManagement.lastVerifiedTime) + [system.TimeSpan]::FromDays($_.VerifyDays))
    } else {
        $_.VerifyNext = "Pending First Verification"
    }

    #Information about Reconcile
    $_.ReconcileManual = $_.platforminfo.Details.CredentialsManagementPolicy.Reconcile.AllowManual
    $_.ReconcileUnSync = $_.platforminfo.Details.CredentialsManagementPolicy.Reconcile.AutomaticReconcileWhenUnsynced

}
$reportProps = @("Safename", "UserName", "Address", "PlatformID") + $props

$accountWork | Select-Object -Property $reportProps | Export-Csv -NoTypeInformation -Path $ReportPath

