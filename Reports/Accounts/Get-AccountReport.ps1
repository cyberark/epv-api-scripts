[CmdletBinding()]
param
(
    # Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off
    [Parameter(Mandatory = $false)]
    [ValidatePattern( '\.csv$' )]
    [Alias("Report")]
    [String]$ReportPath = ".\AccountReport.csv",

    #region Parameters used for logon
    [Parameter(Mandatory = $false, HelpMessage = "Use this parameter to pass a pre-existing authorization token. ")]
    $logonToken,

    [Parameter(Mandatory = $false, HelpMessage = "Enter Identity Name")]
    [String]$IdentityUserName,
    [Parameter(Mandatory = $false, HelpMessage = "Enter Identity URL")]
    [String]$IdentityURL,
    [Parameter(Mandatory = $false, HelpMessage = "Enter Privilege Cloud Subdomain")]
    [String]$PCloudSubDomain,

    [Parameter(Mandatory = $false, HelpMessage = "Enter PVWA URL")]
    [String]$PVWAAddress,
    [Parameter(Mandatory = $false, HelpMessage = "Pass PVWA Credentials")]
    [PSCredential]$PVWACredentials,
    [Parameter(Mandatory = $false, HelpMessage = "Authentication Type for PVWA")]
    [String]$PVWAAuthType = "CyberArk",
    #endregion


    [Parameter(Mandatory = $false)]
    [Switch]$allProps,
    [Parameter(Mandatory = $false)]
    [Switch]$ExcludeExtendedProps,
    [Parameter(Mandatory = $false)]
    [Switch]$MachineRestrictedProps,
    [Parameter(Mandatory = $false)]
    [Switch]$PolicyProps,
    [Parameter(Mandatory = $false)]
    [Switch]$ChangeProps,
    [Parameter(Mandatory = $false)]
    [Switch]$VerifyProps,
    [Parameter(Mandatory = $false)]
    [Switch]$ReconcileProps,
    [Parameter(Mandatory = $false)]
    [Switch]$ObjectNameProps,
    [Parameter(Mandatory = $false)]
    [Switch]$ImportedProps,

    [Parameter(Mandatory = $false)]
    [System.Collections.ArrayList]$PropList
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
    } catch {
        "PSPas was not found and unable to automatically install the module. Please manually install the module and try again."
    }
} 

Get-PASComponentSummary -ErrorAction SilentlyContinue -ErrorVariable TestConnect | Out-Null
if ($TestConnect.count -ne 0) {
    Close-PASSession -ErrorAction SilentlyContinue
}
If ($null -eq (Get-PASSession).User) {
    If (![string]::IsNullOrEmpty($logonToken)) {
        Use-PASSession $logonToken 
    } elseIf (![string]::IsNullOrEmpty($IdentityUserName)) {
        "Identity username provided"  
        IF (!(Test-Path .\IdentityAuth.psm1)) {
            Invoke-WebRequest -Uri https://raw.githubusercontent.com/cyberark/epv-api-scripts/main/Identity%20Authentication/IdentityAuth.psm1 -OutFile IdentityAuth.psm1
        }
        Import-Module .\IdentityAuth.psm1
        $header = Get-IdentityHeader -psPASFormat -IdentityTenantURL $IdentityURL -IdentityUserName $IdentityUserName -PCloudTenantAPIURL "https://$PCloudSubDomain.privilegecloud.cyberark.cloud/passwordvault/"
        if ($null -eq $header) {
            exit
        }
        Use-PASSession $header
        "Successfully Connected"
    } elseif (![string]::IsNullOrEmpty($PVWAAddress)) {
        if ([string]::IsNullOrEmpty($PVWACredentials)) {
            $PVWACredentials = Get-Credential
        }
        New-PASSession -Credential $PVWACredentials -concurrentSession $true -BaseURI $PVWAAddress -type $PVWAAuthType
    } else {
        "You must enter either a Logon Token, PVWAAddress, or IdentityURL and SubDomain"
        break
    }
}
#endregion

$ErrorActionPreference = "SilentlyContinue" 

[System.Collections.ArrayList]$ExcludeExtendedPropsList = @("SecretStatus", "AccountManaged", "manualManagementReason", "ManagingCPM", "PlatformName")
[System.Collections.ArrayList]$MachineRestrictedPropsList = @("RestrictedToSpecificMachines", "RemoteMachines")
[System.Collections.ArrayList]$PolicyPropsList = @("DualControl", "ExclusiveUse", "OneTime", "RequireReason")
[System.Collections.ArrayList]$ChangePropsList = @("ChangeManual", "ChangeOnAdd", "ChangeAuto", "ChangeLast", "ChangeNext", "ChangeDays", "ChangeInReset")
[System.Collections.ArrayList]$VerifyPropsList = @("VerifyManual", "VerifyOnAdd", "VerifyAuto", "VerifyLast", "VerifyNext", "VerifyDays")
[System.Collections.ArrayList]$ReconcilePropsList = @("ReconcileManual", "ReconcileUnSync")
[System.Collections.ArrayList]$ObjectNamePropsList = @("ObjectName")

If (($allProps) -or (-not [String]::IsNullOrEmpty($PropList))) {
    $MachineRestrictedProps = $PolicyProps = $ChangeProps = $VerifyProps = $ReconcileProps = $ObjectNameProps = $ImportedProps = $true
    $ExcludeExtendedProps = $false
}

$props = New-Object -TypeName System.Collections.ArrayList
$ImportedPropsList = New-Object -TypeName System.Collections.ArrayList
if (!$ExcludeExtendedProps) {
    $props += $ExcludeExtendedPropsList
}
if ($MachineRestrictedProps) {
    $props += $MachineRestrictedPropsList
}
if ($PolicyProps) {
    $props += $PolicyPropsList
}
if ($ChangeProps) {
    $props += $ChangePropsList
}
if ($VerifyProps) {
    $props += $VerifyPropsList
}
if ($ReconcileProps) {
    $props += $ReconcilePropsList
}
if ($ObjectNameProps) {
    $props += $ObjectNamePropsList
}

$platforms = Get-PASPlatform 
[hashtable]$platformsht = @{}
$platforms | ForEach-Object {$platformsht.Add($_.PlatformID, $_)}

$safes = Get-PASSafe
[hashtable]$safesht = @{}
$safes | ForEach-Object {$safesht.Add($_.SafeName, $_)}

$accounts = Get-PASAccount
$accountWork = $accounts
$accountWork | Add-Member -MemberType NoteProperty -Name PlatformInfo -Value $null -Force
$accountWork | Add-Member -MemberType NoteProperty -Name SafeInfo -Value $null -Force

$props | ForEach-Object {$accountWork | Add-Member -MemberType NoteProperty -Name $_ -Value $null -Force}   

$accountWork | ForEach-Object {$_.PlatformInfo = $platformsht[$_.PlatformID]}
$accountWork | ForEach-Object {$_.SafeInfo = $safesht[$_.SafeName]}

if ($ImportedProps) {
    [System.Collections.ArrayList]$ImportedPropsList = ($accountWork.platformAccountProperties | ForEach-Object {$_ | Get-Member | Where-Object {$_.MemberType -eq "NoteProperty"} | Select-Object -Property name}).name | Select-Object -Unique
    $ImportedPropsList | ForEach-Object {$accountWork | Add-Member -MemberType NoteProperty -Name $_ -Value $null -Force}   
}

$accountWork | ForEach-Object {

    #Base Account information
    if (!$ExcludeExtendedProps) {
        $_.SecretStatus = $_.secretManagement.Status
        $_.AccountManaged = $_.secretManagement.automaticManagementEnabled
        $_.manualManagementReason = $_.secretManagement.manualManagementReason
        $_.ManagingCPM = $_.safeinfo.managingCPM
        $_.PlatformName = $_.platforminfo.Details.Name
    }
    #Restricted Machine Account Information
    if ($MachineRestrictedProps) {
        $_.RestrictedToSpecificMachines = $_.remoteMachinesAccess.accessRestrictedToRemoteMachines
        $_.RemoteMachines = $_.remoteMachinesAccess.remoteMachines
    }

    #Infomation about Policies
    if ($PolicyProps) {
        $_.DualControl = $_.platforminfo.Details.PrivilegedAccessWorkflows.RequireDualControlPasswordAccessApproval.IsActive
        $_.ExclusiveUse = $_.platforminfo.Details.PrivilegedAccessWorkflows.EnforceCheckinCheckoutExclusiveAccess.IsActive
        $_.OneTime = $_.platforminfo.Details.PrivilegedAccessWorkflows.EnforceOnetimePasswordAccess.IsActive
        $_.RequireReason = $_.platforminfo.Details.PrivilegedAccessWorkflows.RequireUsersToSpecifyReasonForAccess.IsActive
    }

    #Changes Information
    if ($ChangeProps) {
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
    }

    #Verifications Information
    if ($VerifyProps) {
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
    }

    #Reconcile Information
    if ($ReconcileProps) {
        $_.ReconcileManual = $_.platforminfo.Details.CredentialsManagementPolicy.Reconcile.AllowManual
        $_.ReconcileUnSync = $_.platforminfo.Details.CredentialsManagementPolicy.Reconcile.AutomaticReconcileWhenUnsynced
    }
    #Name 
    if ($ObjectNameProps) {
        $_.ObjectName = $_.name
    }

    #Custom Properties
    if ($ImportedProps) {
        ForEach ($prop in $ImportedPropsList) {
            $_ | Add-Member -MemberType NoteProperty -Name $prop -Value $_.platformAccountProperties.$prop -Force
        }
    }
}

[System.Collections.ArrayList]$StandardProps = @( "UserName", "Address", "Safename", "PlatformID", "SecretType")

$reportProps = New-Object -TypeName System.Collections.ArrayList
$reportProps = $StandardProps + $props + $ImportedPropsList

if ([string]::IsNullOrEmpty($PropList)) {
    $accountWork | Select-Object -Property $reportProps | Sort-Object USername, Address, SafeName, PlatformID | Export-Csv -NoTypeInformation -Path $ReportPath
} else {
    $accountWork | Select-Object -Property $PropList | Export-Csv -NoTypeInformation -Path $ReportPath
}

"The End" | Out-Null