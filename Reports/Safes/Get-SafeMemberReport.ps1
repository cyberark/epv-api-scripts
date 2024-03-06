[CmdletBinding()]
param
(
    [Parameter(Mandatory = $false)]
    [ValidatePattern( '\.csv$' )]
    [Alias("Report")]
    [String]$ReportPath = ".\SafeMemberReport.csv",

    [Parameter(Mandatory = $false)]
    [array]$UserTypes =  @("EPVUser", "BasicUser"),

    [Parameter(Mandatory = $false)]
    [Switch]$ExcludeUsers,
    
    [Parameter(Mandatory = $false)]
    [Switch]$IncludePredefinedUsers,

    [Parameter(Mandatory = $false)]
    [Switch]$IncludeGroups,

    [Parameter(Mandatory = $false)]
    [Switch]$IncludeApps,

    [Parameter(Mandatory = $false)]
    [Switch]$HidePerms,

    [Parameter(Mandatory = $false)]
    $PermList,

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
    [String]$PVWAAuthType = "CyberArk"
    #endregion

)
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
        $header = Get-IdentityHeader -psPASFormat -IdentityTenantURL $IdentityURL -IdentityUserName $IdentityUserName -PCloudTenantAPIURL "https://$PCloudSubDomain.privilegecloud.cyberark.cloud/passwordvault/"
        if ($null -eq $header) {
            exit
        }
        Use-PASSession $header
        "Successfully Connected"
    } elseif (![string]::IsNullOrEmpty($PVWAAddress)){
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
If (!$ExcludeUsers) {
    $IncludedUsersTypes = $UserTypes
}

If ($IncludeApps) {
    $IncludedUsersTypes = @("AppProvider", "AIMAccount") + $IncludedUsersTypes
}


$Safes = Get-PASSafe
[hashtable]$safesht = @{}
$safes | ForEach-Object {$safesht.Add($_.SafeName, $_)}

$Users = Get-PASUser
[hashtable]$Usersht = @{}
$Users | ForEach-Object {$Usersht.Add($_.username, $_)}

$SafeMembers = $safes | Get-PASSafeMember -includePredefinedUsers $IncludePredefinedUsers -ErrorAction SilentlyContinue

$SafeMembers | Add-Member -MemberType NoteProperty -Name UserInfo -Value $null -Force
$SafeMembers | Add-Member -MemberType NoteProperty -Name SafeInfo -Value $null -Force

$SafeMembers | ForEach-Object {$_.UserInfo = $Usersht[$_.UserName]}
$SafeMembers | ForEach-Object {$_.SafeInfo = $safesht[$_.SafeName]}

$SafeMembersList = $null

if ($IncludeGroups){
    $SafeMembersList = $SafeMembers | Where-Object {($_.userinfo.UserType -In $IncludedUsersTypes) -or ($_.memberType -eq "Group")}
} else {
    $SafeMembersList = $SafeMembers | Where-Object {($_.userinfo.UserType -In $IncludedUsersTypes)}
}

IF ([string]::IsNullOrEmpty($SafeMembersList)){
    Write-Warning "No safe members found, please expand search partamters and try again. Ending script"
    Return
}
$props = @("Source", "UserType", `
        "Description", "managingCPM", "numberOfDaysRetention", "numberOfVersionsRetention"
)
$props | ForEach-Object {$SafeMembersList | Add-Member -MemberType NoteProperty -Name $_ -Value $null -Force}

$SafeMembersList | ForEach-Object {
    Write-Verbose "Working $($PSItem.MemberName) in safe $($PSItem.safeName)"

    #User information
    $_.Source = $_.userinfo.Source
    $_.UserType = $_.userinfo.UserType

    #Safe information
    $_.ManagingCPM = $_.safeinfo.managingCPM
    $_.Description = $_.safeinfo.Description
    $_.NumberOfDaysRetention = $_.safeinfo.NumberOfDaysRetention
    $_.NumberOfVersionsRetention = $_.safeinfo.NumberOfVersionsRetention

}

[array]$ReportProps = @("Username", "Source", "MemberType", "UserType", "SafeName", "Description", "managingCPM", "numberOfDaysRetention", "numberOfVersionsRetention")

IF (!$HidePerms) {
    If ([string]::IsNullOrEmpty($PermList)) {
        [array]$outputProps = $ReportProps + $($(($SafeMembersList.permissions | Get-Member | Where-Object MemberType -EQ "NoteProperty").name) |Where-Object {$PSItem -notIn $ReportProps})
    } else {
        [array]$outputProps = $ReportProps + $PermList
    } 
} else {
    [array]$outputProps = $ReportProps
}

$SafeMembersList | `
Select-Object -Property $ReportProps -ExpandProperty permissions |`
Select-Object -Property $outputProps | `
Sort-Object -Property username, safename |`
Export-Csv $ReportPath -NoTypeInformation
