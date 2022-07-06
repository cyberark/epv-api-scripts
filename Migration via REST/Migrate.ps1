<# 
###########################################################################

NAME: 
    Migration.PS1 

AUTHOR:  
    Brian Bors  <brian.bors@cyberark.com>
    Assaf Miron <assaf.miron@cyberark.com>

COMMENT: 
    Script used migrate data between two environments

Version: 
    0.1

Change Log:
    2020-09-13 
        Initial Version    

########################################################################### 
#>


[CmdletBinding()]
param(

    [Parameter(Mandatory=$false,HelpMessage="Export Items")]
    [switch]$export,

    [Parameter(Mandatory=$false,HelpMessage="Process File")]
    [switch]$processFile,


    [Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
    [ValidateSet("cyberark","ldap","radius")]
    [String]$SrcAuthType="cyberark",

    [Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
    [ValidateSet("cyberark","ldap","radius")]
    [String]$DstAuthType="cyberark",
    
    [Parameter(Mandatory=$false,HelpMessage="Enter the RADIUS OTP")]
    [ValidateScript({$AuthType -eq "radius"})]
    [String]$OTP,

    [Parameter(Mandatory=$true,HelpMessage="Please enter your source PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
    #[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
    [Alias("srcurl")]
    [String]$SRCPVWAURL,
    [Parameter(Mandatory=$false,HelpMessage="Please enter your destination PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
    #[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
    [Alias("dsturl")]
    [String]$DSTPVWAURL,
	
    [Parameter(Mandatory=$true,HelpMessage="Source Vault Stored Credentials")]
    [PSCredential]$SRCPVWACredentials,

    [Parameter(Mandatory=$false,HelpMessage="Destination Vault Stored Credentials")]

    [PSCredential]$DSTPVWACredentials,

    [Parameter(Mandatory=$false,
        HelpMessage="Path and file name of the objects.csv file created by the export",
        ValueFromPipelineByPropertyName=$true)]
    [ValidateScript({Test-Path -Path $_ -PathType Leaf -IsValid})]
    [ValidatePattern('\.csv$')]
    $exportCSV="$($env:TEMP)\ExportOfAccounts.csv",

    [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
    [ValidatePattern( '\.csv$' )]
    $importCSV="$($env:TEMP)\ExportOfAccounts.csv",


    [Parameter(Mandatory=$false)]
    [String]$newLDAP,

    # Use this switch to Disable SSL verification (NOT RECOMMENDED)
    [Parameter(Mandatory=$false)]
    [Switch]$DisableSSLVerify,

    # Use this switch to skip checking of existing secrets
    [Parameter(Mandatory=$false)]
    [Switch]$SkipCheckSecret,

    # Use this switch to automatically create safes
    [Parameter(Mandatory=$false)]
    [Switch]$createSafes,

    # Use this switch to update safe membership
    [Parameter(Mandatory=$false)]
    [Switch]$UpdateSafeMembers,

    # Use this variable to identify the old CPM
    [Parameter(Mandatory=$false)]
    [String]$CPMOld,

    # Use this variable to identify the new CPM
    [Parameter(Mandatory=$false)]
    [String]$CPMNew,

    [Parameter(Mandatory=$false)]
    [String]$dstUPN

)

#Rest Error Codes to ignore
$global:SkipErrorCode = @("SFWS0007","ITATS127E")

#region Writer Functions
$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent
$oldverbose = $VerbosePreference
if($InVerbose){
    $VerbosePreference = "continue"
}
# Get Script Location 
$ScriptFullPath = $MyInvocation.MyCommand.Path
$ScriptLocation = Split-Path -Parent $ScriptFullPath
$ScriptParameters = @()
$PSBoundParameters.GetEnumerator() | ForEach-Object { $ScriptParameters += ("-{0} '{1}'" -f $_.Key, $_.Value) }
$Script:g_ScriptCommand = "{0} {1}" -f $ScriptFullPath, $($ScriptParameters -join ' ')

$updatedSafes =@()

$cpmsInUse="PrimaryCPM","PCloud_CPM"

$ownersToRemove = "Auditors","Backup Users","Batch","PasswordManager","DR Users","Master","Notification Engines","Notification Engine",
"Operators","PTAAppUsers","PTAAppUser","PVWAGWAccounts","PVWAAppUsers","PVWAAppUser","PVWAAppUser1","PVWAAppUser2","PVWAAppUser3","PVWAAppUser4","PVWAAppUser5",
"PVWAAppUser6","PVWAUsers","PVWAMonitor","PSMUsers","PSMAppUsers","PTAUser"

$ownersToRemove +=$cpmsInUse

$objectSafesToRemove="System","VaultInternal","Notification Engine","SharedAuth_Internal","PVWAUserPrefs",
"PVWAConfig","PVWAReports","PVWATaskDefinitions","PVWAPrivateUserPrefs","PVWAPublicData","PVWATicketingSystem","PasswordManager",
"PasswordManagerTemp","PasswordManager_Pending","PasswordManager_workspace","PasswordManager_ADInternal",
"PasswordManager_Info","PasswordManagerShared","AccountsFeed","PSM","xRay","PIMSuRecordings","xRay_Config",
"AccountsFeedADAccounts","AccountsFeedDiscoveryLogs","PSMSessions","PSMLiveSessions","PSMUniversalConnectors",
"PSMNotifications","PSMUnmanagedSessionAccounts","PSMRecordings","PSMPADBridgeConf","PSMPADBUserProfile","PSMPADBridgeCustom",
"AppProviderConf"

# Script Version
$ScriptVersion = "0.10"

# Set Log file path
New-Variable -Name LOG_FILE_PATH -Value "$ScriptLocation\$(($MyInvocation.MyCommand.Name).Replace("ps1","log"))" -Scope Global -Force

New-Variable -Name AuthType -Value $AuthType -Scope Global -Force

$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent

Import-Module -Name ".\CyberArk-Migration.psm1" -Force

Set-SSLVerify($DisableSSLVerify)

# Check that the PVWA URL is OK
Test-PVWA -PVWAURL $SRCPVWAURL
Write-LogMessage -Type Info -MSG "Getting Logon Tokens"

$srcToken = Get-Logon -url $SRCPVWAURL -Credentials $SRCPVWACredentials -AuthType $SrcAuthType

if ($export) {
    Write-LogMessage -Type Info -Msg "Starting export of accounts"
    $srcAccounts = Get-Accounts -url $SRCPVWAURL -logonHeader $srcToken -limit 1000
    Write-LogMessage -Type Info -Msg "Starting export to CSV of $($srcAccounts.count) accounts"
    $srcAccounts | `
        Where-Object {$_.safename -notIn $objectSafesToRemove} | `
        Select-Object -Property "name","address","userName","safeName","platformId","id" | `

        Export-Csv -Path $exportCSV -NoTypeInformation
}

if ($processFile){


    $dstToken = Get-Logon -url $DSTPVWAURL -Credentials $DSTPVWACredentials -AuthType $dstAuthType
    Test-PVWA -PVWAURL $DSTPVWAURL


    $counter = 0

    $objects = Import-Csv $importCSV
    foreach ($object in $objects){
        $counter++
        $found = $false

        If (!$InVerbose){
        Write-Progress -Activity "Processing objects" -CurrentOperation "$counter of $($objects.count)" -PercentComplete (($counter / $objects.count)*100)
        }$srcAccount = Get-AccountDetail -url $SRCPVWAURL -logonHeader $srcToken -AccountID $object.id
        If ($($srcAccount.safename) -in $objectSafesToRemove){
            Write-LogMessage -Type Debug -Msg "Safe $($srcAccount.safename) is in the excluded safes list. Account with username of `"$($srcAccount.userName)`" with the address of `"$($srcAccount.address)`" will be skipped"
            continue
        }

        $dstAccountArray = Get-Accounts -url $DSTPVWAURL -logonHeader $dstToken -safename $($srcAccount.safeName) -keywords "$($srcAccount.userName) $($srcAccount.address)" -startswith $true
        if(![string]::IsNullOrEmpty($dstAccountArray)){
            foreach($account in $dstAccountArray){
        

                IF(($($account.name) -eq $($srcAccount.name)) -and ($($account.userName) -eq $($srcAccount.userName)) -and ($($account.address) -eq $($srcAccount.address)) -and ($($account.safeName) -eq $($srcAccount.safeName))  ){
                    Write-LogMessage -Type Debug -Msg "Found Account with username `"$($account.userName)`" and address `"$($account.address)`" in safe `"$($account.safeName)`""

                    $found = $true
                    $dstAccount = $account
                }
            }
        }

        $srcSafe = Get-Safe -url $SRCPVWAURL -logonHeader $srcToken -safe $($srcAccount.safename)

        $dstsafe = Get-Safe -url $DSTPVWAURL -logonHeader $dstToken -safe $($srcAccount.safename)

        if ([string]::IsNullOrEmpty($dstsafe)) {
            if($createSafes){

                If ((![string]::IsNullOrEmpty($CPMOld)) -and (![string]::IsNullOrEmpty($CPMnew))) {
                    $dstSafe = New-Safe -url $DSTPVWAURL -logonHeader $dstToken -safe $srcSafe -cpnNameOld $CPMOld -cpnNameNew $CPMnew
                    Write-LogMessage -Type Debug -Msg "Created safe `"$($srcAccount.safename)`""
                } else {
                    $dstSafe = New-Safe -url $DSTPVWAURL -logonHeader $dstToken -safe $srcSafe
                    Write-LogMessage -Type Debug -Msg "Created safe `"$($srcAccount.safename)`""
                }
                $createdDstSafe = $true

            } else {
                Write-LogMessage -Type Warning -Msg "Target safe `"$($srcAccount.safename)`" does not exist in destination and creating of safes disabled, skipping `"$($srcAccount.name)`""
                continue 
            }
        } else {
            Write-LogMessage -Type Debug -Msg "Located safe `"$($dstsafe.safename)`""
        }
        IF ($($dstsafe.safename) -in $updatedSafes){
            Write-LogMessage -Type Debug -Msg "Safe `"$($dstsafe.safename)`" was previously created or updated. No further updates of safe memberships required" 
        } Else {
            If(($UpdateSafeMembers -or $createdDstSafe)){

                $srcSafeMembers = (Get-SafeMembers -url $SRCPVWAURL -logonHeader $srcToken -safe $($srcAccount.safename)).value
                Write-LogMessage -Type Debug -Msg "Retrived Source Safe Members from $($srcAccount.safename)."
                $dstSafeMembers = (Get-SafeMembers -url $DSTPVWAURL -logonHeader $dstToken -safe $($srcAccount.safename)).value.membername
                Write-LogMessage -Type Debug -Msg "Retrived Destination  Safe Members from $($dstsafe.safename)."

                ForEach ($srcMember in $srcSafeMembers){
                    IF ($srcMember.membername -in $ownersToRemove){
                        Write-LogMessage -Type Debug -Msg "Safe Member $($srcMember.membername) is in the excluded owners list"
                    } Else{
                        if ($srcMember.membername -in $dstSafeMembers -or $("$($srcMember.memberName)@$dstUPN") -in $dstSafeMembers){
                            $null = Update-SafeMember -url $DSTPVWAURL -logonHeader $dstToken -safe $($srcAccount.safename) -safemember $srcMember -newLDAP $newLDAP 
                            Write-LogMessage -Type Debug -Msg "Safe Member `"$($srcMember.membername)`" updated on safe `"$($dstsafe.safename)`""
                        } else {
                            if ($srcMember.memberType -eq "User"){
                                $userSource = Get-UserSource -url $SRCPVWAURL -logonHeader $srcToken -safemember $srcMember
                                $srcMember | Add-Member NoteProperty searchIn $userSource
                                If (![string]::IsNullOrEmpty($dstUPN) -and ![string]::IsNullOrEmpty($userSource)){
                                    $srcMember.memberName = "$($srcMember.memberName)@$dstUPN"
                                }
                                $null = New-SafeMember -url $DSTPVWAURL -logonHeader $dstToken -safe $($srcAccount.safename) -safemember $srcMember -newLDAP $newLDAP 
                                Write-LogMessage -Type Debug -Msg "Safe Member `"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`""
                            } else {
                                $groupSource = Get-GroupSource -url $SRCPVWAURL -logonHeader $srcToken -safemember $srcMember
                                $srcMember | Add-Member NoteProperty searchIn $groupSource
                                $null = New-SafeMember -url $DSTPVWAURL -logonHeader $dstToken -safe $($srcAccount.safename) -safemember $srcMember -newLDAP $newLDAP 
                            } 
                        }
                    }
                }
            } else {
                Write-LogMessage -Type Debug -Msg "Creating and/or Updating of Safe Members is disabled. Memberships of `"$($dstsafe.safename)`" not changed" 
            }
        }
    
        if ($found) {
            if (!$SkipCheckSecret){
                Try{
                    [SecureString]$srcSecret = Get-Secret -url $SRCPVWAURL -logonHeader $srcToken -id $srcAccount.id 
                    [SecureString]$dstSecret = Get-Secret -url $DSTPVWAURL -logonHeader $dstToken -id $dstAccount.id 

                    If ((![string]::IsNullOrEmpty($srcSecret)) -and (![string]::IsNullOrEmpty($dstSecret)) ){
                        $secretMatch = Compare-SecureString -pwd1 $srcSecret -pwd2 $dstSecret
                    }
            
                    if ($null -eq $dstSecret -and $null -ne $srcSecret){
                        Write-LogMessage -Type Debug -Msg "No secret found on destination account $($dstAccount.Name). Setting destination secret to match source secret."
                        Set-Secret -url $DSTPVWAURL -logonHeader $dstToken -id $dstAccount.id -secret $srcSecret
                        Write-LogMessage -Type Debug -Msg "Destination account `"$($dstAccount.Name)`" secret set."
                    } elseif ($null -eq $srcSecret){
                        Write-LogMessage -Type Debug -Msg "No secret found on source account $($srcSecret.Name). No change will be made to destination secret."
                    } elseif (!$secretMatch) {
                        Write-LogMessage -Type Debug -Msg "Source Account `"$($srcAccount.Name)`" and destination account `"$($dstAccount.Name)`" secret do not match. Setting destination secret to match source secret."
                        Set-Secret -url $DSTPVWAURL -logonHeader $dstToken -id $dstAccount.id -secret $srcSecret
                        Write-LogMessage -Type Debug -Msg "Destination account `"$($dstAccount.Name)`" secret set."
                    } elseif ($secretMatch) {
                        Write-LogMessage -Type Debug -Msg "Source Account `"$($srcAccount.Name)`" and Destination account `"$($dstAccount.Name)`" secret match. No update required" 
                    } else {
                        Write-LogMessage -Type Warning -Msg "Unknown Error encountered on Source Account `"$($srcAccount.Name)`" and Destination account `"$($dstAccount.Name)`" while working with secrets"
                    }
                } catch [System.Management.Automation.RuntimeException] {
                    If ("Account Locked" -eq $_.Exception){
                        Write-LogMessage -Type Warning -Msg "Source Account `"$($srcAccount.Name)`" Locked, unable to update"
                    }
                } 
            } Else {
                Write-LogMessage -Type Debug -Msg "SkipCheckSecret set to true. No checks being done on source and destination secrets"
            }
        } else {
            try {
                [SecureString]$srcSecret = Get-Secret -url $SRCPVWAURL -logonHeader $srcToken -id $srcAccount.id
                IF (![string]::IsNullOrEmpty($srcSecret)){
                    $dstAccount = New-Account -url $DSTPVWAURL -logonHeader $dstToken -account $srcAccount -secret $srcSecret 
                } else {
                    Write-LogMessage -Type Warning -Msg "Unknown Error encountered on retriving secret from Source Account `"$($srcAccount.Name)`""
                }
            } catch [System.Management.Automation.RuntimeException] {
                If ("Account Locked" -eq $_.Exception.Message){
                    Write-LogMessage -Type Warning -Msg "Source Account `"$($srcAccount.Name)`" Locked, unable to update"
                }
            }
        }
    }
}

#region [Logoff]
# Logoff the session
# ------------------
Write-Host "Logoff Session..."

Invoke-Logoff -url $SRCPVWAURL -logonHeader $srcToken
if (![string]::IsNullOrEmpty($dstToken)){ 
    Invoke-Logoff -url $DSTPVWAURL -logonHeader $dstToken
}


Remove-Variable -Name LOG_FILE_PATH -Scope Global -Force
Remove-Variable -Name AuthType -Scope Global -Force

#endregion

$VerbosePreference = $oldverbose
