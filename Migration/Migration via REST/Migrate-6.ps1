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

    [Parameter(Mandatory = $false, HelpMessage = "Export Items")]
    [switch]$export,

    [Parameter(Mandatory = $false, HelpMessage = "Process Safes")]
    [switch]$processSafes,
    
    [Parameter(Mandatory = $false, HelpMessage = "Process Accounts")]
    [switch]$processAccounts,

    [Parameter(Mandatory = $false, HelpMessage = "Update Allowed Remote Machines")]
    [switch]$getRemoteMachines,

    [Parameter(Mandatory = $false, HelpMessage = "Enter the Authentication type (Default:CyberArk)")]
    [ValidateSet("cyberark", "ldap", "radius")]
    [String]$SrcAuthType = "cyberark",

    [Parameter(Mandatory = $false, HelpMessage = "Enter the Authentication type (Default:CyberArk)")]
    [ValidateSet("cyberark", "ldap", "radius")]
    [String]$DstAuthType = "cyberark",
    
    [Parameter(Mandatory = $false, HelpMessage = "Enter the RADIUS OTP")]
    [ValidateScript({$AuthType -eq "radius"})]
    [String]$OTP,

    [Parameter(Mandatory = $true, HelpMessage = "Please enter your source PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
    #[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
    [Alias("srcurl")]
    [String]$SRCPVWAURL,
    [Parameter(Mandatory = $false, HelpMessage = "Please enter your destination PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
    #[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
    [Alias("dsturl")]
    [String]$DSTPVWAURL,
	
    [Parameter(Mandatory = $false, HelpMessage = "Source Vault Stored Credentials")]
    [PSCredential]$SRCPVWACredentials,

    [Parameter(Mandatory = $false, HelpMessage = "Destination Vault Stored Credentials")]

    [PSCredential]$DSTPVWACredentials,

    [Parameter(Mandatory = $false,
        HelpMessage = "Path and file name of the objects.csv file created by the export",
        ValueFromPipelineByPropertyName = $true)]
    [ValidateScript({Test-Path -Path $_ -PathType Leaf -IsValid})]
    [ValidatePattern('\.csv$')]
    $exportCSV = ".\ExportOfAccounts.csv",

    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true)]
    [ValidatePattern( '\.csv$' )]
    $importCSV = ".\ExportOfAccounts.csv",


    [Parameter(Mandatory = $false)]
    [String]$newLDAP,

    # Use this switch to Disable SSL verification (NOT RECOMMENDED)
    [Parameter(Mandatory = $false)]
    [Switch]$DisableSSLVerify,

    # Use this switch to skip checking of existing secrets
    [Parameter(Mandatory = $false)]
    [Switch]$SkipCheckSecret,

    # Use this switch to automatically create safes
    [Parameter(Mandatory = $false)]
    [Switch]$createSafes,

    # Use this switch to update safe membership
    [Parameter(Mandatory = $false)]
    [Switch]$UpdateSafeMembers,

    # Use this switch to prevent creation of accounts
    [Parameter(Mandatory = $false)]
    [Switch]$noCreate,

    # Use this switch to allow creation of accounts with empty secrets
    [Parameter(Mandatory = $false)]
    [Switch]$allowEmpty,
    
    # Use this variable to identify the old CPM
    [Parameter(Mandatory = $false)]
    [String]$CPMOld,

    # Use this variable to identify the new CPM
    [Parameter(Mandatory = $false)]
    [String]$CPMNew,

    # Use this variable to identify the Override to a single CPM
    [Parameter(Mandatory = $false)]
    [String]$CPMOverride,

    [Parameter(Mandatory = $false)]
    [String]$dstUPN,
	
    # Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off
    [Parameter(Mandatory = $false)]
    $srclogonToken,

    # Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off
    [Parameter(Mandatory = $false)]
    $dstlogonToken,

    [Parameter(Mandatory = $false)]
    $maxJobCount = 10

)

#Rest Error Codes to ignore
$global:SkipErrorCode = @("SFWS0007", "ITATS127E")

#region Writer Functions
$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent
$oldverbose = $VerbosePreference
if ($InVerbose) {
    $VerbosePreference = "continue"
}
# Get Script Location 
$ScriptFullPath = $MyInvocation.MyCommand.Path
$ScriptLocation = Split-Path -Parent $ScriptFullPath
$ScriptParameters = @()
$PSBoundParameters.GetEnumerator() | ForEach-Object { $ScriptParameters += ("-{0} '{1}'" -f $_.Key, $_.Value) }
$Script:g_ScriptCommand = "{0} {1}" -f $ScriptFullPath, $($ScriptParameters -join ' ')

$updatedSafes = @()

$cpmsInUse = "PrimaryCPM", "PCloud_CPM"

$ownersToRemove = "Auditors", "Backup Users", "Batch", "PasswordManager", "DR Users", "Master", "Notification Engines", "Notification Engine",
"Operators", "PTAAppUsers", "PTAAppUser", "PVWAGWAccounts", "PVWAAppUsers", "PVWAAppUser", "PVWAAppUser1", "PVWAAppUser2", "PVWAAppUser3", "PVWAAppUser4", "PVWAAppUser5",
"PVWAAppUser6", "PVWAUsers", "PVWAMonitor", "PSMUsers", "PSMAppUsers", "PTAUser"

$global:ownersToRemove += $ownersToRemove
$global:ownersToRemove += $cpmsInUse

$global:objectSafesToRemove = "System", "VaultInternal", "Notification Engine", "SharedAuth_Internal", "PVWAUserPrefs",
"PVWAConfig", "PVWAReports", "PVWATaskDefinitions", "PVWAPrivateUserPrefs", "PVWAPublicData", "PVWATicketingSystem", "PasswordManager",
"PasswordManagerTemp", "PasswordManager_Pending", "PasswordManager_workspace", "PasswordManager_ADInternal",
"PasswordManager_Info", "PasswordManagerShared", "AccountsFeed", "PSM", "xRay", "PIMSuRecordings", "xRay_Config",
"AccountsFeedADAccounts", "AccountsFeedDiscoveryLogs", "PSMSessions", "PSMLiveSessions", "PSMUniversalConnectors",
"PSMNotifications", "PSMUnmanagedSessionAccounts", "PSMRecordings", "PSMPADBridgeConf", "PSMPADBUserProfile", "PSMPADBridgeCustom",
"AppProviderConf"

# Script Version
$ScriptVersion = "0.10"

# Set Log file path
New-Variable -Name LOG_FILE_PATH -Value "$ScriptLocation\$(($MyInvocation.MyCommand.Name).Replace("ps1","log"))" -Scope Global -Force

$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent

Import-Module -Name ".\CyberArk-Migration.psm1" -Force

Set-SSLVerify($DisableSSLVerify)

# Check that the PVWA URL is OK
Test-PVWA -PVWAURL $SRCPVWAURL

Write-LogMessage -Type Info -MSG "Getting Source Logon Tokens"
If (![string]::IsNullOrEmpty($srclogonToken)) {
    if ($srclogonToken.GetType().name -eq "String") {
        $logonHeader = @{Authorization = $srclogonToken }
        Set-Variable -Scope Global -Name srcToken -Value $logonHeader
    } else {
        Set-Variable -Scope Global -Name srcToken -Value $srclogonToken
    }
} else {
    If (![string]::IsNullOrEmpty($SRCPVWACredentials)) {
        $creds = $srcPVWACredentials
    } else {
        $msg = "Enter your source $srcAuthType User name and Password" 
        $creds = $Host.UI.PromptForCredential($caption, $msg, "", "")
    }
    New-Variable -Name AuthType -Value $SrcAuthType -Scope Global -Force
    Import-Module -Name ".\CyberArk-Migration.psm1" -Force

    if ($AuthType -eq "radius" -and ![string]::IsNullOrEmpty($OTP)) {
        Set-Variable -Scope Global -Name srcToken -Value $(Get-Logon -Credentials $creds -AuthType $SrcAuthType -URL $SRCPVWAURL -OTP $OTP)
    } else {
        Set-Variable -Scope Global -Name srcToken -Value $(Get-Logon -Credentials $creds -AuthType $SrcAuthType -URL $SRCPVWAURL )
    }
    # Verify that we successfully logged on
    If ([string]::IsNullOrEmpty($global:srcToken)) { 
        Write-LogMessage -Type Error -MSG "No Source Credentials were entered" -Footer
        return # No logon header, end script 
    }

    
    $creds = $null
}
Write-LogMessage -type Debug -MSG "Source Token set to $($srcToken|ConvertTo-Json -Depth 10)"

if ($export) {
    Write-LogMessage -Type Info -Msg "Starting export of accounts"
    $srcAccounts = Get-Accounts -url $SRCPVWAURL -logonHeader $srcToken -limit 1000
    Write-LogMessage -Type Info -Msg "Found $($srcAccounts.count) accounts"
    $remove = $srcAccounts | Where-Object {$_.safename -In $objectSafesToRemove}
    Write-LogMessage -Type Info -Msg "Found $($remove.count) accounts in excluded safes and removing from list."
    $srcAccounts = $srcAccounts | Where-Object {$_.safename -notIn $objectSafesToRemove} 
    Write-LogMessage -Type Info -Msg "Starting export to CSV of $($srcAccounts.count) accounts"
    $srcAccounts | `
        Where-Object {$_.safename -notIn $objectSafesToRemove} | `
        Select-Object "name", "address", "userName", "safeName", "platformId", "id", @{ name = "PasswordLastChangeUTC"; Expression = {"$((([System.DateTimeOffset]::FromUnixTimeSeconds($_.secretManagement.lastModifiedTime)).DateTime).ToString())"}} |`
        Export-Csv -Path $exportCSV -NoTypeInformation
    Write-LogMessage -Type Info -Msg "Export of $($srcAccounts.count) accounts completed. All other switches will be ignored"
    exit
}

if ($processSafes -or $processAccounts) {
    Test-PVWA -PVWAURL $DSTPVWAURL

    Write-LogMessage -Type Info -MSG "Getting Destination Logon Tokens"
    If (![string]::IsNullOrEmpty($dstlogonToken)) {
        if ($dstlogonToken.GetType().name -eq "String") {
            $logonHeader = @{Authorization = $dstlogonToken }
            Set-Variable -Scope Global -Name dstToken -Value $logonHeader
        } else {
            Set-Variable -Scope Global -Name dstToken -Value $dstlogonToken
        }
    } else {
        If (![string]::IsNullOrEmpty($dstPVWACredentials)) {
            $creds = $dstPVWACredentials
        } else {
            $msg = "Enter your source $dstAuthType User name and Password" 
            $creds = $Host.UI.PromptForCredential($caption, $msg, "", "")
        }
        New-Variable -Name AuthType -Value $dstAuthType -Scope Global -Force
        Import-Module -Name ".\CyberArk-Migration.psm1" -Force

        if ($AuthType -eq "radius" -and ![string]::IsNullOrEmpty($OTP)) {
            Set-Variable -Scope Global -Name dstToken -Value $(Get-Logon -Credentials $creds -AuthType $dstAuthType -URL $DSTPVWAURL -OTP $OTP)
        } else {
            Set-Variable -Scope Global -Name dstToken -Value $(Get-Logon -Credentials $creds -AuthType $dstAuthType -URL $DSTPVWAURL )
        }
        # Verify that we successfully logged on
        If ($null -eq $global:dstToken) { 
            Write-LogMessage -Type Error -MSG "No Destination Credentials were entered" -Footer
            return # No logon header, end script 
        } 
        $creds = $null
    }
    Write-LogMessage -type Debug -MSG "Destination Token  set to $($dstToken|ConvertTo-Json -Depth 10)"

    if ($processSafes) {
    
        #region Safe Work
        [array]$safeobjects = Import-Csv $importCSV | Select-Object -Property safeName -Unique
        $safeobjects | Add-Member -MemberType NoteProperty -Name ID -Value $null -Force
        
        $i = 0
        foreach ($id in $safeobjects) {
            $safeobjects[$i].id = $i + 1
            $i++
        }

        New-Item -ItemType Directory -Force -Path .\Safes\ | Out-Null
        $safeProgress = @{}
        $safeobjects | ForEach-Object {$safeProgress.($_.id) = @{}}
        $safeProgressSync = [System.Collections.Hashtable]::Synchronized($safeProgress)
        $safeJob = $safeobjects | ForEach-Object -ThrottleLimit $maxJobCount -AsJob -Parallel {

            #region Setup
            #region Setup required variables
            $global:InDebug = $Using:InDebug
            $global:InVerbose = $Using:InVerbose           
            $createSafes = $using:createSafes
            $UpdateSafeMembers = $using:UpdateSafeMembers
            $objectSafesToRemove = $Using:objectSafesToRemove
            $srcToken = $using:srcToken
            $SRCPVWAURL = $using:SRCPVWAURL
            $dstToken = $using:dstToken
            $DSTPVWAURL = $using:DSTPVWAURL
            $CPMnew = $using:CPMnew
            $CPMOld = $using:CPMOld
            $CPMOverride = $using:CPMOverride
            $global:safename = $($PSItem.safeName)
            $global:LOG_FILE_PATH = ".\Safes\$safename.log"
            Import-Module .\CyberArk-Migration.psm1 -Force

            #endregion
            Function Write-LogMessage {
                param(
                    [String]$MSG,
                    [Switch]$NoWrite,
                    [String]$type
                )               
                $SafeStatus.log += "`[$safename`] $msg"
                If ("error" -eq $type) {
                    $SafeStatus.Error += $MSG 
                }
                if (!$NoWrite) {
                    CyberArk-Migration\Write-LogMessage -MSG $MSG -type $type -LogFile $LOG_FILE_PATH @Args
                    $process.Status = $msg
                } 
            }
            #region Setup Progress
            $syncCopy = $using:safeProgressSync
            $process = $syncCopy.$($PSItem.Id)
            $process.Id = $PSItem.Id
            $process.Activity = "Processing safe $($PSItem.safeName)"
            $process.Status = "Starting"
            #endregion
            #region Setup Logging
            $SafeStatus = @{
                id       = $PSItem.id
                safeName = $PSItem.safeName
                success  = $false
                Log      = @()
                safeData = $PSItem
                Error    = @()
            }
            #endregion
            #endregion
            Write-LogMessage -Type Debug -Msg "Working with Safe `"$safename`"" 

            If ($PSItem.safeName -in $objectSafesToRemove) {
                Write-LogMessage -Type Debug -Msg "Safe `"$($PSItem.safeName)`" is in the excluded safes list and will be skipped"
                $SafeStatus.success = $true
                continue
            }
            Write-LogMessage -Type Debug -Msg "Getting source safe `"$safename`""
            $srcSafe = Get-Safe -url $SRCPVWAURL -logonHeader $srcToken -safe $($PSItem.safeName)
            if ([string]::IsNullOrEmpty($srcSafe)) {
                Write-LogMessage -Type Error -Msg "Source safe `"$safename`" not Found. Skipping"
                Continue
            } else {
                Write-LogMessage -Type Debug -Msg "Source safe `"$safename`" located"
            }
            
            Write-LogMessage -Type Debug -Msg "Getting destination safe `"$safename`""
            $dstsafe = Get-Safe -url $DSTPVWAURL -logonHeader $dstToken -safe $($PSItem.safeName) -ErrorAction SilentlyContinue
           
            if ([string]::IsNullOrEmpty($dstsafe)) {
                Write-LogMessage -Type Debug -Msg "Destination safe `"$safename`" not Found"
                if ($createSafes) {
                    Try {
                        Write-LogMessage -Type Verbose -Msg "Source safe Information: $($srcSafe|ConvertTo-Json -Compress)"
                        if (![string]::IsNullOrEmpty($CPMOverride)) {
                            $dstSafe = New-Safe -url $DSTPVWAURL -logonHeader $dstToken -safe $srcSafe -cpnNameNew $CPMOverride
                        } elseIf ((![string]::IsNullOrEmpty($CPMOld)) -and (![string]::IsNullOrEmpty($CPMnew))) {
                            $dstSafe = New-Safe -url $DSTPVWAURL -logonHeader $dstToken -safe $srcSafe -cpnNameOld $CPMOld -cpnNameNew $CPMnew
                        } else {
                            $dstSafe = New-Safe -url $DSTPVWAURL -logonHeader $dstToken -safe $srcSafe
                        }
                        Write-LogMessage -Type Debug -Msg "Created safe `"$safename`""
                        $createdDstSafe = $true
                    } catch {
                        Write-LogMessage -Type Error -Msg "Error creating safe `"$safename`""
                        Write-LogMessage -Type Error -Msg "Error: $_"
                        $process.Completed = $true
                        continue 
                    }
                } else {
                    Write-LogMessage -Type Warning -Msg "Target safe `"$($PSItem.safeName)`" does not exist in destination and creating of safes disabled, skipping `"$($PSItem.safeName)`""
                    $SafeStatus.success = $true
                    continue 
                }
            } else {
                Write-LogMessage -Type Debug -Msg "Located destination safe `"$($dstsafe.safename)`""
            }

            If (($UpdateSafeMembers -or $createdDstSafe)) { 
                $srcSafeMembers = (Get-SafeMembers -url $SRCPVWAURL -logonHeader $srcToken -safe $PSItem.safeName).value
                Write-LogMessage -Type Debug -Msg "Retrived Source Safe Members from `"$($PSItem.safeName)`"."
                $dstSafeMembers = (Get-SafeMembers -url $DSTPVWAURL -logonHeader $dstToken -safe $PSItem.safeName).value.membername
                Write-LogMessage -Type Debug -Msg "Retrived Destination Safe Members from `"$($dstsafe.safename)`"."
                ForEach ($srcMember in $srcSafeMembers) {
                    Try {
                        Write-LogMessage -Type Debug -Msg "Working with Safe Member `"$($srcMember.membername)`" in Safe `"$($PSItem.safeName)`""
                        IF ($srcMember.membername -in $ownersToRemove) {
                            Write-LogMessage -Type Debug -Msg "Safe Member $($srcMember.membername) is in the excluded owners list"
                        } Else {
                            if ($srcMember.membername -in $dstSafeMembers -or $("$($srcMember.memberName)@$dstUPN") -in $dstSafeMembers) {
                                Write-LogMessage -Type Debug -Msg "Safe Member `"$($srcMember.membername)`" is a member of safe `"$($dstsafe.safename)`" attempting to update permissions" 
                                $groupSource = Get-GroupSource -url $SRCPVWAURL -logonHeader $srcToken -safemember $srcMember
                                if ($groupSource -eq "Vault") {
                                    $srcMember | Add-Member NoteProperty searchIn "$groupSource"
                                } elseif (![string]::IsNullOrEmpty($newLDAP)) {
                                    $srcMember | Add-Member NoteProperty searchIn "$newLDAP"
                                } else {
                                    $srcMember | Add-Member NoteProperty searchIn "$groupSource"
                                }
                                Update-SafeMember -url $DSTPVWAURL -logonHeader $dstToken -safe $PSItem.safename -safemember $srcMember -newLDAP $newLDAP | Out-Null
                                Write-LogMessage -Type Debug -Msg "Safe Member `"$($srcMember.membername)`" updated on safe `"$($dstsafe.safename)`""
                            } else {
                                if ($srcMember.memberId -match "[A-Z]") {
                                    Write-LogMessage -Type Debug -Msg "Safe Member `"$($srcMember.membername)`" is from PCloud ISPSS."
                                    Write-LogMessage -Type Debug -Msg "Attempting to add $($srcMember.MemberType) `"$($srcMember.membername)`" to safe `"$($dstsafe.safename)`""
                                    try {
                                        $null = New-SafeMember -url $DSTPVWAURL -logonHeader $dstToken -safe $PSItem.safename -safemember $srcMember -PCloud 
                                        Write-LogMessage -Type Debug -Msg "Safe Member $($srcMember.MemberType)  `"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`""
                                    } catch {
                                        Write-LogMessage -Type Debug -Msg "Safe Member $($srcMember.MemberType)  `"$($srcMember.membername)`" faild to added to safe `"$($dstsafe.safename)`" changing memberType to Role and trying again"
                                        $srcMember.memberType = "Role"
                                        $null = New-SafeMember -url $DSTPVWAURL -logonHeader $dstToken -safe $safename -safemember $srcMember -PCloud 
                                        Write-LogMessage -Type Debug -Msg "Safe Member $($srcMember.MemberType)  `"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`""
                                    }
                                } elseif ($srcMember.memberType -eq "User") {
                                    Write-LogMessage -Type Debug -Msg "Safe Member `"$($srcMember.membername)`" is a user, attempting to find source" 
                                    $userSource = Get-UserSource -url $SRCPVWAURL -logonHeader $srcToken -safemember $srcMember
                                    Write-LogMessage -Type Debug -Msg "Safe Member `"$($srcMember.membername)`" source is `"$userSource`""
                                    $srcMember | Add-Member NoteProperty searchIn $userSource
                                    If (![string]::IsNullOrEmpty($dstUPN) -and ![string]::IsNullOrEmpty($userSource)) {
                                        $srcMember.memberName = "$($srcMember.memberName)@$dstUPN"
                                    }
                                    Write-LogMessage -Type Debug -Msg "Attempting to add user `"$($srcMember.membername)`" to safe `"$($dstsafe.safename)`""
                                    $null = New-SafeMember -url $DSTPVWAURL -logonHeader $dstToken -safe $PSItem.safename -safemember $srcMember -newLDAP $newLDAP 
                                    Write-LogMessage -Type Debug -Msg "Safe Member User`"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`""
                                } elseif ($srcMember.memberType -eq "Group") {
                                    Write-LogMessage -Type Debug -Msg "Safe Member `"$($srcMember.membername)`" is a group, attempting to find source" 
                                    $groupSource = Get-GroupSource -url $SRCPVWAURL -logonHeader $srcToken -safemember $srcMember
                                    if ($groupSource -eq "Vault") {
                                        $srcMember | Add-Member NoteProperty searchIn "$groupSource"
                                    } elseif (![string]::IsNullOrEmpty($newLDAP)) {
                                        $srcMember | Add-Member NoteProperty searchIn "$newLDAP"
                                    } else {
                                        $srcMember | Add-Member NoteProperty searchIn "$groupSource"
                                    }
                                    Write-LogMessage -Type Debug -Msg "Safe Member `"$($srcMember.membername)`" source is `"$groupSource`""
                                    Write-LogMessage -Type Debug -Msg "Attempting to add group `"$($srcMember.membername)`" to safe `"$($dstsafe.safename)`""
                                    New-SafeMember -url $DSTPVWAURL -logonHeader $dstToken -safe $PSItem.safename -safemember $srcMember -newLDAP $newLDAP | Out-Null
                                    Write-LogMessage -Type Debug -Msg "Safe Member Group `"$($srcMember.membername)`" from source `"$groupSource`" added to safe `"$($dstsafe.safename)`""
                                } else {
                                    Write-LogMessage -Type Debug -Msg "Safe Member `"$($srcMember.membername)`" is a unknown and is being skipped"
                                } 
                            }
                        }
                    } Catch {
                        Write-LogMessage -Type Error -Msg "Error working with safe `"$($dstsafe.safename)`" and Safe Member `"$($srcMember.membername)`""
                        Write-LogMessage -Type Error -Msg "Error: $_"  
                        continue
                    }
                }
                $SafeStatus.success = $true 
            } else {
                Write-LogMessage -Type Debug -Msg "Creating and/or Updating of Safe Members is disabled. Memberships of `"$($dstsafe.safename)`" not changed"
                $SafeStatus.success = $true
            } 
            $process.Completed = $true
            $SafeStatus  
        }
    }
    $PSStyle.Progress.View = "Classic"
    while ($safeJob.State -eq 'Running') {
        $safeProgressSync.Keys | ForEach-Object {
            # If key is not defined, ignore
            if (![string]::IsNullOrEmpty($safeProgressSync.$_.keys)) {
                # Create parameter hashtable to splat
                $param = $safeProgressSync.$_

                # Execute Write-Progress
                Write-Progress @param
            }
        }

        # Wait to refresh to not overload gui
        Start-Sleep -Seconds 0.1
    }
}
$($SafeReport = Receive-Job $Safejob) 6> $null
$SafeSuccess = $SafeReport | Where-Object success -EQ $true
$SafeFailed = $SafeReport | Where-Object success -EQ $false
If (![string]::IsNullOrEmpty($SafeFailed)) {
    $SafeFailed.SafeData | Add-Member -MemberType NoteProperty -Name FailReason -Value $null -Force
    $i = 0
    foreach ($id in $SafeFailed) {
        $SafeFailed[$i].SafeData.FailReason = $SafeFailed[$i].Error
        $i++
    }
    $SafeFailed.SafeData | Export-Csv .\FailedSafes.csv
}
"Safes succesfully update: $($SafeSuccess.success.count)"
"Safes failed update: $($SafeFailed.success.count)"
#endregion
if ($processAccounts) {
    #region Account Work 
    [array]$accountobjects = Import-Csv $importCSV
    $accountobjects | Add-Member -MemberType NoteProperty -Name ProcessID -Value $null -Force
    
    $i = 0
    foreach ($id in $accountobjects) {
        $accountobjects[$i].ProcessID = $i + 1
        $i++
    }
    
    New-Item -ItemType Directory -Force -Path .\Accounts\ | Out-Null
    $accountProgress = @{}
    $accountobjects | ForEach-Object {$accountProgress.($_.ProcessID) = @{}}
    $accountProgressSync = [System.Collections.Hashtable]::Synchronized($accountProgress)
    $AccountJob = $accountobjects | ForEach-Object -ThrottleLimit $maxJobCount -AsJob -Parallel {
        
        #region Setup
        #region Setup required variables
        $global:InDebug = $Using:InDebug
        $global:InVerbose = $Using:InVerbose

        $SkipCheckSecret = $Using:SkipCheckSecret
        $objectSafesToRemove = $Using:objectSafesToRemove
        $getRemoteMachines = $using:getRemoteMachines
        $noCreate = $using:noCreate
        $allowEmpty = $using:allowEmpty

        $srcToken = $using:srcToken
        $SRCPVWAURL = $using:SRCPVWAURL
        $dstToken = $using:dstToken
        $DSTPVWAURL = $using:DSTPVWAURL

        $baseAccount = $PSItem
        $global:accountID = $($PSItem.id)
        $global:accountName = $($PSItem.name)
        $global:safeName = $($PSItem.safeName)
        $global:LOG_FILE_PATH = ".\Accounts\$safeName-$accountID-$accountName.log"
        Import-Module .\CyberArk-Migration.psm1 -Force

        #endregion
        Function Write-LogMessage {
            param(
                [String]$MSG,
                [Switch]$NoWrite,
                [String]$type
            )               
            $AccountStatus.log += "`[$accountID`] $msg"
            If (("error" -eq $type) -or ("Warning" -eq $type) ) {
                $AccountStatus.Error = $MSG 
            }
            if (!$NoWrite) {
                CyberArk-Migration\Write-LogMessage -MSG $MSG -type $type -LogFile $LOG_FILE_PATH @Args
                $process.Status = $msg
            } 
        }
        Try {

            $syncCopy = $using:accountProgressSync
            $process = $syncCopy.$($baseAccount.ProcessID)
            $process.Id = $PSItem.ProcessID
            $process.Activity = "Processing account $($baseAccount.name)"
            $process.Status = "Starting"
            #endregion
            #region Setup Logging
            $AccountStatus = @{
                id          = $PSItem.ProcessID
                accountName = $PSItem.name
                success     = $false
                Log         = @()
                accountData = $PSItem
                Error       = @()
            }
            $found = $false

            Write-LogMessage -Type Debug -Msg "Getting source account with username `"$($baseAccount.userName)`" and address `"$($baseAccount.address)`" in safe `"$($baseAccount.safeName)`""
            Try {
                $srcAccount = Get-AccountDetail -url $SRCPVWAURL -logonHeader $srcToken -AccountID $baseAccount.id 
            } catch {
                Write-LogMessage -Type Error -Msg "Unable to connect to source account to retrieve username `"$($baseAccount.userName)`" and address `"$($baseAccount.address)`" in safe `"$($baseAccount.safeName)`""
                continue
            }
            If ($($srcAccount.safename) -in $objectSafesToRemove) {
                Write-LogMessage -Type Debug -Msg "Safe $($srcAccount.safename) is in the excluded safes list. Account with username of `"$($srcAccount.userName)`" with the address of `"$($srcAccount.address)`" will be skipped"
                $AccountStatus.success = $true
                continue
            }
            Write-LogMessage -Type Debug -Msg "Getting destination account with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`""
            [array]$dstAccountArray = Get-Accounts -url $DSTPVWAURL -logonHeader $dstToken -safename $($srcAccount.safeName) -keywords "$($srcAccount.userName) $($srcAccount.address)" -startswith $true
            Write-LogMessage -Type Verbose -MSG "destination count: $($dstAccountArray.count)"
            if ((0 -ne $($dstAccountArray.count))) {
                Write-LogMessage -Type Verbose -MSG "Source: $($srcAccount | ConvertTo-Json)"
                Write-LogMessage -Type Verbose -MSG "Found: $($dstAccountArray | ConvertTo-Json)"
                Write-LogMessage -Type Debug -Msg "Found $($dstAccountArray.count) possible destination accounts"
                foreach ($account in $dstAccountArray) {
                    Write-LogMessage -Type Debug -Msg "Comparing found account `"$($account.name)`" to source account of `"$($srcAccount.name)`""
                    IF (($($account.name) -eq $($srcAccount.name)) -and ($($account.userName) -eq $($srcAccount.userName)) -and ($($account.address) -eq $($srcAccount.address)) -and ($($account.safeName) -eq $($srcAccount.safeName))  ) {
                        Write-LogMessage -Type Debug -Msg "Found Account with username `"$($account.userName)`" and address `"$($account.address)`" in safe `"$($account.safeName)`""
                        Write-LogMessage -Type Debug -Msg "$($account | ConvertTo-Json)"
                        $found = $true
                        $dstAccount = $account
                    }
                }
            } else {
                Write-LogMessage -Type Error -Msg "Unable to locate account in destination"
            }
    
            if ($found) {
                if (!$SkipCheckSecret) {
                    Try {
                        Write-LogMessage -Type Debug -Msg "Getting source Secret"
                        [SecureString]$srcSecret = Get-Secret -url $SRCPVWAURL -logonHeader $srcToken -id $srcAccount.id -ErrorAction SilentlyContinue
                        Write-LogMessage -Type Debug -Msg "Getting destination Secret"
                        [SecureString]$dstSecret = Get-Secret -url $DSTPVWAURL -logonHeader $dstToken -id $dstAccount.id -ErrorAction SilentlyContinue

                        If ((![string]::IsNullOrEmpty($srcSecret)) -and (![string]::IsNullOrEmpty($dstSecret)) ) {
                            $secretMatch = Compare-SecureString -pwd1 $srcSecret -pwd2 $dstSecret
                        }
                        if ($null -eq $dstSecret -and $null -ne $srcSecret) {
                            Write-LogMessage -Type Debug -Msg "No secret found on destination account $($dstAccount.Name). Setting destination secret to match source secret."
                            Set-Secret -url $DSTPVWAURL -logonHeader $dstToken -id $dstAccount.id -secret $srcSecret
                            Write-LogMessage -Type Debug -Msg "Destination account `"$($dstAccount.Name)`" secret set."
                            $AccountStatus.success = $true
                        } elseif ($null -eq $srcSecret) {
                            Write-LogMessage -Type Debug -Msg "No secret found on source account $($srcSecret.Name). No change will be made to destination secret."
                            $AccountStatus.success = $true
                        } elseif (!$secretMatch) {
                            Write-LogMessage -Type Debug -Msg "Source Account `"$($srcAccount.Name)`" and destination account `"$($dstAccount.Name)`" secret do not match. Setting destination secret to match source secret."
                            Set-Secret -url $DSTPVWAURL -logonHeader $dstToken -id $dstAccount.id -secret $srcSecret
                            Write-LogMessage -Type Debug -Msg "Destination account `"$($dstAccount.Name)`" secret set."
                            $AccountStatus.success = $true
                        } elseif ($secretMatch) {
                            Write-LogMessage -Type Debug -Msg "Source Account `"$($srcAccount.Name)`" and Destination account `"$($dstAccount.Name)`" secret match. No update required" 
                            $AccountStatus.success = $true
                        } else {
                            Write-LogMessage -Type Warning -Msg "Unknown Error encountered on Source Account `"$($srcAccount.Name)`" and Destination account `"$($dstAccount.Name)`" while working with secrets"
                        }
                    } catch [System.Management.Automation.RuntimeException] {
                        If ("Account Locked" -eq $_) {
                            Write-LogMessage -Type Warning -Msg "Source Account `"$($srcAccount.Name)`" Locked, unable to update"
                        }
                    } 
                } Else {
                    Write-LogMessage -Type Debug -Msg "SkipCheckSecret set to true. No checks being done on source and destination secrets"
                    $AccountStatus.success = $true
                }
                if ($getRemoteMachines) {
                    Update-RemoteMachine -url $DSTPVWAURL -logonHeader $dstToken -dstaccount $dstAccount -srcaccount $srcAccount
                }
            } elseif ($noCreate) {
                Write-LogMessage -Type Warning -Msg "Destination account in safe `"$($srcAccount.safeName)`" does not exist and account creation disabled, skipping creation of account `"$($srcAccount.Name)`""
                $AccountStatus.success = $true
            } else {
                try {
                    write-LogMessage -Type info -Msg "Checking for destination safe `"$($srcAccount.safeName)`""
                    $dstsafe = Get-Safe -url $DSTPVWAURL -logonHeader $dstToken -safe $srcAccount.safeName
                    if ([string]::IsNullOrEmpty($dstsafe)) {
                        Write-LogMessage -Type error -Msg "Destination safe of `"$($srcAccount.safeName)`" does not exist, skipping creation of account `"$($srcAccount.Name)`""
                    }
                    [SecureString]$srcSecret = Get-Secret -url $SRCPVWAURL -logonHeader $srcToken -id $srcAccount.id
                    IF (![string]::IsNullOrEmpty($srcSecret)) {
                        $dstAccount = New-Account -url $DSTPVWAURL -logonHeader $dstToken -account $srcAccount -secret $srcSecret 
                    } elseif ($allowEmpty) {
                        $dstAccount = New-Account -url $DSTPVWAURL -logonHeader $dstToken -account $srcAccount -allowEmpty   
                    } else {
                        Write-LogMessage -Type Warning -Msg "No password set on source for `"$($srcAccount.Name)`""
                    }
                    $AccountStatus.success = $true
                } catch [System.Management.Automation.RuntimeException] {
                    If ("Account Locked" -eq $_.Exception.Message) {
                        Write-LogMessage -Type Warning -Msg "Source Account `"$($srcAccount.Name)`" Locked, unable to update"
                    } elseIf ($_.Exception.Message -match 'Safe .* was not found') {
                        Write-LogMessage -Type Warning -Msg "Source safe `"$($srcAccount.safeName)`" not found"
                    } else {
                        Write-LogMessage -Type Warning -Msg "Unknown Error encountered on retriving secret for `"$($srcAccount.Name)`""
                    }
                }
            }            
        } Finally {
            $accountStatus
            $process.Completed = $true
        }
    }
    $PSStyle.Progress.View = "Classic"
    while ($AccountJob.State -eq 'Running') {
        $accountProgressSync.Keys | ForEach-Object {
            # If key is not defined, ignore
            if (![string]::IsNullOrEmpty($accountProgressSync.$_.keys)) {
                # Create parameter hashtable to splat
                $param = $accountProgressSync.$_

                # Execute Write-Progress
                Write-Progress @param
            }
        }

        # Wait to refresh to not overload gui
        Start-Sleep -Seconds 0.1
    }
}
$($AccountReport = Receive-Job $accountjob) 6> $null
$AccountSuccess = $AccountReport | Where-Object success -EQ $true
$AccountFailed = $AccountReport | Where-Object success -EQ $false
If (![string]::IsNullOrEmpty($AccountFailed)) {
    [array]$AccountFailed.accountData | Add-Member -MemberType NoteProperty -Name FailReason -Value $null -Force
    $i = 0
    foreach ($id in $AccountFailed) {
        $AccountFailed[$i].accountData.FailReason = $AccountFailed[$i].Error
        $i++
    }
    $AccountFailed.accountData | Export-Csv .\FailedAccounts.csv
}
"Accounts succesfully update: $($accountSuccess.success.count)"
"Accounts failed update: $($AccountFailed.success.count)"

#region [Logoff]
# Logoff the session
# ****************--
Write-Host "Logoff Session..."
If (![string]::IsNullOrEmpty($srclogonToken)) {
    if (![string]::IsNullOrEmpty($srcToken)) { 
        Invoke-Logoff -url $SRCPVWAURL -logonHeader $srcToken -ErrorAction SilentlyContinue
    }
}
If (![string]::IsNullOrEmpty($dstlogonToken)) {
    if (![string]::IsNullOrEmpty($dstToken)) { 
        Invoke-Logoff -url $DSTPVWAURL -logonHeader $dstToken -ErrorAction SilentlyContinue
    }
}

Remove-Variable -Name LOG_FILE_PATH -Scope Global -Force -ErrorAction Ignore
Remove-Variable -Name AuthType -Scope Global -Force -ErrorAction Ignore

#endregion

$VerbosePreference = $oldverbose
