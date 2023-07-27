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
	
    [Parameter(Mandatory = $true, HelpMessage = "Source Vault Stored Credentials")]
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
    
    # Use this variable to identify the old CPM
    [Parameter(Mandatory = $false)]
    [String]$CPMOld,

    # Use this variable to identify the new CPM
    [Parameter(Mandatory = $false)]
    [String]$CPMNew,

    [Parameter(Mandatory = $false)]
    [String]$dstUPN,
	
    # Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off
    [Parameter(Mandatory = $false)]
    $srclogonToken,

    # Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off
    [Parameter(Mandatory = $false)]
    $dstlogonToken

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

$ownersToRemove += $cpmsInUse

$objectSafesToRemove = "System", "VaultInternal", "Notification Engine", "SharedAuth_Internal", "PVWAUserPrefs",
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
} elseif ([string]::IsNullOrEmpty($SRCPVWACredentials) -and [sting]::($srclogonToken)) {
    If (![string]::IsNullOrEmpty($srcPVWACredentials)) {
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
    If ($null -eq $srcToken) { 
        return # No logon header, end script 
    }
} else { 
    Write-LogMessage -Type Error -MSG "No Source Credentials were entered" -Footer
    return
}
$creds = $null


if ($export) {
    $srcToken
    Write-LogMessage -Type Info -Msg "Starting export of accounts"
    $srcAccounts = Get-Accounts -url $SRCPVWAURL -logonHeader $srcToken -limit 1000
    Write-LogMessage -Type debug -Msg "Starting export to CSV of $($srcAccounts.count) accounts"
    $srcAccounts | `
        Where-Object {$_.safename -notIn $objectSafesToRemove} | `
        Select-Object "name", "address", "userName", "safeName", "platformId", "id", @{ name = "PasswordLastChangeUTC"; Expression = {"$((([System.DateTimeOffset]::FromUnixTimeSeconds($_.secretManagement.lastModifiedTime)).DateTime).ToString())"}} |`
        Export-Csv -Path $exportCSV -NoTypeInformation
    Write-LogMessage -Type Info -Msg "Export of accounts completed. All other switches will be ignored"
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
        
    } elseif ($null -eq $creds) {
        If (![string]::IsNullOrEmpty($dstPVWACredentials)) {
            $creds = $dstPVWACredentials
        } else {
            $msg = "Enter your Destination $dstAuthType User name and Password" 
            $creds = $Host.UI.PromptForCredential($caption, $msg, "", "")
        }
        New-Variable -Name AuthType -Value $DstAuthType -Scope Global -Force
        Import-Module -Name ".\CyberArk-Migration.psm1" -Force
        if ($AuthType -eq "radius" -and ![string]::IsNullOrEmpty($OTP)) {
            Set-Variable -Scope Global -Name dstToken -Value $(Get-Logon -Credentials $creds -AuthType $DstAuthType -URL $DSTPVWAURL -OTP $OTP)
        } else {
            Set-Variable -Scope Global -Name dstToken -Value $(Get-Logon -Credentials $creds -AuthType $DstAuthType -URL $DSTPVWAURL -OTP $OTP)
        }
        # Verify that we successfully logged on
        If ($null -eq $dstToken) { 
            return # No logon header, end script 
        }
    } else { 
        Write-LogMessage -Type Error -MSG "No Destination Credentials were entered" -Footer
        return
    }
}

if ($processSafes) {
    
    #region Safe Work

    $safecounter = 0
    $safeobjects = Import-Csv $importCSV | Select-Object -Property safeName -Unique

    foreach ($safe in $safeobjects) {
        $safecounter++

        If (!$InVerbose) {
            Write-Progress -Activity "Processing safe objects" -CurrentOperation "$safecounter of $($safeobjects.count)" -PercentComplete (($safecounter / $safeobjects.count) * 100)
        }

        If ($safe.safeName -in $objectSafesToRemove) {
            Write-LogMessage -Type Debug -Msg "Safe `"$($safe.safeName)`" is in the excluded safes list and will be skipped"
            continue
        }

        $srcSafe = Get-Safe -url $SRCPVWAURL -logonHeader $srcToken -safe $safe.safeName

        $dstsafe = Get-Safe -url $DSTPVWAURL -logonHeader $dstToken -safe $safe.safeName 

        if ([string]::IsNullOrEmpty($dstsafe)) {
            if ($createSafes) {
                If ((![string]::IsNullOrEmpty($CPMOld)) -and (![string]::IsNullOrEmpty($CPMnew))) {
                    $dstSafe = New-Safe -url $DSTPVWAURL -logonHeader $dstToken -safe $srcSafe -cpnNameOld $CPMOld -cpnNameNew $CPMnew
                    Write-LogMessage -Type Debug -Msg "Created safe `"$($safe.safeName)`""
                } else {
                    $dstSafe = New-Safe -url $DSTPVWAURL -logonHeader $dstToken -safe $srcSafe
                    Write-LogMessage -Type Debug -Msg "Created safe `"$($safe.safeName)`""
                }
                $createdDstSafe = $true

            } else {
                Write-LogMessage -Type Warning -Msg "Target safe `"$($safe.safeName)`" does not exist in destination and creating of safes disabled, skipping `"$($srcAccount.name)`""
                continue 
            }
        } else {
            Write-LogMessage -Type Debug -Msg "Located safe `"$($dstsafe.safename)`""
        }
        IF ($($dstsafe.safename) -in $updatedSafes) {
            Write-LogMessage -Type Debug -Msg "Safe `"$($dstsafe.safename)`" was previously created or updated. No further updates of safe memberships required" 
        } Else {
            If (($UpdateSafeMembers -or $createdDstSafe)) {
                $updatedSafes += $($dstsafe.safename) 
                $srcSafeMembers = (Get-SafeMembers -url $SRCPVWAURL -logonHeader $srcToken -safe $safe.safeName).value
                Write-LogMessage -Type Debug -Msg "Retrived Source Safe Members from `"$($safe.safeName)`"."
                $dstSafeMembers = (Get-SafeMembers -url $DSTPVWAURL -logonHeader $dstToken -safe $safe.safeName).value.membername
                Write-LogMessage -Type Debug -Msg "Retrived Destination Safe Members from `"$($dstsafe.safename)`"."
                ForEach ($srcMember in $srcSafeMembers) {
                    Write-LogMessage -Type Debug -Msg "Working with Safe Member `"$($srcMember.membername)`" in Safe `"$($safe.safeName)`""
                    IF ($srcMember.membername -in $ownersToRemove) {
                        Write-LogMessage -Type Debug -Msg "Safe Member $($srcMember.membername) is in the excluded owners list"
                    } Else {
                        if ($srcMember.membername -in $dstSafeMembers -or $("$($srcMember.memberName)@$dstUPN") -in $dstSafeMembers) {
                            $groupSource = Get-GroupSource -url $SRCPVWAURL -logonHeader $srcToken -safemember $srcMember
                            if ($groupSource -eq "Vault") {
                                $srcMember | Add-Member NoteProperty searchIn "$groupSource"
                            } elseif (![string]::IsNullOrEmpty($newLDAP)) {
                                $srcMember | Add-Member NoteProperty searchIn "$newLDAP"
                            } else {
                                $srcMember | Add-Member NoteProperty searchIn "$groupSource"
                            }
                            $null = Update-SafeMember -url $DSTPVWAURL -logonHeader $dstToken -safe $safe -safemember $srcMember -newLDAP $newLDAP 
                            Write-LogMessage -Type Debug -Msg "Safe Member `"$($srcMember.membername)`" updated on safe `"$($dstsafe.safename)`""
                        } else {
                            if ($srcMember.memberType -eq "User") {
                                $userSource = Get-UserSource -url $SRCPVWAURL -logonHeader $srcToken -safemember $srcMember
                                $srcMember | Add-Member NoteProperty searchIn $userSource
                                If (![string]::IsNullOrEmpty($dstUPN) -and ![string]::IsNullOrEmpty($userSource)) {
                                    $srcMember.memberName = "$($srcMember.memberName)@$dstUPN"
                                }
                                $null = New-SafeMember -url $DSTPVWAURL -logonHeader $dstToken -safe $safe -safemember $srcMember -newLDAP $newLDAP 
                                Write-LogMessage -Type Debug -Msg "Safe Member User`"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`""
                            } else {
                                $groupSource = Get-GroupSource -url $SRCPVWAURL -logonHeader $srcToken -safemember $srcMember
                                if ($groupSource -eq "Vault") {
                                    $srcMember | Add-Member NoteProperty searchIn "$groupSource"
                                } elseif (![string]::IsNullOrEmpty($newLDAP)) {
                                    $srcMember | Add-Member NoteProperty searchIn "$newLDAP"
                                } else {
                                    $srcMember | Add-Member NoteProperty searchIn "$groupSource"
                                }
                                $null = New-SafeMember -url $DSTPVWAURL -logonHeader $dstToken -safe $safe -safemember $srcMember -newLDAP $newLDAP
                                Write-LogMessage -Type Debug -Msg "Safe Member Group `"$($srcMember.membername)`" from source `"$groupSource`" added  to safe `"$($dstsafe.safename)`""
                            } 
                        }
                    }
                }
            } else {
                Write-LogMessage -Type Debug -Msg "Creating and/or Updating of Safe Members is disabled. Memberships of `"$($dstsafe.safename)`" not changed" 
            }
        }
    }
}
#endregion
if ($processAccounts) {
    #region Account Work 
    $counter = 0
    $accountobjects = Import-Csv $importCSV
    foreach ($accountobject in $accountobjects) {
        $counter++
        $found = $false

        If (!$InVerbose) {
            Write-Progress -Activity "Processing account objects" -CurrentOperation "$counter of $($accountobjects.count)" -PercentComplete (($counter / $accountobjects.count) * 100)
        }
        
        $srcAccount = Get-AccountDetail -url $SRCPVWAURL -logonHeader $srcToken -AccountID $accountobject.id
        If ($($srcAccount.safename) -in $objectSafesToRemove) {
            Write-LogMessage -Type Debug -Msg "Safe $($srcAccount.safename) is in the excluded safes list. Account with username of `"$($srcAccount.userName)`" with the address of `"$($srcAccount.address)`" will be skipped"
            continue
        }

        $dstAccountArray = Get-Accounts -url $DSTPVWAURL -logonHeader $dstToken -safename $($srcAccount.safeName) -keywords "$($srcAccount.userName) $($srcAccount.address)" -startswith $true
        if (![string]::IsNullOrEmpty($dstAccountArray)) {
            foreach ($account in $dstAccountArray) {
                IF (($($account.name) -eq $($srcAccount.name)) -and ($($account.userName) -eq $($srcAccount.userName)) -and ($($account.address) -eq $($srcAccount.address)) -and ($($account.safeName) -eq $($srcAccount.safeName))  ) {
                    Write-LogMessage -Type Debug -Msg "Found Account with username `"$($account.userName)`" and address `"$($account.address)`" in safe `"$($account.safeName)`""

                    $found = $true
                    $dstAccount = $account
                }
            }
        }        
    
        if ($found) {
            if (!$SkipCheckSecret) {
                Try {
                    [SecureString]$srcSecret = Get-Secret -url $SRCPVWAURL -logonHeader $srcToken -id $srcAccount.id 
                    [SecureString]$dstSecret = Get-Secret -url $DSTPVWAURL -logonHeader $dstToken -id $dstAccount.id 

                    If ((![string]::IsNullOrEmpty($srcSecret)) -and (![string]::IsNullOrEmpty($dstSecret)) ) {
                        $secretMatch = Compare-SecureString -pwd1 $srcSecret -pwd2 $dstSecret
                    }
            
                    if ($null -eq $dstSecret -and $null -ne $srcSecret) {
                        Write-LogMessage -Type Debug -Msg "No secret found on destination account $($dstAccount.Name). Setting destination secret to match source secret."
                        Set-Secret -url $DSTPVWAURL -logonHeader $dstToken -id $dstAccount.id -secret $srcSecret
                        Write-LogMessage -Type Debug -Msg "Destination account `"$($dstAccount.Name)`" secret set."
                    } elseif ($null -eq $srcSecret) {
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
                    If ("Account Locked" -eq $_) {
                        Write-LogMessage -Type Warning -Msg "Source Account `"$($srcAccount.Name)`" Locked, unable to update"
                    }
                } 
            } Else {
                Write-LogMessage -Type Debug -Msg "SkipCheckSecret set to true. No checks being done on source and destination secrets"
            }
            if ($getRemoteMachines) {
                Update-RemoteMachine -url $DSTPVWAURL -logonHeader $dstToken -dstaccount $dstAccount -srcaccount $srcAccount
            }
        } elseif ($noCreate) {
            Write-LogMessage -Type Warning -Msg "Destination account in safe `"$($srcAccount.safeName)`" does not exist and account creation disabled, skipping creation of account `"$($srcAccount.Name)`""
        } else {
            try {
                [SecureString]$srcSecret = Get-Secret -url $SRCPVWAURL -logonHeader $srcToken -id $srcAccount.id
                IF (![string]::IsNullOrEmpty($srcSecret)) {
                    $dstsafe = Get-Safe -url $DSTPVWAURL -logonHeader $dstToken -safe $srcAccount.safeName
                    if ([string]::IsNullOrEmpty($dstsafe)) {
                        Write-LogMessage -Type Warning -Msg "Destination safe of `"$($srcAccount.safeName)`" does not exist, skipping creation of account `"$($srcAccount.Name)`""
                    }
                    $dstAccount = New-Account -url $DSTPVWAURL -logonHeader $dstToken -account $srcAccount -secret $srcSecret 
                } else {
                    Write-LogMessage -Type Warning -Msg "No password set on source for `"$($srcAccount.Name)`""
                }
            } catch [System.Management.Automation.RuntimeException] {
                If ("Account Locked" -eq $_.Exception.Message) {
                    Write-LogMessage -Type Warning -Msg "Source Account `"$($srcAccount.Name)`" Locked, unable to update"
                } else {
                    Write-LogMessage -Type Warning -Msg "Unknown Error encountered on retriving secret from Source Account `"$($srcAccount.Name)`""
                }
            }
        }
    }
}

#region [Logoff]
# Logoff the session
# ------------------
Write-Host "Logoff Session..."
If (![string]::IsNullOrEmpty($srclogonToken)) {
    Invoke-Logoff -url $SRCPVWAURL -logonHeader $srcToken
}
If (![string]::IsNullOrEmpty($dstlogonToken)) {
    if (![string]::IsNullOrEmpty($dstToken)) { 
        Invoke-Logoff -url $DSTPVWAURL -logonHeader $dstToken
    }
}

Remove-Variable -Name LOG_FILE_PATH -Scope Global -Force
Remove-Variable -Name AuthType -Scope Global -Force

#endregion

$VerbosePreference = $oldverbose
