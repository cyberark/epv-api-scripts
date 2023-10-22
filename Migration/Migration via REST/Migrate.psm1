if ($PSVersionTable.PSVersion -lt [System.Version]"6.0") {
    Write-Host -ForegroundColor Red "This module must be run in PowerShell 6 or greater required`nUse the following link for instructions on how to download and install the current version of PowerShell`nhttps://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows"
    Throw
}
# Script Version
$ScriptVersion = "0.20"

New-Variable -Name LOG_FILE_PATH -Value "$(($Script:MyInvocation.MyCommand.Name).Replace("psm1","log"))" -Scope Global -Force

$global:LOG_DATE = $(Get-Date -Format yyyyMMdd) + "-" + $(Get-Date -Format HHmmss)

[String[]]$script:objectSafesToRemove = @("System", "VaultInternal", "Notification Engine", "SharedAuth_Internal", "PVWAUserPrefs",
    "PVWAConfig", "PVWAReports", "PVWATaskDefinitions", "PVWAPrivateUserPrefs", "PVWAPublicData", "PVWATicketingSystem",
    "AccountsFeed", "PSM", "xRay", "PIMSuRecordings", "xRay_Config", "AccountsFeedADAccounts", "AccountsFeedDiscoveryLogs", "PSMSessions", "PSMLiveSessions", "PSMUniversalConnectors",
    "PSMNotifications", "PSMUnmanagedSessionAccounts", "PSMRecordings", "PSMPADBridgeConf", "PSMPADBUserProfile", "PSMPADBridgeCustom",
    "AppProviderConf", "PasswordManagerTemp", "PasswordManager_Pending", "PasswordManagerShared")

[String[]]$script:CPMSafes = @("PasswordManager", "PasswordManager_workspace", "PasswordManager_ADInternal", "PasswordManager_Info")

[String[]]$script:ownersToRemove = @("Auditors", "Backup Users", "Batch", "PasswordManager", "DR Users", "Master", "Notification Engines", "Notification Engine",
    "Operators", "PTAAppUsers", "PTAAppUser", "PVWAGWAccounts", "PVWAAppUsers", "PVWAAppUser", "PVWAAppUser1", "PVWAAppUser2", "PVWAAppUser3", "PVWAAppUser4", "PVWAAppUser5",
    "PVWAAppUser6", "PVWAUsers", "PVWAMonitor", "PSMUsers", "PSMAppUsers", "PTAUser", "Administrator", "PSMAppUsers")


Import-Module -Name ".\CyberArk-Migration.psm1" -Force

function Initialize-Function {
    [CmdletBinding()]
    param ()
    $global:InDebug = $PSBoundParameters.Debug.IsPresent
    $global:InVerbose = $PSBoundParameters.Verbose.IsPresent
    IF (2 -lt (Get-PSCallStack).count) {
        IF (!$global:InDebug) {
            Set-Variable -Scope Global -Name InDebug -Value (Get-Variable -Scope 1 -Name PSBoundParameters -ValueOnly).Debug.IsPresent
        }
        If (!$global:InVerbose) {
            Set-Variable -Scope Global -Name InVerbose -Value (Get-Variable -Scope 1 -Name PSBoundParameters -ValueOnly).Verbose.IsPresent -ErrorAction SilentlyContinue
        }
    }
    Import-Module -Name ".\CyberArk-Migration.psm1" -Force

}

Function Get-CPMUsers {
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    [OutputType([String[]])]
    param(    )
    $URL_GetCPMList = "$script:SRCPVWAURL/API/ComponentsMonitoringDetails/CPM/"
    Try {
        $CPMList = Invoke-RestMethod -Method Get -Uri $URL_GetCPMList -Headers $Script:srcToken -ErrorVariable ErrorCPMList
        IF ([string]::IsNullOrEmpty($CPMList.ComponentsDetails.ComponentUSername)) {
            Write-Warning "Unable to retrieve list of CPM users. Ensure that CPMList parameter has been passed or source CPM is named `"PasswordManager`"" -WarningAction Inquire
            return @()
        } else {
            Write-LogMessage -type Debug "$($($CPMList.ComponentsDetails.ComponentUSername).count) CPM users found"
            Write-LogMessage -type Verbose "List of CPM users found: $($($CPMList.ComponentsDetails.ComponentUSername)|ConvertTo-Json -Depth 9 -Compress)"
            return $($CPMList.ComponentsDetails.ComponentUSername)
        }
    } catch [Microsoft.PowerShell.Commands.HttpResponseException] {
        If ($PSitem.Exception.Response.StatusCode -eq "Forbidden") {
            $URL_Verify = "$url/API/Verify/"
            $ReturnResultUser = Invoke-RestMethod -Method Get -Uri $URL_Verify -Headers $logonToken -ErrorVariable RestErrorUser
            IF ([string]::IsNullOrEmpty($ReturnResultUser.ServerName) -or [string]::IsNullOrEmpty(!$RestErrorUser)) {
                Write-Warning "Unable to retrieve list of CPM users. Ensure that CPMList parameter has been passed or source CPM is named `"PasswordManager`"" -WarningAction Inquire
                return @()
            } else {
                Write-Warning "Connected with a account that is not a member of `"vault admins`""
                Write-Warning "Unable to retrieve list of CPM users. Ensure that CPMList parameter has been passed or source CPM is named `"PasswordManager`"" -WarningAction Inquire
                return @()
            }
        }
    }
}

Function Test-Session {
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param(
        $logonToken,
        $url
    )
    Function Invoke-Report {
        Write-LogMessage -type Debug -MSG "Error Message attempting to do admin connection: $($RestErrorAdmin.ErrorRecord)"
        IF ([string]::IsNullOrEmpty(!$($RestErrorUser))) {
            Write-LogMessage -type Debug -MSG "Error Message attempting to do user connection: $($RestErrorUser.ErrorRecord)"
        }
    }

    $URL_GetHealthSummery = "$url/API/ComponentsMonitoringSummary/"
    Try {
        $ReturnResultAdmin = Invoke-RestMethod -Method Get -Uri $URL_GetHealthSummery -Headers $logonToken -ErrorVariable RestErrorAdmin
        Write-LogMessage -Type Verbose -MSG "Test-Session:ReturnResult: $($ReturnResultAdmin|ConvertTo-Json -Depth 9 -Compress)"
        if ((![string]::IsNullOrEmpty($ReturnResultAdmin.Components)) -and ($ReturnResultAdmin.Components.Count -ne 0)) {
            Return $true
        } else {
            Invoke-Report
            return $false
        }
    } catch [Microsoft.PowerShell.Commands.HttpResponseException] {
        If ($PSitem.Exception.Response.StatusCode -eq "Forbidden") {
            $URL_Verify = "$url/API/Verify/"
            $ReturnResultUser = Invoke-RestMethod -Method Get -Uri $URL_Verify -Headers $logonToken -ErrorVariable RestErrorUser
            IF ([string]::IsNullOrEmpty($ReturnResultUser.ServerName) -or [string]::IsNullOrEmpty(!$RestErrorUser)) {
                Invoke-Report
                Return $false
            } else {
                Invoke-Report
                Write-LogMessage -type Warning -MSG "Connected with a account that is not a member of `"vault admins`". Access to create may be restricted."
                Return $true
            }
        }
    }
}
function Test-AccountList {
    If ([string]::IsNullOrEmpty($($script:AccountList))) {
        Write-LogMessage -Type Warning -MSG "No accounts found, attempting import of accounts using default settings"
        Import-Accounts
        If ([string]::IsNullOrEmpty($($script:AccountList))) {
            Write-LogMessage -Type ErrorThrow -MSG "No accounts found after import attempt"
            Throw "No accounts found after import attempt"
        }
    }
}
function Test-SessionsValid {
    If (!(Test-SourceSession)) {
        $SessionFailed = $true
        Write-LogMessage -type Error -MSG "Source Session Test Failed. Run `"New-SourceSession`" to create a new session to the source environment"
    }
    IF (!(Test-DestinationSession)) {
        $SessionFailed = $true
        Write-LogMessage -type Error -MSG "Destination Session Test Failed. Run `"New-DestinationSession`" to create a new session to the destination environment"
    }
    If ($SessionFailed) {
        Throw "Tests to environment(s) failed"
    }
}
function New-SourceSession {
    [CmdletBinding()]
    param (

        <#
    URL for the source environment
    - HTTPS://Source.lab.local/PasswordVault
    #>
        [Parameter(Mandatory = $true)]
        [Alias("srcurl", "PVWAURL")]
        [String]$SRCPVWAURL,

        <#
    Authentication types for logon.
	- Available values: _CyberArk, LDAP, RADIUS_
	- Default value: _CyberArk_
    #>
        [Parameter(Mandatory = $false)]
        [ValidateSet("cyberark", "ldap", "radius")]
        [String]$SrcAuthType = "cyberark",

        <#
    One Time Password for the source environment when used with RADIUS
    #>
        [Parameter(Mandatory = $false)]
        [ValidateScript({$AuthType -eq "radius"})]
        [String]$srcOTP,

        <#
    Stored credentials for source environment
    #>
        [Parameter(Mandatory = $false)]
        [PSCredential]$SRCPVWACredentials,

        <#
    Headers for use with source environment
    - Used with Privileged Cloud environment
    - When used, log off is suppressed in the source environment
    #>
        [Parameter(Mandatory = $false)]
        $srclogonToken,
        <#
            Use this switch to Disable SSL verification (NOT RECOMMENDED)
            #>
        [Parameter(Mandatory = $false)]
        [Switch]$DisableSSLVerify
    )

    Initialize-Function
    Set-SSLVerify($DisableSSLVerify)

    # Check that the PVWA URL is OK
    Test-PVWA -PVWAURL $SRCPVWAURL

    Write-LogMessage -Type Info -MSG "Getting Source Logon Tokens"
    If (![string]::IsNullOrEmpty($srclogonToken)) {
        if ($srclogonToken.GetType().name -eq "String") {
            $logonHeader = @{Authorization = $srclogonToken }
            Set-Variable -Scope script -Name srcToken -Value $logonHeader
        } else {
            Set-Variable -Scope script -Name srcToken -Value $srclogonToken
        }
    } else {
        If (![string]::IsNullOrEmpty($SRCPVWACredentials)) {
            $creds = $srcPVWACredentials
        } else {
            $msg = "Enter your source $srcAuthType User name and Password"
            $creds = $Host.UI.PromptForCredential($caption, $msg, "", "")
        }
        New-Variable -Name AuthType -Value $SrcAuthType -Scope script -Force
        Import-Module -Name ".\CyberArk-Migration.psm1" -Force

        if ($AuthType -eq "radius" -and ![string]::IsNullOrEmpty($srcOTP)) {
            Set-Variable -Scope Script -Name srcToken -Value $(Get-Logon -Credentials $creds -AuthType $SrcAuthType -URL $SRCPVWAURL -OTP $OTP)
        } else {
            Set-Variable -Scope Script -Name srcToken -Value $(Get-Logon -Credentials $creds -AuthType $SrcAuthType -URL $SRCPVWAURL )
        }
        # Verify that we successfully logged on
        If ([string]::IsNullOrEmpty($srcToken)) {
            Write-LogMessage -Type Error -MSG "No Source Credentials were entered" -Footer
            return # No logon header, end script
        }
        $creds = $null
    }
    Set-Variable -Scope Script -Name SRCPVWAURL -Value $SRCPVWAURL
    if (Test-Session -logonToken $script:srcToken -url $script:SRCPVWAURL) {
        Write-LogMessage -type Info -MSG "Source session successfully configured and tested"
        Write-LogMessage -type Debug -MSG "Source Token set to $($srcToken|ConvertTo-Json -Depth 10)"
    } else {
        Throw "Source session failed to connect successfully"
    }
}
Function Close-SourceSession {
    Initialize-Function
    Invoke-Logoff -url $SRCPVWAURL -logonHeader $srcToken -ErrorAction SilentlyContinue
}
Function Test-SourceSession {
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param()
    If ([string]::IsNullOrEmpty($Script:srcToken) -or [string]::IsNullOrEmpty($Script:SRCPVWAURL)) {
        return $false
    } else {
        Return Test-Session -logonToken $Script:srcToken -url $Script:SRCPVWAURL
    }
}
function New-DestinationSession {
    [CmdletBinding()]
    param (
        <#
    URL for the destination environment
    - HTTPS://Destination.lab.local/PasswordVault
    #>
        [Parameter(Mandatory = $false)]
        [Alias("dsturl", "PVWAURL")]
        [String]$DSTPVWAURL,

        <#
    Authentication types for logon.
	- Available values: _CyberArk, LDAP_
	- Default value: _CyberArk_
    #>

        [Parameter(Mandatory = $false)]
        [ValidateSet("cyberark", "ldap")]
        [String]$DstAuthType = "cyberark",

        <#
    Destination credentials for source environment
    #>
        [Parameter(Mandatory = $false)]
        [PSCredential]$DSTPVWACredentials,

        <#
    Headers for use with destination environment
    - Used with Privileged Cloud environment
    - When used, log off is suppressed in the destination environment
    #>
        [Parameter(Mandatory = $false)]
        $dstlogonToken,
        <#
            Use this switch to Disable SSL verification (NOT RECOMMENDED)
            #>
        [Parameter(Mandatory = $false)]
        [Switch]$DisableSSLVerify
    )
    Initialize-Function
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
            Set-Variable -Scope script -Name dstToken -Value $(Get-Logon -Credentials $creds -AuthType $dstAuthType -URL $DSTPVWAURL -OTP $OTP)
        } else {
            Set-Variable -Scope script -Name dstToken -Value $(Get-Logon -Credentials $creds -AuthType $dstAuthType -URL $DSTPVWAURL )
        }
        # Verify that we successfully logged on
        If ($null -eq $script:dstToken) {
            Write-LogMessage -Type Error -MSG "No Destination Credentials were entered" -Footer
            return # No logon header, end script
        }
        $creds = $null
    }
    Set-Variable -Scope Script -Name DSTPVWAURL -Value $DSTPVWAURL
    if (Test-Session -logonToken $script:dstToken -url $script:DSTPVWAURL) {
        Write-LogMessage -type Info -MSG "Destination session successfully configured and tested"
        Write-LogMessage -type Debug -MSG "Destination Token set to $($script:dstToken |ConvertTo-Json -Depth 10)"
    } else {
        Write-LogMessage -type Error -MSG "Destination session failed to connect successfully"
    }
}
function Close-DestinationSession {
    Invoke-Logoff -url $DSTPVWAURL -logonHeader $dstToken -ErrorAction SilentlyContinue
}
Function Test-DestinationSession {
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    param()
    If ([string]::IsNullOrEmpty($Script:dstToken) -or [string]::IsNullOrEmpty($Script:DSTPVWAURL)) {
        return $false
    } else {
        Return Test-Session -logonToken $Script:dstToken -url $Script:DSTPVWAURL
    }
}
function Export-Accounts {
    param (
        <#
    Path and filename for use by Export
    #>
        [Parameter(Mandatory = $false)]
        [ValidateScript({Test-Path -Path $_ -PathType Leaf -IsValid})]
        [ValidatePattern('\.csv$')]
        $exportCSV = ".\ExportOfAccounts.csv"
    )
    Initialize-Function

    Write-LogMessage -Type Info -Msg "Starting export of accounts"
    $srcAccounts = Get-Accounts -url $SRCPVWAURL -logonHeader $srcToken -limit 1000
    Write-LogMessage -Type Info -Msg "Found $($srcAccounts.count) accounts"
    $remove = $srcAccounts | Where-Object {$_.safename -In $objectSafesToRemove}
    Write-LogMessage -Type Info -Msg "Found $($remove.count) accounts in excluded safes and removing from list"
    $srcAccounts = $srcAccounts | Where-Object {$_.safename -notIn $objectSafesToRemove}
    Write-LogMessage -Type Info -Msg "Starting export to CSV of $($srcAccounts.count) accounts"
    $srcAccounts | `
        Where-Object {$_.safename -notIn $objectSafesToRemove} | `
        Select-Object "name", "address", "userName", "safeName", "platformId", "id", @{ name = "PasswordLastChangeUTC"; Expression = {"$((([System.DateTimeOffset]::FromUnixTimeSeconds($_.secretManagement.lastModifiedTime)).DateTime).ToString())"}} |`
        Export-Csv -Path $exportCSV -NoTypeInformation
    Write-LogMessage -Type Info -Msg "Export of $($srcAccounts.count) accounts completed. All other switches will be ignored"
}
Function Import-Accounts {
    param (
        <#
    Path and filename for use by Export
    #>
        [Parameter(Mandatory = $false)]
        [ValidateScript({Test-Path -Path $_ -PathType Leaf -IsValid})]
        [ValidatePattern('\.csv$')]
        $importCSV = ".\ExportOfAccounts.csv"
    )
    [array]$script:AccountList = Import-Csv $importCSV -ErrorAction SilentlyContinue
    Write-LogMessage -Type Info -Msg "Imported $($script:AccountList.count) accounts from `"$importCSV`""
    IF ($global:SuperVerbose) {
        Write-LogMessage -Type Verbose -Msg "SuperVerbose: Imported Accounts: $($script:AccountList |ConvertTo-Json -Depth 9 -Compress)"
    }
}
Function Get-Accountlist {
    $script:AccountList
}
Function Set-AccountList {
    param (
        <#
    New Account list
    #>
        [Parameter(Mandatory = $true, ValueFromPipeline)]
        [PSCustomObject]$newAccountList
    )
    Set-Variable -Scope Script -Name AccountList -Value $newAccountList

}
Function Clear-Accountlist {
    Remove-Variable -Scope Script -Name AccountList -ErrorAction SilentlyContinue
}
Function Sync-All {
    Sync-Safes
    Sync-Accounts
}
Function Sync-Safes {
    param (
        <#
        Automatically create safes in destination environment if not found.
        #>
        [Parameter(Mandatory = $false)]
        [Switch]$createSafes,
        <#
        Automatically update safe members permissions in destination environment to match source environment.
        - May result in loss of permissions
        #>
        [Parameter(Mandatory = $false)]
        [Switch]$UpdateSafeMembers,
        <#
        Name of the old CPM which will be replaced
        #>
        [Parameter(Mandatory = $false)]
        [String]$CPMOld,
        <#
        Name of the new CPM which will be used in place of CPMOld
        #>
        [Parameter(Mandatory = $false)]
        [String]$CPMNew,
        <#
        Name of CPM to be used in all creation
        - Overrides CPMOld and CPMNew
        #>
        [Parameter(Mandatory = $false)]
        [String]$CPMOverride,
        <#
        Array of strings with the names of CPM servers currently in the source environment so they can be skipped during ownership processing
        #>
        [Parameter(Mandatory = $false)]
        [String[]]$CPMList,
        <#
        Name of directory in the destination
        For PCloud destinations this should be the DirectoryServiceUuid
        #>
        [Parameter(Mandatory = $false)]
        [String]$newDir,
        <#
        Domain name to be added to safe owners who are memberType of "user" when searching the destination environment
        - Should be added when going from a environment not using UPN names to PCloud
        - Example:
            - dstDomainSuffix = Lab.local
            - SourceUsername = Admin
            - End result of username
                Admin@lab.local
        #>
        [Parameter(Mandatory = $false)]
        [String]$dstDomainSuffix,
        <#
        Display details of jobs in progress bar
        Not recommended if maxJobCount is higher then 5
        #>
        [Parameter(Mandatory = $false)]
        [switch]$srcRemoveDomain,
        <#
        The amount of jobs that should be running at one time
        #>
        [Parameter(Mandatory = $false)]
        [String]$maxJobCount = 10,
        <#
        Display details of jobs in progress bar
        Not recommended if maxJobCount is higher then 5
        #>
        [Parameter(Mandatory = $false)]
        [switch]$ProgressDetails,
        <#
        Suppress Progress bar being displayed
        #>
        [Parameter(Mandatory = $false)]
        [switch]$SuppressProgress
    )

    Write-LogMessage -Type Info -MSG "Starting safe processing at $(Get-Date -Format "HH:mm:ss")"

    Initialize-Function
    Test-SessionsValid
    Test-AccountList

    #region Safe Work

    $cpmUsers = Get-CPMUsers
    $cpmSafes = @()
    $cpmUsers | ForEach-Object {
        $cpmSafes += "$($PSitem)"
        $cpmSafes += "$($PSitem)_Accounts"
        $cpmSafes += "$($PSitem)_ADInternal"
        $cpmSafes += "$($PSitem)_Info"
        $cpmSafes += "$($PSitem)_workspace"
    }

    $SafesToRemove = $cpmSafes
    $SafesToRemove += $script:objectSafesToRemove
    Write-LogMessage -type Debug "$($SafesToRemove.Count) safes in safes to remove list"


    [array]$safeobjects += $script:AccountList | `
        Select-Object -Property safeName -Unique | `
        Where-Object {$_.safename -notIn $SafesToRemove} | `
        ForEach-Object { $PSItem }

    Write-LogMessage -Type Info -MSG "Found $($safeobjects.count) unique safes for processing"

    $safeobjects | Add-Member -MemberType NoteProperty -Name ID -Value $null -Force

    $i = 0
    foreach ($id in $safeobjects) {
        $safeobjects[$i].id = $i + 1
        $i++
    }

    $ownersToRemove = $script:ownersToRemove
    $ownersToRemove += $CPMList
    $ownersToRemove += $cpmUsers

    Write-LogMessage -Type Debug "$($ownersToRemove.Count) owners in owners to remove list"
    Write-LogMessage -Type Verbose "$($ownersToRemove|ConvertTo-Json -Depth 9 -Compress)"

    New-Item -ItemType Directory -Force -Path .\LogFiles-Safes\ | Out-Null
    $safeProgress = @{}
    $safeobjects | ForEach-Object {$safeProgress.($_.id) = @{}}
    $safeProgressSync = [System.Collections.Hashtable]::Synchronized($safeProgress)
    Write-LogMessage -Type Info -MSG "Setup of safe job object completed. Starting to submit jobs at $(Get-Date -Format "HH:mm:ss")."
    $safeJob = $safeobjects | ForEach-Object -ThrottleLimit $maxJobCount -AsJob -Parallel {

        $global:InDebug = $Using:InDebug
        $global:InVerbose = $Using:InVerbose
        $createSafes = $using:createSafes
        $UpdateSafeMembers = $using:UpdateSafeMembers
        $objectSafesToRemove = $Using:objectSafesToRemove
        $srcToken = $using:srcToken
        $SRCPVWAURL = $using:SRCPVWAURL
        $dstToken = $using:dstToken
        $DSTPVWAURL = $using:DSTPVWAURL
        $srcRemoveDomain = $using:srcRemoveDomain
        $dstDomainSuffix = $using:dstDomainSuffix
        $newDir = $using:newDir
        $CPMnew = $using:CPMnew
        $CPMOld = $using:CPMOld
        $CPMOverride = $using:CPMOverride
        $ownersToRemove = $using:ownersToRemove
        $global:safename = $($PSItem.safeName)
        $global:LOG_FILE_PATH = ".\LogFiles-Safes\$safename.log"
        $global:SuperVerbose = $using:SuperVerbose
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
        Try {
            #region Setup Progress
            $syncCopy = $using:safeProgressSync
            $process = $syncCopy.$($PSItem.Id)
            $process.Id = $PSItem.Id
            $process.Activity = "Processing safe $($PSItem.safeName)"
            $process.Status = "Starting"
            #endregion
            #region Setup Logging
            $SafeStatus = @{
                id                = $PSItem.id
                safeName          = $PSItem.safeName
                success           = $false
                createSkip        = $false
                UpdateMembersFail = $false
                safeData          = $PSItem
                Log               = @()
                Error             = @()
            }
            #endregion
            #endregion
            Write-LogMessage -Type Info -Msg "Working with Safe `"$safename`""

            If ($PSItem.safeName -in $objectSafesToRemove) {
                Write-LogMessage -Type Info -Msg "Safe `"$($PSItem.safeName)`" is in the excluded safes list and will be skipped"
                $SafeStatus.success = $true
                write-LogMessage -Type Verbose -Msg "Final `$SafeStatus $($SafeStatus | ConvertTo-Json -Compress)"
                continue
            }
            Write-LogMessage -Type Debug -Msg "Getting source safe `"$safename`""
            $srcSafe = Get-Safe -url $SRCPVWAURL -logonHeader $srcToken -safe $($PSItem.safeName)
            if ([string]::IsNullOrEmpty($srcSafe)) {
                Write-LogMessage -Type error -Msg "Source safe `"$safename`" not Found. Skipping"
                write-LogMessage -Type Verbose -Msg "Final `$SafeStatus $($SafeStatus |ConvertTo-Json -Compress)"
                Continue
            } else {
                Write-LogMessage -Type Debug -Msg "Source safe `"$safename`" located"
            }

            Write-LogMessage -Type Debug -Msg "Getting destination safe `"$safename`""
            Try {
                $dstsafe = Get-Safe -url $DSTPVWAURL -logonHeader $dstToken -safe $($PSItem.safeName) -ErrorAction SilentlyContinue
            } catch {
                $dstsafe = $null
            }

            if ([string]::IsNullOrEmpty($dstsafe)) {
                Write-LogMessage -Type Debug -Msg "Destination safe `"$safename`" not Found"
                if ($createSafes) {
                    Try {
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
                        Write-LogMessage -Type error -Msg "Error creating safe `"$safename`""
                        Write-LogMessage -Type Debug -Msg "Error: $_"
                        $process.Completed = $true
                        continue
                    }
                } else {
                    Write-LogMessage -Type Warning -Msg "`tTarget safe `"$($PSItem.safeName)`" does not exist in destination and creating of safes disabled, skipping `"$($PSItem.safeName)`""
                    $SafeStatus.createSkip = $true
                    $SafeStatus.success = $true
                    continue
                }
            } else {
                Write-LogMessage -Type Debug -Msg "Destination safe  `"$($dstsafe.safename)`" located"
            }
            If (($UpdateSafeMembers -or $createdDstSafe)) {
                $srcSafeMembers = (Get-SafeMembers -url $SRCPVWAURL -logonHeader $srcToken -safe $PSItem.safeName).value
                Write-LogMessage -Type Info -Msg "From source safe retrived $($srcSafeMembers.Count) Safe Members"
                $dstSafeMembers = (Get-SafeMembers -url $DSTPVWAURL -logonHeader $dstToken -safe $PSItem.safeName).value.membername
                Write-LogMessage -Type Info -Msg "From destination safe retrived $($dstSafeMembers.Count) Safe Members"
                $safememberCount = 0
                ForEach ($srcMember in $srcSafeMembers) {
                    $safememberCount += 1
                    Try {
                        Write-LogMessage -Type Info -Msg "[$($safememberCount)] Working with Safe Member `"$($srcMember.membername)`" in Safe `"$($PSItem.safeName)`""
                        IF ($srcMember.membername -in $ownersToRemove) {
                            Write-LogMessage -Type Info -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is in the excluded owners list"
                        } Else {
                            if ($srcRemoveDomain) {
                                Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Removing domain from source username `"$($srcMember.membername)`""
                                $srcMember.membername = $($($srcMember.membername).Split("@"))[0]
                                Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Updated username to `"$($srcMember.membername)`""
                                If (!$([string]::IsNullOrEmpty($dstDomainSuffix))) {
                                    Write-LogMessage -type Debug "[$($safememberCount)] New domain suffix of $dstDomainSuffix provided"
                                    $srcMember.memberName = "$($srcMember.memberName)@$dstDomainSuffix"
                                    Write-LogMessage -type Debug "[$($safememberCount)] Updated username to `"$($srcMember.membername)`""
                                }
                            }
                            if ($srcMember.membername -in $dstSafeMembers -or $("$($srcMember.memberName)@$dstDomainSuffix") -in $dstSafeMembers) {
                                Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is a member of safe `"$($dstsafe.safename)`" attempting to update permissions"
                                $groupSource = Get-GroupSource -url $SRCPVWAURL -logonHeader $srcToken -safemember $srcMember
                                <#                                 if ($groupSource -eq "Vault") {
                                    $srcMember | Add-Member -MemberType NoteProperty -NotePropertyName searchIn -NotePropertyValue "$groupSource"
                                } elseif (![string]::IsNullOrEmpty($newDir)) {
                                    Write-LogMessage -type Debug -MSG "New direcory provided, updating `"seachIn`" to `"$newDir`""
                                    $srcMember | Add-Member -MemberType NoteProperty -NotePropertyName searchIn -NotePropertyValue "$newDir"
                                } else {
                                    $srcMember | Add-Member -MemberType NoteProperty -NotePropertyName searchIn -NotePropertyValue "$groupSource"
                                } #>
                                Update-SafeMember -url $DSTPVWAURL -logonHeader $dstToken -safe $PSItem.safename -safemember $srcMember | Out-Null
                                Write-LogMessage -Type Info -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" updated on safe `"$($dstsafe.safename)`" succesfully"
                            } else {
                                if ($srcMember.memberId -match "[A-Z]") {
                                    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is from PCloud ISPSS"
                                    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Attempting to add $($srcMember.MemberType) `"$($srcMember.membername)`" to safe `"$($dstsafe.safename)`""
                                    try {
                                        $null = New-SafeMember -url $DSTPVWAURL -logonHeader $dstToken -safe $PSItem.safename -safemember $srcMember -PCloud
                                        Write-LogMessage -Type Info -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType)  `"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`" succesfully"
                                    } catch {
                                        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType)  `"$($srcMember.membername)`" faild to added to safe `"$($dstsafe.safename)`" changing memberType to Role and trying again"
                                        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Removing domain from source username `"$($srcMember.membername)`""
                                        $srcMember.membername = $($($srcMember.membername).Split("@"))[0]
                                        $srcMember.memberType = "Role"
                                        $null = New-SafeMember -url $DSTPVWAURL -logonHeader $dstToken -safe $safename -safemember $srcMember -PCloud
                                        Write-LogMessage -Type Info -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType)  `"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`" succesfully"
                                    }
                                } elseif ($srcMember.memberType -eq "User") {
                                    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is a user, attempting to find source"
                                    $userSource = Get-UserSource -url $SRCPVWAURL -logonHeader $srcToken -safemember $srcMember
                                    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" source is `"$userSource`""
                                    IF ([sting]::IsNullOrEmpty($newDir)) {
                                        $srcMember | Add-Member NoteProperty searchIn $userSource
                                    } else {
                                        Write-LogMessage -type Debug -MSG "New direcory provided, updating `"seachIn`" to `"$newDir`""
                                        $srcMember | Add-Member NoteProperty searchIn $newDir
                                    }
                                    Write-LogMessage -Type Info -Msg "[$($safememberCount)] Attempting to add user `"$($srcMember.membername)`" to safe `"$($dstsafe.safename)`""
                                    $null = New-SafeMember -url $DSTPVWAURL -logonHeader $dstToken -safe $PSItem.safename -safemember $srcMember
                                    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member User`"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`""
                                } elseif ($srcMember.memberType -eq "Group") {
                                    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is a group, attempting to find source"
                                    $groupSource = Get-GroupSource -url $SRCPVWAURL -logonHeader $srcToken -safemember $srcMember
                                    if ($groupSource -eq "Vault") {
                                        $srcMember | Add-Member NoteProperty searchIn "$groupSource"
                                    } elseif (![string]::IsNullOrEmpty($newDir)) {
                                        Write-LogMessage -type Debug -MSG "New direcory provided, updating `"seachIn`" to `"$newDir`""
                                        $srcMember | Add-Member NoteProperty searchIn "$newDir"
                                    } else {
                                        $srcMember | Add-Member NoteProperty searchIn "$groupSource"
                                    }
                                    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" source is `"$groupSource`""
                                    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Attempting to add group `"$($srcMember.membername)`" to safe `"$($dstsafe.safename)`""
                                    try {
                                        $null = New-SafeMember -url $DSTPVWAURL -logonHeader $dstToken -safe $PSItem.safename -safemember $srcMember -PCloud
                                        Write-LogMessage -Type Info -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType)  `"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`" succesfully"
                                    } catch {
                                        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType)  `"$($srcMember.membername)`" faild to added to safe `"$($dstsafe.safename)`""
                                        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Removing domain from source username `"$($srcMember.membername)`" and trying again"
                                        $srcMember.membername = $($($srcMember.membername).Split("@"))[0]
                                        $null = New-SafeMember -url $DSTPVWAURL -logonHeader $dstToken -safe $safename -safemember $srcMember -PCloud
                                        Write-LogMessage -Type Info -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType)  `"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`" succesfully"
                                    }
                                } else {
                                    Write-LogMessage -Type Error -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is a unknown and is being skipped"
                                    $SafeStatus.UpdateMembersFail = $true
                                }
                            }
                        }
                    } Catch {
                        Write-LogMessage -Type Error -Msg "`t[$($safememberCount)] Failed to add or update Safe Member `"$($srcMember.membername)`" in safe `"$($dstsafe.safename)`""
                        $SafeStatus.UpdateMembersFail = $true
                        continue
                    }
                }
                $SafeStatus.success = $true
            } else {
                Write-LogMessage -Type Info -Msg "Creating and/or Updating of Safe Members is disabled. Memberships of `"$($dstsafe.safename)`" not changed"
                $SafeStatus.success = $true
            }
        } Finally {
            write-LogMessage -Type Info -Msg "Completed work with safe `"$safename`""
            If ($SuperVerbose) {
                write-LogMessage -Type Verbose -Msg "SuperVerbose: Final `$SafeStatus $($SafeStatus | ConvertTo-Json -Compress)"
            } else {
                write-LogMessage -Type Verbose -Msg "Final `$SafeStatus $($SafeStatus |Select-Object -Property Id,SafeName,createSkip,Success,UpdateMembersFail | ConvertTo-Json -Depth 1 -Compress)"
            } $SafeStatus
            $process.Completed = $true
        }
    }
    Write-LogMessage -Type Info -MSG "Submission of $($safeJob.ChildJobs.Count) jobs completed at $(Get-Date -Format "HH:mm:ss"). Maxiumn running PowerShell jobs set to $maxJobCount."
    $PSStyle.Progress.View = "Classic"
    while ($safeJob.State -eq 'Running') {
        $safeProgressSync.Keys | ForEach-Object {
            if (![string]::IsNullOrEmpty($safeProgressSync.$_.keys)) {
                if (!$SuppressProgress) {
                    $completed = $($safeJob.ChildJobs | Where-Object {$_.State -eq "Completed"}).count
                    $total = $safeJob.ChildJobs.count
                    $Precent = ($completed / $total) * 100
                    $process = @{}
                    $process.Id = 0
                    $process.Activity = "Processing Safes"
                    $process.Status = "$completed out of $total jobs completed"
                    $process.PercentComplete = $Precent
                    Write-Progress @process
                    if ($ProgressDetails.IsPresent) {
                        $param = $safeProgressSync.$_
                        $param.ParentId = 0
                        Write-Progress @param
                    }
                }
            }
        }
        Start-Sleep -Seconds 0.5
    }
    Write-Progress -Id 0 -Completed $true
    # Wait to refresh to not overload gui
    Write-LogMessage -Type Info "All safes processed, generating results"

    $($SafeReport = Receive-Job $Safejob -Keep) 6> $null 5> $null 4> $null 3> $null 2> $null 1> $null
    $SafeSuccess = $SafeReport | Where-Object {($PSItem.success -EQ $true) -and ($PSItem.createSkip -eq $false)}
    $SafeCreateSkip = $SafeReport | Where-Object {($PSItem.success -EQ $true) -and ($PSItem.createSkip -eq $true)}
    $SafeFailed = $SafeReport | Where-Object {$PSItem.success -EQ $false}
    $SafeUpdateMembersFail = $SafeReport | Where-Object {$PSItem.UpdateMembersFail -EQ $true}
    If (![string]::IsNullOrEmpty($SafeFailed)) {
        $SafeFailed.SafeData | Add-Member -MemberType NoteProperty -Name FailReason -Value $null -Force
        $i = 0
        foreach ($id in $SafeFailed) {
            $SafeFailed[$i].SafeData.FailReason = $SafeFailed[$i].Error
            $i++
        }
        $SafeFailed.SafeData | Export-Csv .\FailedSafes.csv
    }
    Write-LogMessage -Type Info "Safes succesfully processed: $($SafeSuccess.success.count)"
    Write-LogMessage -Type Info "Safes creation skipped: $($SafeCreateSkip.success.count)"
    Write-LogMessage -Type Info "Safes processing failed: $($SafeFailed.success.count)"
    Write-LogMessage -Type Info "Safes membership add or updates failed: $($SafeUpdateMembersFail.success.count)"
    Write-LogMessage -Type Info "Processing of safes completed at $(Get-Date -Format "HH:mm:ss")"
}
function Sync-Accounts {
    param (
        <#
        Skip checking of existing secrets
        #>
        [Parameter(Mandatory = $false)]
        [Switch]$SkipCheckSecret,
        <#
        Update Allowed Remote Machines on accounts
        #>
        [Parameter(Mandatory = $false)]
        [switch]$getRemoteMachines,
        <#
        Prevent creation of accounts
        #>
        [Parameter(Mandatory = $false)]
        [Switch]$noCreate,
        <#
        Allow Create eation of accounts with empty secrets
        #>
        [Parameter(Mandatory = $false)]
        [Switch]$allowEmpty,
        <#
        Verify platform exists in destination and if needed correct casing to prevent creation error
        #>
        [Parameter(Mandatory = $false)]
        [Switch]$VerifyPlatform,
        <#
        The amount of jobs that should be running at one time
        #>
        [Parameter(Mandatory = $false)]
        [String]$maxJobCount = 10,
        <#
        Display details of jobs in progress bar
        Not recommended if maxJobCount is higher then 5
        #>
        [Parameter(Mandatory = $false)]
        [switch]$ProgressDetails,
        <#
        Suppress Progress bar being displayed
        #>
        [Parameter(Mandatory = $false)]
        [switch]$SuppressProgress
    )
    Write-LogMessage -Type Info -MSG "Starting account processing at $(Get-Date -Format "HH:mm:ss")"

    Initialize-Function
    Test-SessionsValid
    Test-AccountList
    Write-LogMessage -Type debug -MSG "All tests passed"

    IF ($VerifyPlatform) {
        Write-LogMessage -Type Info -Msg "VerifyPlatform set, retriving platforms for destination environment"
        $platforms = (Get-Platforms -url $DSTPVWAURL -logonHeader $dstToken)
        Write-LogMessage -Type debug -MSG "$($platforms.count) platforms retrieved from destination environment"
    } else {
        $platforms = "Skipped"
    }

    [array]$accountobjects = $script:AccountList | ForEach-Object { $PSItem }
    $accountobjects | Add-Member -MemberType NoteProperty -Name ProcessID -Value $null -Force

    $i = 0
    foreach ($id in $accountobjects) {
        $accountobjects[$i].ProcessID = $i + 1
        $i++
    }

    New-Item -ItemType Directory -Force -Path .\LogFiles-Accounts\ | Out-Null
    $accountProgress = @{}
    $accountobjects | ForEach-Object {$accountProgress.($_.ProcessID) = @{}}
    $accountProgressSync = [System.Collections.Hashtable]::Synchronized($accountProgress)
    Write-LogMessage -Type Debug -MSG "Setup of account object completed. Starting to submit jobs at $(Get-Date -Format "HH:mm:ss")."
    $AccountJob = $accountobjects | ForEach-Object -ThrottleLimit $maxJobCount -AsJob -Parallel {


        $global:InDebug = $Using:InDebug
        $global:InVerbose = $Using:InVerbose

        $SkipCheckSecret = $Using:SkipCheckSecret
        $objectSafesToRemove = $Using:objectSafesToRemove
        $getRemoteMachines = $using:getRemoteMachines
        $noCreate = $using:noCreate
        $allowEmpty = $using:allowEmpty
        $VerifyPlatform = $using:VerifyPlatform
        If ($using:VerifyPlatform) {
            $platforms = $using:platforms
        }

        $srcToken = $using:srcToken
        $SRCPVWAURL = $using:SRCPVWAURL
        $dstToken = $using:dstToken
        $DSTPVWAURL = $using:DSTPVWAURL

        $baseAccount = $PSItem
        $global:accountID = $($PSItem.id)
        $global:accountName = $($PSItem.name)
        $global:safeName = $($PSItem.safeName)
        $global:LOG_FILE_PATH = ".\LogFiles-Accounts\$safeName-$accountName-$accountID-.log"
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
            $dstAccountFound = $false

            Write-LogMessage -Type Info -Msg "Working with source account with username `"$($baseAccount.userName)`" and address `"$($baseAccount.address)`" in safe `"$($baseAccount.safeName)`""
            Try {
                $srcAccount = Get-AccountDetail -url $SRCPVWAURL -logonHeader $srcToken -AccountID $baseAccount.id
            } catch {
                Write-LogMessage -Type Error -Msg "Unable to connect to source account to retrieve username `"$($baseAccount.userName)`" and address `"$($baseAccount.address)`" in safe `"$($baseAccount.safeName)`""
                Write-LogMessage -Type Error -Msg $PSitem
                Write-LogMessage -Type Debug -Msg "$srcAccount = Get-AccountDetail -url $SRCPVWAURL -logonHeader $srcToken -AccountID $baseAccount.id"
                continue
            }
            If ($($srcAccount.safename) -in $objectSafesToRemove) {
                Write-LogMessage -Type Info -Msg "Safe $($srcAccount.safename) is in the excluded safes list. Account with username of `"$($srcAccount.userName)`" with the address of `"$($srcAccount.address)`" will be skipped"
                $AccountStatus.success = $true
                continue
            }
            write-LogMessage -Type Debug -Msg "Found source account"
            write-LogMessage -Type Verbose -Msg "Source account: $($srcAccount |ConvertTo-Json -Compress)"
            Write-LogMessage -Type Debug -Msg "Searching for destination account with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`""
            [array]$dstAccountArray = Get-Accounts -url $DSTPVWAURL -logonHeader $dstToken -safename $($srcAccount.safeName) -keywords "$($srcAccount.userName) $($srcAccount.address)" -startswith $true
            if ((0 -ne $($dstAccountArray.count))) {
                Write-LogMessage -Type Verbose -MSG "Results array from destination: $($dstAccountArray | ConvertTo-Json -Compress)"
                Write-LogMessage -Type Debug -Msg "Found $($dstAccountArray.count) possible destination accounts"
                foreach ($account in $dstAccountArray) {
                    Write-LogMessage -Type Debug -Msg "Comparing found account `"$($account.name)`" to source account of `"$($srcAccount.name)`""
                    IF (($($account.name) -eq $($srcAccount.name)) -and ($($account.userName) -eq $($srcAccount.userName)) -and ($($account.address) -eq $($srcAccount.address)) -and ($($account.safeName) -eq $($srcAccount.safeName))  ) {
                        Write-LogMessage -Type Debug -Msg "Found destination account with username `"$($account.userName)`" and address `"$($account.address)`" in safe `"$($account.safeName)`""
                        Write-LogMessage -Type Verbose -Msg "Destination account: $($account | ConvertTo-Json -Compress)"
                        $dstAccountFound = $true
                        $dstAccount = $account
                    }
                }
            } else {
                Write-LogMessage -Type Warning -Msg "Unable to locate destination account `"$($srcAccount.Name)`" in destination safe `"$($srcAccount.safeName)`""
            }

            if ($dstAccountFound) {
                if (!$SkipCheckSecret) {
                    Write-LogMessage -Type debug -Msg "SkipCheckSecret set to false. Starting check on source and destination secrets"
                    Try {
                        Write-LogMessage -Type Debug -Msg "Getting source Secret"
                        [SecureString]$srcSecret = Get-Secret -url $SRCPVWAURL -logonHeader $srcToken -id $srcAccount.id -ErrorAction SilentlyContinue
                        Write-LogMessage -Type Debug -Msg "Source secret found: $(!$([string]::IsNullOrEmpty($srcSecret)))"
                         if ($null -eq $srcSecret) {
                            Write-LogMessage -Type Info -Msg "No secret found on source account. No change will be made to destination secret."
                            $AccountStatus.success = $true
                        Continue
                        }
                        Write-LogMessage -Type Debug -Msg "Getting destination Secret"
                        [SecureString]$dstSecret = Get-Secret -url $DSTPVWAURL -logonHeader $dstToken -id $dstAccount.id -ErrorAction SilentlyContinue
                        Write-LogMessage -Type Debug -Msg "Destination secret found: $(!$([string]::IsNullOrEmpty($srcSecret)))"
                        If ((![string]::IsNullOrEmpty($srcSecret)) -and (![string]::IsNullOrEmpty($dstSecret)) ) {
                            Write-LogMessage -type Debug -MSG "Comparing secrets"
                            $secretMatch = Compare-SecureString -pwd1 $srcSecret -pwd2 $dstSecret
                        }
                        if ($null -eq $dstSecret -and $null -ne $srcSecret) {
                            Write-LogMessage -Type Debug -Msg "No secret found on destination account $($dstAccount.Name). Setting destination secret to match source secret."
                            Set-Secret -url $DSTPVWAURL -logonHeader $dstToken -id $dstAccount.id -secret $srcSecret
                            Write-LogMessage -Type Info -Msg "Destination account with username `"$($dstAccount.userName)`" and address `"$($dstAccount.address)`" in safe `"$($dstAccount.safeName)`" secret set to match source account."
                            $AccountStatus.success = $true
                        } elseif (!$secretMatch) {
                            Write-LogMessage -Type Debug -Msg "The secret for ource and destination account with username `"$($dstAccount.userName)`" and address `"$($dstAccount.address)`" in safe `"$($dstAccount.safeName)`" secret do not match. Setting destination secret to match source secret."
                            Set-Secret -url $DSTPVWAURL -logonHeader $dstToken -id $dstAccount.id -secret $srcSecret
                            Write-LogMessage -Type Info -Msg "Destination account secret with username `"$($dstAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`" set to match source account."
                            $AccountStatus.success = $true
                        } elseif ($secretMatch) {
                            Write-LogMessage -Type Info -Msg "Source and destination account secret match. No update required"
                            $AccountStatus.success = $true
                        } else {
                            Write-LogMessage -Type Warning -Msg "Unknown Error encountered while working with secrets for source and destination account with username `"$($dstAccount.userName)`" and address `"$($dstAccount.address)`" in safe `"$($dstAccount.safeName)`""
                        }
                    } catch [System.Management.Automation.RuntimeException] {
                        If ("Account Locked" -eq $_) {
                            Write-LogMessage -Type Warning -Msg "Source Account `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`" Locked to another user, unable to update."
                            Write-LogMessage -Type Debug -Msg "$($PSitem.Exception)"
                        } else {
                            Write-LogMessage -Type Error -Msg "Error encountered while working with acount with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `" $($srcAccount.safeName)`": $($_.Exception.Message)" -ErrorAction SilentlyContinue
                            Write-LogMessage -Type LogOnly -Msg "Error encountered while working with acount with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `": $($_|ConvertTo-Json -Compress)" -ErrorAction SilentlyContinue
                        }
                    }
                } Else {
                    Write-LogMessage -Type Debug -Msg "SkipCheckSecret set to true. No checks being done on source and destination secrets"
                    $AccountStatus.success = $true
                }
                if ($getRemoteMachines) {
                    Write-LogMessage -Type Debug -Msg "getRemoteMachines set to true. Updating remoteMachinesAccess on destination account with usernam `"$($dstAccount.userName)`" and address `"$($dstAccount.address)`" in safe `" $($srcAccount.safeName)`""
                    Update-RemoteMachine -url $DSTPVWAURL -logonHeader $dstToken -dstaccount $dstAccount -srcaccount $srcAccount
                }
            } elseif ($noCreate) {
                Write-LogMessage -Type Warning -Msg "Destination account with username of `"$($dstAccount.userName)`" and address `"$($dstAccount.address)`" in safe safe `" $($srcAccount.safeName)`" does not exist and account creation disabled, skipping creation of account"
                $AccountStatus.success = $true
            } else {
                try {
                    If ($VerifyPlatform) {
                        write-LogMessage -Type info -Msg "Verifying platform with ID of `"$($srcAccount.platformId)`" exists in destination enviorment for account `"$($srcAccount.Name)`" in safe `"$($srcAccount.safeName)`""
                        write-LogMessage -Type Verbose -Msg "Source Accounts: $($srcAccount |ConvertTo-Json -Compress)"
                        $srcAccount.platformId = $($platforms.Platforms.general | Where-Object {$_.id -like $srcAccount.platformId}).id
                        if ([string]::IsNullOrEmpty($srcAccount.platformId )) {
                            write-LogMessage -Type Error -Msg "Unable to locate platform in destination for account with the username `"$($dstAccount.userName)`" and address `"$($dstAccount.address)`" in safe `" $($srcAccount.safeName)`" unable to create account"
                            Continue
                        }
                    }

                    write-LogMessage -Type info -Msg "Destination account with username `"$($dstAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`" does not exist. Attempting to create account."
                    write-LogMessage -Type info -Msg "Checking for destination safe `"$($srcAccount.safeName)`""
                    $dstsafe = Get-Safe -url $DSTPVWAURL -logonHeader $dstToken -safe $srcAccount.safeName -ErrorAction SilentlyContinue
                    if ([string]::IsNullOrEmpty($dstsafe)) {
                        Write-LogMessage -Type error -Msg "Destination safe of `"$($srcAccount.safeName)`" does not exist, skipping creation of account with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`""
                        continue
                    }
                    write-LogMessage -Type info -Msg "Destination safe `"$($srcAccount.safeName)`" found"
                    [SecureString]$srcSecret = Get-Secret -url $SRCPVWAURL -logonHeader $srcToken -id $srcAccount.id -ErrorAction SilentlyContinue
                    IF (![string]::IsNullOrEmpty($srcSecret)) {
                        Write-LogMessage -Type debug -Msg "Source account with username `"$($dstAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`" has a secret. Sending creation request to destination enviorment"
                        $dstAccount = New-Account -url $DSTPVWAURL -logonHeader $dstToken -account $srcAccount -secret $srcSecret
                        Write-LogMessage -type Debug -Msg "Account with username `"$($dstAccount.userName)`" and address `"$($dstAccount.address)`" in safe `"$($dstAccount.safeName)`" succefully created in destination enviorment"
                    } elseif ($allowEmpty) {
                        Write-LogMessage -Type debug -Msg "Source account with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`" does not have a secret, but empty secrets are allowed. Sending creation request to destination enviorment"
                        $dstAccount = New-Account -url $DSTPVWAURL -logonHeader $dstToken -account $srcAccount -allowEmpty
                        Write-LogMessage -type Debug -Msg "Account with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`" succefully created in destination enviorment"
                    } else {
                            Write-LogMessage -Type Warning -Msg "No password set on source account with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`""
                    }
                    $AccountStatus.success = $true
                } catch [System.Management.Automation.RuntimeException] {
                    If ("Account Locked" -eq $_.Exception.Message) {
                        Write-LogMessage -Type Warning -Msg "Source Account with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`" Locked, unable to update"
                        Write-LogMessage -Type Debug -Msg $PSitem
                    } elseIf ($_.Exception.Message -match 'Safe .* was not found') {
                        Write-LogMessage -Type Warning -Msg "Source safe `"$($srcAccount.safeName)`" not found"
                        Write-LogMessage -Type Debug -Msg $PSitem
                    } elseIf ($_.Exception.Message -match 'Platform .* was not found') {
                        Write-LogMessage -Type Warning -Msg "Platform `"$($srcAccount.platformId)`" not found. Unable to create `"$($srcAccount.Name)`" in safe `"$($srcAccount.safeName)`""
                        Write-LogMessage -Type Debug -Msg $PSitem
                    } else {
                        Write-LogMessage -Type Error -Msg "Error encountered while working with account with username `"$($srcAccount.userName)`" and address `"$($srcAccount.address)`" in safe `"$($srcAccount.safeName)`": $($_.Exception.Message)" -ErrorAction SilentlyContinue
                        Write-LogMessage -Type LogOnly -Msg "Error encountered while working with `"$($srcAccount.Name)`": $($_|ConvertTo-Json -Compress)" -ErrorAction SilentlyContinue
                        Write-LogMessage -Type Debug -Msg "Caught Exception:`n$($PSitem.Exception)"
                    }
                }
            }
        } Finally {
            $accountStatus
            $process.Completed = $true
        }
    }
    Write-LogMessage -Type Info -MSG "Submission of $($AccountJob.ChildJobs.Count) jobs completed at $(Get-Date -Format "HH:mm:ss"). Maxiumn running PowerShell jobs set to $maxJobCount."
    $PSStyle.Progress.View = "Classic"
    while ($AccountJob.State -eq 'Running') {
        $accountProgressSync.Keys | ForEach-Object {
            if (![string]::IsNullOrEmpty($accountProgressSync.$_.keys)) {
                if (!$SuppressProgress) {
                    $completed = $($AccountJob.ChildJobs | Where-Object {$_.State -eq "Completed"}).count
                    $total = $AccountJob.ChildJobs.count
                    $Precent = ($completed / $total) * 100
                    $process = @{}
                    $process.Id = 0
                    $process.Activity = "Processing Accounts"
                    $process.Status = "$completed out of $total jobs completed"
                    $process.PercentComplete = $Precent
                    Write-Progress -Id 0 @process

                    if ($ProgressDetails.IsPresent) {
                        $param = $accountProgressSync.$_
                        $param.ParentId = 0
                        Write-Progress @param
                    }
                }
            }
        }

        # Wait to refresh to not overload gui
        Start-Sleep -Seconds .5
    }
    Write-Progress -Id 0 -Completed $true
    $($AccountReport = Receive-Job $accountjob) 6> $null 5> $null 4> $null 3> $null 2> $null 1> $null
    $AccountSuccess = $AccountReport | Where-Object success -EQ $true
    $AccountFailed = $AccountReport | Where-Object success -EQ $false -ErrorAction SilentlyContinue
    Write-LogMessage -Type Info "Accounts succesfully updated: $($accountSuccess.success.count)"
    Write-LogMessage -Type Info "Accounts failed to updated: $($AccountFailed.success.count)"
    If (![string]::IsNullOrEmpty($AccountFailed)) {
        [array]$AccountFailed.accountData | Add-Member -MemberType NoteProperty -Name FailReason -Value $null -Force
        $i = 0
        foreach ($id in $AccountFailed) {
            $AccountFailed[$i].accountData.FailReason = $AccountFailed[$i].Error
            $i++
        }
        $AccountFailed.accountData | Where-Object {!$([string]::IsNullOrEmpty($PSItem.FailReason))} | Export-Csv -Force .\FailedAccounts.csv
        Write-LogMessage -type Error -MSG "Errors found, list outputted to `".\FailedAccounts.csv`""
    }
    Write-LogMessage -Type Info "Processing of accounts completed at $(Get-Date -Format "HH:mm:ss")"

    if ([string]::IsNullOrEmpty($srcToken)) {
        $srcToken = Get-IdentityHeader -IdentityUserName brian.bors@cyberark.cloud.1024 -IdentityTenantURL "https://aal4797.my.idaptive.app"
    }
}
<#
.SYNOPSIS

Migrate data from one CyberArk environment to another
Synchronize data from CyberArk environment to another
#>
