<#

AUTHOR: Jake DeSantis <jake.desantis@cyberark.com>, Brian Bors <brian.bors@cyberark.com>

Date: 3/1/2021

Description: This script can be used to convert exported Vault Environment Migration data to a format that can be used with
various REST API Scripts available via CyberArk's GitHub. When needing to migrate from older versions to version 10+. 
This is also useful for on-prem to Privilege Cloud migrations until a more official solution is available.

Updates:
2021-07-12
Updated to generate seperate file for account links to allow for them to be imported seperatly.
Brian Bors

#>

$global:LOG_DATE = $(Get-Date -Format yyyyMMdd) + "-" + $(Get-Date -Format HHmmss)
$global:LOG_FILE_PATH = ".\Convert-VemFiles-$LOG_DATE.log"

function Convert-vemOwnersFileSS {
    <#
.Synopsis
Converts ownsers.csv file for use with the safe management utiliy against Shared Services ISPSS
.DESCRIPTION
Creates a new file in the directory specified with only the values that are used in the safe-management.ps1 utility.
The file that's created can then be used with the CyberArk Safe Management utility to quickly onboard the safes.
.EXAMPLE
Convert-vemOwnersFileSS -ownersCSV C:\Temp\owners.csv -usersGroupsCSV C:\Temp\UsersGroups.csv -destinationFile C:\Temp\safe-management.csv
.EXAMPLE
Convert-vemOwnersFileSS -ownersCSV C:\Temp\owners.csv -usersGroupsCSV C:\Temp\UsersGroups.csv -ManagingCPM CPM_WIN
.EXAMPLE
Convert-vemOwnersFileSS -ownersCSV C:\Temp\owners.csv -usersGroupsCSV C:\Temp\UsersGroups.csv -destinationFile C:\Temp\safe-management.csv -verbose
.NOTES
- As good practice, check the output file. Manually remove any records that do not need to be imported
- Built-In users and safes will not be removed from the output file. Remove these manually if needed

#>
    [CmdletBinding()]
    [Alias("cvow")]
    [OutputType()]
    Param
    (
        # Objects.csv file that was created with the VEM utility
        [Parameter(Mandatory = $true,
            HelpMessage = "Path and file name of the objects.csv file created by the vem utiltiy",
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        $ownersCSV,
        [Parameter(Mandatory = $true,
            HelpMessage = "Path and file name of the usersGroups.csv file created by the vem utiltiy",
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        $usersGroupsCSV,
        #Destination file and path for the objects
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        [ValidatePattern( '\.csv$' )]
        $destinationFile = "$($env:TEMP)\ownersForImport.csv",
        #CPM to be used for all safes
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        $newCPM,
        #CPM to be removed
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        $oldCPM,
        #Domain Suffix to be added to users and groups
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        [string]$domainToAdd
    )
    Begin {
        $global:LOG_DATE = $(Get-Date -Format yyyyMMdd) + "-" + $(Get-Date -Format HHmmss)
        $global:LOG_FILE_PATH = ".\Convert-vemOwnersFileSS$LOG_DATE.log"

        $Global:InDebug = IF ($PSBoundParameters.Debug.IsPresent) {
            $true
        } else {
            $false
        }
        $Global:InVerbose = IF ($PSBoundParameters.Verbose.IsPresent) {
            $true
        } else {
            $false
        }

        #import the userGroups.csv to object
        $userGroups = Import-Csv $usersGroupsCSV
        Write-LogMessage -type Info -MSG "Importing users and groups from :`'$usersGroupsCSV`'"

        #import the owners.csv to object
        $owners = Import-Csv $ownersCSV
        Write-LogMessage -type Info -MSG "Importing safe owners from `"$ownersCSV`""

        $vaultAdminsReplacement = "Privilege Cloud Administrators"
        Write-LogMessage -type Info -MSG "Using `"$vaultAdminsReplacement`" to replace Vault Admins"

        $destinationFileSafes = $destinationFile.replace(".csv", "_Safes.CSV")
        $destinationFileAdmin = $destinationFile.replace(".csv", "_Admin.CSV")
        Write-LogMessage -type Info -MSG "Outputing Owner results to : $destinationFile"
        Write-LogMessage -type Info -MSG "Outputing list of safes alone to : $destinationFileSafes"
        Write-LogMessage -type Info -MSG "Outputing list of safes to add `"$vaultAdminsReplacement`" : $destinationFileAdmin"

        #define the properties needed for safe-management script
        $newProperties = "Safename", "Description", "Member", "MemberLocation", "MemberType", "UseAccounts", "RetrieveAccounts", "ListAccounts", "AddAccounts", "UpdateAccountContent",
        "UpdateAccountProperties", "InitiateCPMAccountManagementOperations", "SpecifyNextAccountContent", "RenameAccounts", "DeleteAccounts", "UnlockAccounts", "ManageSafe",
        "ManageSafeMembers", "BackupSafe", "ViewAuditLog", "ViewSafeMembers", "RequestsAuthorizationLevel", "AccessWithoutConfirmation", "CreateFolders",
        "DeleteFolders", "MoveAccountsAndFolders", "InternalOwner", "InternalSafe", "ManagingCPM"

        #Define built in users to remove
        $ownersToRemove = "Auditors", "Backup Users", "Batch", "PasswordManager", "DR Users", "Master", "Notification Engines", "Notification Engine",
        "Operators", "PTAAppUsers", "PTAAppUser", "PVWAGWAccounts", "PVWAAppUsers", "PVWAAppUser", "PVWAAppUser1", "PVWAAppUser2", "PVWAAppUser3", "PVWAAppUser4", "PVWAAppUser5",
        "PVWAAppUser6", "PVWAUsers", "PVWAMonitor", "PSMUsers", "PSMAppUsers", "PTAUser", $oldCPM

        #Define built-in safes to remove
        $safesToRemove = "System", "VaultInternal", "Notification Engine", "SharedAuth_Internal", "PVWAUserPrefs",
        "PVWAConfig", "PVWAReports", "PVWATaskDefinitions", "PVWAPrivateUserPrefs", "PVWAPublicData", "PVWATicketingSystem",
        "PasswordManagerTemp", "PasswordManager_Pending", "PasswordManagerShared",
        "$($oldCPM)", "$($oldCPM)_Accounts", "$($oldCPM)_ADInternal", "$($oldCPM)_Info", "$($oldCPM)_workspace",
        "PasswordManager", "PasswordManager_Accounts", "PasswordManager_ADInternal", "PasswordManager_Info", "PasswordManager_workspace",
        "PasswordManager1", "PasswordManager1_Accounts", "PasswordManager1_ADInternal", "PasswordManager1_Info", "PasswordManager1_workspace",
        "PasswordManager2", "PasswordManager2_Accounts", "PasswordManager2_ADInternal", "PasswordManager2_Info", "PasswordManager2_workspace",
        "PasswordManager3", "PasswordManager3_Accounts", "PasswordManager3_ADInternal", "PasswordManager3_Info", "PasswordManager3_workspace",
        "AccountsFeed", "PSM", "xRay", "PIMSuRecordings", "xRay_Config",
        "AccountsFeedADAccounts", "AccountsFeedDiscoveryLogs", "PSMSessions", "PSMLiveSessions", "PSMUniversalConnectors",
        "PSMNotifications", "PSMUnmanagedSessionAccounts", "PSMRecordings", "PSMPADBridgeConf", "PSMPADBUserProfile", "PSMPADBridgeCustom",
        "AppProviderConf"

        #add each property to the owners object
        foreach ($property in $newProperties) {
            $owners | Add-Member -MemberType NoteProperty -Name $property -Value $null
        }
        Write-LogMessage -type Debug -MSG "newProperties: $newProperties"

    }
    Process {
        #start the counter for writing progress
        $counter = 0
        #update each new ownership property with the cooresponding PACLI ownership property
        foreach ($owner in $owners) {
            $counter++
            #Write progress bar
            Write-Progress -Activity "Processing safe ownerships" -CurrentOperation "$counter of $($owners.count)" -PercentComplete (($counter / $owners.count) * 100)
            Write-LogMessage -type Debug -MSG "For safe `"$($owner.'safe name')`" processing line: $owner"
            if ("Vault Admins" -eq $owner.'Owner Name') {
                $owner.'Owner Name' = $vaultAdminsReplacement
                $owner.MemberType = "Role"
            }

            $owner.safename = $owner.'Safe Name' 
            $owner.Member = $owner.'Owner Name'
            $owner.UseAccounts = $owner.'Use Password'
            $owner.RetrieveAccounts = $owner.Retrieve
            $owner.ListAccounts = $owner.List
            $owner.AddAccounts = $owner.'Create Object'
            $owner.UpdateAccountProperties = $owner.'Update object properties'
            $owner.InitiateCPMAccountManagementOperations = $owner.'Initiate CPM change'
            $owner.SpecifyNextAccountContent = $owner.'Initiate CPM change with manual password'
            $owner.RenameAccounts = $owner.'Rename object'
            $owner.DeleteAccounts = $owner.Delete
            $owner.UnlockAccounts = $owner.'Unlock object'
            $owner.ManageSafe = $owner.Administer
            $owner.ManageSafeMembers = $owner.'Manage owners'
            $owner.BackupSafe = $owner.Backup
            $owner.ViewAuditLog = $owner.'View audit'
            $owner.ViewSafeMembers = $owner.'View permissions'
            $owner.AccessWithoutConfirmation = $owner.'Access no confirmation'
            $owner.CreateFolders = $owner.'Create folder'
            $owner.DeleteFolders = $owner.'Delete folder'
            $owner.UpdateAccountContent = $owner.Store
            $owner.ManagingCPM = "$newCPM"

            #if the safe is in the list of safes to remove, mark it as internal then move to the next one
            if ($safesToRemove -contains $owner.safename) {
                Write-LogMessage -type LogOnly -MSG "Marking safe `"$($owner.safename)`" as internal because it is likely built-in."
                $owner.InternalSafe = "true"
                continue
            } else {
                $owner.InternalSafe = "false"
            }

            #if the safe owner is in the list of owners to remove, mark it as internal then move to the next one
            if ($ownersToRemove -contains $owner.Member) {
                Write-LogMessage -type LogOnly -MSG "Marking owner `"$($owner.'owner name')`" as internal for the safe `"$($owner.safename)`" because it is likely built-in."
                $owner.InternalOwner = "true"
                continue
            } else {
                $owner.InternalOwner = "false"
            }

            #if old properties move from and move into are both set as YES, set move accounts and folders to yes
            if (($owner.'Move from' -eq "YES") -and ($owner.'Move into' -eq "YES")) {
                Write-LogMessage -type Debug -MSG "Old values `"move from`" and `"move into`" are both set to `"YES`", setting `"MoveAccountsAndFolders`" to `"YES`" for `"$($owner.'Owner Name')`" on `"$($owner.safename)`""
                $owner.MoveAccountsAndFolders = "YES"

            } else {
                $owner.MoveAccountsAndFolders = "NO"
            }

            #if old property supervise is yes, set requestauthorizationlevel to 1
            if ($owner.Supervise -eq "YES") {
                Write-LogMessage -type Debug -MSG "Old value, `"Supervise`", is set to `"YES`". Setting request authorization level for `"$($owner.'owner name')`" to `"1`" on `"$($owner.safename)`""
                $owner.RequestsAuthorizationLevel = 1
            } else {
                $owner.RequestsAuthorizationLevel = 0
            }

            #map the owner location to the LDAP Directory in the usersgroups.csv
            $ownerLocation = ($userGroups | Where-Object Name -EQ $owner.'Owner Name').'LDAP Directory'

            #if LDAP Direcotry is empty or null, set the MemberLocation property to "vault", otherwise, set it to the ldap directory name defined.
            if ($ownerLocation -like $null) {
                Write-LogMessage -type Debug -MSG "`"$($owner.'owner name')`" is a vault object. Assigning member location as `"vault`""
                $owner.MemberLocation = "vault"
            } else {
                Write-LogMessage -type Debug -MSG "`"$($owner.'owner name')`" is a `"$ownerLocation`" object. Assigning member location as `"$ownerLocation`""
                $owner.MemberLocation = $ownerLocation
            }

            #map the owner location to the Type in the usersgroups.csv
            $ownerType = ($userGroups | Where-Object Name -EQ $owner.'Owner Name').'Type'

            If ("EXTERNAL USER" -eq $ownerType) {
                $owner.MemberType = "User"
            } elseif ("EXTERNAL GROUP" -eq $ownerType) {
                $owner.MemberType = "Group"
            } elseIF ("USER" -EQ "$ownerType") {
                $owner.MemberType = "Review - Internal User"
            } elseif ("GROUP" -eq $ownerType) {
                $owner.MemberType = "Review - Internal Group"
            }
            If (![string]::IsNullOrEmpty($domainToAdd) -and ($owner.MemberType -in @("User", "Group"))) {
                $owner.Member = $owner.'Owner Name' + "@" + $domainToAdd
                Write-LogMessage -type Debug -MSG "Added `"@ + $domainToAdd`" to Member name"
            } else {
                $owner.Member = $owner.'Owner Name'
            }
        }
        $owners | Add-Member -MemberType NoteProperty -Name "EnableAutoMgmt" -Value $null

        #Output result to a CSV file
        $owners | Where-Object { ($_.internalOwner -eq "false") -and ($_.internalSafe -eq "false") } | Select-Object -Unique "Safename", "Description", "ManagingCPM" | Export-Csv -NoTypeInformation $destinationFileSafes

        #convert YES/NO to true/false in the destination file
(Get-Content $destinationFileSafes).Replace('"YES"', '"true"').Replace('"NO"', '"false"') | Set-Content $destinationFileSafes

        $owners | Where-Object { ($_.internalOwner -eq "false") -and ($_.internalSafe -eq "false") } | Select-Object -Unique "Safename", "Member", "MemberType", "MemberLocation", "UseAccounts", "RetrieveAccounts", 
        "ListAccounts", "AddAccounts", "UpdateAccountContent",
        "UpdateAccountProperties", "InitiateCPMAccountManagementOperations", "SpecifyNextAccountContent", "RenameAccounts", "DeleteAccounts", "UnlockAccounts", "ManageSafe",
        "ManageSafeMembers", "BackupSafe", "ViewAuditLog", "ViewSafeMembers", "RequestsAuthorizationLevel", "AccessWithoutConfirmation", "CreateFolders", "DeleteFolders",
        "MoveAccountsAndFolders" | Export-Csv -NoTypeInformation $destinationFile

        #convert YES/NO to true/false in the destination file
(Get-Content $destinationFile).Replace('"YES"', '"true"').Replace('"NO"', '"false"') | Set-Content $destinationFile

        Write-LogMessage -type Info -MSG "Owners file written to `"$destinationFile`""
        Write-LogMessage -type Info -MSG "Safes file written to `"$destinationFileSafes`"" 


        $adminTemp = $owners | Where-Object { ($_.internalOwner -eq "false") -and ($_.internalSafe -eq "false") } | Select-Object -Unique 'SafeName'

        [PSCustomObject]$admins = @{}

        $adminTemp | ForEach-Object { [PSCustomObject]$adminBase = @{
                safeName                               = $_.SafeName
                Member                                 = $vaultAdminsReplacement
                MemberType                             = "Role"
                MemberLocation                         = $null
                UseAccounts                            = $True
                RetrieveAccounts                       = $True
                ListAccounts                           = $True
                AddAccounts                            = $True
                UpdateAccountProperties                = $True
                UpdateAccountContent                   = $True
                InitiateCPMAccountManagementOperations = $True
                SpecifyNextAccountContent              = $True
                RenameAccounts                         = $True
                DeleteAccounts                         = $True
                UnlockAccounts                         = $True
                ManageSafe                             = $True
                ManageSafeMembers                      = $True
                BackupSafe                             = $True
                ViewAuditLog                           = $True
                ViewSafeMembers                        = $True
                AccessWithoutConfirmation              = $True
                CreateFolders                          = $True
                DeleteFolders                          = $True
                MoveAccountsAndFolders                 = $True
                RequestsAuthorizationLevel             = 1

            }
            $admins += $adminBase
        }
        $admins | Select-Object -Unique | Export-Csv -NoTypeInformation $destinationFileAdmin
        Write-LogMessage -type Info -MSG "Admins file written to `"$destinationFileAdmin`"" 
    }
}

function Convert-vemObjectsFile {
    <#
 .Synopsis
Converts objects.csv file for use with the 
 .DESCRIPTION
Creates a new file in the directory specified with only the values that are used in the accounts onboarding utility.
The file that's created can then be used with the CyberArk Accounts Onboarding Utility to quickly onboard the accounts.
A total of four file may be created. they include
 ObjectsForImport.csv - Main file with all the objects
 ObjectsForImport_GroupObjects.csv - Contains all the accounts group objects
 ObjectsForImport_LinkObjects.csv - Contains all the links between accounts. This includes Logon, Enable, and Reconconcile accounts.
 ObjectsForImport_Usages.csv - Contains all accounts usgages.
 
 The files should be processed as follows.
 
 ObjectsForImport
 Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -Create -CSVPath "ObjectsForImport.csv"
 ObjectsForImport_GroupObjects.csv
 Import-module .\Import-CyberArkGroupObjects.ps1
 Process-CyberArkGroupObjects -groupedObjectsCSV ObjectsForImport_GroupObjects -caEnv myPVWA.myDomain.com -logonUser Administrator -authSystem CyberArk
 ObjectsForImport_LinkObjects.csv
 Link-Accounts.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -CSVPath ObjectsForImport_LinkObjects.csv
 ObjectsForImport_Usages.csv
 ***Warning*** This file requires manual updates prior to running
 Onboard-DependentAccountsFromCSV.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -CsvPath ObjectsForImport_Usages.csv
 
 .EXAMPLE
Convert-vemObjectsFile -objectsCSV C:\Temp\Objects.csv -destinationFile C:\Temp\ObjectsForImport.csv
 .EXAMPLE
Convert-vemObjectsFile -objectsCSV C:\Temp\Objects.csv
 .EXAMPLE
Convert-vemObjectsFile -objectsCSV C:\Temp\Objects.csv -destinationFile C:\Temp\ObjectsForImport.csv -verbose
 .NOTES
- Objects that have no password are filtered out.
- As good practice, check the output file. Manually remove any records that do not need to be imported like PSM objects, xRay objects, etc..
- You may find passwords in the destination file that have two sets of double quotes in them. Do not modify the objects. The Onboard Utility will remove the extra double quote from the record.
#>
 
    [CmdletBinding()]
    [Alias("cvob")]
    [OutputType()]
    Param
    (
        # Objects.csv file that was created with the VEM utility
        [Parameter(Mandatory = $true,
            HelpMessage = "Path and file name of the objects.csv file created by the vem utiltiy",
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        $objectsCSV,
        #Destination file and path for the objects
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        [ValidatePattern( '\.csv$' )]
        $destinationFile = "$($env:TEMP)\objectsForImport.csv",
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 2)]
        [switch]$ForceCPMEnabled
    )
 
    Begin {
        $global:LOG_DATE = $(Get-Date -Format yyyyMMdd) + "-" + $(Get-Date -Format HHmmss)
        $global:LOG_FILE_PATH = ".\Convert-vemObjectsFile$LOG_DATE.log"
 
        $InDebug = IF ($PSBoundParameters.Debug.IsPresent) {
            $true
        } else {
            $false
        }
        $InVerbose = IF ($PSBoundParameters.Verbose.IsPresent) {
            $true
        } else {
            $false
        }
 
        #import the objects CSV file created by the VEM utiltiy
        Write-LogMessage -type Info -MSG "Importing objects from : $objectsCSV"
        $objects = Import-Csv $objectsCSV
 
        #modify the objects variable removing any records that don't contain a password
        #$objects=$objects | Where-Object password -notlike ''
 
    }
    Process {
 
        #Add properties/members to the objects variable that are needed for the Accounts Onboarding Utility
        $objects | Add-Member -MemberType NoteProperty -Name "EnableAutoMgmt" -Value $null
        $objects | Add-Member -MemberType NoteProperty -Name "PlatformID" -Value $null
        $objects | Add-Member -MemberType NoteProperty -Name "ManualMgmtReason" -Value $null
        $objects | Add-Member -MemberType NoteProperty -Name "GroupPlatformId" -Value $null
        $objects | Add-Member -MemberType NoteProperty -Name "Name" -Value $null
        $objects | Add-Member -MemberType NoteProperty -Name "Delete" -Value $null
 
        #built-in safes for which resident accounts are ignored
        $objectSafesToRemove = "System", "VaultInternal", "Notification Engine", "SharedAuth_Internal", "PVWAUserPrefs",
        "PVWAConfig", "PVWAReports", "PVWATaskDefinitions", "PVWAPrivateUserPrefs", "PVWAPublicData", "PVWATicketingSystem", "PasswordManager",
        "PasswordManagerTemp", "PasswordManager_Pending", "PasswordManager_workspace", "PasswordManager_ADInternal",
        "PasswordManager_Info", "PasswordManagerShared", "AccountsFeed", "PSM", "xRay", "PIMSuRecordings", "xRay_Config",
        "AccountsFeedADAccounts", "AccountsFeedDiscoveryLogs", "PSMSessions", "PSMLiveSessions", "PSMUniversalConnectors",
        "PSMNotifications", "PSMUnmanagedSessionAccounts", "PSMRecordings", "PSMPADBridgeConf", "PSMPADBUserProfile", "PSMPADBridgeCustom",
        "AppProviderConf"
 
        #built in properties to be excluded from standard objects on export
        $BuiltInProperties = "Object Name", "Local Folder", "SequenceID", "LastSuccessChange", "LastSuccessVerification", "LastSuccessReconciliation",
        "RetriesCount", "CPMStatus", "LastTask", "DeviceType", "PolicyID", "LastFailDate", "CPMErrorDetails", "CPMDisabled", "WebApplicationID", "CreationMethod",
        "ResetImmediately", "_PSMLiveSessions_1", "_PSMLiveSessions_2", "_PSMLiveSessions_3", "_PSMLiveSessions_4", "_PSMLiveSessions_5", "ConnectionComponentID",
        "EntityVersion", "ExpectedRecordingsList", "PSMClientApp", "PSMPasswordID", "PSMProtocol", "PSMRecordingEntity", "PSMRemoteMachine", "PSMSafeID", "PSMSourceAddress",
        "PSMStartTime", "PSMStatus", "PSMVaultUserName", "ProviderID", "PSMEndTime", "ActualRecordings", "RiskScore", "IncidentDetails", "RecordingUploadError",
        "MasterPassName", "MasterPassFolder", "ServiceName", "RestartService", "TaskName", "TaskFolder", "AppPoolName", "RegistryValueName", "RegistryPathName", "ConnectionType",
        "INISection", "FilePath", "INIParameterName", "XMLElement", "SSHCertificate"
 
        #Pending Account Properties to be excluded
        $pendingAccountProperties = "AccountEnabled", "DiscoveryPlatformType", "LastLogonDate", "UserDisplayName", "AccountExpirationDate", "AccountDiscoveryDate", "LastPasswordSetDate",
        "OSVersion", "AccountCategory", "PasswordNeverExpires", "OU", "AccountOSGroups", "Domain", "MachineOSFamily", "AccountDescription", "SID", "Dependencies", "AccountSource"
 
        #standard object properties that are built-in
        $standardObjectProperties = "name", "username", "password", "address", "safe", "folder", "platformid", "enableautomgmt", "manualmgmtreason", "remotemachineaddress",
        "restrictremotemachineaccesstolist", "sshkey", "database", "dsn", "port", "LogonDomain", "SSHCertificate", "ActiveDirectoryID", "UseSudoOnReconcile", "ReconcileIsWinAccount"
 
        $linkObjectProperties = "name", "username", "address", "safe", "folder", "ExtraPass1Safe", "ExtraPass1Folder", "ExtraPass1Name", "ExtraPass2Safe", "ExtraPass2Folder", "ExtraPass2Name", "ExtraPass3Safe", "ExtraPass3Folder", "ExtraPass3Name"
 
        #excluded properties for filtering custom properties of standard objects
        $excludedProperties = $standardObjectProperties + $BuiltInProperties + $pendingAccountProperties + "Delete" + "groupPlatformID" + "GroupName", "LimitDomainAccess"
 
        #properties needed for grouped objects
        $groupObjectProperties = "name", "username", "Address", "password", "safe", "folder", "PlatformID", "EnableAutoMgmt", "ManualMgmtReason",
        "RemoteMachineAddresses", "ResrictMachineAccessToList", "SSHKey", "GroupName", "GroupPlatformID", "database", "dsn", "port", "LogonDomain"
 
        #properties needed for usage/dependency objects
        $usageObjectProperties = "name", "username", "address", "safe", "folder", "platformid", "enableautomgmt", "manualmgmtreason", "sshkey",
        "database", "dsn", "port", "LogonDomain", "ExtraPass1Name", "ExtraPass1Folder", "ExtraPass1Safe", "MasterPassName", "MasterPassFolder",
        "ServiceName", "RestartService", "TaskName", "TaskFolder", "AppPoolName", "RegistryValueName", "RegistryPathName", "ConnectionType",
        "INISection", "FilePath", "INIParameterName", "XMLElement"
 
 
        #define custom props as a blank array to be added to durring runtime
        $customprops = @()
 
        #define the counter for writing progress
        $counter = 0
        #for each entry in the objects variable, update the new properties/members
        foreach ($object in $objects) {
            $counter++
            Write-Progress -Activity "Processing objects" -CurrentOperation "$counter of $($objects.count)" -PercentComplete (($counter / $objects.count) * 100)
            Write-LogMessage -type Debug -MSG "Processing object `"$counter`" of `"$($objects.count)`"" 
            Write-LogMessage -type Debug -MSG "Processing object: `"$($object."Object Name")`""
 
            if ($objectSafesToRemove -match $object.safe) {
                Write-LogMessage -type Debug -MSG "Skipping `"$($object."Object Name")`" because it is in a excluded safe"
                #set delete property to true
                $object.Delete = $true
                #skip this object since it's marked for removal
                continue
 
            }
            #Verbose Output
 
 
            #if CPMDisabled is not blank, update the EnableAutoMgmt property to be "No"
            if ($object.CPMDisabled -notlike $null) {
                if ($ForceCPMEnabled) {
                    Write-LogMessage -type Debug -MSG "CPM is disabled for `"$($object."Object Name")`" with `"CPMDisabled`" set to `"$($object.CPMDisabled)`", however ForceCPMEnabled is True. Setting EnableAutoMgmt to `"Yes`" and clearing `"CPMDisabled`""
                    $object.EnableAutoMgmt = "Yes"
                    $object.CPMDisabled = $object.RetriesCount = $object.CPMStatus = $object.CPMStatus = $object.CPMErrorDetails = $object.LastFailDate = $null
                } else {
                    #Verbose output
                    Write-LogMessage -type Debug -MSG "CPM is disabled for `"$($object."Object Name")`". Setting EnableAutoMgmt to `"No`" with `"CPMDisabled`" set to `"$($object.CPMDisabled)`""
                    $object.EnableAutoMgmt = "No"
                }
            } else {
                Write-LogMessage -type Debug -MSG "CPM is enabled for `"$($object."Object Name")`". Setting EnableAutoMgmt to `"Yes`""
                $object.EnableAutoMgmt = "Yes"
            }
 
            #set the platformID property/member to be "PolicyID"
            $object.PlatformID = $object.PolicyID
 
            #set the object name to be the same name as it was before
            $object.name = $object."Object Name"
 
            #set the manual management reason
            $object.ManualMgmtReason = $object.CPMDisabled
 
            #Remove immediately pending CPM actions
            $object.ResetImmediately = $null
 
            #if the object has a group name set the group platform id as the group parent object's policy id
            if ($object.groupname) {
                $groupPlatformID = ($objects | Where-Object { ($_.safe -eq $object.safe) -and ($_.password -eq $object.password) -and ($_.Folder -eq 'Root\Groups') }).PolicyID
                Write-LogMessage -type Debug -MSG "$($object.name) is a grouped account. Assigning $groupPlatformID as the Group Platform ID"
                $object.groupPlatformID = $groupPlatformID
            }
 
            #get the custom properties that are set for this object and add to customprops variable
            $customProps += $($object.PSObject.Properties | Where-Object { ($_.name.ToLower() -notin $excludedProperties) -and ($_.value -notlike $null) })
 
            #Verbose Output
            $verboseOutput = $($object.PSObject.Properties | Where-Object {($_.value -notlike $null) -and ($_.name -ne "Password")})
            Write-LogMessage -type Debug -MSG "Object properties = $($($object | Format-List -Property $verboseOutput.name| Out-String))"
            If ([string]::IsNullOrEmpty($object.Password)) {
                Write-LogMessage -type Debug -MSG "Password not populated"
            } else {
                Write-LogMessage -type Debug -MSG "Password is set but hidden"
            }
        }
 
        #only select the unique custom properties
        $customProps = $customProps.name | Select-Object -Unique | Where-Object { $_ -NotIn $linkObjectProperties }
 
        #create list of all possible object properties
        $objectProps = $standardObjectProperties + $customProps
 
        #export the objects to the destination file
        $objects | Where-Object { ($_.Delete -NE "true") -and (!$_.groupPlatformID) -and (!$_.MasterPassName) } | Select-Object -Property $objectProps -ExcludeProperty "Folder" | Export-Csv $destinationFile -NoTypeInformation
 
        Write-LogMessage -type Info -MSG "Objects file written to $destinationFile"
 
        #Determine if there are any grouped objects
        $groupObjects = $objects | Where-Object { ($_.Delete -NE "true") -and (($_.groupPlatformID) -or ($_.folder -eq "Root\Groups")) } | Select-Object -Property $groupObjectProperties
 
        #if there are group objects, write them to a separate file
        if ($groupObjects) {
            Write-LogMessage -type Debug -MSG "Group Objects Found" 
            #export group objects to a new csv
            $groupObjects | Export-Csv "$($destinationFile.replace(".csv","_GroupObjects.csv"))" -NoTypeInformation
            WWrite-LogMessage -type Info -MSG "Group Objects file written to $($destinationFile.replace(".csv","_GroupObjects.csv"))"
        }
 
        $linkObjects = $objects | Where-Object { ($_.Delete -NE "true") -and (($_.ExtraPass1Name) -or ($_.ExtraPass2Name) -or ($_.ExtraPass3Name)) } | Select-Object -Property $linkObjectProperties
 
        #if there are group objects, write them to a separate file
        if ($linkObjects) {
            Write-LogMessage -type Debug -MSG "Links Found" 
            #export group objects to a new csv
            $linkObjects | Export-Csv "$($destinationFile.replace(".csv","_LinkObjects.csv"))" -NoTypeInformation
            Write-LogMessage -type Info -MSG "Link Objects file written to $($destinationFile.replace(".csv","_LinkObjects.csv"))" 
        }
 
 
        #Determine if there are any usages/dependencies objects
        $usages = $objects | Where-Object { ($_.Delete -NE "true") -and ($_.MasterPassName -notlike $null) } | Select-Object $usageObjectProperties
 
        #if there are usages/dependencies, export them to a new CSV
        if ($usages) {
            Write-LogMessage -type Debug -MSG "Usagaged Found" 
 
            #add properties to usages object
            $usages | Add-Member -MemberType NoteProperty -Name "platformType" -Value $null
            $usages | Add-Member -MemberType NoteProperty -Name "domain" -Value $null
            $usages | Add-Member -MemberType NoteProperty -Name "DependencyName" -Value $null
            $usages | Add-Member -MemberType NoteProperty -Name "dependencyAddress" -Value $null
            $usages | Add-Member -MemberType NoteProperty -Name "dependencyType" -Value $null
 
            foreach ($usage in $usages) {
                #if the usage has TaskName then the dependencyType is Windows Scheduled Task
                if ($usage.TaskName) {
                    $usage.dependencyType = "Windows Scheduled Task"
                    $usage.name = $usage.TaskName
                }
 
                #if the usage has AppPoolName then the dependencyType is IIS Application Pool
                if ($usage.AppPoolName) {
                    $usage.dependencyType = "IIS Application Pool"
                    $usage.name = $usage.AppPoolName
                }
 
                #if the usage has ServiceName then the dependencyType is Windows Service
                if ($usage.ServiceName) {
                    $usage.dependencyType = "Windows Service"
                    $usage.name = $usage.ServiceName
                }
 
                #if the usage has XMLElement then the dependencyType is XMLFile
                #not yet supported by DependentAccountOnbordUtility :(
                if ($usage.XMLElement) {
                    $usage.dependencyType = "XMLFile"
                    $usage.name = $usage.FilePath
                }
 
                #if the usage has INIParameterName then the dependencyType is INIFile
                #not yet supported by DependentAccountOnbordUtility :(
                if ($usage.INIParameterName) {
                    $usage.dependencyType = "INIFile"
                    $usage.name = $usage.FilePath
                }
 
                #if the usage has RegistryPathName then the dependencyType is Registry 
                #not yet supported by DependentAccountOnbordUtility :(
                if ($usage.RegistryPathName) {
                    $usage.dependencyType = "Registry"
                    $usage.name = $usage.RegistryPathName
                }
 
                $usage.dependencyName = $usage.name
                $usage.dependencyAddress = $usage.Address
 
                #set usage domain as the domain name of the master account if it's a domain account
                $usage.domain = ($objects | Where-Object { $_.name -eq $usage.masterpassname }).address
 
                #set the usage's username to the master account username
                $usage.username = ($objects | Where-Object { $_.name -eq $usage.masterpassname }).username
 
                #the usage's address must be set to the master account's address
                $usage.address = ($objects | Where-Object { $_.name -eq $usage.masterpassname }).address
 
                #there is nowhere to derive this informaiton
                $usage.platformType = "<REPLACE>"
                Write-LogMessage -type LogOnly -MSG "You must manually populate PlatformType for $($usage.name) with one of the following:"
                Write-LogMessage -type LogOnly -MSG "Windows Server Local, Windows Desktop Local, Windows Domain, Unix, Unix SSH Key, AWS, AWS Access Keys"
            }
 
            #export usage objects to a new csv
            $usages | Export-Csv "$($destinationFile.replace(".csv","_Usages.csv"))" -NoTypeInformation
            Write-LogMessage -type Info -MSG "Usages/Dependancies file written to $($destinationFile.replace(".csv","_Usages.csv"))"
            Write-LogMessage -type Warning -MSG "NOTE: Because Dependencies were identified, you must manually populate PlatformType for each object. See log for more information" 
        }
 
 
    }
    End {
    }
}
 
function Update-ObjectsSafePlatforms {
    <#
 .SYNOPSIS
 Updates object file formatted for the account onboarding utiltiy with new safe and platform names.
 
 .DESCRIPTION
 The utiltity will update the objects.csv file that has already been formatted
 for the CyberArk Github Repository Account Onboard Utiltiy script. The utiltiy
 takes in two csv-formatted transform files. One for platforms to update and one for safes to update. 
 Each CSV file will contain a column for oldsafename/oldplatformname and newsafename/newplatformname.
 
 The Utility will remove any object with that has well-known safes assigned. i.e:
 "PasswordManager","NotificationEngine","VaultInternal","AccountsFeedADAccounts","PSM","PVWA","System"
 
 SafeTransform.csv Example
 
 oldsafename,newsafename
 Safe1,Safe1_new
 safe2,Safe2_new
 
 platformTransform.csv Example
 
 oldplatformname,newplatformname
 WinDomain,WinDomain_new
 UnixSSH,UnixSSH2
 
 
 .EXAMPLE
 Update-ObjectsSafePlatforms -platformTransformFile C:\Scratch\VEM\PlatformName_Transformation.csv -safeTransformFile C:\Scratch\vem\SafeName_Transformation.csv -objectsFile C:\Scratch\vem\ObjectsForImport.csv -destinationFile C:\Scratch\vem\Updated_ObjectsForImport.csv
 
 #>
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $false,
            HelpMessage = "CSV file with old platform names and new platform names",
            Position = 0)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        [string]$platformTransformFile,
        [Parameter(Mandatory = $false,
            HelpMessage = "CSV file with old safe names and new safe names",
            Position = 1)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        [string]$safeTransformFile,
        [Parameter(Mandatory = $true,
            HelpMessage = "Objects file formatted for import using account onboard utility from github",
            Position = 1)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        [string]$objectsFile,
        [Parameter(Mandatory = $true,
            HelpMessage = "Objects file formatted for import using account onboard utility from github",
            Position = 1)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        [string]$destinationFile = "$env:TEMP\UpdatedObjects.csv"
    )
 
    BEGIN {
        #BEGIN - Execute only once when calling the function when passing in an array
 
        #Decare variables used by the call to the REST API
        if ($platformTransformFile) {
            $platformTransform = Import-Csv $PlatformTransformFile
            $transformPlatforms = $true
        }
        if ($safeTransformFile) {
            $safeTransform = Import-Csv $SafeTransformFile
            $transformSafes = $true
        }
 
        #Add delete property to objects file
        $objects = Import-Csv $objectsFile
        $objects | Add-Member -MemberType NoteProperty -Name Delete -Value $false -Force
 
    }
 
    #PROCESS -Always execute upon every call to the function when passing in an array trhough the pipeline
    PROCESS {
 
 
        #attempt to login with the username and password provided
        foreach ($object in $objects) {
 
            if ($transformPlatforms) {
                if ($PlatformTransform.OldPlatformName -eq $object.PlatformID) {
                    #update platform for the object
 
                    $newPlatformName = ($platformTransform | Where-Object oldplatformName -EQ $object.PlatformID | Select-Object newPlatformName).NewPlatformName
 
                    Write-Log -message "Replacing $($object.UserName)'s current platform, $($object.PlatformID) with $($newPlatformName)." 
                    #$object.PlatformID -eq $PlatformTransform.newplatformname
 
                    $object.PlatformID = $newPlatformName
 
                }
            }
 
            if ($transformSafes) {
 
                if ($SafeTransform.OldSafeName -eq $object.Safe) {
                    #update safe for the object
                    $newSafeName = ($safeTransform | Where-Object oldSafeName -EQ $object.Safe | Select-Object newSafeName).newSafeName
 
                    Write-log -message "Replacing $($object.UserName)'s current safe, $($object.safe) with $newSafeName."
                    #$object.PlatformID -eq $PlatformTransform.newplatformname
 
                    $object.Safe = $newSafeName
 
                }
 
                #update object's for ExtraPass1Safe
                if ($safeTransform.OldSafeName -eq $object.ExtraPass1Safe) {
                    $newSafeName = ($safeTransform | Where-Object oldSafeName -EQ $object.ExtraPass1Safe | Select-Object newSafeName).newSafeName
 
                    Write-log -message "Replacing $($object.UserName)'s current ExtraPass1Safe property, $($object.ExtraPass1Safe) with $newSafeName."
 
                    #Update linked account's safe names
                    $object.ExtraPass1Safe = $newSafeName 
                }
 
                #update object's ExtraPass2Safe
                if ($safeTransform.OldSafeName -eq $object.ExtraPass2Safe) {
                    $newSafeName = ($safeTransform | Where-Object oldSafeName -EQ $object.ExtraPass2Safe | Select-Object newSafeName).newSafeName
 
                    Write-log -message "Replacing $($object.UserName)'s current ExtraPass2Safe property, $($object.ExtraPass2Safe) with $newSafeName."
 
                    #Update linked account's safe names
                    $object.ExtraPass2Safe = $newSafeName 
                }
 
                #update object's for ExtraPass3Safe
                if ($safeTransform.OldSafeName -eq $object.ExtraPass3Safe) {
                    $newSafeName = ($safeTransform | Where-Object oldSafeName -EQ $object.ExtraPass3Safe | Select-Object newSafeName).newSafeName
 
                    Write-log -message "Replacing $($object.UserName)'s current ExtraPass3Safe property, $($object.ExtraPass3Safe) with $newSafeName."
 
                    #Update linked account's safe names
                    $object.ExtraPass3Safe = $newSafeName 
                }
            }
        }
 
        $objects | Select-Object -Property * | Export-Csv -Path $destinationFile -Force
        Write-Host "New object file written to $destinationFile" -ForegroundColor Green
 
    }
 
    END {
 
    }
}
 
function Update-SafeNames {
    <#
 .SYNOPSIS
 Updates object file formatted for the account onboarding utiltiy with new safe and platform names.
 
 .DESCRIPTION
 The utiltity will update the safemanagement.csv file that has already been formatted
 for the CyberArk Github Repository Safe-Management script. The utiltiy
 takes in a csv-formatted transform file to update safe names. 
 The CSV file will contain a column oldsafename and newsafename.
 
 
 SafeTransform.csv Example
 
 oldsafename,newsafename
 Safe1,Safe1_new
 safe2,Safe2_new
 
 
 .EXAMPLE
 Update-SafeNames -safeTransformFile C:\scratch\SafeManagement\SafeTransform.csv -safeManagementFile C:\Scratch\SafeManagement\safes-sampleTest.csv -destinationFile C:\Scratch\SafeManagement\SafesUpdated.csv
 
 #>
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $false,
            HelpMessage = "CSV file with old safe names and new safe names",
            Position = 1)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        [string]$safeTransformFile,
        [Parameter(Mandatory = $true,
            HelpMessage = "Safe Management CSV formatted for import using safe-management utility from github",
            Position = 1)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        [string]$safeManagementFile,
        [Parameter(Mandatory = $true,
            HelpMessage = "Path for the new file",
            Position = 1)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        [string]$destinationFile = "$env:TEMP\UpdatedSafeManagement.csv"
    )
 
    BEGIN {
        #BEGIN - Execute only once when calling the function when passing in an array
 
        #Decare variables used by the call to the REST API
 
        $safeTransform = Import-Csv $SafeTransformFile
 
 
        #Add delete property to objects file
        $safes = Import-Csv $safeManagementFile
        $safes | Add-Member -MemberType NoteProperty -Name Delete -Value $false -Force
 
    }
 
    #PROCESS -Always execute upon every call to the function when passing in an array trhough the pipeline
    PROCESS {
 
 
        #for each safe in the safe management file
        foreach ($safe in $safes) {
 
            if ($SafeTransform.OldSafeName -eq $safe.SafeName) {
                #update safe for the object
                $newSafeName = ($safeTransform | Where-Object oldSafeName -EQ $safe.SafeName | Select-Object newSafeName).newSafeName
 
                Write-log -message "Replacing $($safe.SafeName) with $newSafeName."
 
                $safe.SafeName = $newSafeName
 
            }
        }
        $safes | Select-Object -Property * | Export-Csv -Path $destinationFile -Force
        Write-Host "New object file written to $destinationFile" -ForegroundColor Green
 
    }
 
    END {
 
    }
}
 
function Update-LDAPUserNames {
    <#
 .SYNOPSIS
 Updates ldap users to use UPN if needed based on a CSV for transforming certain users or by parameter to update all
 
 .DESCRIPTION
 replaces usernames with new usernames based on a transform CSV. This can be used to change names from UPN to SAMAccountName or from SAMAccoutnName to UPN.
 
 LDAPUserNameTrasform.csv Example
 
 oldusername,newusername
 jsmith,jsmith@domain.com
 spotter,spotter@anotherdomain.com
 
 .EXAMPLE
 Update-LDAPUserNames -LDAPUserTransformFile C:\Scratch\LDAPUserNameTransformFile.csv -safeManagementFile C:\Scratch\SafeManagement\safeManagement.csv -destinationFile C:\Scratch\SafeManagement\UpdatedSafeManagement_LDAPUsersTransformed.csv
 
 
 #>
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $false,
            HelpMessage = "CSV file with old usernames and new usernames",
            Position = 1)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        [string]$LDAPUserNameTransformFile,
        [Parameter(Mandatory = $true,
            HelpMessage = "Safe Management CSV formatted for import using safe-management utility from github",
            Position = 1)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        [string]$safeManagementFile,
        [Parameter(Mandatory = $false,
            HelpMessage = "Path for the new file",
            Position = 1)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf -IsValid })]
        [ValidatePattern('\.csv$')]
        [string]$destinationFile = "$env:TEMP\UpdatedSafeManagement_LDAPUsersTransformed.csv"
    )
 
    BEGIN {
        #BEGIN - Execute only once when calling the function when passing in an array
 
        #Decare variables used by the call to the REST API
        $LDAPUserNameTransform = Import-Csv $LDAPUserNameTransformFile
        $safes = Import-Csv $safeManagementFile
    }
 
    #PROCESS -Always execute upon every call to the function when passing in an array trhough the pipeline
    PROCESS {
 
        #for each safe in the safe management file
        foreach ($safe in $safes) {
 
            #if the safe member is in the transform file
            if (($LDAPUserNameTransform.oldusername -eq $safe.member) -and ($safe.memberlocation -ne "vault")) {
 
                #determine what the new username should be
                $newUserName = ($LDAPUserNameTransform | Where-Object oldusername -EQ $safe.member | Select-Object newUsername).newUserName
 
                Write-log -message "Replacing $($safe.member) with $newUserName."
 
                #replace the username with the new username
                $safe.member = $newUserName
            }
        }
        $safes | Select-Object -Property * | Export-Csv -Path $destinationFile -Force
        Write-Host "New safe management file written to $destinationFile" -ForegroundColor Green
 
    }
 
    END {
 
    }
}
 
Function Write-Log {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true,
            Position = 0)]
        [string]$message,
        [Parameter(Mandatory = $false)]
        [ValidateSet("ERR", "WARN", "INFO")]
        [string]$logLevel = "INFO"
    )
 
    BEGIN {
        if (!$logfile) {
            $global:logfile = "$env:temp\PoShLog-$((Get-Date).tostring("yyyy-MM-dd-HHmmss")).log"
            Write-Verbose -Message "Writing log to $logfile"
            New-Item -Path $logfile -ItemType File | Out-Null
        }
    }
 
    PROCESS {
        $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
        $Line = "$Stamp [$logLevel] $message"
        Add-Content -Path $logFile -Value $Line -Force
        Write-Verbose $Line
    }
    END {
 
    }
}
 
 
<#PSScriptInfo
 
 .VERSION 1.0
 
 .GUID 0fc1a85e-4568-40d0-9086-ad3dc9109c18
 
 .AUTHOR Brian Bors
 
 .DESCRIPTION Logging The input Message to the Screen and the Log File. The Message Type is presented in colours on the screen based on the type
 
 .PARAMETER LogFile
 The Log File to write to. By default using the LOG_FILE_PATH
 .PARAMETER MSG
 The message to log
 .PARAMETER Header
 Adding a header line before the message
 .PARAMETER SubHeader
 Adding a Sub header line before the message
 .PARAMETER Footer
 Adding a footer line after the message
 .PARAMETER Type
 The type of the message to log (Info, Warning, Error, Debug)
 #>
 
Function Write-LogMessage {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [Switch]$Header,
        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory = $false)]
        [Switch]$Footer,
        [Parameter(Mandatory = $false)]
        [Bool]$WriteLog = $true,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Debug", "Verbose", "Success", "LogOnly")]
        [String]$type = "Info",
        [Parameter(Mandatory = $false)]
        [String]$LogFile = $LOG_FILE_PATH
    )
 
    $private:WriteToHost = $true
    If ($Global:LogOnly -or $Script:LogOnly) {
        $private:WriteToHost = $false
    }
 
    If (![string]::IsNullOrEmpty($PSSenderInfo)) {
        $WriteLog = $false
    }
    Try {
        If ([string]::IsNullOrEmpty($LogFile) -and $WriteLog) {
            # User wanted to write logs, but did not provide a log file - Create a temporary file
            $LogFile = Join-Path -Path $ENV:Temp -ChildPath "$((Get-Date).ToShortDateString().Replace('/','_')).log"
            if ($WriteToHost) {
                Write-Host "No log file path inputted, created a temporary file at: '$LogFile'"
            }
        }
        If ($Header -and $WriteLog) {
            "=======================================" | Out-File -Append -FilePath $LogFile 
            if ($WriteToHost) {
                Write-Host "=======================================" -ForegroundColor Magenta
            }
        } ElseIf ($SubHeader -and $WriteLog) { 
            "------------------------------------" | Out-File -Append -FilePath $LogFile 
            if ($WriteToHost) {
                Write-Host "------------------------------------" -ForegroundColor Magenta
            }
        }
 
        # Replace empty message with 'N/A'
        if ([string]::IsNullOrEmpty($Msg)) {
            $Msg = "N/A" 
        }
        $msgToWrite = ""
 
        # Mask Passwords
        if ($Msg -match ',"Use password":' -or $MSG -match '; Use password=') {
            #"Password" found, however it is being used as a permissions and is safe to display 
        } elseif ($Msg -match '((?:password|credentials|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()-_\=\+\\\/|;:\.,\[\]{}]+))') {
            $Msg = $Msg.Replace($Matches[2], "****")
        }
        # Check the message type
        switch ($type) {
            { ($_ -eq "Info") -or ($_ -eq "LogOnly") } { 
                If ($_ -eq "Info") {
                    if ($WriteToHost) {
                        Write-Host $MSG.ToString() -ForegroundColor $(If ($Header -or $SubHeader) {
                                "Magenta" 
                            } Else {
                                "Gray" 
                            })
                    }
                }
                $msgToWrite = "[INFO]`t$Msg"
                break
            }
            "Success" { 
                if ($WriteToHost) {
                    Write-Host $MSG.ToString() -ForegroundColor Green
                }
                $msgToWrite = "[SUCCESS]`t$Msg"
                break
            }
            "Warning" {
                if ($WriteToHost) {
                    Write-Host $MSG.ToString() -ForegroundColor Yellow
                }$msgToWrite = "[WARNING]`t$Msg"
                break
            }
            "Error" {
                if ($WriteToHost) {
                    Write-Host $MSG.ToString() -ForegroundColor Red
                }$msgToWrite = "[ERROR]`t$Msg"
                break
            }
            "Debug" { 
                if ($InDebug -or $InVerbose) {
                    if ($WriteToHost) {
                        Write-Debug $MSG
                    }
                    $msgToWrite = "[Debug]`t$Msg"
                }
                break
            }
            "Verbose" { 
                if ($InVerbose) {
                    if ($WriteToHost) {
                        Write-Verbose $MSG
                    }
                    $msgToWrite = "[VERBOSE]`t$Msg"
                }
                break
            }
        }
        if (!$InVerbose) {
            if ($LogVerbose) {
                $msgToWrite = "[LOGVERBOSE]`t$Msg"
            }
        }
        If ($WriteLog) { 
            If (![string]::IsNullOrEmpty($msgToWrite)) {				
                "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t$($msgToWrite.Trim())" | Out-File -Append -FilePath $LogFile
            }
        }
        If ($Footer -and $WriteLog) { 
            "=======================================" | Out-File -Append -FilePath $LogFile 
            if ($WriteToHost) {
                Write-Host "=======================================" -ForegroundColor Magenta
            }
        }
    } catch {
        Throw $(New-Object System.Exception ("Cannot write message"), $_.Exception)
    }
}
