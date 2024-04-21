$ImportRoot = '.\Import\'
$SafesImportFile = "$ImportRoot\SafesList.csv"
$ObjectsImportFile = "$ImportRoot\FileList.csv"
$PropertiesImportFile = "$ImportRoot\ObjectProperties.csv"
$PoliciesImportFile = "$ImportRoot\Policies.xml"

$ExportRoot = '.\Export\'
$SafeNamesExportFile = "$ExportRoot\SafeNames.csv"
$AccountsListExportFile = "$ExportRoot\AccountsList.csv"
$InUsePropExportFile = "$ExportRoot\InUseProperties.csv"
$InUsePropUniqueExportFile = "$ExportRoot\InUsePropUnique.csv"
$AccountsExportFile = "$ExportRoot\Accounts.csv"
$LinksExportFile = "$ExportRoot\Links.csv"


$PSStyle.Progress.View = 'Classic'
$progressUpdates = 10000
$timerStart = Get-Date

([wmi]"win32_process.handle=`"$PID`"").setPriority(128) | Out-Null

Write-Host "Started at $($timerStart)" -ForegroundColor Cyan
Write-Host 'Creating list of safes to remove'

[String[]]$objectSafesToRemove = @('System', 'Pictures', 'VaultInternal', 'Notification Engine', 'SharedAuth_Internal', 'PVWAUserPrefs',
    'PVWAConfig', 'PVWAReports', 'PVWATaskDefinitions', 'PVWAPrivateUserPrefs', 'PVWAPublicData', 'PVWATicketingSystem',
    'AccountsFeed', 'PSM', 'xRay', 'PIMSuRecordings', 'xRay_Config', 'AccountsFeedADAccounts', 'AccountsFeedDiscoveryLogs', 'PSMSessions', 'PSMLiveSessions', 'PSMUniversalConnectors',
    'PSMNotifications', 'PSMUnmanagedSessionAccounts', 'PSMRecordings', 'PSMPADBridgeConf', 'PSMPADBUserProfile', 'PSMPADBridgeCustom', 'PSMPConf', 'PSMPLiveSessions'
    'AppProviderConf', 'PasswordManagerTemp', 'PasswordManager_Pending', 'PasswordManagerShared', 'SCIM Config', 'TelemetryConfig')

[string[]]$cpmUsers = @('PasswordManager', 'PasswordManagerCP')
1..20 | ForEach-Object { $cpmUsers += "PasswordManager$($PSitem)" }
[string[]]$cpmSafes = @()
$cpmUsers | ForEach-Object {
    $cpmSafes += "$($PSitem)"
    $cpmSafes += "$($PSitem)_Accounts"
    $cpmSafes += "$($PSitem)_ADInternal"
    $cpmSafes += "$($PSitem)_Info"
    $cpmSafes += "$($PSitem)_workspace"
}

$SafesToRemove = $cpmSafes
$cpmSafes = $null
$SafesToRemove += $objectSafesToRemove
$objectSafesToRemove = $null

Write-Host "A total of $($SafesToRemove.Count.ToString('N0')) safes to remove"

Write-Host "Completed work with safes to remove at $(Get-Date), starting work on safe import" -ForegroundColor Cyan

[string[]]$extraSafesToRemove = @('PSM-PIDMSCCWPRPSM01', 'PSM-RecordingsDWS1', 'PSM-RecordingsLIN', 'PSM-RecordingsLIN4', 'PSM-RecordingsLINUX', 
    'PSM-RecordingsWIN', 'PSM-RecordingsWIN2', 'PSM-RecordingsWIN4', 'PSM-RecordingsWIN6', 'PSMLiveSessions_old', 'PSMRecordings_ADWIN', 
    'PSMRecordingsENCASE', 'PSMRecordingsENCASE1', 'PSMRecordingsLIN', 'PSMRecordingsLIN4', 'PSMrecordingsSCC', 'PSMRecordingsWIN', 'PSMRecordingsWIN4', 
    'PSMRecordingsWIN6', 'PSMSessions_OLD', 'PSMSessions_OLD', 'PSMUnmanagedSessionA-OLD', 'CyberarkLOGS', 'PSM_OlD')

$SafesToRemove += $extraSafesToRemove
$extraSafesToRemove = $null

$SafeFile = Import-Csv $SafesImportFile -Header SafeID, SafeName, LocationID, LocationName, Size, MaxSize, %UsedSize, LastUsed, VirusFree, TextOnly, AccessLocation, SecurityLevel, Delay, FromHour, ToHour, DailyVersions, MonthlyVersions, YearlyVersions, LogRetentionPeriod, ObjectsRetentionPeriod, RequestRetentionPeriod, ShareOptions, ConfirmersCount, ConfirmType, DefaultAccessMarks, DefaultFileCompression, DefaultReadOnly, QuotaOwner, UseFileCategories, RequireReasonToRetrieve, EnforceExlusivePasswords, RequireContentValidation, CreationDate, CreatedBy, NumberOfPasswordVersions
Write-Host "Imported $($SafeFile.Count.ToString('N0')) Safes"
$SafeNames = $SafeFile | Select-Object -Property SafeID, SafeName | Where-Object { $PSItem.SafeName -notIn $safesToRemove }
$SafeFile = $null
Write-Host "Afrer removing out of scope safes $($SafeNames.Count.ToString('N0')) remain"
[hashtable]$safeNamesHT = $null
[hashtable]$safeNamesHT = @{}
$null = $SafeNames | ForEach-Object {
    Try {
        $SafeNamesHT.Add($PSitem.SafeID, $PSItem.SafeName) 
    }
    catch {
        Write-Error "Error on $item"
        Write-Error $PSItem
    }
}
$SafeNames | Sort-Object -Property SafeName | Export-Csv $SafeNamesExportFile
$SafeNames = $null
$SafeFile = $null
Write-Host "Safename hashtable created with $($SafeNamesHT.Count.ToString('N0')) entries"
Write-Host "Completed work with safes at $(Get-Date), starting work on objects" -ForegroundColor Cyan

Write-Host 'Starting to import objects'
$AccountsFile = Import-Csv $ObjectsImportFile -Header SafeID, SafeName, Folder, FileID, FileName, InternalName, Size, CreatedBy, CreationDate, LastUsedBy, LastUsedDate, ModificationDate, ModifiedBy, DeletedBy, DeletionDate, LockDate, LockBy, LockedByUserID, Accessed, New, Retrieved, Modified, IsRequestNeeded, ValidationStatus, Type, CompressedSize, LastModifiedDate, LastModifiedBy, LastUsedByHuman, LastUsedHumanDate, LastUsedByComponent, LastUsedComponentDate
Write-Host "Imported $($AccountsFile.Count.ToString('N0')) objects"
$AccountsListTemp = $AccountsFile | Where-Object { '2' -eq $PSitem.Type } | Select-Object -Property SafeID, SafeName, FileID, FileName 
$AccountsList = $AccountsListTemp |  ForEach-Object { 
    If ($Null -ne $SafeNamesHT[$($PSitem.SafeID)]) {
        $PSitem
    }
}

$SafesToRemove = $Null
$AccountsFile = $null
Write-Host "Afrer removing out of scope safes and file type of file $($AccountsList.Count.ToString('N0')) password objects remain"
$AccountsList | Export-Csv $AccountsListExportFile

Write-Host "Completed work with objects at $(Get-Date), starting work on properties" -ForegroundColor Cyan

[string[]]$baseProps = @('PolicyID', 'DeviceType', 'CPMDisabled', 'CPMErrorDetails', 'CPMStatus', 'Description', 'LimitDomainAccess','AccountIDCode')
[string[]]$ExtraProps = @('ExtraPass1Safe', 'ExtraPass1Folder', 'ExtraPass1Name', 'ExtraPass2Safe', 'ExtraPass2Folder', 'ExtraPass2Name', 'ExtraPass3Safe', 'ExtraPass3Folder', 'ExtraPass3Name')
[xml]$xml = Get-Content $PoliciesImportFile
$Nodes = $xml.SelectNodes('//Property')
[string[]]$InUseProps = $nodes.Name | Select-Object -Unique -CaseInsensitive | Sort-Object
Write-Host "Completed work with $($(Get-Item $PoliciesImportFile).name) at $(Get-Date), starting work on object properties"

$InUseProps += $baseProps
$baseProps = $null
$InUseProps += $ExtraProps
$ExtraProps = $null
Write-Host "Found a total of $($InUseProps.Count.ToString('N0')) in scoppe unique properties"

Write-Host 'Starting import of objects properties'
$ObjectFile = Import-Csv $PropertiesImportFile -Header ObjectPropertyId, ObjectPropertyName, SafeId, FileId, ObjectPropertyValue, Options
Write-Host "Imported $($ObjectFile.Count.ToString('N0')) object properties"
Write-Host "Import completed at $(Get-Date), dropping all properties in a out of scope safe"
$InUseProperties = $ObjectFile |  ForEach-Object { 
    If ($Null -ne $SafeNamesHT[$($PSitem.SafeID)]) {
        $PSitem
    }
}
$ObjectFile = $null
Write-Host "After removing object propterties in out of scope safes $($InUseProperties.Count.ToString('N0')) password object properties remain"
$InUseProperties | Export-Csv $InUsePropExportFile
Write-Host "Export completed of all properties at $(Get-Date), exporting list of unique property types"
[PSCustomObject]$InUseUniqueProperties = $InUseProperties.ObjectPropertyName | Select-Object -Unique 

$InUseUniquePropertiesList = $InUseUniqueProperties | ForEach-Object { iF ($PSItem -in $InUseProps) {
        $PSItem
    }
}
$InUseUniqueProperties = $null
'Property' | Out-File $InUsePropUniqueExportFile
$InUseUniquePropertiesList | Out-File -Append $InUsePropUniqueExportFile
Write-Host "A total of $($InUseUniqueProperties.Count.ToString('N0')) unique object properties found"

Write-Host "Completed work with Properties at $(Get-Date), starting work on Accounts Hash Table" -ForegroundColor Cyan

[hashtable]$AccountsHT = $null
[hashtable]$AccountsHT = @{}
$total = $AccountsList.Count
$progressCount = 0
Write-Progress -Activity 'Populating Accounts Hash Table' -Status "0 out of $($total.ToString('N0')) entered" 
$null = $AccountsList | ForEach-Object {
    Try {
        $item = $PSItem
        $FileName = $PSitem.FileName
        $AccountID = "$($Item.SafeID)_$($Item.FileID)"
        [PSCustomObject]$AccountPropList = @('SafeName', $(@{Name = 'Name'; Expression = { $FileName } }),$(@{Name = 'AccountIDCode'; Expression = { $AccountID } }))
        $AccountPropList += [pscustomobject]$InUseUniquePropertiesList
        $AccountObject = $Item | Select-Object -Property $AccountPropList 
        $AccountsHT.Add($AccountID, $AccountObject)
        $AccountID = $null 
        $AccountObject = $null

        $progressCount += 1
        IF ($progressCount -gt $($progressUpdates - 1)) {
            $progressCount = 0
            $count = $accountsList.IndexOf($PSItem)      
            $progressParameters = @{
                Activity        = 'Populating Accounts Hash Table'
                Status          = "$($($count +1).ToString('N0')) out of $($total.ToString('N0')) entered" 
                PercentComplete = $($($count / $total) * 100)
            }
            Write-Progress @progressParameters
        }
    }
    Catch {
        Write-Error "Error on $item"
        Write-Error $PSItem
        #Wait-Debugger
    }
}
Write-Progress -Completed

$AccountsList = $null
Write-Host "Account hashtable created with $($AccountsHT.Count.ToString('N0')) entries"
Write-Host "Completed work with accounts hash table at $(Get-Date), adding properties to account hash table"

$total = $InUseProperties.Count
$progressCount = 0
Write-Progress -Activity 'Adding Accounts Properties' -Status "0 out of $($total.ToString('N0')) entered" 
Start-Sleep -Milliseconds 1
$null = $InUseProperties | ForEach-Object {
    Try {
        $item = $PSItem
        If ($item.ObjectPropertyName -in $InUseUniquePropertiesList ) {
            $AccountID = "$($Item.SafeID)_$($Item.FileID)"
            IF (!$([string]::IsNullOrEmpty($($item.ObjectPropertyValue)))) {
                $AccountsHT[$AccountID].$($item.ObjectPropertyName) = $($item.ObjectPropertyValue).ToString().replace("`n","")
            }    
        }
        $progressCount += 1
        IF ($progressCount -gt $($progressUpdates - 1)) {
            $progressCount = 0
            $count = $InUseProperties.IndexOf($PSItem)      
            $progressParameters = @{
                Activity        = 'Adding Accounts Properties'
                Status          = "$($($count +1).ToString('N0')) out of $($total.ToString('N0')) entered"  
                PercentComplete = $($($count / $total) * 100)
            }
            Write-Progress @progressParameters
        }
    }
    Catch {
        Write-Error "Error on $item"
        Write-Error $PSItem
        #Wait-Debugger
    }
}
Write-Progress -Completed
$InUseProperties = $null
$InUseUniquePropertiesList = $null
Write-Host "Completed work with accounts properties at $(Get-Date), Exporting Accounts to CSV" -ForegroundColor Cyan

Write-Host "Starting export of accounts to CSV at $(Get-Date)"
$Accounts = $AccountsHT.Values | Where-Object { $PSitem.PSObject.Properties -notmatch 'ExtraPass.*' } | Select-Object -ExcludeProperty @('ExtraPass1Safe', 'ExtraPass1Folder', 'ExtraPass1Name', 'ExtraPass2Safe', 'ExtraPass2Folder', 'ExtraPass2Name', 'ExtraPass3Safe', 'ExtraPass3Folder', 'ExtraPass3Name')
$Accounts | Export-Csv $AccountsExportFile
$Accounts = $null
Write-Host "Export of accounts to CSV completed at $(Get-Date)"

Write-Host "Starting to find account links at $(Get-Date), removing all extra fields"
$LinksPrep = $AccountsHT.Values | Where-Object { $PSitem.PSObject.Properties -match 'ExtraPass.*' } | Select-Object -Property @('SafeName', 'Name', 'Username', 'Address', 'ExtraPass1Safe', 'ExtraPass1Folder', 'ExtraPass1Name', 'ExtraPass2Safe', 'ExtraPass2Folder', 'ExtraPass2Name', 'ExtraPass3Safe', 'ExtraPass3Folder', 'ExtraPass3Name')
Write-Host "Completed removing all extra fields at $(Get-Date), find accounts with logon accounts"
$linkLogon = $LinksPrep | Where-Object { ($Null -ne $PSitem.ExtraPass1Safe) -or ($Null -ne $PSitem.ExtraPass1Folder) -or ($Null -ne $PSitem.ExtraPass1Name) }
Write-Host "Completed finding accounts with logon accounts at $(Get-Date) and found $($linkLogon.count.ToString('N0')) accounts, finding accounts with enable or other linked accounts"
$linkEnable = $LinksPrep | Where-Object { ($Null -ne $PSitem.ExtraPass2Safe) -or ($Null -ne $PSitem.ExtraPass2Folder) -or ($Null -ne $PSitem.ExtraPass2Name) }
Write-Host "Completed finding accounts with enable or other linked accounts at $(Get-Date) and found $($linkEnable.count.ToString('N0')) accounts, finding accounts with reconcile accounts"
$linkRecon = $LinksPrep | Where-Object { ($Null -ne $PSitem.ExtraPass3Safe) -or ($Null -ne $PSitem.ExtraPass3Folder) -or ($Null -ne $PSitem.ExtraPass3Name) }
Write-Host "Completed finding accounts with reconcile accounts at $(Get-Date) and found $($linkRecon.count.ToString('N0')) accounts, merging found accounts"
$LinksPrep = $null

$linksMerge += $linkLogon
$linksMerge += $linkEnable
$linksMerge += $linkRecon

Write-Host "Completed merging account lists at $(Get-Date) and found $($linksMerge.count.ToString('N0')) accounts, removing duplicate accounts"

$links = $linksMerge | Select-Object -Property * -Unique

Write-Host "Completed removing dupliate accounts at $(Get-Date) and found $($links.count.ToString('N0')) unique accounts"

Write-Host "Starting export of account links to CSV at $(Get-Date)"
$Links | Export-Csv $LinksExportFile
Write-Host "Export of account links to CSV completed at $(Get-Date)"

Write-Host "Completed export of accounts properties at $(Get-Date)."
$timerEnd = Get-Date
Write-Host "Completed $($timerEnd)" -ForegroundColor Cyan
New-TimeSpan -Start $timerStart -End $timerEnd
Write-Host "It took $($(New-TimeSpan -Start $timerStart -End $timerEnd).ToString('hh\:mm\:ss')) to complete processing"


[hashtable]$AccountsHT = $null
$Links = $null