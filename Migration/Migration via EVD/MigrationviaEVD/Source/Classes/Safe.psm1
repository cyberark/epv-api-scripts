using Module .\Logging.psm1
using Module .\PASBase.psm1
using Module .\PASObject.psm1
using Module .\SafeMember.psm1


[NoRunspaceAffinity()]
#TODO Create Format File
#https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_format.ps1xml
Class Safe : PASObject {
    [string]$safeUrlId
    [string]$safeName
    [int32]$safeNumber
    [string]$description
    [string]$location
    [IDName]$creator
    [bool]$OLACEnabled
    [string]$ManagingCPM
    [Int32]$NumberOfVersionsRetention
    [Int32]$NumberOfDaysRetention
    [bool]$AutoPurgeEnabled
    hidden [string]$_creationTime
    [datetime]$creationTime
    hidden [string]$_lastModificationTime
    [datetime]$lastModificationTime
    [bool]$isExpiredMember
    [IDName[]]$accounts
    [SafeMember[]]$members
    hidden [string[]]$Jsonprops = @("creationTime", "lastModificationTime", "safeUrlId", "safeName", "safeNumber", "description", "location", "creator", "OLACEnabled", "ManagingCPM", "NumberOfVersionsRetention", "NumberOfDaysRetention", "AutoPurgeEnabled", "isExpiredMember")
    hidden [string[]]$JsonExtra = @("Accounts", "Members")
    #Region Init
    Safe() {
        $this.Init(@{}) 
    }
    Safe([pscustomobject]$Properties) { 
        $this.Init($Properties) 
    }

    [string] ToJson() {
        return $This.ToJson($false)
    }

    [string] ToJson([bool]$Extra = $false) {
        if ($Extra) {
            $propList = $this.JsonProps + $this.JsonExtra
            return  $($This | Select-Object -Property $PSItem.PSobject.Properties.name | Select-Object -Property $propList | ConvertTo-Json -Depth 3 )
        }
        else {
            return  $($This | Select-Object -Property $PSItem.PSobject.Properties.name | Select-Object -Property $This.Jsonprops | ConvertTo-Json -Depth 3 )
        }
    }

    hidden [void] Init([pscustomobject]$PSCustom) {
        $This.WriteVerbose("Creating $($This.GetType()) object: Init Override")
        $this.NewSetGet()
        $This.SetValues($PSCustom)
        $This.WriteVerbose("Succesfully created $($This.GetType()) object: Init Override")
    }

    hidden [void] NewSetGet() {
        [datetime]$This._creationTime = [datetime]$($this | Add-Member -Force ScriptProperty 'creationTime' `
            {
                # get
                $([datetime]$this._creationTime)
            }`
            {
                # set
                param ( $arg )
                [datetime]$this._creationTime = [datetime]$This.GetDateTimeFromEpoch($arg)
            }
        )
        [datetime]$This._lastModificationTime = [datetime]$($this | Add-Member -Force ScriptProperty 'lastModificationTime' `
            {
                # get
                $([datetime]$this._lastModificationTime)
            }`
            {
                # set
                param ( $arg )
                [datetime]$this._lastModificationTime = $(if (![string]::IsNullOrEmpty($arg)) {
                        if (10 -le $($arg.ToString().Length)) { 
                            [datetime]$This.GetDateTimeFromEpoch($arg.toString().Substring(0, 10)) 
                        }
                        Else { 
                            [datetime]$This.GetDateTimeFromEpoch($arg) 
                        }
                    }
                )
            }
        ) 
    }
    #endregion

    #Region Local Commands
    #Region Safe Commands
    [PSCustomObject] Get([string]$SafeUrlId, [bool]$includeAccounts, [bool]$useCache) {
        $This.WriteDebug('Get($SafeUrlId,$includeAccounts,$useCache)')
        $base = "$([Safe]::URL_Base)/API/Safes/$SafeUrlId/"
        [string]$add = "?"
        If ($includeAccounts) {
            $add = "$($add)includeAccounts=true&"
        }
        If ($useCache) {
            $add = "$($add)useCache=true&"
        }
        If ("?" -ne $add) {
            $base = "$($Base)$($add)"
        }
        $This.WriteDebug("Base = $base")
        [pscustomobject]$safeResult = $($This.InvokeGet([string]$base))
#        [pscustomobject]$safeResult2 = $($(New-Object -TypeName PASMigrate).InvokeGet("$($(New-Object -TypeName PASMigrate)::URL_Base)/API/Safes/$SafeUrlId/"))
        $This.SetValues($safeResult)
        return $this 
    }
    [PSCustomObject] Get([string]$SafeUrlId, [bool]$includeAccounts) {
        $This.WriteDebug('Get($SafeUrlId,$includeAccounts)')
        return $This.get($SafeUrlId, $includeAccounts, $false)
    }
    [PSCustomObject] Get([string]$SafeUrlId) {
        $This.WriteDebug('Get($safeName)')
        return $This.get($SafeUrlId, $false)
    }
    [PSCustomObject] Get() {
        $This.WriteDebug('Get($safeName)')
        return $This.get($This.SafeUrlId, $false)
    }

    [safe] Add() {
        $uri = "$([Safe]::URL_Base)/API/Safes/"
        if (![string]::IsNullOrEmpty($This.numberOfVersionsRetention)) {
            $body = $this | Select-Object -Property safeName, location, OLACEnabled, description, ManagingCPM, numberOfVersionsRetention
        }
        else {
            $body = $this | Select-Object -Property safeName, location, OLACEnabled, description, ManagingCPM, NumberOfDaysRetention
        }
        Try {
            $restResult = $This.InvokePost($uri, $($body | ConvertTo-Json))
            $This.SetValues($restResult)
            $This.WriteInfo("Safe named `"$($this.safeName)`" added succsfully")
            Return $this 
        }
        Catch { 
            if (("SFWS0002" -eq ($PSitem | ConvertFrom-Json).ErrorCode) -and ([pasobject]::UpdateOnAdd)) {
                Try {
                    $This.WriteInfo("Safe named `"$($this.safeName)`" already exists, attempting to update")
                    $uri = "$([Safe]::URL_Base)/API/Safes/$($This.safeUrlId)/"
                    $restResult = $This.InvokePut($uri, $($body | ConvertTo-Json))
                    $This.SetValues($restResult)
                    $This.WriteInfo("Safe named `"$($this.safeName)`" updated succsfully")
                    return $this  
                }
                Catch {
                    $This.WriteError($PSItem)
                    return $null
                }
            }
            else {
            
                $This.WriteError($PSItem)
                return $null
            }
        }
    }

    [safe] Update() {
        $uri = "$([Safe]::URL_Base)/API/Safes/$($This.safeUrlId)/"
        if (![string]::IsNullOrEmpty($This.numberOfVersionsRetention)) {
            $body = $this | Select-Object -Property safeName, location, OLACEnabled, description, ManagingCPM, numberOfVersionsRetention
        }
        else {
            $body = $this | Select-Object -Property safeName, location, OLACEnabled, description, ManagingCPM, NumberOfDaysRetention
        }
        Try {
            $restResult = $This.InvokePut($uri, $($body | ConvertTo-Json))
            $This.SetValues($restResult)
            $This.WriteInfo("Safe named `"$($this.safeName)`" updated succsfully")
            return $this        
        }
        Catch { 
            if (("SFWS0007" -eq ($PSitem | ConvertFrom-Json).ErrorCode) -and ([pasobject]::AddOnUpdate)) {
                Try {
                    $This.WriteInfo("Safe named `"$($this.safeName)`" does not exist, attempting to Add")
                    $uri = "$([Safe]::URL_Base)/API/Safes/"
                    $restResult = $This.InvokePost($uri, $($body | ConvertTo-Json))
                    $This.SetValues($restResult)
                    $This.WriteInfo("Safe named `"$($this.safeName)`" added succsfully")
                    return $this  
                }
                Catch {
                    $This.WriteError($PSItem)
                    return $null
                }
            }
            else {
            
                $This.WriteError($PSItem)
                return $null
            }
        }
    }
    [void] Delete() {
        $uri = "$([Safe]::URL_Base)/API/Safes/$($This.safeUrlId)/"
        Try {
            $This.InvokeDelete($uri)
            $This.WriteInfo("Safe named `"$($this.safeName)`" deleted succsfully")
        }
        Catch {
            $This.WriteError($PSItem)
        }
    }
    #endregion Safe Commands
    
    #region Safe Member Commands
    [PSCustomObject] GetMembers() {
        $This.WriteDebug('GetMembers()')
        return $This.GetMember("")
    }
    [PSCustomObject] GetMember([string]$memberName) {
        $This.WriteDebug('GetMember($memberNam)')
        If ([string]::IsNullOrEmpty($memberName)) {
            $memberURL = "$([Safe]::URL_Base)/API/Safes/$($This.SafeUrlId)/Members/"
        }
        else {
            $memberURL = "$([Safe]::URL_Base)/API/Safes/$($This.SafeUrlId)/Members/$memberName/"
        }
        [pscustomobject]$safeResult = $($This.InvokeGet([string]$memberURL))
        if ([string]::IsNullOrEmpty($safeResult)) {
            Return $null
        }
        elseIf (1 -eq $safeResult.Count ) {
            [pscustomobject[]]$memberList = $safeResult
        }
        else {
            [pscustomobject[]]$memberList = $safeResult.value
            
        }
        $memberList | ForEach-Object {
            if ($PSitem.MemberName -notIn $This.members.membername) {
                $this.members += $PSitem
            }
        }
        return $memberList
    }

    #endregion Safe Member Commands
    #endregion Local Commands
    #region Migration commands

    [safe] MigrateAdd() {
        $uri = "$($(New-Object -TypeName PASMigrate)::URL_Base)/API/Safes/"
        if (![string]::IsNullOrEmpty($This.numberOfVersionsRetention)) {
            $body = $this | Select-Object -Property safeName, location, OLACEnabled, description, ManagingCPM, numberOfVersionsRetention
        }
        else {
            $body = $this | Select-Object -Property safeName, location, OLACEnabled, description, ManagingCPM, NumberOfDaysRetention
        }
        Try {
            $restResult = $(New-Object -TypeName PASMigrate).InvokePost($uri, $($body | ConvertTo-Json))
            $This.SetValues($restResult)
            $This.WriteInfo("Safe named `"$($this.safeName)`" added succsfully to target enviorment")
            Return $this 
        }
        Catch {
            $This.WriteError($PSItem)
            return $null
        }
    }
    [safe] MigrateUpdate() {
        $uri = "$($(New-Object -TypeName PASMigrate)::URL_Base)/API/Safes/$($This.safeUrlId)/"
        if (![string]::IsNullOrEmpty($This.numberOfVersionsRetention)) {
            $body = $this | Select-Object -Property safeName, location, OLACEnabled, description, ManagingCPM, numberOfVersionsRetention
        }
        else {
            $body = $this | Select-Object -Property safeName, location, OLACEnabled, description, ManagingCPM, NumberOfDaysRetention
        }
        Try {
            $restResult = $This.InvokePut($uri, $($body | ConvertTo-Json))
            $This.SetValues($restResult)
            $This.WriteInfo("Safe named `"$($this.safeName)`" updated succsfully in target enviorment")
            return $this        
        }
        Catch {
            $This.WriteError($PSItem)
            return $null
        }
    }

    [PSCustomObject] MigrateGetMembers() {
        $This.WriteDebug('GetMembers()')
        return $This.MigrateGetMember("")
    }
    [PSCustomObject] MigrateGetMember([string]$memberName) {
        $This.WriteDebug('GetMember($memberNam)')
        If ([string]::IsNullOrEmpty($memberName)) {
            $memberURL = "$($(New-Object -TypeName PASMigrate)::URL_Base)/API/Safes/$($This.SafeUrlId)/Members/"
        }
        else {
            $memberURL = "$($(New-Object -TypeName PASMigrate)::URL_Base)/API/Safes/$($This.SafeUrlId)/Members/$memberName/"
        }
        [pscustomobject]$safeResult = $($(New-Object -TypeName PASMigrate).InvokeGet([string]$memberURL))
        if ([string]::IsNullOrEmpty($safeResult)) {
            Return $null
        }
        elseIf (1 -eq $safeResult.Count ) {
            [pscustomobject[]]$memberList = $safeResult
        }
        else {
            [pscustomobject[]]$memberList = $safeResult.value
            
        }
        $memberList | ForEach-Object {
            if ($PSitem.MemberName -notIn $This.members.membername) {
            }
        }
        return $memberList
    }
    #endregion Migration commands
}