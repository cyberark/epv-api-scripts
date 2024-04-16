using Module .\Logging.psm1
using Module .\PASBase.psm1
using Module .\PASObject.psm1


[NoRunspaceAffinity()]
Class SafeMembersPermissions : PASBase {
    [bool]$useAccounts
    [bool]$retrieveAccounts
    [bool]$listAccounts
    [bool]$addAccounts
    [bool]$updateAccountContent
    [bool]$updateAccountProperties
    [bool]$initiateCPMAccountManagementOperations
    [bool]$specifyNextAccountContent
    [bool]$renameAccounts
    [bool]$deleteAccounts
    [bool]$unlockAccounts
    [bool]$manageSafe
    [bool]$manageSafeMembers
    [bool]$backupSafe
    [bool]$viewAuditLog
    [bool]$viewSafeMembers
    [bool]$accessWithoutConfirmation
    [bool]$createFolders
    [bool]$deleteFolders
    [bool]$moveAccountsAndFolders
    [bool]$requestsAuthorizationLevel1
    [bool]$requestsAuthorizationLevel2

    SafeMembersPermissions() {
        $this.Init(@{}) 
    }
    SafeMembersPermissions([pscustomobject]$Properties) { 
        $this.Init($Properties) 
    }

    hidden [void] SetValues([pscustomobject]$PSCustom) {
        foreach ($Property in $PSCustom.psobject.properties.name) {
            if ([bool]($this.PSobject.Properties.name.ToLower() -eq $Property.ToLower())) {
                If ("System.Boolean" -eq $this.PSobject.Properties[$Property].TypeNameOfValue -and "System.String" -eq $PSCustom.PSobject.Properties[$Property].TypeNameOfValue) {
                    If ("true" -eq $PSCustom.$Property) {
                        $this.$Property = $true
                    }
                    else {
                        $this.$Property = $false
                    }
                }
                else {
                    $this.$Property = $PSCustom.$Property
                }
            }
        }
    }
}

[NoRunspaceAffinity()]
Class SafeMember : PASObject {
    [string]$memberName
    [string]$memberID
    [string]$memberType
    [string]$membershipExpirationDate
    [bool]$isExpiredMembershipEnable
    [bool]$isPredefinedUser
    [SafeMembersPermissions]$permissions
    hidden [SafeMembersPermissions]$_permissions
    [string]$safeUrlId
    [string]$safeName
    [int32]$safeNumber
    hidden [string]$searchIn
    hidden [string]$LDAPFullDN
    hidden [string]$LDAPDirectory
    [string[]]$safeProps = @("safeUrlId", "memberName", "searchIn", "membershipExpirationDate", "MemberType", "memberID")
    [string[]]$safeRestProps = @("memberName", "searchIn", "membershipExpirationDate", "MemberType")
    [string[]]$permProps = @("useAccounts", "retrieveAccounts", "listAccounts", "addAccounts", "updateAccountContent", "updateAccountProperties", "initiateCPMAccountManagementOperations", 
        "specifyNextAccountContent", "renameAccounts", "deleteAccounts", "unlockAccounts", "manageSafe", "manageSafeMembers", "backupSafe", "viewAuditLog", 
        "viewSafeMembers", "accessWithoutConfirmation", "createFolders", "deleteFolders", "moveAccountsAndFolders", "requestsAuthorizationLevel1", "requestsAuthorizationLevel2")
    SafeMember() {
        $this.Init(@{})
    }
    SafeMember([pscustomobject]$Properties) { 
        $this.Init($Properties) 
    }

    hidden [void] Init([pscustomobject]$PSCustom) {
        if ([string]::IsNullOrEmpty($PSCustom) -or ($PSCustom.count -eq 0)) {
            return
        }
        $This.WriteVerbose("Creating $($This.GetType()) object: Init Override")
        $this.NewSetGet()
        $This.SetValues($PSCustom)
        $This.WriteVerbose("Succesfully created $($This.GetType()) object: Init Override")
    }
    hidden [void] NewSetGet() {
        [pscustomobject]$This._permissions = [SafeMembersPermissions]$($this | Add-Member -Force ScriptProperty 'permissions' `
            {
                # get
                $this | Select-Object -Property safeName, memberName -ExpandProperty _permissions
            }`
            {
                # set
                param ( $arg )
                $This._permissions = $arg
            }
        )
    }

    #region Local Commaands
    SetFull() {
        $This.permissions.psobject.properties.name | ForEach-Object { $This.permissions.$PSitem = $true }
        $This.permissions.requestsAuthorizationLevel2 = $false
    }
    SetUse() {
        $This.permissions.psobject.properties.name | ForEach-Object { $This.permissions.$PSitem = $false }
        @("useAccounts", "listAccounts") | ForEach-Object { $This.permissions.$PSitem = $true }
    }
    SetRetrieve() {
        $This.permissions.psobject.properties.name | ForEach-Object { $This.permissions.$PSitem = $false }
        @("useAccounts", "listAccounts", "retrieveAccounts") | ForEach-Object { $This.permissions.$PSitem = $true }
    }
    SetApprove() {
        $This.permissions.psobject.properties.name | ForEach-Object { $This.permissions.$PSitem = $false }
        @("listAccounts", "viewSafeMembers", "manageSafeMembers", "requestsAuthorizationLevel1") | ForEach-Object { $This.permissions.$PSitem = $true }
    }
    [pscustomobject] Add() {
        $uri = "$([PASObject]::URL_Base)/API/Safes/$($This.safeUrlId)/Members/"
        $body = $this | Select-Object -Property memberName, searchIn, membershipExpirationDate, MemberType, @{expression = { $PSitem.permissions  | Select-Object -Property $This.permProps }; label = 'permissions' }
        Try {
            $restResult = $This.InvokePost($uri, $($body | ConvertTo-Json))
            $This.SetValues($restResult)
            $This.WriteInfo("Member `"$($this.memberName)`" succsfully added to safe `"$($This.safeUrlId)`"")
            Return $this | Select-Object -Property $This.safeRestProps -ExpandProperty permissions 
        }
        Catch { 
            if (("SFWS0012" -eq ($PSitem | ConvertFrom-Json).ErrorCode) -and ([pasobject]::UpdateOnAdd)) {
                Try {
                    $This.WriteInfo("Member `"$($this.memberName)`" already exist in safe `"$($This.safeUrlId)`". Attempting to update member.")
                    $uri = "$([PASObject]::URL_Base)/API/Safes/$($This.safeUrlId)/Members/$($this.memberName)/"
                    $restResult = $This.InvokePut($uri, $($body | ConvertTo-Json))
                    $This.SetValues($restResult)
                    $This.WriteInfo("Member `"$($this.memberName)`" succsfully updated in safe `"$($This.safeUrlId)`"")
                    Return $this | Select-Object -Property $This.safeRestProps -ExpandProperty permissions
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
    
    [pscustomobject] Update() {
        $uri = "$([PASObject]::URL_Base)/API/Safes/$($This.safeUrlId)/Members/$($this.memberName)/"
        $body = $this | Select-Object -Property memberName, searchIn, membershipExpirationDate, MemberType, @{expression = { $PSitem.permissions  | Select-Object -Property $This.permProps  }; label = 'permissions' }
        Try {
            $restResult = $This.InvokePut($uri, $($body | ConvertTo-Json))
            $This.SetValues($restResult)
            $This.WriteInfo("Member `"$($this.memberName)`" succsfully updated in safe `"$($This.safeUrlId)`"")
            Return $this | Select-Object -Property $This.safeRestProps -ExpandProperty permissions 
        }
        Catch { 
            if (("SFWS0008" -eq ($PSitem | ConvertFrom-Json).ErrorCode) -and ([pasobject]::AddOnUpdate)) {
                Try {
                    $This.WriteInfo("Member `"$($this.memberName)`" does not exist in safe `"$($This.safeUrlId)`", unable to update. Attempting to add member.")
                    $uri = "$([PASObject]::URL_Base)/API/Safes/$($This.safeUrlId)/Members/"
                    $restResult = $This.InvokePost($uri, $($body | ConvertTo-Json))
                    $This.SetValues($restResult)
                    $This.WriteInfo("Member `"$($this.memberName)`" succsfully added to safe `"$($This.safeUrlId)`"")
                    Return $this | Select-Object -Property $This.safeRestProps -ExpandProperty permissions
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
    [pscustomobject] Get() {
        $uri = "$([PASObject]::URL_Base)/API/Safes/$($This.safeUrlId)/Members/$($this.memberName)/"
        Try {
            $restResult = $This.InvokeGet($uri)
            $This.SetValues($restResult)
            Return $this | Select-Object -Property $This.safeRestProps -ExpandProperty _permissions
            
        }
        Catch {
            $This.WriteError($PSItem)
            return $null
        }
    }
    [void] Delete() {
        $uri = "$([PASObject]::URL_Base)/API/Safes/$($This.safeUrlId)/Members/$($this.memberName)/"
        Try {
            $This.InvokeDelete($uri)
            $This.WriteInfo("Member `"$($this.memberName)`" deleted succsfully from safe `"$($This.safeUrlId)`"")
        }
        Catch {
            if ("SFWS0007" -eq ($PSitem | ConvertFrom-Json).ErrorCode) {
                $This.WriteInfo("$(($PSitem |ConvertFrom-Json).ErrorMessage) - Bypassing delete")
            }
            else {
                $This.WriteError($PSItem)
            }
        }
    }
    [PSCustomObject] Load($Item) {
        $This.SetValues($($item | Select-Object -Property $This.safeProps))
        $perms = New-Object SafeMembersPermissions
        $perms.SetValues($($item | Select-Object -Property $This.permProps))
        $This.permissions = $perms
        Return $This | Select-Object -Property $This.safeRestProps -ExpandProperty _permissions
    }

    #endregion Local Commaands

    #region Migrate Commaands
    [pscustomobject] MigrateAdd() {
        $uri = "$($(New-Object -TypeName PASMigrate)::URL_Base)/API/Safes/$($This.safeUrlId)/Members/"
        $body = $this | Select-Object -Property memberName, searchIn, membershipExpirationDate, MemberType, @{expression = { $PSitem._permissions }; label = 'permissions' }
        Try {
            $restResult = $This.InvokePost($uri, $($body | ConvertTo-Json))
            $This.SetValues($restResult)
            Return $this | Select-Object -Property $This.safeRestProps -ExpandProperty _permissions 
        }
        Catch {
            $This.WriteError($PSItem)
            return $null
        }
    }
    [pscustomobject] MigrateUpdate() {
        $uri = "$($(New-Object -TypeName PASMigrate)::URL_Base)/API/Safes/$($This.safeUrlId)/Members/$($this.memberName)/"
        $body = $this | Select-Object -Property memberName, searchIn, membershipExpirationDate, MemberType, @{expression = { $PSitem._permissions }; label = 'permissions' }
        Try {
            $restResult = $This.InvokePut($uri, $($body | ConvertTo-Json))
            $This.SetValues($restResult)
            Return $this | Select-Object -Property $This.safeRestProps -ExpandProperty _permissions
        }
        Catch {
            $This.WriteError($PSItem)
            return $null
        }
    }
    [pscustomobject] MigrateGet() {
        $uri = "$($(New-Object -TypeName PASMigrate)::URL_Base)/API/Safes/$($This.safeUrlId)/Members/$($this.memberName)/"
        Try {
            $restResult = $This.InvokeGet($uri)
            $This.SetValues($restResult)
            Return $this | Select-Object -Property $This.safeRestProps -ExpandProperty _permissions
        }
        Catch {
            $This.WriteError($PSItem)
            return $null
        }
    }
    [void] MigrateDelete() {
        $uri = "$($(New-Object -TypeName PASMigrate)::URL_Base)/API/Safes/$($This.safeUrlId)/Members/$($this.memberName)/"
        Try {
            $This.InvokeDelete($uri)
            $This.WriteInfo("In Safe `"$($This.safeUrlId)`" owner `"$($this.memberName)`" deleted succsfully")
        }
        Catch {
            $This.WriteError($PSItem)
        }
    }

    [void] MigrateTranslateLDAPDirectory() {
        If ($null = $this.memberName) {
            Throw "MemberName is required"
        }
        elseif ($null = $this.LDAPFullDN) {
            Throw "LDAPFullDN is Required"
        }
        elseif ($null = $this.LDAPDirectory) { 
            Throw "LDAPDirectory is required"
        }
        $TranslateResult = $(New-Object -TypeName TranslateMember)::Translate($This.memberName, $This.LDAPFullDN, $This.LDAPDirectory)
        $This.memberName = $TranslateResult.MemberName
        $this.searchIn = $TranslateResult.searchIn
        
    }
    #endregion Migrate Commaands

}
