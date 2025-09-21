using module .\Base.psm1

class RemoteMachinesAccess : Base {
    [string]$remoteMachinesAccess
    [bool]$accessRestrictedToRemoteMachines
    hidden[string[]]$_remoteMachines

    RemoteMachinesAccess() {
        $this.ReplaceGetSetRemoteMachine()
    }

    RemoteMachinesAccess([pscustomobject]$PSCustom) {
        $this.ReplaceGetSetRemoteMachine()
        $this.SetValues($PSCustom)
    }

    hidden [void] SetValues([pscustomobject]$PSCustom) {
        $this.ClearValues()
        foreach ($Property in $PSCustom.psobject.properties.name) {
            if ($this.PSobject.Properties.name -contains $Property) {
                if ('remoteMachines' -eq $Property) {
                    $this.$Property = $PSCustom.$Property.Split(';')
                }
                else {
                    $this.$Property = $PSCustom.$Property
                }
            }
            else {
                Write-Error "Property $Property with type $($Property.GetType().Name) not found in $($this.GetType().Name) "
            }
        }
    }
    hidden [void] ReplaceGetSetRemoteMachine() {
        $this | Add-Member -Name remoteMachines -MemberType ScriptProperty -Value {
            return $this._remoteMachines -join ';'
        } -SecondValue {
            param($value)
            $this._remoteMachines = $value
        }
    }
}


class secretManagement : Base {
    [bool]$automaticManagementEnabled
    [string]$status
    [string]$lastModifiedTime
    [string]$lastReconciledTime
    [string]$lastVerifiedTime
    [string]$manualManagementReason

    secretManagement() {}

    secretManagement([pscustomobject]$PSCustom) : base([pscustomobject]$PSCustom) {}
}
class Account : Base {
    [string]$id
    [string]$name
    [string]$address
    [string]$username
    [string]$platformId
    [string]$safeName
    [string]$secretType
    hidden [string]$secret
    [PSCustomObject]$platformAccountProperties
    [secretManagement]$secretManagement
    [RemoteMachinesAccess]$remoteMachinesAccess
    [string]$createdTime
    [string]$CategoryModificationTime
    [PSCustomObject]$LinkedAccounts
    [string]$deleteInsightStatus

    Account() {

    }

    Account([pscustomobject]$PSCustom) : base([pscustomobject]$PSCustom) {
        $this.secretManagement = [secretManagement]@{}
        $this.remoteMachinesAccess = [RemoteMachinesAccess]@{}
        $this.platformAccountProperties = [PSCustomObject]@{}
        $this.LinkedAccounts = [PSCustomObject]@{}
        $this.SetValues($PSCustom)
    }

    hidden [void] SetValues([string]$Property, [string]$Value) {
        $this.$Property = $Value
    }
}
