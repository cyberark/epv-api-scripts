using Module .\Logging.psm1
using Module .\PASBase.psm1
using Module .\PASObject.psm1

ENUM status {
    inProcess
    Success
    Failure
}

Class remoteMachinesAccess {
    [string]$remoteMachines
    [string]$accessRestrictedToRemoteMachines
}

Class secretManagement {
    [bool]$automaticManagementEnabled
    [string]$manualManagementReason
    [status]$status
    [string]$lastModifiedTime
    [string]$lastReconciledTime
    [string]$lastVerifiedTime

}
[NoRunspaceAffinity()]
#TODO Create Format File
#https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_format.ps1xml
Class Account : PASObject {
    [string]$id
    [string]$Name
    [string]$address
    [string]$platformId
    [string]$safeName
    [string]$secretType
    [string]$secret
    [secretManagement]$secretManagement
    [PSCustomObject]$platformAccountProperties
    [remoteMachinesAccess]$remoteMachinesAccess
    [string]$createdTime
    [string]$categoryModificationTime
    [string]$deletionTime

    hidden [pscustomobject]$conversion
    hidden [string[]]$ExcludePropertiesGen
    hidden [string[]]$ExcludePropertiesSecret
    hidden [string[]]$ExcludePropertiesRemote

    Account() {
        $this.Init(@{}) 
    }
    Account([pscustomobject]$Properties) { 
        $this.Init($Properties) 
    }

    Init () {
        $this.Init(@{})
    }

    Init ([pscustomobject]$Properties) {
        $this.load($Properties)
    }

    load([pscustomobject]$object) {
        
        $generalProps = $This | Get-Member -MemberType Property | Select-Object -Property Name
        $secretProps = $This.secretManagement | Get-Member -MemberType Property | Select-Object -Property Name
        $remoteProps = $This.remoteMachinesAccess | Get-Member -MemberType Property | Select-Object -Property Name
        $object.keys | ForEach-Object {
            If ($psitem -in $generalProps.Name) {   
                $this.$($PSItem) = $object[$psitem]
            }
            elseif ($psitem -in $secretProps.name) {   
                $this.secretManagement.$($PSItem) = $object[$psitem]
            }
            elseif ($psitem -in $remoteProps.name) {   
                $this.remoteMachinesAccess.$($PSItem) = $object[$psitem]
            }
            else { 
                IF ($null -eq $this.platformAccountProperties.$PSitem) {  
                    $this.platformAccountProperties.add($($PSItem), $object[$psitem])
                }
                else {
                    $this.platformAccountProperties.$PSitem = $object[$psitem]
                }
            }
        }
    }

    load($object, [bool]$convertFromV1) {
        $ConvertedOobject = @{}
        if ($convertFromV1) {
            $object.keys | ForEach-Object { If ($null -ne $this.conversion[$PSitem]) {
                    $ConvertedOobject.add($($this.conversion[$PSitem]), $object[$psitem])
                }
                Else {
                    $ConvertedOobject.add($($PSItem), $object[$psitem])
                }
            }
        }
        else {
            $ConvertedOobject = $object
        }
        $this.load($ConvertedOobject)
    }





}


<# 	
{
    "id": "string",
    "name": "string",
    "address": "string",
    "userName": "string",
    "platformId": "string",
    "safeName": "string",
    "secretType": "key",
    "platformAccountProperties": {},
    "secretManagement": {
      "automaticManagementEnabled": true,
      "manualManagementReason": "string",
      "status": "inProcess",
      "lastModifiedTime": 0,
      "lastReconciledTime": 0,
      "lastVerifiedTime": 0
    },
    "remoteMachinesAccess": {
      "remoteMachines": "string",
      "accessRestrictedToRemoteMachines": true
    },
    "createdTime": 0
    "categoryModificationTime": 111111111111111111111
  } 
  #>