using Module .\Logging.psm1

[NoRunspaceAffinity()]
Class PASBase : Logging {
    hidden [void] Init([pscustomobject]$PSCustom) {
        if ([string]::IsNullOrEmpty($PSCustom)){
            return
        }
        $This.WriteVerbose("Creating $($This.GetType()) object")
        $This.SetValues($PSCustom)
        $This.WriteVerbose("Succesfully created $($This.GetType()) object")
    }
    hidden [void] SetValues([pscustomobject]$PSCustom) {
        $This.ClearValues()
        foreach ($Property in $PSCustom.psobject.properties.name) {
            if ([bool]($this.PSobject.Properties.name.ToLower() -eq $Property.ToLower())) {
                $this.$Property = $PSCustom.$Property
            }
        }
    }
    hidden [void] ClearValues() {
        foreach ($Property in $This.psobject.properties.name) {
            if ("LogFile" -eq $Property) {
                continue
            }
            Try {
                $this.$Property = $null
            }
            Catch [System.Management.Automation.SetValueInvocationException] {
                If ($PSitem -match 'System.DateTime') {
                    Try {
                        $this.$Property = [DateTime]::MinValue
                    } catch {
                        $this.$Property = 0
                    }
                }
                elseIf ($PSitem -match 'System.Double') {
                    $this.$Property = 0
                }
                else {
                    Throw
                }
            }
        }
    }
    [string] ToJson() {
        return  $($This | Select-Object -Property $PSItem.PSobject.Properties.name | Select-Object -Property * | ConvertTo-Json -Depth 3 )
    }
    [datetime] GetDateTimeFromEpoch([string]$Epoch) {
        [datetime]$Begin = '1970-01-01 00:00:00'
        if (![string]::IsNullOrEmpty($Epoch)) {
            Return $Begin.AddSeconds($Epoch).ToLocalTime()
        }
        else {
            Return $null
        }
    }
}