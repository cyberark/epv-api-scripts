Class Base {

    base () {}

    Base([pscustomobject]$PSCustom) {
        $this.SetValues($PSCustom)
    }

    hidden [void] SetValues([pscustomobject]$PSCustom) {
        $this.ClearValues()
        $propList = $($this |Get-Member -force -MemberType Property).name
        foreach ($Property in $PSCustom.psobject.properties.name) {
            if ($propList -contains $Property) {
                $this.$Property = $PSCustom.$Property
            } else {
                Write-Error "Property $Property with type $($Property.GetType().Name) not found in $($this.GetType().Name) "
            }
        }
    }

    hidden [void] ClearValues() {
        foreach ($Property in $this.psobject.properties.name) {
            try {
                $this.$Property = $null
            }
            catch [System.Management.Automation.SetValueInvocationException] {
                if ($PSItem -match 'System.DateTime') {
                    try {
                        $this.$Property = [DateTime]::MinValue
                    }
                    catch {
                        $this.$Property = 0
                    }
                }
                elseif ($PSItem -match 'System.Double') {
                    $this.$Property = 0
                }
                else {
                    throw
                }
            }
        }
    }

    [void] Report() {
        Report($This.GetType().Name + 'ClassReport.csv')
    }

    [void] Report([string]$path) {
        Report($path, $false)
    }
    [void] Report([string]$path, [bool]$append) {
        $this | Export-Csv -Path $path -Append:$append
    }
}
