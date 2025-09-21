Using Module .\Base.psm1

Class Comp : Base {

    [string]$ComponentIP
    [string]$ComponentUserName
    [string]$ComponentVersion
    [string]$ComponentSpecificStat
    [string]$IsLoggedOn
    [string]$LastLogonDate
    [string]$ComponentType


    Comp() {}

    Comp([pscustomobject]$PSCustom) : Base([pscustomobject]$PSCustom) {
        $this.SetValues($PSCustom)
        if ('-62135568000' -eq $this.LastLogonDate) {
            $this.LastLogonDate = 'Never'
        }
    }
}
