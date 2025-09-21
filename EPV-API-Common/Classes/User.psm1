# PSScriptAnalyzer: disable=TypeNotFound
Using Module .\Base.psm1

Class businessAddress : Base {
    [string]$workStreet
    [string]$workCity
    [string]$workState
    [string]$workZip
    [string]$workCountry

        phones() {}
    businessAddress([pscustomobject]$PSCustom) : Base([pscustomobject]$PSCustom) {}
}

Class internet : Base {
    [string]$homePage
    [string]$homeEmail
    [string]$businessEmail
    [string]$otherEmail
    [string]$workCountry

    phones() {}
    internet([pscustomobject]$PSCustom) : Base([pscustomobject]$PSCustom) {}
}

Class phones : Base {
    [string]$homeNumber
    [string]$businessNumber
    [string]$cellularNumber
    [string]$faxNumber
    [string]$pagerNumber

    phones() {}
    phones([pscustomobject]$PSCustom) : Base([pscustomobject]$PSCustom) {}
}

Class personalDetails : Base {
    [string]$street
    [string]$city
    [string]$state
    [string]$zip
    [string]$country
    [string]$title
    [string]$organization
    [string]$department
    [string]$profession
    [string]$firstName
    [string]$middleName
    [string]$lastName

    personalDetails() {}
    personalDetails([pscustomobject]$PSCustom) : Base([pscustomobject]$PSCustom) {}
}

Class User : Base {
    [string]$username
    [string]$userType
    [string]$initialPassword
    [string[]]$authenticationMethod
    [string[]]$allowedAuthenticationMethods
    [string]$location
    [string[]]$unAuthorizedInterfaces
    [int]$expiryDate
    [string[]]$vaultAuthorization
    [bool]$enableUser
    [bool]$changePassOnNextLogon
    [bool]$passwordNeverExpires
    [string]$description
    [businessAddress]$businessAddress
    [internet]$internet
    [phones]$phones
    [personalDetails]$personalDetails

    User() {
        $this.businessAddress = [businessAddress]::new()
        $this.internet = [internet]::new()
        $this.phones = [phones]::new()
        $this.personalDetails = [personalDetails]::new()
    }

    User([pscustomobject]$PSCustom) : Base([pscustomobject]$PSCustom) {
        $this.businessAddress = [businessAddress]::new()
        $this.internet = [internet]::new()
        $this.phones = [phones]::new()
        $this.personalDetails = [personalDetails]::new()
        $this.SetValues($PSCustom)
    }

}
