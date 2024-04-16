using Module .\PASObject.psm1

[NoRunspaceAffinity()]
Class PASMigrate : PASObject {
    static [pscredential]$Credentials
    static [AuthTypes]$AuthType
    static [string]$URL_Base
    static [string]$URL_Identity = "https://aal4797.my.idaptive.app"
    static [bool]$RestConfigured = $false
    static [datetime]$LogonTime
    static [timespan]$MaxSessionDuration = (New-TimeSpan -Minutes 5)
    static [bool]$NewSessionInProgress = $false
    hidden static [System.Collections.IDictionary]$_AuthHeader
    hidden [System.Collections.IDictionary] $AuthHeader = [PASMigrate]::_AuthHeader

    PASMigrate (){
    }
}