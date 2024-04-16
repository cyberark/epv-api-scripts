using Module .\RestCall.psm1
using Module .\Logging.psm1
using Module .\PASBase.psm1
Enum AuthTypes {
    CyberArk
    LDAP
    RADIUS
    Identity
    OAuth2
}

[NoRunspaceAffinity()]
class IDName : PASBase {
    [string]$id
    [string]$name
    IDName() {
        $this.Init(@{}) 
    }
    IDName([pscustomobject]$Properties) { 
        $this.Init($Properties) 
    }

}

[NoRunspaceAffinity()]
Class PASObject : Restcall {
    #Properties
    static [pscredential]$Credentials
    static [AuthTypes]$AuthType
    static [string]$URL_Base
    static [string]$URL_Identity = "https://aal4797.my.idaptive.app"
    static [bool]$RestConfigured = $false
    static [datetime]$LogonTime
    static [timespan]$MaxSessionDuration = (New-TimeSpan -Minutes 5)
    static [bool]$NewSessionInProgress = $false
    hidden static [System.Collections.IDictionary]$_AuthHeader
    hidden [System.Collections.IDictionary] $AuthHeader = [PASObject]::_AuthHeader
    hidden [int32]$AmountOfJobs
    static [bool]$AddOnUpdate
    static [bool]$UpdateOnAdd

    static [string] TrimLast($value) {
        return  $value.Substring(0, $value.Length - 1)
    }

    #Region Logon to PAS
    hidden [void] InvokeLogonPAS ([pscredential]$Credentials, [AuthTypes]$AuthType) {
        $This.WriteDebug("In InvokeLogonPAS")
        $URL_Logon = (New-Object -TypeName $($this.GetType()))::URL_Base + "/api/auth/$AuthType/Logon"
        $body = [PSCustomObject]@{ 
            username          = $Credentials.username.Replace('\', '')
            password          = $Credentials.GetNetworkCredential().password
            concurrentSession = $true
        }
        $response = $(Invoke-RestMethod -Method Post -ContentType "application/json" -Uri $URL_Logon -Body $($body | ConvertTo-Json -Compress))
        (New-Object -TypeName $($this.GetType()))::_AuthHeader = [System.Collections.IDictionary]@{Authorization = "$($response)" }
        (New-Object -TypeName $($this.GetType()))::LogonTime = [datetime]::Now
        (New-Object -TypeName $($this.GetType()))::AuthType = $AuthType
        (New-Object -TypeName $($this.GetType()))::Credentials = $Credentials
        $This.WriteDebug("Completed InvokeLogonPAS")
    }

    [void] LogonPAS ([pscredential]$Credentials, [AuthTypes]$AuthType) {
        (New-Object -TypeName $($this.GetType()))::Credentials = $Credentials
        (New-Object -TypeName $($this.GetType()))::AuthType = $AuthType
        if ([string]::IsNullOrEmpty((New-Object -TypeName $($this.GetType()))::URL_Base)) {
            Throw "Unable to connect, URL not set"
        }
        (New-Object -TypeName $($this.GetType()))::RestConfigured = $true
        $this.InvokeLogonPAS($Credentials, $AuthType)
    }
    [void] LogonPAS ([pscredential]$Credentials, [AuthTypes]$AuthType, [string]$url) {
        (New-Object -TypeName $($this.GetType()))::URL_Base = $url
        $this.LogonPAS($Credentials, $AuthType)
    }
    [void] LogonPAS () {
        $ThisoutputVerbose = $true   
        if ([string]::IsNullOrEmpty((New-Object -TypeName $($this.GetType()))::URL_Base)) {
            Throw "RestCall URL_Base is not set"
        }
        $this.LogonPAS($(Get-Credential), "CyberArk")
    }
    [void] ConfigurePAS([string]$URL_Base) {
        (New-Object -TypeName $($this.GetType()))::URL_Base = $URL_Base
        (New-Object -TypeName $($this.GetType()))::RestConfigured = $true
    }
    [void] ConfigurePAS([string]$URL_Base, [string]$logonToken) {
        $this.ConfigurePAS($URL_Base)
        (New-Object -TypeName $($this.GetType()))::_AuthHeader = @{Authorization = $logonToken }
    }
    hidden [void] ConfigurePAS([string]$URL_Base, [PSCustomObject]$AuthHeader) {
        $this.ConfigurePAS($URL_Base)
        (New-Object -TypeName $($this.GetType()))::_AuthHeader = $AuthHeader
    } 

    #endregion

    #Region Logon to PCloud via OAuth2
    hidden [void] InvokeLogonOAuth2 ([pscredential]$Credentials) {
        $This.WriteDebug("In InvokeLogonOAuth2")
        If ($((New-Object -TypeName $($this.GetType()))::URL_Identity) -notmatch "/oauth2/platformtoken" ) {
            (New-Object -TypeName $($this.GetType()))::URL_Identity = "$((New-Object -TypeName $($this.GetType()))::URL_Identity)/oauth2/platformtoken"
        }
        
        $URL_Logon = (New-Object -TypeName $($this.GetType()))::URL_Identity 
        $body = @{
            grant_type    = "client_credentials"
            client_id     = $Credentials.username.Replace('\', '')
            client_secret = $Credentials.GetNetworkCredential().password
        }
        $response = $(Invoke-RestMethod -Method Post -Uri $URL_Logon -Body $body)
        (New-Object -TypeName $($this.GetType()))::_AuthHeader = [System.Collections.IDictionary]@{Authorization = "Bearer $($response.access_token)" }
        (New-Object -TypeName $($this.GetType()))::LogonTime = [datetime]::Now
        (New-Object -TypeName $($this.GetType()))::AuthType = [AuthTypes]::OAuth2
        (New-Object -TypeName $($this.GetType()))::Credentials = $Credentials
        $This.WriteDebug("Completed InvokeLogonOAuth2")
    }

    [void] ConfigureOAuth2([string]$URL_Identity, [string]$URL_Base) {
        (New-Object -TypeName $($this.GetType()))::URL_Identity = $URL_Identity
        (New-Object -TypeName $($this.GetType()))::URL_Base = $URL_Base
        (New-Object -TypeName $($this.GetType()))::RestConfigured = $true
    }
    
    #endregion


    hidden [void] InvokeLogonISPSS ([pscredential]$Credentials) {
        [string]$URL_StartAuthentication = "$((New-Object -TypeName $($this.GetType()))::URL_Identity)/Security/StartAuthentication"
        [string]$URL_AdvanceAuthentication = "$((New-Object -TypeName $($this.GetType()))::URL_Identity)/Security/AdvanceAuthentication"
        [pscustomobject]$Body = @{
            User    = $Credentials.username
            Version = "1.0"
        }
        [pscustomobject]$StartResponse = $(Invoke-RestMethod -Method Post -ContentType "application/json" -Uri $URL_StartAuthentication -Body $body | ConvertTo-Json -Compress) 
        [string]$SesshID = $StartResponse.Result.sessionid  
        [string]$SelectedMechIDUp = ""
        $i = 1
        foreach ($prop in $StartResponse) {
            foreach ($mech in $prop.Result.Challenges.mechanisms) {
                $mechname = $mech.name
                $mechid = $mech.mechanismid
                $i++
                if ($mechname -eq "UP") {
                    $SelectedMechIDUp = $mechid
                }
            }
        } 
        if ([string]::IsNullOrEmpty($SelectedMechIDUp)) {
            Throw "Unable to locate user password authentication"
        }
        $AdvAuthParms = @{
            Action          = "Answer" 
            Answer          = $Credentials.GetNetworkCredential().password 
            MechanismId     = $SelectedMechIDUp
            SessionId       = $SesshID
            PersistentLogin = "true" 
        }
        $AdvResponse = Invoke-RestMethod -Uri $URL_AdvanceAuthentication -Method POST -ContentType "application/json" -Body (ConvertTo-Json($AdvAuthParms)) 
        if ($AdvResponse.success) {
            (New-Object -TypeName $($this.GetType()))::_AuthHeader = @{
                Authorization          = "Bearer $($AdvResponse.Result.Token)"
                'X-IDAP-NATIVE-CLIENT' = "true"
            }
            (New-Object -TypeName $($this.GetType()))::AuthType = [AuthTypes]::Identity
            (New-Object -TypeName $($this.GetType()))::Credentials = $Credentials
        } Else {
            Throw "Authentication failure"
        }
        
    }

    [void] Logon ([pscredential]$Credentials, [AuthTypes]$AuthType) {
        If (!(New-Object -TypeName $($this.GetType()))::RestConfigured) {
            Throw "Unable to logon due to configuration not being set"
        }
        Switch ($AuthType) {
            "OAuth2" {
                $this.InvokeLogonOAuth2($Credentials)
            }
            "Identity" {
                #TODO
            }
            default {
                $this.LogonPAS($Credentials, $AuthType)
            }
        }
    }

    hidden [void] RefreshLogon() {
        $This.WriteDebug("In RefreshLogon")
        If (!(New-Object -TypeName $($this.GetType()))::RestConfigured) {
            Throw "Unable to RefreshLogon due to configuration not being set"
        }
        Switch ((New-Object -TypeName $($this.GetType()))::AuthType) {
            OAuth2 {
                $this.InvokeLogonOAuth2((New-Object -TypeName $($this.GetType()))::Credentials)
            }
            Identity {

            }
            default {
                $this.LogonPAS((New-Object -TypeName $($this.GetType())).Credentials, (New-Object -TypeName $($this.GetType())).AuthType)
            }
        }
        $This.WriteDebug("Completed RefreshLogon")
    }

    [PSCustomObject]InvokeRestCall([Microsoft.PowerShell.Commands.WebRequestMethod]$command, [string]$URI, [string]$body, [PSCustomObject]$AuthHeader = (New-Object -TypeName $($this.GetType()))::_AuthHeader) {
        if (!(New-Object -TypeName $($this.GetType()))::RestConfigured) {
            Throw "Rest not configured"
        }
        While ((New-Object -TypeName $($this.GetType()))::NewSessionInProgress) {
            Start-Sleep -Seconds 1
        }
        if ([datetime]::Now -gt $((New-Object -TypeName $($this.GetType()))::LogonTime) + (New-Object -TypeName $($this.GetType()))::MaxSessionDuration) {
            $This.WriteInfo("Max Duration Exceeded")
            (New-Object -TypeName $($this.GetType()))::NewSessionInProgress = $true
            Start-Sleep -Seconds .5
            $this.RefreshLogon()
            (New-Object -TypeName $($this.GetType()))::NewSessionInProgress = $false
        }
        return [PSCustomObject](New-Object -TypeName RestCall).InvokeRestCall($command, $URI, $body, $AuthHeader)
    }
    
    [PSCustomObject]InvokeRestOutCall([Microsoft.PowerShell.Commands.WebRequestMethod]$command, [string]$URI, [string]$Outfile, [PSCustomObject]$body, [PSCustomObject]$AuthHeader = (New-Object -TypeName $($this.GetType()))::_AuthHeader) {
        if (!(New-Object -TypeName $($this.GetType()))::RestConfigured) {
            Throw "Rest not configured"
        }
        While ((New-Object -TypeName $($this.GetType()))::NewSessionInProgress) {
            Start-Sleep -Seconds 1
        }
        if ([datetime]::Now -gt $((New-Object -TypeName $($this.GetType()))::LogonTime) + (New-Object -TypeName $($this.GetType()))::MaxSessionDuration) {
            $This.WriteInfo("Max Duration Exceeded")
            (New-Object -TypeName $($this.GetType()))::NewSessionInProgress = $true
            Start-Sleep -Seconds .5
            $this.RefreshLogonPAS()
            (New-Object -TypeName $($this.GetType()))::NewSessionInProgress = $false
        }
        try {
            return [PSCustomObject](New-Object -TypeName RestCall).InvokeRestOutCall($command, $URI, $outfile, $body, $AuthHeader)
        } catch {
            throw $_
        }

    }
    [string]GenURLSearchString([string]$url,[pscustomobject]$URLSearchParms) {
        $base = "$((New-Object -TypeName $($this.GetType()))::URL_Base)/$url"
        [string]$add = "?"
        $URLSearchParms.PSObject.Properties | ForEach-Object {
            if (![string]::IsNullOrEmpty($($PSItem.value)) -and 0 -ne $PSItem.value) {
                $add = "$($add)$($PSitem.name)=$($PSItem.value)&"
            }
        }
        If ("?" -ne $add) {
            $base = (New-Object -TypeName $($this.GetType()))::trimLast($("$($Base)$($add)"))
        }
        $This.WriteDebug("Base = $base")
        return $base
    }

}