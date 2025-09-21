Using Module .\Classes\Base.psm1
Using Module .\Classes\Safe.psm1
Using Module .\Classes\SafeMember.psm1
Using Module .\Classes\Account.psm1
Using Module .\Classes\Comp.psm1
using namespace System.Management.Automation
#Region '.\Private\ConnectorManagement\Get-CMURL.ps1' -1

#function Get-ConnectorManagementURL {
function Get-CMURL {
[CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Base URL of the CyberArk Privileged Cloud platform',
            ValueFromPipelineByPropertyName = $true)]
        [string]$PCloudURL,
        [Parameter(ValueFromRemainingArguments = $true,
            DontShow = $true)]
        $CatchAll
    )
    Begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null
        $PCloudURL -match '^(?:https|http):\/\/(?<sub>.*).privilegecloud.cyberark.(?<top>cloud|com)\/PasswordVault.*$' | Out-Null
        $ConnectorManagementBaseURL = "https://$($matches['sub']).connectormanagement.cyberark.$($matches['top'])"
    }
    Process {
        # Return the Connector Management URL
        $ConnectorManagementURL = "$ConnectorManagementBaseURL/api/pool-service"
        return $ConnectorManagementURL
    }
}
#EndRegion '.\Private\ConnectorManagement\Get-CMURL.ps1' 25
#Region '.\Private\Identity\Authentication\Format-PCloudURL.ps1' -1

<#
.SYNOPSIS
Formats and validates a PCloudURL to ensure it follows the correct format.

.DESCRIPTION
The Format-PCloudURL function validates and corrects common mistakes in PCloudURL formatting.
It ensures the URL follows the correct format: https://<subdomain>.privilegecloud.cyberark.com/PasswordVault

Common mistakes it corrects:
- https://<subdomain>.cyberark.cloud/privilegecloud/ -> https://<subdomain>.privilegecloud.cyberark.com/PasswordVault
- Missing /PasswordVault suffix
- Incorrect domain structure

.PARAMETER PCloudURL
The Privileged Cloud URL to format and validate.

.EXAMPLE
Format-PCloudURL -PCloudURL "https://tenant.cyberark.cloud/privilegecloud/"
Returns: "https://tenant.privilegecloud.cyberark.com/PasswordVault"

.EXAMPLE
Format-PCloudURL -PCloudURL "https://tenant.privilegecloud.cyberark.com"
Returns: "https://tenant.privilegecloud.cyberark.com/PasswordVault"

.NOTES
This function is used internally to ensure consistent URL formatting for Privileged Cloud connections.

#>

function Format-PCloudURL {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Privileged Cloud URL to format',
            ValueFromPipelineByPropertyName = $true)]
        [string]$PCloudURL,
        [Parameter(ValueFromRemainingArguments = $true,
            DontShow = $true)]
        $CatchAll
    )

    Begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null
    }

    Process {
        Write-LogMessage -type Verbose -MSG "Original PCloudURL: $PCloudURL"

        # Remove trailing slashes and normalize the URL
        $CleanURL = $PCloudURL.TrimEnd('/')

        # Check for common mistake: https://<subdomain>.cyberark.cloud/privilegecloud/
        if ($CleanURL -match '^(?:https|http):\/\/(?<sub>.*?)\.cyberark\.(?<top>cloud|com)\/privilegecloud\/?.*$') {
            $subdomain = $matches['sub']
            $topDomain = $matches['top']
            $CorrectedURL = "https://$subdomain.privilegecloud.cyberark.$topDomain/PasswordVault"
            Write-LogMessage -type Warning -MSG "Corrected common PCloudURL mistake. Original: $PCloudURL -> Corrected: $CorrectedURL"
            return $CorrectedURL
        }

        # Check for correct format but missing /PasswordVault
        elseif ($CleanURL -match '^(?:https|http):\/\/(?<sub>.*?)\.privilegecloud\.cyberark\.(?<top>cloud|com)\/?.*$') {
            $subdomain = $matches['sub']
            $topDomain = $matches['top']
            $CorrectedURL = "https://$subdomain.privilegecloud.cyberark.$topDomain/PasswordVault"

            # Only log if we're actually making a change
            if ($CorrectedURL -ne $PCloudURL) {
                Write-LogMessage -type Verbose -MSG "Added missing /PasswordVault to PCloudURL: $PCloudURL -> $CorrectedURL"
            }
            return $CorrectedURL
        }

        # Check for other variations with privilegecloud in subdomain
        elseif ($CleanURL -match '^(?:https|http):\/\/.*privilegecloud.*\.cyberark\.(?<top>cloud|com).*$') {
            # Extract the subdomain part before privilegecloud
            if ($CleanURL -match '^(?:https|http):\/\/(?<sub>.*?)(?:\.privilegecloud)?\.cyberark\.(?<top>cloud|com).*$') {
                $subdomain = $matches['sub'] -replace '\.privilegecloud$', ''
                $topDomain = $matches['top']
                $CorrectedURL = "https://$subdomain.privilegecloud.cyberark.$topDomain/PasswordVault"
                Write-LogMessage -type Verbose -MSG "Formatted PCloudURL: $PCloudURL -> $CorrectedURL"
                return $CorrectedURL
            }
        }

        # If no patterns match, try to extract subdomain from any cyberark URL
        elseif ($CleanURL -match '^(?:https|http):\/\/(?<sub>.*?)\.cyberark\.(?<top>cloud|com).*$') {
            $subdomain = $matches['sub']
            $topDomain = $matches['top']
            $CorrectedURL = "https://$subdomain.privilegecloud.cyberark.$topDomain/PasswordVault"
            Write-LogMessage -type Warning -MSG "Detected non-standard PCloudURL format. Attempting correction: $PCloudURL -> $CorrectedURL"
            return $CorrectedURL
        }

        # If we can't parse it, return the original URL with a warning
        else {
            Write-LogMessage -type Warning -MSG "Unable to parse PCloudURL format: $PCloudURL. Expected format: https://<subdomain>.privilegecloud.cyberark.com/PasswordVault"
            return $PCloudURL
        }
    }
}
#EndRegion '.\Private\Identity\Authentication\Format-PCloudURL.ps1' 103
#Region '.\Private\Identity\Authentication\Format-Token.ps1' -1

function Format-Token {
    [CmdletBinding()]
    param (
        $AuthToken
    )
    $IdentityHeaders = New-Object System.Collections.Generic.Dictionary"[String,string]"
    $IdentityHeaders.add('Authorization', "Bearer $AuthToken")
    $IdentityHeaders.add('X-IDAP-NATIVE-CLIENT', 'true')
    Return $IdentityHeaders
}
#EndRegion '.\Private\Identity\Authentication\Format-Token.ps1' 11
#Region '.\Private\Identity\Authentication\Get-BaseURL.ps1' -1

function Get-BaseURL {
    [CmdletBinding()]
    [OutputType([String])]
    param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Base URL of CyberArk Privileged Cloud',
            ValueFromPipelineByPropertyName = $true)]
        [string]$PCloudURL,
        [Parameter(ValueFromRemainingArguments = $true,
            DontShow = $true)]
        $CatchAll
    )
    Begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null
        $PCloudURL -match '^(?:https|http):\/\/(?<sub>.*).privilegecloud.cyberark.(?<top>cloud|com)\/PasswordVault.*$' | Out-Null
        $PCloudSubDomain = $($matches['sub'])
        $TopDomain = $($matches['top'])
    }
    Process {
        # Return the Discovery Management service URL
        $BaseURL = "https://$PCloudSubDomain.privilegecloud.cyberark.$TopDomain"
    }
    end {
        # Return the Discovery URL
        return $BaseURL
    }
}
#EndRegion '.\Private\Identity\Authentication\Get-BaseURL.ps1' 29
#Region '.\Private\Identity\Authentication\Get-DiscoveryURL.ps1' -1

function Get-DiscoveryURL {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Base URL of CyberArk Privileged Cloud',
            ValueFromPipelineByPropertyName = $true)]
        [string]$PCloudURL,
        [Parameter(ValueFromRemainingArguments = $true,
            DontShow = $true)]
        $CatchAll
    )
    Begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null
        $PCloudURL -match '^(?:https|http):\/\/(?<sub>.*).privilegecloud.cyberark.(?<top>cloud|com)\/PasswordVault.*$' | Out-Null
        $PCloudSubDomain = $($matches['sub'])
        $TopDomain = $($matches['top'])
    }
    Process {
        # Return the Discovery Management service URL
        $DiscoveryURL = "https://$PCloudSubDomain.discoverymgmt.cyberark.$TopDomain"
    }
    end {
        # Return the Discovery URL
        return $DiscoveryURL
    }
}
#EndRegion '.\Private\Identity\Authentication\Get-DiscoveryURL.ps1' 28
#Region '.\Private\Identity\Authentication\Get-IdentityAuthToken.ps1' -1

Function Get-IdentityAuthToken {
    [CmdletBinding(DefaultParameterSetName = 'IdentityUserName')]
    Param (
        #The Username that will log into the system. It just needs the username, we will ask for PW, Push etc when doing the authentication.
        [Parameter(
            ParameterSetName = 'IdentityUserName',
            Mandatory = $true,
            HelpMessage = 'User to authenticate into the platform')]
        [string]$IdentityUserName,
        #Username and Password to use when prompted for user password. Replaces the parameter IdentityUserName
        [Parameter(
            ParameterSetName = 'UPCreds',
            Mandatory = $true,
            HelpMessage = 'Credentials to pass if option is UP')]
        [pscredential]$UPCreds,
        #Username and shared secret to use when connecting via OAuth. Replaces the parameter IdentityUserName
        [Parameter(
            ParameterSetName = 'OAuthCreds',
            Mandatory = $true,
            HelpMessage = 'Credentials to pass if option is UP')]
        [pscredential]$OAuthCreds,
        #The URL of the tenant. you can find it if you go to Identity Admin Portal > Settings > Customization > Tenant URL.
        [Alias('IdentityURL')]
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Identity Tenant URL')]
        [string]$IdentityTenantURL,
        #The Subdomain assigned to the privileged cloud environment.
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Subdomain of the privileged cloud environment')]
        [string]$PCloudSubdomain
    )
    Write-LogMessage -type 'Verbose' -MSG "Base URL used : $IdentityTenantURL"
    $IdentityBasePlatformSecURL = "$IdentityTenantURL/Security"
    $startPlatformAPIAuth = "$IdentityBasePlatformSecURL/StartAuthentication"
    if ('UPCreds' -eq $PSCmdlet.ParameterSetName) {
        $IdentityUserName = $UPCreds.UserName
    }
    $startPlatformAPIBody = [PSCustomObject]@{
        User    = $IdentityUserName
        Version = '1.0'
    }
    #Reformat the body to JSON per Identity API requirements

    $startPlatformAPIBody = $startPlatformAPIBody | ConvertTo-Json -Depth 9 -Compress
    $IdentityResponse = Invoke-Rest -Uri $startPlatformAPIAuth -Method Post -Body $startPlatformAPIBody
    $SessionId = $($IdentityResponse.Result.SessionId)
    Write-LogMessage -type 'Verbose' -MSG "SessionId : $($SessionId |ConvertTo-Json -Depth 9 -Compress)"
    $AnswerToResponse = Invoke-Challenge $IdentityResponse -UPCreds $UPCreds -PCloudIdentityURL $IdentityTenantURL
    If ($AnswerToResponse.success) {
        $identityHeaders = Format-Token($AnswerToResponse.Result.Token)
        Write-LogMessage -type 'Verbose' -MSG "IdentityHeaders - $($IdentityHeaders |ConvertTo-Json -Depth 9 -Compress)"
        Write-LogMessage -type Success -MSG 'Identity Token Set Successfully'
        return $identityHeaders
    }
    else {
        Write-LogMessage -type 'Verbose' -MSG "identityHeaders: $($AnswerToResponse|ConvertTo-Json -Depth 9 -Compress)"
        Write-LogMessage -type Error -MSG "Error during logon : $($AnswerToResponse.Message)"
    }
}
#EndRegion '.\Private\Identity\Authentication\Get-IdentityAuthToken.ps1' 62
#Region '.\Private\Identity\Authentication\Get-IdentityOAuthToken.ps1' -1

function Get-IdentityOAuthToken {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,
        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [pscredential]$OAuthCreds,
        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string]$PCloudIdentityURL
    )
    Begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null
    }
    Process {
        # Check if the OAuth credentials are provided
        if (-not $OAuthCreds) {
            Write-LogMessage -type Error -MSG 'OAuth credentials are required.'
            return
        }
        # Check if the OAuth credentials are valid
        if ($OAuthCreds.GetNetworkCredential().UserName -and $OAuthCreds.GetNetworkCredential().Password) {
            Write-LogMessage -type Verbose -MSG 'Valid OAuth credentials provided.'
        }
        else {
            Write-LogMessage -type Error -MSG 'Invalid OAuth credentials.'
            return
        }
    }
    End {
        $body = @{
            'grant_type'    = 'client_credentials'
            'client_id'     = $($OAuthCreds.GetNetworkCredential().UserName)
            'client_secret' = $($OAuthCreds.GetNetworkCredential().Password)
        }
        $token = Invoke-Rest "$PCloudIdentityURL/oauth2/platformtoken/" -Method 'POST' -Body $body -ContentType "application/x-www-form-urlencoded"
        return $token
    }
}
#EndRegion '.\Private\Identity\Authentication\Get-IdentityOAuthToken.ps1' 39
#Region '.\Private\Identity\Authentication\Get-IdentityURL.ps1' -1

function Get-IdentityURL {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Base URL of the CyberArk Identity platform',
            ValueFromPipelineByPropertyName = $true)]
        [string]$PCloudURL,
        [Parameter(ValueFromRemainingArguments = $true,
            DontShow = $true)]
        $CatchAll
    )
    Begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null
        $PCloudURL -match '^(?:https|http):\/\/(?<sub>.*).privilegecloud.cyberark.(?<top>cloud|com)\/PasswordVault.*$' | Out-Null
        $PCloudBaseURL = "https://$($matches['sub']).cyberark.$($matches['top'])"
    }
    Process {
        # PowerShell 7.4+ always uses RequestMessage.RequestUri.Host
        $IdentityBaseURL = $(Invoke-WebRequest $PCloudBaseURL -WebSession $Script:websession.value).BaseResponse.RequestMessage.RequestUri.Host
    }
    end {
        # Return the Identity URL
        $IdentityURL = "https://$IdentityBaseURL"
        return $IdentityURL
    }
}
#EndRegion '.\Private\Identity\Authentication\Get-IdentityURL.ps1' 28
#Region '.\Private\Identity\Authentication\Get-PCLoudLogonHeader.ps1' -1

Function Get-PCLoudLogonHeader {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,
        #The Username that will log into the system. It just needs the username, we will ask for PW, Push etc when doing the authentication.
        [Parameter(
            ParameterSetName = 'IdentityUserName',
            Mandatory = $true,
            HelpMessage = 'User to authenticate into the platform')]
        [Alias('Username')]
        [string]$IdentityUserName,
        #Username and Password to use when prompted for user password. Replaces the parameter IdentityUserName
        [Parameter(
            ParameterSetName = 'UPCreds',
            Mandatory = $true,
            HelpMessage = 'Credentials to pass if option is UP')]
        [Alias('PVWACreds', 'IdentityCreds', 'Creds')]
        [pscredential]$UPCreds,
        #Username and shared secret to use when connecting via OAuth. Replaces the parameter IdentityUserName
        [Parameter(
            ParameterSetName = 'OAuthCreds',
            Mandatory = $true,
            HelpMessage = 'Credentials to pass if option is UP')]
        [pscredential]$OAuthCreds,
        #The Subdomain assigned to the privileged cloud environment.
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'URL privileged cloud environment')]
        [string]$PCloudURL
    )
    Begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null
        $PCloudURL = Format-PVWAURL -PCloudURL $PCloudURL
        $PCloudIdentityURL = Get-IdentityURL -PCloudURL $PCloudURL
    }

    Process {
        switch ($PSCmdlet.ParameterSetName) {
            'OAuthCreds' {
                $OAuthToken = Get-IdentityOAuthToken -PCloudIdentityURL $PCloudIdentityURL -UPCreds $UPCreds -OAuthCreds $OAuthCreds
                #Creating the header for the request to the Identity URL
                $BearerToken = "Bearer $($OAuthToken.access_token)"
            }
            'UPCreds' {
                $Token = Get-IdentityAuthToken -IdentityTenantURL $PCloudIdentityURL -UPCreds $UPCreds
                $BearerToken = "$($Token.Authorization)"
            }
            'IdentityUserName' {
                $Token = Get-IdentityAuthToken -IdentityTenantURL $PCloudIdentityURL -IdentityUserName $IdentityUserName
                $BearerToken = "$($Token.Authorization)"
            }
        }
        return $BearerToken
    }
}
#EndRegion '.\Private\Identity\Authentication\Get-PCLoudLogonHeader.ps1' 57
#Region '.\Private\Identity\Authentication\Invoke-AdvancedAuthBody.ps1' -1


Function Invoke-AdvancedAuthBody {
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Session ID of the mechanism')]
        [string]$SessionId,
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Mechanism of Authentication')]
        $Mechanism,
        #The URL of the tenant. you can find it if you go to Identity Admin Portal > Settings > Customization > Tenant URL.
        [Alias('IdentityURL')]
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Identity Tenant URL')]
        [string]$PCloudIdentityURL,
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Credentials to pass if option is UP')]
        [pscredential]$UPCreds
    )
    $startPlatformAPIAdvancedAuth = "$PCloudIdentityURL/Security/AdvanceAuthentication"
    $MechanismId = $Mechanism.MechanismId
    #need to do this if/elseif as a function so we do not double code here.
    If ($Mechanism.AnswerType -eq 'StartTextOob') {
        #We got two options here 1 text and one Push notification. We will need to do the while statement in this option.
        $Action = 'StartOOB'
        $startPlatformAPIAdvancedAuthBody = @{SessionId = $SessionId; MechanismId = $MechanismId; Action = $Action; } | ConvertTo-Json -Compress
        Write-LogMessage -type 'Info' -MSG 'Waiting for Push to be pressed'
    }
    ElseIf ($Mechanism.AnswerType -eq 'Text') {
        $Action = 'Answer'
        IF (($Mechanism.Name -eq 'UP') -and ($UPCreds)) {
            Write-LogMessage -type Warning -Msg 'Responding with stored credentials'
            $answer = $UPCreds.Password
        }
        else {
            $Answer = Read-Host $($Mechanism.PromptMechChosen) -AsSecureString
        }
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Answer)
        $startPlatformAPIAdvancedAuthBody = @{SessionId = $SessionId; MechanismId = $MechanismId; Action = $Action; Answer = ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)) } | ConvertTo-Json -Compress
    }
    #Rest API
    Try {
        $AnswerToResponse = Invoke-Rest -Uri $startPlatformAPIAdvancedAuth -Method Post -Body $startPlatformAPIAdvancedAuthBody
    }
    Catch {
        Write-LogMessage -type Error -MSG $PSitem.ErrorDetails.Message
    }
    while ($AnswerToResponse.Result.Summary -eq 'OobPending') {
        Start-Sleep -Seconds 2
        $pollBody = @{SessionId = $SessionId; MechanismId = $MechanismId; Action = 'Poll'; } | ConvertTo-Json -Compress
        $AnswerToResponse = Invoke-Rest -Uri $startPlatformAPIAdvancedAuth -Method Post -Body $pollBody
        Write-LogMessage -type 'Info' -MSG "$($AnswerToResponse.Result.Summary)"
    }
    return $AnswerToResponse
}
#EndRegion '.\Private\Identity\Authentication\Invoke-AdvancedAuthBody.ps1' 60
#Region '.\Private\Identity\Authentication\Invoke-Challenge.ps1' -1

function Invoke-Challenge {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true)]
        [array]$IdaptiveResponse,
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Credentials to pass if option is UP')]
        [pscredential]$UPCreds,
        #The URL of the tenant. you can find it if you go to Identity Admin Portal > Settings > Customization > Tenant URL.
        [Alias('IdentityURL')]
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Identity Tenant URL')]
        [string]$PCloudIdentityURL,
        [Parameter(
            DontShow = $true)]
        [int]$SAMLTimeout = 180
    )
    if ($($IdaptiveResponse.Result.IdpRedirectShortUrl)) {
        Write-LogMessage -type 'Important' -MSG "Use the following adddress to complete logon: $($IdaptiveResponse.Result.IdpRedirectShortUrl)" -Header -Footer
        $counter = 0
        do {
            $status = Invoke-Rest -Uri "$IdaptiveBasePlatformSecURL/OobAuthStatus?sessionId=$($IdaptiveResponse.Result.IdpLoginSessionId)" -Method Post -WaitInProgress -WaitCount $counter
            $status
            Start-Sleep 1
            $counter += 1
            if ($counter -gt $SAMLTimeout) {
                Write-LogMessage -type ErrorThrow -MSG 'Timeout waiting for SAML authentication to complete'
                break
            }
        }
        until(-not($status.result.State -eq 'Pending'))
        return $status
    }
    $j = 1
    foreach ($challenge in $IdaptiveResponse.Result.Challenges) {
        #TODO Capture failure messages better. Example being when success = false with message explaining
        #reseting variables
        $Mechanism = $null
        $ChallengeCount = 0
        $ChallengeCount = $challenge.mechanisms.count
        Write-LogMessage -type 'Info' -MSG "Challenge $($j):"
        #Multi mechanisms option response
        if ($ChallengeCount -gt 1) {
            Write-LogMessage -type 'Info' -MSG "There are $ChallengeCount options to choose from."
            $mechanisms = $challenge.mechanisms
            #Displaying the two options for MFA at this challenge part
            $i = 1
            foreach ($mechanismsOption in $mechanisms) {
                $mechanismsName = $mechanismsOption.Name
                $MechanismsMechChosen = $mechanismsOption.PromptMechChosen
                Write-LogMessage -type 'Info' -MSG "$i - is $mechanismsName - $MechanismsMechChosen"
                $i = $i + 1
            }
            #Requesting to know which option the user wants to use
            $Option = $Null
            while ($Option -gt $ChallengeCount -or $Option -lt 1 -or $Null -eq $Option) {
                $Option = Read-Host "Please enter the option number you want to use. from 1-$ChallengeCount"
                try {
                    $Option = [Int]$Option
                }
                catch {
                    Write-LogMessage -type Error -MSG $PSitem.ErrorDetails.Message
                }
            }
            #Getting the mechanism
            $Mechanism = $challenge.mechanisms[$Option - 1] #This is an array so number-1 means the actual position
            #Completing step of authentication
            $AnswerToResponse = Invoke-AdvancedAuthBody -SessionId $SessionId -Mechanism $Mechanism -PCloudIdentityURL $PCloudIdentityURL -UPCreds $UPCreds
            Write-LogMessage -type 'Verbose' -MSG "AnswerToResponce - $($AnswerToResponse |ConvertTo-Json -Depth 9 -Compress)"
        }
        #One mechanism
        else {
            $Mechanism = $challenge.mechanisms
            $MechanismName = $Mechanism.Name
            $MechanismPrmpt = $Mechanism.PromptMechChosen
            Write-LogMessage -type 'Info' -MSG "$MechanismName - $MechanismPrmpt"
            $AnswerToResponse = Invoke-AdvancedAuthBody -SessionId $SessionId -Mechanism $Mechanism -PCloudIdentityURL $PCloudIdentityURL -UPCreds $UPCreds
            Write-LogMessage -type 'Verbose' -MSG "AnswerToResponce - $($AnswerToResponse |ConvertTo-Json -Depth 9 -Compress)"
        }
        #Need Better logic here to make sure that we are done with all the challenges correctly and got next challenge.
        $j = + 1 #incrementing the challenge number
    }
    return $AnswerToResponse
}
#EndRegion '.\Private\Identity\Authentication\Invoke-Challenge.ps1' 88
#Region '.\Private\PAS\Get-OnPremHeader.ps1' -1

function Get-OnPremHeader {
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)] $CatchAll,
        [string] $PVWAURL,
        [string] $Username,
        [Alias('Creds')] [pscredential] $PVWACreds,
        [string] $AuthType = 'Cyberark'
    )
    $PSBoundParameters.Remove('CatchAll') | Out-Null
    $URL_Logon = "$PVWAURL/api/Auth/$AuthType/Logon"

    If ([string]::IsNullOrEmpty($PVWACreds) -and [string]::IsNullOrEmpty($Username)) {
        $username = Read-Host 'Please enter your user name:'
    }
    If ([string]::IsNullOrEmpty($PVWACreds)) {
        $PVWACreds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $(Read-Host 'Please enter your password:' -AsSecureString)
    }
    [pscustomobject]$logonBody = @{ username = $PVWACreds.GetNetworkCredential().UserName; password = $PVWACreds.GetNetworkCredential().password; concurrentSession = 'true' } | ConvertTo-Json -Depth 9 -Compress
    try {
        $logonToken = Invoke-Rest -Command Post -URI $URL_Logon -Body $logonBody
        return $logonToken
    }
    catch {
        Throw 'Unable to establish a connection to CyberArk'
    }
}
#EndRegion '.\Private\PAS\Get-OnPremHeader.ps1' 27
#Region '.\Private\PAS\Get-VaultTime.ps1' -1

function Get-VaultTime {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [int]$EpochTime
    )

    process {
        # Convert epoch time to DateTime
        $dateTime = (Get-Date "1970-01-01 00:00:00Z").AddSeconds($EpochTime)
        return $dateTime
    }
}
#EndRegion '.\Private\PAS\Get-VaultTime.ps1' 14
#Region '.\Private\Shared\Format-PVWAURL.ps1' -1

function Format-PVWAURL {
    param (
        [Parameter()]
        [Alias("PCloudURL", "PAMURL")]
        [string]
        $PVWAURL,
        [Parameter()]
        [switch]
        $AllowInsecureURL
    )
    #check url scheme to ensure it's secure and add https if not present
    IF ($PVWAURL -match '^(?<scheme>https:\/\/|http:\/\/|).*$') {
        if ('http://' -eq $matches['scheme'] -and $AllowInsecureURL -eq $false) {
            $PVWAURL = $PVWAURL.Replace('http://', 'https://')
            Write-LogMessage -type Warning -MSG "Detected inscure scheme in URL `nThe URL was automaticly updated to: $PVWAURL `nPlease ensure you are using the correct scheme in the url"
        }
        elseif ([string]::IsNullOrEmpty($matches['scheme'])) {
            $PVWAURL = "https://$PVWAURL"
            Write-LogMessage -type Warning -MSG "Detected no scheme in URL `nThe URL was automaticly updated to: $PVWAURL `nPlease ensure you are using the correct scheme in the url"
        }
    }

    #check url for improper Privilege Cloud URL and add /PasswordVault/ if not present
    if ($PVWAURL -match '^(?:https|http):\/\/(?<sub>.*).cyberark.(?<top>cloud|com)\/privilegecloud.*$') {
        $PVWAURL = "https://$($matches['sub']).privilegecloud.cyberark.$($matches['top'])/PasswordVault/"
        Write-LogMessage -type Warning -MSG "Detected improperly formated Privilege Cloud URL `nThe URL was automaticly updated to: $PVWAURL `nPlease ensure you are using the correct URL. Pausing for 10 seconds to allow you to copy correct url.`n"
        Start-Sleep 10
    }
    elseif ($PVWAURL -notmatch '^.*PasswordVault(?:\/|)$') {
        $PVWAURL = "$PVWAURL/PasswordVault/"
        Write-LogMessage -type Warning -MSG "Detected improperly formated Privileged Access Manager URL `nThe URL was automaticly updated to: $PVWAURL `nPlease ensure you are using the correct URL. Pausing for 10 seconds to allow you to copy correct url.`n"
        Start-Sleep 10
    }
    return $PVWAURL
}
#EndRegion '.\Private\Shared\Format-PVWAURL.ps1' 36
#Region '.\Private\Shared\Get-CallerPreference.ps1' -1

function Get-CallerPreference {
  <#
.Synopsis
    Retrieves and sets caller preference variables.
  .DESCRIPTION
    The Get-CallerPreference function retrieves specific preference variables from the caller's session state and sets them in the current session state or a specified session state.
    It ensures that the preference variables such as ErrorActionPreference, VerbosePreference, and DebugPreference are correctly set based on the caller's context.
  .EXAMPLE
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    This example retrieves the caller preference variables from the current session state and sets them accordingly.
  .EXAMPLE
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $CustomSessionState
    This example retrieves the caller preference variables from the current session state and sets them in a custom session state.
  .INPUTS
    [System.Management.Automation.PSScriptCmdlet]
      The cmdlet from which to retrieve the caller preference variables.
    [System.Management.Automation.SessionState]
      The session state where the preference variables will be set.
  .OUTPUTS
    None
  .NOTES
    This function is useful for ensuring that preference variables are consistently set across different session states.
  .COMPONENT
    EPV-API-Common
  .ROLE
    Utility
  .FUNCTIONALITY
    Preference Management
  #>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateScript({ $_.GetType().FullName -eq 'System.Management.Automation.PSScriptCmdlet' })]
    $Cmdlet,
    [Parameter(Mandatory = $true)]
    [System.Management.Automation.SessionState]
    $SessionState
  )

  $vars = @{
    'ErrorView'             = $null
    'ErrorActionPreference' = 'ErrorAction'
    'VerbosePreference'     = 'Verbose'
    'DebugPreference'       = 'Debug'
  }

  foreach ($entry in $vars.GetEnumerator()) {
    if ([string]::IsNullOrEmpty($entry.Value) -or -not $Cmdlet.MyInvocation.BoundParameters.ContainsKey($entry.Value)) {
      $variable = $Cmdlet.SessionState.PSVariable.Get($entry.Key)
      if ($null -ne $variable) {
        if ($SessionState -eq $ExecutionContext.SessionState) {
          Set-Variable -Scope 1 -Name $variable.Name -Value $variable.Value -Force -Confirm:$false -WhatIf:$false
        } else {
          $SessionState.PSVariable.Set($variable.Name, $variable.Value)
        }
      }
    }
  }
}
#EndRegion '.\Private\Shared\Get-CallerPreference.ps1' 60
#Region '.\Private\Shared\Invoke-Rest.ps1' -1

<#
.SYNOPSIS
    Invokes a REST API call with the specified parameters.

.DESCRIPTION
    The Invoke-Rest function is designed to make REST API calls using various HTTP methods such as GET, POST, DELETE, PATCH, and PUT.
    It supports custom headers, request bodies, and content types. The function also includes error handling and logging mechanisms.

.PARAMETER Command
    Specifies the HTTP method to use for the REST API call.
    Valid values are 'GET', 'POST', 'DELETE', 'PATCH', and 'PUT'. This parameter is mandatory.

.PARAMETER URI
    Specifies the URI of the REST API endpoint. This parameter is mandatory.

.PARAMETER Header
    Specifies the headers to include in the REST API call. This parameter is optional.

.PARAMETER Body
    Specifies the body content to include in the REST API call. This parameter is optional.

.PARAMETER ContentType
    Specifies the content type of the request body. The default value is 'application/json'. This parameter is optional.

.PARAMETER ErrAction
    Specifies the action to take if an error occurs.
    Valid values are 'Continue', 'Ignore', 'Inquire', 'SilentlyContinue', 'Stop', and 'Suspend'. The default value is 'Continue'. This parameter is optional.

.EXAMPLE
    Invoke-Rest -Command GET -URI "https://api.example.com/data" -Header @{Authorization = "Bearer token"}

    This example makes a GET request to the specified URI with an authorization header.

.EXAMPLE
    Invoke-Rest -Command POST -URI "https://api.example.com/data" -Body '{"name":"value"}' -ContentType "application/json"

    This example makes a POST request to the specified URI with a JSON body.

.NOTES
    This function includes extensive logging for debugging purposes. It logs the entry and exit points, as well as detailed information about the request and response.
#>

function Invoke-Rest {
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Scope = 'Function', Justification = 'Used in deep debugging')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Alias('Method')]
        [ValidateSet('GET', 'POST', 'DELETE', 'PATCH', 'PUT')]
        [String]$Command,

        [Alias('PCloudURL', 'IdentityURL', 'URL')]
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$URI,

        [Alias('LogonToken', 'Headers')]
        [Parameter(Mandatory = $false)]
        $Header,

        [Parameter(Mandatory = $false)]
        $Body,

        [Parameter(Mandatory = $false)]
        [String]$ContentType = 'application/json',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Continue', 'Ignore', 'Inquire', 'SilentlyContinue', 'Stop', 'Suspend')]
        [String]$ErrAction = 'Continue',

        [Parameter(Mandatory = $false)]
        [Microsoft.PowerShell.Commands.WebRequestSession][ref]$WebSession,

        [Parameter(Mandatory = $false)]
        [String]$SessionVariable,

        [Parameter(Mandatory = $false, DontShow = $true)]
        [switch]$WaitInProgress,

        [Parameter(Mandatory = $false, DontShow = $true)]
        [int]$WaitCount = 0,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSec = 0
    )

    process {
        if ($WaitInProgress) {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tEntering Invoke-Rest but WaitInProgress is true, suppressing standard logging. Loop number: $WaitCount"
        }
        else {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tEntering Invoke-Rest"
        }
        $restResponse = ''
        try {
            if (!$WaitInProgress) {
                Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tCommand:`t$Command`tURI:  $URI"
            }
            $RestCall = @{
                Uri         = $URI
                Method      = $Command
                ContentType = $ContentType
                TimeoutSec  = $TimeoutSec
                ErrorAction = $ErrAction
            }
            if ($WaitInProgress) {
                $restCall.Add('Verbose', $false)
                $restCall.Add('Debug', $false)
            }
            if ($Header) {
                if (!$WaitInProgress) {
                    Write-LogMessage -type Verbose -MSG "Header Found: `t$Header"
                }
                if ($Header -isnot [System.Collections.IDictionary]) {
                    $Header = @{Authorization = $Header }
                }
                $WebSession.Headers.Authorization = $Header.Authorization
            }
            if ($WebSession) {
                if (!$WaitInProgress) {
                    Write-LogMessage -type Verbose -MSG "WebSession Found: `t$($WebSession |ConvertTo-Json -Depth 9 -Compress)"
                }
                $RestCall.Add('WebSession', $WebSession)
            }
            elseif ($SessionVariable) {
                if (!$WaitInProgress) {
                    Write-LogMessage -type Verbose -MSG "SessionVariable Found: `t$SessionVariable"
                }
                $RestCall.Add('SessionVariable', $SessionVariable)
            }
            else {
                $SessionVariable = 'IdentitySession'
                if (!$WaitInProgress) {
                    Write-LogMessage -type Verbose -MSG "SessionVariable Not Found: `tSetting to $SessionVariable"
                }$RestCall.Add('SessionVariable', $SessionVariable)
            }
            if ($Body) {
                if (!$WaitInProgress) {
                    Write-LogMessage -type Verbose -MSG "Body Found: `t$($Body | ConvertTo-Json -Depth 9 -Compress)"
                }
                $RestCall.Add('Body', $Body)
            }

            $restResponse = Invoke-RestMethod @RestCall

        }
        catch [System.Net.WebException] {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tCaught WebException"
            if ($ErrAction -match ('\bContinue\b|\bInquire\b|\bStop\b|\bSuspend\b')) {
                Write-LogMessage -type Error -MSG "Error Message: $PSItem"
                Write-LogMessage -type Error -MSG "Exception Message: $($PSItem.Exception.Message)"
                Write-LogMessage -type Error -MSG "Status Code: $($PSItem.Exception.Response.StatusCode.value__)"
                Write-LogMessage -type Error -MSG "Status Description: $($PSItem.Exception.Response.StatusDescription)"
                $restResponse = $null
                throw
                Else {
                    throw $PSItem
                }
            }
        }
        catch [Microsoft.PowerShell.Commands.HttpResponseException] {
            if ('500' -eq $PSItem.Exception.StatusCode.value__ -and $URI -match '.*discovered-accounts/onboard/bulk.*') {
                Write-LogMessage -type Verbose -MSG 'Possible overload detected during bulk submission, sending back to function to process'
                throw $PSItem
            }
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tCaught HttpResponseException"
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tCommand:`t$Command`tURI:  $URI"
            if (-not [string]::IsNullOrEmpty($Body)) {
                Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tBody:`t $Body"
            }
            try {
                if ($PSItem.ErrorDetails.Message) {
                    Write-LogMessage -type Error -MSG $PSItem.ErrorDetails.Message
                    try {
                        $Details = ($PSItem.ErrorDetails.Message | ConvertFrom-Json)
                    }
                    catch {
                        $details = $PSitem.ErrorDetails.message
                    }
                }
            }
            catch {
                Write-LogMessage -type Error -MSG "Invoke-Rest:`tError in parsing ErrorDetails: $($PSItem.ErrorDetails)"
                Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tExiting Invoke-Rest"
                throw $PSItem
            }
            if ('SFWS0007' -eq $Details.ErrorCode) {
                Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.ErrorMessage)"
                throw $PSItem
            }
            elseif ('ITATS127E' -eq $Details.ErrorCode) {
                Write-LogMessage -type Error -MSG 'Was able to connect to the PVWA successfully, but the account was locked'
                Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.ErrorMessage)"
                throw [System.Management.Automation.RuntimeException] 'Account Locked'
            }
            elseif ('PASWS013E' -eq $Details.ErrorCode) {
                Write-LogMessage -type Error -MSG "$($Details.ErrorMessage)" -Header -Footer
            }
            elseif ('SFWS0002' -eq $Details.ErrorCode) {
                Write-LogMessage -type Warning -MSG "$($Details.ErrorMessage)"
                throw "$($Details.ErrorMessage)"
            }
            if ('SFWS0012' -eq $Details.ErrorCode) {
                Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.ErrorMessage)"
                throw $PSItem
            }
            if ('SFWS0015' -eq $Details.ErrorCode) {
                Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.ErrorMessage)"
                throw $PSItem
            }
            elseif (!($errorDetails.ErrorCode -in $global:SkipErrorCode)) {
                Write-LogMessage -type Error -MSG 'Was able to connect to the PVWA successfully, but the command resulted in an error'
                Write-LogMessage -type Error -MSG "Returned ErrorCode: $($errorDetails.ErrorCode)"
                Write-LogMessage -type Error -MSG "Returned ErrorMessage: $($errorDetails.ErrorMessage)"
                Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tExiting Invoke-Rest"
                throw $PSItem
            }
            else {
                Write-LogMessage -type Error -MSG "Error in running '$Command' on '$URI', $($details.ErrorMessage)"
                throw $PSItem
            }
        }
        catch {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tCaught Exception"
            if ($ErrAction -ne 'SilentlyContinue') {
                Write-LogMessage -type Error -MSG "Error in running $Command on '$URI', $PSItem.Exception"
                Write-LogMessage -type Error -MSG "Error Message: $PSItem"
            }
            else {
                Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tError in running $Command on '$URI', $PSItem.Exception"
                Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tError Message: $PSItem"
            }
            throw $(New-Object System.Exception ("Error in running $Command on '$URI'", $PSItem.Exception))
        }
        if (!$WaitInProgress) {
            if ($URI -match 'Password/Retrieve') {
                Write-LogMessage -type Verbose -MSG 'Invoke-Rest:`tInvoke-REST Response: ***********'
            }
            else {
                if ($global:SuperVerbose) {
                    Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tInvoke-REST Response Type: $($restResponse.GetType().Name)"
                    $type = $restResponse.GetType().Name
                    if ('String' -ne $type) {
                        Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tInvoke-REST ConvertTo-Json Response: $($restResponse | ConvertTo-Json -Depth 9 -Compress)"
                    }
                    else {
                        Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tInvoke-REST Response: $restResponse"
                    }
                }
                else {
                    Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tInvoke-REST Response: $restResponse"
                }
            }
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tExiting Invoke-Rest"
        }
        return $restResponse
    }
}
#EndRegion '.\Private\Shared\Invoke-Rest.ps1' 259
#Region '.\Private\Shared\Invoke-RestNextCurser.ps1' -1

<#
.SYNOPSIS
Invokes a REST API call and handles pagination if necessary.

.DESCRIPTION
The Invoke-RestNextLink function sends a REST API request using the specified HTTP method and URI.
It supports pagination by following the 'NextLink' property in the response. If pagination is disabled,
it returns only the initial set of results.

.PARAMETER Command
Specifies the HTTP method to use for the REST API call. Valid values are 'GET', 'POST', 'DELETE', 'PATCH', and 'PUT'.

.PARAMETER URI
Specifies the URI for the REST API call. This parameter is mandatory and cannot be null or empty.

.PARAMETER Header
Specifies the headers to include in the REST API call. This parameter is optional.

.PARAMETER ContentType
Specifies the content type for the REST API call. The default value is 'application/json'.

.PARAMETER ErrAction
Specifies the action to take if an error occurs during the REST API call. Valid values are 'Continue', 'Ignore', 'Inquire', 'SilentlyContinue', 'Stop', and 'Suspend'. The default value is 'Continue'.

.RETURNS
Returns an array of PSCustomObject containing the results of the REST API call.

.EXAMPLE
Invoke-RestNextLink -Command GET -URI "https://api.example.com/resource" -Header $header

This example sends a GET request to the specified URI with the provided headers and handles pagination if necessary.

.NOTES
This function uses the Invoke-Rest function to send the REST API request and handles pagination by following the 'NextLink' property in the response.
#>
Function Invoke-RestNextCursor {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Alias('Method')]
        [ValidateSet('GET', 'POST', 'DELETE', 'PATCH', 'PUT')]
        [String]$Command,

        [Alias('PCloudURL', 'IdentityURL', 'URL')]
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$URI,

        [Alias('LogonToken', 'Headers')]
        [Parameter(Mandatory = $false)]
        $Header,

        [Parameter(Mandatory = $false)]
        [String]$ContentType = 'application/json',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Continue', 'Ignore', 'Inquire', 'SilentlyContinue', 'Stop', 'Suspend')]
        [String]$ErrAction = 'Continue'
    )

    $restResponse = Invoke-Rest -Uri $URI -Method $Command -Headers $Header -ContentType $ContentType -ErrorAction $ErrAction
    [PSCustomObject[]]$resultList = $restResponse.items

    if (-not [string]::IsNullOrEmpty($restResponse.nextCursor)) {

        [system.uri]$uri = [system.uri]$URI
        $BaseURL = $URI.AbsoluteUri.Replace($URI.PathAndQuery,"")
        if ($DoNotPage) {
            Write-LogMessage -Type Verbose -MSG "A total of $($resultList.Count) results found, but paging is disabled. Returning only $($resultList.Count) results"
        } else {
            do {
                Write-LogMessage -Type Verbose -MSG "nextCursor found, getting next page"
                $restResponse = Invoke-Rest -Uri "$BaseURL/$($restResponse.nextCursor)" -Method $Command
                $resultList += $restResponse.items
            } until ([string]::IsNullOrEmpty($restResponse.nextCursor))
        }
    } else {
        Write-LogMessage -Type Verbose -MSG "Found $($resultList.Count) results"
    }

    return $resultList
}
#EndRegion '.\Private\Shared\Invoke-RestNextCurser.ps1' 83
#Region '.\Private\Shared\Invoke-RestNextLink.ps1' -1

<#
.SYNOPSIS
Invokes a REST API call and handles pagination if necessary.

.DESCRIPTION
The Invoke-RestNextLink function sends a REST API request using the specified HTTP method and URI.
It supports pagination by following the 'NextLink' property in the response. If pagination is disabled,
it returns only the initial set of results.

.PARAMETER Command
Specifies the HTTP method to use for the REST API call. Valid values are 'GET', 'POST', 'DELETE', 'PATCH', and 'PUT'.

.PARAMETER URI
Specifies the URI for the REST API call. This parameter is mandatory and cannot be null or empty.

.PARAMETER Header
Specifies the headers to include in the REST API call. This parameter is optional.

.PARAMETER ContentType
Specifies the content type for the REST API call. The default value is 'application/json'.

.PARAMETER ErrAction
Specifies the action to take if an error occurs during the REST API call. Valid values are 'Continue', 'Ignore', 'Inquire', 'SilentlyContinue', 'Stop', and 'Suspend'. The default value is 'Continue'.

.RETURNS
Returns an array of PSCustomObject containing the results of the REST API call.

.EXAMPLE
Invoke-RestNextLink -Command GET -URI "https://api.example.com/resource" -Header $header

This example sends a GET request to the specified URI with the provided headers and handles pagination if necessary.

.NOTES
This function uses the Invoke-Rest function to send the REST API request and handles pagination by following the 'NextLink' property in the response.
#>
Function Invoke-RestNextLink {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Alias('Method')]
        [ValidateSet('GET', 'POST', 'DELETE', 'PATCH', 'PUT')]
        [String]$Command,

        [Alias('PCloudURL', 'IdentityURL', 'URL')]
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$URI,

        [Alias('LogonToken', 'Headers')]
        [Parameter(Mandatory = $false)]
        $Header,

        [Parameter(Mandatory = $false)]
        [String]$ContentType = 'application/json',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Continue', 'Ignore', 'Inquire', 'SilentlyContinue', 'Stop', 'Suspend')]
        [String]$ErrAction = 'Continue'
    )

    $restResponse = Invoke-Rest -Uri $URI -Method $Command -Headers $Header -ContentType $ContentType -ErrorAction $ErrAction
    [PSCustomObject[]]$resultList = $restResponse.value

    if (-not [string]::IsNullOrEmpty($restResponse.NextLink)) {

        [system.uri]$uri = [system.uri]$URI
        $BaseURL = "$($URI.AbsoluteUri.Replace($URI.PathAndQuery,''))/PasswordVault/"
        if ($DoNotPage) {
            Write-LogMessage -Type Verbose -MSG "A total of $($resultList.Count) results found, but paging is disabled. Returning only $($resultList.Count) results"
        } else {
            do {
                Write-LogMessage -Type Verbose -MSG "NextLink found, getting next page"
                $restResponse = Invoke-Rest -Uri "$BaseURL/$($restResponse.NextLink)" -Method GET
                $resultList += $restResponse.value
            } until ([string]::IsNullOrEmpty($restResponse.NextLink))
        }
    } else {
        Write-LogMessage -Type Verbose -MSG "Found $($resultList.Count) results"
    }

    return $resultList
}
#EndRegion '.\Private\Shared\Invoke-RestNextLink.ps1' 83
#Region '.\Private\Shared\Load-Modules.ps1' -1

# Load the Base module
#Using Module .\Classes\Base.psm1

# Load the Safe module
#Using Module .\Classes\Safe.psm1

# Load the SafeMember module
#Using Module .\Classes\SafeMember.psm1

# Load the Account module
#Using Module .\Classes\Account.psm1

# Load the Comp module
#Using Module .\Classes\Comp.psm1

# Load the namespace to allow different colors with Write-LogMessage
#using namespace System.Management.Automation
#EndRegion '.\Private\Shared\Load-Modules.ps1' 18
#Region '.\Public\Identity\Directory\Get-DirectoryService.ps1' -1

<#
.Synopsis
    Get Identity Directories
.DESCRIPTION
    Get Identity Directories
.EXAMPLE
    Example of how to use this cmdlet
.EXAMPLE
    Another example of how to use this cmdlet
.INPUTS
    Inputs to this cmdlet (if any)
.OUTPUTS
    Output from this cmdlet (if any)
.NOTES
    General notes
.COMPONENT
    The component this cmdlet belongs to
.ROLE
    The role this cmdlet belongs to
.FUNCTIONALITY
    The functionality that best describes this cmdlet
#>
function Get-DirectoryService {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]
        $IdentityURL,

        [Alias('header')]
        $LogonToken,
        [switch]
        $IDOnly,
        [Parameter(ValueFromPipeline)]
        [Alias('DirID', 'DirectoryUUID')]
        [String[]]
        $DirectoryServiceUuid,
        [Parameter(ValueFromPipeline)]
        [string]
        $directoryName,
        [Parameter(ValueFromPipeline)]
        [string]
        $directoryService,
        [switch]
        $UuidOnly
    )
    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }
    Process {
        if ($DirectoryServiceUuid) {
            Write-LogMessage -type Verbose -MSG "Directory UUID Provided. Setting Search Directory to `"$DirectoryServiceUuid`""
            [PSCustomObject[]]$DirID = $DirectoryServiceUuid
        } elseif ($directoryName) {
            Write-LogMessage -type Verbose -MSG "Directory name provided. Searching for directory with the name of `"$directoryName`""
            $RestParms = @{
                Uri    = "$IdentityURL/Core/GetDirectoryServices"
                Method = 'Get'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $dirResult = Invoke-Rest @RestParms
            if ($dirResult.Success -and $dirResult.result.Count -ne 0) {
                Write-LogMessage -type Verbose -MSG "Found $($dirResult.result.Count) directories with the name of `"$directoryName`""
                if ($UuidOnly) {
                    [PSCustomObject[]]$DirID = $dirResult.result.Results.Row | Where-Object { $_.DisplayName -like "*$directoryName*" } | Select-Object -ExpandProperty directoryServiceUuid
                } else {
                    [PSCustomObject[]]$DirID = $dirResult.result.Results.Row | Where-Object { $_.DisplayName -like "*$directoryName*" }
                }
            }
        } elseif ($directoryService) {
            Write-LogMessage -type Verbose -MSG "Directory service provided. Searching for directory with the name of `"$directoryService`""
            $RestParms = @{
                Uri    = "$IdentityURL/Core/GetDirectoryServices"
                Method = 'Get'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $dirResult = Invoke-Rest @RestParms
            if ($dirResult.Success -and $dirResult.result.Count -ne 0) {
                Write-LogMessage -type Verbose -MSG "Found $($dirResult.result.Count) directories with the service type of `"$directoryService`""
                if ($UuidOnly) {
                    [PSCustomObject[]]$DirID = $dirResult.result.Results.Row | Where-Object { $_.DisplayName -like "*$directoryService*" } | Select-Object -ExpandProperty directoryServiceUuid
                } else {
                    [PSCustomObject[]]$DirID = $dirResult.result.Results.Row | Where-Object { $_.DisplayName -like "*$directoryService*" }
                }
            }
        } else {
            Write-LogMessage -type Verbose -MSG 'No directory parameters passed. Gathering all directories, except federated'
            $RestParms = @{
                Uri    = "$IdentityURL/Core/GetDirectoryServices"
                Method = 'Get'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $dirResult = Invoke-Rest @RestParms
            if ($dirResult.Success -and $dirResult.result.Count -ne 0) {
                Write-LogMessage -type Verbose -MSG "Found $($dirResult.result.Count) directories"
                if ($UuidOnly) {
                    [PSCustomObject[]]$DirID = $dirResult.result.Results.Row | Select-Object -ExpandProperty directoryServiceUuid
                } else {
                    [PSCustomObject[]]$DirID = $dirResult.result.Results.Row
                }
            }
        }
        return $DirID
    }
}
#EndRegion '.\Public\Identity\Directory\Get-DirectoryService.ps1' 115
#Region '.\Public\Identity\Role\Add-IdentityRoleToGroup.ps1' -1

<#
.SYNOPSIS
Adds a specified identity role to one or more Groups.

.DESCRIPTION
The Add-IdentityRoleToGroup function assigns a specified role to one or more Groups by making a REST API call to update the role. It supports ShouldProcess for confirmation prompts and logs detailed messages about the operation.

.PARAMETER RoleName
The name of the role to be added to the Groups. This parameter is mandatory and accepts pipeline input.

.PARAMETER IdentityURL
The base URL of the identity service. This parameter is mandatory.

.PARAMETER LogonToken
The authentication token required to log on to the identity service. This parameter is mandatory.

.PARAMETER Group
An array of Group identifiers to which the role will be added. This parameter is mandatory and accepts pipeline input.

.EXAMPLE
PS> Add-IdentityRoleToGroup -RoleName "Admin" -IdentityURL "https://identity.example.com" -LogonToken $token -Group "Group1"

Adds the "Admin" role to the Group "Group1".

.EXAMPLE
PS> "Group1", "Group2" | Add-IdentityRoleToGroup -RoleName "Admin" -IdentityURL "https://identity.example.com" -LogonToken $token

Adds the "Admin" role to the Groups "Group1" and "Group2".

.NOTES
This function requires the Write-LogMessage and Invoke-Rest functions to be defined in the session.
#>
function Add-IdentityRoleToGroup {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('role')]
        [ValidateNotNullOrEmpty()]
        [string]
        $RoleName,

        [Alias('url')]
        [ValidateNotNullOrEmpty()]
        [string]
        $IdentityURL,

        [Alias('header')]
        $LogonToken,
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Groups', 'Member')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Group
    )
    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }
    Process {
        Write-LogMessage -type Verbose -MSG "Adding `"$Group`" to role `"$RoleName`""
        $rolesResult = Get-IdentityRole @PSBoundParameters -IDOnly

        if ($rolesResult.Count -eq 0) {
            Throw "Role `"$RoleName`" not found"
        }
        elseif ($rolesResult.Count -ge 2) {
            Throw "Multiple roles found, please enter a unique role name and try again"
        }
        else {
            $addGroupToRole = [PSCustomObject]@{
                Groups = [PSCustomObject]@{
                    Add = $Group
                }
                Name  = $rolesResult
            }
            try {
                if ($PSCmdlet.ShouldProcess($Group, 'Add-IdentityRoleToGroup')) {
                    Write-LogMessage -type Verbose -MSG "Adding `"$RoleName`" to Group `"$Group`""
                    $RestParms = @{
                        Uri    = "$IdentityURL/Roles/UpdateRole"
                        Method = 'POST'
                        Body   = ($addGroupToRole | ConvertTo-Json -Depth 99)
                    }
                    if ($null -ne $LogonToken -and $LogonToken -ne "") {
                        $RestParms.LogonToken = $LogonToken
                    }
                    $result = Invoke-Rest @RestParms
                    if ($result.success) {
                        if ($Group.Count -eq 1) {
                            Write-LogMessage -type Success -MSG "Role `"$RoleName`" added to Group `"$Group`""
                        }
                        else {
                            Write-LogMessage -type Success -MSG "Role `"$RoleName`" added to all Groups"
                        }
                    }
                    else {
                        if ($Group.Count -eq 1) {
                            Write-LogMessage -type Error -MSG "Error adding `"$RoleName`" to Group `"$Group`": $($result.Message)"
                        }
                        else {
                            Write-LogMessage -type Error -MSG "Error adding `"$RoleName`" to Groups: $($result.Message)"
                        }
                    }
                }
                else {
                    Write-LogMessage -type Warning -MSG "Skipping addition of role `"$RoleName`" to Group `"$Group`" due to confirmation being denied"
                }
            }
            catch {
                Write-LogMessage -type Error -MSG "Error while trying to add Groups to `"$RoleName`": $_"
            }
        }
    }
}
#EndRegion '.\Public\Identity\Role\Add-IdentityRoleToGroup.ps1' 116
#Region '.\Public\Identity\Role\Add-IdentityRoleToUser.ps1' -1

<#
.SYNOPSIS
Adds a specified identity role to one or more users.

.DESCRIPTION
The Add-IdentityRoleToUser function assigns a specified role to one or more users by making a REST API call to update the role. It supports ShouldProcess for confirmation prompts and logs detailed messages about the operation.

.PARAMETER RoleName
The name of the role to be added to the users. This parameter is mandatory and accepts pipeline input.

.PARAMETER IdentityURL
The base URL of the identity service. This parameter is mandatory.

.PARAMETER LogonToken
The authentication token required to log on to the identity service. This parameter is mandatory.

.PARAMETER User
An array of user identifiers to which the role will be added. This parameter is mandatory and accepts pipeline input.

.EXAMPLE
PS> Add-IdentityRoleToUser -RoleName "Admin" -IdentityURL "https://identity.example.com" -LogonToken $token -User "user1"

Adds the "Admin" role to the user "user1".

.EXAMPLE
PS> "user1", "user2" | Add-IdentityRoleToUser -RoleName "Admin" -IdentityURL "https://identity.example.com" -LogonToken $token

Adds the "Admin" role to the users "user1" and "user2".

.NOTES
This function requires the Write-LogMessage and Invoke-Rest functions to be defined in the session.
#>
function Add-IdentityRoleToUser {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('role')]
        [ValidateNotNullOrEmpty()]
        [string]
        $RoleName,

        [Alias('url')]
        [ValidateNotNullOrEmpty()]
        [string]
        $IdentityURL,

        [Alias('header')]
        $LogonToken,
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Users', 'Member')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $User
    )
    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }
    Process {
        Write-LogMessage -type Verbose -MSG "Adding `"$User`" to role `"$RoleName`""
        $rolesResult = Get-IdentityRole @PSBoundParameters -IDOnly

        if ($rolesResult.Count -eq 0) {
            Throw "Role `"$RoleName`" not found"
        }
        elseif ($rolesResult.Count -ge 2) {
            Throw "Multiple roles found, please enter a unique role name and try again"
        }
        else {
            $addUserToRole = [PSCustomObject]@{
                Users = [PSCustomObject]@{
                    Add = $User
                }
                Name  = $rolesResult
            }
            try {
                if ($PSCmdlet.ShouldProcess($User, 'Add-IdentityRoleToUser')) {
                    Write-LogMessage -type Verbose -MSG "Adding `"$RoleName`" to user `"$User`""
                    $RestParms = @{
                        Uri    = "$IdentityURL/Roles/UpdateRole"
                        Method = 'POST'
                        Body   = ($addUserToRole | ConvertTo-Json -Depth 99)
                    }
                    if ($null -ne $LogonToken -and $LogonToken -ne "") {
                        $RestParms.LogonToken = $LogonToken
                    }
                    $result = Invoke-Rest @RestParms
                    if ($result.success) {
                        if ($User.Count -eq 1) {
                            Write-LogMessage -type Success -MSG "Role `"$RoleName`" added to user `"$User`""
                        }
                        else {
                            Write-LogMessage -type Success -MSG "Role `"$RoleName`" added to all users"
                        }
                    }
                    else {
                        if ($User.Count -eq 1) {
                            Write-LogMessage -type Error -MSG "Error adding `"$RoleName`" to user `"$User`": $($result.Message)"
                        }
                        else {
                            Write-LogMessage -type Error -MSG "Error adding `"$RoleName`" to users: $($result.Message)"
                        }
                    }
                }
                else {
                    Write-LogMessage -type Warning -MSG "Skipping addition of role `"$RoleName`" to user `"$User`" due to confirmation being denied"
                }
            }
            catch {
                Write-LogMessage -type Error -MSG "Error while trying to add users to `"$RoleName`": $_"
            }
        }
    }
}
#EndRegion '.\Public\Identity\Role\Add-IdentityRoleToUser.ps1' 116
#Region '.\Public\Identity\Role\Get-IdentityGroup.ps1' -1

<#
.SYNOPSIS
Retrieves identity group information from a specified identity URL.

.DESCRIPTION
The Get-IdentityGroup function retrieves information about identity groups from a specified identity URL.
It supports retrieving all groups or a specific group by name. The function can also return only the ID of the group if specified.

.PARAMETER IdentityURL
The URL of the identity service to query.

.PARAMETER LogonToken
The logon token used for authentication with the identity service.

.PARAMETER GroupName
The name of the group to retrieve information for. This parameter is mandatory when using the "GroupName" parameter set.

.PARAMETER IDOnly
A switch to specify if only the ID of the group should be returned.

.PARAMETER AllGroups
A switch to specify if all groups should be retrieved. This parameter is mandatory when using the "AllGroups" parameter set.

.EXAMPLE
Get-IdentityGroup -IdentityURL "https://identity.example.com" -LogonToken $token -GroupName "Admins"

This example retrieves information about the "Admins" group from the specified identity URL.

.EXAMPLE
Get-IdentityGroup -IdentityURL "https://identity.example.com" -LogonToken $token -AllGroups

This example retrieves information about all groups from the specified identity URL.

.NOTES
The function uses Invoke-Rest to query the identity service and requires appropriate permissions to access the service.
#>

function Get-IdentityGroup {
    [CmdletBinding(DefaultParameterSetName = "GroupName")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]
        $IdentityURL,

        [Alias('header')]
        $LogonToken,
        [Parameter( ValueFromPipeline, ParameterSetName = "GroupName")]
        [Alias('Group')]
        [string]
        $GroupName,
        [switch]
        $IDOnly,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = "AllGroups")]
        [switch]
        $AllGroups
    )
    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }
    Process {
        if ($AllGroups) {
            Write-LogMessage -type Verbose -Message "Attempting to locate all groups"
            $Groups = [PSCustomObject]@{
                '_or' = [PSCustomObject]@{
                    'DisplayName' = [PSCustomObject]@{
                        '_like' = ""
                    }
                },
                [PSCustomObject]@{
                    'SystemName' = [PSCustomObject]@{
                        '_like' = [PSCustomObject]@{
                            value      = ""
                            ignoreCase = 'true'
                        }
                    }
                }
            }
        }
        else {
            Write-LogMessage -type Verbose -Message "Attempting to locate Identity Group named `"$GroupName`""
            $Group = $GroupName.Trim()
            $Groups = [PSCustomObject]@{
                '_or' = [PSCustomObject]@{
                    'DisplayName' = [PSCustomObject]@{
                        '_like' = $Group
                    }
                },
                [PSCustomObject]@{
                    'SystemName' = [PSCustomObject]@{
                        '_like' = [PSCustomObject]@{
                            value      = $Group
                            ignoreCase = 'true'
                        }
                    }
                }
            }
        }

        $GroupQuery = [PSCustomObject]@{
            'group' = "$($Groups | ConvertTo-Json -Depth 99 -Compress)"
            'Args'  = [PSCustomObject]@{
                'PageNumber' = 1
                'PageSize'   = 100000
                'Limit'      = 100000
                'SortBy'     = ''
                'Caching'    = -1
            }
        }

        Write-LogMessage -type Verbose -Message "Gathering Directories"
        $RestParms = @{
            Uri    = "$IdentityURL/Core/GetDirectoryServices"
            Method = 'Get'
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $DirResult = Invoke-Rest @RestParms

        if ($DirResult.Success -and $DirResult.result.Count -ne 0) {
            Write-LogMessage -type Verbose -Message "Located $($DirResult.result.Count) Directories"
            Write-LogMessage -type Verbose -Message "Directory results: $($DirResult.result.Results.Row | ConvertTo-Json -Depth 99 -Compress)"
            [string[]]$DirID = $DirResult.result.Results.Row | Where-Object { $_.Service -eq 'ADProxy' } | Select-Object -ExpandProperty directoryServiceUuid
            $GroupQuery | Add-Member -Type NoteProperty -Name 'directoryServices' -Value $DirID -Force
        }

        Write-LogMessage -type Verbose -Message "Body set to : `"$($GroupQuery | ConvertTo-Json -Depth 99 -Compress)`""
        $RestParms = @{
            Uri    = "$IdentityURL/UserMgmt/DirectoryServiceQuery"
            Method = 'POST'
            Body   = ($GroupQuery | ConvertTo-Json -Depth 99 -Compress)
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $Result = Invoke-Rest @RestParms
        Write-LogMessage -type Verbose -Message "Result set to : `"$($Result | ConvertTo-Json -Depth 99 -Compress)`""

        if (!$Result.Success) {
            Write-LogMessage -type Error -Message $Result.Message
            return
        }

        if ($Result.Result.Groups.Results.FullCount -eq 0) {
            Write-LogMessage -type Warning -Message 'No Group found'
            return
        }
        else {
            if ($IDOnly) {
                Write-LogMessage -type Verbose -Message "Returning ID of Group `"$GroupName`""
                return $Result.Result.Group.Results.row.InternalName
            }
            else {
                Write-LogMessage -type Verbose -Message "Returning all information about Group `"$GroupName`""
                return $Result.Result.Group.Results.row
            }
        }
    }
}
#EndRegion '.\Public\Identity\Role\Get-IdentityGroup.ps1' 163
#Region '.\Public\Identity\Role\Get-IdentityRole.ps1' -1

<#
.SYNOPSIS
Retrieves identity roles from the specified identity URL.

.DESCRIPTION
The Get-IdentityRole function retrieves identity roles from a specified identity URL. It supports retrieving a specific role by name or all roles. The function can return either the full role information or just the role ID.

.PARAMETER IdentityURL
The URL of the identity service.

.PARAMETER LogonToken
The logon token used for authentication.

.PARAMETER roleName
The name of the role to retrieve. This parameter is mandatory when using the "RoleName" parameter set.

.PARAMETER IDOnly
A switch to indicate if only the role ID should be returned.

.PARAMETER AllRoles
A switch to indicate if all roles should be retrieved. This parameter is mandatory when using the "AllRoles" parameter set.

.EXAMPLE
Get-IdentityRole -IdentityURL "https://identity.example.com" -LogonToken $token -roleName "Admin"
Retrieves the role information for the role named "Admin".

.EXAMPLE
Get-IdentityRole -IdentityURL "https://identity.example.com" -LogonToken $token -AllRoles
Retrieves all roles from the identity service.

.NOTES
The function uses REST API calls to interact with the identity service.
#>

function Get-IdentityRole {
    [CmdletBinding(DefaultParameterSetName = "RoleName")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]
        $IdentityURL,

        [Alias('header')]
        $LogonToken,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = "roleName")]
        [Alias('role')]
        [string]
        $roleName,
        [switch]
        $IDOnly,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = "AllRoles")]
        [switch]
        $AllRoles
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }

    Process {
        if ($AllRoles) {
            $query = [PSCustomObject]@{ script = "SELECT Role.Name, Role.ID FROM Role" }
            $RestParms = @{
                Uri    = "$IdentityURL/Redrock/Query"
                Method = 'POST'
                Body   = ($query | ConvertTo-Json -Depth 99)
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $result = Invoke-Rest @RestParms
            return $result.result.results.Row  |Select-Object -Property Name, ID
        }

        Write-LogMessage -type Verbose -MSG "Attempting to locate Identity Role named `"$roleName`""
        $roles = [PSCustomObject]@{
            '_or' = [PSCustomObject]@{
                '_ID' = [PSCustomObject]@{ '_like' = $roleName }
            },
            [PSCustomObject]@{
                'Name' = [PSCustomObject]@{
                    '_like' = [PSCustomObject]@{
                        value      = $roleName
                        ignoreCase = 'true'
                    }
                }
            }
        }

        $rolequery = [PSCustomObject]@{
            'roles' = ($roles | ConvertTo-Json -Depth 99 -Compress)
            'Args'  = [PSCustomObject]@{
                'PageNumber' = 1
                'PageSize'   = 100000
                'Limit'      = 100000
                'SortBy'     = ''
                'Caching'    = -1
            }
        }

        Write-LogMessage -type Verbose -MSG "Gathering Directories"
        $RestParms = @{
            Uri    = "$IdentityURL/Core/GetDirectoryServices"
            Method = 'Get'
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $dirResult = Invoke-Rest @RestParms

        if ($dirResult.Success -and $dirResult.result.Count -ne 0) {
            Write-LogMessage -type Verbose -MSG "Located $($dirResult.result.Count) Directories"
            Write-LogMessage -type Verbose -MSG "Directory results: $($dirResult.result.Results.Row)"
            [string[]]$DirID = $dirResult.result.Results.Row | Where-Object { $_.Service -eq 'CDS' } | Select-Object -ExpandProperty directoryServiceUuid
            $rolequery | Add-Member -Type NoteProperty -Name 'directoryServices' -Value $DirID -Force
        }

        $RestParms = @{
            Uri    = "$IdentityURL/UserMgmt/DirectoryServiceQuery"
            Method = 'POST'
            Body   = ($rolequery | ConvertTo-Json -Depth 99)
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $result = Invoke-Rest @RestParms

        if (!$result.Success) {
            Write-LogMessage -type Error -MSG $result.Message
            return
        }

        if ($result.Result.roles.Results.Count -eq 0) {
            Write-LogMessage -type Warning -MSG 'No role found'
            return
        }
        else {
            if ($IDOnly) {
                Write-LogMessage -type Verbose -MSG "Returning ID of role `"$roleName`""
                return $result.Result.roles.Results.Row._ID
            }
            else {
                Write-LogMessage -type Verbose -MSG "Returning all information about role `"$roleName`""
                return $result.Result.roles.Results.Row
            }
        }
    }
}
#EndRegion '.\Public\Identity\Role\Get-IdentityRole.ps1' 151
#Region '.\Public\Identity\Role\Get-IdentityRoleInDir.ps1' -1

<#
.SYNOPSIS
Retrieves identity roles and rights from a specified directory.

.DESCRIPTION
The Get-IdentityRoleInDir function sends a POST request to the specified IdentityURL to retrieve roles and rights for a given directory. The function requires an identity URL, a logon token, and a directory identifier.

.PARAMETER IdentityURL
The URL of the identity service endpoint.

.PARAMETER LogonToken
The logon token used for authentication.

.PARAMETER Directory
The unique identifier of the directory service.

.EXAMPLE
PS> Get-IdentityRoleInDir -IdentityURL "https://example.com" -LogonToken $token -Directory "12345"
This example retrieves the roles and rights for the directory with the identifier "12345" from the specified identity service URL.

.NOTES
The function removes the CatchAll parameter from the bound parameters before processing the request.
#>
function Get-IdentityRoleInDir {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]
        $IdentityURL,

        [Alias('header')]
        $LogonToken,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('DirectoryServiceUuid', '_ID')]
        [string]
        $Directory
    )
    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }
    Process {
        $RestParms = @{
            Uri    = "$IdentityURL/Core/GetDirectoryRolesAndRights?path=$Directory"
            Method = 'POST'
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $result = Invoke-Rest @RestParms
        return $result.result.Results.Row
    }
}
#EndRegion '.\Public\Identity\Role\Get-IdentityRoleInDir.ps1' 56
#Region '.\Public\Identity\Role\Get-IdentityRoleMember.ps1' -1

<#
.SYNOPSIS
Retrieves members of a specified identity role.

.DESCRIPTION
The Get-IdentityRoleMember function sends a POST request to the specified Identity URL to retrieve members of a role identified by its UUID. The function requires a logon token for authentication.

.PARAMETER IdentityURL
The base URL of the identity service.

.PARAMETER LogonToken
The authentication token required to access the identity service.

.PARAMETER UUID
The unique identifier of the role whose members are to be retrieved.

.EXAMPLE
PS> Get-IdentityRoleMember -IdentityURL "https://identity.example.com" -LogonToken $token -UUID "12345"

.NOTES
The function removes any additional parameters passed to it using the CatchAll parameter.
#>
function Get-IdentityRoleMember {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]
        $IdentityURL,

        [Alias('header')]
        $LogonToken,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [Alias('role', '_ID', "ID")]
        [string]
        $UUID,
        [switch]
        $IncludeRoleName
    )
    Begin {
        $PSBoundParameters.Remove("CatchAll")  | Out-Null
        IF ($includeName) {
            $roleName = (Get-IdentityRole -roleName $uuid).Name
        }
    }
    process {
        $RestParms = @{
            Uri    = "$IdentityURL/Roles/GetRoleMembers?name=$UUID"
            Method = 'POST'
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $result = Invoke-Rest @RestParms
        If (-not [string]::IsNullOrEmpty($result.result.Results.Row)) {
            $result.result.Results.Row | Add-Member -MemberType NoteProperty -Name "RoleUUID" -Value $UUID
            if ($includeName) {
                $result.result.Results.Row | Add-Member -MemberType NoteProperty -Name "RoleName" -Value $roleName
            }
            Return $result.result.Results.Row
        }

    }
}
#EndRegion '.\Public\Identity\Role\Get-IdentityRoleMember.ps1' 67
#Region '.\Public\Identity\Role\New-IdentityRole.ps1' -1

<#
.SYNOPSIS
Creates a new identity role.

.DESCRIPTION
The `New-IdentityRole` function creates a new identity role with specified parameters such as role name, role type, users, roles, and groups. It sends a POST request to the specified Identity URL to store the role.

.PARAMETER IdentityURL
The URL of the identity service where the role will be created.

.PARAMETER LogonToken
The logon token used for authentication.

.PARAMETER roleName
The name of the role to be created.

.PARAMETER Description
A description of the role.

.PARAMETER RoleType
The type of the role. Valid values are 'PrincipalList', 'Script', and 'Everybody'. Default is 'PrincipalList'.

.PARAMETER Users
An array of users to be added to the role.

.PARAMETER Roles
An array of roles to be added to the role.

.PARAMETER Groups
An array of groups to be added to the role.

.EXAMPLE
PS> New-IdentityRole -IdentityURL "https://identity.example.com" -LogonToken $token -roleName "Admin" -Description "Administrator role" -RoleType "PrincipalList" -Users "user1", "user2"

Creates a new role named "Admin" with the specified users.

.NOTES
The function supports ShouldProcess for safety and confirmation prompts.
#>
function New-IdentityRole {
    [CmdletBinding(
        SupportsShouldProcess,
        ConfirmImpact = 'High'
    )]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]
        $IdentityURL,

        [Alias('header')]
        $LogonToken,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]
        $roleName,
        [Alias('desc')]
        [string]
        $Description,
        [ValidateSet('PrincipalList', 'Script', 'Everybody')]
        [string]
        $RoleType = 'PrincipalList',
        [Alias('User')]
        [string[]]
        $Users,
        [Alias('Role')]
        [string[]]
        $Roles,
        [Alias('Group')]
        [string[]]
        $Groups
    )
    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }
    Process {
        Write-LogMessage -type Verbose -MSG "Creating new Role named `"$roleName`""
        $body = [PSCustomObject]@{
            Name     = $roleName
            RoleType = $RoleType
        }
        if ($Users) {
            Write-LogMessage -type Verbose -MSG "Adding users `"$Users`" to new Role named `"$roleName`""
            $body | Add-Member -MemberType NoteProperty -Name Users -Value $Users
        }
        if ($Roles) {
            Write-LogMessage -type Verbose -MSG "Adding roles `"$Roles`" to new Role named `"$roleName`""
            $body | Add-Member -MemberType NoteProperty -Name Roles -Value $Roles
        }
        if ($Groups) {
            Write-LogMessage -type Verbose -MSG "Adding groups `"$Groups`" to new Role named `"$roleName`""
            $body | Add-Member -MemberType NoteProperty -Name Groups -Value $Groups
        }
        if ($PSCmdlet.ShouldProcess($roleName, 'New-IdentityRole')) {
            Write-LogMessage -type Verbose -MSG "Creating role named `"$roleName`""
            $RestParms = @{
                Uri    = "$IdentityURL/Roles/StoreRole"
                Method = 'POST'
                Body   = ($body | ConvertTo-Json -Depth 99)
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $result = Invoke-Rest @RestParms
            if (!$result.Success) {
                Write-LogMessage -type Error -MSG $result.Message
                return
            }
            else {
                Write-LogMessage -type Success -MSG "New Role named `"$roleName`" created"
                return $result.Result._RowKey
            }
        }
        else {
            Write-LogMessage -type Warning -MSG "Skipping addition of role `"$roleName`" due to confirmation being denied"
        }
    }
}
#EndRegion '.\Public\Identity\Role\New-IdentityRole.ps1' 120
#Region '.\Public\Identity\Role\Remove-IdentityRole.ps1' -1

<#
.SYNOPSIS
Removes an identity role from the system.

.DESCRIPTION
The Remove-IdentityRole function removes a specified identity role from the system.
It supports confirmation prompts and can be forced to bypass confirmation.
The function logs messages at various stages of execution.

.PARAMETER Force
A switch to force the removal without confirmation.

.PARAMETER IdentityURL
The URL of the identity service.

.PARAMETER LogonToken
The logon token for authentication.

.PARAMETER Role
The name of the role to be removed.

.EXAMPLE
Remove-IdentityRole -IdentityURL "https://example.com" -LogonToken $token -Role "Admin"

This command removes the "Admin" role from the identity service at "https://example.com".

.EXAMPLE
Remove-IdentityRole -IdentityURL "https://example.com" -LogonToken $token -Role "Admin" -Force

This command forcefully removes the "Admin" role from the identity service at "https://example.com" without confirmation.

.NOTES
The function logs messages at various stages of execution, including warnings and errors.
#>

function Remove-IdentityRole {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,
        [Switch]
        $Force,

        [Alias('url')]
        [string]
        $IdentityURL,

        [Alias('header')]
        $LogonToken,
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]
        $Role
    )
    begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        if ($Force -and -not $Confirm) {
            Write-LogMessage -type Warning -MSG 'Confirmation prompt suppressed, proceeding with all removals'
            $ConfirmPreference = 'None'
        }
    }
    process {
        Write-LogMessage -type Verbose -MSG "Removing role named `"$Role`""
        try {
            $RoleID = Get-IdentityRole -LogonToken $LogonToken -roleName "$Role" -IdentityURL $IdentityURL -IDOnly
            if ([string]::IsNullOrEmpty($RoleID)) {
                Write-LogMessage -type Warning -MSG "Role named `"$Role`" not found"
                return
            }
        }
        catch {
            Write-LogMessage -type Error -MSG $_
            return
        }
        $body = [PSCustomObject]@{ Name = $RoleID }
        if ($PSCmdlet.ShouldProcess($Role, 'Remove-IdentityRole')) {
            $RestParms = @{
                Uri    = "$IdentityURL/SaasManage/DeleteRole/"
                Method = 'POST'
                Body   = ($body | ConvertTo-Json -Depth 99)
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $result = Invoke-Rest @RestParms
            if (!$result.Success) {
                Write-LogMessage -type Error -MSG $result.Message
            }
            else {
                Write-LogMessage -type Warning -MSG "Role named `"$Role`" successfully deleted"
            }
        }
        else {
            Write-LogMessage -type Warning -MSG "Skipping removal of role `"$Role`" due to confirmation being denied"
        }
    }
}
#EndRegion '.\Public\Identity\Role\Remove-IdentityRole.ps1' 97
#Region '.\Public\Identity\Role\Remove-IdentityRoleFromUser.ps1' -1

<#
.SYNOPSIS
Removes a specified role from one or more users.

.DESCRIPTION
The Remove-IdentityRoleFromUser function removes a specified role from one or more users in an identity management system.
It supports pipeline input and can be forced to bypass confirmation prompts.

.PARAMETER roleName
The name of the role to be removed from the users.

.PARAMETER IdentityURL
The URL of the identity management system.

.PARAMETER LogonToken
The authentication token required to log on to the identity management system.

.PARAMETER User
An array of users from whom the role will be removed.

.PARAMETER Force
A switch to bypass confirmation prompts.

.INPUTS
System.String
System.String[]

.OUTPUTS
None

.EXAMPLE
PS> Remove-IdentityRoleFromUser -roleName "Admin" -IdentityURL "https://identity.example.com" -LogonToken $token -User "user1"

Removes the "Admin" role from "user1".

.EXAMPLE
PS> "user1", "user2" | Remove-IdentityRoleFromUser -roleName "Admin" -IdentityURL "https://identity.example.com" -LogonToken $token

Removes the "Admin" role from "user1" and "user2".

.NOTES
This function requires the Write-LogMessage and Get-IdentityRole functions to be defined in the session.
#>

function Remove-IdentityRoleFromUser {
    [CmdletBinding(
        SupportsShouldProcess,
        ConfirmImpact = 'High'
    )]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,
        [Switch]$Force,
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('role')]
        [string]
        $roleName,

        [Alias('url')]
        [string]
        $IdentityURL,

        [Alias('header')]
        $LogonToken,
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Users')]
        [string[]]
        $User
    )
    begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        if ($Force -and -not $Confirm) {
            Write-LogMessage -type Warning -MSG 'Confirmation prompt suppressed, proceeding with all removals'
            $ConfirmPreference = 'None'
        }
        Write-LogMessage -type Verbose -MSG "Starting removal of users from role named `"$roleName`""
        $rolesResult = Get-IdentityRole @PSBoundParameters -IDOnly
        if ($rolesResult.Count -eq 0) {
            Write-LogMessage -type Error -MSG 'No roles Found'
            return
        }
        elseif ($rolesResult.Count -ge 2) {
            Write-LogMessage -type Error -MSG 'Multiple roles found, please enter a unique role name and try again'
            return
        }
    }
    process {
        foreach ($user in $User) {
            if ($PSCmdlet.ShouldProcess($user, "Remove-IdentityRoleFromUser $roleName")) {
                $removeUserFromRole = [PSCustomObject]@{
                    Users = [PSCustomObject]@{
                        Delete = $User
                    }
                    Name  = $($rolesResult)
                }
                try {
                    $RestParms = @{
                        Uri    = "$IdentityURL/Roles/UpdateRole"
                        Method = 'POST'
                        Body   = ($removeUserFromRole | ConvertTo-Json -Depth 99)
                    }
                    if ($null -ne $LogonToken -and $LogonToken -ne "") {
                        $RestParms.LogonToken = $LogonToken
                    }
                    $result = Invoke-Rest @RestParms
                    if ($result.success) {
                        if ($User.Count -eq 1) {
                            Write-LogMessage -type Success -MSG "Role `"$roleName`" removed from user `"$user`""
                        }
                        else {
                            Write-LogMessage -type Success -MSG "Role `"$roleName`" removed from all users"
                        }
                    }
                    else {
                        if ($User.Count -eq 1) {
                            Write-LogMessage -type Error -MSG "Error removing `"$roleName`" from user `"$user`": $($result.Message)"
                        }
                        else {
                            Write-LogMessage -type Error -MSG "Error removing `"$roleName`" from users: $($result.Message)"
                        }
                    }
                }
                catch {
                    Write-LogMessage -type Error -MSG "Error while trying to remove users from `"$roleName`": $_"
                }
            }
            else {
                Write-LogMessage -type Warning -MSG "Skipping removal of user $user from role `"$roleName`" due to confirmation being denied"
            }
        }
    }
}
#EndRegion '.\Public\Identity\Role\Remove-IdentityRoleFromUser.ps1' 133
#Region '.\Public\Identity\User\Get-IdentityUser.ps1' -1

<#
.SYNOPSIS
Retrieves identity user information from a specified identity URL.

.DESCRIPTION
The Get-IdentityUser function retrieves user information from an identity service. It supports various parameters to filter the search, including UUID, name, display name, email, and internal name. The function can return either detailed information or just the user IDs based on the provided switches.

.PARAMETER IdentityURL
The URL of the identity service to query.

.PARAMETER LogonToken
The logon token used for authentication with the identity service.

.PARAMETER IDOnly
A switch to return only the user IDs.

.PARAMETER DirectoryServiceUuid
The UUID(s) of the directory service(s) to query.

.PARAMETER directoryName
The name of the directory to query.

.PARAMETER directoryService
The directory service to query.

.PARAMETER name
The name of the user to search for.

.PARAMETER DisplayName
The display name of the user to search for.

.PARAMETER mail
The email of the user to search for.

.PARAMETER InternalName
The internal name of the user to search for.

.PARAMETER UUID
The UUID of the user to search for.

.PARAMETER AllUsers
A switch to retrieve all users from the directory service.

.PARAMETER IncludeDetails
A switch to include detailed information about the users.

.EXAMPLE
Get-IdentityUser -IdentityURL "https://identity.example.com" -LogonToken $token -UUID "1234-5678-90ab-cdef"

.EXAMPLE
Get-IdentityUser -IdentityURL "https://identity.example.com" -LogonToken $token -name "jdoe" -IDOnly

.NOTES
Author: Your Name
Date: Today's Date
#>

function Get-IdentityUser {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]
        $IdentityURL,

        [Alias('header')]
        $LogonToken,
        [switch]
        $IDOnly,
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('DirID,DirectoryUUID')]
        [String[]]
        $DirectoryServiceUuid,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]
        $directoryName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]
        $directoryService,
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('user', 'username', 'member', 'UserPrincipalName', 'SamAccountName')]
        [string]
        $name,
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]
        $DisplayName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [alias('email')]
        [string]
        $mail,
        [Parameter(ValueFromPipelineByPropertyName, DontShow)]
        [string]
        $InternalName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('ObjectGUID', 'GUID', 'ID', 'UID')]
        [string]
        $UUID,
        [Parameter(ParameterSetName = 'AllUsers')]
        [switch]
        $AllUsers,
        [Parameter(ParameterSetName = 'AllUsers')]
        [switch]
        $IncludeDetails
    )
    begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        [string[]]$DirID = Get-DirectoryService @PSBoundParameters -UuidOnly
        $count = (Get-Variable -Name users -Scope 1 -ErrorAction SilentlyContinue).value.Count
        $currentValue = 0
    }
    process {
        if ($count -ne 0) {
            $currentValue += 1
            $percent = ($currentValue / $count) * 100
            Write-Progress -Activity "Getting detailed user information" -Status "$currentValue out of $count" -PercentComplete $percent
        }
        if ($AllUsers) {
            Write-LogMessage -type Warning -MSG 'All Users switch passed, getting all users'
            $RestParms = @{
                Uri    = "$IdentityURL/CDirectoryService/GetUsers"
                Method = 'POST'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $result = Invoke-Rest @RestParms
            if (!$result.Success) {
                Write-LogMessage -type Error -MSG $result.Message
                return
            }
            elseif (![string]::IsNullOrEmpty($result.Result.Exceptions.User)) {
                Write-LogMessage -type Error -MSG $result.Result.Exceptions.User
                return
            }
            if ($result.Result.Results.Count -eq 0) {
                Write-LogMessage -type Warning -MSG 'No user found'
                return
            }
            else {
                if ($IDOnly) {
                    Write-LogMessage -type Verbose -MSG 'Returning ID of users'
                    return $result.Result.Results.Row.UUID
                }
                elseif ($IncludeDetails) {
                    Write-LogMessage -type Verbose -MSG 'Returning detailed information about users'
                    [PSCustomObject[]]$users = $result.Result.Results.Row | Select-Object -Property UUID
                    $ReturnedUsers = $users | Get-IdentityUser -DirectoryServiceUuid $DirID
                    return $ReturnedUsers
                }
                else {
                    Write-LogMessage -type Verbose -MSG 'Returning basic information about users'
                    [PSCustomObject[]]$users = $result.Result.Results.Row
                    return $users
                }
            }
        }
        [PSCustomObject[]]$userSearch = @()
        if (![string]::IsNullOrEmpty($UUID)) {
            Write-LogMessage -type Verbose -MSG "User UUID provided, adding `"$UUID`" to user search parameters"
            $userSearch += [PSCustomObject]@{_ID = [PSCustomObject]@{'_like' = [PSCustomObject]@{value = $UUID; ignoreCase = 'true' } } }
        }
        if (![string]::IsNullOrEmpty($name)) {
            Write-LogMessage -type Verbose -MSG "User Name provided, adding `"$name`" to user search parameters"
            $userSearch += [PSCustomObject]@{SystemName = [PSCustomObject]@{'_like' = [PSCustomObject]@{value = $name; ignoreCase = 'true' } } }
        }
        if (![string]::IsNullOrEmpty($DisplayName)) {
            Write-LogMessage -type Verbose -MSG "User Display Name provided, adding `"$DisplayName`" to user search parameters"
            $userSearch += [PSCustomObject]@{DisplayName = [PSCustomObject]@{'_like' = [PSCustomObject]@{value = $DisplayName; ignoreCase = 'true' } } }
        }
        if (![string]::IsNullOrEmpty($mail)) {
            Write-LogMessage -type Verbose -MSG "User Email provided, adding `"$mail`" to user search parameters"
            $userSearch += [PSCustomObject]@{Email = [PSCustomObject]@{'_like' = [PSCustomObject]@{value = $mail; ignoreCase = 'true' } } }
        }
        if (![string]::IsNullOrEmpty($InternalName)) {
            Write-LogMessage -type Verbose -MSG "User Internal Name provided, adding `"$InternalName`" to user search parameters"
            $userSearch += [PSCustomObject]@{InternalName = [PSCustomObject]@{'_like' = [PSCustomObject]@{value = $InternalName; ignoreCase = 'true' } } }
        }
        elseif ($userSearch.Count -eq 0) {
            Write-LogMessage -type ErrorThrow -MSG 'No search parameters found'
        }
        $user = $userSearch
        $userquery = [PSCustomObject]@{
            'user' = "$($user | ConvertTo-Json -Depth 99 -Compress)"
        }
        $userquery | Add-Member -Type NoteProperty -Name 'directoryServices' -Value $DirID -Force
        try {
            Write-LogMessage -type Verbose -MSG 'Starting search for user'
            $RestParms = @{
                Uri    = "$IdentityURL/UserMgmt/DirectoryServiceQuery"
                Method = 'POST'
                Body   = ($userquery | ConvertTo-Json -Depth 99)
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $result = Invoke-Rest @RestParms
            if (!$result.Success) {
                Write-LogMessage -type Error -MSG $result.Message
                return
            }
            elseif (![string]::IsNullOrEmpty($result.Result.Exceptions.User)) {
                Write-LogMessage -type Error -MSG $result.Result.Exceptions.User
                return
            }
            if ($result.Result.User.Results.Count -eq 0) {
                Write-LogMessage -type Warning -MSG 'No user found'
                return
            }
            else {
                if ($IDOnly) {
                    Write-LogMessage -type Verbose -MSG 'Returning ID of user'
                    return $result.Result.User.Results.Row.InternalName
                }
                else {
                    Write-LogMessage -type Verbose -MSG 'Returning all information about user'
                    return $result.Result.User.Results.Row
                }
            }
        }
        catch {
            Write-LogMessage -type Error -MSG "Error Code : $($_.Exception.Message)"
        }
    }
    end {
        Write-Progress -Completed
    }
}
#EndRegion '.\Public\Identity\User\Get-IdentityUser.ps1' 230
#Region '.\Public\Identity\User\Invoke-RefreshIdentityUser.ps1' -1

function Invoke-RefreshIdentityUser {
    [CmdletBinding()]
    [CmdletBinding()]
    param (

        [string]
        $UUID,

        [string]
        $Username,

        [Alias('url')]
        [string]
        $IdentityURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll
    )

    process {

        if ([string]::IsNullOrEmpty($uuid) -and -not [string]::IsNullOrEmpty($Username)) {
            Write-LogMessage -type verbose 'No UUID passed and Username passed, looking up user UUID'
            try {
                $UUID = Get-IdentityUser -IDOnly -name $Username
                Write-LogMessage -type Verbose "UUID of $UUID found for user $username"
            }
            catch {

            }
        }

        $url = "$IdentityURL/CDirectoryService/RefreshToken?ID={0}" -f $UUID
        Write-LogMessage -type verbose "Invokeing: Invoke-RestMethod $url -Method 'POST' -Headers $logonToken"
        try {
            $RestParms = @{
                Uri    = $url
                Method = 'POST'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $RefreshResponce = Invoke-Rest @RestParms
            Write-LogMessage -type Success "UUID `"$UUID`" refreshed succesfully: $($RefreshResponce.success)"
        }
        catch {
            throw
        }
    }

}
#EndRegion '.\Public\Identity\User\Invoke-RefreshIdentityUser.ps1' 55
#Region '.\Public\Identity\User\Remove-IdentityUser.ps1' -1

<#
.SYNOPSIS
Removes identity users from the system.

.DESCRIPTION
The Remove-IdentityUser function removes identity users from the system based on the provided parameters.
It supports confirmation prompts and can process input from the pipeline.

.PARAMETER Force
A switch to force the removal without confirmation.

.PARAMETER IdentityURL
The URL of the identity service.

.PARAMETER LogonToken
The logon token for authentication.

.PARAMETER User
The username of the identity user to be removed. This parameter can be provided from the pipeline by property name.

.PARAMETER mail
The email of the identity user to be removed. This parameter can be provided from the pipeline by property name.

.EXAMPLE
Remove-IdentityUser -IdentityURL "https://identity.example.com" -LogonToken $token -User "jdoe"

.EXAMPLE
Remove-IdentityUser -IdentityURL "https://identity.example.com" -LogonToken $token -mail "jdoe@example.com"

.NOTES
This function requires the Write-LogMessage and Invoke-Rest functions to be defined elsewhere in the script or module.
#>

function Remove-IdentityUser {
    [CmdletBinding(
        SupportsShouldProcess,
        ConfirmImpact = 'High'
    )]
    param (
        [Switch]$Force,

        [Alias('url')]
        [string]
        $IdentityURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]
        $User,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('email')]
        [string]
        $mail
    )

    begin {
        if ($Force) {
            Write-LogMessage -type Warning -MSG 'Confirmation prompt suppressed, proceeding with all removals'
            $ConfirmPreference = 'None'
        }
        $userList = @()
        $userNames = @()
    }

    process {
        $userID = Get-IdentityUser @PSBoundParameters
        if ([string]::IsNullOrEmpty($userID)) {
            if ([string]::IsNullOrEmpty($User) -and [string]::IsNullOrEmpty($mail)) {
                Write-LogMessage -type Warning -MSG 'Username or mail not provided'
                return
            }
            elseif (![string]::IsNullOrEmpty($User)) {
                Write-LogMessage -type Warning -MSG "User `"$User`" not found"
                return
            }
            elseif (![string]::IsNullOrEmpty($mail)) {
                Write-LogMessage -type Warning -MSG "Mail `"$mail`" not found"
                return
            }
            else {
                Write-LogMessage -type Warning -MSG "User `"$User`" or mail `"$mail`" not found"
                return
            }
        }

        Write-LogMessage -type Info -MSG "A total of $($userID.Count) user accounts found"
        $userID | ForEach-Object {
            if ($PSCmdlet.ShouldProcess($_.SystemName, 'Remove-IdentityUser')) {
                $userNames += [string]$_.SystemName
                $userList += [string]$_.InternalName
            }
            else {
                Write-LogMessage -type Warning -MSG "Skipping removal of Identity User `"$User`" due to confirmation being denied"
            }
        }
    }

    end {
        try {
            if ($userList.Count -eq 0) {
                Write-LogMessage -type Warning -MSG 'No accounts found to delete'
                return
            }

            $UserJson = [pscustomobject]@{ Users = $userList }
            $RestParms = @{
                Uri    = "$IdentityURL/UserMgmt/RemoveUsers"
                Method = 'POST'
                Body   = ($UserJson | ConvertTo-Json -Depth 99)
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $result = Invoke-Rest @RestParms

            if ($result.success) {
                if ($result.Result.Exceptions.User.Count -ne 0) {
                    Write-LogMessage -type Error -MSG 'Users failed to remove, no logs given'
                }
                else {
                    Write-LogMessage -type Success -MSG "The following Users removed successfully:`n$userNames"
                }
            }
        }
        catch {
            Write-LogMessage -type Error -MSG "Error removing users:`n$PSitem"
        }
    }
}
#EndRegion '.\Public\Identity\User\Remove-IdentityUser.ps1' 133
#Region '.\Public\PAS\Account\Access\Grant-AccountAdministrativeAccess.ps1' -1

<#
.SYNOPSIS
Grants administrative access to a target Windows machine using an account in the PVWA system.

.DESCRIPTION
The Grant-AccountAdministrativeAccess function connects to the PVWA API to request
and receive access to a target Windows machine with administrative rights. The domain
user who runs this function will be added to the local Administrators group of the target machine.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication with the PVWA API.

.PARAMETER AccountID
The local account that will be used to add the logged on user to the Administrators group on the machine.

.EXAMPLE
Grant-AccountAdministrativeAccess -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34"

Grants administrative access to the target machine using account with ID "12_34".

.NOTES
The user who runs this function requires 'List accounts' and 'Use accounts' permissions
in the Safe where the account is stored.
The platform must be enabled for ad hoc access at platform level.
Supported end user machine environments: Windows Server 2012/2012R2/2016, Windows 8, Windows 10.
This function is part of the EPV-API-Common module and is used to manage accounts
in the CyberArk Privileged Access Security Web Application.
#>
function Grant-AccountAdministrativeAccess {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [Alias("id")]
        [string]$AccountID
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $GrantAccessURL = "$BaseURL/Accounts/{0}/GrantAdministrativeAccess"
    }

    Process {
        Write-LogMessage -type Verbose -MSG "Granting administrative access using account `"$AccountID`""

        $URL = $GrantAccessURL -f $AccountID
        $RestParms = @{
            Uri    = $URL
            Method = 'POST'
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $restResponse = Invoke-Rest @RestParms

        Write-LogMessage -type Verbose -MSG "Administrative access granted successfully using account `"$AccountID`""
        return $restResponse
    }
}
#EndRegion '.\Public\PAS\Account\Access\Grant-AccountAdministrativeAccess.ps1' 74
#Region '.\Public\PAS\Account\Access\Invoke-AccountCheckIn.ps1' -1

<#
.SYNOPSIS
Checks an exclusive account into the Vault in the PVWA system.

.DESCRIPTION
The Invoke-AccountCheckIn function connects to the PVWA API to check an exclusive
account into the Vault. If the account is managed automatically by the CPM, after
it is checked in, the password is changed immediately. If the account is managed
manually, a notification is sent to a user who is authorized to change the password.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication with the PVWA API.

.PARAMETER AccountID
The unique ID of the account to check in.

.EXAMPLE
Invoke-AccountCheckIn -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34"

Checks in the account with ID "12_34" to the Vault.

.NOTES
The user who runs this function requires 'Initiate CPM password management operations'
permission in the Safe where the privileged account is stored.
This function is part of the EPV-API-Common module and is used to manage accounts
in the CyberArk Privileged Access Security Web Application.
#>
function Invoke-AccountCheckIn {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [Alias("id")]
        [string]$AccountID
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $AccountCheckInURL = "$BaseURL/Accounts/{0}/CheckIn"
    }

    Process {
        Write-LogMessage -type Verbose -MSG "Checking in account `"$AccountID`""

        $URL = $AccountCheckInURL -f $AccountID
        $RestParms = @{
            Uri    = $URL
            Method = 'POST'
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $restResponse = Invoke-Rest @RestParms

        Write-LogMessage -type Verbose -MSG "Account `"$AccountID`" checked in successfully"
        return $restResponse
    }
}
#EndRegion '.\Public\PAS\Account\Access\Invoke-AccountCheckIn.ps1' 73
#Region '.\Public\PAS\Account\Access\Revoke-AccountAdministrativeAccess.ps1' -1

<#
.SYNOPSIS
Revokes administrative access from a target Windows machine using an account in the PVWA system.

.DESCRIPTION
The Revoke-AccountAdministrativeAccess function connects to the PVWA API to revoke
JIT (Just-In-Time) access to a target Windows machine with administrative rights.
The domain user who runs this function will be removed from the local Administrators
group of the target machine.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication with the PVWA API.

.PARAMETER AccountID
The local account for the target machine on which the logged on user will be removed from the Administrators group.

.EXAMPLE
Revoke-AccountAdministrativeAccess -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34"

Revokes administrative access from the target machine using account with ID "12_34".

.NOTES
The user who runs this function requires appropriate permissions in the Safe
where the account is stored.
This function is part of the EPV-API-Common module and is used to manage accounts
in the CyberArk Privileged Access Security Web Application.
#>
function Revoke-AccountAdministrativeAccess {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [Alias("id")]
        [string]$AccountID
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $RevokeAccessURL = "$BaseURL/Accounts/{0}/RevokeAdministrativeAccess"
    }

    Process {
        Write-LogMessage -type Verbose -MSG "Revoking administrative access using account `"$AccountID`""

        $URL = $RevokeAccessURL -f $AccountID
        $RestParms = @{
            Uri    = $URL
            Method = 'POST'
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $restResponse = Invoke-Rest @RestParms

        Write-LogMessage -type Verbose -MSG "Administrative access revoked successfully using account `"$AccountID`""
        return $restResponse
    }
}
#EndRegion '.\Public\PAS\Account\Access\Revoke-AccountAdministrativeAccess.ps1' 73
#Region '.\Public\PAS\Account\Access\Unlock-Account.ps1' -1

<#
.SYNOPSIS
Unlocks an account in the PVWA system.

.DESCRIPTION
The Unlock-Account function connects to the PVWA API to unlock a locked account.
This operation removes the lock from an account that has been locked due to failed
password changes or other CPM operations.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication with the PVWA API.

.PARAMETER AccountID
The unique ID of the account to unlock.

.EXAMPLE
Unlock-Account -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34"

Unlocks the account with ID "12_34".

.NOTES
The user who runs this function requires 'Unlock accounts' permission in the Safe
where the privileged account is stored.
This function is part of the EPV-API-Common module and is used to manage accounts
in the CyberArk Privileged Access Security Web Application.
#>
function Unlock-Account {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [Alias("id")]
        [string]$AccountID
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $AccountUnlockURL = "$BaseURL/Accounts/{0}/Unlock"
    }

    Process {
        Write-LogMessage -type Verbose -MSG "Unlocking account `"$AccountID`""

        $URL = $AccountUnlockURL -f $AccountID
        $RestParms = @{
            Uri    = $URL
            Method = 'POST'
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $restResponse = Invoke-Rest @RestParms

        Write-LogMessage -type Verbose -MSG "Account `"$AccountID`" unlocked successfully"
        return $restResponse
    }
}
#EndRegion '.\Public\PAS\Account\Access\Unlock-Account.ps1' 72
#Region '.\Public\PAS\Account\Core\Get-Account.ps1' -1

<#
.SYNOPSIS
Retrieves account information from the PVWA API.

.DESCRIPTION
The Get-Account function retrieves account information from the PVWA API based on various parameters such as AccountID, Search, Filter, and SavedFilter. It supports multiple parameter sets to allow for flexible querying.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER AccountID
The ID of the account to retrieve.

.PARAMETER AccountLink
Switch to include account links in the response.

.PARAMETER AccountLinkObject
Switch to include account link objects in the response.

.PARAMETER AllAccounts
Switch to retrieve all accounts.

.PARAMETER Search
Search term to filter accounts.

.PARAMETER SearchType
Type of search to perform.

.PARAMETER Filter
Filter to apply to the account query.

.PARAMETER SavedFilter
Predefined filter to apply to the account query. Valid values are:
- Regular
- Recently
- New
- Link
- Deleted
- PolicyFailures
- AccessedByUsers
- ModifiedByUsers
- ModifiedByCPM
- DisabledPasswordByUser
- DisabledPasswordByCPM
- ScheduledForChange
- ScheduledForVerify
- ScheduledForReconcile
- SuccessfullyReconciled
- FailedChange
- FailedVerify
- FailedReconcile
- LockedOrNew
- Locked

.PARAMETER Offset
Offset for pagination.

.PARAMETER Limit
Limit for pagination.

.PARAMETER DoNotPage
Switch to disable pagination.

.PARAMETER Sort
Sort order for the results. Valid values are "asc" and "desc".

.EXAMPLE
Get-Account -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12345"

.EXAMPLE
Get-Account -PVWAURL "https://pvwa.example.com" -LogonToken $token -Search "admin" -SearchType "contains"

.NOTES
This function requires the PVWA URL and a valid logon token to authenticate API requests.

#>

function Get-Account {
    [CmdletBinding(DefaultParameterSetName = 'Filter')]
    param (

        [Parameter(ParameterSetName = 'AccountID', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string]$AccountID,

        [Parameter(ParameterSetName = 'AccountID', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [switch]$AccountLink,

        [Parameter(ParameterSetName = 'AccountID', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [switch]$AccountLinkObject,

        [Parameter(ParameterSetName = 'AllAccounts')]
        [switch]$AllAccounts,

        [Parameter(ParameterSetName = 'Search', ValueFromPipelineByPropertyName)]
        [string]$Search,

        [Parameter(ParameterSetName = 'Search', ValueFromPipelineByPropertyName)]
        [string]$SearchType,

        [Parameter(ParameterSetName = 'Search')]
        [Parameter(ParameterSetName = 'Filter', ValueFromPipelineByPropertyName)]
        [string]$Filter,

        [Parameter(ParameterSetName = 'savedfilter', ValueFromPipelineByPropertyName)]
        [string]
        [ValidateSet('Regular', 'Recently', 'New', 'Link', 'Deleted', 'PolicyFailures',
            'AccessedByUsers', 'ModifiedByUsers', 'ModifiedByCPM', 'DisabledPasswordByUser',
            'DisabledPasswordByCPM', 'ScheduledForChange', 'ScheduledForVerify',
            'ScheduledForReconcile', 'SuccessfullyReconciled', 'FailedChange',
            'FailedVerify', 'FailedReconcile', 'LockedOrNew', 'Locked', 'deleteInsightStatus'
        )]
        $SavedFilter,

        [Parameter(ParameterSetName = 'AllAccounts')]
        [Parameter(ParameterSetName = 'Filter')]
        [Parameter(ParameterSetName = 'savedfilter')]
        [Parameter(ParameterSetName = 'Search')]
        [string]$Offset,

        [Parameter(ParameterSetName = 'AllAccounts')]
        [Parameter(ParameterSetName = 'Filter')]
        [Parameter(ParameterSetName = 'savedfilter')]
        [Parameter(ParameterSetName = 'Search')]
        [string]$Limit,

        [Parameter(ParameterSetName = 'AllAccounts')]
        [Parameter(ParameterSetName = 'Filter')]
        [Parameter(ParameterSetName = 'savedfilter')]
        [Parameter(ParameterSetName = 'Search')]
        [switch]$DoNotPage,

        [Parameter(ParameterSetName = 'AllAccounts')]
        [Parameter(ParameterSetName = 'Filter')]
        [Parameter(ParameterSetName = 'savedfilter')]
        [Parameter(ParameterSetName = 'Search')]
        [AllowEmptyString]
        [ValidateSet('asc', 'desc')]
        $Sort,

        [Alias('url', 'PCloudURL')]
        [string]$PVWAURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll
    )

    begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $AccountUrl = "$BaseURL/Accounts/?"
        $AccountIDURL = "$BaseURL/Accounts/{0}/?"
    }

    process {
        $AccountIDExists = -not [string]::IsNullOrEmpty($AccountID)
        $SavedFilterExists = -not [string]::IsNullOrEmpty($SavedFilter)
        $SearchExists = -not [string]::IsNullOrEmpty($Search)
        $FilterExists = -not [string]::IsNullOrEmpty($Filter)

        if ($AccountIDExists) {
            [account]$Account = Get-AccountViaID -AccountID $AccountID -AccountIDURL $AccountIDURL -LogonToken $LogonToken
            if ($AccountLink -or $AccountLinkObject) {
                $Account.LinkedAccounts = Get-AccountLink -AccountID $AccountID -accountObject:$AccountLinkObject -LogonToken $LogonToken
            }
            return $Account
        }
        else {
            if (-not ($AccountIDExists -or $FilterExists -or $SavedFilterExists -or $SearchExists)) {
                Write-LogMessage -type Verbose -MSG 'No Account ID, Filter, SavedFilter, or Search provided, returning all accounts'
            }
            Write-LogMessage -type Verbose -MSG 'Getting list of accounts'
            $URL = $AccountUrl
            $PassParms = $PSBoundParameters
            $PassParms.url = [ref]$URL
            Add-BaseQueryParameter @PassParms
            Add-AccountQueryParameter @PassParms
            $RestParms = @{
                Uri    = $URL
                Method = 'GET'
            }
            if ($null -ne $LogonToken) {
                $RestParms.LogonToken = $LogonToken
            }
            [Account[]]$resultList = Invoke-RestNextLink @RestParms
            return $resultList
        }
    }
}

function Get-AccountViaID {
    param (
        $AccountID,
        $AccountIDURL,
        $LogonToken
    )
    $URL = $AccountIDURL -f $AccountID
    Write-LogMessage -type Verbose -MSG "Getting account with ID of `"$AccountID`""
    $RestParms = @{
        Uri    = $URL
        Method = 'GET'
    }
    if ($null -ne $LogonToken) {
        $RestParms.LogonToken = $LogonToken
    }
    [account]$restResponse = Invoke-Rest @RestParms
    return $restResponse
}



function Add-AccountQueryParameter {
    param (
        [ref]$URL,
        $Search,
        $SearchType,
        $SavedFilter,
        $Filter
    )
    Write-LogMessage -type Verbose -MSG 'Adding Query Parameters'
    if (-not [string]::IsNullOrEmpty($Search)) {
        $URL.Value += "&search=$Search"
        Write-LogMessage -type Verbose -MSG "Applying a search of `"$Search`""
    }
    if (-not [string]::IsNullOrEmpty($SearchType)) {
        $URL.Value += "&searchType=$SearchType"
        Write-LogMessage -type Verbose -MSG "Applying a search type of `"$SearchType`""
    }
    if (-not [string]::IsNullOrEmpty($SavedFilter)) {
        $URL.Value += "&savedfilter=$SavedFilter"
        Write-LogMessage -type Verbose -MSG "Applying a savedfilter of `"$SavedFilter`""
    }
    if (-not [string]::IsNullOrEmpty($Filter)) {
        $URL.Value += "&filter=$Filter"
        Write-LogMessage -type Verbose -MSG "Applying a filter of `"$Filter`""
    }
    Write-LogMessage -type Verbose -MSG "New URL: $URL"
}
#EndRegion '.\Public\PAS\Account\Core\Get-Account.ps1' 244
#Region '.\Public\PAS\Account\Core\New-Account.ps1' -1

<#
.SYNOPSIS
Creates a new account in the PVWA system.

.DESCRIPTION
The New-Account function connects to the PVWA API to create a new privileged account.
It requires the PVWA URL and a logon token for authentication. The function
supports ShouldProcess for confirmation prompts.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication with the PVWA API.

.PARAMETER Name
The name of the account to create.

.PARAMETER Address
The address/hostname of the target system.

.PARAMETER UserName
The username of the account.

.PARAMETER PlatformId
The platform ID that defines the account's platform settings.

.PARAMETER SafeName
The name of the safe where the account will be stored.

.PARAMETER Secret
The secret/password for the account (SecureString).

.PARAMETER SecretType
The type of secret (password or key). Default is "password".

.PARAMETER PlatformAccountProperties
Additional platform-specific properties for the account. Note: Any extra parameters not explicitly defined in this function will automatically be added to platformAccountProperties.

.PARAMETER AutomaticManagementEnabled
Whether automatic management is enabled for the account. Default is $true.

.PARAMETER ManualManagementReason
The reason for manual management if automatic management is disabled.

.PARAMETER RemoteMachines
Semicolon-separated list of remote machines that can access this account.

.PARAMETER AccessRestrictedToRemoteMachines
Whether access is restricted to the specified remote machines. Default is $false.

.PARAMETER ExtraParameters
Additional parameters that will be automatically added to platformAccountProperties. This parameter captures any undefined parameters passed to the function using ValueFromRemainingArguments.

.EXAMPLE
$securePassword = ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force
New-Account -PVWAURL "https://pvwa.example.com" -LogonToken $token -Name "srv01-admin" -Address "srv01.domain.com" -UserName "administrator" -PlatformId "WindowsServerLocal" -SafeName "IT-Servers" -Secret $securePassword -AutomaticManagementEnabled $true

Creates a new Windows server account in the IT-Servers safe with automatic management enabled.

.EXAMPLE
New-Account -PVWAURL "https://pvwa.example.com" -LogonToken $token -Name "db01-sa" -Address "db01.domain.com" -UserName "sa" -PlatformId "SQLServerDatabase" -SafeName "Database-Accounts" -SecretType "password" -RemoteMachines "srv01.domain.com;srv02.domain.com" -AccessRestrictedToRemoteMachines $true

Creates a new SQL Server account with access restricted to specific remote machines.

.EXAMPLE
New-Account -PVWAURL "https://pvwa.example.com" -LogonToken $token -Name "app-service" -Address "app01.domain.com" -UserName "svc_app" -PlatformId "WindowsServerLocal" -SafeName "Service-Accounts" -AutomaticManagementEnabled $false -ManualManagementReason "Service account requires manual password changes"

Creates a new service account with manual management and a specified reason.

.EXAMPLE
New-Account -PVWAURL "https://pvwa.example.com" -LogonToken $token -Name "oracle-db" -Address "ora01.domain.com" -UserName "sys" -PlatformId "Oracle" -SafeName "Database-Accounts" -Port 1521 -SID "ORCL" -ServiceName "MYSERVICE"

Creates a new Oracle database account with platform-specific properties (Port, SID, ServiceName) automatically added to platformAccountProperties.

.NOTES
The user who runs this function requires 'Add account' permission in the target Safe.
This function is part of the EPV-API-Common module and is used to manage accounts
in the CyberArk Privileged Access Security Web Application.
This function can be used from PAM v9.7 and above.

IMPORTANT: When using extra parameters (platform-specific properties), ensure that the
properties exist on the target platform. If a property does not exist on the platform,
the API will return an error. Verify platform properties before using extra parameters.
#>
function New-Account {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL", SupportsShouldProcess = $true)]
    param (

        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Parameter( ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [string]$Address,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [string]$UserName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [string]$PlatformId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [string]$SafeName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [SecureString]$Secret,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet("password", "key")]
        [string]$SecretType = "password",

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$PlatformAccountProperties,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$AutomaticManagementEnabled = $true,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ManualManagementReason,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$RemoteMachines,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$AccessRestrictedToRemoteMachines = $false,

        # Capture any additional parameters for platform-specific properties
        [Parameter(ValueFromRemainingArguments)]
        [object[]]$ExtraParameters
    )

    Begin {
        $BaseURL = "$PVWAURL/API/"
        $AccountURL = "$BaseURL/Accounts"
    }

    Process {
        if ($PSCmdlet.ShouldProcess($Name, 'New-Account')) {
            Write-LogMessage -type Verbose -MSG "Creating new account `"$Name`" in safe `"$SafeName`""

            # Build the request body
            $body = @{
                "address" = $Address
                "userName" = $UserName
                "platformId" = $PlatformId
                "safeName" = $SafeName
                "secretType" = $SecretType
            }

            if ($Name) {
                $body["name"] = $Name
            }

            # Add secret if provided
            if ($Secret) {
                $body["secret"] = [System.Net.NetworkCredential]::new("", $Secret).Password
            }

            # Add platform account properties if provided or capture extra parameters
            $platformProperties = @{}

            # Start with explicitly provided PlatformAccountProperties
            if ($PlatformAccountProperties) {
                $platformProperties = $PlatformAccountProperties.Clone()
            }

            # Process extra parameters from ValueFromRemainingArguments
            if ($ExtraParameters -and $ExtraParameters.Count -gt 0) {
                Write-LogMessage -type Verbose -MSG "Processing $($ExtraParameters.Count) extra parameters"

                # ExtraParameters contains parameter names and values in pairs
                for ($i = 0; $i -lt $ExtraParameters.Count; $i += 2) {
                    if ($i + 1 -lt $ExtraParameters.Count) {
                        $paramName = $ExtraParameters[$i].ToString().TrimStart('-')
                        $paramValue = $ExtraParameters[$i + 1]

                        $platformProperties[$paramName] = $paramValue
                        Write-LogMessage -type Verbose -MSG "Adding extra parameter '$paramName' to platformAccountProperties with value: $paramValue"
                    }
                }
            }

            # Only add platformAccountProperties if we have any properties
            if ($platformProperties.Count -gt 0) {
                $body["platformAccountProperties"] = $platformProperties
            }

            # Add secret management settings
            $secretManagement = @{
                "automaticManagementEnabled" = $AutomaticManagementEnabled
            }

            if ($PSBoundParameters.ContainsKey('ManualManagementReason') -and $ManualManagementReason) {
                $secretManagement["manualManagementReason"] = $ManualManagementReason
            }

            $body["secretManagement"] = $secretManagement

            # Add remote machines access settings
            if ($PSBoundParameters.ContainsKey('RemoteMachines') -or $PSBoundParameters.ContainsKey('AccessRestrictedToRemoteMachines')) {
                $remoteMachinesAccess = @{
                    "accessRestrictedToRemoteMachines" = $AccessRestrictedToRemoteMachines
                }

                if ($PSBoundParameters.ContainsKey('RemoteMachines') -and $RemoteMachines) {
                    $remoteMachinesAccess["remoteMachines"] = $RemoteMachines
                }

                $body["remoteMachinesAccess"] = $remoteMachinesAccess
            }

            try {
                $RestParms = @{
                    Uri    = $AccountURL
                    Method = 'POST'
                    Body   = ($body | ConvertTo-Json -Depth 5)
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                $restResponse = Invoke-Rest @RestParms

                if ($restResponse) {
                    Write-LogMessage -type Success -MSG "Account `"$($restResponse.Name)`" created successfully with ID: $($restResponse.id)"
                    return $restResponse
                }
            }
            catch {
                Write-LogMessage -type Failure -MSG "Failed to create account `"$Name`": $($_.Exception.Message)"
                throw
            }
        }
        else {
            Write-LogMessage -type Failure -MSG "Skipping creation of account `"$Name`" due to confirmation being denied"
        }
    }
}
#EndRegion '.\Public\PAS\Account\Core\New-Account.ps1' 246
#Region '.\Public\PAS\Account\Core\Remove-Account.ps1' -1

<#
.SYNOPSIS
Removes an account from the PVWA system.

.DESCRIPTION
The Remove-Account function connects to the PVWA API to delete a specific account.
It requires the PVWA URL, a logon token, and the account ID for the account to be deleted.
The function supports ShouldProcess for confirmation prompts.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication with the PVWA API.

.PARAMETER AccountID
The unique ID of the account to delete.

.EXAMPLE
Remove-Account -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34"

Removes the account with ID "12_34" from the PVWA system.

.NOTES
The user who runs this function requires Delete Accounts permission in the Vault.
This function is part of the EPV-API-Common module and is used to manage accounts
in the CyberArk Privileged Access Security Web Application.
#>
function Remove-Account {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL", SupportsShouldProcess = $true)]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [Alias("id")]
        [string]$AccountID
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $AccountDeleteURL = "$BaseURL/Accounts/{0}/"
    }

    Process {
        Try {
        if ($PSCmdlet.ShouldProcess($AccountID, 'Remove-Account')) {
            Write-LogMessage -type Verbose -MSG "Deleting account with ID `"$AccountID`""

            $URL = $AccountDeleteURL -f $AccountID
            $RestParms = @{
                Uri    = $URL
                Method = 'DELETE'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms

            Write-LogMessage -type Success -MSG "Account `"$AccountID`" deleted successfully"
            return $restResponse
        }
        else {
            Write-LogMessage -type Failure -MSG "Skipping deletion of account `"$AccountID`" due to confirmation being denied"
        }
    } catch {
                Write-LogMessage -type Failure -MSG "Failed to remove account `"$AccountID`""
                Write-LogMessage -type Error -MSG "Failed to remove account `"$AccountID`": $($_.Exception.Message)"
    }
    }
}
#EndRegion '.\Public\PAS\Account\Core\Remove-Account.ps1' 81
#Region '.\Public\PAS\Account\Core\Set-Account.ps1' -1

<#
.SYNOPSIS
Updates an existing account's properties in the PVWA system.

.DESCRIPTION
The Set-Account function updates an existing account's properties in the PVWA (Password Vault Web Access).
It allows you to modify various account properties including name, address, username, platform,
platform-specific properties, secret management settings, and remote machine access settings.
Any extra parameters not explicitly defined will be automatically added to platformAccountProperties.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication with the PVWA API.

.PARAMETER AccountID
The unique ID of the account to update.

.PARAMETER Name
The new name for the account.

.PARAMETER Address
The new address/hostname of the target system.

.PARAMETER UserName
The new username for the account.

.PARAMETER PlatformId
The new platform ID that defines the account's platform settings.

.PARAMETER PlatformAccountProperties
Additional platform-specific properties for the account. Note: Any extra parameters not explicitly defined in this function will automatically be added to platformAccountProperties.

.PARAMETER AutomaticManagementEnabled
Whether automatic management is enabled for the account.

.PARAMETER ManualManagementReason
The reason for manual management if automatic management is disabled.

.PARAMETER RemoteMachines
Semicolon-separated list of remote machines that can access this account.

.PARAMETER AccessRestrictedToRemoteMachines
Whether access is restricted to the specified remote machines.

.PARAMETER ExtraParameters
Additional parameters that will be automatically added to platformAccountProperties. This parameter captures any undefined parameters passed to the function using ValueFromRemainingArguments.

.EXAMPLE
Set-Account -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_345" -Name "srv01-admin-updated" -Address "srv01-new.domain.com"

Updates an account's name and address.

.EXAMPLE
Set-Account -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_345" -AutomaticManagementEnabled $false -ManualManagementReason "Service account requires manual password changes"

Updates an account's management settings.

.EXAMPLE
Set-Account -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_345" -Port 1521 -SID "ORCL" -ServiceName "MYSERVICE"

Updates an Oracle database account with platform-specific properties (Port, SID, ServiceName) automatically added to platformAccountProperties.

.EXAMPLE
Set-Account -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_345" -RemoteMachines "srv01.domain.com;srv02.domain.com" -AccessRestrictedToRemoteMachines $true

Updates an account's remote machine access settings.

.NOTES
The user who runs this function requires appropriate permissions to update accounts.
This function is part of the EPV-API-Common module and is used to manage accounts
in the CyberArk Privileged Access Security Web Application.
This function can be used from PAM v9.7 and above.

IMPORTANT: When using extra parameters (platform-specific properties), ensure that the
properties exist on the target platform. If a property does not exist on the platform,
the API will return an error. Verify platform properties before using extra parameters.
#>
function Set-Account {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL", SupportsShouldProcess = $true)]
    param (
        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [string]$AccountID,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Address,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$UserName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PlatformId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$PlatformAccountProperties,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$AutomaticManagementEnabled,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ManualManagementReason,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$RemoteMachines,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$AccessRestrictedToRemoteMachines,

        # Capture any additional parameters for platform-specific properties
        [Parameter(ValueFromRemainingArguments)]
        [object[]]$ExtraParameters
    )

    Begin {
        $BaseURL = "$PVWAURL/API/"
        $AccountURL = "$BaseURL/Accounts/$AccountID"
    }

    Process {
        if ($PSCmdlet.ShouldProcess($AccountID, 'Set-Account')) {
            Write-LogMessage -type Verbose -MSG "Updating account `"$AccountID`""

            # Build the operations array for JSON Patch
            $operations = @()

            # Add basic property updates
            if ($PSBoundParameters.ContainsKey('Name')) {
                $operations += @{ op = "replace"; path = "/name"; value = $Name }
                Write-LogMessage -type Verbose -MSG "Updating account name to: $Name"
            }

            if ($PSBoundParameters.ContainsKey('Address')) {
                $operations += @{ op = "replace"; path = "/address"; value = $Address }
                Write-LogMessage -type Verbose -MSG "Updating account address to: $Address"
            }

            if ($PSBoundParameters.ContainsKey('UserName')) {
                $operations += @{ op = "replace"; path = "/userName"; value = $UserName }
                Write-LogMessage -type Verbose -MSG "Updating account username to: $UserName"
            }

            if ($PSBoundParameters.ContainsKey('PlatformId')) {
                $operations += @{ op = "replace"; path = "/platformId"; value = $PlatformId }
                Write-LogMessage -type Verbose -MSG "Updating account platform to: $PlatformId"
            }

            # Handle platform account properties including extra parameters
            $platformProperties = @{}

            # Start with explicitly provided PlatformAccountProperties
            if ($PlatformAccountProperties) {
                $platformProperties = $PlatformAccountProperties.Clone()
            }

            # Process extra parameters from ValueFromRemainingArguments
            if ($ExtraParameters -and $ExtraParameters.Count -gt 0) {
                Write-LogMessage -type Verbose -MSG "Processing $($ExtraParameters.Count) extra parameters"

                # ExtraParameters contains parameter names and values in pairs
                for ($i = 0; $i -lt $ExtraParameters.Count; $i += 2) {
                    if ($i + 1 -lt $ExtraParameters.Count) {
                        $paramName = $ExtraParameters[$i].ToString().TrimStart('-')
                        $paramValue = $ExtraParameters[$i + 1]

                        $platformProperties[$paramName] = $paramValue
                        Write-LogMessage -type Verbose -MSG "Adding extra parameter '$paramName' to platformAccountProperties with value: $paramValue"
                    }
                }
            }

            # Add platform properties operations if we have any
            if ($platformProperties.Count -gt 0) {
                foreach ($prop in $platformProperties.GetEnumerator()) {
                    $operations += @{ op = "replace"; path = "/platformAccountProperties/$($prop.Key)"; value = $prop.Value }
                    Write-LogMessage -type Verbose -MSG "Updating platform property '$($prop.Key)' to: $($prop.Value)"
                }
            }

            # Handle secret management settings
            if ($PSBoundParameters.ContainsKey('AutomaticManagementEnabled')) {
                $operations += @{ op = "replace"; path = "/secretManagement/automaticManagementEnabled"; value = $AutomaticManagementEnabled }
                Write-LogMessage -type Verbose -MSG "Updating automatic management enabled to: $AutomaticManagementEnabled"
            }

            if ($PSBoundParameters.ContainsKey('ManualManagementReason') -and $ManualManagementReason) {
                $operations += @{ op = "replace"; path = "/secretManagement/manualManagementReason"; value = $ManualManagementReason }
                Write-LogMessage -type Verbose -MSG "Updating manual management reason to: $ManualManagementReason"
            }

            # Handle remote machines access settings
            if ($PSBoundParameters.ContainsKey('RemoteMachines') -and $RemoteMachines) {
                $operations += @{ op = "replace"; path = "/remoteMachinesAccess/remoteMachines"; value = $RemoteMachines }
                Write-LogMessage -type Verbose -MSG "Updating remote machines to: $RemoteMachines"
            }

            if ($PSBoundParameters.ContainsKey('AccessRestrictedToRemoteMachines')) {
                $operations += @{ op = "replace"; path = "/remoteMachinesAccess/accessRestrictedToRemoteMachines"; value = $AccessRestrictedToRemoteMachines }
                Write-LogMessage -type Verbose -MSG "Updating access restricted to remote machines to: $AccessRestrictedToRemoteMachines"
            }

            # Check if we have any operations to perform
            if ($operations.Count -eq 0) {
                Write-LogMessage -type Warning -MSG "No properties specified for update. Account `"$AccountID`" was not modified."
                return
            }

            try {
                Write-LogMessage -type Verbose -MSG "Performing $($operations.Count) update operations on account `"$AccountID`""
                $RestParms = @{
                    Uri    = $AccountURL
                    Method = 'PATCH'
                    Body   = ($operations | ConvertTo-Json -Depth 5)
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                $restResponse = Invoke-Rest @RestParms

                if ($restResponse) {
                    Write-LogMessage -type Success -MSG "Account `"$AccountID`" updated successfully"
                    return $restResponse
                }
            }
            catch {
                Write-LogMessage -type failure -MSG "Failed to update account `"$AccountID`""
                Write-LogMessage -type Error -MSG "Failed to update account `"$AccountID`": $($_.Exception.Message)"
                throw
            }
        }
        else {
            Write-LogMessage -type Warning -MSG "Skipping update of account `"$AccountID`" due to confirmation being denied"
        }
    }
}
#EndRegion '.\Public\PAS\Account\Core\Set-Account.ps1' 247
#Region '.\Public\PAS\Account\Groups\Add-AccountGroup.ps1' -1

#TODO
#EndRegion '.\Public\PAS\Account\Groups\Add-AccountGroup.ps1' 2
#Region '.\Public\PAS\Account\Groups\Add-AccountGroupMember.ps1' -1

#TODO
#EndRegion '.\Public\PAS\Account\Groups\Add-AccountGroupMember.ps1' 2
#Region '.\Public\PAS\Account\Groups\Get-AccountGroup.ps1' -1

#TODO
#EndRegion '.\Public\PAS\Account\Groups\Get-AccountGroup.ps1' 2
#Region '.\Public\PAS\Account\Groups\Get-AccountGroupMember.ps1' -1

#TODO
#EndRegion '.\Public\PAS\Account\Groups\Get-AccountGroupMember.ps1' 2
#Region '.\Public\PAS\Account\Groups\Remove-AccountGroup.ps1' -1

#TODO
#EndRegion '.\Public\PAS\Account\Groups\Remove-AccountGroup.ps1' 2
#Region '.\Public\PAS\Account\Linking\Add-DependentAccount.ps1' -1

<#
.SYNOPSIS
Adds a dependent account to an existing account in the PVWA system.

.DESCRIPTION
The Add-DependentAccount function connects to the PVWA API to add a dependent
account to an existing master account. The dependent account will be created
in the same safe and folder as the master account.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication with the PVWA API.

.PARAMETER AccountID
The account ID of the master account to which the dependent account will be added.

.PARAMETER Name
The name of the dependent account.

.PARAMETER Address
The address/hostname of the dependent account.

.PARAMETER UserName
The username of the dependent account.

.PARAMETER PlatformId
The platform ID for the dependent account.

.PARAMETER Secret
The secret/password for the dependent account.

.PARAMETER SecretType
The type of secret (password or key).

.PARAMETER PlatformAccountProperties
Additional platform-specific properties for the dependent account.

.PARAMETER SecretManagement
Secret management settings for the dependent account.

.PARAMETER RemoteMachinesAccess
Remote machine access settings for the dependent account.

.EXAMPLE
Add-DependentAccount -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34" -Name "DependentApp" -Address "server.domain.com" -UserName "appuser" -PlatformId "WindowsServerLocal" -Secret (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force)

Adds a dependent account to the master account with ID "12_34".

.NOTES
The user who runs this function requires 'Add account' permission in the Safe
of the master account.
This function is part of the EPV-API-Common module and is used to manage accounts
in the CyberArk Privileged Access Security Web Application.
#>
function Add-DependentAccount {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [Alias("id")]
        [string]$AccountID,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [string]$Address,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [string]$UserName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [string]$PlatformId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [SecureString]$Secret,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet("password", "key")]
        [string]$SecretType = "password",

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$PlatformAccountProperties,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$SecretManagement,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$RemoteMachinesAccess
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $AddDependentAccountURL = "$BaseURL/Accounts/{0}/DependentAccounts"
    }

    Process {
        Write-LogMessage -type Verbose -MSG "Adding dependent account `"$Name`" to master account `"$AccountID`""

        $URL = $AddDependentAccountURL -f $AccountID

        # Build the request body
        $body = @{
            "name" = $Name
            "address" = $Address
            "userName" = $UserName
            "platformId" = $PlatformId
            "secretType" = $SecretType
        }

        if ($Secret) {
            $body["secret"] = [System.Net.NetworkCredential]::new("", $Secret).Password
        }

        if ($PlatformAccountProperties) {
            $body["platformAccountProperties"] = $PlatformAccountProperties
        }

        if ($SecretManagement) {
            $body["secretManagement"] = $SecretManagement
        }

        if ($RemoteMachinesAccess) {
            $body["remoteMachinesAccess"] = $RemoteMachinesAccess
        }

        $RestParms = @{
            Uri    = $URL
            Method = 'POST'
            Body   = $body
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $restResponse = Invoke-Rest @RestParms

        Write-LogMessage -type Verbose -MSG "Dependent account `"$Name`" added successfully to master account `"$AccountID`""
        return $restResponse
    }
}
#EndRegion '.\Public\PAS\Account\Linking\Add-DependentAccount.ps1' 154
#Region '.\Public\PAS\Account\Linking\Clear-AccountLink.ps1' -1

<#
.SYNOPSIS
Removes association between a linked account and source account in the PVWA system.

.DESCRIPTION
The Clear-AccountLink function connects to the PVWA API to remove the association
between a linked account and its source account. This clears the link between
accounts such as reconcile accounts or logon accounts.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication with the PVWA API.

.PARAMETER AccountID
The unique ID of the source account.

.PARAMETER ExtraPasswordIndex
The linked account's extra password index. The index can be for Reconcile account,
Logon account, or other linked account that is defined in the Platform configuration.

.EXAMPLE
Clear-AccountLink -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34" -ExtraPasswordIndex 2

Removes the association for the linked account at index 2 from account with ID "12_34".

.NOTES
The user who runs this function requires 'List accounts' and 'Update account properties'
permissions in the Safe of the source account. 'Manage Safe' authorization may be needed
if "RequireManageSafeToClearLinkedAccount" is enabled in the configuration.
This function is part of the EPV-API-Common module and is used to manage accounts
in the CyberArk Privileged Access Security Web Application.
#>
function Clear-AccountLink {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [Alias("id")]
        [string]$AccountID,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [int]$ExtraPasswordIndex
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $ClearLinkURL = "$BaseURL/Accounts/{0}/LinkAccount/{1}"
    }

    Process {
        Write-LogMessage -type Verbose -MSG "Clearing linked account at index `"$ExtraPasswordIndex`" from account `"$AccountID`""

        $URL = $ClearLinkURL -f $AccountID, $ExtraPasswordIndex
        $RestParms = @{
            Uri    = $URL
            Method = 'DELETE'
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $restResponse = Invoke-Rest @RestParms

        Write-LogMessage -type Verbose -MSG "Linked account cleared successfully from account `"$AccountID`""
        return $restResponse
    }
}
#EndRegion '.\Public\PAS\Account\Linking\Clear-AccountLink.ps1' 80
#Region '.\Public\PAS\Account\Linking\Get-AccountLink.ps1' -1

<#
.SYNOPSIS
Retrieves linked accounts for a specified account from the PVWA API.

.DESCRIPTION
The Get-AccountLink function retrieves linked accounts for a specified account ID from the PVWA API. It supports retrieving the linked accounts as account objects if the -accountObject switch is specified.

.PARAMETER PVWAURL
The base URL of the PVWA API. This parameter is mandatory.

.PARAMETER LogonToken
The authentication token required to access the PVWA API. This parameter is mandatory.

.PARAMETER AccountID
The ID of the account for which linked accounts are to be retrieved. This parameter is mandatory when using the 'AccountID' parameter set.

.PARAMETER accountObject
A switch parameter that, when specified, retrieves the linked accounts as account objects.

.EXAMPLE
PS> Get-AccountLink -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_45"

Retrieves the linked accounts for the account with ID "12_45".

.EXAMPLE
PS> Get-AccountLink -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12345" -accountObject

Retrieves the linked accounts for the account with ID "12345" and returns them as account objects.

.NOTES
This function requires the Write-LogMessage and Invoke-Rest functions to be defined in the session.
#>
function Get-AccountLink {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,
        [Alias('url', 'PCloudURL')]

        [string]$PVWAURL,

        [Alias('header')]

        $LogonToken,

        [Parameter(ParameterSetName = 'AccountID', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [Alias("id")]
        [string]$AccountID,

        [Parameter()]
        [switch]$accountObject
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $AccountIDLink = "$BaseURL/ExtendedAccounts/{0}/LinkedAccounts"
    }

    Process {
        $URL = $AccountIDLink -f $AccountID
        Write-LogMessage -type Verbose -MSG "Getting account links with ID of `"$AccountID`""
        $RestParms = @{
            Uri    = $URL
            Method = 'GET'
        }
        if ($null -ne $LogonToken) {
            $RestParms.LogonToken = $LogonToken
        }
        $restResponse = Invoke-Rest @RestParms
        If ($accountObject) {
            $restResponse.LinkedAccounts | ForEach-Object {
                IF (-not [string]::IsNullOrEmpty($PSitem.AccountID)) {
                    $PSItem | Add-Member -Name "AccountObject" -MemberType NoteProperty -Value $($PSitem | Get-Account)
                }
            }
        }
        Return $restResponse
    }
}
#EndRegion '.\Public\PAS\Account\Linking\Get-AccountLink.ps1' 81
#Region '.\Public\PAS\Account\Linking\Get-DependentAccount.ps1' -1

<#
.SYNOPSIS
Retrieves dependent accounts associated with a specific account in the PVWA system.

.DESCRIPTION
The Get-DependentAccount function connects to the PVWA API to get all dependent
accounts associated to a specific master account. Dependent accounts are accounts
that depend on a master account for their credentials.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication with the PVWA API.

.PARAMETER AccountID
The account ID of the master account.

.PARAMETER Search
List of keywords separated with space to search in dependent accounts.

.PARAMETER Filter
Filter to apply when searching dependent accounts.

.PARAMETER FailedOnly
Get only failed dependent accounts.

.EXAMPLE
Get-DependentAccount -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34"

Retrieves all dependent accounts for the master account with ID "12_34".

.EXAMPLE
Get-DependentAccount -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34" -FailedOnly $true

Retrieves only failed dependent accounts for the master account with ID "12_34".

.NOTES
The user who runs this function requires appropriate permissions in the Safe
where the privileged account is stored.
This function is part of the EPV-API-Common module and is used to manage accounts
in the CyberArk Privileged Access Security Web Application.
#>
function Get-DependentAccount {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [Alias("id")]
        [string]$AccountID,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Search,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Filter,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$FailedOnly
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $DependentAccountsURL = "$BaseURL/Accounts/{0}/DependentAccounts"
    }

    Process {
        Write-LogMessage -type Verbose -MSG "Retrieving dependent accounts for master account `"$AccountID`""

        $URL = $DependentAccountsURL -f $AccountID
        $queryParams = @()

        if (-not [string]::IsNullOrEmpty($Search)) {
            $queryParams += "search=$Search"
        }

        if (-not [string]::IsNullOrEmpty($Filter)) {
            $queryParams += "filter=$Filter"
        }

        if ($PSBoundParameters.ContainsKey('FailedOnly')) {
            $queryParams += "failed=$FailedOnly"
        }

        if ($queryParams.Count -gt 0) {
            $URL += "?" + ($queryParams -join "&")
        }

        $RestParms = @{
            Uri    = $URL
            Method = 'GET'
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $restResponse = Invoke-Rest @RestParms

        Write-LogMessage -type Verbose -MSG "Dependent accounts retrieved successfully for master account `"$AccountID`""
        return $restResponse
    }
}
#EndRegion '.\Public\PAS\Account\Linking\Get-DependentAccount.ps1' 113
#Region '.\Public\PAS\Account\Linking\Set-AccountLink.ps1' -1

<#
.SYNOPSIS
Sets the account link for a specified account in the PVWA.

.DESCRIPTION
The Set-AccountLink function links an account to an extra password in the PVWA. It supports multiple parameter sets to specify the extra password either by its type or by its index.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The authentication token for the PVWA.

.PARAMETER AccountID
The ID of the account to link.

.PARAMETER extraPass
The type of extra password to link (Logon, Enable, Reconcile).

.PARAMETER extraPassIndex
The index of the extra password to link.

.PARAMETER extraPassSafe
The safe where the extra password is stored.

.PARAMETER extraPassObject
The name of the extra password object.

.PARAMETER extraPassFolder
The folder where the extra password object is stored. Defaults to "Root".

.EXAMPLE
Set-Account -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12345" -extraPass Logon -extraPassSafe "Safe1" -extraPassObject "Object1"

.LINK
https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Implementing%20the%20REST%20API.htm
#>

enum extraPass {
    Logon       = 1
    Enable      = 2
    Reconcile   = 3
}

function Set-AccountLink {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL", SupportsShouldProcess = $true)]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Alias('ID')]
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [string]$AccountID,

        [Parameter(ParameterSetName = 'extraPass',Mandatory,ValueFromPipelineByPropertyName)]
        [extraPass]$extraPass,

        [Parameter(ParameterSetName = 'extraPasswordIndex',Mandatory,ValueFromPipelineByPropertyName)]
        [int]$extraPassIndex,

        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [string]$extraPassSafe,

        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [string]$extraPassObject,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$extraPassFolder = "Root"
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $AccountIDLink = "$BaseURL/Accounts/{0}/LinkAccount/"
    }

    Process {

        if ($PSCmdlet.ShouldProcess($AccountID, 'Set-AccountLink')) {

            $extraPassBody = @{
                safe = $extraPassSafe
                extraPasswordIndex =  $(if (-not [string]::IsNullOrEmpty($extraPass)) {$extraPass} else {$extraPassIndex})
                name =  $extraPassObject
                folder = $extraPassFolder
                }

            $URL = $AccountIDLink -f $AccountID
            $RestParms = @{
                Uri    = $URL
                Method = 'Post'
                Body   = ($extraPassBody | ConvertTo-Json -Depth 3)
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms
            Write-LogMessage -type Verbose -MSG "Set account `"$safeName`" successfully"
        }
        else {
            Write-LogMessage -type Warning -MSG "Skipping update of AccountID `"$AccountID`" due to confirmation being denied"
        }

    }
}
#EndRegion '.\Public\PAS\Account\Linking\Set-AccountLink.ps1' 114
#Region '.\Public\PAS\Account\Password\Get-AccountPassword.ps1' -1

<#
.SYNOPSIS
Retrieves the password or SSH key from an account in the PVWA system.

.DESCRIPTION
The Get-AccountPassword function connects to the PVWA API to retrieve the password or SSH key
of an existing account identified by its Account ID. It enables users to specify a reason
and ticket ID, if required.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication with the PVWA API.

.PARAMETER AccountID
The unique ID of the account to retrieve the password from.

.PARAMETER Reason
The reason for retrieving the password (if required by the platform).

.PARAMETER TicketID
The ticket ID for retrieving the password (if required by the platform).

.PARAMETER Version
The version of the password to retrieve (if not specified, retrieves the latest version).

.PARAMETER ActionType
The action type for retrieving the password.

.PARAMETER IsUse
Indicates whether the password is being retrieved for use.

.PARAMETER Machine
The machine for which the password is being retrieved.

.EXAMPLE
Get-AccountPassword -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34" -Reason "Maintenance"

Retrieves the password for account with ID "12_34" with the reason "Maintenance".

.EXAMPLE
Get-AccountPassword -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34" -Reason "Emergency" -TicketID "TICKET123"

Retrieves the password for account with ID "12_34" with a reason and ticket ID.

.NOTES
The user who runs this function requires Use Accounts permission in the Safe where the account is stored.
This function is part of the EPV-API-Common module and is used to manage accounts
in the CyberArk Privileged Access Security Web Application.
#>
function Get-AccountPassword {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [Alias("id")]
        [string]$AccountID,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Reason,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$TicketID,

        [Parameter(ValueFromPipelineByPropertyName)]
        [int]$Version,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ActionType,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$IsUse,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Machine
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $PasswordRetrieveURL = "$BaseURL/Accounts/{0}/Password/Retrieve"
    }

    Process {
        Write-LogMessage -type Verbose -MSG "Retrieving password for account with ID `"$AccountID`""

        $URL = $PasswordRetrieveURL -f $AccountID

        # Build the request body
        $body = @{}

        if (-not [string]::IsNullOrEmpty($Reason)) {
            $body["reason"] = $Reason
        }

        if (-not [string]::IsNullOrEmpty($TicketID)) {
            $body["ticketID"] = $TicketID
        }

        if ($Version -gt 0) {
            $body["version"] = $Version
        }

        if (-not [string]::IsNullOrEmpty($ActionType)) {
            $body["actionType"] = $ActionType
        }

        if ($PSBoundParameters.ContainsKey('IsUse')) {
            $body["isUse"] = $IsUse
        }

        if (-not [string]::IsNullOrEmpty($Machine)) {
            $body["machine"] = $Machine
        }

        $RestParms = @{
            Uri    = $URL
            Method = 'POST'
            Body   = $body
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $restResponse = Invoke-Rest @RestParms

        Write-LogMessage -type Verbose -MSG "Password retrieved successfully for account `"$AccountID`""
        return $restResponse
    }
}
#EndRegion '.\Public\PAS\Account\Password\Get-AccountPassword.ps1' 141
#Region '.\Public\PAS\Account\Password\Get-AccountSecretVersions.ps1' -1

<#
.SYNOPSIS
Retrieves all secret versions for an account in the PVWA system.

.DESCRIPTION
The Get-AccountSecretVersions function connects to the PVWA API to return all
secret versions for a specific account. This allows you to see the history
of password changes for the account.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication with the PVWA API.

.PARAMETER AccountID
The unique ID of the account to retrieve secret versions for.

.PARAMETER ShowTemporary
Whether to return both real and temporary password versions or only real versions.

.EXAMPLE
Get-AccountSecretVersions -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34"

Retrieves all real secret versions for account with ID "12_34".

.EXAMPLE
Get-AccountSecretVersions -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34" -ShowTemporary $true

Retrieves all secret versions (including temporary) for account with ID "12_34".

.NOTES
The user who runs this function requires 'List Accounts' and 'View Safe Members'
permissions in the Safe where the privileged account is stored.
This function is part of the EPV-API-Common module and is used to manage accounts
in the CyberArk Privileged Access Security Web Application.
#>
function Get-AccountSecretVersions {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [Alias("id")]
        [string]$AccountID,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$ShowTemporary
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $SecretVersionsURL = "$BaseURL/Accounts/{0}/Secret/Versions"
    }

    Process {
        Write-LogMessage -type Verbose -MSG "Retrieving secret versions for account `"$AccountID`""

        $URL = $SecretVersionsURL -f $AccountID

        if ($PSBoundParameters.ContainsKey('ShowTemporary')) {
            $URL += "?showTemporary=$ShowTemporary"
        }

        $RestParms = @{
            Uri    = $URL
            Method = 'GET'
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $restResponse = Invoke-Rest @RestParms

        Write-LogMessage -type Verbose -MSG "Secret versions retrieved successfully for account `"$AccountID`""
        return $restResponse
    }
}
#EndRegion '.\Public\PAS\Account\Password\Get-AccountSecretVersions.ps1' 88
#Region '.\Public\PAS\Account\Password\Invoke-AccountPasswordChange.ps1' -1

<#
.SYNOPSIS
Marks an account for immediate credentials change by the CPM in the PVWA system.

.DESCRIPTION
The Invoke-AccountPasswordChange function connects to the PVWA API to mark an account
for an immediate credentials change by the CPM (Central Policy Manager) to a new
random password. This operation triggers an immediate password change on the target system.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication with the PVWA API.

.PARAMETER AccountID
The unique ID of the account for which to change the password.

.PARAMETER ChangeImmediately
Indicates whether the password should be changed immediately.

.PARAMETER NewCredentials
The new credentials to set (if not specified, a random password will be generated).

.EXAMPLE
Invoke-AccountPasswordChange -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34"

Marks the account with ID "12_34" for immediate password change by the CPM.

.EXAMPLE
Invoke-AccountPasswordChange -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34" -ChangeImmediately $true

Marks the account with ID "12_34" for immediate password change with the ChangeImmediately flag set.

.NOTES
The user who runs this function requires 'Initiate CPM password management operations'
permission in the Safe where the privileged account is stored.
This function is part of the EPV-API-Common module and is used to manage accounts
in the CyberArk Privileged Access Security Web Application.
#>
function Invoke-AccountPasswordChange {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [Alias("id")]
        [string]$AccountID,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$ChangeImmediately,

        [Parameter(ValueFromPipelineByPropertyName)]
        [SecureString]$NewCredentials
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $AccountChangeURL = "$BaseURL/Accounts/{0}/Change"
    }

    Process {
        Write-LogMessage -type Verbose -MSG "Initiating password change for account `"$AccountID`""

        $URL = $AccountChangeURL -f $AccountID

        # Build the request body
        $body = @{}

        if ($PSBoundParameters.ContainsKey('ChangeImmediately')) {
            $body["changeImmediately"] = $ChangeImmediately
        }

        if ($NewCredentials) {
            $body["newCredentials"] = [System.Net.NetworkCredential]::new("", $NewCredentials).Password
        }

        $RestParms = @{
            Uri    = $URL
            Method = 'POST'
            Body   = $body
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $restResponse = Invoke-Rest @RestParms

        Write-LogMessage -type Verbose -MSG "Password change initiated successfully for account `"$AccountID`""
        return $restResponse
    }
}
#EndRegion '.\Public\PAS\Account\Password\Invoke-AccountPasswordChange.ps1' 102
#Region '.\Public\PAS\Account\Password\Invoke-AccountReconcile.ps1' -1

<#
.SYNOPSIS
Marks an account for automatic reconciliation by the CPM in the PVWA system.

.DESCRIPTION
The Invoke-AccountReconcile function connects to the PVWA API to mark an account
for automatic reconciliation by the CPM (Central Policy Manager). Reconciliation
is used when the password stored in the Vault is different from the password
on the target system.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication with the PVWA API.

.PARAMETER AccountID
The unique ID of the account to reconcile.

.EXAMPLE
Invoke-AccountReconcile -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34"

Marks the account with ID "12_34" for reconciliation by the CPM.

.NOTES
The user who runs this function requires 'Initiate CPM password management operations'
permission in the Safe where the privileged account is stored.
This function is part of the EPV-API-Common module and is used to manage accounts
in the CyberArk Privileged Access Security Web Application.
#>
function Invoke-AccountReconcile {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [Alias("id")]
        [string]$AccountID
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $AccountReconcileURL = "$BaseURL/Accounts/{0}/Reconcile"
    }

    Process {
        Write-LogMessage -type Verbose -MSG "Marking account `"$AccountID`" for reconciliation"

        $URL = $AccountReconcileURL -f $AccountID
        $RestParms = @{
            Uri    = $URL
            Method = 'POST'
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $restResponse = Invoke-Rest @RestParms

        Write-LogMessage -type Verbose -MSG "Account `"$AccountID`" marked for reconciliation successfully"
        return $restResponse
    }
}
#EndRegion '.\Public\PAS\Account\Password\Invoke-AccountReconcile.ps1' 73
#Region '.\Public\PAS\Account\Password\Invoke-AccountVerify.ps1' -1

<#
.SYNOPSIS
Marks an account for verification by the CPM in the PVWA system.

.DESCRIPTION
The Invoke-AccountVerify function connects to the PVWA API to mark an account for verification
by the CPM (Central Policy Manager). This operation checks if the stored password
matches the password on the target system.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication with the PVWA API.

.PARAMETER AccountID
The unique ID of the account to verify.

.EXAMPLE
Invoke-AccountVerify -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34"

Marks the account with ID "12_34" for verification by the CPM.

.NOTES
The user who runs this function requires 'Initiate CPM password management operations'
permission in the Safe where the privileged account is stored.
This function is part of the EPV-API-Common module and is used to manage accounts
in the CyberArk Privileged Access Security Web Application.
This function can be used from PAM v9.10 and above.
#>
function Invoke-AccountVerify {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [Alias("id")]
        [string]$AccountID
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $AccountVerifyURL = "$BaseURL/Accounts/{0}/Verify"
    }

    Process {
        Write-LogMessage -type Verbose -MSG "Marking account `"$AccountID`" for verification"

        $URL = $AccountVerifyURL -f $AccountID
        $RestParms = @{
            Uri    = $URL
            Method = 'POST'
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $restResponse = Invoke-Rest @RestParms

        Write-LogMessage -type Verbose -MSG "Account `"$AccountID`" marked for verification successfully"
        return $restResponse
    }
}
#EndRegion '.\Public\PAS\Account\Password\Invoke-AccountVerify.ps1' 73
#Region '.\Public\PAS\Account\Password\New-AccountPassword.ps1' -1

<#
.SYNOPSIS
Generates a new password for an account in the PVWA system.

.DESCRIPTION
The New-AccountPassword function connects to the PVWA API to generate a new password
for an existing account based on the account's platform complexity rules. The new
password will be returned but not stored on the account.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication with the PVWA API.

.PARAMETER AccountID
The unique ID of the account to generate a password for.

.PARAMETER Length
The length of the password to generate (if supported by platform).

.PARAMETER UseComplexity
Whether to use the platform's complexity rules.

.PARAMETER PasswordLevel
The password level/complexity to use.

.EXAMPLE
New-AccountPassword -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34"

Generates a new password for account with ID "12_34" using the platform's default complexity.

.EXAMPLE
New-AccountPassword -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34" -Length 16

Generates a new 16-character password for account with ID "12_34".

.NOTES
This function generates a password but does not store it on the account.
The user who runs this function requires appropriate permissions in the Safe
where the privileged account is stored.
This function is part of the EPV-API-Common module and is used to manage accounts
in the CyberArk Privileged Access Security Web Application.
#>
function New-AccountPassword {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [Alias("id")]
        [string]$AccountID,

        [Parameter(ValueFromPipelineByPropertyName)]
        [int]$Length,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$UseComplexity
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $GeneratePasswordURL = "$BaseURL/Accounts/{0}/Secret/Generate"
    }

    Process {
        Write-LogMessage -type Verbose -MSG "Generating password for account `"$AccountID`""

        $URL = $GeneratePasswordURL -f $AccountID

        # Build the request body
        $body = @{}

        if ($Length -gt 0) {
            $body["length"] = $Length
        }

        if ($PSBoundParameters.ContainsKey('UseComplexity')) {
            $body["useComplexity"] = $UseComplexity
        }

        $RestParms = @{
            Uri    = $URL
            Method = 'POST'
            Body   = $body
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $restResponse = Invoke-Rest @RestParms

        Write-LogMessage -type Verbose -MSG "Password generated successfully for account `"$AccountID`""
        return $restResponse
    }
}
#EndRegion '.\Public\PAS\Account\Password\New-AccountPassword.ps1' 106
#Region '.\Public\PAS\Account\Password\Set-AccountNextPassword.ps1' -1

<#
.SYNOPSIS
Sets the account's credentials for the next CPM change in the PVWA system.

.DESCRIPTION
The Set-AccountNextPassword function connects to the PVWA API to set the account's
credentials for the next CPM (Central Policy Manager) change. This allows you to
specify what the password should be changed to on the next CPM change cycle.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication with the PVWA API.

.PARAMETER AccountID
The unique ID of the account to set the next password for.

.PARAMETER NextPassword
The password to be set on the next CPM change.

.PARAMETER ChangeImmediately
Indicates whether the password should be changed immediately after setting.

.EXAMPLE
Set-AccountNextPassword -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34" -NextPassword (ConvertTo-SecureString "NextP@ssw0rd" -AsPlainText -Force)

Sets the next password for account with ID "12_34" to be used on the next CPM change.

.NOTES
The user who runs this function requires 'Initiate CPM password management operations'
and 'Specify next password value' permissions in the Safe where the privileged account is stored.
This function is part of the EPV-API-Common module and is used to manage accounts
in the CyberArk Privileged Access Security Web Application.
#>
function Set-AccountNextPassword {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [Alias("id")]
        [string]$AccountID,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [SecureString]$NextPassword,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$ChangeImmediately
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $SetNextPasswordURL = "$BaseURL/Accounts/{0}/SetNextPassword"
    }

    Process {
        Write-LogMessage -type Verbose -MSG "Setting next password for account `"$AccountID`""

        $URL = $SetNextPasswordURL -f $AccountID

        # Build the request body
        $body = @{
            "changeCredentials" = [System.Net.NetworkCredential]::new("", $NextPassword).Password
        }

        if ($PSBoundParameters.ContainsKey('ChangeImmediately')) {
            $body["changeImmediately"] = $ChangeImmediately
        }

        $RestParms = @{
            Uri    = $URL
            Method = 'POST'
            Body   = $body
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $restResponse = Invoke-Rest @RestParms

        Write-LogMessage -type Verbose -MSG "Next password set successfully for account `"$AccountID`""
        return $restResponse
    }
}
#EndRegion '.\Public\PAS\Account\Password\Set-AccountNextPassword.ps1' 95
#Region '.\Public\PAS\Account\Password\Set-AccountPassword.ps1' -1

<#
.SYNOPSIS
Updates an account's credentials in the Vault without affecting the target device.

.DESCRIPTION
The Set-AccountPassword function connects to the PVWA API to set the account's
credentials and change it in the Vault only. This will not affect the credentials
on the target device. This is useful when the password was changed externally
and needs to be updated in the Vault.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication with the PVWA API.

.PARAMETER AccountID
The unique ID of the account to update the password for.

.PARAMETER NewPassword
The new password to set in the Vault.

.PARAMETER ChangeEntireGroup
Indicates whether to change the password for the entire group (for group accounts).

.EXAMPLE
Set-AccountPassword -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34" -NewPassword (ConvertTo-SecureString "NewP@ssw0rd" -AsPlainText -Force)

Updates the password for account with ID "12_34" in the Vault.

.NOTES
The user who runs this function requires 'Update password value' permission in the Safe
where the privileged account is stored.
This function is part of the EPV-API-Common module and is used to manage accounts
in the CyberArk Privileged Access Security Web Application.
#>
function Set-AccountPassword {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [Alias("id")]
        [string]$AccountID,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [SecureString]$NewPassword,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$ChangeEntireGroup
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $PasswordUpdateURL = "$BaseURL/Accounts/{0}/Password/Update"
    }

    Process {
        Write-LogMessage -type Verbose -MSG "Updating password in Vault for account `"$AccountID`""

        $URL = $PasswordUpdateURL -f $AccountID

        # Build the request body
        $body = @{
            "newCredentials" = [System.Net.NetworkCredential]::new("", $NewPassword).Password
        }

        if ($PSBoundParameters.ContainsKey('ChangeEntireGroup')) {
            $body["changeEntireGroup"] = $ChangeEntireGroup
        }

        $RestParms = @{
            Uri    = $URL
            Method = 'POST'
            Body   = $body
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $restResponse = Invoke-Rest @RestParms

        Write-LogMessage -type Verbose -MSG "Password updated in Vault successfully for account `"$AccountID`""
        return $restResponse
    }
}
#EndRegion '.\Public\PAS\Account\Password\Set-AccountPassword.ps1' 96
#Region '.\Public\PAS\Application\Get-Application.ps1' -1

# TODO: Implement Get-Application function
# This function should retrieve application information from the PVWA API
function Get-Application {
    [CmdletBinding()]
    param()

    Write-Warning "Function not yet implemented. This will retrieve application information."
}
#EndRegion '.\Public\PAS\Application\Get-Application.ps1' 9
#Region '.\Public\PAS\ConnectorManagement\Add-ConnectorPoolIdentifier.ps1' -1

<#
.SYNOPSIS
Adds a pool identifier to a connector pool in the Connector Management API.                Write-LogMessage -type Success -MSG "Successfully added identifier to pool: $PoolId"

.DESCRIPTION
The Add-ConnectorPoolIdentifier function adds a new identifier to a connector pool in the CyberArk Connector Management API.

.PARAMETER CMURL
The URL of the CyberArk Connector Management service in the format https://<subdomain>.connectormanagement.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER PoolId
The unique identifier of the pool to add the identifier to (mandatory).

.PARAMETER Type
The type of the identifier (mandatory).

.PARAMETER Value
The value of the identifier (mandatory).

.PARAMETER AdditionalProperties
Additional properties to include in the identifier request body (optional).

.EXAMPLE
Add-ConnectorPoolIdentifier -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token -PoolId "12345678-1234-1234-1234-123456789012" -Type "IP" -Value "192.168.1.100"

.NOTES
This function requires the CMURL and a valid logon token to authenticate API requests.
Uses the /pools/{pool_id}/identifiers endpoint with POST method.

#>

function Add-ConnectorPoolIdentifier {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'ConnectorManagementURL')]
        [string]$CMURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$PoolId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [string]$Type,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [string]$Value,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$AdditionalProperties
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }

    Process {
        try {
            $URL = "$CMURL/pools/$PoolId/identifiers"

            # Build the request body from individual parameters
            $RequestBody = @{
                type = $Type
                value = $Value
            }

            # Add any additional properties if provided
            if ($PSBoundParameters.ContainsKey('AdditionalProperties') -and $AdditionalProperties.Count -gt 0) {
                foreach ($key in $AdditionalProperties.Keys) {
                    $RequestBody[$key] = $AdditionalProperties[$key]
                }
            }

            $Body = $RequestBody | ConvertTo-Json -Depth 10 -Compress

            Write-LogMessage -type Verbose -MSG "Adding identifier to pool: $PoolId"
            Write-LogMessage -type Verbose -MSG "Identifier type: $Type, value: $Value"
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"
            Write-LogMessage -type Verbose -MSG "Request Body: $Body"

            $RestParms = @{
                Uri         = $URL
                Method      = 'POST'
                Body        = $Body
                ContentType = "application/json"
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms

            Write-LogMessage -type Success -MSG "Successfully added identifier to pool: $PoolId"
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to add identifier to pool $PoolId. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\ConnectorManagement\Add-ConnectorPoolIdentifier.ps1' 109
#Region '.\Public\PAS\ConnectorManagement\Get-ConnectorIdentifierType.ps1' -1

<#
.SYNOPSIS
Gets identifi.NOTES
This function requires the CMUR        try {
            $URL = "$CMURL/identifier-types"and a valid logon token to authenticate API requests.
Uses the /identifier-types endpoint.types from the Connector Management API.

.DESCRIPTION
The Get-ConnectorIdentifierType function retrieves available identifier types from the CyberArk Connector Management API.

.PARAMETER CMURL
The URL of the CyberArk Connector Management service in the format https://<subdomain>.connectormanagement.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER Order
Order by parameter. ASC/DESC.

.PARAMETER PageSize
Page size for pagination.

.PARAMETER Sort
Sort by parameter.

.PARAMETER ContinuationToken
Continuation token for pagination.

.EXAMPLE
Get-ConnectorIdentifierType -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token

.NOTES
This function requires the ConnectorManagementURL and a valid logon token to authenticate API requests.
Uses the /pools/identifier-types endpoint.

#>

function Get-ConnectorIdentifierType {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'ConnectorManagementURL')]
        [string]$CMURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet("ASC", "DESC")]
        [string]$Order,

        [Parameter(ValueFromPipelineByPropertyName)]
        [int]$PageSize,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Sort,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ContinuationToken
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }

    Process {
        try {
            $URL = "$ConnectorManagementURL/pools/identifier-types"

            # Build query parameters
            $QueryParams = @()
            if (-not [string]::IsNullOrEmpty($Order)) {
                $QueryParams += "order=$Order"
            }
            if ($PSBoundParameters.ContainsKey('PageSize')) {
                $QueryParams += "pageSize=$PageSize"
            }
            if (-not [string]::IsNullOrEmpty($Sort)) {
                $QueryParams += "sort=$([System.Web.HttpUtility]::UrlEncode($Sort))"
            }
            if (-not [string]::IsNullOrEmpty($ContinuationToken)) {
                $QueryParams += "continuationToken=$([System.Web.HttpUtility]::UrlEncode($ContinuationToken))"
            }

            if ($QueryParams.Count -gt 0) {
                $URL += "?" + ($QueryParams -join "&")
            }

            Write-LogMessage -type Verbose -MSG "Getting identifier types"
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"

            $RestParms = @{
                Uri    = $URL
                Method = 'GET'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to get identifier types. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\ConnectorManagement\Get-ConnectorIdentifierType.ps1' 110
#Region '.\Public\PAS\ConnectorManagement\Get-ConnectorNetwork.ps1' -1

<#
.SYNOPSIS
Gets connector networks from the Connector Management API.

.DESCRIPTION
The Get-ConnectorNetwork function retrieves connector networks from the CyberArk Connector Management API. It supports both getting all networks with optional filtering/searching and getting a specific network by ID.

.PARAMETER CMURL
The URL of the CyberArk Connector Management service in the format https://<subdomain>.connectormanagement.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER NetworkId
The unique identifier of the network to retrieve (for single network mode).

.PARAMETER Name
The name of the network to search for (optional). This is a convenience parameter that creates a filter for you.

.PARAMETER Filter
Filter parameter for the results. Supports filtering by name and description.

.PARAMETER Order
Order by parameter. ASC/DESC.

.PARAMETER PageSize
Page size for pagination.

.PARAMETER Projection
Projection of the response. BASIC/EXTENDED.

.PARAMETER Sort
Sort by parameter.

.PARAMETER ContinuationToken
Continuation token for pagination.

.EXAMPLE
Get-ConnectorNetwork -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token

.EXAMPLE
Get-ConnectorNetwork -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token -NetworkId "12345678-1234-1234-1234-123456789012"

.EXAMPLE
Get-ConnectorNetwork -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token -Name "Production Network"

.EXAMPLE
Get-ConnectorNetwork -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token -Filter 'name:=="Production Network"' -Projection "EXTENDED"

.NOTES
This function requires the CMURL and a valid logon token to authenticate API requests.
Uses the /networks endpoint.

#>

function Get-ConnectorNetwork {
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'ConnectorManagementURL')]
        [string]$CMURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(ParameterSetName = 'ByID', Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$NetworkId,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [string]$Filter,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [ValidateSet("ASC", "DESC")]
        [string]$Order,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [int]$PageSize,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [ValidateSet("BASIC", "EXTENDED")]
        [string]$Projection,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [string]$Sort,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [string]$ContinuationToken
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }

    Process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'ByID') {
                # Get specific network by ID
                $URL = "$CMURL/networks/$NetworkId"
                Write-LogMessage -type Verbose -MSG "Getting connector network with ID: $NetworkId"
            }
            else {
                # Get all networks with optional parameters
                $URL = "$CMURL/networks"

                # Build query parameters
                $QueryParams = @()

                # Handle Name parameter (convenience filter)
                if (-not [string]::IsNullOrEmpty($Name)) {
                    $nameFilter = "name:`"$Name`""
                    $QueryParams += "filter=$([System.Web.HttpUtility]::UrlEncode($nameFilter))"
                }
                elseif (-not [string]::IsNullOrEmpty($Filter)) {
                    $QueryParams += "filter=$([System.Web.HttpUtility]::UrlEncode($Filter))"
                }
                if (-not [string]::IsNullOrEmpty($Order)) {
                    $QueryParams += "order=$Order"
                }
                if ($PSBoundParameters.ContainsKey('PageSize')) {
                    $QueryParams += "pageSize=$PageSize"
                }
                if (-not [string]::IsNullOrEmpty($Projection)) {
                    $QueryParams += "projection=$Projection"
                }
                if (-not [string]::IsNullOrEmpty($Sort)) {
                    $QueryParams += "sort=$([System.Web.HttpUtility]::UrlEncode($Sort))"
                }
                if (-not [string]::IsNullOrEmpty($ContinuationToken)) {
                    $QueryParams += "continuationToken=$([System.Web.HttpUtility]::UrlEncode($ContinuationToken))"
                }

                if ($QueryParams.Count -gt 0) {
                    $URL += "?" + ($QueryParams -join "&")
                }

                Write-LogMessage -type Verbose -MSG "Getting connector networks with parameters"
            }

            Write-LogMessage -type Verbose -MSG "Request URL: $URL"

            $RestParms = @{
                Uri    = $URL
                Method = 'GET'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to get connector network(s). Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\ConnectorManagement\Get-ConnectorNetwork.ps1' 163
#Region '.\Public\PAS\ConnectorManagement\Get-ConnectorPool.ps1' -1

<#
.SYNOPSIS
Gets connector pools from the Connector Management API.

.DESCRIPTION
The Get-ConnectorPool function retrieves connector pools from the CyberArk Connector Management API. It supports both getting all pools with optional filtering/searching and getting a specific pool by ID.

.PARAMETER CMURL
The URL of the CyberArk Connector Management service in the format https://<subdomain>.connectormanagement.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER PoolId
The unique identifier of the pool to retrieve (for single pool mode).

.PARAMETER Name
The name of the pool to search for (optional). This is a convenience parameter that creates a filter for you.

.PARAMETER Filter
Filter parameter for the results. Supports filtering by name, description, type, networks.id, networks.name, identifiers.type, identifiers.value, components.type.

.PARAMETER Order
Order by parameter. ASC/DESC.

.PARAMETER PageSize
Page size for pagination.

.PARAMETER Projection
Projection of the response. BASIC/EXTENDED.

.PARAMETER Sort
Sort by parameter.

.PARAMETER ContinuationToken
Continuation token for pagination.

.EXAMPLE
Get-ConnectorPool -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token

.EXAMPLE
Get-ConnectorPool -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token -PoolId "12345678-1234-1234-1234-123456789012"

.EXAMPLE
Get-ConnectorPool -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token -Name "Production Pool"

.EXAMPLE
Get-ConnectorPool -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token -Filter 'name:=="Production Pool"' -Projection "EXTENDED"

.NOTES
This function requires the CMURL and a valid logon token to authenticate API requests.
Uses the /pools endpoint.

#>

function Get-ConnectorPool {
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'ConnectorManagementURL')]
        [string]$CMURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(ParameterSetName = 'ByID', Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$PoolId,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [string]$Filter,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [ValidateSet("ASC", "DESC")]
        [string]$Order,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [int]$PageSize,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [ValidateSet("BASIC", "EXTENDED")]
        [string]$Projection,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [string]$Sort,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [string]$ContinuationToken
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }

    Process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'ByID') {
                # Get specific pool by ID
                $URL = "$CMURL/pools/$PoolId"
                Write-LogMessage -type Verbose -MSG "Getting connector pool with ID: $PoolId"
            }
            else {
                # Get all pools with optional parameters
                $URL = "$CMURL/pools"

                # Build query parameters
                $QueryParams = @()

                # Handle Name parameter (convenience filter)
                if (-not [string]::IsNullOrEmpty($Name)) {
                    $nameFilter = "name:`"$Name`""
                    $QueryParams += "filter=$([System.Web.HttpUtility]::UrlEncode($nameFilter))"
                }
                elseif (-not [string]::IsNullOrEmpty($Filter)) {
                    $QueryParams += "filter=$([System.Web.HttpUtility]::UrlEncode($Filter))"
                }
                if (-not [string]::IsNullOrEmpty($Order)) {
                    $QueryParams += "order=$Order"
                }
                if ($PSBoundParameters.ContainsKey('PageSize')) {
                    $QueryParams += "pageSize=$PageSize"
                }
                if (-not [string]::IsNullOrEmpty($Projection)) {
                    $QueryParams += "projection=$Projection"
                }
                if (-not [string]::IsNullOrEmpty($Sort)) {
                    $QueryParams += "sort=$([System.Web.HttpUtility]::UrlEncode($Sort))"
                }
                if (-not [string]::IsNullOrEmpty($ContinuationToken)) {
                    $QueryParams += "continuationToken=$([System.Web.HttpUtility]::UrlEncode($ContinuationToken))"
                }

                if ($QueryParams.Count -gt 0) {
                    $URL += "?" + ($QueryParams -join "&")
                }

                Write-LogMessage -type Verbose -MSG "Getting connector pools with parameters"
            }

            Write-LogMessage -type Verbose -MSG "Request URL: $URL"

            $RestParms = @{
                Uri    = $URL
                Method = 'GET'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to get connector pool(s). Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\ConnectorManagement\Get-ConnectorPool.ps1' 163
#Region '.\Public\PAS\ConnectorManagement\Get-ConnectorPoolIdentifier.ps1' -1

<#
.SYNOPSIS
Gets pool identifiers from the Connector Management API.

.DESCRIPTION
The Get-ConnectorPoolIdentifier function retrieves pool identifiers from the CyberArk Connector Management API for a specific pool.

.PARAMETER CMURL
The URL of the CyberArk Connector Management service in the format https://<subdomain>.connectormanagement.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER PoolId
The unique identifier of the pool to get identifiers for (mandatory).

.PARAMETER Type
The type of identifier to search for (optional). This is a convenience parameter that creates a filter for you.

.PARAMETER Filter
Filter parameter for the results.

.PARAMETER Order
Order by parameter. ASC/DESC.

.PARAMETER PageSize
Page size for pagination.

.PARAMETER Projection
Projection of the response. BASIC/EXTENDED.

.PARAMETER Sort
Sort by parameter.

.PARAMETER ContinuationToken
Continuation token for pagination.

.EXAMPLE
Get-ConnectorPoolIdentifier -ConnectorManagementURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token -PoolId "12345678-1234-1234-1234-123456789012"

.EXAMPLE
Get-ConnectorPoolIdentifier -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token -PoolId "12345678-1234-1234-1234-123456789012" -Type "IP"

.EXAMPLE
Get-ConnectorPoolIdentifier -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token -PoolId "12345678-1234-1234-1234-123456789012" -Filter 'type:=="IP"'

.NOTES
This function requires the CMURL and a valid logon token to authenticate API requests.
Uses the /pools/{pool_id}/identifiers endpoint.

#>

function Get-ConnectorPoolIdentifier {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'ConnectorManagementURL')]
        [string]$CMURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$PoolId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Type,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Filter,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet("ASC", "DESC")]
        [string]$Order,

        [Parameter(ValueFromPipelineByPropertyName)]
        [int]$PageSize,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet("BASIC", "EXTENDED")]
        [string]$Projection,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Sort,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ContinuationToken
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }

    Process {
        try {
            $URL = "$CMURL/pools/$PoolId/identifiers"

            # Build query parameters
            $QueryParams = @()

            # Handle Type parameter (convenience filter)
            if (-not [string]::IsNullOrEmpty($Type)) {
                $typeFilter = "type:`"$Type`""
                $QueryParams += "filter=$([System.Web.HttpUtility]::UrlEncode($typeFilter))"
            }
            elseif (-not [string]::IsNullOrEmpty($Filter)) {
                $QueryParams += "filter=$([System.Web.HttpUtility]::UrlEncode($Filter))"
            }
            if (-not [string]::IsNullOrEmpty($Order)) {
                $QueryParams += "order=$Order"
            }
            if ($PSBoundParameters.ContainsKey('PageSize')) {
                $QueryParams += "pageSize=$PageSize"
            }
            if (-not [string]::IsNullOrEmpty($Projection)) {
                $QueryParams += "projection=$Projection"
            }
            if (-not [string]::IsNullOrEmpty($Sort)) {
                $QueryParams += "sort=$([System.Web.HttpUtility]::UrlEncode($Sort))"
            }
            if (-not [string]::IsNullOrEmpty($ContinuationToken)) {
                $QueryParams += "continuationToken=$([System.Web.HttpUtility]::UrlEncode($ContinuationToken))"
            }

            if ($QueryParams.Count -gt 0) {
                $URL += "?" + ($QueryParams -join "&")
            }

            Write-LogMessage -type Verbose -MSG "Getting pool identifiers for pool: $PoolId"
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"

            $RestParms = @{
                Uri    = $URL
                Method = 'GET'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to get pool identifiers for pool $PoolId. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\ConnectorManagement\Get-ConnectorPoolIdentifier.ps1' 151
#Region '.\Public\PAS\ConnectorManagement\New-ConnectorNetwork.ps1' -1

<#
.SYNOPSIS
Creates a new connector network in the Connector Management API.

.DESCRIPTION
The New-ConnectorNetwork function creates a new connector network in the CyberArk Connector Management API using the provided network data.

.PARAMETER CMURL
The URL of the CyberArk Connector Management service in the format https://<subdomain>.connectormanagement.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER Name
The name of the network (mandatory).

.PARAMETER Description
The description of the network (optional).

.PARAMETER AdditionalProperties
Additional properties to include in the network request body (optional).

.EXAMPLE
New-ConnectorNetwork -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token -Name "Production Network" -Description "Network for production environments"

.NOTES
This function requires the CMURL and a valid logon token to authenticate API requests.
Uses the /networks endpoint with POST method.

#>

function New-ConnectorNetwork {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'ConnectorManagementURL')]
        [string]$CMURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$AdditionalProperties
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }

    Process {
        try {
            $URL = "$CMURL/networks"

            # Build the request body from individual parameters
            $RequestBody = @{
                name = $Name
            }

            # Add optional description if provided
            if (-not [string]::IsNullOrEmpty($Description)) {
                $RequestBody.description = $Description
            }

            # Add any additional properties if provided
            if ($PSBoundParameters.ContainsKey('AdditionalProperties') -and $AdditionalProperties.Count -gt 0) {
                foreach ($key in $AdditionalProperties.Keys) {
                    $RequestBody[$key] = $AdditionalProperties[$key]
                }
            }

            $Body = $RequestBody | ConvertTo-Json -Depth 10 -Compress

            Write-LogMessage -type Verbose -MSG "Creating new connector network: $Name"
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"
            Write-LogMessage -type Verbose -MSG "Request Body: $Body"

            $RestParms = @{
                Uri         = $URL
                Method      = 'POST'
                Body        = $Body
                ContentType = "application/json"
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms

            Write-LogMessage -type Success -MSG "Successfully created connector network: $Name (ID: $($restResponse.id))"
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to create connector network '$Name'. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\ConnectorManagement\New-ConnectorNetwork.ps1' 105
#Region '.\Public\PAS\ConnectorManagement\New-ConnectorPool.ps1' -1

<#
.SYNOPSIS
Creates a new connector pool in the Connector Management API.

.DESCRIPTION
The New-ConnectorPool function creates a new connector pool in the CyberArk Connector Management API using the provided pool data.

.PARAMETER CMURL
The URL of the CyberArk Connector Management service in the format https://<subdomain>.connectormanagement.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER Name
The name of the pool (mandatory).

.PARAMETER Description
The description of the pool (optional).

.PARAMETER Type
The type of the pool (mandatory).

.PARAMETER Networks
Array of network objects associated with the pool (optional).

.PARAMETER Identifiers
Array of identifier objects for the pool (optional).

.PARAMETER Components
Array of component objects for the pool (optional).

.PARAMETER AdditionalProperties
Additional properties to include in the pool request body (optional).

.EXAMPLE
New-ConnectorPool -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token -Name "Production Pool" -Description "Pool for production environments" -Type "CONNECTOR"

.EXAMPLE
$networks = @(
    @{
        id = "network-123"
        name = "Production Network"
    }
)
New-ConnectorPool -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token -Name "Production Pool" -Type "CONNECTOR" -Networks $networks

.NOTES
This function requires the CMURL and a valid logon token to authenticate API requests.
Uses the /pools endpoint with POST method.

#>

function New-ConnectorPool {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'ConnectorManagementURL')]
        [string]$CMURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [string]$Type,

        [Parameter(ValueFromPipelineByPropertyName)]
        [array]$Networks,

        [Parameter(ValueFromPipelineByPropertyName)]
        [array]$Identifiers,

        [Parameter(ValueFromPipelineByPropertyName)]
        [array]$Components,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$AdditionalProperties
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }

    Process {
        try {
            $URL = "$CMURL/pools"

            # Build the request body from individual parameters
            $RequestBody = @{
                name = $Name
                type = $Type
            }

            # Add optional description if provided
            if (-not [string]::IsNullOrEmpty($Description)) {
                $RequestBody.description = $Description
            }

            # Add optional networks if provided
            if ($PSBoundParameters.ContainsKey('Networks') -and $Networks.Count -gt 0) {
                $RequestBody.networks = $Networks
            }

            # Add optional identifiers if provided
            if ($PSBoundParameters.ContainsKey('Identifiers') -and $Identifiers.Count -gt 0) {
                $RequestBody.identifiers = $Identifiers
            }

            # Add optional components if provided
            if ($PSBoundParameters.ContainsKey('Components') -and $Components.Count -gt 0) {
                $RequestBody.components = $Components
            }

            # Add any additional properties if provided
            if ($PSBoundParameters.ContainsKey('AdditionalProperties') -and $AdditionalProperties.Count -gt 0) {
                foreach ($key in $AdditionalProperties.Keys) {
                    $RequestBody[$key] = $AdditionalProperties[$key]
                }
            }

            $Body = $RequestBody | ConvertTo-Json -Depth 10 -Compress

            Write-LogMessage -type Verbose -MSG "Creating new connector pool: $Name"
            Write-LogMessage -type Verbose -MSG "Pool type: $Type"
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"
            Write-LogMessage -type Verbose -MSG "Request Body: $Body"

            $RestParms = @{
                Uri         = $URL
                Method      = 'POST'
                Body        = $Body
                ContentType = "application/json"
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms

            Write-LogMessage -type Success -MSG "Successfully created connector pool: $Name (ID: $($restResponse.id))"
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to create connector pool '$Name'. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\ConnectorManagement\New-ConnectorPool.ps1' 155
#Region '.\Public\PAS\ConnectorManagement\Remove-ConnectorNetwork.ps1' -1

<#
.SYNOPSIS
Removes a connector network from the Connector Management API.

.DESCRIPTION
The Remove-ConnectorNetwork function deletes a connector network from the CyberArk Connector Management API based on the network ID.

.PARAMETER CMURL
The URL of the CyberArk Connector Management service in the format https://<subdomain>.connectormanagement.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER NetworkId
The unique identifier of the network to delete (mandatory).

.EXAMPLE
Remove-ConnectorNetwork -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token -NetworkId "12345678-1234-1234-1234-123456789012"

.NOTES
This function requires the CMURL and a valid logon token to authenticate API requests.
Uses the /networks/{network_id} endpoint with DELETE method.

#>

function Remove-ConnectorNetwork {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'ConnectorManagementURL')]
        [string]$CMURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$NetworkId
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }

    Process {
        if ($PSCmdlet.ShouldProcess($NetworkId, "Delete Connector Network")) {
            try {
                $URL = "$CMURL/networks/$NetworkId"

                Write-LogMessage -type Verbose -MSG "Deleting connector network with ID: $NetworkId"
                Write-LogMessage -type Verbose -MSG "Request URL: $URL"

                $RestParms = @{
                    Uri    = $URL
                    Method = 'DELETE'
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                $restResponse = Invoke-Rest @RestParms

                Write-LogMessage -type Success -MSG "Successfully deleted connector network: $NetworkId"
                return $restResponse
            }
            catch {
                Write-LogMessage -type Error -MSG "Failed to delete connector network $NetworkId. Error: $($_.Exception.Message)"
                throw
            }
        }
    }
}
#EndRegion '.\Public\PAS\ConnectorManagement\Remove-ConnectorNetwork.ps1' 74
#Region '.\Public\PAS\ConnectorManagement\Remove-ConnectorPool.ps1' -1

<#
.SYNOPSIS
Removes a connector pool from the Connector Management API.

.DESCRIPTION
The Remove-ConnectorPool function deletes a connector pool from the CyberArk Connector Management API based on the pool ID.

.PARAMETER CMURL
The URL of the CyberArk Connector Management service in the format https://<subdomain>.connectormanagement.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER PoolId
The unique identifier of the pool to delete (mandatory).

.EXAMPLE
Remove-ConnectorPool -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token -PoolId "12345678-1234-1234-1234-123456789012"

.NOTES
This function requires the CMURL and a valid logon token to authenticate API requests.
Uses the /pools/{pool_id} endpoint with DELETE method.

#>

function Remove-ConnectorPool {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'ConnectorManagementURL')]
        [string]$CMURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$PoolId
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }

    Process {
        if ($PSCmdlet.ShouldProcess($PoolId, "Delete Connector Pool")) {
            try {
                $URL = "$CMURL/pools/$PoolId"

                Write-LogMessage -type Verbose -MSG "Deleting connector pool with ID: $PoolId"
                Write-LogMessage -type Verbose -MSG "Request URL: $URL"

                $RestParms = @{
                    Uri    = $URL
                    Method = 'DELETE'
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                $restResponse = Invoke-Rest @RestParms

                Write-LogMessage -type Success -MSG "Successfully deleted connector pool: $PoolId"
                return $restResponse
            }
            catch {
                Write-LogMessage -type Error -MSG "Failed to delete connector pool $PoolId. Error: $($_.Exception.Message)"
                throw
            }
        }
    }
}
#EndRegion '.\Public\PAS\ConnectorManagement\Remove-ConnectorPool.ps1' 74
#Region '.\Public\PAS\ConnectorManagement\Remove-ConnectorPoolIdentifier.ps1' -1

<#
.SYNOPSIS
Removes a pool identifier from a connector pool in the Connector Management API.

.DESCRIPTION
The Remove-ConnectorPoolIdentifier function removes an identifier from a connector pool in the CyberArk Connector Management API.

.PARAMETER CMURL
The URL of the CyberArk Connector Management service in the format https://<subdomain>.connectormanagement.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER PoolId
The unique identifier of the pool to remove the identifier from (mandatory).

.PARAMETER IdentifierId
The unique identifier of the identifier to remove (mandatory).

.EXAMPLE
Remove-ConnectorPoolIdentifier -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token -PoolId "12345678-1234-1234-1234-123456789012" -IdentifierId "87654321-4321-4321-4321-210987654321"

.NOTES
This function requires the CMURL and a valid logon token to authenticate API requests.
Uses the /pools/{pool_id}/identifiers/{identifier_id} endpoint with DELETE method.

#>

function Remove-ConnectorPoolIdentifier {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'ConnectorManagementURL')]
        [string]$CMURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$PoolId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$IdentifierId
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }

    Process {
        if ($PSCmdlet.ShouldProcess("$PoolId/$IdentifierId", "Remove Pool Identifier")) {
            try {
                $URL = "$CMURL/pools/$PoolId/identifiers/$IdentifierId"

                Write-LogMessage -type Verbose -MSG "Removing identifier $IdentifierId from pool: $PoolId"
                Write-LogMessage -type Verbose -MSG "Request URL: $URL"

                $RestParms = @{
                    Uri    = $URL
                    Method = 'DELETE'
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                $restResponse = Invoke-Rest @RestParms

                Write-LogMessage -type Success -MSG "Successfully removed identifier $IdentifierId from pool: $PoolId"
                return $restResponse
            }
            catch {
                Write-LogMessage -type Error -MSG "Failed to remove identifier $IdentifierId from pool $PoolId. Error: $($_.Exception.Message)"
                throw
            }
        }
    }
}
#EndRegion '.\Public\PAS\ConnectorManagement\Remove-ConnectorPoolIdentifier.ps1' 81
#Region '.\Public\PAS\ConnectorManagement\Set-ConnectorNetwork.ps1' -1

<#
.SYNOPSIS
Updates an existing connector network in the Connector Management API.

.DESCRIPTION
The Set-ConnectorNetwork function updates an existing connector network in the CyberArk Connector Management API using the provided network data.

.PARAMETER CMURL
The URL of the CyberArk Connector Management service in the format https://<subdomain>.connectormanagement.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER NetworkId
The unique identifier of the network to update (mandatory).

.PARAMETER Name
The name of the network (optional).

.PARAMETER Description
The description of the network (optional).

.PARAMETER AdditionalProperties
Additional properties to include in the network request body (optional).

.EXAMPLE
Set-ConnectorNetwork -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token -NetworkId "12345678-1234-1234-1234-123456789012" -Name "Updated Production Network" -Description "Updated network for production environments"

.NOTES
This function requires the CMURL and a valid logon token to authenticate API requests.
Uses the /networks/{network_id} endpoint with PATCH method.

#>

function Set-ConnectorNetwork {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'ConnectorManagementURL')]
        [string]$CMURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$NetworkId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$AdditionalProperties
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }

    Process {
        try {
            $URL = "$CMURL/networks/$NetworkId"

            # Build the request body from individual parameters (only include provided parameters)
            $RequestBody = @{}

            # Add optional parameters if provided
            if (-not [string]::IsNullOrEmpty($Name)) {
                $RequestBody.name = $Name
            }

            if (-not [string]::IsNullOrEmpty($Description)) {
                $RequestBody.description = $Description
            }

            # Add any additional properties if provided
            if ($PSBoundParameters.ContainsKey('AdditionalProperties') -and $AdditionalProperties.Count -gt 0) {
                foreach ($key in $AdditionalProperties.Keys) {
                    $RequestBody[$key] = $AdditionalProperties[$key]
                }
            }

            $Body = $RequestBody | ConvertTo-Json -Depth 10 -Compress

            Write-LogMessage -type Verbose -MSG "Updating connector network with ID: $NetworkId"
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"
            Write-LogMessage -type Verbose -MSG "Request Body: $Body"

            $RestParms = @{
                Uri         = $URL
                Method      = 'PATCH'
                Body        = $Body
                ContentType = "application/json"
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms

            Write-LogMessage -type Success -MSG "Successfully updated connector network: $NetworkId"
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to update connector network $NetworkId. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\ConnectorManagement\Set-ConnectorNetwork.ps1' 114
#Region '.\Public\PAS\ConnectorManagement\Set-ConnectorPool.ps1' -1

<#
.SYNOPSIS
Updates an existing connector pool in the Connector Management API.

.DESCRIPTION
The Set-ConnectorPool function updates an existing connector pool in the CyberArk Connector Management API using the provided pool data.

.PARAMETER CMURL
The URL of the CyberArk Connector Management service in the format https://<subdomain>.connectormanagement.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER PoolId
The unique identifier of the pool to update (mandatory).

.PARAMETER Name
The name of the pool (optional).

.PARAMETER Description
The description of the pool (optional).

.PARAMETER Type
The type of the pool (optional).

.PARAMETER Networks
Array of network objects associated with the pool (optional).

.PARAMETER Identifiers
Array of identifier objects for the pool (optional).

.PARAMETER Components
Array of component objects for the pool (optional).

.PARAMETER AdditionalProperties
Additional properties to include in the pool request body (optional).

.EXAMPLE
Set-ConnectorPool -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -LogonToken $token -PoolId "12345678-1234-1234-1234-123456789012" -Name "Updated Production Pool" -Description "Updated pool for production environments"

.NOTES
This function requires the CMURL and a valid logon token to authenticate API requests.
Uses the /pools/{pool_id} endpoint with PATCH method.

#>

function Set-ConnectorPool {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'ConnectorManagementURL')]
        [string]$CMURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$PoolId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Type,

        [Parameter(ValueFromPipelineByPropertyName)]
        [array]$Networks,

        [Parameter(ValueFromPipelineByPropertyName)]
        [array]$Identifiers,

        [Parameter(ValueFromPipelineByPropertyName)]
        [array]$Components,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$AdditionalProperties
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }

    Process {
        try {
            $URL = "$CMURL/pools/$PoolId"

            # Build the request body from individual parameters (only include provided parameters)
            $RequestBody = @{}

            # Add optional parameters if provided
            if (-not [string]::IsNullOrEmpty($Name)) {
                $RequestBody.name = $Name
            }

            if (-not [string]::IsNullOrEmpty($Description)) {
                $RequestBody.description = $Description
            }

            if (-not [string]::IsNullOrEmpty($Type)) {
                $RequestBody.type = $Type
            }

            # Add optional networks if provided
            if ($PSBoundParameters.ContainsKey('Networks') -and $Networks.Count -gt 0) {
                $RequestBody.networks = $Networks
            }

            # Add optional identifiers if provided
            if ($PSBoundParameters.ContainsKey('Identifiers') -and $Identifiers.Count -gt 0) {
                $RequestBody.identifiers = $Identifiers
            }

            # Add optional components if provided
            if ($PSBoundParameters.ContainsKey('Components') -and $Components.Count -gt 0) {
                $RequestBody.components = $Components
            }

            # Add any additional properties if provided
            if ($PSBoundParameters.ContainsKey('AdditionalProperties') -and $AdditionalProperties.Count -gt 0) {
                foreach ($key in $AdditionalProperties.Keys) {
                    $RequestBody[$key] = $AdditionalProperties[$key]
                }
            }

            $Body = $RequestBody | ConvertTo-Json -Depth 10 -Compress

            Write-LogMessage -type Verbose -MSG "Updating connector pool with ID: $PoolId"
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"
            Write-LogMessage -type Verbose -MSG "Request Body: $Body"

            $RestParms = @{
                Uri         = $URL
                Method      = 'PATCH'
                Body        = $Body
                ContentType = "application/json"
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms

            Write-LogMessage -type Success -MSG "Successfully updated connector pool: $PoolId"
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to update connector pool $PoolId. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\ConnectorManagement\Set-ConnectorPool.ps1' 157
#Region '.\Public\PAS\CPM\Get-CPMUser.ps1' -1

<#
.SYNOPSIS
Retrieves the list of Component User Names (CPMs) from the system health.

.DESCRIPTION
The Get-CPMUser function retrieves the list of Component User Names (CPMs) by calling the Get-SystemHealth cmdlet with the -CPM parameter. It logs the process of retrieving the list and returns the list of CPMs.

.PARAMETERS
None

.OUTPUTS
System.String[]
Returns an array of strings containing the Component User Names (CPMs).

.EXAMPLES
Example 1:
PS> Get-CPMUser
This example retrieves and returns the list of Component User Names (CPMs).
#>
function Get-CPMUser {
    [CmdletBinding()]
    param ()

    process {
        Write-LogMessage -type verbose -MSG "Getting list of CPMs"
        [string[]]$CPMList = (Get-SystemHealth -CPM).ComponentUserName
        Write-LogMessage -type verbose -MSG "Retrieved list of CPMs successfully: $($CPMList -join ', ')"
        return $CPMList
    }
}
#EndRegion '.\Public\PAS\CPM\Get-CPMUser.ps1' 31
#Region '.\Public\PAS\Discovery\Add-DiscoveredAccount.ps1' -1

<#
.SYNOPSIS
Adds or edits a discovered account in the PVWA API.

.DESCRIPTION
The Add-DiscoveredAccount function adds or edits a discovered account in the PVWA API using the provided account data.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER Type
The type of the discovered account (mandatory).

.PARAMETER SubType
The sub type of the discovered account (mandatory).

.PARAMETER Identifiers
Dictionary of properties that define the uniqueness of the discovered account (mandatory).

.PARAMETER Source
The service which discovered the account (mandatory).

.PARAMETER IsPrivileged
Indication if the account is privileged on the target (optional, defaults to true).

.PARAMETER CustomProperties
Dictionary of additional properties of the discovered account (optional).

.PARAMETER Tags
List of tags that are associated with the discovered account (optional).

.EXAMPLE
$identifiers = @{
    username = "admin"
    address = "server01.domain.com"
}
Add-DiscoveredAccount -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -Type "Windows" -SubType "Local" -Identifiers $identifiers -Source "Discovery"

.EXAMPLE
$identifiers = @{
    username = "admin"
    address = "server01.domain.com"
}
$customProps = @{
    department = "IT"
    owner = "John Doe"
}
$tags = @("production", "critical")
Add-DiscoveredAccount -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -Type "Windows" -SubType "Local" -Identifiers $identifiers -Source "Discovery" -IsPrivileged $true -CustomProperties $customProps -Tags $tags

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /api/discovered-accounts endpoint with PUT method.

#>

function Add-DiscoveredAccount {
    [CmdletBinding()]
    param (

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [string]$Type,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [string]$SubType,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [hashtable]$Identifiers,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 20)]
        [ValidatePattern('^[\w.-]+$')]
        [string]$Source,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$IsPrivileged = $true,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$CustomProperties = @{},

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateCount(0, 20)]
        [ValidateScript({
                foreach ($tag in $_) {
                    if ($tag -notmatch '^[\w]+$' -or $tag.Length -gt 100 -or $tag.Length -lt 1) {
                        throw "Tag '$tag' must be 1-100 characters and contain only word characters"
                    }
                }
                return $true
            })]
        [string[]]$Tags,

        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$BaseURL,

        [Alias('header')]
        $LogonToken

    )

    begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null
        $APIURL = "$BaseURL/api"
    }

    process {
        try {
            $URL = "$APIURL/discovered-accounts"

            # Build the request body from individual parameters
            $RequestBody = @{
                type             = $Type
                subType          = $SubType
                identifiers      = $Identifiers
                source           = $Source
                isPrivileged     = $IsPrivileged
                customProperties = $CustomProperties
            }

            # Add tags if provided
            if ($PSBoundParameters.ContainsKey('Tags') -and $Tags.Count -gt 0) {
                $RequestBody.tags = $Tags
            }

            $Body = $RequestBody | ConvertTo-Json -Depth 10 -Compress

            Write-LogMessage -type Verbose -MSG 'Adding or editing discovered account'
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"
            Write-LogMessage -type Verbose -MSG "Request Body: $Body"

            $RestParms = @{
                Uri         = $URL
                Method      = 'PUT'
                Body        = $Body
                ContentType = 'application/json'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to add or edit discovered account. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\Discovery\Add-DiscoveredAccount.ps1' 157
#Region '.\Public\PAS\Discovery\Clear-DiscoveredAccount.ps1' -1

<#
.SYNOPSIS
Clears all discovered accounts from the PVWA API asynchronously.

.DESCRIPTION
The Clear-DiscoveredAccount function deletes all discovered accounts entries asynchronously from the PVWA API.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.EXAMPLE
Clear-DiscoveredAccount -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /api/discovered-accounts/clear endpoint with DELETE method.
This operation is asynchronous and may take time to complete.

#>

function Clear-DiscoveredAccount {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$BaseURL,

        [Alias('header')]
        $LogonToken
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $APIURL = "$BaseURL/API/"
    }

    Process {
        try {
            if ($PSCmdlet.ShouldProcess("All discovered accounts", "Clear discovered accounts (async)")) {
                $URL = "$APIURL/discovered-accounts/clear"

                Write-LogMessage -type Verbose -MSG "Clearing all discovered accounts (asynchronous operation)"
                Write-LogMessage -type Verbose -MSG "Request URL: $URL"

                $RestParms = @{
                    Uri    = $URL
                    Method = 'DELETE'
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                $restResponse = Invoke-Rest @RestParms

                Write-LogMessage -type Success -MSG "Successfully initiated clearing of all discovered accounts"
                return $restResponse
            }
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to clear discovered accounts. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\Discovery\Clear-DiscoveredAccount.ps1' 69
#Region '.\Public\PAS\Discovery\Deny-DiscoveryRuleSetRecommendation.ps1' -1

<#
.SYNOPSIS
Dismisses a discovery rule set recommendation in the PVWA API.

.DESCRIPTION
The Deny-DiscoveryRuleSetRecommendation function dismisses a discovery rule set recommendation in the PVWA API.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER RecommendationID
The discovery rule set recommendation ID to dismiss.

.EXAMPLE
Deny-DiscoveryRuleSetRecommendation -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -RecommendationID "12345"

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /api/discovery-rule-sets/recommendations/{id}/dismiss endpoint with POST method.

#>

function Deny-DiscoveryRuleSetRecommendation {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$BaseURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string]$RecommendationID
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $APIURL = "$BaseURL/API/"
    }

    Process {
        try {
            if ($PSCmdlet.ShouldProcess($RecommendationID, "Dismiss discovery rule set recommendation")) {
                $URL = "$APIURL/discovery-rule-sets/recommendations/$RecommendationID/dismiss"

                Write-LogMessage -type Verbose -MSG "Dismissing discovery rule set recommendation with ID: $RecommendationID"
                Write-LogMessage -type Verbose -MSG "Request URL: $URL"

                $RestParms = @{
                    Uri    = $URL
                    Method = 'POST'
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                $restResponse = Invoke-Rest @RestParms

                Write-LogMessage -type Success -MSG "Successfully dismissed discovery rule set recommendation: $RecommendationID"
                return $restResponse
            }
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to dismiss discovery rule set recommendation $RecommendationID. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\Discovery\Deny-DiscoveryRuleSetRecommendation.ps1' 74
#Region '.\Public\PAS\Discovery\Get-DiscoveredAccount.ps1' -1

<#
.SYNOPSIS
Gets discovered accounts from the PVWA API.

.DESCRIPTION
The Get-DiscoveredAccount function retrieves discovered account information from the PVWA API.
It supports both getting a specific discovered account by ID and querying multiple discovered accounts with various filters.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER AccountID
The discovered account ID to retrieve. When specified, returns a single account.

.PARAMETER ExtendedDetails
Indication if to return extended details from the discovered account's activities.

.PARAMETER Filter
Filtering according to REST standard. Supported filters: type, subType, isPrivileged - allow multiple selection.

.PARAMETER Limit
The maximum number of discovered accounts to return. When used together with the Offset parameter, this value determines the number of discovered accounts to return.

.PARAMETER Offset
Offset of the first discovered account that is returned in the collection of results.

.PARAMETER Search
Searches in all identifiers values of the discovered account for the given string. If searchOnAllFields is set to True search in customProperties values as well. Search is case sensitive.

.PARAMETER SearchOnAllFields
Indication if the search will be done in customProperties values as well.

.EXAMPLE
Get-DiscoveredAccount -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token

.EXAMPLE
Get-DiscoveredAccount -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -AccountID "12345"

.EXAMPLE
Get-DiscoveredAccount -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -Filter "type eq 'Windows'" -Limit 50

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /api/discovered-accounts and /api/discovered-accounts/{id} endpoints.

#>

function Get-DiscoveredAccount {
    [CmdletBinding(DefaultParameterSetName = "Query")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$BaseURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(ParameterSetName = 'AccountID', Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string]$AccountID,

        [Parameter(ParameterSetName = 'AccountID', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'Query', ValueFromPipelineByPropertyName)]
        [string]$ExtendedDetails,

        [Parameter(ParameterSetName = 'Query', ValueFromPipelineByPropertyName)]
        [string]$Filter,

        [Parameter(ParameterSetName = 'Query', ValueFromPipelineByPropertyName)]
        [string]$Limit,

        [Parameter(ParameterSetName = 'Query', ValueFromPipelineByPropertyName)]
        [string]$Offset,

        [Parameter(ParameterSetName = 'Query', ValueFromPipelineByPropertyName)]
        [string]$Search,

        [Parameter(ParameterSetName = 'Query', ValueFromPipelineByPropertyName)]
        [string]$SearchOnAllFields
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $APIURL = "$BaseURL/api"
    }

    Process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'AccountID') {
                # Get specific discovered account by ID
                $URL = "$APIURL/discovered-accounts/$AccountID"

                # Add query parameters if provided
                $QueryParams = @()
                if (-not [string]::IsNullOrEmpty($ExtendedDetails)) {
                    $QueryParams += "extendedDetails=$([System.Web.HttpUtility]::UrlEncode($ExtendedDetails))"
                }

                if ($QueryParams.Count -gt 0) {
                    $URL += "?" + ($QueryParams -join "&")
                }

                Write-LogMessage -type Verbose -MSG "Getting discovered account with ID: $AccountID"
                Write-LogMessage -type Verbose -MSG "Request URL: $URL"

                $RestParms = @{
                    Uri    = $URL
                    Method = 'GET'
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                $restResponse = Invoke-Rest @RestParms
                return $restResponse
            }
            else {
                # Query discovered accounts
                $URL = "$BaseURL/discovered-accounts"

                # Add query parameters if provided
                $QueryParams = @()
                if (-not [string]::IsNullOrEmpty($ExtendedDetails)) {
                    $QueryParams += "extendedDetails=$([System.Web.HttpUtility]::UrlEncode($ExtendedDetails))"
                }
                if (-not [string]::IsNullOrEmpty($Filter)) {
                    $QueryParams += "filter=$([System.Web.HttpUtility]::UrlEncode($Filter))"
                }
                if (-not [string]::IsNullOrEmpty($Limit)) {
                    $QueryParams += "limit=$([System.Web.HttpUtility]::UrlEncode($Limit))"
                }
                if (-not [string]::IsNullOrEmpty($Offset)) {
                    $QueryParams += "offset=$([System.Web.HttpUtility]::UrlEncode($Offset))"
                }
                if (-not [string]::IsNullOrEmpty($Search)) {
                    $QueryParams += "search=$([System.Web.HttpUtility]::UrlEncode($Search))"
                }
                if (-not [string]::IsNullOrEmpty($SearchOnAllFields)) {
                    $QueryParams += "searchOnAllFields=$([System.Web.HttpUtility]::UrlEncode($SearchOnAllFields))"
                }

                if ($QueryParams.Count -gt 0) {
                    $URL += "?" + ($QueryParams -join "&")
                }

                Write-LogMessage -type Verbose -MSG "Getting discovered accounts"
                Write-LogMessage -type Verbose -MSG "Request URL: $URL"

                $RestParms = @{
                    Uri    = $URL
                    Method = 'GET'
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                $restResponse = Invoke-RestNextCursor @RestParms
                return $restResponse
            }
        }
        catch {
            if ($PSCmdlet.ParameterSetName -eq 'AccountID') {
                Write-LogMessage -type Error -MSG "Failed to get discovered account $AccountID. Error: $($_.Exception.Message)"
            }
            else {
                Write-LogMessage -type Error -MSG "Failed to get discovered accounts. Error: $($_.Exception.Message)"
            }
            throw
        }
    }
}
#EndRegion '.\Public\PAS\Discovery\Get-DiscoveredAccount.ps1' 174
#Region '.\Public\PAS\Discovery\Get-DiscoveredAccountActivity.ps1' -1

<#
.SYNOPSIS
Gets discovered account activities from the PVWA API.

.DESCRIPTION
The Get-DiscoveredAccountActivity function retrieves discovered account activities entries from the PVWA API for a specific account.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER AccountID
The discovered account ID to retrieve activities for.

.PARAMETER Limit
The maximum number of activities to return. When used together with the Offset parameter, this value determines the number of activities to return.

.PARAMETER Offset
Offset of the first activity that is returned in the collection of results.

.PARAMETER Search
Search term to filter activities.

.EXAMPLE
Get-DiscoveredAccountActivity -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -AccountID "12345"

.EXAMPLE
Get-DiscoveredAccountActivity -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -AccountID "12345" -Limit 20 -Search "rule"

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /api/discovered-accounts/{id}/activities endpoint.

#>

function Get-DiscoveredAccountActivity {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$BaseURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string]$AccountID,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Limit,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Offset,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Search
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $APIURL = "$BaseURL/API/"
    }

    Process {
        try {
            $URL = "$APIURL/discovered-accounts/$AccountID/activities"

            # Add query parameters if provided
            $QueryParams = @()
            if (-not [string]::IsNullOrEmpty($Limit)) {
                $QueryParams += "limit=$([System.Web.HttpUtility]::UrlEncode($Limit))"
            }
            if (-not [string]::IsNullOrEmpty($Offset)) {
                $QueryParams += "offset=$([System.Web.HttpUtility]::UrlEncode($Offset))"
            }
            if (-not [string]::IsNullOrEmpty($Search)) {
                $QueryParams += "search=$([System.Web.HttpUtility]::UrlEncode($Search))"
            }

            if ($QueryParams.Count -gt 0) {
                $URL += "?" + ($QueryParams -join "&")
            }

            Write-LogMessage -type Verbose -MSG "Getting discovered account activities for account ID: $AccountID"
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"

            $RestParms = @{
                Uri    = $URL
                Method = 'GET'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-RestNextCursor @RestParms
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to get discovered account activities for account $AccountID. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\Discovery\Get-DiscoveredAccountActivity.ps1' 107
#Region '.\Public\PAS\Discovery\Get-DiscoveredDependentAccount.ps1' -1

<#
.SYNOPSIS
Gets discovered dependent accounts for a discovered account from the PVWA API.

.DESCRIPTION
The Get-DiscoveredDependentAccount function retrieves all discovered dependent accounts of a discovered account from the PVWA API.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER AccountID
The discovered account ID to retrieve dependent accounts for.

.PARAMETER Limit
The maximum number of discovered dependent accounts to return. When used together with the Offset parameter, this value determines the number of discovered dependent accounts to return.

.PARAMETER Offset
Offset of the first discovered dependent account that is returned in the collection of results.

.PARAMETER Search
Searches in all identifiers values of the discovered dependent account for the given string. If searchOnAllFields is set to True search in customProperties values as well. Search is case sensitive.

.PARAMETER SearchOnAllFields
Indication if the search will be done in customProperties values as well.

.EXAMPLE
Get-DiscoveredDependentAccount -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -AccountID "12345"

.EXAMPLE
Get-DiscoveredDependentAccount -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -AccountID "12345" -Limit 25 -Search "service"

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /api/discovered-accounts/{id}/discovered-dependent-accounts endpoint.

#>

function Get-DiscoveredDependentAccount {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$BaseURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string]$AccountID,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Limit,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Offset,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Search,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$SearchOnAllFields
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $APIURL = "$BaseURL/API/"
    }

    Process {
        try {
            $URL = "$APIURL/discovered-accounts/$AccountID/discovered-dependent-accounts"

            # Add query parameters if provided
            $QueryParams = @()
            if (-not [string]::IsNullOrEmpty($Limit)) {
                $QueryParams += "limit=$([System.Web.HttpUtility]::UrlEncode($Limit))"
            }
            if (-not [string]::IsNullOrEmpty($Offset)) {
                $QueryParams += "offset=$([System.Web.HttpUtility]::UrlEncode($Offset))"
            }
            if (-not [string]::IsNullOrEmpty($Search)) {
                $QueryParams += "search=$([System.Web.HttpUtility]::UrlEncode($Search))"
            }
            if (-not [string]::IsNullOrEmpty($SearchOnAllFields)) {
                $QueryParams += "searchOnAllFields=$([System.Web.HttpUtility]::UrlEncode($SearchOnAllFields))"
            }

            if ($QueryParams.Count -gt 0) {
                $URL += "?" + ($QueryParams -join "&")
            }

            Write-LogMessage -type Verbose -MSG "Getting discovered dependent accounts for account ID: $AccountID"
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"

            $RestParms = @{
                Uri    = $URL
                Method = 'GET'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-RestNextCursor @RestParms
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to get discovered dependent accounts for account $AccountID. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\Discovery\Get-DiscoveredDependentAccount.ps1' 116
#Region '.\Public\PAS\Discovery\Get-DiscoveryInsight.ps1' -1

<#
.SYNOPSIS
Gets account discovery insight from the PVWA API.

.DESCRIPTION
The Get-DiscoveryInsight function retrieves account discovery insight information from the PVWA API based on the account ID and optional insight type.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER AccountID
The account ID to retrieve associated account discovery insight.

.PARAMETER Type
Indication of the type of the account discovery insight to retrieve.

.EXAMPLE
Get-DiscoveryInsight -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -AccountID "12345"

.EXAMPLE
Get-DiscoveryInsight -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -AccountID "12345" -Type "specific_type"

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /api/accounts/{id}/discovery-insights endpoint.

#>

function Get-DiscoveryInsight {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$BaseURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string]$AccountID,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Type
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $APIURL = "$BaseURL/api"
    }

    Process {
        try {
            $URL = "$APIURL/accounts/$AccountID/discovery-insights"

            # Add query parameters if provided
            $QueryParams = @()
            if (-not [string]::IsNullOrEmpty($Type)) {
                $QueryParams += "type=$([System.Web.HttpUtility]::UrlEncode($Type))"
                Write-LogMessage -type Verbose -MSG "Adding type parameter: $Type"
            }

            if ($QueryParams.Count -gt 0) {
                $URL += "?" + ($QueryParams -join "&")
            }

            Write-LogMessage -type Verbose -MSG "Getting discovery insight for account ID: $AccountID"
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"

            $RestParms = @{
                Uri    = $URL
                Method = 'GET'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to get discovery insight for account $AccountID. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\Discovery\Get-DiscoveryInsight.ps1' 90
#Region '.\Public\PAS\Discovery\Get-DiscoveryRuleSet.ps1' -1

<#
.SYNOPSIS
Gets discovery rule sets from the PVWA API.

.DESCRIPTION
The Get-DiscoveryRuleSet function retrieves discovery rule set information from the PVWA API.
It supports both getting a specific rule set by ID and querying multiple rule sets.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER RuleSetID
The discovery rule set ID to retrieve. When specified, returns a single rule set.

.PARAMETER Limit
The maximum number of discovery rule sets to return.

.PARAMETER Offset
Offset of the first discovery rule set that is returned in the collection of results.

.PARAMETER Search
Search term to filter rule sets.

.EXAMPLE
Get-DiscoveryRuleSet -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token

.EXAMPLE
Get-DiscoveryRuleSet -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -RuleSetID "12345"

.EXAMPLE
Get-DiscoveryRuleSet -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -Limit 20 -Search "Windows"

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /api/discovery-rule-sets and /api/discovery-rule-sets/{id} endpoints.

#>

function Get-DiscoveryRuleSet {
    [CmdletBinding(DefaultParameterSetName = 'Query')]
    param (

        [Parameter(ParameterSetName = 'RuleSetID', Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string]$RuleSetID,

        [Parameter(ParameterSetName = 'Query', ValueFromPipelineByPropertyName)]
        [string]$Limit,

        [Parameter(ParameterSetName = 'Query', ValueFromPipelineByPropertyName)]
        [string]$Offset,

        [Parameter(ParameterSetName = 'Query', ValueFromPipelineByPropertyName)]
        [string]$Search,

        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$BaseURL,

        [Alias('header')]
        $LogonToken

    )

    begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null
        $APIURL = "$BaseURL/API/"
    }

    process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'RuleSetID') {
                # Get specific discovery rule set by ID
                $URL = "$APIURL/discovery-rule-sets/$RuleSetID"

                Write-LogMessage -type Verbose -MSG "Getting discovery rule set with ID: $RuleSetID"
                Write-LogMessage -type Verbose -MSG "Request URL: $URL"

                $RestParms = @{
                    Uri    = $URL
                    Method = 'GET'
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                $restResponse = Invoke-Rest @RestParms
                Write-LogMessage -type Success -MSG "Successfully got discovery rule set: $RuleSetID"
                return $restResponse
            }
            else {
                # Query discovery rule sets
                $URL = "$BaseURL/discovery-rule-sets"

                # Add query parameters if provided
                $QueryParams = @()
                if (-not [string]::IsNullOrEmpty($Limit)) {
                    $QueryParams += "limit=$([System.Web.HttpUtility]::UrlEncode($Limit))"
                }
                if (-not [string]::IsNullOrEmpty($Offset)) {
                    $QueryParams += "offset=$([System.Web.HttpUtility]::UrlEncode($Offset))"
                }
                if (-not [string]::IsNullOrEmpty($Search)) {
                    $QueryParams += "search=$([System.Web.HttpUtility]::UrlEncode($Search))"
                }

                if ($QueryParams.Count -gt 0) {
                    $URL += '?' + ($QueryParams -join '&')
                }

                Write-LogMessage -type Verbose -MSG 'Getting discovery rule sets'
                Write-LogMessage -type Verbose -MSG "Request URL: $URL"

                $RestParms = @{
                    Uri    = $URL
                    Method = 'GET'
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                $restResponse = Invoke-RestNextCursor @RestParms
                Write-LogMessage -type Success -MSG "Successfully got discovery rule set using query parameters: $QueryParams"
                return $restResponse
            }
        }
        catch {
            if ($PSCmdlet.ParameterSetName -eq 'RuleSetID') {
                Write-LogMessage -type Failure -MSG "Failed to get discovery rule set $RuleSetID."
                Write-LogMessage -type Error -MSG "Failed to get discovery rule set $RuleSetID. Error: $($_.Exception.Message)"
            }
            else {
                Write-LogMessage -type Error -MSG "Failed to get discovery rule sets. Error: $($_.Exception.Message)"
            }
            throw
        }
    }
}
#EndRegion '.\Public\PAS\Discovery\Get-DiscoveryRuleSet.ps1' 141
#Region '.\Public\PAS\Discovery\Get-DiscoveryRuleSetRecommendation.ps1' -1

<#
.SYNOPSIS
Gets discovery rule set recommendations from the PVWA API.

.DESCRIPTION
The Get-DiscoveryRuleSetRecommendation function retrieves discovery rule set recommendation information from the PVWA API.
It supports both getting a specific recommendation by ID and querying all recommendations.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER RecommendationID
The discovery rule set recommendation ID to retrieve. When specified, returns a single recommendation.

.EXAMPLE
Get-DiscoveryRuleSetRecommendation -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token

.EXAMPLE
Get-DiscoveryRuleSetRecommendation -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -RecommendationID "12345"

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /api/discovery-rule-sets/recommendations and /api/discovery-rule-sets/recommendations/{id} endpoints.

#>

function Get-DiscoveryRuleSetRecommendation {
    [CmdletBinding(DefaultParameterSetName = "Query")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$BaseURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(ParameterSetName = 'RecommendationID', Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string]$RecommendationID
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $APIURL = "$BaseURL/API/"
    }

    Process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'RecommendationID') {
                # Get specific discovery rule set recommendation by ID
                $URL = "$APIURL/discovery-rule-sets/recommendations/$RecommendationID"

                Write-LogMessage -type Verbose -MSG "Getting discovery rule set recommendation with ID: $RecommendationID"
                Write-LogMessage -type Verbose -MSG "Request URL: $URL"

                $RestParms = @{
                    Uri    = $URL
                    Method = 'GET'
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                $restResponse = Invoke-Rest @RestParms
                return $restResponse
            }
            else {
                # Query all discovery rule set recommendations
                $URL = "$BaseURL/discovery-rule-sets/recommendations"

                Write-LogMessage -type Verbose -MSG "Getting all discovery rule set recommendations"
                Write-LogMessage -type Verbose -MSG "Request URL: $URL"

                $RestParms = @{
                    Uri    = $URL
                    Method = 'GET'
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                $restResponse = Invoke-RestNextCursor @RestParms
                return $restResponse
            }
        }
        catch {
            if ($PSCmdlet.ParameterSetName -eq 'RecommendationID') {
                Write-LogMessage -type Error -MSG "Failed to get discovery rule set recommendation $RecommendationID. Error: $($_.Exception.Message)"
            }
            else {
                Write-LogMessage -type Error -MSG "Failed to get discovery rule set recommendations. Error: $($_.Exception.Message)"
            }
            throw
        }
    }
}
#EndRegion '.\Public\PAS\Discovery\Get-DiscoveryRuleSetRecommendation.ps1' 99
#Region '.\Public\PAS\Discovery\New-DiscoveryRuleSet.ps1' -1

<#
.SYNOPSIS
Adds a new discovery rule set to the PVWA API.

.DESCRIPTION
The New-DiscoveryRuleSet function adds a new discovery rule set entry to the PVWA API using the provided rule set data.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER ApplyOn
Parameter to specify what the rule set applies to.

.PARAMETER InputObject
The discovery rule set data to add. This should be a hashtable or PSCustomObject containing the rule set information.

.EXAMPLE
$ruleSetData = @{
    name = "Windows Discovery Rules"
    status = "ACTIVE"
    rules = @(
        @{
            name = "Onboard Admin Accounts"
            action = @{
                type = "ONBOARD"
                parameters = @{
                    safeName = "DiscoveredAccounts"
                    platformId = "WinDomain"
                }
            }
        }
    )
}
New-DiscoveryRuleSet -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -ApplyOn "discovered_accounts" -InputObject $ruleSetData

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /api/discovery-rule-sets endpoint with POST method.

#>

function New-DiscoveryRuleSet {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$BaseURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [string]$ApplyOn,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [object]$InputObject
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $APIURL = "$BaseURL/API/"
    }

    Process {
        try {
            $URL = "$APIURL/discovery-rule-sets"

            # Add applyOn parameter
            $URL += "?applyOn=$([System.Web.HttpUtility]::UrlEncode($ApplyOn))"

            # Convert input object to JSON
            $Body = $InputObject | ConvertTo-Json -Depth 10 -Compress

            Write-LogMessage -type Verbose -MSG "Adding discovery rule set"
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"
            Write-LogMessage -type Verbose -MSG "Request Body: $Body"

            $RestParms = @{
                Uri         = $URL
                Method      = 'POST'
                Body        = $Body
                ContentType = "application/json"
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms

            Write-LogMessage -type Success -MSG "Successfully added discovery rule set"
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to add discovery rule set. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\Discovery\New-DiscoveryRuleSet.ps1' 103
#Region '.\Public\PAS\Discovery\Remove-DiscoveredAccount.ps1' -1

<#
.SYNOPSIS
Removes a discovered account from the PVWA API.

.DESCRIPTION
The Remove-DiscoveredAccount function deletes a discovered account entry from the PVWA API based on the account ID.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER AccountID
The discovered account ID to delete.

.EXAMPLE
Remove-DiscoveredAccount -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -AccountID "12345"

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /api/discovered-accounts/{id} endpoint with DELETE method.

#>

function Remove-DiscoveredAccount {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$BaseURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string]$AccountID
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $APIURL = "$BaseURL/api"
    }

    Process {
        try {
            if ($PSCmdlet.ShouldProcess($AccountID, "Delete discovered account")) {
                $URL = "$APIURL/discovered-accounts/$AccountID"

                Write-LogMessage -type Verbose -MSG "Deleting discovered account with ID: $AccountID"
                Write-LogMessage -type Verbose -MSG "Request URL: $URL"

                $RestParms = @{
                    Uri    = $URL
                    Method = 'DELETE'
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                $restResponse = Invoke-Rest @RestParms

                Write-LogMessage -type Success -MSG "Successfully deleted discovered account: $AccountID"
                return $restResponse
            }
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to delete discovered account $AccountID. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\Discovery\Remove-DiscoveredAccount.ps1' 74
#Region '.\Public\PAS\Discovery\Remove-DiscoveryRuleSet.ps1' -1

<#
.SYNOPSIS
Removes a discovery rule set from the PVWA API.

.DESCRIPTION
The Remove-DiscoveryRuleSet function deletes a discovery rule set entry from the PVWA API based on the rule set ID.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER RuleSetID
The discovery rule set ID to delete.

.EXAMPLE
Remove-DiscoveryRuleSet -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -RuleSetID "12345"

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /api/discovery-rule-sets/{id} endpoint with DELETE method.

#>

function Remove-DiscoveryRuleSet {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$BaseURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string]$RuleSetID
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $APIURL = "$BaseURL/API/"
    }

    Process {
        try {
            if ($PSCmdlet.ShouldProcess($RuleSetID, "Delete discovery rule set")) {
                $URL = "$APIURL/discovery-rule-sets/$RuleSetID"

                Write-LogMessage -type Verbose -MSG "Deleting discovery rule set with ID: $RuleSetID"
                Write-LogMessage -type Verbose -MSG "Request URL: $URL"

                $RestParms = @{
                    Uri    = $URL
                    Method = 'DELETE'
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                $restResponse = Invoke-Rest @RestParms

                Write-LogMessage -type Success -MSG "Successfully deleted discovery rule set: $RuleSetID"
                return $restResponse
            }
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to delete discovery rule set $RuleSetID. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\Discovery\Remove-DiscoveryRuleSet.ps1' 74
#Region '.\Public\PAS\Discovery\Set-DiscoveryInsight.ps1' -1

<#
.SYNOPSIS
Updates account discovery insight in the PVWA API.

.DESCRIPTION
The Set-DiscoveryInsight function updates account discovery insight information in the PVWA API based on the account ID and provided input data.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER AccountID
The account ID to update associated discovery insight.

.PARAMETER Type
The type of the discovery insight.

.PARAMETER Status
The status of the discovery insight.

.EXAMPLE
Set-DiscoveryInsight -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -AccountID "12345" -Type "specific_type" -Status "active"

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /api/accounts/{id}/discovery-insights endpoint with PUT method.

#>

function Set-DiscoveryInsight {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$BaseURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string]$AccountID,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [string]$Type,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [string]$Status
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $APIURL = "$BaseURL/api"
    }

    Process {
        try {
            $URL = "$APIURL/accounts/$AccountID/discovery-insights"

            # Build the request body from individual parameters
            $Body = @{
                type = $Type
                status = $Status
            } | ConvertTo-Json -Depth 10 -Compress

            Write-LogMessage -type Verbose -MSG "Updating discovery insight for account ID: $AccountID"
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"
            Write-LogMessage -type Verbose -MSG "Request Body: $Body"

            $RestParms = @{
                Uri         = $URL
                Method      = 'PUT'
                Body        = $Body
                ContentType = "application/json"
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to update discovery insight for account $AccountID. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\Discovery\Set-DiscoveryInsight.ps1' 91
#Region '.\Public\PAS\Discovery\Set-DiscoveryRuleSet.ps1' -1

<#
.SYNOPSIS
Updates a discovery rule set in the PVWA API.

.DESCRIPTION
The Set-DiscoveryRuleSet function edits a discovery rule set entry in the PVWA API using the provided rule set data.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER RuleSetID
The discovery rule set ID to edit.

.PARAMETER InputObject
The discovery rule set data to update. This should be a hashtable or PSCustomObject containing the updated rule set information.

.EXAMPLE
$updatedRuleSetData = @{
    name = "Updated Windows Discovery Rules"
    status = "DRAFT"
    rules = @(
        @{
            name = "Onboard Admin Accounts"
            action = @{
                type = "ONBOARD"
                parameters = @{
                    safeName = "UpdatedDiscoveredAccounts"
                    platformId = "WinDomain"
                }
            }
        }
    )
}
Set-DiscoveryRuleSet -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -RuleSetID "12345" -InputObject $updatedRuleSetData

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /api/discovery-rule-sets/{id} endpoint with PUT method.

#>

function Set-DiscoveryRuleSet {
    [CmdletBinding()]
    param (

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string]$RuleSetID,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [object]$InputObject,

        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$BaseURL,

        [Alias('header')]
        $LogonToken

    )

    begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null
        $APIURL = "$BaseURL/API/"
    }

    process {
        try {
            $URL = "$APIURL/discovery-rule-sets/$RuleSetID"

            # Convert input object to JSON
            $Body = $InputObject | ConvertTo-Json -Depth 10 -Compress

            Write-LogMessage -type Verbose -MSG "Updating discovery rule set with ID: $RuleSetID"
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"
            Write-LogMessage -type Verbose -MSG "Request Body: $Body"

            $RestParms = @{
                Uri         = $URL
                Method      = 'PUT'
                Body        = $Body
                ContentType = 'application/json'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms

            Write-LogMessage -type Success -MSG "Successfully updated discovery rule set: $RuleSetID"
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to update discovery rule set $RuleSetID. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\Discovery\Set-DiscoveryRuleSet.ps1' 102
#Region '.\Public\PAS\Discovery\Start-DiscoveredAccountOnboard.ps1' -1

<#
.SYNOPSIS
Onboards a discovered account using the PVWA API.

.DESCRIPTION
The Start-DiscoveredAccountOnboard function onboards a discovered account to the PVWA vault system using the provided onboarding data.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER AccountID
The discovered account ID to onboard.

.PARAMETER SafeName
The name of the safe where the account will be stored (mandatory).

.PARAMETER PlatformId
The platform ID that defines the account type and policies (mandatory).

.PARAMETER AdditionalProperties
Additional properties to be set on the account that are not taken from the identifiers or customProperties of the discovered account (optional).

.PARAMETER Secret
The initial secret value for the account (optional, defaults to empty string).

.PARAMETER ResetSecret
An indication whether the account should be immediately rotated (reconcile or change depending on the type) (optional, defaults to true).

.EXAMPLE
Start-DiscoveredAccountOnboard -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -AccountID "12345" -SafeName "DiscoveredAccounts" -PlatformId "WinDomain"

.EXAMPLE
$additionalProps = @{
    address = "server01.domain.com"
    userName = "admin"
}
Start-DiscoveredAccountOnboard -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -AccountID "12345" -SafeName "DiscoveredAccounts" -PlatformId "WinDomain" -AdditionalProperties $additionalProps -Secret "initialPassword" -ResetSecret $false

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /api/discovered-accounts/{id}/onboard endpoint with POST method.

#>

function Start-DiscoveredAccountOnboard {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$BaseURL,

        [Alias('header')]
        $LogonToken,

        [Alias('ID')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string]$AccountID,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [string]$SafeName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [string]$PlatformId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [pscustomobject]$AdditionalProperties = @{},

        [Parameter(ValueFromPipelineByPropertyName)]
        [pscustomobject]$customAttributes = @{},

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Secret = '',

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$ResetSecret = $true
    )

    begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null
        $APIURL = "$BaseURL/api"
    }

    process {
        try {
            $URL = "$APIURL/discovered-accounts/$AccountID/onboard"

            # Build the request body from individual parameters
            $RequestBody = @{
                coreAttributes       = @{
                    safeName   = $SafeName
                    platformId = $PlatformId
                }
                customAttributes     = $customAttributes
                additionalProperties = $AdditionalProperties
                secret               = $Secret
                resetSecret          = $ResetSecret
            }

            $Body = $RequestBody | ConvertTo-Json -Depth 10 -Compress

            Write-LogMessage -type Verbose -MSG "Onboarding discovered account with ID: $AccountID"
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"
            Write-LogMessage -type Verbose -MSG "Request Body: $Body"

            try {
                $RestParms = @{
                    Uri         = $URL
                    Method      = 'POST'
                    Body        = $Body
                    ContentType = 'application/json'
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                $restResponse = Invoke-Rest @RestParms

                Write-LogMessage -type Success -MSG "Successfully initiated onboarding for discovered account: $AccountID"
                return $restResponse
            }
            catch  [Microsoft.PowerShell.Commands.HttpResponseException] {
                if ('409' -eq $PSItem.Exception.StatusCode.value__) {
                    Write-LogMessage -type Failure -MSG "Successfully initiated onboarding for discovered account, however account already exists: $AccountID"
                    return [pscustomobject]@{
                        id        = $AccountID
                        accountID = "$($PSItem.Exception.StatusCode)"
                    }
                }
                if ('409' -eq $PSItem.Exception.StatusCode.value__) {
                    Write-LogMessage -type Failure -MSG "Successfully initiated onboarding for discovered account, however operation timed out in progress: $AccountID"
                    return [pscustomobject]@{
                        id        = $AccountID
                        accountID = "$($PSItem.Exception.StatusCode)"
                    }
                }
                Write-LogMessage -type Failure -MSG "Successfully initiated onboarding for discovered account, however it ended with a status code of $($PSItem.Exception.StatusCode): $AccountID"
                Write-LogMessage -type Verbose -MSG "Unknown Error detected: Message: $($PSitem.Exception.Message)"
                if ($PSitem.Exception.InnerException.Message) {
                    Write-LogMessage -type Verbose -MSG "Unknown Error detected: InnerException Message: $($PSitem.Exception.InnerException.Message)"
                }
                return [pscustomobject]@{
                    id        = $AccountID
                    accountID = "$($PSItem.Exception.StatusCode)"
                }
            }
            catch {
                Write-LogMessage  -type Failure -MSG "Unknown Error detected: $AccountID"
                Write-LogMessage -type Error -MSG "Unknown Error detected: Message: $($PSitem.Exception.Message)"
                if ($PSitem.Exception.InnerException.Message) {
                    Write-LogMessage -type Error -MSG "Unknown Error detected: InnerException Message: $($PSitem.Exception.Message)"
                }
                throw $PSItem
            }

        }
        catch {
            Write-LogMessage -type Failure -MSG "Failed to onboard discovered account: $AccountID"
            Write-LogMessage -type Error -MSG "Failed to onboard discovered account: $AccountID Error: $($_.Exception.Message)"
            throw $PSItem
        }
    }
}
#EndRegion '.\Public\PAS\Discovery\Start-DiscoveredAccountOnboard.ps1' 167
#Region '.\Public\PAS\Discovery\Start-DiscoveredAccountOnboardBulk.ps1' -1

<#
.SYNOPSIS
Onboards a discovered account using the PVWA API.

.DESCRIPTION
The Start-DiscoveredAccountOnboard function onboards a discovered account to the PVWA vault system using the provided onboarding data.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER AccountID
The discovered account ID to onboard.

.PARAMETER SafeName
The name of the safe where the account will be stored (mandatory).

.PARAMETER PlatformId
The platform ID that defines the account type and policies (mandatory).

.PARAMETER AdditionalProperties
Additional properties to be set on the account that are not taken from the identifiers or customProperties of the discovered account (optional).

.PARAMETER Secret
The initial secret value for the account (optional, defaults to empty string).

.PARAMETER ResetSecret
An indication whether the account should be immediately rotated (reconcile or change depending on the type) (optional, defaults to true).

.EXAMPLE
Start-DiscoveredAccountOnboard -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -AccountID "12345" -SafeName "DiscoveredAccounts" -PlatformId "WinDomain"

.EXAMPLE
$additionalProps = @{
    address = "server01.domain.com"
    userName = "admin"
}
Start-DiscoveredAccountOnboard -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -AccountID "12345" -SafeName "DiscoveredAccounts" -PlatformId "WinDomain" -AdditionalProperties $additionalProps -Secret "initialPassword" -ResetSecret $false

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /api/discovered-accounts/{id}/onboard endpoint with POST method.

#>

function Start-DiscoveredAccountOnboardBulk {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$BaseURL,

        [Alias('header')]
        $LogonToken,

        [Alias('ID')]
        [Parameter( ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string]$AccountID,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$SafeName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PlatformId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [pscustomobject]$AdditionalProperties = @{},

        [Parameter(ValueFromPipelineByPropertyName)]
        [pscustomobject]$customAttributes = @{},

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Secret = '',

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$ResetSecret = $true
    )

    begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null
        $APIURL = "$BaseURL/api"
        [pscustomobject]$items = '
        {
            "items": []
        }
        ' | ConvertFrom-Json
    }

    process {

        $item = [pscustomobject]@{
            id                   = $AccountID
            coreAttributes       = @{
                safeName   = if ($SafeName) { $SafeName } else { $PSItem.RuleAction.parameters.safename }
                platformId = if ($PlatformId) { $PlatformId } else { $PSItem.RuleAction.parameters.platformId }
            }
            customAttributes     = $customAttributes
            additionalProperties = $AdditionalProperties
            secret               = $Secret
            resetSecret          = $ResetSecret
        }
        $items.items += $item
    }

    end {
        try {
            $URL = "$APIURL/discovered-accounts/onboard/bulk"

            $Body = $items | ConvertTo-Json -Depth 9 -Compress
            Write-LogMessage -type Verbose -MSG 'Onboarding bulk discovered accounts'
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"

            try {
                $success = $false
                $badcount = 0
                do {
                    try {
                        $RestParms = @{
                            Uri         = $URL
                            Method      = 'POST'
                            Body        = $Body
                            ContentType = 'application/json'
                        }
                        if ($null -ne $LogonToken -and $LogonToken -ne "") {
                            $RestParms.LogonToken = $LogonToken
                        }
                        $restResponse = Invoke-Rest @RestParms
                        $success = $true
                        Write-LogMessage -type Verbose -MSG "Successfully submitted bulk onboarding request"
                    }
                    catch  [Microsoft.PowerShell.Commands.HttpResponseException] {
                        if ('500' -eq $PSItem.Exception.StatusCode.value__) {
                            $badcount++
                            if ($badcount -gt 30) {
                                Write-LogMessage -type Error -MSG "Received 500 status code on attempt $badcount, throwing a failure"
                                throw $PSitem
                            }
                            else {
                                Write-LogMessage -type Verbose -MSG "Received 500 status code on attempt $badcount, assuming overload and trying again"
                                Start-Sleep -Seconds 5
                            }
                        }
                        else {
                            throw $PSitem
                        }
                    }
                    catch {
                        throw $PSitem
                    }
                } while (-not $success)

                $running = $true
                $trackingLoop = 0
                $trackURL = "$APIURL/discovered-accounts/bulk/{0}" -f $restResponse.id
                Write-LogMessage -type Verbose -MSG "Tracking request URL: $trackURL"
                do {


                    $RestParms = @{
                        Uri         = $trackURL
                        Method      = 'GET'
                        ContentType = 'application/json'
                    }
                    if ($null -ne $LogonToken -and $LogonToken -ne "") {
                        $RestParms.LogonToken = $LogonToken
                    }
                    $trackResponse = Invoke-Rest @RestParms

                    $results = $trackResponse | Select-Object -Property * -ExcludeProperty results
                    $resultsAccounts = $trackResponse.results | ConvertTo-Json -Compress

                    if ('FINISHED' -eq $trackResponse.status) {
                        Write-LogMessage -type Verbose -MSG "Completed bulk request: $($restResponse.id)"
                        $running = $false
                    }
                    else {
                        Write-LogMessage -type Verbose -MSG "Tracking bulk request: $($restResponse.id)"
                        Start-Sleep -Seconds 10
                        $trackingLoop++
                        if ($trackingLoop -gt 100) {
                            break
                        }
                    }
                } while ($running)

                if ($running) {
                    Write-LogMessage -type Verbose -MSG "Still processing bulk process but breaking out of loop after 100 cycles: $results"
                    Write-LogMessage -type Verbose -MSG "Accounts: $resultsAccounts"
                }
                else {
                    Write-LogMessage -type Verbose -MSG "Successfully completed bulk process: $results"
                    Write-LogMessage -type Verbose -MSG "Accounts: $resultsAccounts"
                }
            }

            catch {
                Write-LogMessage -type Failure -MSG "Unknown Error detected: Message: $($PSitem.Exception.Message)"
                Write-LogMessage -type Error -MSG "Failed body: $body"
                if ($PSitem.Exception.InnerException.Message) {
                    Write-LogMessage -type Error -MSG "Unknown Error detected: InnerException Message: $($PSitem.Exception.Message)"
                }
                throw $PSItem
            }

        }
        catch {

            Write-LogMessage -type Failure -MSG "Failed to onboard bulk discovered accounts: $($_.Exception.Message)"
            Write-LogMessage -type Error -MSG "Failed body: $body"
            throw $PSItem
        }
    }
}
#EndRegion '.\Public\PAS\Discovery\Start-DiscoveredAccountOnboardBulk.ps1' 218
#Region '.\Public\PAS\Discovery\Test-AccountExistence.ps1' -1

<#
.SYNOPSIS
Tests the existence of accounts in the PVWA API.

.DESCRIPTION
The Test-AccountExistence function checks if accounts with the provided identifiers exist in the system using the PVWA API.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER InputObject
The account existence check data. This should be a hashtable or PSCustomObject containing the account identifiers to check.

.EXAMPLE
$checkData = @{
    accounts = @(
        @{
            type = "Windows"
            identifiers = @{
                username = "admin"
                address = "server01.domain.com"
            }
        }
    )
}
Test-AccountExistence -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -InputObject $checkData

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /api/discovered-accounts/check-existence endpoint with POST method.

#>

function Test-AccountExistence {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,
        [Alias('url')]
        [string]$BaseURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [object]$InputObject
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $APIURL = "$BaseURL/api"
    }

    Process {
        try {
            $URL = "$APIURL/discovered-accounts/check-existence"

            # Convert input object to JSON
            $Body = $InputObject | ConvertTo-Json -Depth 10 -Compress

            Write-LogMessage -type Verbose -MSG "Checking account existence"
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"
            Write-LogMessage -type Verbose -MSG "Request Body: $Body"

            $RestParms = @{
                Uri         = $URL
                Method      = 'POST'
                Body        = $Body
                ContentType = "application/json"
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to check account existence. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\Discovery\Test-AccountExistence.ps1' 86
#Region '.\Public\PAS\DiscoveryManagement\Get-Scan.ps1' -1

<#
.SYNOPSIS
Gets scan instances from the Discovery Management API.

.DESCRIPTION
The Get-Scan function retrieves scan instances from the Discovery Management API. It supports both getting all scan instances with optional filtering/searching and getting a specific scan instance by ID.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER ScanID
The unique identifier of the scan instance to retrieve (for single scan instance mode).

.PARAMETER Search
Searches in all identifiers values of the scan instance for the given string.

.PARAMETER Offset
Offset of the first scan instance that is returned in the collection of results (default: 0).

.PARAMETER Limit
The maximum number of scan instances to return (default: 50).

.PARAMETER Sort
Sorting parameter for the results.

.PARAMETER Filter
Filter parameter for the results.

.EXAMPLE
Get-Scan -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token

.EXAMPLE
Get-Scan -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -ScanID "9d963737-b704-4c63-bba9-17d8236691f6"

.EXAMPLE
Get-Scan -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -Search "windows" -Limit 25

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /scans endpoint.

#>

function Get-Scan {
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param (

        [Parameter(ParameterSetName = 'ByID', Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$ScanID,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [string]$Search,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [int]$Offset = 0,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [int]$Limit = 50,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [string]$Sort,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [string]$Filter,

        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$DiscoveryURL,

        [Alias('header')]
        $LogonToken
    )

    begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null
        $BaseURL = "$DiscoveryURL/api"
    }

    process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'ByID') {
                # Get specific scan instance by ID
                $URL = "$BaseURL/scans/$ScanID"
                Write-LogMessage -type Verbose -MSG "Getting scan instance with ID: $ScanID"
            }
            else {
                # Get all scan instances with optional parameters
                $URL = "$BaseURL/scans"

                # Build query parameters
                $QueryParams = @()
                if (-not [string]::IsNullOrEmpty($Search)) {
                    $QueryParams += "search=$([System.Web.HttpUtility]::UrlEncode($Search))"
                }
                if ($PSBoundParameters.ContainsKey('Offset')) {
                    $QueryParams += "offset=$Offset"
                }
                if ($PSBoundParameters.ContainsKey('Limit')) {
                    $QueryParams += "limit=$Limit"
                }
                if (-not [string]::IsNullOrEmpty($Sort)) {
                    $QueryParams += "sort=$([System.Web.HttpUtility]::UrlEncode($Sort))"
                }
                if (-not [string]::IsNullOrEmpty($Filter)) {
                    $QueryParams += "filter=$([System.Web.HttpUtility]::UrlEncode($Filter))"
                }

                if ($QueryParams.Count -gt 0) {
                    $URL += '?' + ($QueryParams -join '&')
                }

                Write-LogMessage -type Verbose -MSG 'Getting scan instances with parameters'
            }

            Write-LogMessage -type Verbose -MSG "Request URL: $URL"

            $RestParms = @{
                Uri    = $URL
                Method = 'GET'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-RestNextCursor @RestParms
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to get scan instance(s). Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\DiscoveryManagement\Get-Scan.ps1' 139
#Region '.\Public\PAS\DiscoveryManagement\Get-ScanDefinition.ps1' -1

<#
.SYNOPSIS
Gets scan definitions from the Discovery Management API.

.DESCRIPTION
The Get-ScanDefinition function retrieves scan definitions from the Discovery Management API. It supports both getting all scan definitions with optional filtering/searching and getting a specific scan definition by ID.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER ScanDefinitionID
The unique identifier of the scan definition to retrieve (for single scan definition mode).

.PARAMETER Search
Searches in all identifiers values of the scan definition for the given string.

.PARAMETER Offset
Offset of the first scan definition that is returned in the collection of results (default: 0).

.PARAMETER Limit
The maximum number of scan definitions to return (default: 50).

.PARAMETER Sort
Sorting parameter for the results.

.PARAMETER Filter
Filter parameter for the results.

.EXAMPLE
Get-ScanDefinition -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token

.EXAMPLE
Get-ScanDefinition -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -ScanDefinitionID "9d963737-b704-4c63-bba9-17d8236691f6"

.EXAMPLE
Get-ScanDefinition -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -Search "windows" -Limit 25

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /scan-definitions endpoint.

#>

function Get-ScanDefinition {
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param (

        [Parameter(ParameterSetName = 'ByID', Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$ScanDefinitionID,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [string]$Search,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [int]$Offset = 0,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [int]$Limit = 50,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [string]$Sort,

        [Parameter(ParameterSetName = 'List', ValueFromPipelineByPropertyName)]
        [string]$Filter,

        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$DiscoveryURL,

        [Alias('header')]
        $LogonToken

    )

    begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null
        $BaseURL = "$DiscoveryURL/api"
    }

    process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'ByID') {
                # Get specific scan definition by ID
                $URL = "$BaseURL/scan-definitions/$ScanDefinitionID"
                Write-LogMessage -type Verbose -MSG "Getting scan definition with ID: $ScanDefinitionID"
            }
            else {
                # Get all scan definitions with optional parameters
                $URL = "$BaseURL/scan-definitions"

                # Build query parameters
                $QueryParams = @()
                if (-not [string]::IsNullOrEmpty($Search)) {
                    $QueryParams += "search=$([System.Web.HttpUtility]::UrlEncode($Search))"
                }
                if ($PSBoundParameters.ContainsKey('Offset')) {
                    $QueryParams += "offset=$Offset"
                }
                if ($PSBoundParameters.ContainsKey('Limit')) {
                    $QueryParams += "limit=$Limit"
                }
                if (-not [string]::IsNullOrEmpty($Sort)) {
                    $QueryParams += "sort=$([System.Web.HttpUtility]::UrlEncode($Sort))"
                }
                if (-not [string]::IsNullOrEmpty($Filter)) {
                    $QueryParams += "filter=$([System.Web.HttpUtility]::UrlEncode($Filter))"
                }

                if ($QueryParams.Count -gt 0) {
                    $URL += '?' + ($QueryParams -join '&')
                }

                Write-LogMessage -type Verbose -MSG 'Getting scan definitions with parameters'
            }

            Write-LogMessage -type Verbose -MSG "Request URL: $URL"

            $RestParms = @{
                Uri    = $URL
                Method = 'GET'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-RestNextCursor @RestParms
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to get scan definition(s). Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\DiscoveryManagement\Get-ScanDefinition.ps1' 140
#Region '.\Public\PAS\DiscoveryManagement\New-ScanDefinition.ps1' -1

<#
.SYNOPSIS
Creates a new scan definition in the Discovery Management API.

.DESCRIPTION
The New-ScanDefinition function creates a new scan definition in the CyberArk Discovery Management API using the provided scan definition data. The function supports both domain-based and file-based scans for Windows and *nix systems.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER Name
The name of the scan definition (mandatory). Must be up to 100 alphanumeric characters including spaces and underscore, dash, period, and at signs (_ - . @). Must begin and end with a valid character and not a space.

.PARAMETER Type
The scan type to use for this scan definition (mandatory). Valid values: WIN_NIX_LIST, WIN_NIX_DOMAIN.

.PARAMETER Domain
The domain name for the scan (mandatory for domain scans, optional for list scans). Example: "company.com"

.PARAMETER OU
Organizational Unit for domain scans (optional). Discovery scans the entire AD domain for machines and users defined at the AD level, directly in the OU, and in all the AD groups within the OU. Example: "dc=domain,dc=com" or "cn=Marketing,cn=Users,dc=mydomain,dc=com"

.PARAMETER ResourceId
The unique ID for a machine list file that is used for file-based discovery scans (mandatory for WIN_NIX_LIST scans).

.PARAMETER DomainControllerTarget
Include domain controllers in the scan targets (default: true for domain scans).

.PARAMETER NonPrivilegedTarget
Include non-privileged machines in the scan targets (default: true for domain scans).

.PARAMETER GroupsTarget
Include AD groups in the scan (default: true for domain scans).

.PARAMETER Properties
A hashtable of additional properties that define the scan (optional). Use this for properties not covered by individual parameters.

.PARAMETER Credentials
The credentials used to run the scan and access the targets. Array of credential objects with name, type, and properties.

.PARAMETER NetworkId
The network ID selected by the customer. The network must be defined in Connector Management and assigned to a connector pool with at least one connector. Mandatory for list scans, optional for domain scans.

.PARAMETER NetworkName
The network name selected by the customer. Alternative to NetworkId - the function will resolve the name to an ID using Get-ConnectorNetwork. The network must be defined in Connector Management and assigned to a connector pool with at least one connector.

.PARAMETER CMURL
The URL of the CyberArk Connector Management service. Required when using NetworkName to resolve network names to IDs. Can be automatically derived from PCloudURL using Get-CMURL helper function.

.PARAMETER RecurrenceType
Determines the recurrence policy of the scan (mandatory). Valid values: IMMEDIATE, SCHEDULED, RECURRING.

.PARAMETER Tags
User-defined tags that are added to accounts discovered in this scan. Up to 20 tags for domain scan, up to 10 tags for list scan. Alphanumeric strings (no spaces, can include underscore _).

.PARAMETER AdditionalProperties
Additional properties to include in the scan definition request body (optional).

.EXAMPLE
# Create a Windows/nix domain scan
New-ScanDefinition -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -Name "Windows-nix-scan" -Type "WIN_NIX_DOMAIN" -Domain "company.com" -OU "cn=mygroup" -DomainControllerTarget $true -NonPrivilegedTarget $true -GroupsTarget $true -Credentials $creds -RecurrenceType "IMMEDIATE"

.EXAMPLE
# Create a file-based machine list scan
$creds = @(
    @{
        name = "DOMAIN_ADMIN"
        type = "ACCOUNT"
        properties = @{
            account_id = "10_3"
        }
    }
)
New-ScanDefinition -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -Name "machinelist2" -Type "WIN_NIX_LIST" -ResourceId "c2601488-7e2c-4d82-a5b8-9c59cfa869cd" -Domain "sampledomain.com" -NetworkId "3114a726-6f1f-448a-8a04-87a6605b1758" -Credentials $creds -RecurrenceType "IMMEDIATE"

.EXAMPLE
# Create a file-based machine list scan using network name
$creds = @(
    @{
        name = "DOMAIN_ADMIN"
        type = "ACCOUNT"
        properties = @{
            account_id = "10_3"
        }
    }
)
New-ScanDefinition -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -Name "machinelist2" -Type "WIN_NIX_LIST" -ResourceId "c2601488-7e2c-4d82-a5b8-9c59cfa869cd" -Domain "sampledomain.com" -NetworkName "Production Network" -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -Credentials $creds -RecurrenceType "IMMEDIATE"

.EXAMPLE
# Create a domain scan with additional properties
$additionalProps = @{
    customField = "customValue"
    schedule = "0 2 * * *"
}
New-ScanDefinition -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -Name "Advanced-scan" -Type "WIN_NIX_DOMAIN" -Domain "company.com" -Properties $additionalProps -RecurrenceType "SCHEDULED"

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /scan-definitions endpoint with POST method.
You can define up to 500 scan definitions.
The network must be defined in Connector Management for list scans.

#>

function New-ScanDefinition {
    [CmdletBinding()]
    param (

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 100)]
        [ValidatePattern('^[a-zA-Z0-9].*[a-zA-Z0-9]$|^[a-zA-Z0-9]$')]
        [string]$Name,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [ValidateSet('WIN_NIX_LIST', 'WIN_NIX_DOMAIN')]
        [string]$Type,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Domain,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$OU,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$ResourceId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$DomainControllerTarget = $true,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$NonPrivilegedTarget = $true,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$GroupsTarget = $true,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$Properties,

        [Parameter(ValueFromPipelineByPropertyName)]
        [array]$Credentials,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$NetworkId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$NetworkName,

        [Alias('ConnectorManagementURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$CMURL,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [ValidateSet('IMMEDIATE', 'SCHEDULED', 'RECURRING')]
        [string]$RecurrenceType,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateCount(0, 20)]
        [string[]]$Tags,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$AdditionalProperties,

        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$DiscoveryURL,

        [Alias('header')]
        $LogonToken
    )

    begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null
        $BaseURL = "$DiscoveryURL/api"
    }

    process {
        try {
            $URL = "$BaseURL/scan-definitions"

            # Build the properties object based on scan type and provided parameters
            $PropertiesObject = @{}

            # Add common properties
            if (-not [string]::IsNullOrEmpty($Domain)) {
                $PropertiesObject.domain = $Domain
            }

            # Add scan type specific properties
            switch ($Type) {
                'WIN_NIX_DOMAIN' {
                    # Domain scan specific properties
                    if (-not [string]::IsNullOrEmpty($OU)) {
                        $PropertiesObject.ou = $OU
                    }

                    # Add targets object
                    $PropertiesObject.targets = @{
                        domainController = $DomainControllerTarget
                        nonPrivileged    = $NonPrivilegedTarget
                    }

                    # Add adGroups object
                    $PropertiesObject.adGroups = @{
                        groups = $GroupsTarget
                    }

                    # Validate domain is provided for domain scans
                    if ([string]::IsNullOrEmpty($Domain)) {
                        throw 'Domain parameter is mandatory for WIN_NIX_DOMAIN scan type'
                    }
                }
                'WIN_NIX_LIST' {
                    # List scan specific properties
                    if (-not [string]::IsNullOrEmpty($ResourceId)) {
                        $PropertiesObject.resource = @{
                            id = $ResourceId
                        }
                    }
                    else {
                        throw 'ResourceId parameter is mandatory for WIN_NIX_LIST scan type'
                    }
                }
            }

            # Add any additional properties from the Properties hashtable
            if ($PSBoundParameters.ContainsKey('Properties') -and $Properties.Count -gt 0) {
                foreach ($key in $Properties.Keys) {
                    $PropertiesObject[$key] = $Properties[$key]
                }
            }

            # Build the request body from individual parameters
            $RequestBody = @{
                name           = $Name
                type           = $Type
                properties     = $PropertiesObject
                recurrenceType = $RecurrenceType
            }

            # Add optional credentials if provided
            if ($PSBoundParameters.ContainsKey('Credentials') -and $Credentials.Count -gt 0) {
                $RequestBody.credentials = $Credentials
            }

            # Resolve network name to ID if NetworkName is provided
            $ResolvedNetworkId = $NetworkId
            if (-not [string]::IsNullOrEmpty($NetworkName)) {
                if ([string]::IsNullOrEmpty($CMURL)) {
                    throw 'CMURL parameter is required when using NetworkName'
                }

                Write-LogMessage -type Verbose -MSG "Resolving network name '$NetworkName' to ID"
                try {
                    $networks = Get-ConnectorNetwork -CMURL $CMURL -LogonToken $LogonToken -Name $NetworkName
                    if ($networks -and $networks.data -and $networks.data.Count -gt 0) {
                        $ResolvedNetworkId = $networks.data[0].id
                        Write-LogMessage -type Verbose -MSG "Resolved network '$NetworkName' to ID: $ResolvedNetworkId"
                    }
                    else {
                        throw "Network with name '$NetworkName' not found"
                    }
                }
                catch {
                    throw "Failed to resolve network name '$NetworkName'. Error: $($_.Exception.Message)"
                }
            }            # Add optional networkId if provided or resolved
            if (-not [string]::IsNullOrEmpty($ResolvedNetworkId)) {
                $RequestBody.networkId = $ResolvedNetworkId
            }

            # Add optional tags if provided
            if ($PSBoundParameters.ContainsKey('Tags') -and $Tags.Count -gt 0) {
                $RequestBody.tags = $Tags
            }

            # Add any additional properties if provided
            if ($PSBoundParameters.ContainsKey('AdditionalProperties') -and $AdditionalProperties.Count -gt 0) {
                foreach ($key in $AdditionalProperties.Keys) {
                    $RequestBody[$key] = $AdditionalProperties[$key]
                }
            }

            $Body = $RequestBody | ConvertTo-Json -Depth 10 -Compress

            Write-LogMessage -type Verbose -MSG "Creating new scan definition: $Name"
            Write-LogMessage -type Verbose -MSG "Scan type: $Type"
            if (-not [string]::IsNullOrEmpty($Domain)) {
                Write-LogMessage -type Verbose -MSG "Domain: $Domain"
            }
            if ($Type -eq 'WIN_NIX_LIST' -and -not [string]::IsNullOrEmpty($ResourceId)) {
                Write-LogMessage -type Verbose -MSG "Resource ID: $ResourceId"
            }
            if (-not [string]::IsNullOrEmpty($ResolvedNetworkId)) {
                if (-not [string]::IsNullOrEmpty($NetworkName)) {
                    Write-LogMessage -type Verbose -MSG "Network: $NetworkName (ID: $ResolvedNetworkId)"
                }
                else {
                    Write-LogMessage -type Verbose -MSG "Network ID: $ResolvedNetworkId"
                }
            }
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"
            Write-LogMessage -type Verbose -MSG "Request Body: $Body"

            $RestParms = @{
                Uri         = $URL
                Method      = 'POST'
                Body        = $Body
                ContentType = 'application/json'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms

            Write-LogMessage -type Success -MSG "Successfully created scan definition: $Name (ID: $($restResponse.id))"
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to create scan definition '$Name'. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\DiscoveryManagement\New-ScanDefinition.ps1' 331
#Region '.\Public\PAS\DiscoveryManagement\Remove-ScanDefinition.ps1' -1

<#
.SYNOPSIS
Removes a scan definition from the Discovery Management API.

.DESCRIPTION
The Remove-ScanDefinition function deletes a scan definition from the Discovery Management API based on the scan definition ID.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER ScanDefinitionID
The unique identifier of the scan definition to delete (mandatory).

.EXAMPLE
Remove-ScanDefinition -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -ScanDefinitionID "9d963737-b704-4c63-bba9-17d8236691f6"

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /scan-definitions/{id} endpoint with DELETE method.

#>

function Remove-ScanDefinition {
    [CmdletBinding(SupportsShouldProcess)]
    param (

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$ScanDefinitionID,

                [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$DiscoveryURL,

        [Alias('header')]
        $LogonToken
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$DiscoveryURL/api"
    }

    Process {
        if ($PSCmdlet.ShouldProcess($ScanDefinitionID, "Delete Scan Definition")) {
            try {
                $URL = "$BaseURL/scan-definitions/$ScanDefinitionID"

                Write-LogMessage -type Verbose -MSG "Deleting scan definition with ID: $ScanDefinitionID"
                Write-LogMessage -type Verbose -MSG "Request URL: $URL"

                $RestParms = @{
                    Uri    = $URL
                    Method = 'DELETE'
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                $restResponse = Invoke-Rest @RestParms

                Write-LogMessage -type Success -MSG "Successfully deleted scan definition: $ScanDefinitionID"
                return $restResponse
            }
            catch {
                Write-LogMessage -type Error -MSG "Failed to delete scan definition $ScanDefinitionID. Error: $($_.Exception.Message)"
                throw
            }
        }
    }
}
#EndRegion '.\Public\PAS\DiscoveryManagement\Remove-ScanDefinition.ps1' 76
#Region '.\Public\PAS\DiscoveryManagement\Set-ScanDefinition.ps1' -1

<#
.SYNOPSIS
Updates an existing scan definition in the Discovery Management API.

.DESCRIPTION
The Set-ScanDefinition function updates an existing scan definition in the CyberArk Discovery Management API using the provided scan definition data. The function supports both domain-based and file-based scans for Windows and *nix systems.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER ScanDefinitionID
The unique identifier of the scan definition to update (mandatory).

.PARAMETER Name
The name of the scan definition (mandatory). Must be up to 100 alphanumeric characters including spaces and underscore, dash, period, and at signs (_ - . @). Must begin and end with a valid character and not a space.

.PARAMETER Type
The scan type to use for this scan definition (mandatory). Valid values: WIN_NIX_LIST, WIN_NIX_DOMAIN.

.PARAMETER Domain
The domain name for the scan (mandatory for domain scans, optional for list scans). Example: "company.com"

.PARAMETER OU
Organizational Unit for domain scans (optional). Discovery scans the entire AD domain for machines and users defined at the AD level, directly in the OU, and in all the AD groups within the OU. Example: "dc=domain,dc=com" or "cn=Marketing,cn=Users,dc=mydomain,dc=com"

.PARAMETER ResourceId
The unique ID for a machine list file that is used for file-based discovery scans (mandatory for WIN_NIX_LIST scans).

.PARAMETER DomainControllerTarget
Include domain controllers in the scan targets (default: true for domain scans).

.PARAMETER NonPrivilegedTarget
Include non-privileged machines in the scan targets (default: true for domain scans).

.PARAMETER GroupsTarget
Include AD groups in the scan (default: true for domain scans).

.PARAMETER Properties
A hashtable of additional properties that define the scan (optional). Use this for properties not covered by individual parameters.

.PARAMETER Credentials
The credentials used to run the scan and access the targets. Array of credential objects with name, type, and properties.

.PARAMETER NetworkId
The network ID selected by the customer. The network must be defined in Connector Management and assigned to a connector pool with at least one connector. Mandatory for list scans, optional for domain scans.

.PARAMETER NetworkName
The network name selected by the customer. Alternative to NetworkId - the function will resolve the name to an ID using Get-ConnectorNetwork. The network must be defined in Connector Management and assigned to a connector pool with at least one connector.

.PARAMETER CMURL
The URL of the CyberArk Connector Management service. Required when using NetworkName to resolve network names to IDs. Can be automatically derived from PCloudURL using Get-CMURL helper function.

.PARAMETER RecurrenceType
Determines the recurrence policy of the scan (mandatory). Valid values: IMMEDIATE, SCHEDULED, RECURRING.

.PARAMETER Tags
User-defined tags that are added to accounts discovered in this scan. Up to 20 tags for domain scan, up to 10 tags for list scan. Alphanumeric strings (no spaces, can include underscore _).

.PARAMETER AdditionalProperties
Additional properties to include in the scan definition request body (optional).

.EXAMPLE
# Update a Windows/nix domain scan
Set-ScanDefinition -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -ScanDefinitionID "9d963737-b704-4c63-bba9-17d8236691f6" -Name "Updated-Windows-nix-scan" -Type "WIN_NIX_DOMAIN" -Domain "updated-company.com" -OU "cn=updated-group" -DomainControllerTarget $true -NonPrivilegedTarget $false -GroupsTarget $true -RecurrenceType "SCHEDULED"

.EXAMPLE
# Update a list scan with network name
Set-ScanDefinition -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -ScanDefinitionID "9d963737-b704-4c63-bba9-17d8236691f6" -Name "Updated-List-Scan" -Type "WIN_NIX_LIST" -ResourceId "c2601488-7e2c-4d82-a5b8-9c59cfa869cd" -NetworkName "Production Network" -CMURL "https://subdomain.connectormanagement.cyberark.cloud/api/pool-service" -RecurrenceType "SCHEDULED"

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /scan-definitions/{id} endpoint with PUT method.

#>

function Set-ScanDefinition {
    [CmdletBinding()]
    param (

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$ScanDefinitionID,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 100)]
        [ValidatePattern('^[a-zA-Z0-9].*[a-zA-Z0-9]$|^[a-zA-Z0-9]$')]
        [string]$Name,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [ValidateSet("WIN_NIX_LIST", "WIN_NIX_DOMAIN")]
        [string]$Type,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Domain,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$OU,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$ResourceId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$DomainControllerTarget = $true,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$NonPrivilegedTarget = $true,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$GroupsTarget = $true,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$Properties,

        [Parameter(ValueFromPipelineByPropertyName)]
        [array]$Credentials,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$NetworkId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$NetworkName,

        [Alias('ConnectorManagementURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$CMURL,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [ValidateSet("IMMEDIATE", "SCHEDULED", "RECURRING")]
        [string]$RecurrenceType,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateCount(0, 20)]
        [string[]]$Tags,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$AdditionalProperties,

                [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$DiscoveryURL,

        [Alias('header')]
        $LogonToken
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$DiscoveryURL/api"
    }

    Process {
        try {
            $URL = "$BaseURL/scan-definitions/$ScanDefinitionID"

            # Build the properties object based on scan type and provided parameters
            $PropertiesObject = @{}

            # Add common properties
            if (-not [string]::IsNullOrEmpty($Domain)) {
                $PropertiesObject.domain = $Domain
            }

            # Add scan type specific properties
            switch ($Type) {
                "WIN_NIX_DOMAIN" {
                    # Domain scan specific properties
                    if (-not [string]::IsNullOrEmpty($OU)) {
                        $PropertiesObject.ou = $OU
                    }

                    # Add targets object
                    $PropertiesObject.targets = @{
                        domainController = $DomainControllerTarget
                        nonPrivileged = $NonPrivilegedTarget
                    }

                    # Add adGroups object
                    $PropertiesObject.adGroups = @{
                        groups = $GroupsTarget
                    }

                    # Validate domain is provided for domain scans
                    if ([string]::IsNullOrEmpty($Domain)) {
                        throw "Domain parameter is mandatory for WIN_NIX_DOMAIN scan type"
                    }
                }
                "WIN_NIX_LIST" {
                    # List scan specific properties
                    if (-not [string]::IsNullOrEmpty($ResourceId)) {
                        $PropertiesObject.resource = @{
                            id = $ResourceId
                        }
                    } else {
                        throw "ResourceId parameter is mandatory for WIN_NIX_LIST scan type"
                    }
                }
            }

            # Add any additional properties from the Properties hashtable
            if ($PSBoundParameters.ContainsKey('Properties') -and $Properties.Count -gt 0) {
                foreach ($key in $Properties.Keys) {
                    $PropertiesObject[$key] = $Properties[$key]
                }
            }

            # Build the request body from individual parameters
            $RequestBody = @{
                name = $Name
                type = $Type
                properties = $PropertiesObject
                recurrenceType = $RecurrenceType
            }

            # Add optional credentials if provided
            if ($PSBoundParameters.ContainsKey('Credentials') -and $Credentials.Count -gt 0) {
                $RequestBody.credentials = $Credentials
            }

            # Resolve network name to ID if NetworkName is provided
            $ResolvedNetworkId = $NetworkId
            if (-not [string]::IsNullOrEmpty($NetworkName)) {
                if ([string]::IsNullOrEmpty($CMURL)) {
                    throw "CMURL parameter is required when using NetworkName"
                }

                Write-LogMessage -type Verbose -MSG "Resolving network name '$NetworkName' to ID"
                try {
                    $networks = Get-ConnectorNetwork -CMURL $CMURL -LogonToken $LogonToken -Name $NetworkName
                    if ($networks -and $networks.data -and $networks.data.Count -gt 0) {
                        $ResolvedNetworkId = $networks.data[0].id
                        Write-LogMessage -type Verbose -MSG "Resolved network '$NetworkName' to ID: $ResolvedNetworkId"
                    } else {
                        throw "Network with name '$NetworkName' not found"
                    }
                }
                catch {
                    throw "Failed to resolve network name '$NetworkName'. Error: $($_.Exception.Message)"
                }
            }            # Add optional networkId if provided or resolved
            if (-not [string]::IsNullOrEmpty($ResolvedNetworkId)) {
                $RequestBody.networkId = $ResolvedNetworkId
            }

            # Add optional tags if provided
            if ($PSBoundParameters.ContainsKey('Tags') -and $Tags.Count -gt 0) {
                $RequestBody.tags = $Tags
            }

            # Add any additional properties if provided
            if ($PSBoundParameters.ContainsKey('AdditionalProperties') -and $AdditionalProperties.Count -gt 0) {
                foreach ($key in $AdditionalProperties.Keys) {
                    $RequestBody[$key] = $AdditionalProperties[$key]
                }
            }

            $Body = $RequestBody | ConvertTo-Json -Depth 10 -Compress

            Write-LogMessage -type Verbose -MSG "Updating scan definition: $Name (ID: $ScanDefinitionID)"
            Write-LogMessage -type Verbose -MSG "Scan type: $Type"
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"
            Write-LogMessage -type Verbose -MSG "Request Body: $Body"

            $RestParms = @{
                Uri         = $URL
                Method      = 'PUT'
                Body        = $Body
                ContentType = "application/json"
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms

            Write-LogMessage -type Success -MSG "Successfully updated scan definition: $Name (ID: $ScanDefinitionID)"
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to update scan definition '$Name' (ID: $ScanDefinitionID). Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\DiscoveryManagement\Set-ScanDefinition.ps1' 290
#Region '.\Public\PAS\DiscoveryManagement\Start-Scan.ps1' -1

<#
.SYNOPSIS
Creates a new scan instance from a scan definition in the Discovery Management API.

.DESCRIPTION
The Start-Scan function creates a new scan instance from an existing scan definition in the Discovery Management API.

.PARAMETER DiscoveryURL
The URL of the CyberArk Discovery Management service in the format https://<subdomain>.discoverymgmt.cyberark.cloud

.PARAMETER LogonToken
The authentication token used for API requests.

.PARAMETER ScanDefinitionID
The unique identifier of the scan definition to create the scan instance from (mandatory).

.PARAMETER AdditionalProperties
Additional properties to include in the scan instance request body (optional).

.EXAMPLE
Start-Scan -DiscoveryURL "https://subdomain.discoverymgmt.cyberark.cloud" -LogonToken $token -ScanDefinitionID "9d963737-b704-4c63-bba9-17d8236691f6"

.NOTES
This function requires the DiscoveryURL and a valid logon token to authenticate API requests.
Uses the /scans endpoint with POST method.

#>

function Start-Scan {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string]$DiscoveryURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$ScanDefinitionID,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$AdditionalProperties
    )

    begin {
        Write-LogMessage -type Warning -MSG 'Not implemented at this time.'
        exit
        $PSBoundParameters.Remove('CatchAll') | Out-Null
        $BaseURL = "$DiscoveryURL/api"
    }

    process {
        try {
            $URL = "$BaseURL/scans"

            # Build the request body with the scan definition ID
            $RequestBody = @{
                scanDefinitionID = $ScanDefinitionID
            }

            # Add any additional properties if provided
            if ($PSBoundParameters.ContainsKey('AdditionalProperties') -and $AdditionalProperties.Count -gt 0) {
                foreach ($key in $AdditionalProperties.Keys) {
                    $RequestBody[$key] = $AdditionalProperties[$key]
                }
            }

            $Body = $RequestBody | ConvertTo-Json -Depth 10 -Compress

            Write-LogMessage -type Verbose -MSG "Creating new scan instance from definition: $ScanDefinitionID"
            Write-LogMessage -type Verbose -MSG "Request URL: $URL"
            Write-LogMessage -type Verbose -MSG "Request Body: $Body"

            $RestParms = @{
                Uri         = $URL
                Method      = 'POST'
                Body        = $Body
                ContentType = 'application/json'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms

            Write-LogMessage -type Success -MSG "Successfully created scan instance from definition: $ScanDefinitionID"
            return $restResponse
        }
        catch {
            Write-LogMessage -type Error -MSG "Failed to create scan instance from definition $ScanDefinitionID. Error: $($_.Exception.Message)"
            throw
        }
    }
}
#EndRegion '.\Public\PAS\DiscoveryManagement\Start-Scan.ps1' 98
#Region '.\Public\PAS\Platform\Get-Platform.ps1' -1

# TODO: Implement Get-Platform function
# This function should retrieve platform information from the PVWA API
function Get-Platform {
    [CmdletBinding()]
    param()

    Write-Warning "Function not yet implemented. This will retrieve platform information."
}
#EndRegion '.\Public\PAS\Platform\Get-Platform.ps1' 9
#Region '.\Public\PAS\PSM\Connect-AccountPSM.ps1' -1

<#
.SYNOPSIS
Connects to an account through PSM (Privileged Session Manager) in the PVWA system.

.DESCRIPTION
The Connect-AccountPSM function connects to the PVWA API to connect with an account
through PSM using an RDP file or to the PSMGW. It returns RDP settings that can be
used with an RDP client application or settings for the PSMGW.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication with the PVWA API.

.PARAMETER AccountID
The unique ID of the account to retrieve and use to connect to the target system through PSM.

.PARAMETER Reason
The reason for connecting to the account.

.PARAMETER TicketID
The ticket ID for connecting to the account.

.PARAMETER ConnectionComponent
The name of the connection component to use.

.PARAMETER AllowMappingLocalDrives
Whether to allow mapping of local drives.

.PARAMETER AllowConnectToConsole
Whether to allow connection to console.

.PARAMETER RedirectSmartCards
Whether to redirect smart cards.

.PARAMETER PSMRemoteApp
The PSM remote application to use.

.PARAMETER LogonDomain
The logon domain for the connection.

.PARAMETER AllowSelectHTML5
Whether to allow HTML5 selection.

.EXAMPLE
Connect-AccountPSM -PVWAURL "https://pvwa.example.com" -LogonToken $token -AccountID "12_34" -Reason "Maintenance"

Connects to account with ID "12_34" through PSM with the reason "Maintenance".

.NOTES
The user who runs this function requires appropriate permissions in the Safe
where the account is stored.
The PVWA and PSM must be configured for transparent connections through PSM with RDP files or PSMGW.
This function is part of the EPV-API-Common module and is used to manage accounts
in the CyberArk Privileged Access Security Web Application.
#>
function Connect-AccountPSM {
    [CmdletBinding(DefaultParameterSetName = "PVWAURL")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PVWAURL,

        [Alias('header')]
        [Parameter(ValueFromPipelineByPropertyName)]
        $LogonToken,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName)]
        [Alias("id")]
        [string]$AccountID,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Reason,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$TicketID,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ConnectionComponent,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$AllowMappingLocalDrives,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$AllowConnectToConsole,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$RedirectSmartCards,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$PSMRemoteApp,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$LogonDomain,

        [Parameter(ValueFromPipelineByPropertyName)]
        [bool]$AllowSelectHTML5
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $PSMConnectURL = "$BaseURL/Accounts/{0}/PSMConnect"
    }

    Process {
        Write-LogMessage -type Verbose -MSG "Connecting to account `"$AccountID`" through PSM"

        $URL = $PSMConnectURL -f $AccountID

        # Build the request body
        $body = @{}

        if (-not [string]::IsNullOrEmpty($Reason)) {
            $body["reason"] = $Reason
        }

        if (-not [string]::IsNullOrEmpty($TicketID)) {
            $body["ticketID"] = $TicketID
        }

        if (-not [string]::IsNullOrEmpty($ConnectionComponent)) {
            $body["connectionComponent"] = $ConnectionComponent
        }

        if ($PSBoundParameters.ContainsKey('AllowMappingLocalDrives')) {
            $body["allowMappingLocalDrives"] = $AllowMappingLocalDrives
        }

        if ($PSBoundParameters.ContainsKey('AllowConnectToConsole')) {
            $body["allowConnectToConsole"] = $AllowConnectToConsole
        }

        if ($PSBoundParameters.ContainsKey('RedirectSmartCards')) {
            $body["redirectSmartCards"] = $RedirectSmartCards
        }

        if (-not [string]::IsNullOrEmpty($PSMRemoteApp)) {
            $body["PSMRemoteApp"] = $PSMRemoteApp
        }

        if (-not [string]::IsNullOrEmpty($LogonDomain)) {
            $body["logonDomain"] = $LogonDomain
        }

        if ($PSBoundParameters.ContainsKey('AllowSelectHTML5')) {
            $body["allowSelectHTML5"] = $AllowSelectHTML5
        }

        $RestParms = @{
            Uri    = $URL
            Method = 'POST'
            Body   = $body
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        $restResponse = Invoke-Rest @RestParms

        Write-LogMessage -type Verbose -MSG "PSM connection established successfully for account `"$AccountID`""
        return $restResponse
    }
}
#EndRegion '.\Public\PAS\PSM\Connect-AccountPSM.ps1' 168
#Region '.\Public\PAS\PSM\Get-PSMSession.ps1' -1

# TODO: Implement Get-PSMSession function
# This function should retrieve PSM session information from the PVWA API
function Get-PSMSession {
    [CmdletBinding()]
    param()

    Write-Warning "Function not yet implemented. This will retrieve PSM session information."
}
#EndRegion '.\Public\PAS\PSM\Get-PSMSession.ps1' 9
#Region '.\Public\PAS\Safe\Core\Get-Safe.ps1' -1

<#
.SYNOPSIS
    Retrieves information about safes from the PVWA API.

.DESCRIPTION
    The Get-Safe function retrieves information about safes from the PVWA API. It supports multiple parameter sets to allow retrieval by Safe ID, Platform ID, or general queries. The function can also return all safes if no specific parameters are provided.

.PARAMETER PVWAURL
    The URL of the PVWA instance.

.PARAMETER LogonToken
    The logon token for authentication.

.PARAMETER SafeUrlId
    The ID of the safe to retrieve.

.PARAMETER SafeName
    The name of the safe to retrieve.

.PARAMETER PlatformID
    The ID of the platform to retrieve safes for.

.PARAMETER AllSafes
    Switch to retrieve all safes.

.PARAMETER ExtendedDetails
    Switch to include extended details in the results.

.PARAMETER includeAccounts
    Switch to include accounts in the results.

.PARAMETER useCache
    Switch to use cached results.

.PARAMETER Search
    A search string to filter the results.

.PARAMETER offset
    The offset for pagination.

.PARAMETER limit
    The limit for pagination.

.PARAMETER DoNotPage
    Switch to disable pagination.

.PARAMETER sort
    The sort order for the results. Valid values are "asc" and "desc".

.EXAMPLE
    Get-Safe -PVWAURL "https://pvwa.example.com" -LogonToken $token -SafeUrlId "12345"
    Retrieves the safe with ID 12345.

.EXAMPLE
    Get-Safe -PVWAURL "https://pvwa.example.com" -LogonToken $token -AllSafes
    Retrieves all safes.

.EXAMPLE
    Get-Safe -PVWAURL "https://pvwa.example.com" -LogonToken $token -SafeName "MySafe" -PlatformID "Platform1"
    Retrieves the safe named "MySafe" for platform "Platform1".

.NOTES
    Author: Your Name
    Date: YYYY-MM-DD
#>
function Get-Safe {
    [CmdletBinding(DefaultParameterSetName = 'PVWAURL')]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,


        [Parameter(ParameterSetName = 'SafeUrlId', ValueFromPipelineByPropertyName)]
        [Alias('SafeID')]
        [string]
        $SafeUrlId,

        [Parameter(ParameterSetName = 'SafeName', ValueFromPipelineByPropertyName)]
        [Alias('Safe')]
        [string]
        $SafeName,

        [Parameter(ParameterSetName = 'PlatformID', ValueFromPipelineByPropertyName)]
        [string]
        $PlatformID,

        [Parameter(ParameterSetName = 'AllSafes', ValueFromPipelineByPropertyName)]
        [switch]
        $AllSafes,

        [Parameter(ParameterSetName = 'AllSafes', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'SafeName', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'SafeUrlId', ValueFromPipelineByPropertyName)]
        [switch]
        $ExtendedDetails,

        [Parameter(ParameterSetName = 'AllSafes', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'SafeName', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'SafeUrlId', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'PlatformID', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'Search', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'PVWAURL', ValueFromPipelineByPropertyName)]
        [switch]
        $includeAccounts,

        [Parameter(ParameterSetName = 'AllSafes')]
        [Parameter(ParameterSetName = 'SafeName', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'SafeUrlId', ValueFromPipelineByPropertyName)]
        [switch]
        $useCache,

        [Parameter(ParameterSetName = 'PVWAURL', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'SafeName', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'Search', ValueFromPipelineByPropertyName)]
        [string]
        $Search,

        [Parameter(ParameterSetName = 'AllSafes')]
        [Parameter(ParameterSetName = 'SafeName', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'SafeUrlId', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'Search')]
        [Nullable[int]]
        $offset = $null,

        [Parameter(ParameterSetName = 'AllSafes')]
        [Parameter(ParameterSetName = 'SafeName', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'Search')]
        [Nullable[int]]
        $limit,

        [Parameter(ParameterSetName = 'AllSafes')]
        [Parameter(ParameterSetName = 'SafeName', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'SafeID', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'Search')]
        [switch]
        $DoNotPage,

        [Parameter(ParameterSetName = 'AllSafes')]
        [Parameter(ParameterSetName = 'SafeName', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'SafeUrlId', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'Search')]
        [AllowEmptyString]
        [ValidateSet('asc', 'desc')]
        $sort,

        [Alias('url', 'PCloudURL')]
        [Parameter(ParameterSetName = 'AllSafes', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'SafeName', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'SafeUrlId', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'PlatformID', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'Search', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'PVWAURL', ValueFromPipelineByPropertyName)]
        [string]
        $PVWAURL,

        [Alias('header')]
        [Parameter(ParameterSetName = 'AllSafes', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'SafeName', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'SafeUrlId', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'PlatformID', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'Search', ValueFromPipelineByPropertyName)]
        [Parameter(ParameterSetName = 'PVWAURL', ValueFromPipelineByPropertyName)]
        $LogonToken
    )

    begin {
        if ([string]::IsNullOrEmpty($PVWAURL) -and -not [string]::IsNullOrEmpty($PSDefaultParameterValues['*:PVWAURL'])) {
            $PVWAURL = $PSDefaultParameterValues['*:PVWAURL']
        }
        if ([string]::IsNullOrEmpty($LogonToken) -and -not [string]::IsNullOrEmpty($PSDefaultParameterValues['*:LogonToken'])) {
            $LogonToken = $PSDefaultParameterValues['*:LogonToken']
        }


        $PSBoundParameters.Remove('CatchAll') | Out-Null
        $BaseURL = "$PVWAURL/API/"
        $SafeURL = "$BaseURL/Safes?"
        $SafeIDURL = "$BaseURL/Safes/{0}/?"
        $PlatformIDURL = "$BaseURL/Platforms/{0}/Safes/{1}/?"
    }

    process {
        $SafeUrlIdExists = -not [string]::IsNullOrEmpty($SafeUrlId)
        $SafeNameExists = -not [string]::IsNullOrEmpty($SafeName)
        $PlatformIDExists = -not [string]::IsNullOrEmpty($PlatformID)
        $SearchExists = -not [string]::IsNullOrEmpty($Search)

        if ($SafeUrlIdExists) {
            Get-SafeViaID
        }
        elseif ($PlatformIDExists) {
            Get-SafeViaPlatformID
        }
        else {
            if (-not ($SafeNameExists -or $PlatformIDExists -or $SafeUrlIdExists)) {
                Write-LogMessage -type Debug -MSG 'No Safe Name, Safe ID, or Platform ID provided, returning all safes'
            }
            Get-SafeViaQuery
        }
    }
}

function Get-SafeViaID {
    $URL = $SafeIDURL -f $SafeUrlId
    Write-LogMessage -type Debug -MSG "Getting safe with ID of `"$SafeUrlId`""
    Add-BaseQueryParameter -URL ([ref]$URL)
    Add-SafeQueryParameter -URL ([ref]$URL)
    $RestParms = @{
        Uri    = $URL
        Method = 'GET'
    }
    if ($null -ne $LogonToken) {
        $RestParms.LogonToken = $LogonToken
    }
    $restResponse = Invoke-Rest @RestParms
    return [safe]$restResponse
}

function Get-SafeViaPlatformID {
    if ($SafeNameExists) {
        Write-LogMessage -type Debug -MSG "Searching for a safe with the name of `"$SafeName`" and a platformID of `"$PlatformID`""
        $URL = $PlatformIDURL -f $PlatformID, $SafeName
    }
    else {
        Write-LogMessage -type Debug -MSG "Getting a list of safes available to platformID `"$PlatformID`""
        $URL = $PlatformIDURL -f $PlatformID
    }
    $RestParms = @{
        Uri    = $URL
        Method = 'GET'
    }
    if ($null -ne $LogonToken) {
        $RestParms.LogonToken = $LogonToken
    }
    [PSCustomObject[]]$resultList = Invoke-RestNextLink @RestParms
    return [safe[]]$resultList
}

function Get-SafeViaQuery {
    Write-LogMessage -type Debug -MSG 'Getting list of safes'
    $URL = $SafeURL
    Add-BaseQueryParameter -URL ([ref]$URL)
    Add-SafeQueryParameter -URL ([ref]$URL)
    $RestParms = @{
        Uri    = $URL
        Method = 'GET'
    }
    if ($null -ne $LogonToken) {
        $RestParms.LogonToken = $LogonToken
    }
    [PSCustomObject[]]$resultList = Invoke-RestNextLink @RestParms
    return [safe[]]$resultList
}

function Add-SafeQueryParameter {
    param (
        [ref]$URL
    )
    Write-LogMessage -type Debug -MSG 'Adding Query Parameters'
    if ($includeAccounts) {
        $URL.Value += '&includeAccounts=true'
        Write-LogMessage -type Debug -MSG 'Including accounts in results'
    }
    if ($ExtendedDetails) {
        $URL.Value += '&extendedDetails=true'
        Write-LogMessage -type Debug -MSG 'Including extended details'
    }

    if ($SafeNameExists -or $SearchExists) {
        $searchValue = "$Safename $Search".trim()
        $Value = $([uri]::EscapeDataString($searchValue))
        $URL.Value += "&search=$Value"
        Write-LogMessage -type Debug -MSG "Applying a search of `"$Value`""
    }
    $URL.Value = $URL.Value.Replace('?&', '?')
    Write-LogMessage -type Debug -MSG "New URL: $($url.Value)"
}
#EndRegion '.\Public\PAS\Safe\Core\Get-Safe.ps1' 278
#Region '.\Public\PAS\Safe\Core\New-Safe.ps1' -1

<#
.SYNOPSIS
Creates a new safe in the specified PVWA instance.

.DESCRIPTION
The New-Safe function creates a new safe in the specified PVWA instance using the provided parameters.
It supports ShouldProcess for confirmation prompts and logs the process.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token for authentication.

.PARAMETER safeName
The name of the safe to be created.

.PARAMETER description
The description of the safe.

.PARAMETER location
The location of the safe.

.PARAMETER olacEnabled
Switch to enable or disable OLAC (Object Level Access Control).

.PARAMETER managingCPM
The name of the managing CPM (Central Policy Manager).

.PARAMETER numberOfVersionsRetention
The number of versions to retain.

.PARAMETER numberOfDaysRetention
The number of days to retain versions.

.PARAMETER AutoPurgeEnabled
Switch to enable or disable automatic purging.

.EXAMPLE
PS> New-Safe -PVWAURL "https://pvwa.example.com" -LogonToken $token -safeName "NewSafe" -description "This is a new safe" -location "Root" -olacEnabled -managingCPM "CPM1" -numberOfVersionsRetention "5" -numberOfDaysRetention "30" -AutoPurgeEnabled

This command creates a new safe named "NewSafe" in the specified PVWA instance with the given parameters.

.NOTES
This function requires the 'Invoke-Rest' and 'Write-LogMessage' functions to be defined in the session.
#>

function New-Safe {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (


        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string] $safeName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $location,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch] $olacEnabled,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $managingCPM,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $numberOfVersionsRetention,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $numberOfDaysRetention,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch] $AutoPurgeEnabled,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch] $UpdateOnDuplicate,


        [Alias('url', 'PCloudURL')]
        [string] $PVWAURL,


        [Alias('header')]
        $LogonToken
    )

    Begin {
        $SafeURL = "$PVWAURL/API/Safes/"
    }

    Process {
        $body = @{
            safeName                  = $safeName
            description               = $description
            location                  = $location
            managingCPM               = $managingCPM
            numberOfVersionsRetention = $numberOfVersionsRetention
            numberOfDaysRetention     = $numberOfDaysRetention
            AutoPurgeEnabled          = $AutoPurgeEnabled.IsPresent
            olacEnabled               = $olacEnabled.IsPresent
        }

        if ($PSCmdlet.ShouldProcess($safeName, 'New-Safe')) {
            Write-LogMessage -type Debug -MSG "Adding safe `"$safeName`""
            Try {
                $RestParms = @{
                    Uri    = $SafeURL
                    Method = 'POST'
                    Body   = ($body | ConvertTo-Json -Depth 99)
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                Invoke-Rest @RestParms -ErrAction SilentlyContinue
                Write-LogMessage -type Success -MSG "Added safe `"$safeName`" successfully"
            }
            Catch {
                If ($($PSItem.ErrorDetails.Message |ConvertFrom-Json).ErrorCode -eq "SFWS0002") {
                    IF ($UpdateOnDuplicate) {
                        Write-LogMessage -type Debug -MSG "Safe `"$safeName`" does not exist, creating instead"
                        $updateParams = @{
                            PVWAURL                  = $PVWAURL
                            LogonToken               = $LogonToken
                            safeName                 = $safeName
                            description              = $description
                            location                 = $location
                            olacEnabled              = $olacEnabled
                            managingCPM              = $managingCPM
                            numberOfVersionsRetention = $numberOfVersionsRetention
                            numberOfDaysRetention    = $numberOfDaysRetention
                            Confirm                  = $false
                        }
                        Set-Safe @updateParams
                    }
                    Else {
                        Write-LogMessage -type Success -MSG "Safe `"$safeName`" already exists, skipping creation"
                    }
                }
                else {
                    Write-LogMessage -type Failure -MSG "Failed to add safe `"$safeName`""
                    Write-LogMessage -type Error -MSG "Failed to add safe `"$safeName`" due to an error: $PSitem"
                    return
                }
            }
        }
        else {
            Write-LogMessage -type failure -MSG "Skipping creation of safe `"$safeName`" due to confirmation being denied"
        }
    }
}
#EndRegion '.\Public\PAS\Safe\Core\New-Safe.ps1' 153
#Region '.\Public\PAS\Safe\Core\Set-Safe.ps1' -1

<#
.SYNOPSIS
Updates the properties of an existing safe in the PVWA.

.DESCRIPTION
The Set-Safe function updates the properties of an existing safe in the PVWA (Password Vault Web Access).
It allows you to modify the safe's description, location, managing CPM, number of versions retention,
number of days retention, and OLAC (Object Level Access Control) status.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The authentication token required to log on to the PVWA.

.PARAMETER safeName
The name of the safe to be updated.

.PARAMETER description
The new description for the safe.

.PARAMETER location
The new location for the safe.

.PARAMETER olacEnabled
A switch parameter to enable or disable OLAC for the safe.

.PARAMETER managingCPM
The name of the CPM (Central Policy Manager) managing the safe.

.PARAMETER numberOfVersionsRetention
The number of versions to retain for the safe.

.PARAMETER numberOfDaysRetention
The number of days to retain the safe.

.EXAMPLE
Set-Safe -PVWAURL "https://pvwa.example.com" -LogonToken $token -safeName "FinanceSafe" -description "Updated description" -location "New York" -olacEnabled -managingCPM "CPM1" -numberOfVersionsRetention "5" -numberOfDaysRetention "30"

This example updates the safe named "FinanceSafe" with a new description, location, and other properties.

.NOTES
This function requires the PVWA URL and a valid logon token for authentication.
The function supports ShouldProcess for confirmation before making changes.
#>
function
Set-Safe {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (

        [Alias('url', 'PCloudURL')]
        [string] $PVWAURL,


        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string] $safeName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $location,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch] $olacEnabled,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $managingCPM,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $numberOfVersionsRetention,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $numberOfDaysRetention,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch] $CreateOnMissing
    )
    Begin {
        $SafeURL = "$PVWAURL/API/Safes/{0}/"
    }
    Process {
        $body = @{
            safeName                  = $safeName
            description               = $description
            location                  = $location
            managingCPM               = $managingCPM
            numberOfVersionsRetention = $numberOfVersionsRetention
            numberOfDaysRetention     = $numberOfDaysRetention
        }

        if ($olacEnabled) {
            $body.Add("olacEnabled", "true")
        }

        if ($PSCmdlet.ShouldProcess($safeName, 'Set-Safe')) {
            Write-LogMessage -type Debug -MSG "Updating safe `"$safeName`""
            Try {
                $RestParms = @{
                    Uri    = ($SafeURL -f $safeName)
                    Method = 'PUT'
                    Body   = ($body | ConvertTo-Json -Depth 99)
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                Invoke-Rest @RestParms -ErrAction SilentlyContinue
                Write-LogMessage -type Success -MSG "Updated safe `"$safeName`" successfully"
            }
            Catch {
                If (($PSItem.ErrorDetails.Message |ConvertFrom-Json).ErrorCode -eq 'SFWS0007') {
                    IF ($CreateOnMissing) {
                        Write-LogMessage -type Debug -MSG "Safe `"$safeName`" not found, creating instead"
                        New-Safe -PVWAURL $PVWAURL -LogonToken $LogonToken -safeName $safeName -description $description -location $location -olacEnabled:$olacEnabled -managingCPM $managingCPM -numberOfVersionsRetention $numberOfVersionsRetention -numberOfDaysRetention $numberOfDaysRetention -Confirm:$false
                    }
                    Else {
                        Write-LogMessage -type Failure -MSG "Failed to update safe `"$safeName`"due to not being found."
                        Write-LogMessage -type ErrorThrow -MSG "Safe `"$safeName`" not found."
                    }
                }
                else {
                    Write-LogMessage -type Failure -MSG "Failed to add safe `"$safeName`" due to an error."
                    Write-LogMessage -type Error -MSG "Failed to add safe `"$safeName`" due to an error: $PSitem"
                    return
                }
            }
        }
        else {
            Write-LogMessage -type Warning -MSG "Skipping update of safe `"$safeName`" due to confirmation being denied"
        }
    }
}
#EndRegion '.\Public\PAS\Safe\Core\Set-Safe.ps1' 136
#Region '.\Public\PAS\Safe\Import-Export\Export-Safe.ps1' -1

<#
.SYNOPSIS
Exports information about safes to a CSV file.

.DESCRIPTION
The Export-Safe function exports details about safes to a specified CSV file. It includes options to force overwrite the file, include account details, and include additional safe details. The function can also exclude system safes from the export.

.PARAMETER CSVPath
The path to the CSV file where the safe information will be exported. Default is ".\SafeExport.csv".

.PARAMETER Force
If specified, forces the overwrite of the existing CSV file.

.PARAMETER Safe
The safe object to be exported. This parameter is mandatory and accepts input from the pipeline.

.PARAMETER IncludeAccounts
If specified, includes account details in the export.

.PARAMETER IncludeDetails
If specified, includes additional details about the safe in the export.

.PARAMETER includeSystemSafes
If specified, includes system safes in the export. This parameter is hidden from the user.

.PARAMETER CPMUser
An array of CPM user names. This parameter is hidden from the user.

.EXAMPLE
Export-Safe -CSVPath "C:\Exports\SafeExport.csv" -Force -Safe $safe -IncludeAccounts -IncludeDetails

This example exports the details of the specified safe to "C:\Exports\SafeExport.csv", including account details and additional safe details, and forces the overwrite of the existing file.

.NOTES
The function logs messages at various stages of execution and handles errors gracefully. It exits with code 80 if the CSV file already exists and the Force switch is not specified.

#>

function Export-Safe {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string] $CSVPath = ".\SafeExport.csv",
        [switch] $Force,
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Safe] $Safe,
        [switch] $IncludeAccounts,
        [switch] $IncludeDetails,
        [Parameter(DontShow)]
        [switch] $includeSystemSafes,
        [Parameter(DontShow)]
        [string[]] $CPMUser
    )
    begin {
        [String[]]$SafesToRemove = @(
            'System', 'Pictures', 'VaultInternal', 'Notification Engine', 'SharedAuth_Internal', 'PVWAUserPrefs',
            'PVWAConfig', 'PVWAReports', 'PVWATaskDefinitions', 'PVWAPrivateUserPrefs', 'PVWAPublicData', 'PVWATicketingSystem',
            'AccountsFeed', 'PSM', 'xRay', 'PIMSuRecordings', 'xRay_Config', 'AccountsFeedADAccounts', 'AccountsFeedDiscoveryLogs',
            'PSMSessions', 'PSMLiveSessions', 'PSMUniversalConnectors', 'PSMNotifications', 'PSMUnmanagedSessionAccounts',
            'PSMRecordings', 'PSMPADBridgeConf', 'PSMPADBUserProfile', 'PSMPADBridgeCustom', 'PSMPConf', 'PSMPLiveSessions',
            'AppProviderConf', 'PasswordManagerTemp', 'PasswordManager_Pending', 'PasswordManagerShared', 'SCIM Config', 'TelemetryConfig'
        )
        [string[]]$cpmSafes = @()
        $CPMUser | ForEach-Object {
            $cpmSafes += "$($_)"
            $cpmSafes += "$($_)_Accounts"
            $cpmSafes += "$($_)_ADInternal"
            $cpmSafes += "$($_)_Info"
            $cpmSafes += "$($_)_workspace"
        }
        $SafesToRemove += $cpmSafes
        $SafeCount = 0
        if (Test-Path $CSVPath) {
            try {
                Write-LogMessage -type Debug -MSG "The file '$CSVPath' already exists. Checking for Force switch"
                if ($Force) {
                    Remove-Item $CSVPath
                    Write-LogMessage -type Debug -MSG "The file '$CSVPath' was removed."
                } else {
                    Write-LogMessage -type Debug -MSG "The file '$CSVPath' already exists and the switch 'Force' was not passed."
                    Write-LogMessage -type Error -MSG "The file '$CSVPath' already exists."
                }
            } catch {
                Write-LogMessage -type ErrorThrow -MSG "Error while trying to remove '$CSVPath'"
            }
        }
    }
    process {
        try {
            if (-not $includeSystemSafes) {
                if ($safe.SafeName -in $SafesToRemove) {
                    Write-LogMessage -type Debug -MSG "Safe '$($Safe.SafeName)' is a system safe, skipping"
                    return
                }
            }
            Write-LogMessage -type Verbose -MSG "Working with safe '$($Safe.Safename)'"
            $item = [pscustomobject]@{
                "Safe Name"        = $Safe.Safename
                "Description"      = $Safe.Description
                "Managing CPM"     = $Safe.managingCPM
                "Retention Policy" = $(if ([string]::IsNullOrEmpty($Safe.numberOfVersionsRetention)) { "$($Safe.numberOfDaysRetention) days" } else { "$($Safe.numberOfVersionsRetention) versions" })
                "Creation Date"    = ([datetime]'1/1/1970').ToLocalTime().AddSeconds($Safe.creationTime)
                "Last Modified"    = ([datetime]'1/1/1970').ToLocalTime().AddMicroseconds($Safe.lastModificationTime)
            }
            if ($IncludeDetails) {
                Write-LogMessage -type Debug -MSG "Including Details"
                $item | Add-Member -MemberType NoteProperty -Name "OLAC Enabled" -Value $safe.OLAC
                $item | Add-Member -MemberType NoteProperty -Name "Auto Purge Enabled" -Value $safe.autoPurgeEnabled
                $item | Add-Member -MemberType NoteProperty -Name "Safe ID" -Value $safe.safeNumber
                $item | Add-Member -MemberType NoteProperty -Name "Safe URL" -Value $safe.safeUrlId
                $item | Add-Member -MemberType NoteProperty -Name "Creator Name" -Value $Safe.Creator.Name
                $item | Add-Member -MemberType NoteProperty -Name "Creator ID" -Value $Safe.Creator.id
                $item | Add-Member -MemberType NoteProperty -Name "Location" -Value $safe.Location
                $item | Add-Member -MemberType NoteProperty -Name "Membership Expired" -Value $safe.isExpiredMember
            }
            if ($IncludeAccounts) {
                Write-LogMessage -type Debug -MSG "Including Accounts"
                $item | Add-Member -MemberType NoteProperty -Name "Accounts" -Value $($Safe.accounts.Name -join ", ")
            }
            Write-LogMessage -type Debug -MSG "Adding safe '$($Safe.Safename)' to CSV '$CSVPath'"
            $item | Export-Csv -Append $CSVPath -NoTypeInformation
            $SafeCount += 1
        } catch {
            Write-LogMessage -type Error -MSG $_
        }
    }
    end {
        Write-LogMessage -type Success -MSG "Exported $SafeCount safes successfully"
        Write-LogMessage -type Debug -MSG "Completed successfully"
    }
}
#EndRegion '.\Public\PAS\Safe\Import-Export\Export-Safe.ps1' 132
#Region '.\Public\PAS\SafeMember\Core\Add-SafeMember.ps1' -1

<#
.SYNOPSIS
    Adds a member to a specified safe in the PVWA.

.DESCRIPTION
    The Add-SafeMember function adds a member to a specified safe in the PVWA with various permissions.
    This function supports ShouldProcess for safety and confirmation prompts.

.PARAMETER PVWAURL
    The URL of the PVWA instance.

.PARAMETER LogonToken
    The logon token for authentication.

.PARAMETER SafeName
    The name of the safe to which the member will be added.

.PARAMETER memberName
    The name of the member to be added to the safe.

.PARAMETER searchIn
    The search scope for the member.

.PARAMETER MemberType
    The type of the member (User, Group, Role).

.PARAMETER membershipExpirationDate
    The expiration date of the membership.

.PARAMETER useAccounts
    Permission to use accounts.

.PARAMETER retrieveAccounts
    Permission to retrieve accounts.

.PARAMETER listAccounts
    Permission to list accounts.

.PARAMETER addAccounts
    Permission to add accounts.

.PARAMETER updateAccountContent
    Permission to update account content.

.PARAMETER updateAccountProperties
    Permission to update account properties.

.PARAMETER initiateCPMAccountManagementOperations
    Permission to initiate CPM account management operations.

.PARAMETER specifyNextAccountContent
    Permission to specify next account content.

.PARAMETER renameAccounts
    Permission to rename accounts.

.PARAMETER deleteAccounts
    Permission to delete accounts.

.PARAMETER unlockAccounts
    Permission to unlock accounts.

.PARAMETER manageSafe
    Permission to manage the safe.

.PARAMETER manageSafeMembers
    Permission to manage safe members.

.PARAMETER backupSafe
    Permission to backup the safe.

.PARAMETER viewAuditLog
    Permission to view the audit log.

.PARAMETER viewSafeMembers
    Permission to view safe members.

.PARAMETER accessWithoutConfirmation
    Permission to access without confirmation.

.PARAMETER createFolders
    Permission to create folders.

.PARAMETER deleteFolders
    Permission to delete folders.

.PARAMETER moveAccountsAndFolders
    Permission to move accounts and folders.

.PARAMETER requestsAuthorizationLevel1
    Permission for requests authorization level 1.

.PARAMETER requestsAuthorizationLevel2
    Permission for requests authorization level 2.

.EXAMPLE
    Add-SafeMember -PVWAURL "https://pvwa.example.com" -LogonToken $token -SafeName "Finance" -memberName "JohnDoe" -MemberType "User" -useAccounts $true

.NOTES
    This function requires the PVWA URL and a valid logon token for authentication.
#>

function Add-SafeMember {
    [CmdletBinding(DefaultParameterSetName = 'memberName', SupportsShouldProcess, ConfirmImpact = 'High')]
    param (

        [Alias('url', 'PCloudURL')]
        [string] $PVWAURL,


        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'memberName')]
        [Alias('Safe')]
        [string] $SafeName,

        [Parameter(ParameterSetName = 'memberObject', Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('SafeMember')]
        [string] $memberObject,

        [Parameter(ParameterSetName = 'memberName', Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('User')]
        [string] $memberName,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [string] $searchIn,

        [ValidateSet('User', 'Group', 'Role')]
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [string] $MemberType,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [AllowNull()]
        [int] $membershipExpirationDate,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $useAccounts,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $retrieveAccounts,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $listAccounts,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $addAccounts,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $updateAccountContent,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $updateAccountProperties,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $initiateCPMAccountManagementOperations,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $specifyNextAccountContent,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $renameAccounts,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $deleteAccounts,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $unlockAccounts,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $manageSafe,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $manageSafeMembers,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $backupSafe,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $viewAuditLog,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $viewSafeMembers,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $accessWithoutConfirmation,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $createFolders,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $deleteFolders,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $moveAccountsAndFolders,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $requestsAuthorizationLevel1,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $requestsAuthorizationLevel2,

        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName, DontShow)]
        [SafePerms] $permissions,

        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]$UpdateOnDuplicate
    )

    begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null

    }

    process {
        if ($PsCmdlet.ParameterSetName -eq 'memberName') {
            $SafeMemberURL = "$PVWAURL/API/Safes/$SafeName/Members/"
            if ( -not [string]::IsNullOrEmpty($permissions)) {
                $permissions = [SafePerms]$permissions
                $out = $permissions | Select-Object -Property useAccounts, retrieveAccounts, listAccounts, addAccounts, updateAccountContent, updateAccountProperties, initiateCPMAccountManagementOperations, specifyNextAccountContent, renameAccounts, deleteAccounts, unlockAccounts, manageSafe, manageSafeMembers, backupSafe, viewAuditLog, viewSafeMembers, accessWithoutConfirmation, createFolders, deleteFolders, moveAccountsAndFolders, requestsAuthorizationLevel1, requestsAuthorizationLevel2
            }
            else {
                $permissions = [SafePerms]@{
                    useAccounts                            = $useAccounts
                    retrieveAccounts                       = $retrieveAccounts
                    listAccounts                           = $listAccounts
                    addAccounts                            = $addAccounts
                    updateAccountContent                   = $updateAccountContent
                    updateAccountProperties                = $updateAccountProperties
                    initiateCPMAccountManagementOperations = $initiateCPMAccountManagementOperations
                    specifyNextAccountContent              = $specifyNextAccountContent
                    renameAccounts                         = $renameAccounts
                    deleteAccounts                         = $deleteAccounts
                    unlockAccounts                         = $unlockAccounts
                    manageSafe                             = $manageSafe
                    manageSafeMembers                      = $manageSafeMembers
                    backupSafe                             = $backupSafe
                    viewAuditLog                           = $viewAuditLog
                    viewSafeMembers                        = $viewSafeMembers
                    accessWithoutConfirmation              = $accessWithoutConfirmation
                    createFolders                          = $createFolders
                    deleteFolders                          = $deleteFolders
                    moveAccountsAndFolders                 = $moveAccountsAndFolders
                    requestsAuthorizationLevel1            = $requestsAuthorizationLevel1
                    requestsAuthorizationLevel2            = $requestsAuthorizationLevel2
                }
            }

            $body = [SafeMember]@{
                memberName               = $memberName
                searchIn                 = $searchIn
                membershipExpirationDate = $membershipExpirationDate
                MemberType               = $MemberType
                Permissions              = $permissions
            }
        }
        elseif ($PsCmdlet.ParameterSetName -eq 'memberObject') {
            $SafeMemberURL = "$PVWAURL/API/Safes/$($memberObject.SafeName)/Members/"
            $memberName = $memberObject.memberName
            $body = $memberObject | Select-Object -Property memberName, searchIn, membershipExpirationDate, MemberType, Permissions
        }

        if ($PSCmdlet.ShouldProcess($memberName, 'Add-SafeMember')) {
            try {
                Write-LogMessage -type Verbose -MSG "Adding owner `"$memberName`" to safe `"$SafeName`""
                $RestParms = @{
                    Uri    = $SafeMemberURL
                    Method = 'POST'
                    Body   = ($body | ConvertTo-Json -Depth 99)
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                Invoke-Rest @RestParms -ErrAction SilentlyContinue
                Write-LogMessage -type Success -MSG "Added owner `"$memberName`" to safe `"$SafeName`" successfully"
            }
            catch {
                if ($PSItem.ErrorDetails.Message -is [string]) {
                    $details = $PSItem.ErrorDetails.Message | ConvertFrom-Json
                }
                else {
                    Write-LogMessage -type Error -MSG "Failed to add Owner `"$memberName`" on `"$SafeName`" due to an error."
                    return
                }
                if ($details.ErrorCode -eq 'SFWS0012') {
                    if ($UpdateOnDuplicate) {
                        Write-LogMessage -type Verbose -MSG "Owner `"$memberName`" on `"$SafeName`" already exist, updating instead"
                        if ( -not [string]::IsNullOrEmpty($permissions)) {
                            $SetParams = @{
                                LogonToken               = $LogonToken
                                SafeName                 = $SafeName
                                memberName               = $memberName
                                MemberType               = $MemberType
                                searchIn                 = $searchIn
                                membershipExpirationDate = $membershipExpirationDate
                                permissions              = [SafePerms]$permissions
                            }
                        }
                        else {
                            $SetParams = @{

                                useAccounts                            = $useAccounts
                                retrieveAccounts                       = $retrieveAccounts
                                listAccounts                           = $listAccounts
                                addAccounts                            = $addAccounts
                                updateAccountContent                   = $updateAccountContent
                                updateAccountProperties                = $updateAccountProperties
                                initiateCPMAccountManagementOperations = $initiateCPMAccountManagementOperations
                                specifyNextAccountContent              = $specifyNextAccountContent
                                renameAccounts                         = $renameAccounts
                                deleteAccounts                         = $deleteAccounts
                                unlockAccounts                         = $unlockAccounts
                                manageSafe                             = $manageSafe
                                manageSafeMembers                      = $manageSafeMembers
                                backupSafe                             = $backupSafe
                                viewAuditLog                           = $viewAuditLog
                                viewSafeMembers                        = $viewSafeMembers
                                accessWithoutConfirmation              = $accessWithoutConfirmation
                                createFolders                          = $createFolders
                                deleteFolders                          = $deleteFolders
                                moveAccountsAndFolders                 = $moveAccountsAndFolders
                                requestsAuthorizationLevel1            = $requestsAuthorizationLevel1
                                requestsAuthorizationLevel2            = $requestsAuthorizationLevel2
                            }
                        }
                        Set-SafeMember @SetParams
                    }
                    else {
                        Write-LogMessage -type Warning -MSG "Owner `"$memberName`" on `"$SafeName`"  already exists, skipping creation"
                    }
                }
                if ($details.ErrorCode -eq 'SFWS0001') {
                    Write-LogMessage -type Error -MSG "Failed to add Owner `"$memberName`" on `"$SafeName`" due to an type being set to Group, updating to Role and trying again."
                    $body.MemberType = 'Role'
                    try {
                        $RestParms = @{
                            Uri    = $SafeMemberURL
                            Method = 'POST'
                            Body   = ($body | ConvertTo-Json -Depth 99)
                        }
                        if ($null -ne $LogonToken -and $LogonToken -ne "") {
                            $RestParms.LogonToken = $LogonToken
                        }
                        Invoke-Rest @RestParms -ErrAction SilentlyContinue
                    }
                    catch {
                        Write-LogMessage -type Error -MSG "Failed to add Owner `"$memberName`" on `"$SafeName`" due to an error: $PSitem"
                        return
                    }
                    Write-LogMessage -type Success -MSG "Added owner `"$memberName`" to safe `"$SafeName`" successfully"
                }
                else {
                        Write-LogMessage -type Error -MSG "Failed to add Owner `"$memberName`" on `"$SafeName`" due to an error: $PSitem"
                        return
                    }
                }
            }
            else {
                Write-LogMessage -type Warning -MSG "Skipping addition of owner `"$memberName`" to safe `"$SafeName`""
            }
        }
    }
#EndRegion '.\Public\PAS\SafeMember\Core\Add-SafeMember.ps1' 363
#Region '.\Public\PAS\SafeMember\Core\Get-SafeMember.ps1' -1

<#
.SYNOPSIS
    Retrieves safe member information from the PVWA API.

.DESCRIPTION
    The Get-SafeMember function retrieves information about members of a specified safe from the PVWA API.
    It supports various parameter sets to filter and search for specific members or member types.

.PARAMETER PVWAURL
    The URL of the PVWA instance.

.PARAMETER LogonToken
    The logon token for authenticating with the PVWA API.

.PARAMETER SafeName
    The name of the safe to retrieve members from.

.PARAMETER memberName
    The name of the member to retrieve information for. This parameter is mandatory when using the 'memberName' parameter set.

.PARAMETER useCache
    A switch to indicate whether to use cached data. This parameter is only valid with the 'memberName' parameter set.

.PARAMETER Search
    A search string to filter members by name. This parameter is only valid with the 'Search' parameter set.

.PARAMETER memberType
    The type of member to filter by. Valid values are "User" and "Group". This parameter is only valid with the 'Search' parameter set.

.PARAMETER membershipExpired
    A filter to include only members with expired memberships. Valid values are "True" and "False". This parameter is only valid with the 'Search' parameter set.

.PARAMETER includePredefinedUsers
    A filter to include predefined users. Valid values are "True" and "False". This parameter is only valid with the 'Search' parameter set.

.PARAMETER offset
    The offset for pagination. This parameter is only valid with the 'Search' parameter set.

.PARAMETER limit
    The limit for pagination. This parameter is only valid with the 'Search' parameter set.

.PARAMETER DoNotPage
    A switch to disable pagination. This parameter is only valid with the 'Search' parameter set.

.PARAMETER sort
    The sort order for the results. Valid values are "asc" and "desc". This parameter is only valid with the 'Search' parameter set.

.PARAMETER permissions
    A switch to include permissions in the output.

.EXAMPLE
    Get-SafeMember -PVWAURL "https://pvwa.example.com" -LogonToken $token -SafeName "Finance"

    Retrieves all members of the "Finance" safe.

.EXAMPLE
    Get-SafeMember -PVWAURL "https://pvwa.example.com" -LogonToken $token -SafeName "Finance" -memberName "JohnDoe"

    Retrieves information about the member "JohnDoe" in the "Finance" safe.
#>

function Get-SafeMember {
    [CmdletBinding(DefaultParameterSetName = "SafeName")]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [string]
        $PVWAURL,

        [Alias('header')]
        $LogonToken,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Safe')]
        [string]
        $SafeName,
        [Parameter(Mandatory, ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [Alias('User')]
        [string]
        $memberName,
        [Parameter(ParameterSetName = 'memberName')]
        [switch]
        $useCache,
        [Parameter(ParameterSetName = 'Search', ValueFromPipelineByPropertyName)]
        [string]
        $Search,
        [Parameter(ParameterSetName = 'Search')]
        [ValidateSet("User", "Group")]
        [string]
        $memberType,
        [Parameter(ParameterSetName = 'Search')]
        [ValidateSet("True", "False")]
        [string]
        $membershipExpired,
        [Parameter(ParameterSetName = 'Search')]
        [ValidateSet("True", "False")]
        [string]
        $includePredefinedUsers,
        [Parameter(ParameterSetName = 'Search')]
        [Nullable[int]]
        $offset = $null,
        [Parameter(ParameterSetName = 'Search')]
        [Nullable[int]]
        $limit,
        [Parameter(ParameterSetName = 'Search')]
        [switch]
        $DoNotPage,
        [Parameter(ParameterSetName = 'Search')]
        [AllowEmptyString]
        [ValidateSet("asc", "desc")]
        $sort,
        [switch]
        $permissions
    )
    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }
    Process {
        if ([string]::IsNullOrEmpty($SafeName)) {
            Write-LogMessage -type Error -MSG "No Safe Name provided"
            return
        }

        if (-not [string]::IsNullOrEmpty($memberName)) {
            $SafeMemberURL = "$PVWAURL/API/Safes/$SafeName/Members/$memberName/"
            Write-LogMessage -type Verbose -MSG "Getting memberName permissions for safe $SafeName"
            $RestParms = @{
                Uri    = $SafeMemberURL
                Method = 'GET'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            return Invoke-Rest @RestParms
        }
        else {
            $SafeMemberURL = "$PVWAURL/API/Safes/$SafeName/Members/?"
            Write-LogMessage -type Verbose -MSG "Getting owners permissions for safe $SafeName"
            $filterList = @()

            if (-not [string]::IsNullOrEmpty($memberType)) {
                $filterList += "memberType eq $memberType"
            }
            if (-not [string]::IsNullOrEmpty($membershipExpired)) {
                $filterList += "membershipExpired eq $membershipExpired"
            }
            if (-not [string]::IsNullOrEmpty($includePredefinedUsers)) {
                $filterList += "includePredefinedUsers eq $includePredefinedUsers"
            }
            if ($filterList.Count -gt 0) {
                $filter = $filterList -join " AND "
                $SafeMemberURL += "filter=$filter"
                Write-LogMessage -type Verbose -MSG "Applying a filter of $filter"
            }
            if (-not [string]::IsNullOrEmpty($Search)) {
                $SafeMemberURL += "&search=$Search"
                Write-LogMessage -type Verbose -MSG "Applying a search of $Search"
            }
            if (-not [string]::IsNullOrEmpty($offset)) {
                $SafeMemberURL += "&offset=$offset"
                Write-LogMessage -type Verbose -MSG "Applying an offset of $offset"
            }
            if (-not [string]::IsNullOrEmpty($limit)) {
                $SafeMemberURL += "&limit=$limit"
                Write-LogMessage -type Verbose -MSG "Applying a limit of $limit"
            }
            if (-not [string]::IsNullOrEmpty($sort)) {
                $SafeMemberURL += "&sort=$sort"
                Write-LogMessage -type Verbose -MSG "Applying a sort of $sort"
            }
            if ($DoNotPage) {
                Write-LogMessage -type Verbose -MSG "Paging is disabled."
            }

            $RestParms = @{
                Uri    = $SafeMemberURL
                Method = 'GET'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $restResponse = Invoke-Rest @RestParms
            [SafeMember[]]$memberList = $restResponse.value

            if (-not [string]::IsNullOrEmpty($restResponse.NextLink)) {
                if ($DoNotPage) {
                    Write-LogMessage -type Verbose -MSG "A total of $($memberList.Count) members found, but paging is disabled. Returning only $($memberList.Count) members"
                }
                else {
                    do {
                        Write-LogMessage -type Verbose -MSG "NextLink found, getting next page"
                        $RestParms = @{
                            Uri    = "$PVWAURL/$($restResponse.NextLink)"
                            Method = 'GET'
                        }
                        if ($null -ne $LogonToken -and $LogonToken -ne "") {
                            $RestParms.LogonToken = $LogonToken
                        }
                        $restResponse = Invoke-Rest @RestParms
                        $memberList += $restResponse.value
                    } until ([string]::IsNullOrEmpty($restResponse.NextLink))
                }
            }
            else {
                Write-LogMessage -type Verbose -MSG "Found $($memberList.Count) members"
            }

            return [SafeMember[]]$memberList
        }
    }
}
#EndRegion '.\Public\PAS\SafeMember\Core\Get-SafeMember.ps1' 213
#Region '.\Public\PAS\SafeMember\Core\Remove-SafeMember.ps1' -1

<#
.SYNOPSIS
Removes a member from a specified safe in the PVW        if ($PSCmdlet.ShouldProcess($memberName, 'Remove-SafeMember')) {
            Write-LogMessage -type Verbose -MSG "Removing member `$memberName` from safe `$SafeName`"
            $RestParms = @{
                Uri    = $SafeMemberURL
                Method = 'DELETE'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            Invoke-Rest @RestParms

.DESCRIPTION
The Remove-SafeMember function removes a specified member from a safe in the PVWA (Privileged Vault Web Access).
It supports confirmation prompts and logging of actions.

.PARAMETER PVWAURL
The URL of the PVWA instance.

.PARAMETER LogonToken
The logon token used for authentication.

.PARAMETER SafeName
The name of the safe from which the member will be removed.

.PARAMETER memberName
The name of the member to be removed from the safe.

.EXAMPLE
Remove-SafeMember -PVWAURL "https://pvwa.example.com" -LogonToken $token -SafeName "FinanceSafe" -memberName "JohnDoe"

This command removes the member "JohnDoe" from the safe "FinanceSafe" in the specified PVWA instance.

.NOTES
- This function supports ShouldProcess for safety.
- The ConfirmImpact is set to High, so confirmation is required by default.
- The function logs actions and warnings using Write-LogMessage.
#>
function Remove-SafeMember {
    [CmdletBinding(
        SupportsShouldProcess,
        ConfirmImpact = 'High'
    )]
    param (

        [Alias('url', 'PCloudURL')]
        [string]
        $PVWAURL,

        [Alias('header')]
        $LogonToken,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Safe')]
        [string]
        $SafeName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('User')]
        [string]
        $memberName
    )

    begin {
        if ($Force -and -not $Confirm) {
            Write-LogMessage -type Warning -MSG 'Confirmation prompt suppressed, proceeding with all removals'
            $ConfirmPreference = 'None'
        }
    }

    process {
        $SafeMemberURL = "$PVWAURL/API/Safes/$SafeName/Members/$memberName/"
        if ($PSCmdlet.ShouldProcess($memberName, 'Remove-SafeMember')) {
            Write-LogMessage -type Verbose -MSG "Removing member `"$memberName`" from safe `"$SafeName`""
            $RestParms = @{
                Uri    = $SafeMemberURL
                Method = 'DELETE'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            Invoke-Rest @RestParms
        } else {
            Write-LogMessage -type Warning -MSG "Skipping removal of member `$memberName` from safe `$SafeName` due to confirmation being denied"
        }
    }
}
#EndRegion '.\Public\PAS\SafeMember\Core\Remove-SafeMember.ps1' 89
#Region '.\Public\PAS\SafeMember\Core\Set-SafeMember.ps1' -1

#TODO Run Co-Pilot doc generator
function Set-SafeMember {
    [CmdletBinding(DefaultParameterSetName = 'memberName', SupportsShouldProcess, ConfirmImpact = 'High')]
    param (

        [Alias('url', 'PCloudURL')]
        [string] $PVWAURL,
        [Alias('header')]
        $LogonToken,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Safe')]
        [string] $SafeName,
        [Parameter(ParameterSetName = 'memberObject', Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('SafeMember')]
        [string] $memberObject,
        [Parameter(ParameterSetName = 'memberName', Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('User')]
        [string] $memberName,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [string] $searchIn,
        [ValidateSet('User', 'Group', 'Role')]
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [string] $MemberType,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [AllowNull()]
        [int] $membershipExpirationDate,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $useAccounts,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $retrieveAccounts,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $listAccounts,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $addAccounts,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $updateAccountContent,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $updateAccountProperties,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $initiateCPMAccountManagementOperations,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $specifyNextAccountContent,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $renameAccounts,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $deleteAccounts,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $unlockAccounts,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $manageSafe,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $manageSafeMembers,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $backupSafe,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $viewAuditLog,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $viewSafeMembers,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $accessWithoutConfirmation,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $createFolders,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $deleteFolders,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $moveAccountsAndFolders,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $requestsAuthorizationLevel1,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName)]
        [bool] $requestsAuthorizationLevel2,
        [Parameter(ParameterSetName = 'memberName', ValueFromPipelineByPropertyName, DontShow)]
        [SafePerms] $permissions,
        [Parameter(ValueFromPipelineByPropertyName)]
        [switch]$CreateOnMissing

    )
    begin {
        $SafeMemberURL = "$PVWAURL/API/Safes/$SafeName/Members/{0}/"
    }
    process {
        if ($PsCmdlet.ParameterSetName -eq 'memberName') {
            if ( -not [string]::IsNullOrEmpty($permissions)) {
                $permissions = [SafePerms]$permissions
            }
            else {
                $permissions = [SafePerms]@{
                    useAccounts                            = $useAccounts
                    retrieveAccounts                       = $retrieveAccounts
                    listAccounts                           = $listAccounts
                    addAccounts                            = $addAccounts
                    updateAccountContent                   = $updateAccountContent
                    updateAccountProperties                = $updateAccountProperties
                    initiateCPMAccountManagementOperations = $initiateCPMAccountManagementOperations
                    specifyNextAccountContent              = $specifyNextAccountContent
                    renameAccounts                         = $renameAccounts
                    deleteAccounts                         = $deleteAccounts
                    unlockAccounts                         = $unlockAccounts
                    manageSafe                             = $manageSafe
                    manageSafeMembers                      = $manageSafeMembers
                    backupSafe                             = $backupSafe
                    viewAuditLog                           = $viewAuditLog
                    viewSafeMembers                        = $viewSafeMembers
                    accessWithoutConfirmation              = $accessWithoutConfirmation
                    createFolders                          = $createFolders
                    deleteFolders                          = $deleteFolders
                    moveAccountsAndFolders                 = $moveAccountsAndFolders
                    requestsAuthorizationLevel1            = $requestsAuthorizationLevel1
                    requestsAuthorizationLevel2            = $requestsAuthorizationLevel2
                }
            }
            $body = [SafeMember]@{
                memberName               = $memberName
                searchIn                 = $searchIn
                membershipExpirationDate = $membershipExpirationDate
                MemberType               = $MemberType
                Permissions              = $permissions
            }
        }
        elseif ($PsCmdlet.ParameterSetName -eq 'memberObject') {
            $memberName = $memberObject.memberName
            $body = $memberObject
        }
        if ($PSCmdlet.ShouldProcess($memberName, 'Set-SafeMember')) {
            try {
                Write-LogMessage -type Verbose -MSG "Updating owner `"$memberName`" to safe `"$SafeName`""
                $URL = $SafeMemberURL -f $memberName
                $RestParms = @{
                    Uri    = $URL
                    Method = 'PUT'
                    Body   = ($body | ConvertTo-Json -Depth 99)
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                Invoke-Rest @RestParms
                Write-LogMessage -type Success -MSG "Updated owner `"$memberName`" on safe `"$SafeName`" successfully"
            }
            catch {
                if ($($PSItem.ErrorDetails.Message | ConvertFrom-Json).ErrorCode -eq 'SFWS0012') {
                    if ($CreateOnMissing) {
                        Write-LogMessage -type Verbose -MSG "Owner `"$memberName`" on `"$SafeName`" doesn't exist, adding instead"
                        $splatParams = @{
                            PVWAURL                                = $PVWAURL
                            LogonToken                             = $LogonToken
                            SafeName                               = $SafeName
                            memberName                             = $memberName
                            memberType                             = $MemberType
                            membershipExpirationDate               = $membershipExpirationDate
                            useAccounts                            = $useAccounts
                            retrieveAccounts                       = $retrieveAccounts
                            listAccounts                           = $listAccounts
                            addAccounts                            = $addAccounts
                            updateAccountContent                   = $updateAccountContent
                            updateAccountProperties                = $updateAccountProperties
                            initiateCPMAccountManagementOperations = $initiateCPMAccountManagementOperations
                            specifyNextAccountContent              = $specifyNextAccountContent
                            renameAccounts                         = $renameAccounts
                            deleteAccounts                         = $deleteAccounts
                            unlockAccounts                         = $unlockAccounts
                            manageSafe                             = $manageSafe
                            manageSafeMembers                      = $manageSafeMembers
                            backupSafe                             = $backupSafe
                            viewAuditLog                           = $viewAuditLog
                            viewSafeMembers                        = $viewSafeMembers
                            accessWithoutConfirmation              = $accessWithoutConfirmation
                            createFolders                          = $createFolders
                            deleteFolders                          = $deleteFolders
                            moveAccountsAndFolders                 = $moveAccountsAndFolders
                            requestsAuthorizationLevel1            = $requestsAuthorizationLevel1
                            requestsAuthorizationLevel2            = $requestsAuthorizationLevel2
                        }
                        Add-SafeMember @splatParams
                    }
                    else {
                        Write-LogMessage -type Warning -MSG "Owner `"$memberName`" on `"$SafeName`" does not exist, unable to set"
                    }
                }
                elseif ($($PSItem.ErrorDetails.Message | ConvertFrom-Json).ErrorCode -eq 'SFWS0015') {
                    Write-LogMessage -type Error -MSG "Failed to update Owner `"$memberName`" on `"$SafeName`" due to an error: $($($PSItem.ErrorDetails.Message | ConvertFrom-Json).ErrorMessage)"
                    return
                }

                else {
                    Write-LogMessage -type Error -MSG "Failed to update Owner `"$memberName`" on `"$SafeName`" due to an error: $PSitem"
                    return
                }
            }
        }
        else {
            Write-LogMessage -type Warning -MSG "Skipping update of owner `"$memberName`" to safe `"$SafeName`""
        }
    }
}
#EndRegion '.\Public\PAS\SafeMember\Core\Set-SafeMember.ps1' 194
#Region '.\Public\PAS\SafeMember\Import-Export\Export-SafeMember.ps1' -1

<#
.SYNOPSIS
Exports safe member information to a CSV file.

.DESCRIPTION
The Export-SafeMember function exports information about safe members to a specified CSV file.
It allows filtering out system safes and includes options to force overwrite the CSV file if it already exists.

.PARAMETER CSVPath
Specifies the path to the CSV file where the safe member information will be exported.
Defaults to ".\SafeMemberExport.csv".

.PARAMETER Force
If specified, forces the overwrite of the CSV file if it already exists.

.PARAMETER SafeMember
Specifies the safe member object to be exported. This parameter is mandatory and accepts input from the pipeline.

.PARAMETER includeSystemSafes
If specified, includes system safes in the export. This parameter is hidden from the help documentation.

.PARAMETER CPMUser
Specifies an array of CPM user names. This parameter is hidden from the help documentation.

.EXAMPLE
Export-SafeMember -CSVPath "C:\Exports\SafeMembers.csv" -SafeMember $safeMember

This example exports the safe member information to "C:\Exports\SafeMembers.csv".

.EXAMPLE
$safeMembers | Export-SafeMember -CSVPath "C:\Exports\SafeMembers.csv" -Force

This example exports the safe member information from the pipeline to "C:\Exports\SafeMembers.csv",
forcing the overwrite of the file if it already exists.

.NOTES
The function logs verbose messages about its operations and handles errors gracefully.
#>
function Export-SafeMember {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $CSVPath = '.\SafeMemberExport.csv',
        [switch]
        $Force,
        [switch]
        $Append,
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [SafeMember]
        $SafeMember,
        #TODO Add ability to drop system users
        [Parameter(DontShow)]
        [switch]
        $includeSystemSafes,

        [Parameter(DontShow)]
        [string[]]
        $CPMUser
    )
    begin {
        [String[]]$SafesToRemove = @('System', 'Pictures', 'VaultInternal', 'Notification Engine', 'SharedAuth_Internal', 'PVWAUserPrefs',
            'PVWAConfig', 'PVWAReports', 'PVWATaskDefinitions', 'PVWAPrivateUserPrefs', 'PVWAPublicData', 'PVWATicketingSystem',
            'AccountsFeed', 'PSM', 'xRay', 'PIMSuRecordings', 'xRay_Config', 'AccountsFeedADAccounts', 'AccountsFeedDiscoveryLogs', 'PSMSessions', 'PSMLiveSessions', 'PSMUniversalConnectors',
            'PSMNotifications', 'PSMUnmanagedSessionAccounts', 'PSMRecordings', 'PSMPADBridgeConf', 'PSMPADBUserProfile', 'PSMPADBridgeCustom', 'PSMPConf', 'PSMPLiveSessions'
            'AppProviderConf', 'PasswordManagerTemp', 'PasswordManager_Pending', 'PasswordManagerShared', 'SCIM Config', 'TelemetryConfig')
        [string[]]$cpmSafes = @()
        $CPMUser | ForEach-Object {
            $cpmSafes += "$($PSitem)"
            $cpmSafes += "$($PSitem)_Accounts"
            $cpmSafes += "$($PSitem)_ADInternal"
            $cpmSafes += "$($PSitem)_Info"
            $cpmSafes += "$($PSitem)_workspace"
        }
        $SafesToRemove += $cpmSafes
        $SafeMemberCount = 0
        if (Test-Path $CSVPath) {
            try {
                Write-LogMessage -type Verbose -MSG "The file `'$CSVPath`' already exists. Checking for Force switch"
                if ($Append) {
                    Write-LogMessage -type Verbose -MSG "Append switch passed, using file `'$CSVPath`'."
                }
                elseif ($Force) {
                    Remove-Item $CSVPath
                    Write-LogMessage -type Verbose -MSG "The file `'$CSVPath`' was removed."
                }
                else {
                    Write-LogMessage -type Verbose -MSG "The file `'$CSVPath`' already exists and the switch `"Force`" was not passed."
                    Write-LogMessage -type Error -MSG "The file `'$CSVPath`' already exists."
                    exit 80
                }
            }
            catch {
                Write-LogMessage -type ErrorThrow -MSG "Error while trying to remove`'$CSVPath`'"
            }
        }
    }
    process {

        try {
            if (-not $includeSystemSafes) {
                if ($PSitem.SafeName -in $SafesToRemove) {
                    Write-LogMessage -type Verbose -MSG "Safe `"$($PSitem.SafeName)`" is a system safe, skipping"
                    return
                }
            }
            Write-LogMessage -type Verbose -MSG "Working with safe `"$($PSitem.Safename)`" and safe member `"$($PSitem.memberName)`""
            if ($PSitem.memberType -eq 'User') {
                $memberType = 'User'
            }
            elseif ($PSitem.memberType -eq 'Group' -and $PSitem.memberName -match '.*@.*') {
                $memberType = 'Group'
            }
            else {
                $memberType = 'Role'
            }
            $item = [pscustomobject]@{
                'Safe Name'                                  = $PSitem.safeName
                'Member Name'                                = $PSitem.memberName
                'Member Type'                                = $memberType
                'List Accounts'                              = $PSitem.Permissions.listAccounts
                'Use Accounts'                               = $PSitem.Permissions.useAccounts
                'Retrieve Accounts'                          = $PSitem.Permissions.retrieveAccounts
                'Add Accounts'                               = $PSitem.Permissions.addAccounts
                'Update Account Properties'                  = $PSitem.Permissions.updateAccountProperties
                'Update Account Content'                     = $PSitem.Permissions.updateAccountContent
                'Initiate CPM Account Management Operations' = $PSitem.Permissions.initiateCPMAccountManagementOperations
                'Specify Next Account Content'               = $PSitem.Permissions.specifyNextAccountContent
                'Rename Account'                             = $PSitem.Permissions.renameAccounts
                'Delete Account'                             = $PSitem.Permissions.deleteAccounts
                'Unlock Account'                             = $PSitem.Permissions.unlockAccounts
                'Manage Safe'                                = $PSitem.Permissions.manageSafe
                'View Safe Members'                          = $PSitem.Permissions.viewSafeMembers
                'Manage Safe Members'                        = $PSitem.Permissions.manageSafeMembers
                'View Audit Log'                             = $PSitem.Permissions.viewAuditLog
                'Backup Safe'                                = $PSitem.Permissions.backupSafe
                'Level 1 Confirmer'                          = $PSitem.Permissions.requestsAuthorizationLevel1
                'Level 2 Confirmer'                          = $PSitem.Permissions.requestsAuthorizationLevel2
                'Access Safe Without Confirmation'           = $PSitem.Permissions.accessWithoutConfirmation
                'Move Accounts / Folders'                    = $PSitem.Permissions.moveAccountsAndFolders
                'Create Folders'                             = $PSitem.Permissions.createFolders
                'Delete Folders'                             = $PSitem.Permissions.deleteFolders

            }

            Write-LogMessage -type Verbose -MSG "Adding safe `"$($PSitem.Safename)`" and safe member `"$($PSitem.memberName)`" to CSV `"$CSVPath`""
            $item | Export-Csv -Append $CSVPath
            $SafeMemberCount += 1
        }
        catch {
            Write-LogMessage -type Error -MSG $PSitem
        }
    }
    end {
        Write-LogMessage -type Success -MSG "Exported $SafeMemberCount safe members successfully"
        Write-LogMessage -type Verbose -MSG 'Completed successfully'
    }
}
#EndRegion '.\Public\PAS\SafeMember\Import-Export\Export-SafeMember.ps1' 159
#Region '.\Public\PAS\SafeMember\Import-Export\Import-SafeMember.ps1' -1

<#
.SYNOPSIS
Imports safe member information from a CSV file.

.DESCRIPTION
The Import-SafeMember function reads safe member information from a specified CSV file and outputs SafeMember objects.

.PARAMETER CSVPath
Specifies the path to the CSV file to import. Defaults to ".\SafeMemberExport.csv".

.EXAMPLE
Import-SafeMember -CSVPath "C:\Exports\SafeMembers.csv"

.NOTES
Adjust property mapping as needed to match your SafeMember class.
#>
function Import-SafeMember {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $CSVPath = ".\SafeMemberExport.csv"
    )
    begin {
        if (-not (Test-Path $CSVPath)) {
            Write-Error "CSV file '$CSVPath' does not exist."
            return
        }
    }
    process {
        $csv = Import-Csv -Path $CSVPath
        foreach ($row in $csv) {
            # Map CSV columns to SafeMember properties as needed
            $safeMember = [SafeMember]::new()
            $safeMember.SafeName   = $row.'Safe Name'
            $safeMember.MemberName = $row.'Member Name'
            $safeMember.MemberType = $row.'Member Type'
            # Map permissions if your SafeMember class supports them
            if ($safeMember.Permissions) {
                $safeMember.Permissions.listAccounts                              = [System.Convert]::ToBoolean($row.'List Accounts')
                $safeMember.Permissions.useAccounts                               = [System.Convert]::ToBoolean($row.'Use Accounts')
                $safeMember.Permissions.retrieveAccounts                          = [System.Convert]::ToBoolean($row.'Retrieve Accounts')
                $safeMember.Permissions.addAccounts                               = [System.Convert]::ToBoolean($row.'Add Accounts')
                $safeMember.Permissions.updateAccountProperties                   = [System.Convert]::ToBoolean($row.'Update Account Properties')
                $safeMember.Permissions.updateAccountContent                      = [System.Convert]::ToBoolean($row.'Update Account Content')
                $safeMember.Permissions.initiateCPMAccountManagementOperations    = [System.Convert]::ToBoolean($row.'Initiate CPM Account Management Operations')
                $safeMember.Permissions.specifyNextAccountContent                 = [System.Convert]::ToBoolean($row.'Specify Next Account Content')
                $safeMember.Permissions.renameAccounts                            = [System.Convert]::ToBoolean($row.'Rename Account')
                $safeMember.Permissions.deleteAccounts                            = [System.Convert]::ToBoolean($row.'Delete Account')
                $safeMember.Permissions.unlockAccounts                            = [System.Convert]::ToBoolean($row.'Unlock Account')
                $safeMember.Permissions.manageSafe                                = [System.Convert]::ToBoolean($row.'Manage Safe')
                $safeMember.Permissions.viewSafeMembers                           = [System.Convert]::ToBoolean($row.'View Safe Members')
                $safeMember.Permissions.manageSafeMembers                         = [System.Convert]::ToBoolean($row.'Manage Safe Members')
                $safeMember.Permissions.viewAuditLog                              = [System.Convert]::ToBoolean($row.'View Audit Log')
                $safeMember.Permissions.backupSafe                                = [System.Convert]::ToBoolean($row.'Backup Safe')
                $safeMember.Permissions.requestsAuthorizationLevel1               = [System.Convert]::ToBoolean($row.'Level 1 Confirmer')
                $safeMember.Permissions.requestsAuthorizationLevel2               = [System.Convert]::ToBoolean($row.'Level 2 Confirmer')
                $safeMember.Permissions.accessWithoutConfirmation                 = [System.Convert]::ToBoolean($row.'Access Safe Without Confirmation')
                $safeMember.Permissions.moveAccountsAndFolders                    = [System.Convert]::ToBoolean($row.'Move Accounts / Folders')
                $safeMember.Permissions.createFolders                             = [System.Convert]::ToBoolean($row.'Create Folders')
                $safeMember.Permissions.deleteFolders                             = [System.Convert]::ToBoolean($row.'Delete Folders')
            }
            $safeMember
        }
    }
}
#EndRegion '.\Public\PAS\SafeMember\Import-Export\Import-SafeMember.ps1' 67
#Region '.\Public\PAS\SystemHealth\Get-SystemHealth.ps1' -1

Function Get-SystemHealth {
    [CmdletBinding(DefaultParameterSetName = 'Summary')]
    Param
    (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,


        [Alias('url', 'PCloudURL')]
        [string] $PVWAURL,


        [Alias('header')]
        $LogonToken,

        [Parameter(ParameterSetName = 'Summary', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [switch] $Summary,

        [Parameter(ParameterSetName = 'CPM', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [switch] $CPM,

        [Parameter(ParameterSetName = 'PVWA', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [switch] $PVWA,

        [Parameter(ParameterSetName = 'PSM', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [switch] $PSM,

        [Parameter(ParameterSetName = 'PSMP', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [switch] $PSMP,

        [Parameter(ParameterSetName = 'PTA', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [switch] $PTA,

        [Parameter(ParameterSetName = 'AIM', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [switch] $AIM,

        [Parameter(ParameterSetName = 'ALL', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [switch] $ALL,

        [Parameter(ParameterSetName = 'ComponentID', ValueFromPipelineByPropertyName, ValueFromPipeline, DontShow)]
        $ComponentID,

        [switch] $Disconnected
    )

    Begin {
        Write-LogMessage -type Verbose -MSG 'Getting System Health'
    }

    Process {
        If ([string]::IsNullOrEmpty($ComponentID)) {
            $ComponentID = $($PSCmdlet.ParameterSetName)
        }
        switch ($PSCmdlet.ParameterSetName) {
            'All' {
                [Comp[]]$result = $(Get-SystemHealth -Disconnected:$Disconnected.IsPresent) | Where-Object { $PSitem.ComponentTotalCount -gt 0 } | ForEach-Object { Get-SystemHealth -ComponentID $PSitem.ComponentID -Disconnected:$Disconnected.IsPresent} | Sort-Object ComponentUserName | Sort-Object ComponentType
                return $result
            }
            'Summary' {
                $URL = "$PVWAURL/api/ComponentsMonitoringSummary/"
                $RestParms = @{
                    Uri    = $URL
                    Method = 'GET'
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                return (Invoke-Rest @RestParms).Components
            }
            Default {
                $URL = "$PVWAURL/api/ComponentsMonitoringDetails/$ComponentID/"
            }
        }
        Try {
            $RestParms = @{
                Uri    = $URL
                Method = 'GET'
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            $result = (Invoke-Rest @RestParms).ComponentsDetails
            $result | Add-Member -MemberType NoteProperty -Name 'ComponentType' -Value $ComponentID
            if ($Disconnected) {
                $result =  $result |Where-Object {-not $PSItem.IsLoggedOn}
            }
            Write-LogMessage -type Verbose -MSG "Found $($result.ComponentsDetails.Count) $ComponentID Components"
            return $result
        }
        Catch {
            Write-LogMessage -type Error -MSG "Error Returned: $_"
        }
    }
}
#EndRegion '.\Public\PAS\SystemHealth\Get-SystemHealth.ps1' 95
#Region '.\Public\PAS\User\Core\Add-VaultUser.ps1' -1



function Add-VaultUser {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,
        [Switch]$Force,

        [Alias('url', 'PCloudURL')]
        [string]$PVWAURL,

        [Alias('header')]
        $LogonToken,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [Alias('Member')]
        [string]$User
    )
    begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        if ($Force -and -not $Confirm) {
            Write-LogMessage -type Warning -MSG 'Confirmation prompt suppressed, proceeding with all removals'
            $ConfirmPreference = 'None'
        }
        $vaultUsers = Get-VaultUsers -url $PVWAURL -logonToken $LogonToken
        $vaultUserHT = @{}
        $vaultUsers.users | ForEach-Object {
            try {
                $username = if ($_.username.Length -le 28) { $_.username } else { $_.username.Substring(0, 28) }
                Write-LogMessage -type verbose -MSG "Adding username `"$username`" with ID `"$($_.ID)`" to hashtable"
                $vaultUserHT[$username] = $_.ID
            }
            catch {
                Write-Error "Error on $item"
                Write-Error $_
            }
        }
    }
    process {
        Write-LogMessage -type Verbose -MSG "Removing Vault User named `"$User`""
        $ID = $vaultUserHT[$User]
        if ([string]::IsNullOrEmpty($ID)) {
            Write-LogMessage -type Error "No ID located for $User"
            return
        }
        else {
            Write-LogMessage -type Verbose -MSG "Vault ID for `"$User`" is `"$ID`""
            if ($PSCmdlet.ShouldProcess($User, 'Add-VaultUser')) {
                Write-LogMessage -type verbose -MSG 'Confirmation to remove received, proceeding with removal'
                try {
                    $URL_AddVaultUser = "$PVWAURL/API/Users/$ID/"
                    $RestParms = @{
                        Uri    = $URL_AddVaultUser
                        Method = 'POST'
                    }
                    if ($null -ne $LogonToken -and $LogonToken -ne "") {
                        $RestParms.LogonToken = $LogonToken
                    }
                    Invoke-Rest @RestParms
                    Write-LogMessage -type Success -MSG "Removed user with the name `"$User`" from the vault successfully"
                }
                catch {
                    Write-LogMessage -type Error -MSG 'Error removing Vault Users'
                    Write-LogMessage -type Error -MSG $_
                }
            }
            else {
                Write-LogMessage -type Warning -MSG "Skipping removal of user `"$User`" due to confirmation being denied"
            }
        }
    }
}
#EndRegion '.\Public\PAS\User\Core\Add-VaultUser.ps1' 73
#Region '.\Public\PAS\User\Core\Get-VaultUser.ps1' -1

<#
.SYNOPSIS
    Retrieves all vault users from the specified PVWA URL.

.DESCRIPTION
    The Get-VaultUser function retrieves all vault users from the specified PVWA URL.
    It supports optional parameters to include extended details and component user information.

.PARAMETER PVWAURL
    The URL of the PVWA (Password Vault Web Access) API endpoint.

.PARAMETER LogonToken
    The logon token used for authentication with the PVWA API.

.PARAMETER componentUser
    A switch parameter to include component user information in the response.

.PARAMETER ExtendedDetails
    A switch parameter to include extended details in the response.

.EXAMPLE
    PS> Get-VaultUser -PVWAURL "https://pvwa.example.com" -LogonToken $token

.NOTES
    The function uses the Invoke-Rest function to send a GET request to the PVWA API endpoint.
    Ensure that the Invoke-Rest function is defined and available in the scope where this function is called.
#>

Function Get-VaultUser {
    Param
    (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url', 'PCloudURL')]
        [string]$PVWAURL,


        [Alias('header')]
        $LogonToken,

        [switch]$componentUser,
        [switch]$ExtendedDetails
    )

    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }

    Process {
        Write-LogMessage -type Verbose -MSG 'Getting all vault users'
        Write-LogMessage -type Verbose -MSG "ExtendedDetails=$ExtendedDetails"
        Write-LogMessage -type Verbose -MSG "componentUser=$componentUser"

        $URL_Users = "$PVWAURL/api/Users?ExtendedDetails=$($ExtendedDetails)&componentUser=$($componentUser)"
        $RestParms = @{
            Uri    = $URL_Users
            Method = 'GET'
        }
        if ($null -ne $LogonToken -and $LogonToken -ne "") {
            $RestParms.LogonToken = $LogonToken
        }
        return Invoke-Rest @RestParms
    }
}
#EndRegion '.\Public\PAS\User\Core\Get-VaultUser.ps1' 66
#Region '.\Public\PAS\User\Core\Remove-VaultUser.ps1' -1

<#
.SYNOPSIS
Removes a specified user from the vault.

.DESCRIPTION
The Remove-VaultUser function removes a specified user from the vault using the provided PVWA URL and logon token.
It supports confirmation prompts and can force removal without confirmation if specified.

.PARAMETER PVWAURL
The URL of the PVWA (Password Vault Web Access).

.PARAMETER LogonToken
The logon token used for authentication.

.PARAMETER User
The username of the vault user to be removed.

.PARAMETER Force
A switch to force the removal without confirmation.

.EXAMPLE
Remove-VaultUser -PVWAURL "https://vault.example.com" -LogonToken $token -User "jdoe"

.EXAMPLE
Remove-VaultUser -PVWAURL "https://vault.example.com" -LogonToken $token -User "jdoe" -Force

.NOTES
This function requires the Get-VaultUsers and Invoke-Rest functions to be defined elsewhere in the script or module.
#>

function Remove-VaultUser {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,
        [Switch]$Force,

        [Alias('url', 'PCloudURL')]
        [string]$PVWAURL,

        [Alias('header')]
        $LogonToken,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [Alias('Member')]
        [string]$User
    )
    begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
        if ($Force -and -not $Confirm) {
            Write-LogMessage -type Warning -MSG 'Confirmation prompt suppressed, proceeding with all removals'
            $ConfirmPreference = 'None'
        }
        $vaultUsers = Get-VaultUsers -url $PVWAURL -logonToken $LogonToken
        $vaultUserHT = @{}
        $vaultUsers.users | ForEach-Object {
            try {
                $username = if ($_.username.Length -le 28) { $_.username } else { $_.username.Substring(0, 28) }
                Write-LogMessage -type verbose -MSG "Adding username `"$username`" with ID `"$($_.ID)`" to hashtable"
                $vaultUserHT[$username] = $_.ID
            }
            catch {
                Write-Error "Error on $item"
                Write-Error $_
            }
        }
    }
    process {
        Write-LogMessage -type Verbose -MSG "Removing Vault User named `"$User`""
        $ID = $vaultUserHT[$User]
        if ([string]::IsNullOrEmpty($ID)) {
            Write-LogMessage -type Error "No ID located for $User"
            return
        }
        else {
            Write-LogMessage -type Verbose -MSG "Vault ID for `"$User`" is `"$ID`""
            if ($PSCmdlet.ShouldProcess($User, 'Remove-VaultUser')) {
                Write-LogMessage -type verbose -MSG 'Confirmation to remove received, proceeding with removal'
                try {
                    $URL_DeleteVaultUser = "$PVWAURL/API/Users/$ID/"
                    $RestParms = @{
                        Uri    = $URL_DeleteVaultUser
                        Method = 'DELETE'
                    }
                    if ($null -ne $LogonToken -and $LogonToken -ne "") {
                        $RestParms.LogonToken = $LogonToken
                    }
                    Invoke-Rest @RestParms
                    Write-LogMessage -type Success -MSG "Removed user with the name `"$User`" from the vault successfully"
                }
                catch {
                    Write-LogMessage -type Error -MSG 'Error removing Vault Users'
                    Write-LogMessage -type Error -MSG $_
                }
            }
            else {
                Write-LogMessage -type Warning -MSG "Skipping removal of user `"$User`" due to confirmation being denied"
            }
        }
    }
}
#EndRegion '.\Public\PAS\User\Core\Remove-VaultUser.ps1' 101
#Region '.\Public\PAS\User\Testing\Add-TestVaultUser.ps1' -1

<#
.SYNOPSIS
Creates a test vault user in the specified PVWA instance.

.DESCRIPTION
The Add-TestVaultUser function creates a test vault user with a predefined initial password and sets the user as disabled.
It requires the PVWA URL, a logon token, and the username of the user to be created.

.PARAMETER PVWAURL
The URL of the PVWA instance where the user will be created. This parameter is mandatory.

.PARAMETER LogonToken
The logon token used for authentication. This parameter is mandatory.

.PARAMETER User
The username of the test vault user to be created. This parameter is mandatory and can be provided via pipeline.

.PARAMETER Force
A switch parameter that can be used to force the operation. This parameter is optional.

.EXAMPLE
Add-TestVaultUser -PVWAURL "https://pvwa.example.com" -LogonToken $token -User "TestUser"

This example creates a test vault user named "TestUser" in the specified PVWA instance using the provided logon token.

.NOTES
The function logs verbose messages for the creation process and catches any errors that occur during the creation of the test vault user.
#>

function Add-TestVaultUser {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,
        [Switch]$Force,

        [Alias('url', 'PCloudURL')]
        [string]$PVWAURL,

        [Alias('header')]
        $LogonToken,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [Alias('Member')]
        [string]$User
    )
    Begin {
        $PSBoundParameters.Remove("CatchAll") | Out-Null
    }
    Process {
        $randomPassword = -join ((33..126) | Get-Random -Count 16 | ForEach-Object {[char]$_})
        Write-LogMessage -type Verbose -Message "Creating Test Vault User named `"$User`""
        $body = @{
            UserName        = $User
            InitialPassword = $randomPassword
            Disabled        = $true
        } | ConvertTo-Json -Depth 3
        $URL_AddVaultUser = "$PVWAURL/API/Users/"
        Try {
            $RestParms = @{
                Uri    = $URL_AddVaultUser
                Method = 'POST'
                Body   = $body
            }
            if ($null -ne $LogonToken -and $LogonToken -ne "") {
                $RestParms.LogonToken = $LogonToken
            }
            Invoke-Rest @RestParms
            Write-LogMessage -type Verbose -Message "Successfully created test vault user named `"$User`""
        }
        catch {
            Write-LogMessage -type Error -Message "Error creating Test Vault User named `"$User`""
        }
    }
}
#EndRegion '.\Public\PAS\User\Testing\Add-TestVaultUser.ps1' 75
#Region '.\Public\Shared\Add-BaseQueryParameter.ps1' -1

<#
.SYNOPSIS
Adds base query parameters to a URL.

.DESCRIPTION
The Add-BaseQueryParameter function appends various query parameters to a given URL.
It supports parameters such as sort, offset, limit, and useCache. It also logs the
actions performed at each step.

.PARAMETER URL
[ref] The URL to which the query parameters will be added.

.PARAMETER sort
(Optional) The sort parameter to be appended to the URL.

.PARAMETER offset
(Optional) The offset parameter to be appended to the URL.

.PARAMETER limit
(Optional) The limit parameter to be appended to the URL.

.PARAMETER DoNotPage
(Optional) If specified, indicates that paging is disabled.

.PARAMETER useCache
(Optional) If specified, indicates that session cache should be used for results.

.EXAMPLE
$URL = [ref] "http://example.com/api/resource"
Add-BaseQueryParameter -URL $URL -sort "name" -offset 10 -limit 50 -useCache

This example adds the sort, offset, limit, and useCache parameters to the given URL.

.NOTES
This function requires the Write-LogMessage function to be defined for logging purposes.
#>
function Add-BaseQueryParameter {
    param (
        [ref]$URL,
        [string]$sort,
        [string]$offset,
        [string]$limit,
        [switch]$DoNotPage,
        [switch]$useCache
    )

    Write-LogMessage -type Verbose -MSG "Adding Base Query Parameters"

    if (-not [string]::IsNullOrEmpty($sort)) {
        $URL.Value += "&sort=$sort"
        Write-LogMessage -type Verbose -MSG "Applying a sort of `"$sort`""
    }

    if (-not [string]::IsNullOrEmpty($offset)) {
        $URL.Value += "&offset=$offset"
        Write-LogMessage -type Verbose -MSG "Applying an offset of `"$offset`""
    }

    if (-not [string]::IsNullOrEmpty($limit)) {
        $URL.Value += "&limit=$limit"
        Write-LogMessage -type Verbose -MSG "Applying a limit of `"$limit`""
    }

    if ($DoNotPage) {
        Write-LogMessage -type Verbose -MSG "Paging is disabled."
    }

    if ($useCache) {
        $URL.Value += "&useCache=true"
        Write-LogMessage -type Verbose -MSG "Using session cache for results"
    }

    Write-LogMessage -type Verbose -MSG "New URL: $($URL.Value)"
}
#EndRegion '.\Public\Shared\Add-BaseQueryParameter.ps1' 75
#Region '.\Public\Shared\Get-SamAccountName.ps1' -1

function Get-SamAccountName {
    [CmdletBinding()]
    [OutputType([String])]
    param (

        [Parameter(Position = 0, ValueFromPipeline)]
        [string]
        $UserPrincipalName,
        [Parameter(Position = 1, ValueFromPipeline)]
        [switch]
        $NoErrorOnNull
    )

    begin {
        if (-not $(Get-Module ActiveDirectory)) {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
            }
            catch {
                Write-Error 'Active Directory Module required, please install and try again'
                throw 'AD Module Not Installed'
            }
        }
    }

    process {
        $user = Get-ADUser -Filter { UserPrincipalName -eq $UserPrincipalName }
        if ($user) {
            return [string]$user.SamAccountName
        }
        else {
            if ($NoErrorOnNull) {
                return ''
            }
            else {
                Write-Error 'Not Found'
            }
        }
    }
}
#EndRegion '.\Public\Shared\Get-SamAccountName.ps1' 41
#Region '.\Public\Shared\Get-UPN.ps1' -1

function Get-UPN {
    [CmdletBinding()]
    [OutputType([String])]
    param (

        [Parameter(Position = 0, ValueFromPipeline)]
        [string]
        $SAMAccountName,
        [Parameter(Position = 1, ValueFromPipeline)]
        [switch]
        $NoErrorOnNull
    )

    begin {
        if (-not $(Get-Module ActiveDirectory)) {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
            }
            catch {
                Write-Error 'Active Directory Module required, please install and try again'
                throw 'AD Module Not Installed'
            }
        }
    }

    process {
        $user = Get-ADUser -Filter { SamAccountName -eq $SAMAccountName }
        if ($user) {
            return [string]$user.UserPrincipalName
        }
        else {
            if ($NoErrorOnNull) {
                return ''
            }
            else {
                Write-Error 'Not Found'
            }
        }
    }
}
#EndRegion '.\Public\Shared\Get-UPN.ps1' 41
#Region '.\Public\Shared\New-Session.ps1' -1

<#
.SYNOPSIS
Creates a new session for connecting to CyberArk environments.

.DESCRIPTION
The New-Session function establishes a new session for connecting to CyberArk environments, including PVWA and Privileged Cloud. It supports multiple parameter sets for different connection scenarios and handles credentials securely.

.PARAMETER Username
Specifies the username to connect with as a string. This parameter is used in the 'PVWAURL', 'PCloudSubdomain', and 'PCloudURL' parameter sets.

.PARAMETER Password
Specifies the password to connect with, stored as a SecureString. This parameter is used in the 'PVWAURL', 'PCloudSubdomain', and 'PCloudURL' parameter sets.

.PARAMETER Creds
Specifies the credentials stored as PSCredentials. This parameter is used in the 'PVWAURL', 'PCloudSubdomain', and 'PCloudURL' parameter sets.

.PARAMETER PVWAURL
Specifies the URL to the PVWA. This parameter is mandatory in the 'PVWAURL' parameter set.

.PARAMETER PCloudURL
Specifies the URL to the Privileged Cloud. This parameter is mandatory in the 'PCloudURL' parameter set.

.PARAMETER PCloudSubdomain
Specifies the subdomain for the Privileged Cloud. This parameter is mandatory in the 'PCloudSubdomain' parameter set.

.PARAMETER IdentityURL
Specifies the URL for CyberArk Identity. This parameter is used in the 'PCloudURL' and 'PCloudSubdomain' parameter sets.

.PARAMETER OAuthCreds
Specifies the OAuth credentials stored as PSCredentials. This parameter is used in the 'PCloudURL' and 'PCloudSubdomain' parameter sets.

.PARAMETER LogFile
Specifies the log file name. The default value is ".\Log.Log".

.PARAMETER OutputResults
Switch parameter that enables success output logging. When specified, successful operations will be logged to the console and/or success file.

.PARAMETER UseResultFile
Switch parameter that enables logging of successful operations to a separate success file. Works in conjunction with OutputResults to provide detailed success tracking.

.PARAMETER UseErrorFile
Switch parameter that enables logging of error operations to a separate success file.

.EXAMPLE
New-Session -Username "admin" -Password (ConvertTo-SecureString "password" -AsPlainText -Force) -PVWAURL "https://pvwa.example.com"

.EXAMPLE
New-Session -Creds (Get-Credential) -PCloudURL "https://cloud.example.com" -IdentityURL "https://identity.example.com"

.EXAMPLE
New-Session -Username "admin" -Password (ConvertTo-SecureString "password" -AsPlainText -Force) -PVWAURL "https://pvwa.example.com" -OutputResults -UseResultFile

Creates a new session with success logging enabled, which will output successful operations to both console and a success file.

.NOTES
This function sets default parameter values for subsequent commands in the session, including logon tokens and URLs.
#>

function New-Session {
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Used to create a new session')]
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = 'PVWAURL')]
        [Parameter(ParameterSetName = 'PCloudSubdomain')]
        [Parameter(ParameterSetName = 'PCloudURL')]
        [Alias('IdentityUserName', 'PVWAUsername')]
        [string] $Username,

        [Parameter(ParameterSetName = 'PVWAURL')]
        [Parameter(ParameterSetName = 'PCloudURL')]
        [Parameter(ParameterSetName = 'PCloudSubdomain')]
        [securestring] $Password,

        [Parameter(ParameterSetName = 'PVWAURL')]
        [Parameter(ParameterSetName = 'PCloudURL')]
        [Parameter(ParameterSetName = 'PCloudSubdomain')]
        [Alias('PVWACreds', 'IdentityCreds')]
        [pscredential] $Creds,

        [Parameter(ParameterSetName = 'PVWAURL', Mandatory)]
        [string] $PVWAURL,

        [Parameter(ParameterSetName = 'PCloudURL', Mandatory)]
        [string] $PCloudURL,

        [Parameter(ParameterSetName = 'PCloudSubdomain', Mandatory)]
        [string] $PCloudSubdomain,

        [Parameter(ParameterSetName = 'PCloudURL')]
        [Parameter(ParameterSetName = 'PCloudSubdomain')]
        [Alias('IdentityTenantURL')]
        [string] $IdentityURL,

        [Parameter(ParameterSetName = 'PCloudURL')]
        [Parameter(ParameterSetName = 'PCloudSubdomain')]
        [pscredential] $OAuthCreds,

        [string] $LogFile,

        [switch]$OutputResults,
        [switch]$OutputErrors,
        [switch]$UseResultFile,
        [switch]$UseErrorFile,

        [switch]$UseVerboseFile,

        [switch]$IncludeCallStack


    )
    begin {

        if ($Password) {
            $PSBoundParameters['Creds'] = [pscredential]::new($Username, $Password)
            $null = $PSBoundParameters.Remove('Username')
            $null = $PSBoundParameters.Remove('Password')
        }
        if ([string]::IsNullOrEmpty($LogFile) -and [string]::IsNullOrEmpty($Script:LogFile)) {
            $LogFile = "$PSScriptRoot\Log.Log"
            $Script:LogFile = $LogFile
            Write-Warning "LogFile not specified. Using default: $LogFile"
        }
        elseif (![string]::IsNullOrEmpty($LogFile)) {
            $Script:LogFile = $LogFile
        }
        else {
            $LogFile = $Script:LogFile
        }

        if ($OutputResults) {
            $script:OutputResult = $OutputResults
        }
        if ($OutputErrors) {
            $script:OutputErrors = $OutputErrors
        }
        if ($UseResultFile) {
            $script:UseResultFile = $UseResultFile
        }
        if ($UseErrorFile) {
            $script:UseErrorFile = $UseErrorFile
        }
        if ($UseErrorFile) {
            $script:UseErrorFile = $UseErrorFile
        }
        if ($UseVerboseFile) {
            $script:UseVerboseFile = $UseVerboseFile
        }
        if ($IncludeCallStack) {
            $script:IncludeCallStack = $IncludeCallStack
        }

        try {
            $script:WebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            $PSDefaultParameterValues['*:WebSession'] = [ref]$script:WebSession
            switch ($PSCmdlet.ParameterSetName) {
                'PCloudURL' {
                    # Format and validate the PCloudURL to ensure correct format
                    $PCloudURL = Format-PCloudURL -PCloudURL $PCloudURL
                    $PSBoundParameters['PCloudURL'] = $PCloudURL
                    $Script:websession.headers.Add('OobIdPAuth', $true)
                    $BearerToken = Get-PCLoudLogonHeader @PSBoundParameters
                    if ($null -ne $BearerToken) {
                        $script:WebSession.Headers.Authorization = $BearerToken
                    }
                    else {
                        $script:WebSession.Headers.Add('Authorization', $BearerToken)
                    }
                    $script:WebSession.Headers.Add('X-IDAP-NATIVE-CLIENT', 'true')
                    $PSDefaultParameterValues['*:LogonToken'] = $BearerToken
                    $PSDefaultParameterValues['*:PVWAURL'] = $PCloudURL
                    $PSDefaultParameterValues['*:IdentityURL'] = Get-IdentityURL $PCloudURL
                    $PSDefaultParameterValues['*:DiscoveryURL'] = Get-DiscoveryURL $PCloudURL
                    $PSDefaultParameterValues['*:CMURL'] = Get-CMURL $PCloudURL
                    $PSDefaultParameterValues['*:BaseURL'] = Get-BaseURL $PCloudURL
                }
                'PCloudSubdomain' {
                    # Construct the full PCloudURL from the subdomain
                    $PCloudURL = "https://$PCloudSubdomain.privilegecloud.cyberark.com/PasswordVault"
                    $PSBoundParameters['PCloudURL'] = $PCloudURL
                    $PSBoundParameters.Remove('PCloudSubdomain') | Out-Null
                    $Script:websession.headers.Add('OobIdPAuth', $true)
                    $BearerToken = Get-PCLoudLogonHeader @PSBoundParameters
                    if ($null -ne $BearerToken) {
                        $script:WebSession.Headers.Authorization = $BearerToken
                    }
                    else {
                        $script:WebSession.Headers.Add('Authorization', $BearerToken)
                    }
                    $script:WebSession.Headers.Add('X-IDAP-NATIVE-CLIENT', 'true')
                    $PSDefaultParameterValues['*:LogonToken'] = $BearerToken
                    $PSDefaultParameterValues['*:PVWAURL'] = $PCloudURL
                    $PSDefaultParameterValues['*:IdentityURL'] = Get-IdentityURL $PCloudURL
                    $PSDefaultParameterValues['*:DiscoveryURL'] = Get-DiscoveryURL $PCloudURL
                    $PSDefaultParameterValues['*:CMURL'] = Get-CMURL $PCloudURL
                    $PSDefaultParameterValues['*:BaseURL'] = Get-BaseURL $PCloudURL
                }
                'PVWAURL' {
                    $logonToken = Get-OnPremHeader @PSBoundParameters
                    if ($null -ne $logonToken) {
                        $script:WebSession.Headers.Authorization = $logonToken
                    }
                    else {
                        $script:WebSession.Headers.Add('Authorization', $logonToken)
                    }
                    $PSDefaultParameterValues['*:LogonToken'] = $logonToken
                    $PSDefaultParameterValues['*:PVWAURL'] = $PVWAURL
                }
            }
        }
        catch {
            Write-LogMessage -type Error -MSG 'Unable to establish a connection to CyberArk'
            throw
        }

        Set-Variable -Name PSDefaultParameterValues -Scope 2 -Value $PSDefaultParameterValues
        Set-Variable -Name PSDefaultParameterValues -Scope Global -Value $PSDefaultParameterValues
        Set-Variable -Name PSDefaultParameterValues -Scope Script -Value $PSDefaultParameterValues

        try {
            [string[]] $CPMUser = Get-CPMUser
            $PSDefaultParameterValues['*:CPMUser'] = $CPMUser
            Set-Variable -Name PSDefaultParameterValues -Scope 2 -Value $PSDefaultParameterValues
            Set-Variable -Name PSDefaultParameterValues -Scope Global -Value $PSDefaultParameterValues
            Set-Variable -Name PSDefaultParameterValues -Scope Script -Value $PSDefaultParameterValues
        }
        catch {
            Write-LogMessage -type Warning -MSG 'Unable to retrieve list of CPMs, the connection was made with a restricted user and not all commands may work'
        }
    }
}
#EndRegion '.\Public\Shared\New-Session.ps1' 231
#Region '.\Public\Shared\Remove-SensitiveData.ps1' -1

function Remove-SensitiveData {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Alias('MSG', 'value', 'string')]
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $message
    )
    begin {
        $cleanedMessage = $message
    }
    process {
        try {
            if ($global:LogSensitiveData -eq $true) {
                # Allows sensitive data to be logged this is useful for debugging authentication issues
                return $message
            }
            # List of fields that contain sensitive data to check for
            $checkFor = @('password', 'secret', 'NewCredentials', 'access_token', 'client_secret', 'auth', 'Authorization', 'Answer', 'Token')
            # Check for sensitive data in the message that is escaped with quotes or double quotes
            $checkFor | ForEach-Object {
                if ($cleanedMessage -imatch "[{\\""']{2,}\s{0,}$PSitem\s{0,}[\\""']{2,}\s{0,}[:=][\\""']{2,}\s{0,}(?<Sensitive>.*?)\s{0,}[\\""']{2,}(?=[,:;])") {
                    if (-not [string]::IsNullOrEmpty($Matches['Sensitive']) -and -not $("," -eq $Matches['Sensitive'])) {
                        $cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
                    }
                }
                # Check for sensitive data in the message that is not escaped with quotes or double quotes
                elseif ($cleanedMessage -imatch "[""']{1,}\s{0,}$PSitem\s{0,}[""']{1,}\s{0,}[:=][""']{1,}\s{0,}(?<Sensitive>.*?)\s{0,}[""']{1,}") {
                    if (-not [string]::IsNullOrEmpty($Matches['Sensitive']) -and -not $("," -eq $Matches['Sensitive'])) {
                        $cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
                    }
                }
                # Check for Sensitive data in pure JSON without quotes
                elseif ( $cleanedMessage -imatch "(?:\s{0,}$PSitem\s{0,}[:=])\s{0,}(?<Sensitive>.*?)(?=; |: )") {
                    if (-not [string]::IsNullOrEmpty($Matches['Sensitive'])) {
                        $cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
                    }
                }
            }
        }
        catch {
            throw $PSItem
        }
    }
    end {
        # Return the modified string
        return $cleanedMessage
    }
}
#
#EndRegion '.\Public\Shared\Remove-SensitiveData.ps1' 52
#Region '.\Public\Shared\Set-Session.ps1' -1

function Set-Session {
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Used to create a new session')]
    [CmdletBinding()]
    param (

        [Parameter(Mandatory)]
        [string]
        $Token,
        [Parameter(ParameterSetName = 'PVWAURL', Mandatory)]
        [string] $PVWAURL,
        [Parameter(ParameterSetName = 'PCloudURL', Mandatory)]
        [string] $PCloudURL,
        [string] $LogFile,
        [switch]$OutputResults,
        [switch]$OutputErrors,
        [switch]$UseResultFile,
        [switch]$UseErrorFile,
        [Parameter(DontShow)]
        [switch]$UseVerboseFile,
        [Parameter(DontShow)]
        [switch]$IncludeCallStack

    )
    if ([string]::IsNullOrEmpty($LogFile) -and [string]::IsNullOrEmpty($Script:LogFile)) {
        $LogFile = "$PSScriptRoot\Log.Log"
        $Script:LogFile = $LogFile
        Write-Warning "LogFile not specified. Using default: $LogFile"
    }
    elseif (![string]::IsNullOrEmpty($LogFile)) {
        $Script:LogFile = $LogFile
    }
    else {
        $LogFile = $Script:LogFile
    }


    if ($OutputResults) {
        $script:OutputResult = $OutputResults
    }
    if ($OutputErrors) {
        $script:OutputErrors = $OutputErrors
    }
    if ($UseResultFile) {
        $script:UseResultFile = $UseResultFile
    }
    if ($UseErrorFile) {
        $script:UseErrorFile = $UseErrorFile
    }
    if ($UseErrorFile) {
        $script:UseErrorFile = $UseErrorFile
    }
    if ($UseVerboseFile) {
        $script:UseVerboseFile = $UseVerboseFile
    }
    if ($IncludeCallStack) {
        $script:IncludeCallStack = $IncludeCallStack
    }

    try {
        $script:WebSession = $null
        $script:WebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $PSDefaultParameterValues['*:WebSession'] = [ref]$script:WebSession
        switch ($PSCmdlet.ParameterSetName) {
            'PCloudURL' {
                $PCloudURL = Format-PCloudURL -PCloudURL $PCloudURL
                $PSBoundParameters['PCloudURL'] = $PCloudURL
                $Script:websession.headers.Add('OobIdPAuth', $true)
                $script:WebSession.Headers.Add('Authorization', $token)
                $script:WebSession.Headers.Add('X-IDAP-NATIVE-CLIENT', 'true')
                $PSDefaultParameterValues['*:LogonToken'] = $token
                $PSDefaultParameterValues['*:PVWAURL'] = $PCloudURL
                $PSDefaultParameterValues['*:IdentityURL'] = Get-IdentityURL $PCloudURL
                $PSDefaultParameterValues['*:DiscoveryURL'] = Get-DiscoveryURL $PCloudURL
                $PSDefaultParameterValues['*:CMURL'] = Get-CMURL $PCloudURL
                $PSDefaultParameterValues['*:BaseURL'] = Get-BaseURL $PCloudURL
            }
            'PVWAURL' {
                $script:WebSession.Headers.Add('Authorization', $Token)
                $PSDefaultParameterValues['*:LogonToken'] = $Token
                $PSDefaultParameterValues['*:PVWAURL'] = $PVWAURL
            }
        }

        Set-Variable -Name PSDefaultParameterValues -Scope 2 -Value $PSDefaultParameterValues
        Set-Variable -Name PSDefaultParameterValues -Scope Global -Value $PSDefaultParameterValues
    }
    catch {
        Write-LogMessage -type Error -MSG 'Unable to establish a connection to CyberArk'
        return
    }
}
#EndRegion '.\Public\Shared\Set-Session.ps1' 92
#Region '.\Public\Shared\Write-LogMessage - orginal.ps1' -1

<#
.SYNOPSIS
    Writes a log message to the console and optionally to a log file with various formatting options.

.DESCRIPTION
    The Write-LogMessage function logs messages to the console with optional headers, subheaders, and footers.
    It also supports writing messages to a log file. The function can handle different message types such as
    Info, Warning, Error, Debug, Verbose, Success, LogOnly, and ErrorThrow. It also masks sensitive information
    like passwords in the messages.

.PARAMETER MSG
    The message to log. This parameter is mandatory and accepts pipeline input.

.PARAMETER Header
    Adds a header line before the message. This parameter is optional.

.PARAMETER SubHeader
    Adds a subheader line before the message. This parameter is optional.

.PARAMETER Footer
    Adds a footer line after the message. This parameter is optional.

.PARAMETER WriteLog
    Indicates whether to write the output to a log file. The default value is $true.

.PARAMETER type
    The type of the message to log. Valid values are 'Info', 'Warning', 'Error', 'Debug', 'Verbose', 'Success',
    'LogOnly', and 'ErrorThrow'. The default value is 'Info'.

.PARAMETER LogFile
    The log file to write to. If not provided and WriteLog is $true, a temporary log file named 'Log.Log' will be created.

.EXAMPLE
    Write-LogMessage -MSG "This is an info message" -type Info

    Logs an info message to the console and the default log file.

.EXAMPLE
    "This is a warning message" | Write-LogMessage -type Warning

    Logs a warning message to the console and the default log file using pipeline input.

.EXAMPLE
    Write-LogMessage -MSG "This is an error message" -type Error -LogFile "C:\Logs\error.log"

    Logs an error message to the console and to the specified log file.

.NOTES
    The function masks sensitive information like passwords in the messages to prevent accidental exposure.
#>

# Original version of the Write-LogMessage function
Function Write-LogMessage-OLD {
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Scope = "Function" , Justification = 'Want to go to console and allow for colors')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [String]$MSG,

        [Parameter(Mandatory = $false)]
        [Switch]$Header,

        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,

        [Parameter(Mandatory = $false)]
        [Switch]$Footer,

        [Parameter(Mandatory = $false)]
        [Bool]$WriteLog = $true,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Debug', 'Verbose', 'Success', 'LogOnly', 'ErrorThrow')]
        [String]$type = 'Info',

        [Parameter(Mandatory = $false)]
        [String]$LogFile
    )

    begin {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    }

    process {
        Try {
            if ([string]::IsNullOrEmpty($LogFile) -and $WriteLog) {
                $LogFile = '.\Log.Log'
            }

            if ($Header -and $WriteLog) {
                '=======================================' | Out-File -Append -FilePath $LogFile
                Write-Host '=======================================' -ForegroundColor Magenta
            }
            elseif ($SubHeader -and $WriteLog) {
                '------------------------------------' | Out-File -Append -FilePath $LogFile
                Write-Host '------------------------------------' -ForegroundColor Magenta
            }

            if ([string]::IsNullOrEmpty($Msg)) {
                $Msg = 'N/A'
            }

            $msgToWrite = ''
            $Msg = $Msg.Replace('"secretType":"password"', '"secretType":"pass"')

            if ($Msg -match '((?:password|credentials|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()-_\=\+\\\/|;:\.,\[\]{}]+))') {
                $Msg = $Msg.Replace($Matches[2], '****')
            }

            $Msg = $Msg.Replace('"secretType":"pass"', '"secretType":"password"')

            switch ($type) {
                { ($PSItem -eq 'Info') -or ($PSItem -eq 'LogOnly') } {
                    if ($PSItem -eq 'Info') {
                        Write-Host $MSG.ToString() -ForegroundColor $(if ($Header -or $SubHeader) { 'Magenta' } else { 'Gray' })
                    }
                    $msgToWrite = "[INFO]`t`t`t$Msg"
                    break
                }
                'Success' {
                    Write-Host $MSG.ToString() -ForegroundColor Green
                    $msgToWrite = "[SUCCESS]`t`t$Msg"
                    break
                }
                'Warning' {
                    Write-Host $MSG.ToString() -ForegroundColor Yellow
                    $msgToWrite = "[WARNING]`t$Msg"
                    break
                }
                'Error' {
                    Write-Host $MSG.ToString() -ForegroundColor Red
                    $msgToWrite = "[ERROR]`t`t$Msg"
                    break
                }
                'ErrorThrow' {
                    $msgToWrite = "[THROW]`t`t$Msg"
                    break
                }
                'Debug' {
                    if ($DebugPreference -ne 'SilentlyContinue' -or $VerbosePreference -ne 'SilentlyContinue') {
                        Write-Debug -Message $MSG
                        $msgToWrite = "[Debug]`t`t`t$Msg"
                    }
                    break
                }
                'Verbose' {
                    if ($VerbosePreference -ne 'SilentlyContinue') {
                        Write-Verbose -Message $MSG
                        $msgToWrite = "[VERBOSE]`t`t$Msg"
                    }
                    break
                }
            }

            if ($WriteLog -and $msgToWrite) {
                "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')]`t$msgToWrite" | Out-File -Append -FilePath $LogFile
            }

            if ($Footer -and $WriteLog) {
                '=======================================' | Out-File -Append -FilePath $LogFile
                Write-Host '=======================================' -ForegroundColor Magenta
            }
        }
        catch {
            Throw $(New-Object System.Exception ('Cannot write message'), $PSItem.Exception)
        }
    }
}
#EndRegion '.\Public\Shared\Write-LogMessage - orginal.ps1' 170
#Region '.\Public\Shared\Write-LogMessage.ps1' -1

# Load the namespace to allow different colors with Write-LogMessage
# Uncomment the following line to load the namespace to allow different colors with Write-LogMessage if not using the module
#using namespace System.Management.Automation

<#
.SYNOPSIS
    Writes a log message to the console and optionally to a log file with various formatting options.

.DESCRIPTION
    The Write-LogMessage function logs messages to the console with optional headers, subheaders, and footers.
    It also supports writing messages to a log file. The function can handle different message types such as
    Info, Warning, Error, Debug, Verbose, Success, LogOnly, and ErrorThrow. It also masks sensitive information
    like passwords in the messages.

.PARAMETER MSG
    The message to log. This parameter is mandatory and accepts pipeline input.

.PARAMETER Header
    Adds a header line before the message. This parameter is optional.

.PARAMETER SubHeader
    Adds a subheader line before the message. This parameter is optional.

.PARAMETER Footer
    Adds a footer line after the message. This parameter is optional.

.PARAMETER WriteLog
    Indicates whether to write the output to a log file. The default value is $true.

.PARAMETER type
    The type of the message to log. Valid values are 'Info', 'Important', 'Warning', 'Error', 'Debug', 'Verbose', 'Success',
    'LogOnly', and 'ErrorThrow'. The default value is 'Info'.

.PARAMETER LogFile
    The log file to write to. if not provided and WriteLog is $true, a temporary log file named 'Log.Log' will be created.

.PARAMETER pad
    The padding width for verbose messages when formatting message arrays. The default value is 20.

.PARAMETER maskAnswer
    Internal switch parameter used for masking sensitive information. This parameter is hidden from help display.

.EXAMPLE
    Write-LogMessage -MSG "This is an info message" -type Info

    Logs an info message to the console and the default log file.

.EXAMPLE
    "This is a warning message" | Write-LogMessage -type Warning

    Logs a warning message to the console and the default log file using pipeline input.

.EXAMPLE
    Write-LogMessage -MSG "This is an error message" -type Error -LogFile "C:\Logs\error.log"

    Logs an error message to the console and to the specified log file.

.EXAMPLE
    Write-LogMessage -MSG "Critical system alert" -type Important

    Logs an important message with special formatting (highlighted background/foreground colors).

.EXAMPLE
    Write-LogMessage -MSG "Operation:	Details about the operation" -type Verbose -pad 25

    Logs a verbose message with custom padding of 25 characters for better formatting.

.NOTES
    The function masks sensitive information like passwords in the messages to prevent accidental exposure.
#>
function Write-LogMessage {
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Scope = 'Function' , Justification = 'In TODO list to remove')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [Alias('Message')]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [Switch]$Header,
        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory = $false)]
        [Switch]$Footer,
        [Parameter(Mandatory = $false)]
        [Bool]$WriteLog = $true,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Important', 'Warning', 'Error', 'Debug', 'Verbose', 'Success', 'LogOnly', 'ErrorThrow', 'Failure', 'Match', 'NoMatch')]
        [String]$type = 'Info',
        [Parameter(Mandatory = $false)]
        [String]$LogFile,
        [Parameter(Mandatory = $false)]
        [int]$pad = 20,
        [Parameter(Mandatory = $false, DontShow = $true)]
        [Switch]$maskAnswer
    )
    begin {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        if ([string]::IsNullOrEmpty($LogFile) -and [string]::IsNullOrEmpty($Script:LogFile) -and [string]::IsNullOrEmpty($Global:LogFile) -and $WriteLog) {
            $LogFile = "$PSScriptRoot\Log.Log"
            $Script:LogFile = $LogFile
            Write-Warning "LogFile not specified. Using default: $LogFile"
        }
        elseif (![string]::IsNullOrEmpty($LogFile) -and $WriteLog) {
            $Script:LogFile = $LogFile
        }
        elseif (![string]::IsNullOrEmpty($Global:LogFile) -and $WriteLog) {
            $Script:LogFile = $Global:LogFile
            $LogFile = $Script:LogFile
        }
        elseif ($WriteLog) {
            $LogFile = $Script:LogFile
        }
        $verboseFile = $($LogFile.replace('.log', '_Verbose.log'))
        $ResultFile = $($LogFile.replace('.log', '_Result.log'))
        $errorFile = $($LogFile.replace('.log', '_Error.log'))
    }
    process {
        try {
            $LogTime = "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')]`t"
            $msgToWrite += "$LogTime"
            $thread = ([System.Threading.Thread]::CurrentThread.ManagedThreadId).ToString().PadLeft(4, '0')
            $msgToWrite += "[$thread]`t"

            if ($Header -and $WriteLog) {
                $msgToWrite += '`n=======================================`n'
                Write-Information '=======================================' -InformationAction Continue
            }
            elseif ($SubHeader -and $WriteLog) {
                $msgToWrite += '`n------------------------------------`n'
                Write-Information '------------------------------------' -InformationAction Continue
            }

            $writeToFile = $true
            # Replace empty message with 'N/A'
            if ([string]::IsNullOrEmpty($Msg)) {
                $Msg = 'N/A'
            }
            # Added to prevent body messages from being masked
            $Msg = Remove-SensitiveData -Msg $Msg
            # Check the message type
            switch ($type) {
                'LogOnly' {
                    $msgToWrite += "[INFO]`t`t$Msg"
                    break
                }
                'Important' {
                    $msgdata = [HostInformationMessage]@{
                        $color          = [System.ConsoleColor]::Red
                        message         = "[IMPORTANT]`t"
                        ForegroundColor = if ($Host.UI.RawUI.BackgroundColor -eq 'Black') { $color }
                        BackgroundColor = if ($Host.UI.RawUI.ForegroundColor -eq 'Black') { $color }
                        NoNewLine       = $true
                    }
                    Write-Information $msgdata -InformationAction Continue
                    $msgToWrite += "[IMPORTANT]`t$Msg"
                    break
                }
                'Success' {
                    $writeVerbose = $true
                    $writeResult = $true
                    if ($script:OutputResult) {
                        $color = [System.ConsoleColor]::Green
                        $msgdata = [HostInformationMessage]@{
                            message         = "SUCCESS:`t$Msg"
                            ForegroundColor = if ($Host.UI.RawUI.BackgroundColor -eq 'Black') { $color }
                            BackgroundColor = if ($Host.UI.RawUI.ForegroundColor -eq 'Black') { $color }
                        }
                        Write-Information $msgdata -InformationAction Continue
                    }
                    $msgToWrite += "[SUCCESS]`t$Msg"
                    break
                }
                'Match' {
                    $writeVerbose = $true
                    $writeResult = $true
                    if ($script:OutputResult) {
                        $color = [System.ConsoleColor]::DarkGreen
                        $msgdata = [HostInformationMessage]@{
                            message         = "MATCH:`t`t$Msg"
                            ForegroundColor = if ($Host.UI.RawUI.BackgroundColor -eq 'Black') { $color }
                            BackgroundColor = if ($Host.UI.RawUI.ForegroundColor -eq 'Black') { $color }
                        }
                        Write-Information $msgdata -InformationAction Continue
                    }
                    $msgToWrite += "[MATCH]`t$Msg"
                    break
                }
                'NoMatch' {
                    $writeVerbose = $true
                    $writeResult = $true
                    if ($script:OutputResult) {
                        $color = [System.ConsoleColor]::DarkYellow
                        $msgdata = [HostInformationMessage]@{
                            message         = "NOMATCH:`t$Msg"
                            ForegroundColor = if ($Host.UI.RawUI.BackgroundColor -eq 'Black') { $color }
                            BackgroundColor = if ($Host.UI.RawUI.ForegroundColor -eq 'Black') { $color }
                        }
                        Write-Information $msgdata -InformationAction Continue
                    }
                    $msgToWrite += "[NOMATCH]`t$Msg"
                    break
                }
                'Info' {
                    $color = [System.ConsoleColor]::Blue
                    $msgdata = [HostInformationMessage]@{
                        message         = "INFO:`t`t$Msg"
                        ForegroundColor = if ($Host.UI.RawUI.BackgroundColor -eq 'Black') { $color }
                        BackgroundColor = if ($Host.UI.RawUI.ForegroundColor -eq 'Black') { $color }
                    }
                    Write-Information $msgdata -InformationAction Continue
                    $msgToWrite += "[INFO]`t`t$Msg"
                    break
                }
                'Warning' {
                    $color = [System.ConsoleColor]::Yellow
                    $msgdata = [HostInformationMessage]@{
                        message         = "WARNING:`t$Msg"
                        ForegroundColor = if ($Host.UI.RawUI.BackgroundColor -eq 'Black') { $color }
                        BackgroundColor = if ($Host.UI.RawUI.ForegroundColor -eq 'Black') { $color }
                    }
                    Write-Information $msgdata -InformationAction Continue
                    $msgToWrite += "[WARNING]`t$Msg"
                    break
                }
                'Error' {
                    $writeError = $true
                    $writeVerbose = $true
                    if ($script:OutputError) {
                        $color = [System.ConsoleColor]::OrangeRed
                        $msgdata = [HostInformationMessage]@{
                            message         = "WARNING:`t$Msg"
                            ForegroundColor = if ($Host.UI.RawUI.BackgroundColor -eq 'Black') { $color }
                            BackgroundColor = if ($Host.UI.RawUI.ForegroundColor -eq 'Black') { $color }
                        }
                        Write-Information $msgdata -InformationAction Continue
                    }
                    $msgToWrite += "[ERROR]`t`t$Msg"
                    break
                }
                'Failure' {
                    $writeResult = $true
                    $writeVerbose = $true
                    if ($script:OutputResult) {
                        $color = [System.ConsoleColor]::Red
                        $msgdata = [HostInformationMessage]@{
                            message         = "FAILURE:`t$Msg"
                            ForegroundColor = if ($Host.UI.RawUI.BackgroundColor -eq 'Black') { $color }
                            BackgroundColor = if ($Host.UI.RawUI.ForegroundColor -eq 'Black') { $color }
                        }
                        Write-Information $msgdata -InformationAction Continue
                    }
                    $msgToWrite += "[FAILURE]`t$Msg"
                    break
                }
                'ErrorThrow' {
                    $writeError = $true
                    $msgToWrite = "[THROW]`t`t$Msg"
                    break
                }
                'Debug' {
                    if ($DebugPreference -ne 'SilentlyContinue' -or $VerbosePreference -ne 'SilentlyContinue' -or $UseVerboseFile) {
                        $writeVerbose = $true
                        $msgToWrite += "[DEBUG]`t`t$Msg"
                    }
                    else {
                        $writeToFile = $False
                        break
                    }
                    if ($DebugPreference -ne 'SilentlyContinue' -or $VerbosePreference -ne 'SilentlyContinue') {
                        Write-Debug $MSG
                    }
                }
                'Verbose' {
                    if ($VerbosePreference -ne 'SilentlyContinue' -or $UseVerboseFile) {
                        $writeVerbose = $true
                        $arrMsg = $msg.split(":`t", 2)
                        if ($arrMsg.Count -gt 1) {
                            $msg = $arrMsg[0].PadRight($pad) + $arrMsg[1]
                        }
                        $msgToWrite += "[VERBOSE]`t$Msg"
                        #TODO Need to decide where to put IncludeCallStack
                        if ($script:IncludeCallStack) {
                            function Get-CallStack {
                                $stack = ''
                                $excludeItems = @('Write-LogMessage', 'Get-CallStack', '<ScriptBlock>')
                                Get-PSCallStack | ForEach-Object {
                                    if ($PSItem.Command -notin $excludeItems) {
                                        $command = $PSitem.Command
                                        #TODO Rewrite to get the script name from the script itself
                                        if ($command -eq $Global:scriptName) {
                                            $command = 'Base'
                                        }
                                        elseif ([string]::IsNullOrEmpty($command)) {
                                            $command = '**Blank**'
                                        }
                                        $Location = $PSItem.Location
                                        $stack = $stack + "$command $Location; "
                                    }
                                }
                                return $stack
                            }
                            $stack = Get-CallStack
                            $stackMsg = "CallStack:`t$stack"
                            $arrstackMsg = $stackMsg.split(":`t", 2)
                            if ($arrMsg.Count -gt 1) {
                                $stackMsg = $arrstackMsg[0].PadRight($pad) + $arrstackMsg[1].trim()
                            }
                            Write-Verbose $stackMsg
                            $msgToWrite += "`n$LogTime"
                            $msgToWrite += "[$thread]`t"
                            $msgToWrite += "[STACK]`t`t$stackMsg"
                        }
                        if ($VerbosePreference -ne 'SilentlyContinue') {
                            Write-Verbose $MSG
                            $writeToFile = $true
                        }
                        else {
                            $writeToFile = $False
                        }
                    }
                    else {
                        $writeToFile = $False
                    }
                }
            }
            if ($Footer) {
                $msgToWrite += '`n======================================='
                Write-Information '=======================================' -InformationAction Continue
            }

            if ($writeToFile) {
                $written = $false
                $trywrite = 0
                do {
                    try {
                        $msgToWrite | Out-File -Append -FilePath $LogFile -ErrorAction SilentlyContinue -ErrorVariable err
                        $written = $true
                    }
                    catch {
                        $trywrite++
                        Start-Sleep -Milliseconds 1
                    }
                } until ($written -or $trywrite -gt 100)
                if (-not $written) {
                    Write-Warning "Unable to write to log file $ResultFile after 100 attempts"
                    throw $err
                }
            }
            if ($script:UseResultFile -and $writeResult) {
                $written = $false
                do {
                    try {
                        $msgToWrite | Out-File -Append -FilePath $ResultFile -ErrorAction SilentlyContinue -ErrorVariable err
                        $written = $true
                    }
                    catch {
                        $trywrite++
                        Start-Sleep -Milliseconds 1
                    }
                } until ($written -or $trywrite -gt 100)
                if (-not $written) {
                    Write-Warning "Unable to write to Result file $ResultFile after 100 attempts"
                    throw $err
                }
            }
            if ($UseVerboseFile -and $writeVerbose) {
                $writeToFile = $false
                do {
                    try {
                        $msgToWrite.replace('`n', '') | Out-File -Append -FilePath $verboseFile -ErrorAction SilentlyContinue -ErrorVariable err
                        $written = $true
                    }
                    catch {
                        $trywrite++
                        Start-Sleep -Milliseconds 1
                    }
                } until ($written -or $trywrite -gt 100)
                if (-not $written) {
                    Write-Warning "Unable to write to verbose file $verboseFile after 100 attempts"
                    throw $err
                }
            }
            if ($UseErrorFile -and $writeError) {
                $writeToFile = $false
                do {
                    try {
                        $msgToWrite | Out-File -Append -FilePath $errorFile -ErrorAction SilentlyContinue -ErrorVariable err
                        $written = $true
                    }
                    catch {
                        $trywrite++
                        Start-Sleep -Milliseconds 1
                    }
                } until ($written -or $trywrite -gt 100)
                if (-not $written) {
                    Write-Warning "Unable to write to error file $errorFile after 100 attempts"
                    throw $err
                }
            }
            if ($type -eq 'ErrorThrow') {
                throw $MSG
            }
        }
        catch {
            if ($type -eq 'ErrorThrow') {
                throw $MSG
            }
            throw $PSItem
        }
    }
}
#EndRegion '.\Public\Shared\Write-LogMessage.ps1' 413
#Region '.\Public\SIA\New-Connector.ps1' -1


function New-Connector {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,

        [Alias('url')]
        [string] $SIAURL,

        [Alias('header')]
        $LogonToken
    )

    Begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null
        $BaseURL = "$SIAURL/api"
        $ConnectorUrl = "$BaseURL/connectors/setup-script"

    }
    Process {

        $body = @{
            connector_type            = 'ON-PREMISE'
            connector_os              = 'windows'
            connector_pool_id         = '358ddcef-c128-404d-b69c-35a6ac37abe7'
            windows_installation_path = 'C:\Program Files\CyberArk\DPAConnector'
        }
        <#         $body = @{
            connector_type            = 'ON-PREMISE'
            connector_os              = 'windows'
            connector_pool_id         = ''
            expiration_minutes        = 15
            proxy_host                = ''
            proxy_port                = 443
            windows_installation_path = 'C:\Program Files\CyberArk\DPAConnector'
        }
#>
        if ($PSCmdlet.ShouldProcess($safeName, 'New-Connector')) {
            Write-LogMessage -type Debug -MSG 'Adding connector'
            Try {
                $RestParms = @{
                    Uri    = $ConnectorUrl
                    Method = 'POST'
                    Body   = ($body | ConvertTo-Json -Compress -Depth 99)
                }
                if ($null -ne $LogonToken -and $LogonToken -ne "") {
                    $RestParms.LogonToken = $LogonToken
                }
                $result = Invoke-Rest @RestParms -ErrAction SilentlyContinue
                Write-LogMessage -type Debug -MSG 'Successfully retrived setup script'
                Write-LogMessage -type Info -MSG "Connector Setup Script: $($result | ConvertTo-Json -Depth 99)"
            }
            Catch {
                Write-LogMessage -type Error -MSG "Failed to add safe `"$safeName`" due to an error: $PSitem"
                return
            }
            Write-LogMessage -type Verbose -MSG "Connector `"$safeName`" successfully created"
        }
        else {
            Write-LogMessage -type Warning -MSG 'Skipping creation of connect due to confirmation being denied'
        }
    }
}
#EndRegion '.\Public\SIA\New-Connector.ps1' 65

