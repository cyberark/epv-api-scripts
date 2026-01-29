<#
.SYNOPSIS
    IdentityAuth - CyberArk Identity Authentication Module

.DESCRIPTION
    Authentication module for CyberArk Identity Security Platform Shared Services (ISPSS).
    Supports OAuth, UP, MFA, and OOBAUTHPIN authentication methods.

.NOTES
    Version:        2.0.0
    Generated:      2026-01-28 23:44:30
    Build Process:  Combined from source files in G:\epv-api-scripts\Identity Authentication\v2-Modernized\PS5.1/
#>

#Requires -Version 5.1

# Set strict mode
Set-StrictMode -Version Latest

# Module-level variables
$script:CurrentSession = $null


# Region: Private - ConvertFrom-SessionToHeaders
#Requires -Version 5.1
<#
.SYNOPSIS
    Convert session hashtable to authorization headers

.DESCRIPTION
    Extracts token from session hashtable and constructs authorization headers
    with X-IDAP-NATIVE-CLIENT header for Privilege Cloud APIs.

.PARAMETER Session
    Session hashtable containing Token and other metadata

.OUTPUTS
    Hashtable with Authorization and X-IDAP-NATIVE-CLIENT headers

.EXAMPLE
    $headers = ConvertFrom-SessionToHeaders -Session $script:CurrentSession

.NOTES
    Private function - Internal use only
#>
function ConvertFrom-SessionToHeaders {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Session
    )

    Write-Verbose "Converting session to headers"

    # PS5.1: Check expiry manually (no IsExpired() method)
    if ($Session.TokenExpiry -and ((Get-Date) -gt $Session.TokenExpiry)) {
        throw "Session token has expired. Please re-authenticate."
    }

    return @{
        'Authorization'        = "Bearer $($Session.Token)"
        'X-IDAP-NATIVE-CLIENT' = 'true'
    }
}

# EndRegion: Private - ConvertFrom-SessionToHeaders


# Region: Private - Format-Token
#Requires -Version 5.1
<#
.SYNOPSIS
    Formats Identity API token response into authorization headers

.DESCRIPTION
    Extracts Bearer token from API response and constructs authorization headers
    for use with CyberArk Privilege Cloud APIs.

.PARAMETER Token
    Raw token string or token response object from Identity API

.OUTPUTS
    Hashtable with Authorization and X-IDAP-NATIVE-CLIENT headers

.EXAMPLE
    $headers = Format-Token -Token $response.access_token

.NOTES
    Private function - Internal use only
#>
function Format-Token {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [object]$Token
    )

    # PS5.1: No ternary operator
    if ($Token -is [string]) {
        $tokenString = $Token
    }
    else {
        $tokenString = $Token.ToString()
    }

    Write-Verbose "Formatting token for authorization header"

    return @{
        'Authorization'        = "Bearer $tokenString"
        'X-IDAP-NATIVE-CLIENT' = 'true'
    }
}

# EndRegion: Private - Format-Token


# Region: Private - Invoke-AdvancedAuthBody
#Requires -Version 5.1
<#
.SYNOPSIS
    Handles AdvanceAuthentication API calls

.DESCRIPTION
    Processes authentication mechanism and submits answer via AdvanceAuthentication endpoint.
    Handles text answers, push notifications with polling, and other challenge types.

.PARAMETER SessionId
    Identity session ID from StartAuthentication

.PARAMETER Mechanism
    Authentication mechanism object containing MechanismId, Name, AnswerType

.PARAMETER IdentityURL
    Identity tenant base URL

.PARAMETER UPCreds
    Optional PSCredential for Username/Password mechanism

.OUTPUTS
    API response object with authentication result

.EXAMPLE
    $response = Invoke-AdvancedAuthBody -SessionId $sessionId -Mechanism $mech -IdentityURL $url

.NOTES
    Private function - Internal use only
    Used by: Invoke-Challenge, OOBAUTHPIN flow
#>
function Invoke-AdvancedAuthBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SessionId,

        [Parameter(Mandatory)]
        [PSCustomObject]$Mechanism,

        [Parameter(Mandatory)]
        [string]$IdentityURL,

        [Parameter()]
        [PSCredential]$UPCreds
    )

    $mechanismId = $Mechanism.MechanismId
    $advanceAuthUrl = "$IdentityURL/Security/AdvanceAuthentication"

    Write-Verbose "Processing mechanism: $($Mechanism.Name) (Type: $($Mechanism.AnswerType))"

    if ($Mechanism.AnswerType -eq 'StartTextOob') {
        # Push notification flow
        $body = @{
            SessionId   = $SessionId
            MechanismId = $mechanismId
            Action      = 'StartOOB'
        }

        Write-Host 'Waiting for push notification approval...'
        $response = Invoke-Rest -Uri $advanceAuthUrl -Method Post -Body $body

        # Poll for push approval
        while ($response.Result.Summary -eq 'OobPending') {
            Start-Sleep -Seconds 2
            Write-Verbose 'Polling for push approval...'

            $pollBody = @{
                SessionId   = $SessionId
                MechanismId = $mechanismId
                Action      = 'Poll'
            }

            $response = Invoke-Rest -Uri $advanceAuthUrl -Method Post -Body $pollBody
            Write-Verbose "Poll status: $($response.Result.Summary)"
        }

        return $response
    }
    elseif ($Mechanism.AnswerType -eq 'Text') {
        # Text answer (password, OTP, etc.)
        $action = 'Answer'

        if ($Mechanism.Name -eq 'UP' -and $UPCreds) {
            Write-Verbose 'Using stored UP credentials'
            $answer = $UPCreds.Password
        }
        else {
            # PS5.1: No ternary operator
            if ($Mechanism.Name -eq 'UP') {
                $promptText = 'Password'
            }
            elseif ($Mechanism.Name -eq 'OTP') {
                $promptText = 'OTP code'
            }
            else {
                $promptText = 'Answer'
            }
            $answer = Read-Host "Enter $promptText" -AsSecureString
        }

        # Convert SecureString to plain text
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($answer)
        $plainAnswer = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

        $body = @{
            SessionId   = $SessionId
            MechanismId = $mechanismId
            Action      = $action
            Answer      = $plainAnswer
        }

        $response = Invoke-Rest -Uri $advanceAuthUrl -Method Post -Body $body

        # Clear sensitive data
        $plainAnswer = $null
        $body = $null

        return $response
    }
    else {
        throw "Unsupported AnswerType: $($Mechanism.AnswerType)"
    }
}

# EndRegion: Private - Invoke-AdvancedAuthBody


# Region: Private - Invoke-Challenge
#Requires -Version 5.1
<#
.SYNOPSIS
    Processes authentication challenges from Identity API

.DESCRIPTION
    Iterates through challenges array, presents mechanism options to user,
    and submits answers via AdvanceAuthentication. Handles recursive challenges
    until token is received.

.PARAMETER IdaptiveResponse
    StartAuthentication response containing challenges array

.PARAMETER IdentityURL
    Identity tenant base URL

.PARAMETER UPCreds
    Optional PSCredential for Username/Password authentication

.OUTPUTS
    API response object containing authentication token

.EXAMPLE
    $response = Invoke-Challenge -IdaptiveResponse $startAuthResponse -IdentityURL $url

.NOTES
    Private function - Internal use only
    Used by: Get-IdentityHeader (standard flow)
#>
function Invoke-Challenge {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$IdaptiveResponse,

        [Parameter(Mandatory)]
        [string]$IdentityURL,

        [Parameter()]
        [PSCredential]$UPCreds
    )

    $sessionId = $IdaptiveResponse.Result.SessionId
    Write-Verbose "Processing challenges for session: $sessionId"

    $challengeNumber = 1
    $finalResponse = $null

    foreach ($challenge in $IdaptiveResponse.Result.Challenges) {
        Write-Host "Challenge $challengeNumber"
        $mechanisms = $challenge.mechanisms
        $mechanismCount = $mechanisms.Count

        # Select mechanism
        if ($mechanismCount -gt 1) {
            Write-Host "There are $mechanismCount options to choose from:"

            $i = 1
            foreach ($mech in $mechanisms) {
                Write-Host "$i - $($mech.Name) - $($mech.PromptMechChosen)"
                $i++
            }

            $option = $null
            while ($option -gt $mechanismCount -or $option -lt 1 -or $null -eq $option) {
                $userInput = Read-Host "Please enter option number (1-$mechanismCount)"
                try {
                    $option = [int]$userInput
                }
                catch {
                    Write-Host "Invalid input. Please enter a number."
                }
            }

            $selectedMechanism = $mechanisms[$option - 1]
        }
        else {
            $selectedMechanism = $mechanisms[0]
            Write-Host "$($selectedMechanism.Name) - $($selectedMechanism.PromptMechChosen)"
        }

        # Process the selected mechanism
        $advanceAuthParams = @{
            SessionId   = $sessionId
            Mechanism   = $selectedMechanism
            IdentityURL = $IdentityURL
            UPCreds     = $UPCreds
        }
        $finalResponse = Invoke-AdvancedAuthBody @advanceAuthParams

        Write-Verbose "Challenge response: $($finalResponse | ConvertTo-Json -Depth 5 -Compress)"

        # Check if we have a token (successful authentication)
        if ($finalResponse.PSObject.Properties['success'] -and
            $finalResponse.success -and
            $finalResponse.Result.Token) {
            Write-Verbose "Token received successfully"
            return $finalResponse
        }

        $challengeNumber++
    }

    # If we get here, no token was received
    if (-not $finalResponse.success) {
        throw "Authentication failed: $($finalResponse.Message)"
    }

    return $finalResponse
}

# EndRegion: Private - Invoke-Challenge


# Region: Private - Invoke-OOBAUTHPIN
#Requires -Version 5.1
<#
.SYNOPSIS
    Handles OOBAUTHPIN (SAML + PIN) authentication flow

.DESCRIPTION
    Processes OOBAUTHPIN authentication by:
    1. Displaying short URL for user to complete SAML authentication
    2. Prompting for PIN received via email/SMS
    3. Submitting PIN to complete authentication
    4. Returning token response

.PARAMETER IdaptiveResponse
    StartAuthentication response containing IdpRedirectShortUrl and session IDs

.PARAMETER IdentityURL
    Identity tenant base URL

.PARAMETER PIN
    Optional pre-provided PIN code (for automation scenarios)

.OUTPUTS
    API response object containing authentication token

.EXAMPLE
    $response = Invoke-OOBAUTHPIN -IdaptiveResponse $startAuthResponse -IdentityURL $url

.NOTES
    Private function - Internal use only
    Used by: Get-IdentityHeader (OOBAUTHPIN flow)
#>
function Invoke-OOBAUTHPIN {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$IdaptiveResponse,

        [Parameter(Mandatory)]
        [string]$IdentityURL,

        [Parameter()]
        [string]$PIN
    )

    # Extract required session information
    $idpRedirectShortUrl = $IdaptiveResponse.Result.IdpRedirectShortUrl
    $sessionId = $IdaptiveResponse.Result.SessionId
    $idpLoginSessionId = $IdaptiveResponse.Result.IdpLoginSessionId

    Write-Verbose "OOBAUTHPIN Flow Started"
    Write-Verbose "Session ID: $sessionId"
    Write-Verbose "IDP Login Session ID: $idpLoginSessionId"

    if ([string]::IsNullOrEmpty($idpRedirectShortUrl)) {
        throw "IdpRedirectShortUrl is empty. Cannot proceed with OOBAUTHPIN authentication."
    }

    # Display instructions to user
    Write-Host ""
    Write-Host ("=" * 80)
    Write-Host "OOBAUTHPIN Authentication Required"
    Write-Host ("=" * 80)
    Write-Host ""
    Write-Host "Please complete the following steps:"
    Write-Host "  1. Open this URL in your browser: $idpRedirectShortUrl"
    Write-Host "  2. Complete SAML authentication"
    Write-Host "  3. You will receive a PIN code via email or SMS"
    Write-Host "  4. Enter the PIN code below"
    Write-Host ""

    # Attempt to open browser automatically
    try {
        Start-Process $idpRedirectShortUrl -ErrorAction SilentlyContinue
        Write-Host "Browser opened automatically. If not, copy the URL above."
    }
    catch {
        Write-Verbose "Could not auto-open browser: $($_.Exception.Message)"
        Write-Host "Please manually open the URL in your browser."
    }

    Write-Host ""

    # Get PIN from user or parameter
    if ([string]::IsNullOrEmpty($PIN)) {
        $valid = $false
        do {
            $inputValue = Read-Host "Enter PIN code (numbers only)"
            $inputValue = $inputValue.Trim()

            if ($inputValue -match '^\d+$') {
                $pinCode = $inputValue
                $valid = $true
            }
            else {
                Write-Host "Invalid input. Please enter numbers only."
            }
        }
        until ($valid)
    }
    else {
        $pinCode = $PIN
        Write-Verbose "Using provided PIN parameter"
    }

    Write-Verbose "PIN received, submitting to Identity..."

    # Submit PIN to AdvanceAuthentication
    $advanceAuthUrl = "$IdentityURL/Security/AdvanceAuthentication"
    $pinBody = @{
        SessionId   = $idpLoginSessionId
        MechanismId = 'OOBAUTHPIN'
        Action      = 'Answer'
        Answer      = $pinCode
    }

    try {
        $pinResponse = Invoke-Rest -Uri $advanceAuthUrl -Method Post -Body $pinBody
        Write-Verbose "PIN submitted successfully"

        # Check if token received
        if ($pinResponse.success -and $pinResponse.Result.Token) {
            Write-Verbose "OOBAUTHPIN authentication successful"
            return $pinResponse
        }
        elseif ($pinResponse.Result.Challenges) {
            # Additional challenges required
            Write-Verbose "Additional challenges detected after PIN submission"
            throw "Additional challenges after OOBAUTHPIN not yet supported. Response: $($pinResponse | ConvertTo-Json -Depth 5)"
        }
        else {
            throw "PIN authentication failed: $($pinResponse.Message)"
        }
    }
    catch {
        Write-Verbose "PIN submission failed: $($_.Exception.Message)"
        throw "OOBAUTHPIN authentication failed: $($_.Exception.Message)"
    }
}

# EndRegion: Private - Invoke-OOBAUTHPIN


# Region: Private - Invoke-Rest
#Requires -Version 5.1
<#
.SYNOPSIS
    Centralized REST API call wrapper with logging

.DESCRIPTION
    Makes REST API calls using splatting pattern with consistent error handling
    and optional verbose logging.

.PARAMETER Uri
    API endpoint URI

.PARAMETER Method
    HTTP method (Get, Post, Put, Delete)

.PARAMETER Body
    Request body (string or object to be converted to JSON)

.PARAMETER Headers
    Request headers hashtable

.OUTPUTS
    API response object

.EXAMPLE
    $response = Invoke-Rest -Uri $url -Method Post -Body $jsonBody -Headers $headers

.NOTES
    Private function - Internal use only
#>
function Invoke-Rest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [ValidateSet('Get', 'Post', 'Put', 'Delete', 'Patch')]
        [string]$Method,

        [Parameter()]
        [object]$Body,

        [Parameter()]
        [hashtable]$Headers
    )

    Write-Verbose "API Call: $Method $Uri"

    $restParams = @{
        Uri         = $Uri
        Method      = $Method
        ContentType = 'application/json'
        TimeoutSec  = 30
    }

    if ($Headers) {
        $restParams.Headers = $Headers
        Write-Verbose "Headers: $(($Headers.Keys | ForEach-Object { "$_=$($Headers[$_])" }) -join ', ')"
    }

    if ($Body) {
        if ($Body -is [string]) {
            $restParams.Body = $Body
        }
        else {
            $restParams.Body = $Body | ConvertTo-Json -Depth 10 -Compress
        }
        Write-Verbose "Body: $($restParams.Body)"
    }

    try {
        $response = Invoke-RestMethod @restParams
        Write-Verbose "Response received: $($response | ConvertTo-Json -Depth 5 -Compress)"
        return $response
    }
    catch {
        Write-Verbose "API Error: $($_.Exception.Message)"
        throw
    }
}

# EndRegion: Private - Invoke-Rest


# Region: Private - New-IdentitySession
#Requires -Version 5.1
<#
.SYNOPSIS
    Create new Identity session hashtable

.DESCRIPTION
    Creates a new session hashtable with all required properties for session state management.
    Used after successful authentication to store session data.

.PARAMETER Properties
    Hashtable containing session properties (Token, TokenExpiry, IdentityURL, etc.)

.OUTPUTS
    Hashtable with complete session structure

.EXAMPLE
    $session = New-IdentitySession -Properties @{
        Token = $token
        TokenExpiry = (Get-Date).AddSeconds(3600)
        IdentityURL = $identityUrl
        PCloudURL = $pcloudUrl
        Username = $username
        AuthMethod = 'OAuth'
    }

.NOTES
    Private function - Internal use only
#>
function New-IdentitySession {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Properties
    )

    Write-Verbose "Creating new Identity session for user: $($Properties.Username)"

    # PS5.1: Use hashtable instead of class
    $session = @{
        Token             = $Properties.Token
        TokenExpiry       = $Properties.TokenExpiry
        IdentityURL       = $Properties.IdentityURL
        PCloudURL         = $Properties.PCloudURL
        Username          = $Properties.Username
        SessionId         = $Properties.SessionId
        AuthMethod        = $Properties.AuthMethod
        StoredCredentials = $Properties.StoredCredentials
        Metadata          = @{
            CreatedAt     = Get-Date
            LastRefreshed = Get-Date
            RefreshCount  = 0
            RefreshToken  = $null
        }
    }

    Write-Verbose "Session created. Expires: $($session.TokenExpiry)"

    return $session
}

# EndRegion: Private - New-IdentitySession


# Region: Private - Update-IdentitySession
#Requires -Version 5.1
<#
.SYNOPSIS
    Update session with refreshed token

.DESCRIPTION
    Updates an existing session hashtable with new token and expiry.
    Used for OAuth token refresh to extend session lifetime.

.PARAMETER Session
    Session hashtable to update

.EXAMPLE
    Update-IdentitySession -Session $script:CurrentSession

.NOTES
    Private function - Internal use only
    Used by: OAuth token refresh logic
#>
function Update-IdentitySession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Session
    )

    # TODO: Implementation
    throw "Not yet implemented"
}

# EndRegion: Private - Update-IdentitySession


# Region: Public - Clear-IdentitySession
#Requires -Version 5.1
<#
.SYNOPSIS
    Clears current Identity session

.DESCRIPTION
    Clears the current session from memory and optionally calls logout endpoint
    to invalidate token on server.

.PARAMETER NoLogout
    Skip calling logout endpoint (only clear local session)

.EXAMPLE
    Clear-IdentitySession

.EXAMPLE
    Clear-IdentitySession -NoLogout

.NOTES
    Public function - Exported
#>
function Clear-IdentitySession {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$NoLogout
    )

    # TODO: Implementation
    throw "Not yet implemented"
}

# EndRegion: Public - Clear-IdentitySession


# Region: Public - Get-IdentityHeader
#Requires -Version 5.1
<#
.SYNOPSIS
    Main authentication entry point for CyberArk Identity

.DESCRIPTION
    Authenticates to CyberArk Identity and returns Bearer token for Privilege Cloud APIs.
    Supports multiple authentication methods:
    - OAuth client credentials
    - Username/Password
    - MFA (OTP, Push, etc.)
    - OOBAUTHPIN (SAML with PIN)

.PARAMETER IdentityUserName
    Username for interactive authentication

.PARAMETER UPCreds
    PSCredential for Username/Password authentication

.PARAMETER OAuthCreds
    PSCredential containing OAuth Client ID (username) and Client Secret (password)

.PARAMETER PCloudURL
    Privilege Cloud URL (e.g., https://subdomain.cyberark.cloud)

.PARAMETER IdentityTenantURL
    Identity tenant URL (optional, derived from PCloudURL if not provided)

.PARAMETER ForceNewSession
    Forces new authentication even if valid cached session exists

.OUTPUTS
    String - Bearer token for use with Privilege Cloud APIs

.EXAMPLE
    # OAuth authentication
    $token = Get-IdentityHeader -OAuthCreds $creds -PCloudURL 'https://subdomain.cyberark.cloud'

.EXAMPLE
    # Interactive authentication
    $token = Get-IdentityHeader -IdentityUserName 'user@company.com' -PCloudURL 'https://subdomain.cyberark.cloud'

.NOTES
    Public function - Exported
    Returns: Bearer token string (compatible with Accounts_Onboard_Utility.ps1 -logonToken parameter)
#>
function Get-IdentityHeader {
    [CmdletBinding(DefaultParameterSetName = 'IdentityUserName')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'IdentityUserName')]
        [string]$IdentityUserName,

        [Parameter(Mandatory, ParameterSetName = 'UPCreds')]
        [PSCredential]$UPCreds,

        [Parameter(Mandatory, ParameterSetName = 'OAuthCreds')]
        [PSCredential]$OAuthCreds,

        [Parameter()]
        [string]$PIN,

        [Parameter(Mandatory)]
        [string]$PCloudURL,

        [Parameter()]
        [string]$IdentityTenantURL,

        [Parameter()]
        [switch]$ForceNewSession
    )

    # Check for existing session
    if (-not $ForceNewSession -and $script:CurrentSession) {
        $isExpired = $script:CurrentSession.TokenExpiry -and ((Get-Date) -gt $script:CurrentSession.TokenExpiry)
        if (-not $isExpired) {
            Write-Verbose 'Using existing session token'
            $headers = ConvertFrom-SessionToHeaders -Session $script:CurrentSession
            return $headers.Authorization
        }
        else {
            Write-Verbose 'Session expired, re-authenticating'
        }
    }

    # Get Identity URL
    if (-not $IdentityTenantURL) {
        $IdentityTenantURL = Get-IdentityURL -PCloudURL $PCloudURL
    }

    # PS5.1: No ternary operator
    if ($IdentityTenantURL -match '^https://') {
        $identityBaseUrl = $IdentityTenantURL
    }
    else {
        $identityBaseUrl = "https://$IdentityTenantURL"
    }
    Write-Verbose "Identity URL: $identityBaseUrl"

    # OAuth flow
    if ($PSCmdlet.ParameterSetName -eq 'OAuthCreds') {
        Write-Verbose 'Using OAuth authentication'

        $clientId = $OAuthCreds.UserName
        $clientSecret = $OAuthCreds.GetNetworkCredential().Password

        $body = @{
            grant_type    = 'client_credentials'
            client_id     = $clientId
            client_secret = $clientSecret
        }

        $tokenUrl = "$identityBaseUrl/oauth2/platformtoken"
        $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded'

        $token = $response.access_token
        # PS5.1: No null coalescing
        if ($response.expires_in) {
            $expiresIn = $response.expires_in
        }
        else {
            $expiresIn = 3600
        }

        # Create session - OAuth has no SessionId
        $session = New-IdentitySession -Properties @{
            Token             = $token
            TokenExpiry       = (Get-Date).AddSeconds($expiresIn)
            IdentityURL       = $identityBaseUrl
            PCloudURL         = $PCloudURL
            Username          = $clientId
            AuthMethod        = 'OAuth'
            StoredCredentials = $OAuthCreds
            SessionId         = $null
        }

        # Safe property check for refresh token
        if ($response.PSObject.Properties['refresh_token']) {
            $session.Metadata.RefreshToken = $response.refresh_token
        }

        $script:CurrentSession = $session
        $headers = Format-Token -Token $token
        return $headers
    }

    # Interactive authentication
    # PS5.1: No ternary operator
    if ($PSCmdlet.ParameterSetName -eq 'UPCreds') {
        $username = $UPCreds.UserName
    }
    else {
        $username = $IdentityUserName
    }
    Write-Verbose "Authenticating user: $username"

    $startAuthUrl = "$identityBaseUrl/Security/StartAuthentication"
    $startAuthBody = @{
        User    = $username
        Version = '1.0'
    }
    $requestHeaders = @{
        'Content-Type'         = 'application/json'
        'X-IDAP-NATIVE-CLIENT' = 'true'
        OobIdPAuth             = 'true'
    }

    $idaptiveResponse = Invoke-Rest -Uri $startAuthUrl -Method Post -Body $startAuthBody -Headers $requestHeaders

    # Check for SAML/OOBAUTHPIN flow (property may not exist in all responses)
    $hasIdpRedirect = $null -ne $idaptiveResponse.Result.PSObject.Properties['IdpRedirectShortUrl']

    if ($hasIdpRedirect -and -not [string]::IsNullOrEmpty($idaptiveResponse.Result.IdpRedirectShortUrl)) {
        Write-Verbose 'OOBAUTHPIN flow detected'

        $oobParams = @{
            IdaptiveResponse = $idaptiveResponse
            IdentityURL      = $identityBaseUrl
            PIN              = $PIN
        }
        $answerResponse = Invoke-OOBAUTHPIN @oobParams

        if ($answerResponse.success -and $answerResponse.Result.Token) {
            $token = $answerResponse.Result.Token
            # PS5.1: No ternary operator
            if ($answerResponse.Result.PSObject.Properties['TokenLifetime']) {
                $tokenLifetime = $answerResponse.Result.TokenLifetime
            }
            else {
                $tokenLifetime = 3600
            }

            # Create session
            $session = New-IdentitySession -Properties @{
                Token             = $token
                TokenExpiry       = (Get-Date).AddSeconds($tokenLifetime)
                IdentityURL       = $identityBaseUrl
                PCloudURL         = $PCloudURL
                Username          = $username
                SessionId         = $idaptiveResponse.Result.SessionId
                AuthMethod        = 'OOBAUTHPIN'
                StoredCredentials = $null
            }

            if ($answerResponse.Result.PSObject.Properties['RefreshToken']) {
                $session.Metadata.RefreshToken = $answerResponse.Result.RefreshToken
            }
            $script:CurrentSession = $session
            $headers = Format-Token -Token $token
            return $headers
        }
        else {
            $errorMsg = if ($answerResponse.PSObject.Properties['Message']) { $answerResponse.Message } else { 'Unknown error' }
            throw "OOBAUTHPIN authentication failed: $errorMsg"
        }
    }

    $sessionId = $idaptiveResponse.Result.SessionId
    Write-Verbose "Session ID: $sessionId"

    # Standard challenge flow
    $challengeParams = @{
        IdaptiveResponse = $idaptiveResponse
        IdentityURL      = $identityBaseUrl
        UPCreds          = $UPCreds
    }
    $answerResponse = Invoke-Challenge @challengeParams

    Write-Verbose "Response properties: $($answerResponse.PSObject.Properties.Name -join ', ')"
    Write-Verbose "Response JSON: $($answerResponse | ConvertTo-Json -Depth 5 -Compress)"

    if ($answerResponse.PSObject.Properties['success'] -and $answerResponse.success -and $answerResponse.Result.Token) {
        $token = $answerResponse.Result.Token
        # PS5.1: No ternary operator
        if ($answerResponse.Result.PSObject.Properties['TokenLifetime']) {
            $tokenLifetime = $answerResponse.Result.TokenLifetime
        }
        else {
            $tokenLifetime = 3600
        }

        # Create session
        $session = New-IdentitySession -Properties @{
            Token             = $token
            TokenExpiry       = (Get-Date).AddSeconds($tokenLifetime)
            IdentityURL       = $identityBaseUrl
            PCloudURL         = $PCloudURL
            Username          = $username
            SessionId         = $sessionId
            AuthMethod        = 'UP'
            StoredCredentials = $null
        }

        $script:CurrentSession = $session
        $headers = Format-Token -Token $token
        return $headers
    }
    else {
        # Gather error details - safely check properties
        $hasSuccess = $null -ne $answerResponse.PSObject.Properties['success']
        $successValue = if ($hasSuccess) { $answerResponse.success } else { 'Property missing' }

        $hasResult = $null -ne $answerResponse.PSObject.Properties['Result']
        $hasToken = if ($hasResult -and $answerResponse.Result) {
            $null -ne $answerResponse.Result.PSObject.Properties['Token'] -and $answerResponse.Result.Token
        } else {
            $false
        }

        # Try to extract error message
        if ($answerResponse.PSObject.Properties['Message']) {
            $errorMsg = $answerResponse.Message
        } elseif ($hasResult -and $answerResponse.Result.PSObject.Properties['Message']) {
            $errorMsg = $answerResponse.Result.Message
        } else {
            $errorMsg = "Success=$successValue, HasToken=$hasToken. Use -Verbose to see full response."
        }
        throw "Authentication failed: $errorMsg"
    }
}

# EndRegion: Public - Get-IdentityHeader


# Region: Public - Get-IdentitySession
#Requires -Version 5.1
<#
.SYNOPSIS
    Retrieves current Identity session details

.DESCRIPTION
    Returns current session information including token expiry, authentication method,
    and other metadata.

.OUTPUTS
    Hashtable - Current session details

.EXAMPLE
    $session = Get-IdentitySession

.NOTES
    Public function - Exported
#>
function Get-IdentitySession {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    # TODO: Implementation
    throw "Not yet implemented"
}

# EndRegion: Public - Get-IdentitySession


# Region: Public - Get-IdentityURL
#Requires -Version 5.1
<#
.SYNOPSIS
    Discovers Identity URL from Privilege Cloud URL

.DESCRIPTION
    Uses HTTP redirect discovery to find Identity tenant URL from Privilege Cloud URL.
    Makes a request to PCloud and follows redirect to extract Identity subdomain.

.PARAMETER PCloudURL
    Privilege Cloud URL (e.g., https://subdomain.cyberark.cloud)

.OUTPUTS
    String - Identity URL (e.g., https://abc123.id.cyberark.cloud)

.EXAMPLE
    $identityUrl = Get-IdentityURL -PCloudURL 'https://subdomain.cyberark.cloud'

.NOTES
    Public function - Exported
#>
function Get-IdentityURL {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$PCloudURL
    )

    Write-Verbose "Discovering Identity URL from: $PCloudURL"

    $PCloudURL.ToLower() -match '^(?:https|http):\/\/(?<sub>.*)(.privilegecloud).cyberark.(?<top>cloud|com)\/(privilegecloud|passwordvault)(\/?)$' | Out-Null
    $pcloudBase = "https://$($matches['sub']).cyberark.$($matches['top'])"

    Write-Verbose "PCloud base URL: $pcloudBase"

    try {
        $response = Invoke-WebRequest -Uri $pcloudBase -UseBasicParsing -ErrorAction Stop
        Write-Verbose "Response Status: $($response.StatusCode)"
        Write-Verbose "Response Type: $($response.GetType().FullName)"

        # PS5.1: Try different property paths
        if ($response.BaseResponse.ResponseUri) {
            $identityHost = $response.BaseResponse.ResponseUri.Host
            Write-Verbose "Using BaseResponse.ResponseUri.Host"
        }
        elseif ($response.BaseResponse.RequestMessage.RequestUri) {
            $identityHost = $response.BaseResponse.RequestMessage.RequestUri.Host
            Write-Verbose "Using BaseResponse.RequestMessage.RequestUri.Host"
        }
        elseif ($response.Headers.Location) {
            $locationUri = [Uri]$response.Headers.Location
            $identityHost = $locationUri.Host
            Write-Verbose "Using Headers.Location"
        }
        else {
            throw "Could not extract Identity URL from response. Response properties: $($response.PSObject.Properties.Name -join ', ')"
        }
    }
    catch {
        if ($_.Exception.Response) {
            $response = $_.Exception.Response
            Write-Verbose "Caught redirect response: $($response.StatusCode)"

            # Try to extract from redirect response
            if ($response.ResponseUri) {
                $identityHost = $response.ResponseUri.Host
            }
            elseif ($response.Headers -and $response.Headers.Location) {
                $locationUri = [Uri]$response.Headers.Location
                $identityHost = $locationUri.Host
            }
            else {
                throw "Failed to extract Identity URL from redirect: $($_.Exception.Message)"
            }
        }
        else {
            throw "Failed to connect to PCloud URL: $($_.Exception.Message)"
        }
    }

    Write-Verbose "Discovered Identity host: $identityHost"

    return "https://$identityHost"
}

# EndRegion: Public - Get-IdentityURL


# Region: Public - Test-IdentityToken
#Requires -Version 5.1
<#
.SYNOPSIS
    Validates Identity token

.DESCRIPTION
    Validates token format and checks if token is expired.
    Optionally decodes JWT claims.

.PARAMETER Token
    Bearer token to validate

.PARAMETER IdentityURL
    Identity tenant URL (optional, for additional validation)

.OUTPUTS
    Boolean - True if token is valid and not expired

.EXAMPLE
    $isValid = Test-IdentityToken -Token $token

.NOTES
    Public function - Exported
#>
function Test-IdentityToken {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$Token,

        [Parameter()]
        [string]$IdentityURL
    )

    # TODO: Implementation
    throw "Not yet implemented"
}

# EndRegion: Public - Test-IdentityToken


# Export public functions
Export-ModuleMember -Function @(
    'Clear-IdentitySession',
    'Get-IdentityHeader',
    'Get-IdentitySession',
    'Get-IdentityURL',
    'Test-IdentityToken'
)
