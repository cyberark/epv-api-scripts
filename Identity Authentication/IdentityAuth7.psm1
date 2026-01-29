<#
.SYNOPSIS
    IdentityAuth7 - CyberArk Identity Authentication Module

.DESCRIPTION
    Authentication module for CyberArk Identity Security Platform Shared Services (ISPSS).
    Supports OAuth, UP, MFA, and OOBAUTHPIN authentication methods.

.NOTES
    Version:        2.0.0
    Generated:      2026-01-28 23:44:30
    Build Process:  Combined from source files in G:\epv-api-scripts\Identity Authentication\v2-Modernized\PS7/
#>

#Requires -Version 7.0

# Set strict mode
Set-StrictMode -Version Latest

# Module-level variables
$script:CurrentSession = $null


# Region: Class - ChallengeInfo
#Requires -Version 7.0
<#
.SYNOPSIS
    Challenge information class

.DESCRIPTION
    Represents an authentication challenge with multiple mechanism options
#>

class ChallengeInfo {
    [string]$ChallengeId
    [array]$Mechanisms
    [string]$Type
    [hashtable]$Metadata = @{}

    # Constructor
    ChallengeInfo([PSCustomObject]$Challenge) {
        $this.ChallengeId = $Challenge.ChallengeId ?? [guid]::NewGuid().ToString()
        $this.Mechanisms = $Challenge.Mechanisms ?? @()
        $this.Type = $Challenge.Type ?? 'Unknown'
    }

    # Get mechanism by name
    [PSCustomObject] GetMechanismByName([string]$Name) {
        return $this.Mechanisms | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    }

    # Check if challenge has multiple mechanisms
    [bool] HasMultipleMechanisms() {
        return $this.Mechanisms.Count -gt 1
    }
}

# EndRegion: Class - ChallengeInfo


# Region: Class - IdentityAuthResponse
#Requires -Version 7.0
<#
.SYNOPSIS
    Identity authentication response class

.DESCRIPTION
    Represents a response from Identity authentication APIs
#>

class IdentityAuthResponse {
    [bool]$Success
    [string]$Message
    [PSCustomObject]$Result
    [hashtable]$ErrorInfo
    [int]$StatusCode
    [datetime]$Timestamp = [datetime]::Now

    # Constructor
    IdentityAuthResponse([PSCustomObject]$ApiResponse) {
        $this.Success = $ApiResponse.success ?? $false
        $this.Message = $ApiResponse.Message ?? ''
        $this.Result = $ApiResponse.Result
        $this.ErrorInfo = @{}
        $this.StatusCode = 200
    }

    # Extract token from response
    [string] ToToken() {
        if ($this.Success -and $this.Result.Token) {
            return $this.Result.Token
        }
        return $null
    }

    # Check if response contains challenges
    [bool] HasChallenges() {
        return $null -ne $this.Result.Challenges -and $this.Result.Challenges.Count -gt 0
    }
}

# EndRegion: Class - IdentityAuthResponse


# Region: Class - IdentitySession
#Requires -Version 7.0
<#
.SYNOPSIS
    Identity session class

.DESCRIPTION
    Represents an active Identity authentication session with full lifecycle management
#>

class IdentitySession {
    # Core authentication data
    [string]$Token
    [datetime]$TokenExpiry
    [string]$IdentityURL
    [string]$PCloudURL

    # User and session metadata
    [string]$Username
    [string]$SessionId
    [AuthenticationMechanism]$AuthMethod

    # Optional stored credentials (OAuth only for auto-refresh)
    [PSCredential]$StoredCredentials

    # Additional metadata
    [hashtable]$Metadata = @{
        CreatedAt = [datetime]::Now
        LastRefreshed = [datetime]::Now
        RefreshCount = 0
        PCloudVersion = $null
        TenantId = $null
        RefreshToken = $null
    }

    # Default constructor
    IdentitySession() { }

    # Constructor from hashtable
    IdentitySession([hashtable]$Properties) {
        $this.Token = $Properties.Token
        $this.TokenExpiry = $Properties.TokenExpiry
        $this.IdentityURL = $Properties.IdentityURL
        $this.PCloudURL = $Properties.PCloudURL ?? ''
        $this.Username = $Properties.Username
        $this.SessionId = $Properties.SessionId ?? ''
        $this.AuthMethod = $Properties.AuthMethod
        $this.StoredCredentials = $Properties.StoredCredentials ?? $null
    }

    # Check if token is expired
    [bool] IsExpired() {
        return (Get-Date) -gt $this.TokenExpiry
    }

    # Check if token is expiring soon
    [bool] IsExpiringSoon([int]$ThresholdSeconds = 60) {
        $expiryThreshold = (Get-Date).AddSeconds($ThresholdSeconds)
        return $this.TokenExpiry -lt $expiryThreshold
    }

    # Refresh OAuth token
    [void] Refresh() {
        if ($this.AuthMethod -eq [AuthenticationMechanism]::OAuth) {
            if ($null -ne $this.StoredCredentials) {
                Write-Verbose "Auto-refreshing OAuth token"

                $ClientId = $this.StoredCredentials.UserName
                $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($this.StoredCredentials.Password)
                $ClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

                try {
                    $body = "grant_type=client_credentials&client_id=$ClientId&client_secret=$ClientSecret"
                    $oauthParams = @{
                        Uri = "$($this.IdentityURL)/OAuth2/Token/$ClientId"
                        Method = 'Post'
                        ContentType = 'application/x-www-form-urlencoded'
                        Body = $body
                        ErrorAction = 'Stop'
                    }
                    $response = Invoke-RestMethod @oauthParams

                    $this.Token = $response.access_token
                    $this.TokenExpiry = (Get-Date).AddSeconds($response.expires_in)
                    $this.Metadata.LastRefreshed = Get-Date
                    $this.Metadata.RefreshCount++

                    Write-Verbose "OAuth token refreshed successfully (Refresh count: $($this.Metadata.RefreshCount))"
                } catch {
                    throw "Failed to refresh OAuth token: $($_.Exception.Message)"
                } finally {
                    if ($bstr) {
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                    }
                    $ClientSecret = $null
                }
            } else {
                throw "Cannot refresh: OAuth credentials not stored in session"
            }
        } else {
            throw "Cannot auto-refresh: AuthMethod '$($this.AuthMethod)' requires manual user interaction"
        }
    }

    # Get authorization header
    [hashtable] GetAuthHeader() {
        if ($this.IsExpired()) {
            throw "Token expired. Re-authentication required."
        }
        return @{
            'Authorization' = "Bearer $($this.Token)"
            'X-IDAP-NATIVE-CLIENT' = 'true'
        }
    }

    # Dispose and logout
    [void] Dispose() {
        Write-Verbose "Disposing Identity session for user: $($this.Username)"

        # Call logout endpoint
        try {
            $logoutUrl = "$($this.IdentityURL)/Security/logout"
            $logoutParams = @{
                Uri = $logoutUrl
                Method = 'Post'
                Headers = $this.GetAuthHeader()
                ErrorAction = 'SilentlyContinue'
            }
            Invoke-RestMethod @logoutParams | Out-Null
            Write-Verbose "Logout API call successful"
        } catch {
            Write-Verbose "Logout API call failed: $($_.Exception.Message)"
        }

        # Clear sensitive data
        $this.Token = $null
        $this.StoredCredentials = $null
        $this.SessionId = $null
        Write-Verbose "Session disposed"
    }
}

# EndRegion: Class - IdentitySession


# Region: Class - MechanismInfo
#Requires -Version 7.0
<#
.SYNOPSIS
    Mechanism information class

.DESCRIPTION
    Represents a single authentication mechanism option
#>

class MechanismInfo {
    [string]$MechanismId
    [string]$Name
    [string]$AnswerType
    [string]$PromptMechChosen
    [hashtable]$Properties = @{}

    # Constructor
    MechanismInfo([PSCustomObject]$Mechanism) {
        $this.MechanismId = $Mechanism.MechanismId
        $this.Name = $Mechanism.Name
        $this.AnswerType = $Mechanism.AnswerType
        $this.PromptMechChosen = $Mechanism.PromptMechChosen ?? $Mechanism.PromptSelectMech
    }

    # Check if mechanism requires user input
    [bool] RequiresUserInput() {
        return $this.AnswerType -eq 'Text'
    }

    # Check if mechanism is out-of-band (push notification)
    [bool] IsOOB() {
        return $this.AnswerType -like '*Oob*'
    }
}

# EndRegion: Class - MechanismInfo


# Region: Class - SessionManager
#Requires -Version 7.0
<#
.SYNOPSIS
    Session manager class

.DESCRIPTION
    Manages the current Identity session lifecycle
#>

class SessionManager {
    hidden [IdentitySession]$CurrentSession

    # Get current session
    [IdentitySession] GetSession() {
        return $this.CurrentSession
    }

    # Set current session
    [void] SetSession([IdentitySession]$Session) {
        $this.CurrentSession = $Session
        Write-Verbose "Session set for user: $($Session.Username)"
    }

    # Clear current session
    [void] ClearSession([bool]$Logout = $true) {
        if ($this.HasActiveSession()) {
            if ($Logout) {
                $this.CurrentSession.Dispose()
            }
            $this.CurrentSession = $null
            Write-Verbose "Session cleared"
        }
    }

    # Check if there's an active session
    [bool] HasActiveSession() {
        return $null -ne $this.CurrentSession -and -not $this.CurrentSession.IsExpired()
    }

    # Refresh token if needed
    [bool] RefreshIfNeeded() {
        if ($this.HasActiveSession() -and $this.CurrentSession.IsExpiringSoon()) {
            try {
                $this.CurrentSession.Refresh()
                return $true
            } catch {
                Write-Verbose "Failed to refresh session: $($_.Exception.Message)"
                return $false
            }
        }
        return $false
    }
}

# EndRegion: Class - SessionManager


# Region: Class - TokenValidator
#Requires -Version 7.0
<#
.SYNOPSIS
    Token validator class

.DESCRIPTION
    Validates Identity tokens and extracts claims
#>

class TokenValidator {
    # Validate token format (basic JWT structure check)
    static [bool] ValidateFormat([string]$Token) {
        if ([string]::IsNullOrEmpty($Token)) {
            return $false
        }

        # JWT tokens have 3 parts separated by dots
        $parts = $Token.Split('.')
        return $parts.Count -eq 3
    }

    # Validate token expiry
    static [bool] ValidateExpiry([datetime]$Expiry) {
        return (Get-Date) -lt $Expiry
    }

    # Get token claims (simplified - basic Base64 decode of payload)
    static [hashtable] GetTokenClaims([string]$Token) {
        try {
            $parts = $Token.Split('.')
            if ($parts.Count -ne 3) {
                return @{ Error = 'Invalid token format' }
            }

            # Decode payload (second part)
            $payload = $parts[1]
            # Add padding if needed
            while ($payload.Length % 4 -ne 0) {
                $payload += '='
            }

            $payloadBytes = [Convert]::FromBase64String($payload)
            $payloadJson = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
            $claims = $payloadJson | ConvertFrom-Json

            return @{
                Subject = $claims.sub
                Issuer = $claims.iss
                Audience = $claims.aud
                IssuedAt = $claims.iat
                Expiry = $claims.exp
            }
        } catch {
            return @{ Error = $_.Exception.Message }
        }
    }
}

# EndRegion: Class - TokenValidator


# Region: Enum - AuthenticationMechanism
#Requires -Version 7.0
<#
.SYNOPSIS
    Authentication mechanism enumeration

.DESCRIPTION
    Defines supported authentication mechanisms for CyberArk Identity
#>

enum AuthenticationMechanism {
    UP = 1                      # Username/Password
    OAuth = 2                   # OAuth client credentials
    EmailOTP = 3                # Email one-time password
    SMSOTP = 4                  # SMS one-time password
    PushNotification = 5        # Push notification to device
    SAML_Deprecated = 6         # Legacy SAML (deprecated)
    OOBAUTHPIN = 7              # Out-of-band authentication PIN
    PhoneCall = 8               # Phone call verification
    SecurityQuestions = 9       # Security questions
}

# EndRegion: Enum - AuthenticationMechanism


# Region: Enum - ChallengeType
#Requires -Version 7.0
<#
.SYNOPSIS
    Challenge type enumeration

.DESCRIPTION
    Defines types of authentication challenges from Identity API
#>

enum ChallengeType {
    Text = 1                    # Text-based answer (password, OTP, etc.)
    StartTextOob = 2            # Start text-based out-of-band (push notification)
    StartOob = 3                # Start out-of-band authentication
    Poll = 4                    # Poll for OOB completion
    Answer = 5                  # Submit answer to challenge
    SAML = 6                    # SAML redirect
}

# EndRegion: Enum - ChallengeType


# Region: Enum - MechanismType
#Requires -Version 7.0
<#
.SYNOPSIS
    Mechanism type enumeration

.DESCRIPTION
    Defines specific mechanism types returned by Identity API
#>

enum MechanismType {
    UP = 1                      # Username/Password
    OTP = 2                     # One-time password
    EMAIL = 3                   # Email verification
    SMS = 4                     # SMS verification
    PF = 5                      # Push notification (PushFactor)
    OATH = 6                    # OATH token
    RADIUS = 7                  # RADIUS authentication
    SQ = 8                      # Security questions
    SAML = 9                    # SAML
}

# EndRegion: Enum - MechanismType


# Region: Enum - SessionState
#Requires -Version 7.0
<#
.SYNOPSIS
    Session state enumeration

.DESCRIPTION
    Defines possible states of an Identity authentication session
#>

enum SessionState {
    NotAuthenticated = 0        # No active session
    Authenticating = 1          # Authentication in progress
    Authenticated = 2           # Successfully authenticated
    Expired = 3                 # Token expired
    RefreshRequired = 4         # Token needs refresh
    Invalid = 5                 # Session is invalid
}

# EndRegion: Enum - SessionState


# Region: Private - ConvertFrom-SessionToHeaders
#Requires -Version 7.0
<#
.SYNOPSIS
    Convert IdentitySession object to authorization headers

.DESCRIPTION
    Extracts token from IdentitySession class instance and constructs authorization headers
    with X-IDAP-NATIVE-CLIENT header for Privilege Cloud APIs.

.PARAMETER Session
    IdentitySession object containing Token and other metadata

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
        [IdentitySession]$Session
    )

    Write-Verbose "Converting session to headers"

    if ($Session.IsExpired()) {
        throw "Session token has expired. Please re-authenticate."
    }

    return $Session.GetAuthHeader()
}

# EndRegion: Private - ConvertFrom-SessionToHeaders


# Region: Private - Format-Token
#Requires -Version 7.0
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

    $tokenString = $Token -is [string] ? $Token : $Token.ToString()

    Write-Verbose "Formatting token for authorization header"

    return @{
        'Authorization' = "Bearer $tokenString"
        'X-IDAP-NATIVE-CLIENT' = 'true'
    }
}

# EndRegion: Private - Format-Token


# Region: Private - Invoke-AdvancedAuthBody
#Requires -Version 7.0
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

        Write-Information 'Waiting for push notification approval...'
        $response = Invoke-Rest -Uri $advanceAuthUrl -Method Post -Body $body

        # Poll for push approval
        while ($response.Result.Summary -eq 'OobPending') {
            Start-Sleep -Seconds 2
            Write-Information 'Polling for push approval...'

            $pollBody = @{
                SessionId   = $SessionId
                MechanismId = $mechanismId
                Action      = 'Poll'
            }

            $response = Invoke-Rest -Uri $advanceAuthUrl -Method Post -Body $pollBody
            Write-Verbose "Poll status: $($response.Result.Summary)"
        }

        return $response
    } elseif ($Mechanism.AnswerType -eq 'Text') {
        # Text answer (password, OTP, etc.)
        $action = 'Answer'

        if ($Mechanism.Name -eq 'UP' -and $UPCreds) {
            Write-Information 'Using stored UP credentials'
            $answer = $UPCreds.Password
        } else {
            $promptText = $Mechanism.Name -eq 'UP' ? 'Password' :
            ($Mechanism.Name -eq 'OTP' ? 'OTP code' : 'Answer')
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
    } else {
        throw "Unsupported AnswerType: $($Mechanism.AnswerType)"
    }
}

# EndRegion: Private - Invoke-AdvancedAuthBody


# Region: Private - Invoke-Challenge
#Requires -Version 7.0
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
    foreach ($challenge in $IdaptiveResponse.Result.Challenges) {
        Write-Information "Challenge $challengeNumber"
        $mechanisms = $challenge.mechanisms
        $mechanismCount = $mechanisms.Count

        # Select mechanism
        if ($mechanismCount -gt 1) {
            Write-Information "There are $mechanismCount options to choose from:"

            $i = 1
            foreach ($mech in $mechanisms) {
                Write-Information "$i - $($mech.Name) - $($mech.PromptMechChosen)"
                $i++
            }

            $option = $null
            while ($option -gt $mechanismCount -or $option -lt 1 -or $null -eq $option) {
                $userInput = Read-Host "Please enter option number (1-$mechanismCount)"
                try {
                    $option = [int]$userInput
                }
                catch {
                    Write-Information "Invalid input. Please enter a number."
                }
            }

            $selectedMechanism = $mechanisms[$option - 1]
        }
        else {
            $selectedMechanism = $mechanisms[0]
            Write-Information "$($selectedMechanism.Name) - $($selectedMechanism.PromptMechChosen)"
        }

        # Process the selected mechanism
        $advanceAuthParams = @{
            SessionId = $sessionId
            Mechanism = $selectedMechanism
            IdentityURL = $IdentityURL
            UPCreds = $UPCreds
        }
        $answerToResponse = Invoke-AdvancedAuthBody @advanceAuthParams

        Write-Verbose "Challenge response: $($answerToResponse | ConvertTo-Json -Depth 5 -Compress)"

        # Check if we have a token (successful authentication)
        if ($answerToResponse.PSObject.Properties['success'] -and $answerToResponse.success -and $answerToResponse.Result.Token) {
            Write-Verbose "Token received successfully"
            return $answerToResponse
        }

        $challengeNumber++
    }

    # If we get here, no token was received
    if (-not $answerToResponse.success) {
        throw "Authentication failed: $($answerToResponse.Message)"
    }

    return $answerToResponse
}

# EndRegion: Private - Invoke-Challenge


# Region: Private - Invoke-OOBAUTHPIN
#Requires -Version 7.0
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

    $InformationPreference = 'Continue'
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
    Write-Information ""
    Write-Information ("=" * 80)
    Write-Information "OOBAUTHPIN Authentication Required"
    Write-Information ("=" * 80)
    Write-Information ""
    Write-Information "Please complete the following steps:"
    Write-Information "  1. Open this URL in your browser: $idpRedirectShortUrl"
    Write-Information "  2. Complete SAML authentication"
    Write-Information "  3. You will receive a PIN code via email or SMS"
    Write-Information "  4. Enter the PIN code below"
    Write-Information ""
    Write-Information ""

    # Get PIN from user or parameter
    if ([string]::IsNullOrEmpty($PIN)) {
        $valid = $false
        do {
            $inputValue = Read-Host "Enter PIN code (numbers only)" -MaskInput
            $inputValue = $inputValue.Trim()

            if ($inputValue -match '^\d+$') {
                $pinCode = $inputValue
                $valid = $true
            }
            else {
                Write-Information "Invalid input. Please enter numbers only."
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
#Requires -Version 7.0
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
        Uri = $Uri
        Method = $Method
        ContentType = 'application/json'
        TimeoutSec = 30
    }

    if ($Headers) {
        $restParams.Headers = $Headers
        Write-Verbose "Headers: $(($Headers.Keys | ForEach-Object { "$_=$($Headers[$_])" }) -join ', ')"
    }

    if ($Body) {
        if ($Body -is [string]) {
            $restParams.Body = $Body
        } else {
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
#Requires -Version 7.0
<#
.SYNOPSIS
    Create new IdentitySession object

.DESCRIPTION
    Creates a new IdentitySession class instance with all required properties.
    Used after successful authentication to store session data.

.PARAMETER Properties
    Hashtable containing session properties (Token, TokenExpiry, IdentityURL, etc.)

.OUTPUTS
    IdentitySession object

.EXAMPLE
    $session = New-IdentitySession -Properties @{
        Token = $token
        TokenExpiry = (Get-Date).AddSeconds(3600)
        IdentityURL = $identityUrl
        PCloudURL = $pcloudUrl
        Username = $username
        AuthMethod = [AuthenticationMechanism]::OAuth
    }

.NOTES
    Private function - Internal use only
#>
function New-IdentitySession {
    [CmdletBinding()]
    [OutputType([IdentitySession])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Properties
    )

    Write-Verbose "Creating new IdentitySession for user: $($Properties.Username)"

    $session = [IdentitySession]::new($Properties)

    $session.Metadata.CreatedAt = Get-Date
    $session.Metadata.LastRefreshed = Get-Date
    $session.Metadata.RefreshCount = 0

    Write-Verbose "Session created. Expires: $($session.TokenExpiry)"

    return $session
}

# EndRegion: Private - New-IdentitySession


# Region: Private - Update-IdentitySession
#Requires -Version 7.0
<#
.SYNOPSIS
    Update IdentitySession with refreshed token

.DESCRIPTION
    Updates an existing IdentitySession object with new token and expiry.
    Used for OAuth token refresh to extend session lifetime.

.PARAMETER Session
    IdentitySession object to update

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
        [IdentitySession]$Session
    )

    Write-Verbose "Updating session with refreshed token"

    if ($Session.AuthMethod -ne [AuthenticationMechanism]::OAuth) {
        throw "Cannot auto-refresh: Only OAuth sessions support automatic refresh"
    }

    try {
        $Session.Refresh()
        Write-Verbose "Session refreshed successfully. New expiry: $($Session.TokenExpiry)"
    }
    catch {
        Write-Verbose "Session refresh failed: $($_.Exception.Message)"
        throw
    }
}

# EndRegion: Private - Update-IdentitySession


# Region: Public - Clear-IdentitySession
#Requires -Version 7.0
<#
.SYNOPSIS
    Clears current Identity session

.DESCRIPTION
    Clears the current session from memory and optionally calls logout endpoint
    to invalidate token on server. Uses SessionManager class for lifecycle management.

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

    if (-not $script:CurrentSession) {
        Write-Verbose "No active session to clear"
        return
    }

    Write-Verbose "Clearing Identity session"

    if (-not $NoLogout -and $script:CurrentSession.IdentityURL) {
        try {
            $logoutUrl = "$($script:CurrentSession.IdentityURL)/Security/logout"
            $headers = $script:CurrentSession.GetAuthHeader()

            Write-Verbose "Calling logout endpoint"
            Invoke-RestMethod -Uri $logoutUrl -Method Post -Headers $headers -ErrorAction SilentlyContinue | Out-Null
            Write-Verbose "Logout successful"
        }
        catch {
            Write-Verbose "Logout call failed (continuing with local cleanup): $($_.Exception.Message)"
        }
    }

    # Clear the session
    $script:CurrentSession.Dispose()
    $script:CurrentSession = $null

    Write-Verbose "Session cleared"
}

# EndRegion: Public - Clear-IdentitySession


# Region: Public - Get-IdentityHeader
#Requires -Version 7.0
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

    PS7 version utilizes classes and enums for enhanced type safety.

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

    $InformationPreference = 'Continue'
    # Check for existing session
    if (-not $ForceNewSession -and $script:CurrentSession) {
        if (-not $script:CurrentSession.IsExpired()) {
            Write-Verbose 'Using existing session token'
            $headers = $script:CurrentSession.GetAuthHeader()
            return $headers.Authorization
        } else {
            Write-Verbose 'Session expired, re-authenticating'
        }
    }

    # Get Identity URL
    if (-not $IdentityTenantURL) {
        $IdentityTenantURL = Get-IdentityURL -PCloudURL $PCloudURL
    }

    $identityBaseUrl = $IdentityTenantURL -match '^https://' ? $IdentityTenantURL : "https://$IdentityTenantURL"
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
        $expiresIn = $response.expires_in ?? 3600

        # Create session - OAuth has no SessionId
        $session = New-IdentitySession -Properties @{
            Token             = $token
            TokenExpiry       = (Get-Date).AddSeconds($expiresIn)
            IdentityURL       = $identityBaseUrl
            PCloudURL         = $PCloudURL
            Username          = $clientId
            AuthMethod        = [AuthenticationMechanism]::OAuth
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
    $username = $PSCmdlet.ParameterSetName -eq 'UPCreds' ? $UPCreds.UserName : $IdentityUserName
    Write-Verbose "Authenticating user: $username"

    $startAuthUrl = "$identityBaseUrl/Security/StartAuthentication"
    $startAuthBody = @{
        User    = $username
        Version = '1.0'
    }
    $Headers = @{
        'Content-Type'         = 'application/json'
        'X-IDAP-NATIVE-CLIENT' = 'true'
        OobIdPAuth             = 'true'
    }

    $idaptiveResponse = Invoke-Rest -Uri $startAuthUrl -Method Post -Body $startAuthBody -headers $headers

    # Check for SAML/OOBAUTHPIN flow (property may not exist in all responses)
    if ($idaptiveResponse.Result.PSObject.Properties['IdpRedirectShortUrl'] -and
        -not [string]::IsNullOrEmpty($idaptiveResponse.Result.IdpRedirectShortUrl)) {
        Write-Verbose 'OOBAUTHPIN flow detected'

        $oobParams = @{
            IdaptiveResponse = $idaptiveResponse
            IdentityURL      = $identityBaseUrl
            PIN              = $PIN
        }
        $answerResponse = Invoke-OOBAUTHPIN @oobParams

        if ($answerResponse.success -and $answerResponse.Result.Token) {
            $token = $answerResponse.Result.Token
            $tokenLifetime = ($answerResponse.Result.PSObject.Properties['TokenLifetime']) ? $answerResponse.Result.TokenLifetime : 3600


            # Create session
            $session = New-IdentitySession -Properties @{
                Token             = $token
                TokenExpiry       = (Get-Date).AddSeconds($tokenLifetime)
                IdentityURL       = $identityBaseUrl
                PCloudURL         = $PCloudURL
                Username          = $username
                SessionId         = $idaptiveResponse.Result.SessionId
                AuthMethod        = [AuthenticationMechanism]::OOBAUTHPIN
                StoredCredentials = $null
            }

            $session.Metadata.RefreshToken = ($answerResponse.Result.PSObject.Properties['RefreshToken']) ? $answerResponse.Result.RefreshToken : $null
            $script:CurrentSession = $session
            $headers = Format-Token -Token $token
            return $headers
        } else {
            $errorMsg = $answerResponse.PSObject.Properties['Message'] ? $answerResponse.Message : 'Unknown error'
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

    if ($answerResponse.PSObject.Properties['success'] -and $answerResponse.success -and $answerResponse.Result.Token) {
        $token = $answerResponse.Result.Token
        $tokenLifetime = ($answerResponse.Result.PSObject.Properties['TokenLifetime']) ? $answerResponse.Result.TokenLifetime : 3600

        # Create session
        $session = New-IdentitySession -Properties @{
            Token       = $token
            TokenExpiry = (Get-Date).AddSeconds($tokenLifetime)
            IdentityURL = $identityBaseUrl
            PCloudURL   = $PCloudURL
            Username    = $username
            SessionId   = $sessionId
            AuthMethod  = [AuthenticationMechanism]::UP
            StoredCredentials = $null
        }
        $session.Metadata.RefreshToken = ($answerResponse.Result.PSObject.Properties['RefreshToken']) ? $answerResponse.Result.RefreshToken : $null
        $script:CurrentSession = $session
        $headers = Format-Token -Token $token
        return $headers
    } else {
        $errorMsg = $answerResponse.PSObject.Properties['Message'] ? $answerResponse.Message : 'Unknown error'
        throw "Authentication failed: $errorMsg"
    }
}

# EndRegion: Public - Get-IdentityHeader


# Region: Public - Get-IdentitySession
#Requires -Version 7.0
<#
.SYNOPSIS
    Retrieves current Identity session details

.DESCRIPTION
    Returns current IdentitySession object with token expiry, authentication method,
    and other metadata.

.OUTPUTS
    IdentitySession - Current session object

.EXAMPLE
    $session = Get-IdentitySession

.NOTES
    Public function - Exported
#>
function Get-IdentitySession {
    [CmdletBinding()]
    [OutputType([IdentitySession])]
    param()

    if (-not $script:CurrentSession) {
        Write-Verbose "No active session"
        return $null
    }

    Write-Verbose "Returning current session"
    Write-Verbose "User: $($script:CurrentSession.Username)"
    Write-Verbose "Expires: $($script:CurrentSession.TokenExpiry)"
    Write-Verbose "Is Expired: $($script:CurrentSession.IsExpired())"

    return $script:CurrentSession
}

# EndRegion: Public - Get-IdentitySession


# Region: Public - Get-IdentityURL
#Requires -Version 7.0
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
        $response = Invoke-WebRequest -Uri $pcloudBase -UseBasicParsing -ErrorAction SilentlyContinue
    } catch {
        if ($_.Exception.Response) {
            $response = $_.Exception.Response
        } else {
            throw "Failed to connect to PCloud URL: $($_.Exception.Message)"
        }
    }

    $identityHost = $response.BaseResponse.RequestMessage.RequestUri.Host

    Write-Verbose "Discovered Identity host: $identityHost"

    return "https://$identityHost"
}

# EndRegion: Public - Get-IdentityURL


# Region: Public - Test-IdentityToken
#Requires -Version 7.0
<#
.SYNOPSIS
    Validates Identity token

.DESCRIPTION
    Validates token format and checks if token is expired.
    Optionally decodes JWT claims using TokenValidator class.

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

    Write-Verbose "Validating token"

    # Basic format check - JWT should have 3 parts separated by dots
    if ($Token -notmatch '^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$') {
        Write-Verbose "Token format invalid"
        return $false
    }

    try {
        # Decode the payload (second part)
        $tokenParts = $Token.Split('.')
        $payload = $tokenParts[1]

        # Add padding if needed
        $padding = '=' * ((4 - ($payload.Length % 4)) % 4)
        $payload = $payload.Replace('-', '+').Replace('_', '/') + $padding

        # Decode from Base64
        $payloadBytes = [System.Convert]::FromBase64String($payload)
        $payloadJson = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
        $claims = $payloadJson | ConvertFrom-Json

        # Check expiration
        if ($claims.exp) {
            $expiryDate = [DateTimeOffset]::FromUnixTimeSeconds($claims.exp).LocalDateTime
            Write-Verbose "Token expires: $expiryDate"

            if ((Get-Date) -gt $expiryDate) {
                Write-Verbose "Token has expired"
                return $false
            }
        }

        Write-Verbose "Token is valid"
        return $true
    }
    catch {
        Write-Verbose "Token validation error: $($_.Exception.Message)"
        return $false
    }
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
