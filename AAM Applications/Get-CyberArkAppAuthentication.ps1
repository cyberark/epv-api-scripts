<#
.SYNOPSIS
    Retrieves authentication methods for a CyberArk Application.

.DESCRIPTION
    This script authenticates to CyberArk and retrieves all authentication
    methods configured for a specified application.

.PARAMETER PVWAUrl
    The base URL of the CyberArk PVWA (e.g., https://pvwa.company.com)

.PARAMETER Credential
    PSCredential object for CyberArk authentication. If not provided, will prompt.

.PARAMETER AppID
    The Application ID to retrieve authentication methods for

.PARAMETER DisableCertificateValidation
    Disables SSL certificate validation. Use only for testing with self-signed certificates.

.EXAMPLE
    $cred = Get-Credential
    .\Get-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" `
        -Credential $cred `
        -AppID "MyApp"

.EXAMPLE
    .\Get-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" `
        -AppID "MyApp"
    # Credentials will be prompted if not provided
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AppID,

    [Parameter(Mandatory = $false)]
    [switch]$DisableCertificateValidation,

    [Parameter(Mandatory = $true)]
    [string]$PVWAUrl,

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory = $false, HelpMessage = 'Enter the Authentication type (Default:CyberArk)')]
    [ValidateSet('cyberark', 'ldap', 'radius')]
    [String]$AuthenticationType = 'cyberark',

    [Parameter(Mandatory = $false, HelpMessage = 'Enter the RADIUS OTP')]
    [String]$OTP,

    [Parameter(Mandatory = $false, HelpMessage = 'Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off')]
    [Alias('session', 'sessionToken')]
    $logonToken
)

# Disable certificate validation if requested (NOT recommended for production)
if ($DisableCertificateValidation) {
    Write-Warning "Certificate validation is disabled. This should only be used for testing!"
    add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

# Set TLS to 1.2 or higher
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Check if session token was provided
$shouldLogoff = $true
if ($logonToken) {
    Write-Output 'Using provided session token...'
    if ($logonToken.GetType().name -eq 'String') {
        $sessionToken = $logonToken
    } else {
        $sessionToken = $logonToken
    }
    $shouldLogoff = $false
    Write-Output 'Session token accepted. Will NOT log off at end.'
} else {
    # Prompt for credentials if not provided
    if (-not $Credential) {
        $Credential = Get-Credential -Message 'Enter CyberArk credentials'
        if (-not $Credential) {
            throw 'Credentials are required to proceed.'
        }
    }

    # Extract username and password from credential object
    $Username = $Credential.UserName
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
    $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    Write-Output "Authenticating to CyberArk using $AuthenticationType..."

    # Prepare authentication request
    $authUrl = "$PVWAUrl/API/Auth/$AuthenticationType/Logon"
    $authBody = @{
        username          = $Username
        password          = $PlainPassword
        concurrentSession = $true
    } | ConvertTo-Json

    # Add RADIUS OTP if provided
    if ($AuthenticationType -eq 'radius' -and $OTP) {
        $authBodyObj = $authBody | ConvertFrom-Json
        $authBodyObj.password = "$PlainPassword,$OTP"
        $authBody = $authBodyObj | ConvertTo-Json
    }

    Write-Verbose $authBody
}

try {
    if (-not $logonToken) {
        # Authenticate and get session token
        $authResponse = Invoke-RestMethod -Uri $authUrl -Method Post -Body $authBody -ContentType 'application/json'
        Write-Verbose $authResponse
        $sessionToken = $authResponse

        Write-Output 'Authentication successful!'
    }

    # Retrieve authentication methods
    Write-Output "`nRetrieving authentication methods for application '$AppID'..."

    # Prepare the API URL (remove any trailing slash from PVWAUrl)
    $PVWAUrl = $PVWAUrl.TrimEnd('/')
    $getAuthUrl = "$PVWAUrl/WebServices/PIMServices.svc/Applications/$AppID/Authentications/"
    Write-Verbose "GET URL: $getAuthUrl"

    # Prepare headers with session token
    $headers = @{
        'Authorization' = $sessionToken
        'Content-Type'  = 'application/json'
    }

    $authMethods = Invoke-RestMethod -Uri $getAuthUrl -Method Get -Headers $headers
    Write-Verbose ($authMethods | ConvertTo-Json -Depth 5)

    # Display all authentication methods
    if ($authMethods.authentication) {
        Write-Output "`nFound $($authMethods.authentication.Count) authentication method(s) for application '$AppID':"
        Write-Output ("=" * 80)

        foreach ($auth in $authMethods.authentication) {
            Write-Output "`n  - Auth ID: $($auth.authID) | Type: $($auth.AuthType)"

            if ($auth.AuthValue) {
                Write-Output "    AuthValue: $($auth.AuthValue)"
            }
            if ($auth.Subject) {
                Write-Output "    Subject: $($auth.Subject -join ', ')"
            }
            if ($auth.Issuer) {
                Write-Output "    Issuer: $($auth.Issuer -join ', ')"
            }
            if ($auth.SubjectAlternativeName) {
                Write-Output "    SubjectAlternativeName: $($auth.SubjectAlternativeName -join ', ')"
            }
            if ($auth.Comment) {
                Write-Output "    Comment: $($auth.Comment)"
            }
            if ($null -ne $auth.IsFolder) {
                Write-Output "    IsFolder: $($auth.IsFolder)"
            }
            if ($null -ne $auth.AllowInternalScripts) {
                Write-Output "    AllowInternalScripts: $($auth.AllowInternalScripts)"
            }
        }

        Write-Output "`n" # Extra line before separator
        Write-Output ("=" * 80)
    } else {
        Write-Output "`nNo authentication methods found for application '$AppID'."
    }

    # Logoff (only if we authenticated in this script)
    if ($shouldLogoff) {
        Write-Output "`nLogging off..."
        $logoffUrl = "$PVWAUrl/API/Auth/Logoff"
        Invoke-RestMethod -Uri $logoffUrl -Method Post -Headers $headers
        Write-Output 'Session closed successfully.'
    } else {
        Write-Output "`nSession token was provided - NOT logging off."
    }
} catch {
    Write-Output "`nError occurred:"
    Write-Output $_.Exception.Message

    if ($_.ErrorDetails.Message) {
        Write-Output 'API Error Details:'
        Write-Output $_.ErrorDetails.Message
    }

    # Attempt to log off even if there was an error (only if we authenticated)
    if ($sessionToken -and $shouldLogoff) {
        try {
            $logoffUrl = "$PVWAUrl/API/Auth/Logoff"
            $headers = @{
                'Authorization' = $sessionToken
            }
            Invoke-RestMethod -Uri $logoffUrl -Method Post -Headers $headers
            Write-Output 'Session closed.'
        } catch {
            Write-Output 'Could not close session properly.'
        }
    } elseif (-not $shouldLogoff) {
        Write-Output 'Session token was provided - NOT logging off.'
    }

    exit 1
} finally {
    # Clear sensitive data from memory
    if ($BSTR) {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
    $PlainPassword = $null
}
