<#
.SYNOPSIS
    Retrieves all CyberArk Applications or filters by specific criteria.

.DESCRIPTION
    This script authenticates to CyberArk and retrieves a list of all applications
    or filters by AppID, Location, and sublocation settings.

.PARAMETER PVWAUrl
    The base URL of the CyberArk PVWA (e.g., https://pvwa.company.com)

.PARAMETER Credential
    PSCredential object for CyberArk authentication. If not provided, will prompt.

.PARAMETER AppID
    Optional. Filter by application name.

.PARAMETER Location
    Optional. Filter by location in the Vault hierarchy. Default is '\'.

.PARAMETER IncludeSublocations
    Optional. Whether to include sublocations in the search. Default is $true.

.PARAMETER DisableCertificateValidation
    Disables SSL certificate validation. Use only for testing with self-signed certificates.

.EXAMPLE
    # Get all applications
    .\Get-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com"

.EXAMPLE
    # Get specific application
    $cred = Get-Credential
    .\Get-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com" `
        -Credential $cred `
        -AppID "MyApp"

.EXAMPLE
    # Get applications in specific location
    .\Get-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com" `
        -Location "\Applications" `
        -IncludeSublocations $false
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$AppID,

    [Parameter(Mandatory = $false)]
    [string]$Location,

    [Parameter(Mandatory = $false)]
    [bool]$IncludeSublocations = $true,

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

    # Build query parameters
    $queryParams = @()
    if ($AppID) {
        $queryParams += "AppID=$([System.Web.HttpUtility]::UrlEncode($AppID))"
    }
    if ($Location) {
        $queryParams += "Location=$([System.Web.HttpUtility]::UrlEncode($Location))"
    }
    if ($PSBoundParameters.ContainsKey('IncludeSublocations')) {
        $queryParams += "IncludeSublocations=$($IncludeSublocations.ToString().ToLower())"
    }

    $queryString = if ($queryParams.Count -gt 0) { "?" + ($queryParams -join "&") } else { "" }

    # Retrieve applications
    Write-Output "`nRetrieving applications..."

    # Prepare the API URL
    $PVWAUrl = $PVWAUrl.TrimEnd('/')
    $getAppsUrl = "$PVWAUrl/WebServices/PIMServices.svc/Applications/$queryString"
    Write-Verbose "GET URL: $getAppsUrl"

    # Prepare headers with session token
    $headers = @{
        'Authorization' = $sessionToken
        'Content-Type'  = 'application/json'
    }

    $applications = Invoke-RestMethod -Uri $getAppsUrl -Method Get -Headers $headers
    Write-Verbose ($applications | ConvertTo-Json -Depth 5)

    # Display applications
    if ($applications.application) {
        Write-Output "`nFound $($applications.application.Count) application(s):"
        Write-Output ("=" * 100)

        foreach ($app in $applications.application) {
            Write-Output "`n  Application: $($app.AppID)"
            if ($app.Description) {
                Write-Output "    Description: $($app.Description)"
            }
            if ($app.Location) {
                Write-Output "    Location: $($app.Location)"
            }
            Write-Output "    Disabled: $($app.Disabled)"
            if ($app.AccessPermittedFrom -or $app.AccessPermittedTo) {
                Write-Output "    Access Hours: $($app.AccessPermittedFrom) - $($app.AccessPermittedTo)"
            }
            if ($app.ExpirationDate) {
                Write-Output "    Expiration Date: $($app.ExpirationDate)"
            }
            if ($app.BusinessOwnerFName -or $app.BusinessOwnerLName) {
                Write-Output "    Business Owner: $($app.BusinessOwnerFName) $($app.BusinessOwnerLName)"
            }
            if ($app.BusinessOwnerEmail) {
                Write-Output "    Business Owner Email: $($app.BusinessOwnerEmail)"
            }
            if ($app.BusinessOwnerPhone) {
                Write-Output "    Business Owner Phone: $($app.BusinessOwnerPhone)"
            }
        }

        Write-Output "`n" # Extra line before separator
        Write-Output ("=" * 100)
    } else {
        Write-Output "`nNo applications found."
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
