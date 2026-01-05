<#
.SYNOPSIS
    Adds a new application to CyberArk.

.DESCRIPTION
    This script authenticates to CyberArk and creates a new application in the Vault.

.PARAMETER PVWAUrl
    The base URL of the CyberArk PVWA (e.g., https://pvwa.company.com)

.PARAMETER Credential
    PSCredential object for CyberArk authentication. If not provided, will prompt.

.PARAMETER AppID
    The application name (required).

.PARAMETER Description
    Optional description of the application.

.PARAMETER Location
    Optional location of the application in the Vault hierarchy.

.PARAMETER AccessPermittedFrom
    Optional start hour that access is permitted (0-23).

.PARAMETER AccessPermittedTo
    Optional end hour that access is permitted (0-23).

.PARAMETER ExpirationDate
    Optional expiration date of the application (mm-dd-yyyy format).

.PARAMETER Disabled
    Optional flag to create the application as disabled. Default is $false.

.PARAMETER BusinessOwnerFName
    Optional business owner first name.

.PARAMETER BusinessOwnerLName
    Optional business owner last name.

.PARAMETER BusinessOwnerEmail
    Optional business owner email.

.PARAMETER BusinessOwnerPhone
    Optional business owner phone number.

.PARAMETER DisableCertificateValidation
    Disables SSL certificate validation. Use only for testing with self-signed certificates.

.EXAMPLE
    $cred = Get-Credential
    .\New-CyberArkApplication.ps1 -PVWAUrl "https://pvwa.company.com" `
        -Credential $cred `
        -AppID "MyNewApp" `
        -Description "My application for testing" `
        -Location "\Applications"

.EXAMPLE
    .\New-CyberArkApplication.ps1 -PVWAUrl "https://pvwa.company.com" `
        -AppID "MyNewApp" `
        -BusinessOwnerFName "John" `
        -BusinessOwnerLName "Doe" `
        -BusinessOwnerEmail "john.doe@company.com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AppID,

    [Parameter(Mandatory = $false)]
    [string]$Description,

    [Parameter(Mandatory = $false)]
    [string]$Location,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 23)]
    [int]$AccessPermittedFrom,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 23)]
    [int]$AccessPermittedTo,

    [Parameter(Mandatory = $false)]
    [string]$ExpirationDate,

    [Parameter(Mandatory = $false)]
    [bool]$Disabled = $false,

    [Parameter(Mandatory = $false)]
    [string]$BusinessOwnerFName,

    [Parameter(Mandatory = $false)]
    [string]$BusinessOwnerLName,

    [Parameter(Mandatory = $false)]
    [string]$BusinessOwnerEmail,

    [Parameter(Mandatory = $false)]
    [string]$BusinessOwnerPhone,

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

    # Check if application already exists
    Write-Output "`nChecking if application '$AppID' already exists..."
    $PVWAUrl = $PVWAUrl.TrimEnd('/')
    $headers = @{
        'Authorization' = $sessionToken
        'Content-Type'  = 'application/json'
    }

    try {
        $checkUrl = "$PVWAUrl/WebServices/PIMServices.svc/Applications/$AppID/"
        $existingApp = Invoke-RestMethod -Uri $checkUrl -Method Get -Headers $headers

        if ($existingApp) {
            throw "Application '$AppID' already exists. Use a different name or delete the existing application first."
        }
    } catch {
        if ($_.Exception.Response.StatusCode -eq 404 -or $_.Exception.Message -match "404") {
            Write-Output "Application does not exist. Proceeding with creation."
        } else {
            Write-Warning "Could not verify if application exists: $($_.Exception.Message)"
            Write-Output "Attempting to create application..."
        }
    }

    # Prepare the application object
    $applicationObject = @{
        AppID = $AppID
        Disabled = $Disabled
    }

    # Add optional properties
    if ($Description) { $applicationObject['Description'] = $Description }
    if ($Location) { $applicationObject['Location'] = $Location }
    if ($PSBoundParameters.ContainsKey('AccessPermittedFrom')) { $applicationObject['AccessPermittedFrom'] = $AccessPermittedFrom }
    if ($PSBoundParameters.ContainsKey('AccessPermittedTo')) { $applicationObject['AccessPermittedTo'] = $AccessPermittedTo }
    if ($ExpirationDate) { $applicationObject['ExpirationDate'] = $ExpirationDate }
    if ($BusinessOwnerFName) { $applicationObject['BusinessOwnerFName'] = $BusinessOwnerFName }
    if ($BusinessOwnerLName) { $applicationObject['BusinessOwnerLName'] = $BusinessOwnerLName }
    if ($BusinessOwnerEmail) { $applicationObject['BusinessOwnerEmail'] = $BusinessOwnerEmail }
    if ($BusinessOwnerPhone) { $applicationObject['BusinessOwnerPhone'] = $BusinessOwnerPhone }

    # Prepare the request body
    $requestBody = @{
        application = $applicationObject
    } | ConvertTo-Json -Depth 5

    Write-Output "`nCreating application '$AppID'..."
    Write-Verbose 'Request Body:'
    Write-Verbose $requestBody

    # Create the application
    $createAppUrl = "$PVWAUrl/WebServices/PIMServices.svc/Applications/"
    Write-Verbose "POST URL: $createAppUrl"

    Invoke-RestMethod -Uri $createAppUrl -Method Post -Headers $headers -Body $requestBody | Out-Null

    Write-Output "`nApplication '$AppID' created successfully!"

    # Verify the application was created
    Write-Output "`nVerifying application was created..."
    $verifyUrl = "$PVWAUrl/WebServices/PIMServices.svc/Applications/$AppID/"
    $verifiedApp = Invoke-RestMethod -Uri $verifyUrl -Method Get -Headers $headers

    if ($verifiedApp.application) {
        $app = $verifiedApp.application[0]
        Write-Output "`nApplication Details:"
        Write-Output ("=" * 80)
        Write-Output "  AppID: $($app.AppID)"
        if ($app.Description) {
            Write-Output "  Description: $($app.Description)"
        }
        if ($app.Location) {
            Write-Output "  Location: $($app.Location)"
        }
        Write-Output "  Disabled: $($app.Disabled)"
        if ($app.AccessPermittedFrom -or $app.AccessPermittedTo) {
            Write-Output "  Access Hours: $($app.AccessPermittedFrom) - $($app.AccessPermittedTo)"
        }
        if ($app.ExpirationDate) {
            Write-Output "  Expiration Date: $($app.ExpirationDate)"
        }
        if ($app.BusinessOwnerFName -or $app.BusinessOwnerLName) {
            Write-Output "  Business Owner: $($app.BusinessOwnerFName) $($app.BusinessOwnerLName)"
        }
        if ($app.BusinessOwnerEmail) {
            Write-Output "  Business Owner Email: $($app.BusinessOwnerEmail)"
        }
        if ($app.BusinessOwnerPhone) {
            Write-Output "  Business Owner Phone: $($app.BusinessOwnerPhone)"
        }
        Write-Output ("=" * 80)
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
