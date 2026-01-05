<#
.SYNOPSIS
    Deletes an application from CyberArk.

.DESCRIPTION
    This script authenticates to CyberArk and deletes a specified application from the Vault.
    Displays application details before deletion and requires user confirmation.

.PARAMETER PVWAUrl
    The base URL of the CyberArk PVWA (e.g., https://pvwa.company.com)

.PARAMETER Credential
    PSCredential object for CyberArk authentication. If not provided, will prompt.

.PARAMETER AppID
    The application name to delete.

.PARAMETER DisableCertificateValidation
    Disables SSL certificate validation. Use only for testing with self-signed certificates.

.EXAMPLE
    $cred = Get-Credential
    .\Remove-CyberArkApplication.ps1 -PVWAUrl "https://pvwa.company.com" `
        -Credential $cred `
        -AppID "MyApp"

.EXAMPLE
    # List applications first, then delete
    .\Get-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com"
    .\Remove-CyberArkApplication.ps1 -PVWAUrl "https://pvwa.company.com" -AppID "MyApp"
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

    # Get application details before deleting
    Write-Output "`nRetrieving application details..."
    $PVWAUrl = $PVWAUrl.TrimEnd('/')
    $getAppUrl = "$PVWAUrl/WebServices/PIMServices.svc/Applications/$AppID/"
    Write-Verbose "GET URL: $getAppUrl"

    $headers = @{
        'Authorization' = $sessionToken
        'Content-Type'  = 'application/json'
    }

    $appDetails = Invoke-RestMethod -Uri $getAppUrl -Method Get -Headers $headers

    if (-not $appDetails.application) {
        throw "Application '$AppID' not found."
    }

    $app = $appDetails.application[0]

    Write-Output "`nApplication to be deleted:"
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
    Write-Output ("=" * 80)

    # Confirm deletion
    $confirmation = Read-Host "`nAre you sure you want to delete application '$AppID'? (yes/no)"
    if ($confirmation -ne 'yes') {
        Write-Output "Deletion cancelled by user."
        return
    }

    # Delete application
    Write-Output "`nDeleting application '$AppID'..."
    $deleteAppUrl = "$PVWAUrl/WebServices/PIMServices.svc/Applications/$AppID/"
    Write-Verbose "DELETE URL: $deleteAppUrl"

    Invoke-RestMethod -Uri $deleteAppUrl -Method Delete -Headers $headers

    Write-Output "`nApplication '$AppID' deleted successfully!"

    # Verify deletion
    Write-Output "`nVerifying application was deleted..."
    try {
        $null = Invoke-RestMethod -Uri $getAppUrl -Method Get -Headers $headers
        Write-Output "Warning: Application '$AppID' still exists."
    } catch {
        if ($_.Exception.Response.StatusCode -eq 404 -or $_.Exception.Message -match "404") {
            Write-Output "Confirmed: Application '$AppID' no longer exists."
        } else {
            Write-Warning "Could not verify deletion: $($_.Exception.Message)"
        }
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
