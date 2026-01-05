<#
.SYNOPSIS
    Deletes an authentication method from a CyberArk Application.

.DESCRIPTION
    This script authenticates to CyberArk and deletes a specific authentication
    method from a specified application using the AuthID.

.PARAMETER PVWAUrl
    The base URL of the CyberArk PVWA (e.g., https://pvwa.company.com)

.PARAMETER Credential
    PSCredential object for CyberArk authentication. If not provided, will prompt.

.PARAMETER AppID
    The Application ID from which the authentication will be deleted

.PARAMETER AuthID
    The unique ID of the authentication method to delete.
    Use Get-CyberArkAppAuthentication.ps1 to find the AuthID.

.PARAMETER DisableCertificateValidation
    Disables SSL certificate validation. Use only for testing with self-signed certificates.

.EXAMPLE
    $cred = Get-Credential
    .\Remove-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" `
        -Credential $cred `
        -AppID "MyApp" `
        -AuthID 5

.EXAMPLE
    .\Remove-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" `
        -AppID "MyApp" `
        -AuthID 5
    # Credentials will be prompted if not provided

.EXAMPLE
    # List authentication methods to find AuthID, then delete
    .\Get-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" -AppID "MyApp"
    .\Remove-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" -AppID "MyApp" -AuthID 5
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AppID,

    [Parameter(Mandatory = $true)]
    [int]$AuthID,

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

    # Prepare the API URL (remove any trailing slash from PVWAUrl)
    $PVWAUrl = $PVWAUrl.TrimEnd('/')
    $deleteAuthUrl = "$PVWAUrl/WebServices/PIMServices.svc/Applications/$AppID/Authentications/$AuthID/"
    Write-Verbose "DELETE URL: $deleteAuthUrl"

    # Prepare headers with session token
    $headers = @{
        'Authorization' = $sessionToken
        'Content-Type'  = 'application/json'
    }

    # Get authentication details before deleting (for display purposes)
    Write-Output "`nRetrieving authentication details before deletion..."
    $getAuthUrl = "$PVWAUrl/WebServices/PIMServices.svc/Applications/$AppID/Authentications/"
    $authMethods = Invoke-RestMethod -Uri $getAuthUrl -Method Get -Headers $headers
    $authToDelete = $authMethods.authentication | Where-Object { $_.authID -eq $AuthID }

    if (-not $authToDelete) {
        throw "Authentication with AuthID $AuthID not found for application '$AppID'."
    }

    Write-Output "`nAuthentication to be deleted:"
    Write-Output "  - Auth ID: $($authToDelete.authID) | Type: $($authToDelete.AuthType)"
    if ($authToDelete.AuthValue) {
        Write-Output "    AuthValue: $($authToDelete.AuthValue)"
    }
    if ($authToDelete.Subject) {
        Write-Output "    Subject: $($authToDelete.Subject -join ', ')"
    }
    if ($authToDelete.Issuer) {
        Write-Output "    Issuer: $($authToDelete.Issuer -join ', ')"
    }
    if ($authToDelete.SubjectAlternativeName) {
        Write-Output "    SubjectAlternativeName: $($authToDelete.SubjectAlternativeName -join ', ')"
    }

    # Confirm deletion
    $confirmation = Read-Host "`nAre you sure you want to delete this authentication? (yes/no)"
    if ($confirmation -ne 'yes') {
        Write-Output "Deletion cancelled by user."
        return
    }

    # Delete authentication method
    Write-Output "`nDeleting authentication (AuthID: $AuthID) from application '$AppID'..."
    Invoke-RestMethod -Uri $deleteAuthUrl -Method Delete -Headers $headers

    Write-Output "`nAuthentication successfully deleted from application '$AppID'!"

    # Verify the authentication was deleted
    Write-Output "`nVerifying authentication was deleted..."
    $authMethods = Invoke-RestMethod -Uri $getAuthUrl -Method Get -Headers $headers
    $stillExists = $authMethods.authentication | Where-Object { $_.authID -eq $AuthID }

    if (-not $stillExists) {
        Write-Output "Confirmed: Authentication (AuthID: $AuthID) no longer exists."
    } else {
        Write-Output "Warning: Authentication (AuthID: $AuthID) still appears to exist."
    }

    # Display remaining authentication methods
    if ($authMethods.authentication) {
        Write-Output "`nRemaining authentication method(s) for application '$AppID': $($authMethods.authentication.Count)"
        Write-Output ("=" * 80)
        foreach ($auth in $authMethods.authentication) {
            Write-Output "  - Auth ID: $($auth.authID) | Type: $($auth.AuthType)"
            if ($auth.AuthValue) {
                Write-Output "    AuthValue: $($auth.AuthValue)"
            }
        }
        Write-Output ("=" * 80)
    } else {
        Write-Output "`nNo authentication methods remain for application '$AppID'."
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
