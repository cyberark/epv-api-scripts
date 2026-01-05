<#
.SYNOPSIS
    Adds one or more authentication methods to a CyberArk Application.

.DESCRIPTION
    This script authenticates to CyberArk and adds authentication methods to a specified application.
    You can add multiple authentication types in a single call by specifying multiple parameters.

    Supported authentication types:
    - Path: File or folder path (use -Path parameter)
    - Hash: File hash (use -Hash parameter)
    - OS User: Windows user account (use -OSUser parameter)
    - Machine Address: IP address or subnet (use -MachineAddress parameter)
    - Certificate Serial Number: Certificate serial number (use -CertificateSerialNumber parameter)
    - Certificate Attributes: Certificate subject/issuer (use -CertificateIssuer, -CertificateSubject, -CertificateSubjectAlternativeName)

.PARAMETER AppID
    The Application ID to which authentication methods will be added

.PARAMETER Path
    Path to executable or folder for Path authentication. Can provide multiple paths as an array.

.PARAMETER PathIsFolder
    For Path authentication - whether the path is a folder. Default: $false

.PARAMETER PathAllowInternalScripts
    For Path authentication - whether to allow internal scripts. Default: $false

.PARAMETER Hash
    File hash value for Hash authentication. Can provide multiple hashes as an array.

.PARAMETER HashComment
    Optional comment for Hash authentication

.PARAMETER OSUser
    Windows user account (e.g., "DOMAIN\User") for OS User authentication. Can provide multiple as an array.

.PARAMETER MachineAddress
    IP address or subnet (e.g., "192.168.1.100" or "192.168.1.0/24") for Machine Address authentication. Can provide multiple as an array.

.PARAMETER CertificateSerialNumber
    Certificate serial number for Certificate Serial Number authentication. Can provide multiple as an array.

.PARAMETER CertificateSerialNumberComment
    Optional comment for Certificate Serial Number authentication

.PARAMETER CertificateIssuer
    Array of certificate issuer attributes (e.g., @("CN=Company CA","OU=IT")) for Certificate Attributes authentication

.PARAMETER CertificateSubject
    Array of certificate subject attributes (e.g., @("CN=app.company.com","OU=IT")) for Certificate Attributes authentication

.PARAMETER CertificateSubjectAlternativeName
    Array of certificate SAN attributes (e.g., @("DNS Name=www.example.com")) for Certificate Attributes authentication

.PARAMETER PVWAUrl
    The base URL of the CyberArk PVWA (e.g., https://pvwa.company.com)

.PARAMETER Credential
    PSCredential object for CyberArk authentication. If not provided, will prompt.

.PARAMETER DisableCertificateValidation
    Disables SSL certificate validation. Use only for testing with self-signed certificates.

.EXAMPLE
    # Add Path authentication
    .\Add-CyberArkAppAuthentication.ps1 -AppID "MyApp" -Path "C:\Program Files\MyApp\app.exe"

.EXAMPLE
    # Add multiple authentication methods at once
    .\Add-CyberArkAppAuthentication.ps1 -AppID "MyApp" `
        -Path "C:\Program Files\MyApp\app.exe" `
        -OSUser "DOMAIN\ServiceAccount" `
        -MachineAddress "192.168.1.0/24"

.EXAMPLE
    # Add multiple paths
    .\Add-CyberArkAppAuthentication.ps1 -AppID "MyApp" `
        -Path @("C:\App\app1.exe", "C:\App\app2.exe")

.EXAMPLE
    # Add Certificate Attributes authentication
    .\Add-CyberArkAppAuthentication.ps1 -AppID "MyApp" `
        -CertificateSubject @("CN=app.company.com","OU=IT") `
        -CertificateIssuer @("CN=Company Root CA")

.EXAMPLE
    # Add Hash with comment
    .\Add-CyberArkAppAuthentication.ps1 -AppID "MyApp" `
        -Hash "A1B2C3D4E5F6" `
        -HashComment "Production server hash"

.EXAMPLE
    # Just verify application exists (no auth methods specified)
    .\Add-CyberArkAppAuthentication.ps1 -AppID "MyApp"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AppID,

    [Parameter(Mandatory = $false)]
    [string[]]$Path,

    [Parameter(Mandatory = $false)]
    [bool]$PathIsFolder = $false,

    [Parameter(Mandatory = $false)]
    [bool]$PathAllowInternalScripts = $false,

    [Parameter(Mandatory = $false)]
    [string[]]$Hash,

    [Parameter(Mandatory = $false)]
    [string]$HashComment,

    [Parameter(Mandatory = $false)]
    [string[]]$OSUser,

    [Parameter(Mandatory = $false)]
    [string[]]$MachineAddress,

    [Parameter(Mandatory = $false)]
    [string[]]$CertificateSerialNumber,

    [Parameter(Mandatory = $false)]
    [string]$CertificateSerialNumberComment,

    [Parameter(Mandatory = $false)]
    [string[]]$CertificateIssuer,

    [Parameter(Mandatory = $false)]
    [string[]]$CertificateSubject,

    [Parameter(Mandatory = $false)]
    [string[]]$CertificateSubjectAlternativeName,

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

# Build list of authentication methods to add
$authMethodsToAdd = @()

# Path authentication
if ($Path) {
    foreach ($p in $Path) {
        $authMethodsToAdd += @{
            Type = 'Path'
            Object = @{
                AuthType = 'path'
                AuthValue = $p
                IsFolder = $PathIsFolder
                AllowInternalScripts = $PathAllowInternalScripts
            }
        }
    }
}

# Hash authentication
if ($Hash) {
    foreach ($h in $Hash) {
        $authObj = @{
            AuthType = 'hash'
            AuthValue = $h
        }
        if ($HashComment) {
            $authObj['Comment'] = $HashComment
        }
        $authMethodsToAdd += @{
            Type = 'Hash'
            Object = $authObj
        }
    }
}

# OS User authentication
if ($OSUser) {
    foreach ($user in $OSUser) {
        $authMethodsToAdd += @{
            Type = 'OSUser'
            Object = @{
                AuthType = 'osUser'
                AuthValue = $user
            }
        }
    }
}

# Machine Address authentication
if ($MachineAddress) {
    foreach ($addr in $MachineAddress) {
        $authMethodsToAdd += @{
            Type = 'MachineAddress'
            Object = @{
                AuthType = 'machineAddress'
                AuthValue = $addr
            }
        }
    }
}

# Certificate Serial Number authentication
if ($CertificateSerialNumber) {
    foreach ($serial in $CertificateSerialNumber) {
        $authObj = @{
            AuthType = 'certificateserialnumber'
            AuthValue = $serial
        }
        if ($CertificateSerialNumberComment) {
            $authObj['Comment'] = $CertificateSerialNumberComment
        }
        $authMethodsToAdd += @{
            Type = 'CertificateSerialNumber'
            Object = $authObj
        }
    }
}

# Certificate Attributes authentication
if ($CertificateIssuer -or $CertificateSubject -or $CertificateSubjectAlternativeName) {
    $authObj = @{
        AuthType = 'certificateattr'
    }
    if ($CertificateIssuer) {
        $authObj['Issuer'] = $CertificateIssuer
    }
    if ($CertificateSubject) {
        $authObj['Subject'] = $CertificateSubject
    }
    if ($CertificateSubjectAlternativeName) {
        $authObj['SubjectAlternativeName'] = $CertificateSubjectAlternativeName
    }
    $authMethodsToAdd += @{
        Type = 'CertificateAttr'
        Object = $authObj
    }
}

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

    # If no authentication methods specified, throw an error
    if ($authMethodsToAdd.Count -eq 0) {
        throw "No authentication methods specified. Please provide at least one authentication parameter (Path, Hash, OSUser, MachineAddress, CertificateSerialNumber, or Certificate attributes)."
    }

    # Setup headers and URLs
    $PVWAUrl = $PVWAUrl.TrimEnd('/')
    $getAuthUrl = "$PVWAUrl/WebServices/PIMServices.svc/Applications/$AppID/Authentications/"
    $headers = @{
        'Authorization' = $sessionToken
        'Content-Type'  = 'application/json'
    }

    # Get existing authentication methods
    Write-Output "`nRetrieving existing authentication methods for application '$AppID'..."
    try {
        $existingAuthMethods = Invoke-RestMethod -Uri $getAuthUrl -Method Get -Headers $headers
    } catch {
        Write-Warning "Could not retrieve existing authentication methods: $($_.Exception.Message)"
        $existingAuthMethods = @{ authentication = @() }
    }

    # Track added authentications
    $addedAuths = @()
    $skippedAuths = @()
    $failedAuths = @()

    # Process each authentication method
    foreach ($authMethod in $authMethodsToAdd) {
        $authType = $authMethod.Type
        $authObj = $authMethod.Object

        # Check for duplicates
        $isDuplicate = $false
        foreach ($existing in $existingAuthMethods.authentication) {
            if ($authType -eq 'CertificateAttr' -and $existing.AuthType -eq 'certificateattr') {
                # For certificate attributes, compare all fields
                $existingSubject = if ($existing.Subject) { @($existing.Subject) } else { @() }
                $existingIssuer = if ($existing.Issuer) { @($existing.Issuer) } else { @() }
                $existingSAN = if ($existing.SubjectAlternativeName) { @($existing.SubjectAlternativeName) } else { @() }

                $subjectMatches = (-not $authObj.Subject -and $existingSubject.Count -eq 0) -or
                                 ($authObj.Subject -and $existingSubject.Count -gt 0 -and -not (Compare-Object $authObj.Subject $existingSubject))
                $issuerMatches = (-not $authObj.Issuer -and $existingIssuer.Count -eq 0) -or
                                ($authObj.Issuer -and $existingIssuer.Count -gt 0 -and -not (Compare-Object $authObj.Issuer $existingIssuer))
                $sanMatches = (-not $authObj.SubjectAlternativeName -and $existingSAN.Count -eq 0) -or
                             ($authObj.SubjectAlternativeName -and $existingSAN.Count -gt 0 -and -not (Compare-Object $authObj.SubjectAlternativeName $existingSAN))

                if ($subjectMatches -and $issuerMatches -and $sanMatches) {
                    $isDuplicate = $true
                    break
                }
            } else {
                # For other types, compare AuthType and AuthValue
                if ($existing.AuthType -eq $authObj.AuthType -and $existing.AuthValue -eq $authObj.AuthValue) {
                    $isDuplicate = $true
                    break
                }
            }
        }

        if ($isDuplicate) {
            $displayValue = if ($authObj.AuthValue) { $authObj.AuthValue } else { "Certificate Attributes" }
            $skippedAuths += "$authType`: $displayValue (duplicate)"
            Write-Output "  Skipping $authType authentication - already exists: $displayValue"
            continue
        }

        # Add the authentication method
        try {
            $requestBody = @{
                authentication = $authObj
            } | ConvertTo-Json -Depth 5

            Write-Output "  + Adding $authType authentication..."
            Write-Verbose "Request Body: $requestBody"

            $addAuthUrl = "$PVWAUrl/WebServices/PIMServices.svc/Applications/$AppID/Authentications/"
            Invoke-RestMethod -Uri $addAuthUrl -Method Post -Headers $headers -Body $requestBody | Out-Null

            $displayValue = if ($authObj.AuthValue) { $authObj.AuthValue } else { "Certificate Attributes" }
            $addedAuths += "$authType`: $displayValue"
            Write-Output "  Successfully added $authType authentication: $displayValue"

        } catch {
            $displayValue = if ($authObj.AuthValue) { $authObj.AuthValue } else { "Certificate Attributes" }
            $failedAuths += "$authType`: $displayValue - $($_.Exception.Message)"
            Write-Output "  Failed to add $authType authentication: $($_.Exception.Message)"
        }
    }

    # Display summary
    Write-Output @"

$('=' * 80)
SUMMARY
$('=' * 80)
"@

    if ($addedAuths.Count -gt 0) {
        Write-Output "`nAdded $($addedAuths.Count) authentication method(s):"
        foreach ($auth in $addedAuths) {
            Write-Output "  - $auth"
        }
    }

    if ($skippedAuths.Count -gt 0) {
        Write-Output "`nSkipped $($skippedAuths.Count) authentication method(s):"
        foreach ($auth in $skippedAuths) {
            Write-Output "  - $auth"
        }
    }

    if ($failedAuths.Count -gt 0) {
        Write-Output "`nFailed $($failedAuths.Count) authentication method(s):"
        foreach ($auth in $failedAuths) {
            Write-Output "  - $auth"
        }
    }

    # Display all current authentication methods
    if ($addedAuths.Count -gt 0) {
        Write-Output "`nRetrieving updated authentication methods..."
        $authMethods = Invoke-RestMethod -Uri $getAuthUrl -Method Get -Headers $headers

        if ($authMethods.authentication) {
            Write-Output "`nApplication '$AppID' now has $($authMethods.authentication.Count) authentication method(s):"
            Write-Output ("=" * 80)

            foreach ($auth in $authMethods.authentication) {
                Write-Output "  - Auth ID: $($auth.authID) | Type: $($auth.AuthType)"
                if ($auth.AuthValue) {
                    Write-Output "    Value: $($auth.AuthValue)"
                }
                if ($auth.Subject) {
                    Write-Output "    Subject: $($auth.Subject)"
                }
                if ($auth.Issuer) {
                    Write-Output "    Issuer: $($auth.Issuer)"
                }
                if ($auth.SubjectAlternativeName) {
                    Write-Output "    SubjectAlternativeName: $($auth.SubjectAlternativeName)"
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
            Write-Output ("=" * 80)
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
