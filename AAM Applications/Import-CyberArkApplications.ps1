<#
.SYNOPSIS
    Imports CyberArk Applications and their authentication methods from CSV

.DESCRIPTION
    This script imports CyberArk Applications including all their authentication methods from a CSV file.
    Creates applications with all configured authentication methods as defined in the CSV.
    Works with both Privilege Cloud and Self-Hosted PAM.

.PARAMETER PVWAUrl
    The base URL of the PVWA (e.g., https://pvwa.company.com or https://tenant.privilegecloud.cyberark.cloud)

.PARAMETER CSVPath
    Path to the CSV file containing applications to import

.PARAMETER Credential
    PSCredential object for authentication. If not provided, prompts for credentials

.PARAMETER AuthenticationType
    Authentication type: cyberark, ldap, or radius (default: cyberark)

.PARAMETER OTP
    One-time password for RADIUS authentication

.PARAMETER logonToken
    Pre-existing session token. If provided, script will NOT log off at the end
    Aliases: session, sessionToken

.PARAMETER DisableCertificateValidation
    Disables SSL certificate validation (not recommended for production)

.EXAMPLE
    .\Import-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com" -CSVPath ".\applications.csv"
    Imports all applications from CSV

.EXAMPLE
    .\Import-CyberArkApplications.ps1 -PVWAUrl "https://tenant.privilegecloud.cyberark.cloud" -logonToken $token -CSVPath ".\apps.csv"
    Imports using existing session token (Privilege Cloud)

.EXAMPLE
    .\Import-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com" -CSVPath ".\apps.csv" -AuthenticationType ldap
    Imports using LDAP authentication

.NOTES
    Author: CyberArk
    Version: 2.0
    Requires: PowerShell 5.1 or higher, CyberArk PAS v10.4+
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "PVWA URL (e.g., https://pvwa.company.com)")]
    [Alias("url")]
    [ValidateNotNullOrEmpty()]
    [string]$PVWAUrl,

    [Parameter(Mandatory = $true, HelpMessage = "Path to the CSV import file")]
    [Alias("path")]
    [ValidateNotNullOrEmpty()]
    [string]$CSVPath,

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [ValidateSet("cyberark", "ldap", "radius")]
    [string]$AuthenticationType = "cyberark",

    [Parameter(Mandatory = $false)]
    [string]$OTP,

    [Parameter(Mandatory = $false)]
    [Alias("session", "sessionToken")]
    $logonToken,

    [Parameter(Mandatory = $false)]
    [switch]$DisableCertificateValidation
)

#region Helper Functions
Function Write-LogMessage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Debug", "Verbose")]
        [string]$Type = "Info"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Type] $Message"

    switch ($Type) {
        "Info" { Write-Host $Message }
        "Warning" { Write-Warning $Message }
        "Error" { Write-Host $Message -ForegroundColor Red }
        "Debug" { if ($PSCmdlet.MyInvocation.BoundParameters["Debug"]) { Write-Debug $Message } }
        "Verbose" { if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"]) { Write-Verbose $Message } }
    }
}

Function ConvertTo-URL {
    param([string]$text)
    if (![string]::IsNullOrEmpty($text)) {
        return [URI]::EscapeDataString($text)
    }
    return $text
}

Function TryConvertTo-Bool {
    param([string]$text)

    if ([string]::IsNullOrEmpty($text)) {
        return $text
    }

    $retBool = $false
    if ($text -match "^y$|^yes$|^true$|^1$") {
        return $true
    }
    elseif ($text -match "^n$|^no$|^false$|^0$") {
        return $false
    }
    elseif ([bool]::TryParse($text, [ref]$retBool)) {
        return $retBool
    }

    # Not a boolean - return original text
    return $text
}

Function Convert-StringToObject {
    param([string]$String)

    $retObject = New-Object PSCustomObject
    if (![string]::IsNullOrEmpty($String)) {
        foreach ($item in $String.Split(';')) {
            if (![string]::IsNullOrEmpty($item)) {
                $keyValue = $item.Split('=', 2)
                if ($keyValue.Count -eq 2) {
                    $key = $keyValue[0].Trim()
                    $value = $keyValue[1].Trim()

                    # Skip authID, authenticationID, AppID, and empty values
                    if ($key -notin @('authID', 'authenticationID', 'AppID') -and ![string]::IsNullOrEmpty($value)) {
                        # Certificate attributes (Subject, Issuer, SubjectAlternativeName) are arrays
                        if ($key -in @('Subject', 'Issuer', 'SubjectAlternativeName')) {
                            $arrayValue = $value -split ','
                            $retObject | Add-Member -NotePropertyName $key -NotePropertyValue $arrayValue
                        }
                        else {
                            # Try to convert to bool if applicable
                            $convertedValue = TryConvertTo-Bool -text $value
                            if ($convertedValue -is [bool]) {
                                $retObject | Add-Member -NotePropertyName $key -NotePropertyValue $convertedValue
                            }
                            else {
                                $retObject | Add-Member -NotePropertyName $key -NotePropertyValue $value
                            }
                        }
                    }
                }
            }
        }
    }
    return $retObject
}

Function Initialize-SSL {
    if ($DisableCertificateValidation) {
        Write-LogMessage -Type Warning -Message "SSL certificate validation is disabled"
        if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
            Add-Type @"
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
        }
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}

Function Invoke-PASRestMethod {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("GET", "POST", "DELETE", "PATCH")]
        [string]$Method,
        [Parameter(Mandatory = $true)]
        [string]$URI,
        [Parameter(Mandatory = $true)]
        [hashtable]$Header,
        [Parameter(Mandatory = $false)]
        [string]$Body
    )

    try {
        Write-LogMessage -Type Verbose -Message "$Method $URI"
        $params = @{
            Uri         = $URI
            Method      = $Method
            Headers     = $Header
            ContentType = "application/json"
            TimeoutSec  = 2700
        }

        if (![string]::IsNullOrEmpty($Body)) {
            $params.Body = $Body
            Write-LogMessage -Type Debug -Message "Body: $Body"
        }

        $response = Invoke-RestMethod @params
        return $response
    }
    catch {
        Write-LogMessage -Type Error -Message "REST API call failed: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            Write-LogMessage -Type Error -Message "Status Code: $($_.Exception.Response.StatusCode.value__)"
            Write-LogMessage -Type Error -Message "Status Description: $($_.Exception.Response.StatusDescription)"
        }
        throw
    }
}

Function Get-PASLogonHeader {
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credential,
        [Parameter(Mandatory = $true)]
        [string]$BaseURL,
        [Parameter(Mandatory = $true)]
        [string]$AuthType,
        [Parameter(Mandatory = $false)]
        [string]$OTP
    )

    $logonURL = "$BaseURL/api/auth/$AuthType/Logon"
    $logonBody = @{
        username = $Credential.UserName
        password = $Credential.GetNetworkCredential().Password
    }

    if (![string]::IsNullOrEmpty($OTP)) {
        $logonBody.password += ",$OTP"
    }

    try {
        Write-LogMessage -Type Verbose -Message "Authenticating to $BaseURL using $AuthType"
        $response = Invoke-RestMethod -Uri $logonURL -Method Post -Body ($logonBody | ConvertTo-Json) -ContentType "application/json"
        $logonBody = $null

        if ([string]::IsNullOrEmpty($response)) {
            throw "Authentication failed - no token received"
        }

        return @{ Authorization = $response }
    }
    catch {
        throw "Authentication failed: $($_.Exception.Message)"
    }
}

Function Invoke-PASLogoff {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Header,
        [Parameter(Mandatory = $true)]
        [string]$BaseURL
    )

    try {
        Write-LogMessage -Type Verbose -Message "Logging off session"
        $logoffURL = "$BaseURL/api/auth/Logoff"
        Invoke-RestMethod -Uri $logoffURL -Method Post -Headers $Header -ContentType "application/json" | Out-Null
    }
    catch {
        Write-LogMessage -Type Warning -Message "Logoff failed: $($_.Exception.Message)"
    }
}
#endregion

#region Main Script
try {
    Write-LogMessage -Type Info -Message "Import CyberArk Applications - Starting"

    # Initialize SSL/TLS
    Initialize-SSL

    # Normalize PVWA URL - just trim trailing slashes
    $PVWAUrl = $PVWAUrl.TrimEnd('/')

    # Check if CSV file exists
    if (!(Test-Path $CSVPath)) {
        throw "CSV file not found: $CSVPath"
    }

    # Import CSV
    Write-LogMessage -Type Info -Message "Reading CSV file: $CSVPath"
    $importData = Import-Csv -Path $CSVPath

    if ($importData.Count -eq 0) {
        throw "CSV file is empty or invalid"
    }

    Write-LogMessage -Type Info -Message "Found $($importData.Count) application(s) to import"

    # Determine if we need to manage the session
    $managedSession = $false
    $sessionHeader = $null

    if ($null -ne $logonToken) {
        Write-LogMessage -Type Verbose -Message "Using provided session token"
        if ($logonToken.GetType().Name -eq "String") {
            $sessionHeader = @{ Authorization = $logonToken }
        } else {
            $sessionHeader = $logonToken
        }
    }
    else {
        # Need to authenticate
        $managedSession = $true

        if ($null -eq $Credential) {
            $Credential = Get-Credential -Message "Enter CyberArk credentials ($AuthenticationType)"
        }

        if ($null -eq $Credential) {
            throw "Credentials are required to proceed"
        }

        $sessionHeader = Get-PASLogonHeader -Credential $Credential -BaseURL $PVWAUrl -AuthType $AuthenticationType -OTP $OTP
        Write-LogMessage -Type Verbose -Message "Successfully authenticated"
    }

    # Define API URLs
    $applicationsURL = "$PVWAUrl/WebServices/PIMServices.svc/Applications"

    # Import applications
    $successCount = 0
    $failureCount = 0
    $authSuccessCount = 0
    $authFailureCount = 0

    foreach ($app in $importData) {
        try {
            Write-LogMessage -Type Info -Message "Creating application: $($app.AppID)"

            # Build application object
            $appBody = @{
                application = @{
                    AppID               = $app.AppID
                    Description         = if ([string]::IsNullOrEmpty($app.Description)) { "" } else { $app.Description }
                    Location            = if ([string]::IsNullOrEmpty($app.Location)) { "\" } else { $app.Location }
                    AccessPermittedFrom = if ([string]::IsNullOrEmpty($app.AccessPermittedFrom)) { 0 } else { [int]$app.AccessPermittedFrom }
                    AccessPermittedTo   = if ([string]::IsNullOrEmpty($app.AccessPermittedTo)) { 23 } else { [int]$app.AccessPermittedTo }
                    Disabled            = TryConvertTo-Bool -text $app.Disabled
                }
            }

            # Add optional properties if they exist
            if (![string]::IsNullOrEmpty($app.ExpirationDate)) {
                $appBody.application.ExpirationDate = $app.ExpirationDate
            }
            if (![string]::IsNullOrEmpty($app.BusinessOwnerFName)) {
                $appBody.application.BusinessOwnerFName = $app.BusinessOwnerFName
            }
            if (![string]::IsNullOrEmpty($app.BusinessOwnerLName)) {
                $appBody.application.BusinessOwnerLName = $app.BusinessOwnerLName
            }
            if (![string]::IsNullOrEmpty($app.BusinessOwnerEmail)) {
                $appBody.application.BusinessOwnerEmail = $app.BusinessOwnerEmail
            }
            if (![string]::IsNullOrEmpty($app.BusinessOwnerPhone)) {
                $appBody.application.BusinessOwnerPhone = $app.BusinessOwnerPhone
            }

            # Create application
            $newApp = Invoke-PASRestMethod -Method POST -URI $applicationsURL -Header $sessionHeader -Body ($appBody | ConvertTo-Json -Depth 5)

            if ($null -ne $newApp) {
                Write-LogMessage -Type Verbose -Message "  Application created successfully"
                $successCount++

                # Add authentication methods
                if (![string]::IsNullOrEmpty($app.Authentications)) {
                    $authMethods = $app.Authentications -split '\|'
                    $encodedAppID = ConvertTo-URL -text $app.AppID
                    $authURL = "$applicationsURL/$encodedAppID/Authentications"

                    foreach ($authString in $authMethods) {
                        if (![string]::IsNullOrEmpty($authString)) {
                            try {
                                $authObject = Convert-StringToObject -String $authString

                                # Verify AuthType exists
                                if (-not $authObject.AuthType) {
                                    Write-LogMessage -Type Warning -Message "  Skipping authentication method - missing AuthType. Raw data: $authString"
                                    $authFailureCount++
                                    continue
                                }

                                $authBody = @{
                                    authentication = $authObject
                                }

                                Write-LogMessage -Type Verbose -Message "  Adding authentication method: $($authObject.AuthType)"
                                Write-LogMessage -Type Debug -Message "  Auth body: $($authBody | ConvertTo-Json -Depth 5)"

                                $newAuth = Invoke-PASRestMethod -Method POST -URI $authURL -Header $sessionHeader -Body ($authBody | ConvertTo-Json -Depth 5)

                                if ($null -ne $newAuth) {
                                    $authSuccessCount++
                                }
                            }
                            catch {
                                Write-LogMessage -Type Warning -Message "  Failed to add authentication method: $($_.Exception.Message)"
                                $authFailureCount++
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-LogMessage -Type Error -Message "Failed to create application '$($app.AppID)': $($_.Exception.Message)"
            $failureCount++
        }
    }

    # Summary
    Write-LogMessage -Type Info -Message "Import Summary:"
    Write-LogMessage -Type Info -Message "  Applications - Success: $successCount, Failed: $failureCount"
    if (($authSuccessCount + $authFailureCount) -gt 0) {
        Write-LogMessage -Type Info -Message "  Authentication Methods - Success: $authSuccessCount, Failed: $authFailureCount"
    }

}
catch {
    Write-LogMessage -Type Error -Message "Import failed: $($_.Exception.Message)"
    throw
}
finally {
    # Cleanup
    if ($managedSession -and $null -ne $sessionHeader) {
        Invoke-PASLogoff -Header $sessionHeader -BaseURL $PVWAUrl
        Write-LogMessage -Type Verbose -Message "Session logged off"
    }
    elseif ($null -ne $logonToken) {
        Write-LogMessage -Type Verbose -Message "Session token was provided - NOT logging off (session management is caller's responsibility)"
    }

    # Clear sensitive data
    if ($null -ne $Credential) {
        $Credential = $null
    }

    Write-LogMessage -Type Info -Message "Import CyberArk Applications - Complete"
}
#endregion
