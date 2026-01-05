<#
.SYNOPSIS
    Exports CyberArk Applications and their authentication methods to CSV

.DESCRIPTION
    This script exports CyberArk Applications including all their authentication methods to a CSV file.
    Supports exporting all applications or filtering by specific AppID.
    Works with both Privilege Cloud and Self-Hosted PAM.

.PARAMETER PVWAUrl
    The base URL of the PVWA (e.g., https://pvwa.company.com or https://tenant.privilegecloud.cyberark.cloud)

.PARAMETER AppID
    Optional. Filter export to a specific application ID

.PARAMETER CSVPath
    Path where the CSV file will be saved

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
    .\Export-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com" -CSVPath ".\applications.csv"
    Exports all applications to CSV

.EXAMPLE
    .\Export-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com" -AppID "MyApp" -CSVPath ".\myapp.csv"
    Exports a specific application

.EXAMPLE
    .\Export-CyberArkApplications.ps1 -PVWAUrl "https://tenant.privilegecloud.cyberark.cloud" -logonToken $token -CSVPath ".\apps.csv"
    Exports using existing session token (Privilege Cloud)

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

    [Parameter(Mandatory = $false, HelpMessage = "Filter by specific Application ID")]
    [Alias("id")]
    [string]$AppID,

    [Parameter(Mandatory = $true, HelpMessage = "Path to save the CSV export file")]
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

Function Convert-ObjectToString {
    param([PSCustomObject]$Object)

    $retString = [string]::Empty
    if ($null -ne $Object) {
        $arrItems = @()
        $Object.PSObject.Properties | ForEach-Object {
            # Skip authID, authenticationID, AppID, and empty values
            if ($_.Name -notin @('authID', 'authenticationID', 'AppID') -and ![string]::IsNullOrEmpty($_.Value)) {
                $value = $_.Value
                # Handle arrays - join with comma (no spaces)
                if ($value -is [Array]) {
                    # Trim each element and join without spaces
                    $value = ($value | ForEach-Object { $_.Trim() }) -join ','
                } else {
                    # For string values, remove spaces after commas (API may return formatted strings)
                    $value = $value -replace ',\s+', ','
                }
                $arrItems += "$($_.Name)=$value"
            }
        }
        $retString = $arrItems -join ';'
    }
    return $retString
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
    Write-LogMessage -Type Info -Message "Export CyberArk Applications - Starting"

    # Initialize SSL/TLS
    Initialize-SSL

    # Normalize PVWA URL - just trim trailing slashes
    $PVWAUrl = $PVWAUrl.TrimEnd('/')

    # Check if CSV file exists
    if (Test-Path $CSVPath) {
        $response = Read-Host "CSV file already exists at '$CSVPath'. Overwrite? (Y/N)"
        if ($response -notmatch '^y(es)?$') {
            Write-LogMessage -Type Warning -Message "Export cancelled by user"
            return
        }
        Remove-Item $CSVPath -Force
    }

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

    # Get applications
    Write-LogMessage -Type Info -Message "Retrieving applications..."
    $applications = @()

    if (![string]::IsNullOrEmpty($AppID)) {
        Write-LogMessage -Type Verbose -Message "Filtering by AppID: $AppID"
        $encodedAppID = ConvertTo-URL -text $AppID
        $response = Invoke-PASRestMethod -Method GET -URI "$applicationsURL/$encodedAppID" -Header $sessionHeader
        if ($null -ne $response.application) {
            $applications = @($response.application)
        }
    }
    else {
        $response = Invoke-PASRestMethod -Method GET -URI $applicationsURL -Header $sessionHeader
        if ($null -ne $response.application) {
            $applications = @($response.application)
        }
    }

    if ($applications.Count -eq 0) {
        Write-LogMessage -Type Warning -Message "No applications found"
        return
    }

    Write-LogMessage -Type Info -Message "Found $($applications.Count) application(s)"

    # Export applications with authentication methods
    $exportData = @()

    foreach ($app in $applications) {
        Write-LogMessage -Type Verbose -Message "Processing application: $($app.AppID)"

        # Create export object with application properties
        $exportObject = [PSCustomObject]@{
            AppID                 = $app.AppID
            Description           = $app.Description
            Location              = $app.Location
            AccessPermittedFrom   = $app.AccessPermittedFrom
            AccessPermittedTo     = $app.AccessPermittedTo
            ExpirationDate        = $app.ExpirationDate
            Disabled              = $app.Disabled
            BusinessOwnerFName    = $app.BusinessOwnerFName
            BusinessOwnerLName    = $app.BusinessOwnerLName
            BusinessOwnerEmail    = $app.BusinessOwnerEmail
            BusinessOwnerPhone    = $app.BusinessOwnerPhone
            Authentications       = ""
        }

        # Get authentication methods for this application
        try {
            $encodedAppID = ConvertTo-URL -text $app.AppID
            $authURL = "$applicationsURL/$encodedAppID/Authentications"
            $authResponse = Invoke-PASRestMethod -Method GET -URI $authURL -Header $sessionHeader

            if ($null -ne $authResponse.authentication) {
                $authStrings = @()
                foreach ($auth in $authResponse.authentication) {
                    $authStrings += Convert-ObjectToString -Object $auth
                }
                $exportObject.Authentications = $authStrings -join '|'
                Write-LogMessage -Type Verbose -Message "  Found $($authResponse.authentication.Count) authentication method(s)"
            }
        }
        catch {
            Write-LogMessage -Type Warning -Message "  Failed to retrieve authentication methods: $($_.Exception.Message)"
        }

        $exportData += $exportObject
    }

    # Export to CSV
    Write-LogMessage -Type Info -Message "Exporting to CSV: $CSVPath"
    $exportData | Export-Csv -Path $CSVPath -NoTypeInformation -Encoding UTF8
    Write-LogMessage -Type Info -Message "Successfully exported $($exportData.Count) application(s)"

}
catch {
    Write-LogMessage -Type Error -Message "Export failed: $($_.Exception.Message)"
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

    Write-LogMessage -Type Info -Message "Export CyberArk Applications - Complete"
}
#endregion
