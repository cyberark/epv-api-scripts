<#
.SYNOPSIS
    Demonstrates a complete CyberArk application management workflow with session token reuse.

.DESCRIPTION
    This script demonstrates a full workflow of CyberArk application management operations:
    - Creating an application
    - Adding authentication methods
    - Retrieving application details
    - (Optional) Exporting application to CSV
    - (Optional) Modifying CSV and importing as new application
    - (Optional) Showing both original and imported applications
    - Cleanup operations

    It also shows efficient session token reuse across multiple operations, which is more
    efficient than authenticating for each individual operation.

.PARAMETER PVWAUrl
    The base URL of the CyberArk PVWA (e.g., https://pvwa.company.com)

.PARAMETER AuthenticationType
    The authentication type: cyberark, ldap, or radius (Default: cyberark)

.PARAMETER Credential
    PSCredential object for CyberArk authentication. If not provided, will prompt.

.PARAMETER logonToken
    Pre-existing session token to use. If provided, skips authentication step.

.PARAMETER Automated
    Run in automated mode without prompts. Assumes yes to export/import demo and no to cleanup.

.EXAMPLE
    .\Show-CyberArkAppWorkflow.ps1 -PVWAUrl "https://pvwa.company.com"

.EXAMPLE
    .\Show-CyberArkAppWorkflow.ps1 -PVWAUrl "https://pvwa.company.com" -Automated

.EXAMPLE
    .\Show-CyberArkAppWorkflow.ps1 -PVWAUrl "https://pvwa.company.com" -AuthenticationType ldap

.EXAMPLE
    $cred = Get-Credential
    .\Show-CyberArkAppWorkflow.ps1 -PVWAUrl "https://pvwa.company.com" -Credential $cred

.EXAMPLE
    # Use existing token
    $token = (Invoke-RestMethod -Uri "https://pvwa.company.com/API/Auth/CyberArk/Logon" ...)
    .\Show-CyberArkAppWorkflow.ps1 -PVWAUrl "https://pvwa.company.com" -logonToken $token
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PVWAUrl,

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [ValidateSet('cyberark', 'ldap', 'radius')]
    [String]$AuthenticationType = 'cyberark',

    [Parameter(Mandatory = $false)]
    [Alias('session', 'sessionToken')]
    $logonToken,

    [Parameter(Mandatory = $false)]
    [switch]$Automated
)

# Set TLS to 1.2 or higher
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Output -InputObject ('=' * 80)
Write-Output -InputObject 'CyberArk Application Management - Workflow Demonstration'
Write-Output -InputObject ('=' * 80)

try {
    # Step 1: Authenticate once and get session token (or use provided token)
    $shouldLogoff = $true

    if ($logonToken) {
        Write-Output "`n[STEP 1] Using provided session token..."
        if ($logonToken.GetType().name -eq 'String') {
            $sessionToken = $logonToken
        } else {
            $sessionToken = $logonToken
        }
        $shouldLogoff = $false
        Write-Output 'Session token accepted! Will NOT log off at end.'
        Write-Output '  Token will be reused for all subsequent operations...'
    } else {
        Write-Output "`n[STEP 1] Authenticating to CyberArk..."

        if (-not $Credential) {
            $Credential = Get-Credential -Message 'Enter CyberArk credentials'
        }

        $authUrl = "$PVWAUrl/API/Auth/$AuthenticationType/Logon"
        $authBody = @{
            username          = $Credential.UserName
            password          = $Credential.GetNetworkCredential().Password
            concurrentSession = $true
        } | ConvertTo-Json

        $sessionToken = Invoke-RestMethod -Uri $authUrl -Method Post -Body $authBody -ContentType 'application/json'
        $shouldLogoff = $true
        Write-Output 'Authentication successful! Session token obtained.'
        Write-Output '  Token will be reused for all subsequent operations...'
    }

    # Step 2: List all applications using the token
    Write-Output "`n[STEP 2] Retrieving all applications..."
    & "$PSScriptRoot\Get-CyberArkApplications.ps1" -PVWAUrl $PVWAUrl -logonToken $sessionToken
    Write-Output 'Applications retrieved successfully'

    # Step 3: Create a test application (uncomment to test)
    Write-Output "`n[STEP 3] Creating test application..."
    $testAppID = "TestApp_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Write-Output "  Creating application: $testAppID"

    & "$PSScriptRoot\New-CyberArkApplication.ps1" `
        -PVWAUrl $PVWAUrl `
        -logonToken $sessionToken `
        -AppID $testAppID `
        -Description 'Test application created by workflow demonstration' `
        -Location '\'

    Write-Output 'Application created successfully'

    # Step 4: Add multiple authentication methods to the test application
    Write-Output "`n[STEP 4] Adding authentication methods..."
    Write-Output "  Adding Path authentication to $testAppID"

    & "$PSScriptRoot\Add-CyberArkAppAuthentication.ps1" `
        -PVWAUrl $PVWAUrl `
        -logonToken $sessionToken `
        -AppID $testAppID `
        -Path 'C:\Program Files\TestApp\test.exe'

    Write-Output "  Adding OSUser authentication to $testAppID"
    & "$PSScriptRoot\Add-CyberArkAppAuthentication.ps1" `
        -PVWAUrl $PVWAUrl `
        -logonToken $sessionToken `
        -AppID $testAppID `
        -OSUser 'DOMAIN\AppUser'

    Write-Output "  Adding MachineAddress authentication to $testAppID"
    & "$PSScriptRoot\Add-CyberArkAppAuthentication.ps1" `
        -PVWAUrl $PVWAUrl `
        -logonToken $sessionToken `
        -AppID $testAppID `
        -MachineAddress '192.168.1.100'

    Write-Output "  Adding Hash authentication to $testAppID"
    & "$PSScriptRoot\Add-CyberArkAppAuthentication.ps1" `
        -PVWAUrl $PVWAUrl `
        -logonToken $sessionToken `
        -AppID $testAppID `
        -Hash 'ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890'

    Write-Output "  Adding Certificate Serial Number authentication to $testAppID"
    & "$PSScriptRoot\Add-CyberArkAppAuthentication.ps1" `
        -PVWAUrl $PVWAUrl `
        -logonToken $sessionToken `
        -AppID $testAppID `
        -CertificateSerialNumber '1234567890ABCDEF'

    Write-Output "  Adding Certificate Subject authentication to $testAppID"
    & "$PSScriptRoot\Add-CyberArkAppAuthentication.ps1" `
        -PVWAUrl $PVWAUrl `
        -logonToken $sessionToken `
        -AppID $testAppID `
        -CertificateSubject @('CN=TestApp', 'OU=IT', 'O=Company', 'C=US')

    Write-Output "  Adding Certificate Issuer authentication to $testAppID"
    & "$PSScriptRoot\Add-CyberArkAppAuthentication.ps1" `
        -PVWAUrl $PVWAUrl `
        -logonToken $sessionToken `
        -AppID $testAppID `
        -CertificateIssuer @('CN=Company Root CA', 'OU=Security')

    Write-Output "  Adding Certificate Subject Alternative Name authentication to $testAppID"
    & "$PSScriptRoot\Add-CyberArkAppAuthentication.ps1" `
        -PVWAUrl $PVWAUrl `
        -logonToken $sessionToken `
        -AppID $testAppID `
        -CertificateSubjectAlternativeName @('DNS Name=testapp.company.com', 'DNS Name=testapp.local')

    Write-Output 'Authentication methods added successfully'

    # Step 5: Retrieve authentication methods
    Write-Output "`n[STEP 5] Retrieving authentication methods..."
    & "$PSScriptRoot\Get-CyberArkAppAuthentication.ps1" `
        -PVWAUrl $PVWAUrl `
        -logonToken $sessionToken `
        -AppID $testAppID

    Write-Output 'Authentication methods retrieved successfully'

    # Step 6: Ask if user wants to demo export/import
    Write-Output "`n[STEP 6] Export/Import demonstration..."

    if ($Automated) {
        $demoExportImport = 'yes'
        Write-Output "Automated mode: Running export/import demo"
    } else {
        $demoExportImport = Read-Host "Do you want to demo Export/Import functionality? (yes/no)"
    }

    $importedAppID = $null
    $exportPath = $null

    if ($demoExportImport -eq 'yes') {
        # Step 6a: Export application to CSV
        Write-Output "`n  [STEP 6a] Exporting application to CSV..."
        $exportPath = "$PSScriptRoot\export_$testAppID.csv"
        Write-Output "    Exporting $testAppID to: $exportPath"

        & "$PSScriptRoot\Export-CyberArkApplications.ps1" `
            -PVWAUrl $PVWAUrl `
            -logonToken $sessionToken `
            -AppID $testAppID `
            -CSVPath $exportPath

        Write-Output '    Application exported successfully'

        # Step 6b: Modify CSV to rename application
        Write-Output "`n  [STEP 6b] Modifying CSV for import..."
        $exportedData = Import-Csv $exportPath
        $importedAppID = "$($exportedData.AppID)_Imported"
        $exportedData.AppID = $importedAppID
        $exportedData.Description = "$($exportedData.Description) (Imported copy from $testAppID)"

        Write-Output "    Original AppID: $testAppID"
        Write-Output "    New AppID: $importedAppID"

        # Save modified CSV
        $importPath = "$PSScriptRoot\import_$testAppID.csv"
        $exportedData | Export-Csv -Path $importPath -NoTypeInformation
        Write-Output "    Modified CSV saved to: $importPath"

        # Step 6c: Import the modified application
        Write-Output "`n  [STEP 6c] Importing application from CSV..."
        & "$PSScriptRoot\Import-CyberArkApplications.ps1" `
            -PVWAUrl $PVWAUrl `
            -logonToken $sessionToken `
            -CSVPath $importPath

        Write-Output '    Application imported successfully'

        # Step 6d: Show both applications
        Write-Output "`n  [STEP 6d] Listing all applications (showing both original and imported)..."
        & "$PSScriptRoot\Get-CyberArkApplications.ps1" `
            -PVWAUrl $PVWAUrl `
            -logonToken $sessionToken

        Write-Output "`n    Both applications now exist:"
        Write-Output "      - Original: $testAppID"
        Write-Output "      - Imported: $importedAppID"

        # Step 6e: Show authentication methods for original application
        Write-Output "`n  [STEP 6e] Authentication methods for ORIGINAL application ($testAppID)..."
        & "$PSScriptRoot\Get-CyberArkAppAuthentication.ps1" `
            -PVWAUrl $PVWAUrl `
            -logonToken $sessionToken `
            -AppID $testAppID

        # Step 6f: Show authentication methods for imported application
        Write-Output "`n  [STEP 6f] Authentication methods for IMPORTED application ($importedAppID)..."
        & "$PSScriptRoot\Get-CyberArkAppAuthentication.ps1" `
            -PVWAUrl $PVWAUrl `
            -logonToken $sessionToken `
            -AppID $importedAppID

        # Step 6f: Show authentication methods for imported application
        Write-Output "`n  [STEP 6f] Authentication methods for IMPORTED application ($importedAppID)..."
        & "$PSScriptRoot\Get-CyberArkAppAuthentication.ps1" `
            -PVWAUrl $PVWAUrl `
            -logonToken $sessionToken `
            -AppID $importedAppID

        # Clean up import CSV
        if (Test-Path $importPath) {
            Remove-Item $importPath -Force
            Write-Output "`n    Import CSV cleaned up"
        }
    } else {
        Write-Output "  Export/Import demo skipped"
    }

    # Step 7: Ask if user wants to clean up
    Write-Output "`n[STEP 7] Cleanup..."

    if ($Automated) {
        $cleanup = 'yes'
        Write-Output "Automated mode: Cleaning up test applications"
    } else {
        $cleanup = Read-Host "Do you want to delete the test application(s)? (yes/no)"
    }

    if ($cleanup -eq 'yes') {
        $headers = @{
            'Authorization' = $sessionToken
            'Content-Type'  = 'application/json'
        }

        # Delete original application
        Write-Output "  Deleting original application: $testAppID"

        $getAuthUrl = "$PVWAUrl/WebServices/PIMServices.svc/Applications/$testAppID/Authentications/"
        $authMethods = Invoke-RestMethod -Uri $getAuthUrl -Method Get -Headers $headers

        if ($authMethods.authentication) {
            foreach ($auth in $authMethods.authentication) {
                Write-Output "    Removing authentication (AuthID: $($auth.authID))..."
                $deleteAuthUrl = "$PVWAUrl/WebServices/PIMServices.svc/Applications/$testAppID/Authentications/$($auth.authID)/"
                Invoke-RestMethod -Uri $deleteAuthUrl -Method Delete -Headers $headers
            }
        }

        $deleteAppUrl = "$PVWAUrl/WebServices/PIMServices.svc/Applications/$testAppID/"
        Invoke-RestMethod -Uri $deleteAppUrl -Method Delete -Headers $headers
        Write-Output "    Original application deleted successfully"

        # Delete imported application if it exists
        if ($importedAppID) {
            Write-Output "`n  Deleting imported application: $importedAppID"

            $getAuthUrl = "$PVWAUrl/WebServices/PIMServices.svc/Applications/$importedAppID/Authentications/"
            try {
                $authMethods = Invoke-RestMethod -Uri $getAuthUrl -Method Get -Headers $headers

                if ($authMethods.authentication) {
                    foreach ($auth in $authMethods.authentication) {
                        Write-Output "    Removing authentication (AuthID: $($auth.authID))..."
                        $deleteAuthUrl = "$PVWAUrl/WebServices/PIMServices.svc/Applications/$importedAppID/Authentications/$($auth.authID)/"
                        Invoke-RestMethod -Uri $deleteAuthUrl -Method Delete -Headers $headers
                    }
                }

                $deleteAppUrl = "$PVWAUrl/WebServices/PIMServices.svc/Applications/$importedAppID/"
                Invoke-RestMethod -Uri $deleteAppUrl -Method Delete -Headers $headers
                Write-Output "    Imported application deleted successfully"
            } catch {
                Write-Output "    Warning: Could not delete imported application: $_"
            }
        }

        Write-Output "`n  All test applications cleaned up"
    } else {
        Write-Output "  Test application(s) were NOT deleted:"
        Write-Output "    - $testAppID"
        if ($importedAppID) {
            Write-Output "    - $importedAppID"
        }
    }

    # Step 8: Clean up export file
    if ($exportPath -and (Test-Path $exportPath)) {
        if ($Automated) {
            Write-Output "`nAutomated mode: Keeping export file for inspection at: $exportPath"
        } else {
            $cleanupExport = Read-Host "`nDo you want to delete the export file? (yes/no)"
            if ($cleanupExport -eq 'yes') {
                Remove-Item $exportPath -Force
                Write-Output '  Export file deleted'
            } else {
                Write-Output "  Export file kept at: $exportPath"
            }
        }
    }

    # Step 9: Manually logoff (only if we authenticated in this script)
    if ($shouldLogoff) {
        Write-Output "`n[STEP 9] Logging off..."
        $logoffUrl = "$PVWAUrl/API/Auth/Logoff"
        $headers = @{
            'Authorization' = $sessionToken
        }
        Invoke-RestMethod -Uri $logoffUrl -Method Post -Headers $headers
        Write-Output 'Session closed successfully'
    } else {
        Write-Output "`n[STEP 9] Skipping logoff (token was provided externally)..."
        Write-Output '  External caller is responsible for session management'
    }

    # Summary
    Write-Output @"

$('=' * 80)
SUMMARY:
$('=' * 80)
"@
    if ($logonToken) {
        Write-Output @"
Used EXISTING session token (provided as parameter)
Token reused across MULTIPLE script operations
Session NOT logged off (external token management)
"@
    } else {
        Write-Output @"
Authenticated ONCE and obtained session token
Used token across MULTIPLE script operations
No logoff occurred during script calls
"@
        if ($shouldLogoff) {
            Write-Output 'Manually logged off when all operations completed'
        }
    }
    Write-Output @"

This demonstrates efficient session token reuse!
$('=' * 80)
"@

} catch {
    Write-Output "`nERROR: $_"

    # Attempt to logoff (only if we authenticated)
    if ($sessionToken -and $shouldLogoff) {
        try {
            Write-Output "`nAttempting to logoff..."
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
        Write-Output "`nSession token was provided externally - NOT logging off."
    }

    exit 1
}

Write-Output "`nExample completed successfully!"
