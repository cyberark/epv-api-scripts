#Requires -Version 5.1

<#
.SYNOPSIS
    PowerShell module for managing CyberArk default parameter values.

.DESCRIPTION
    This module provides functions to configure $PSDefaultParameterValues for CyberArk
    PowerShell scripts, enabling session token reuse and simplified script execution.
#>

# Set TLS to 1.2 or higher
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Show-CyberArkDefaults {
    <#
    .SYNOPSIS
        Display current CyberArk default parameter values.

    .DESCRIPTION
        Shows all CyberArk-related default parameter values currently set in $PSDefaultParameterValues.

    .EXAMPLE
        Show-CyberArkDefaults
    #>
    [CmdletBinding()]
    param()

    Write-Host ("`n" + ('=' * 80)) -ForegroundColor Cyan
    Write-Host 'Current CyberArk Default Parameter Values' -ForegroundColor Cyan
    Write-Host ('=' * 80) -ForegroundColor Cyan

    $cyberArkDefaults = $global:PSDefaultParameterValues.GetEnumerator() |
    Where-Object {
        $PSItem.Key -like '*:PVWAUrl' -or
        $PSItem.Key -like '*:PVWAURL' -or
        $PSItem.Key -like '*:PVWAAddress' -or
        $PSItem.Key -like '*:PCloudURL' -or
        $PSItem.Key -like '*:AuthenticationType' -or
        $PSItem.Key -like '*:logonToken' -or
        $PSItem.Key -like '*:session' -or
        $PSItem.Key -like '*:sessionToken' -or
        $PSItem.Key -like '*:DisableCertificateValidation'
    }

    if ($cyberArkDefaults) {
        foreach ($default in $cyberArkDefaults | Sort-Object Key) {
            $displayValue = if (($default.Key -like '*:logonToken' -or $default.Key -like '*:session' -or $default.Key -like '*:sessionToken') -and $default.Value) {
                "[Session Token Set - $(($default.Value -as [string]).Substring(0, [Math]::Min(20, ($default.Value -as [string]).Length)))...]"
            } else {
                $default.Value
            }
            Write-Host "  $($default.Key.PadRight(60)) = " -NoNewline -ForegroundColor White
            Write-Host "$displayValue" -ForegroundColor Green
        }
    } else {
        Write-Host '  No CyberArk defaults currently set' -ForegroundColor Yellow
    }

    Write-Host ('=' * 80) -ForegroundColor Cyan
}

function Clear-CyberArkDefaults {
    <#
    .SYNOPSIS
        Clear CyberArk default parameter values without logging off.

    .DESCRIPTION
        Removes all CyberArk-related default parameter values from $PSDefaultParameterValues.
        Does not perform a logoff operation. Use for Privilege Cloud or when preserving sessions.

    .EXAMPLE
        Clear-CyberArkDefaults
    #>
    [CmdletBinding()]
    param()

    Write-Host ("`n" + ('=' * 80)) -ForegroundColor Cyan
    Write-Host 'Clearing CyberArk Default Parameter Values (No Logoff)' -ForegroundColor Cyan
    Write-Host ('=' * 80) -ForegroundColor Cyan

    $keysToRemove = $global:PSDefaultParameterValues.Keys | Where-Object {
        $PSItem -like '*:PVWAUrl' -or
        $PSItem -like '*:PVWAURL' -or
        $PSItem -like '*:PVWAAddress' -or
        $PSItem -like '*:PCloudURL' -or
        $PSItem -like '*:AuthenticationType' -or
        $PSItem -like '*:logonToken' -or
        $PSItem -like '*:session' -or
        $PSItem -like '*:sessionToken' -or
        $PSItem -like '*:DisableCertificateValidation'
    }

    if ($keysToRemove) {
        Write-Host "`n[CLEARING] Removing default parameter values..." -ForegroundColor Cyan
        foreach ($key in $keysToRemove) {
            Write-Host "  Removing: $key" -ForegroundColor Gray
            $global:PSDefaultParameterValues.Remove($key)
        }
        Write-Host "`nAll CyberArk defaults cleared (session NOT logged off)" -ForegroundColor Green
    } else {
        Write-Host "`n  No CyberArk defaults to clear" -ForegroundColor Yellow
    }

    Write-Host ('=' * 80) -ForegroundColor Cyan
}

function Invoke-CyberArkLogoff {
    <#
    .SYNOPSIS
        Logoff CyberArk session and clear default parameter values.

    .DESCRIPTION
        Logs off the current CyberArk session using the stored session token and PVWA URL,
        then removes all CyberArk-related default parameter values.

    .EXAMPLE
        Invoke-CyberArkLogoff
    #>
    [CmdletBinding()]
    param()

    Write-Host ("`n" + ('=' * 80)) -ForegroundColor Yellow
    Write-Host 'Logoff and Clear CyberArk Default Parameter Values' -ForegroundColor Yellow
    Write-Host ('=' * 80) -ForegroundColor Yellow

    $pcloudKey = $global:PSDefaultParameterValues.Keys | Where-Object { $PSItem -like '*:PCloudURL' } | Select-Object -First 1

    if ($pcloudKey) {
        Write-Host "`nERROR: Cannot logoff Privilege Cloud sessions using this function" -ForegroundColor Red
        Write-Host '' -ForegroundColor Red
        Write-Host '  Privilege Cloud sessions are managed externally and cannot be logged off' -ForegroundColor Yellow
        Write-Host '  using the standard API/Auth/Logoff endpoint.' -ForegroundColor Yellow
        Write-Host '' -ForegroundColor Yellow
        Write-Host '  Use Clear-CyberArkDefaults instead to remove defaults without logging off:' -ForegroundColor White
        Write-Host '    Clear-CyberArkDefaults' -ForegroundColor Cyan
        Write-Host '' -ForegroundColor Yellow
        Write-Host ('=' * 80) -ForegroundColor Yellow
        return
    }

    $tokenKey = $global:PSDefaultParameterValues.Keys | Where-Object {
        $PSItem -like '*:logonToken' -or $PSItem -like '*:session' -or $PSItem -like '*:sessionToken'
    } | Select-Object -First 1

    $sessionToken = if ($tokenKey) {
        $global:PSDefaultParameterValues[$tokenKey]
    } else {
        $null
    }

    $urlKey = $global:PSDefaultParameterValues.Keys | Where-Object {
        $PSItem -like '*:PVWAUrl' -or $PSItem -like '*:PVWAURL' -or $PSItem -like '*:PVWAAddress'
    } | Select-Object -First 1

    $PVWAUrl = if ($urlKey) {
        $global:PSDefaultParameterValues[$urlKey]
    } else {
        $null
    }

    if ($sessionToken -and $PVWAUrl) {
        Write-Host "`n[LOGOFF] Session token detected, logging off..." -ForegroundColor Cyan
        try {
            $logoffUrl = "$($PVWAUrl.TrimEnd('/'))/API/Auth/Logoff"
            $headers = @{
                'Authorization' = $sessionToken
            }
            Invoke-RestMethod -Uri $logoffUrl -Method Post -Headers $headers -ErrorAction Stop | Out-Null
            Write-Host '  Successfully logged off from CyberArk' -ForegroundColor Green
        } catch {
            Write-Host '  Could not log off (session may have already expired)' -ForegroundColor Yellow
            Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Gray
        }
    } elseif ($sessionToken) {
        Write-Host "`n[WARNING] Session token exists but no PVWA URL found - cannot logoff automatically" -ForegroundColor Yellow
        Write-Host '  You may need to logoff manually if the session is still active' -ForegroundColor Gray
    }

    $keysToRemove = $global:PSDefaultParameterValues.Keys | Where-Object {
        $PSItem -like '*:PVWAUrl' -or
        $PSItem -like '*:PVWAURL' -or
        $PSItem -like '*:PVWAAddress' -or
        $PSItem -like '*:PCloudURL' -or
        $PSItem -like '*:AuthenticationType' -or
        $PSItem -like '*:logonToken' -or
        $PSItem -like '*:session' -or
        $PSItem -like '*:sessionToken' -or
        $PSItem -like '*:DisableCertificateValidation'
    }

    if ($keysToRemove) {
        Write-Host "`n[CLEARING] Removing default parameter values..." -ForegroundColor Cyan
        foreach ($key in $keysToRemove) {
            Write-Host "  Removing: $key" -ForegroundColor Gray
            $global:PSDefaultParameterValues.Remove($key)
        }
        Write-Host "`nAll CyberArk defaults cleared" -ForegroundColor Green
    } else {
        Write-Host "`n  No CyberArk defaults to clear" -ForegroundColor Yellow
    }

    Write-Host ('=' * 80) -ForegroundColor Yellow
}

function Install-CyberArkDefaults {
    <#
    .SYNOPSIS
        Installs the CyberArkDefaults module for the current user or all users.

    .DESCRIPTION
        Copies the CyberArkDefaults module files to the PowerShell modules directory.
        Automatically detects PowerShell version and installs to the correct location:
        - PowerShell 5.1: Documents\WindowsPowerShell\Modules (user) or Program Files\WindowsPowerShell\Modules (all users)
        - PowerShell 7+: Documents\PowerShell\Modules (user) or Program Files\PowerShell\Modules (all users)

    .PARAMETER AllUsers
        Installs the module for all users (requires administrator privileges).
        If not specified, installs for current user only.

    .PARAMETER Force
        Overwrites existing module installation if present.

    .EXAMPLE
        Install-CyberArkDefaults

    .EXAMPLE
        Install-CyberArkDefaults -AllUsers

    .EXAMPLE
        Install-CyberArkDefaults -Force
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$AllUsers,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    Write-Output ("`n" + ('=' * 80))
    Write-Output 'Install CyberArkDefaults Module'
    Write-Output ('=' * 80)

    try {
        $moduleName = 'CyberArkDefaults'
        $moduleFiles = @('CyberArkDefaults.psm1', 'CyberArkDefaults.psd1')

        # Check for admin privileges if installing for all users
        if ($AllUsers) {
            $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) {
                throw "Installation for all users requires administrator privileges. Please run PowerShell as Administrator or remove the -AllUsers parameter."
            }
        }

        # Determine PowerShell version and module path
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $psVersion = "PowerShell 7+"
            if ($AllUsers) {
                $baseModulePath = "$env:ProgramFiles\PowerShell\Modules"
                $scope = "All Users (System-wide)"
            } else {
                $baseModulePath = "$env:USERPROFILE\Documents\PowerShell\Modules"
                $scope = "Current User"
            }
        } else {
            $psVersion = "PowerShell 5.1"
            if ($AllUsers) {
                $baseModulePath = "$env:ProgramFiles\WindowsPowerShell\Modules"
                $scope = "All Users (System-wide)"
            } else {
                $baseModulePath = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules"
                $scope = "Current User"
            }
        }

        $moduleInstallPath = Join-Path -Path $baseModulePath -ChildPath $moduleName

        Write-Output "`nDetected $psVersion"
        Write-Output "Installation scope: $scope"
        Write-Output "Target installation path: $moduleInstallPath"

        # Check if module already exists
        if (Test-Path -Path $moduleInstallPath) {
            if ($Force) {
                Write-Output "`nExisting module found - Force flag specified, will overwrite"
            } else {
                Write-Warning "`nModule is already installed at: $moduleInstallPath"
                Write-Output "Use -Force to overwrite the existing installation"
                return
            }
        }

        # Get source directory (where this module is currently running from)
        $sourceDir = Split-Path -Parent $PSCommandPath

        # Verify source files exist
        $missingFiles = @()
        foreach ($file in $moduleFiles) {
            $sourcePath = Join-Path -Path $sourceDir -ChildPath $file
            if (-not (Test-Path -Path $sourcePath)) {
                $missingFiles += $file
            }
        }

        if ($missingFiles.Count -gt 0) {
            throw "Cannot find required module files: $($missingFiles -join ', ')"
        }

        # Create module directory
        if ($PSCmdlet.ShouldProcess($moduleInstallPath, 'Create module directory')) {
            Write-Output "`nCreating module directory..."
            $null = New-Item -ItemType Directory -Path $moduleInstallPath -Force
            Write-Output "  Created: $moduleInstallPath"
        }

        # Copy module files
        Write-Output "`nCopying module files..."
        foreach ($file in $moduleFiles) {
            $sourcePath = Join-Path -Path $sourceDir -ChildPath $file
            $destPath = Join-Path -Path $moduleInstallPath -ChildPath $file

            if ($PSCmdlet.ShouldProcess($destPath, 'Copy module file')) {
                Copy-Item -Path $sourcePath -Destination $destPath -Force
                Write-Output "  Copied: $file"
            }
        }

        Write-Output "`n" + ('=' * 80)
        Write-Output 'Installation Complete!'
        Write-Output ('=' * 80)
        Write-Output "`nThe CyberArkDefaults module has been installed to:"
        Write-Output "  $moduleInstallPath"
        Write-Output "`nInstallation scope: $scope"
        Write-Output "`nTo use the module in future sessions:"
        Write-Output "  Import-Module CyberArkDefaults"
        Write-Output "`nThe module is already loaded in this session."
        Write-Output ('=' * 80)

    } catch {
        Write-Output "`nInstallation failed:" -ForegroundColor Red
        Write-Output $_.Exception.Message -ForegroundColor Red
        throw
    }
}

function Uninstall-CyberArkDefaults {
    <#
    .SYNOPSIS
        Uninstalls the CyberArkDefaults module from the current user or all users.

    .DESCRIPTION
        Removes the CyberArkDefaults module files from the PowerShell modules directory.
        Automatically detects PowerShell version and removes from the correct location.
        Also clears any active default parameter values.

    .PARAMETER AllUsers
        Uninstalls the module from all users location (requires administrator privileges).
        If not specified, uninstalls from current user location.

    .PARAMETER Force
        Bypasses confirmation prompt.

    .EXAMPLE
        Uninstall-CyberArkDefaults

    .EXAMPLE
        Uninstall-CyberArkDefaults -AllUsers

    .EXAMPLE
        Uninstall-CyberArkDefaults -Force
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$AllUsers,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    Write-Output ("`n" + ('=' * 80))
    Write-Output 'Uninstall CyberArkDefaults Module'
    Write-Output ('=' * 80)

    try {
        $moduleName = 'CyberArkDefaults'

        # Check for admin privileges if uninstalling for all users
        if ($AllUsers) {
            $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) {
                throw "Uninstallation for all users requires administrator privileges. Please run PowerShell as Administrator or remove the -AllUsers parameter."
            }
        }

        # Determine PowerShell version and module path
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $psVersion = "PowerShell 7+"
            if ($AllUsers) {
                $baseModulePath = "$env:ProgramFiles\PowerShell\Modules"
                $scope = "All Users (System-wide)"
            } else {
                $baseModulePath = "$env:USERPROFILE\Documents\PowerShell\Modules"
                $scope = "Current User"
            }
        } else {
            $psVersion = "PowerShell 5.1"
            if ($AllUsers) {
                $baseModulePath = "$env:ProgramFiles\WindowsPowerShell\Modules"
                $scope = "All Users (System-wide)"
            } else {
                $baseModulePath = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules"
                $scope = "Current User"
            }
        }

        $moduleInstallPath = Join-Path -Path $baseModulePath -ChildPath $moduleName

        Write-Output "`nDetected $psVersion"
        Write-Output "Uninstallation scope: $scope"
        Write-Output "Module installation path: $moduleInstallPath"

        # Check if module exists
        if (-not (Test-Path -Path $moduleInstallPath)) {
            Write-Output "`nModule is not installed at: $moduleInstallPath"
            Write-Output "Nothing to uninstall."
            return
        }

        # Confirm uninstallation
        $shouldProcessMessage = "Remove CyberArkDefaults module from $moduleInstallPath"
        if ($Force -or $PSCmdlet.ShouldProcess($moduleInstallPath, $shouldProcessMessage)) {

            # Clear any active defaults
            Write-Output "`nClearing active default parameter values..."
            Clear-CyberArkDefaults

            # Remove the module from current session
            Write-Output "`nRemoving module from current session..."
            if (Get-Module -Name $moduleName) {
                Remove-Module -Name $moduleName -Force
                Write-Output "  Module removed from session"
            }

            # Delete module files
            Write-Output "`nDeleting module files..."
            Remove-Item -Path $moduleInstallPath -Recurse -Force
            Write-Output "  Deleted: $moduleInstallPath"

            Write-Output "`n" + ('=' * 80)
            Write-Output 'Uninstallation Complete!'
            Write-Output ('=' * 80)
            Write-Output "`nThe CyberArkDefaults module has been removed."
            Write-Output "Scope: $scope"
            Write-Output ('=' * 80)
        } else {
            Write-Output "`nUninstallation cancelled."
        }

    } catch {
        Write-Output "`nUninstallation failed:" -ForegroundColor Red
        Write-Output $_.Exception.Message -ForegroundColor Red
        throw
    }
}

function Set-CyberArkDefaults {
    <#
    .SYNOPSIS
        Sets default parameter values for CyberArk PowerShell scripts.

    .DESCRIPTION
        Configures $PSDefaultParameterValues to set common parameters for all CyberArk
        PowerShell scripts in the current PowerShell session. This allows you to authenticate
        once and run multiple scripts without repeating parameters.

    .PARAMETER PVWAUrl
        The base URL of the CyberArk Self-Hosted PVWA (e.g., https://pvwa.lab.local)
        For Privilege Cloud, use -PCloudURL instead.

    .PARAMETER PCloudURL
        The base URL of CyberArk Privilege Cloud including /PasswordVault
        https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault
        REQUIRES -logonToken parameter.

    .PARAMETER logonToken
        Pre-existing session token. REQUIRED when using -PCloudURL.

    .PARAMETER AuthenticationType
        The authentication type: cyberark, ldap, or radius (Default: cyberark)

    .PARAMETER Credential
        PSCredential object for CyberArk authentication. If not provided, will prompt.

    .PARAMETER OTP
        RADIUS one-time password (required if using RADIUS authentication)

    .PARAMETER DisableCertificateValidation
        Disables SSL certificate validation for all scripts. Use only for testing!

    .PARAMETER SkipAuthentication
        Skip authentication and only set PVWAUrl and other defaults (no token)

    .EXAMPLE
        # Privilege Cloud - REQUIRES session token
        $token = "your-privilege-cloud-session-token"
        Set-CyberArkDefaults -PCloudURL "https://EPV-API-Scripts.privilegecloud.cyberark.cloud/PasswordVault" -logonToken $token

    .EXAMPLE
        # Self-Hosted - Authenticate and set defaults
        Set-CyberArkDefaults -PVWAUrl "https://pvwa.lab.local"

    .EXAMPLE
        # Use LDAP authentication
        Set-CyberArkDefaults -PVWAUrl "https://pvwa.lab.local" -AuthenticationType ldap

    .EXAMPLE
        # Set defaults without authentication
        Set-CyberArkDefaults -PVWAUrl "https://pvwa.lab.local" -SkipAuthentication
    #>
    [CmdletBinding(DefaultParameterSetName = 'SetDefaults')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'SetDefaults')]
        [string]$PVWAUrl,

        [Parameter(Mandatory = $true, ParameterSetName = 'PCloud')]
        [string]$PCloudURL,

        [Parameter(Mandatory = $true, ParameterSetName = 'PCloud')]
        [Parameter(Mandatory = $false, ParameterSetName = 'SetDefaults')]
        [Alias('session', 'sessionToken')]
        $logonToken,

        [Parameter(Mandatory = $false, ParameterSetName = 'SetDefaults')]
        [ValidateSet('cyberark', 'ldap', 'radius')]
        [String]$AuthenticationType = 'cyberark',

        [Parameter(Mandatory = $false, ParameterSetName = 'SetDefaults')]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $false, ParameterSetName = 'SetDefaults')]
        [String]$OTP,

        [Parameter(Mandatory = $false, ParameterSetName = 'SetDefaults')]
        [switch]$DisableCertificateValidation,

        [Parameter(Mandatory = $false, ParameterSetName = 'SetDefaults')]
        [switch]$SkipAuthentication
    )

    Write-Host ("`n" + ('=' * 80)) -ForegroundColor Cyan
    Write-Host 'CyberArk - Configure Session Defaults (Privilege Cloud & Self-Hosted)' -ForegroundColor Cyan
    Write-Host ('=' * 80) -ForegroundColor Cyan

    try {
        $isPCloud = $PSCmdlet.ParameterSetName -eq 'PCloud'

        if ($isPCloud) {
            $PVWAUrl = $PCloudURL.TrimEnd('/')
            $sessionToken = $logonToken
            Write-Host "`n[MODE] Privilege Cloud - Using provided session token" -ForegroundColor Cyan
            Write-Host "  URL: $PVWAUrl" -ForegroundColor Gray
            Write-Host '  Token: [Provided Externally]' -ForegroundColor Gray
        } else {
            $PVWAUrl = $PVWAUrl.TrimEnd('/')

            if ($logonToken) {
                $sessionToken = $logonToken
                Write-Host "`n[MODE] Self-Hosted - Using provided session token" -ForegroundColor Cyan
                Write-Host "  URL: $PVWAUrl" -ForegroundColor Gray
            }
        }

        if (-not $isPCloud -and -not $sessionToken -and -not $SkipAuthentication) {
            Write-Host "`n[STEP 1] Authenticating to CyberArk Self-Hosted..." -ForegroundColor Yellow

            if (-not $Credential) {
                $Credential = Get-Credential -Message 'Enter CyberArk credentials'
                if (-not $Credential) {
                    throw 'Credentials are required for authentication. Use -SkipAuthentication to set defaults without authenticating.'
                }
            }

            $Username = $Credential.UserName
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
            $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

            $authUrl = "$PVWAUrl/API/Auth/$AuthenticationType/Logon"
            $authBody = @{
                username          = $Username
                password          = $PlainPassword
                concurrentSession = $true
            } | ConvertTo-Json

            if ($AuthenticationType -eq 'radius' -and $OTP) {
                $authBodyObj = $authBody | ConvertFrom-Json
                $authBodyObj.password = "$PlainPassword,$OTP"
                $authBody = $authBodyObj | ConvertTo-Json
            }

            $sessionToken = Invoke-RestMethod -Uri $authUrl -Method Post -Body $authBody -ContentType 'application/json'

            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            $PlainPassword = $null

            Write-Host 'Authentication successful! Session token obtained.' -ForegroundColor Green
        } elseif (-not $isPCloud -and -not $sessionToken) {
            Write-Host "`n[STEP 1] Skipping authentication (as requested)..." -ForegroundColor Yellow
            Write-Host '  Scripts will prompt for credentials when executed' -ForegroundColor Gray
        } elseif ($sessionToken) {
            Write-Host "`n[STEP 1] Using provided session token..." -ForegroundColor Yellow
            Write-Host '  Token accepted and will be used for all operations' -ForegroundColor Green
        }

        Write-Host "`n[STEP 2] Setting default parameter values (applies to ALL scripts)..." -ForegroundColor Yellow

        $keysToRemove = $global:PSDefaultParameterValues.Keys | Where-Object {
            $PSItem -like '*:PVWAUrl' -or
            $PSItem -like '*:PVWAURL' -or
            $PSItem -like '*:PVWAAddress' -or
            $PSItem -like '*:PCloudURL' -or
            $PSItem -like '*:AuthenticationType' -or
            $PSItem -like '*:logonToken' -or
            $PSItem -like '*:session' -or
            $PSItem -like '*:sessionToken' -or
            $PSItem -like '*:DisableCertificateValidation'
        }
        foreach ($key in $keysToRemove) {
            $global:PSDefaultParameterValues.Remove($key)
        }

        $global:PSDefaultParameterValues['*:PVWAUrl'] = $PVWAUrl
        $global:PSDefaultParameterValues['*:PVWAURL'] = $PVWAUrl
        $global:PSDefaultParameterValues['*:PVWAAddress'] = $PVWAUrl

        if ($isPCloud) {
            $global:PSDefaultParameterValues['*:PCloudURL'] = $PVWAUrl
            Write-Host "  Set PCloudURL/PVWAURL/PVWAAddress for all scripts: $PVWAUrl" -ForegroundColor Green
        } else {
            Write-Host "  Set PVWAUrl/PVWAURL/PVWAAddress for all scripts: $PVWAUrl" -ForegroundColor Green
        }

        if (-not $isPCloud) {
            $global:PSDefaultParameterValues['*:AuthenticationType'] = $AuthenticationType
            Write-Host "  Set AuthenticationType for all scripts: $AuthenticationType" -ForegroundColor Green
        }

        if ($sessionToken) {
            $global:PSDefaultParameterValues['*:logonToken'] = $sessionToken
            $global:PSDefaultParameterValues['*:session'] = $sessionToken
            $global:PSDefaultParameterValues['*:sessionToken'] = $sessionToken
            $tokenPreview = $sessionToken.Substring(0, [Math]::Min(20, $sessionToken.Length))
            Write-Host "  Set logonToken for all scripts: $tokenPreview... (full token stored)" -ForegroundColor Green
        }

        if ($DisableCertificateValidation) {
            $global:PSDefaultParameterValues['*:DisableCertificateValidation'] = $true
            Write-Host "  Set DisableCertificateValidation for all scripts: $true" -ForegroundColor Green
            Write-Host '    WARNING: Certificate validation is disabled!' -ForegroundColor Yellow
        }

        Write-Host "`n[STEP 3] Configuration Summary" -ForegroundColor Yellow
        Write-Host ('=' * 80) -ForegroundColor Cyan
        if ($isPCloud) {
            Write-Host '  Mode: Privilege Cloud' -ForegroundColor White
        } else {
            Write-Host '  Mode: Self-Hosted PAM' -ForegroundColor White
        }
        Write-Host '  Defaults configured for ALL PowerShell scripts' -ForegroundColor White
        Write-Host "`n  Default Parameters Set:" -ForegroundColor White
        if ($isPCloud) {
            Write-Host "    PCloudURL/PVWAURL: $PVWAUrl" -ForegroundColor Gray
        } else {
            Write-Host "    PVWAUrl: $PVWAUrl" -ForegroundColor Gray
            Write-Host "    AuthenticationType: $AuthenticationType" -ForegroundColor Gray
        }
        if ($sessionToken) {
            Write-Host '    logonToken: [Session Token Active]' -ForegroundColor Gray
        } else {
            Write-Host '    logonToken: [Not Set - Will Prompt]' -ForegroundColor Gray
        }
        Write-Host ('=' * 80) -ForegroundColor Cyan

        Write-Host "`n[USAGE] Run ANY CyberArk script without common parameters:" -ForegroundColor Yellow
        Write-Host ''
        Write-Host '  .\Accounts_Onboard_Utility.ps1 -CsvPath accounts.csv -Create' -ForegroundColor White
        Write-Host '  .\Safe-Management.ps1 -Report -SafeName T-APP-MyApp' -ForegroundColor White
        Write-Host '  .\Get-Accounts.ps1 -SafeName T-APP-MyApp' -ForegroundColor White
        Write-Host ''
        Write-Host '  View current defaults:' -ForegroundColor Gray
        Write-Host '    Show-CyberArkDefaults' -ForegroundColor White
        Write-Host ''
        Write-Host '  Clear defaults (no logoff):' -ForegroundColor Gray
        Write-Host '    Clear-CyberArkDefaults' -ForegroundColor White
        Write-Host ''
        Write-Host '  Logoff and clear defaults:' -ForegroundColor Gray
        Write-Host '    Invoke-CyberArkLogoff' -ForegroundColor White

        Write-Host ("`n" + ('=' * 80)) -ForegroundColor Cyan
        Write-Host 'Configuration complete! Defaults are now active.' -ForegroundColor Green
        Write-Host ('=' * 80) -ForegroundColor Cyan

    } catch {
        Write-Host "`nError occurred:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red

        if ($_.ErrorDetails.Message) {
            Write-Host "`nAPI Error Details:" -ForegroundColor Red
            Write-Host $_.ErrorDetails.Message -ForegroundColor Red
        }

        throw
    }
}

Export-ModuleMember -Function Set-CyberArkDefaults, Show-CyberArkDefaults, Clear-CyberArkDefaults, Invoke-CyberArkLogoff
