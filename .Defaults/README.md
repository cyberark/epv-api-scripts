# CyberArkDefaults PowerShell Module

PowerShell module for managing CyberArk default parameter values across all scripts in EPV-API-Scripts. This module enables session token reuse and simplified script execution by configuring `$PSDefaultParameterValues` for common CyberArk parameters.

## Features

- Set default PVWA URL and authentication type for all CyberArk scripts
- Store and reuse session tokens across multiple script executions
- Support for both Self-Hosted PAM and Privilege Cloud
- Works with any CyberArk PowerShell script that uses common parameters
- Session management (logoff and cleanup)
- View current default parameter values

## Installation

### Quick Install (Recommended)

**For Current User:**
```powershell
# Navigate to the .Defaults directory
cd "G:\epv-api-scripts\.Defaults"

# Import the module temporarily
Import-Module ".\CyberArkDefaults.psd1"

# Install for current user (works for PowerShell 5.1 and 7+)
Install-CyberArkDefaults

# Module is now installed and can be imported from anywhere
Import-Module CyberArkDefaults
```

**For All Users (Requires Administrator):**
```powershell
# Run PowerShell as Administrator
# Navigate to the .Defaults directory
cd "G:\epv-api-scripts\.Defaults"

# Import the module temporarily
Import-Module ".\CyberArkDefaults.psd1"

# Install for all users (works for PowerShell 5.1 and 7+)
Install-CyberArkDefaults -AllUsers

# Module is now installed system-wide
Import-Module CyberArkDefaults
```

### Manual Installation Options

#### Option 1: Load for Current Session Only (Quick Start)

```powershell
# Navigate to the .Defaults directory
cd "G:\epv-api-scripts\.Defaults"

# Import the module for this session only
Import-Module ".\CyberArkDefaults.psd1"

# Verify module is loaded
Get-Command -Module CyberArkDefaults

# Module will be available until you close PowerShell
# No installation required - perfect for testing or one-time use
```

#### Option 2: Install for Current User (Manual Method)

```powershell
# Navigate to the .Defaults directory
cd "G:\epv-api-scripts\.Defaults"

# For PowerShell 5.1
$modulePath = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\CyberArkDefaults"

# For PowerShell 7+
# $modulePath = "$env:USERPROFILE\Documents\PowerShell\Modules\CyberArkDefaults"

New-Item -ItemType Directory -Path $modulePath -Force

# Copy module files
Copy-Item -Path ".\CyberArkDefaults.psm1" -Destination $modulePath
Copy-Item -Path ".\CyberArkDefaults.psd1" -Destination $modulePath

# Import the module
Import-Module CyberArkDefaults

# Verify installation
Get-Command -Module CyberArkDefaults

# Module is now installed and can be imported from anywhere
```

#### Option 3: Install for All Users (Requires Admin)

```powershell
# Navigate to the .Defaults directory
cd "G:\epv-api-scripts\.Defaults"

# For PowerShell 5.1
$modulePath = "$env:ProgramFiles\WindowsPowerShell\Modules\CyberArkDefaults"

# For PowerShell 7+
$modulePath = "$env:ProgramFiles\PowerShell\Modules\CyberArkDefaults"

New-Item -ItemType Directory -Path $modulePath -Force

# Copy module files
Copy-Item -Path ".\CyberArkDefaults.psm1" -Destination $modulePath
Copy-Item -Path ".\CyberArkDefaults.psd1" -Destination $modulePath

# Import the module
Import-Module CyberArkDefaults

# Verify installation
Get-Command -Module CyberArkDefaults
```

#### Option 4: Auto-Load on Every PowerShell Session

Add to your PowerShell profile (`$PROFILE`):

```powershell
# Edit your profile
notepad $PROFILE

# Add this line to auto-import the module
Import-Module CyberArkDefaults
```

## Commands

The module exports six functions:

- `Set-CyberArkDefaults` - Configure default parameter values
- `Show-CyberArkDefaults` - Display current defaults
- `Clear-CyberArkDefaults` - Remove defaults without logging off
- `Invoke-CyberArkLogoff` - Logoff session and remove defaults
- `Install-CyberArkDefaults` - Install module for current user
- `Uninstall-CyberArkDefaults` - Uninstall module from current user

## Quick Start

### Self-Hosted PAM

```powershell
# Import the module
Import-Module CyberArkDefaults

# Set defaults (will prompt for credentials)
Set-CyberArkDefaults -PVWAUrl "https://pvwa.lab.local"

# Now run any CyberArk script without common parameters
.\Safe-Management.ps1 -Add -SafeName "T-APP-MyApp" -Description "Application Safe"
.\Accounts_Onboard_Utility.ps1 -CsvPath "accounts.csv" -Create

# View current defaults
Show-CyberArkDefaults

# Logoff and clear when done
Invoke-CyberArkLogoff
```

### Privilege Cloud

```powershell
# Import the module
Import-Module CyberArkDefaults

# Obtain session token externally (using Identity authentication)
$header = Get-IdentityHeader -IdentityTenantURL "something.id.cyberark.cloud" -IdentityUserName "UserToAuthenticate@cyberark.cloud.ID"

# Set defaults with token
Set-CyberArkDefaults -PCloudURL "https://EPV-API-Script.privilegecloud.cyberark.cloud/PasswordVault" -logonToken $header

# Now run any CyberArk script
.\Safe-Management.ps1 -Add -SafeName "T-APP-MyApp" -Description "Application Safe"
.\Accounts_Onboard_Utility.ps1 -CsvPath "accounts.csv" -Create

# View current defaults
Show-CyberArkDefaults

# Clear when done (no logoff for Privilege Cloud)
Clear-CyberArkDefaults
```

## Advanced Usage

### With Existing Credentials

```powershell
# Use existing credential object
$cred = Get-Credential
Set-CyberArkDefaults -PVWAUrl "https://pvwa.lab.local" -Credential $cred
```

### LDAP Authentication

```powershell
# Use LDAP authentication
Set-CyberArkDefaults -PVWAUrl "https://pvwa.lab.local" -AuthenticationType ldap
```

### RADIUS Authentication

```powershell
# RADIUS with OTP
$cred = Get-Credential
Set-CyberArkDefaults -PVWAUrl "https://pvwa.lab.local" -AuthenticationType radius -Credential $cred -OTP "123456"
```

### Skip Authentication

```powershell
# Set URL only (no authentication - will prompt per script)
Set-CyberArkDefaults -PVWAUrl "https://pvwa.lab.local" -SkipAuthentication
```

### Disable Certificate Validation

```powershell
# Disable certificate validation (testing only)
Set-CyberArkDefaults -PVWAUrl "https://pvwa.lab.local" -DisableCertificateValidation
```

## How It Works

The module uses PowerShell's `$PSDefaultParameterValues` with wildcard patterns (`*:ParameterName`) to automatically apply default values to any script that accepts common CyberArk parameters:

- `*:PVWAUrl` / `*:PVWAURL` / `*:PCloudURL`
- `*:AuthenticationType`
- `*:logonToken` / `*:session` / `*:sessionToken`
- `*:DisableCertificateValidation`

This works with:

- Scripts from `github.com/cyberark/epv-api-scripts`
- Custom CyberArk scripts
- Any PowerShell script that uses these parameter names

**Note:** For Privilege Cloud, always include `/PasswordVault` in the URL:
- Gen 2 (Current): `https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault`
- Gen 1 (Legacy): `https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault`

## Session Management

### Self-Hosted PAM

```powershell
# Authenticate and set defaults
Set-CyberArkDefaults -PVWAUrl "https://pvwa.lab.local"

# ... work with multiple scripts ...

# Logoff and clear when done
Invoke-CyberArkLogoff
```

### Privilege Cloud

```powershell
# Set defaults with external token (use full URL with /PasswordVault)
Set-CyberArkDefaults -PCloudURL "https://EPV-API-Scripts.privilegecloud.cyberark.cloud/PasswordVault" -logonToken $token

# ... work with multiple scripts ...

# Clear when done (no logoff needed)
Clear-CyberArkDefaults
```

## Uninstallation

### Quick Uninstall

**Remove from Current User:**
```powershell
# Import the module if not already loaded
Import-Module CyberArkDefaults

# Uninstall (works for PowerShell 5.1 and 7+)
Uninstall-CyberArkDefaults

# Or force without confirmation
Uninstall-CyberArkDefaults -Force
```

**Remove from All Users (Requires Administrator):**
```powershell
# Run PowerShell as Administrator
# Import the module if not already loaded
Import-Module CyberArkDefaults

# Uninstall from all users (works for PowerShell 5.1 and 7+)
Uninstall-CyberArkDefaults -AllUsers

# Or force without confirmation
Uninstall-CyberArkDefaults -AllUsers -Force
```

### Manual Uninstallation

```powershell
# Remove the module from current session
Remove-Module CyberArkDefaults

# For PowerShell 5.1
$modulePath = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\CyberArkDefaults"

# For PowerShell 7+
# $modulePath = "$env:USERPROFILE\Documents\PowerShell\Modules\CyberArkDefaults"

# Delete module files
Remove-Item -Path $modulePath -Recurse -Force
```

## PowerShell Version Compatibility

The module works with both PowerShell 5.1 and PowerShell 7+:

| Feature | PowerShell 5.1 | PowerShell 7+ |
|---------|---------------|---------------|
| Module Location (User) | `Documents\WindowsPowerShell\Modules` | `Documents\PowerShell\Modules` |
| Module Location (System) | `Program Files\WindowsPowerShell\Modules` | `Program Files\PowerShell\Modules` |
| Install-CyberArkDefaults | ✅ Auto-detects | ✅ Auto-detects |
| Install-CyberArkDefaults -AllUsers | ✅ Auto-detects (Admin required) | ✅ Auto-detects (Admin required) |
| Uninstall-CyberArkDefaults | ✅ Auto-detects | ✅ Auto-detects |
| Uninstall-CyberArkDefaults -AllUsers | ✅ Auto-detects (Admin required) | ✅ Auto-detects (Admin required) |
| All other functions | ✅ Fully supported | ✅ Fully supported |

## Requirements

- PowerShell 5.1 or higher
- Network access to CyberArk PVWA
- Valid CyberArk credentials with appropriate permissions

## Compatibility

This module is compatible with any CyberArk PowerShell script that uses standard parameter names:

- Scripts in this repository (epv-api-scripts)
- Custom scripts that follow PowerShell best practices
- Community scripts from other sources

## Troubleshooting

### Module Not Found

```powershell
# Verify module is installed
Get-Module -ListAvailable CyberArkDefaults

# Check module paths
$env:PSModulePath -split ';'

# Manually specify module path
Import-Module "C:\Path\To\CyberArkDefaults\CyberArkDefaults.psd1"
```

### View Current Defaults

```powershell
# Using module function
Show-CyberArkDefaults

# Or directly view $PSDefaultParameterValues
$PSDefaultParameterValues.GetEnumerator() | Where-Object { $_.Key -like '*:PVWA*' -or $_.Key -like '*:logon*' }
```

### Clear Stuck Defaults

```powershell
# Clear all CyberArk defaults
Clear-CyberArkDefaults

# Or manually clear specific defaults
$PSDefaultParameterValues.Remove('*:PVWAUrl')
$PSDefaultParameterValues.Remove('*:logonToken')
```


## References

- [CyberArk REST API Documentation](https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/api-ref-intro.htm)
- [PowerShell $PSDefaultParameterValues](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_parameters_default_values)
- [CyberArk EPV API Scripts Repository](https://github.com/cyberark/epv-api-scripts)
