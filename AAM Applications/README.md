# CyberArk Application Management Scripts

PowerShell scripts for managing CyberArk Applications and their authentication methods via REST API.

## Overview

These scripts provide a complete toolkit for CyberArk Application Identity Manager (AIM) operations, including creating applications, managing authentication methods, and retrieving configuration details. All scripts support session token reuse, multiple authentication types (CyberArk, LDAP, RADIUS), and work with both Privilege Cloud and Self-Hosted PAM.

## Features

- ✅ **Session Token Support** - Reuse authentication across multiple operations
- ✅ **Multiple Authentication Types** - CyberArk, LDAP, and RADIUS
- ✅ **Privilege Cloud & Self-Hosted** - Compatible with both deployment models
- ✅ **Comprehensive Management** - Full CRUD operations for applications and authentication methods
- ✅ **Self-Contained** - No external dependencies or helper scripts required

## Scripts

| Script | Description |
|--------|-------------|
| [Get-CyberArkApplications.ps1](#get-cyberarkapplications) | List all applications or filter by criteria |
| [New-CyberArkApplication.ps1](#new-cyberarkapplication) | Create a new application |
| [Get-CyberArkAppAuthentication.ps1](#get-cyberarkappAuthentication) | View authentication methods for an application |
| [Add-CyberArkAppAuthentication.ps1](#add-cyberarkappAuthentication) | Add authentication methods (Path, Hash, OSUser, etc.) |
| [Remove-CyberArkAppAuthentication.ps1](#remove-cyberarkappAuthentication) | Delete an authentication method |
| [Remove-CyberArkApplication.ps1](#remove-cyberarkapplication) | Delete an application |
| [Export-CyberArkApplications.ps1](#export-cyberarkapplications) | Export applications to CSV with authentication methods |
| [Import-CyberArkApplications.ps1](#import-cyberarkapplications) | Import applications from CSV with authentication methods |
| [Export-Import-Applications.ps1](#export-import-applications-legacy) | Legacy export/import script (v9.10+) |
| [Show-CyberArkAppWorkflow.ps1](#show-cyberarkappworkflow) | Complete workflow demo with all authentication types |

## Quick Start

### Basic Usage
Prompts for CyberArk credentials on each command
```powershell
# List all applications
.\Get-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com"

# Create a new application
.\New-CyberArkApplication.ps1 -PVWAUrl "https://pvwa.company.com" -AppID "MyApp"

# Add Path authentication
.\Add-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" `
    -AppID "MyApp" -Path "C:\Program Files\MyApp\app.exe"
```

### Privilege Cloud

```powershell
# Privilege Cloud requires session token (obtain through Identity authentication)
.\Get-CyberArkApplications.ps1 -PVWAUrl "https://mikeb.privilegecloud.cyberark.cloud" -logonToken "your-session-token"

# For easier usage with Privilege Cloud, use Set-CyberArkDefaults.ps1
.\Set-CyberArkDefaults.ps1 -PCloudURL "https://mikeb.privilegecloud.cyberark.cloud" -logonToken "your-session-token"
.\Get-CyberArkApplications.ps1
```

### Use with Set-CyberArkDefaults

For the easiest experience, use with [Set-CyberArkDefaults.ps1](./):

See documentation for Set-CyberArkDefault to see all parameters and options

**Self-Hosted:**
```powershell
# Set defaults once (Assumes CyberArk authentication and prompts for credentials)
# Assumes that Set-CyberArkDefaults.ps1 has been copied to same folder (Not required)
..\Set-CyberArkDefaults.ps1 -PVWAUrl "https://pvwa.company.com"

# Now run scripts without common parameters
.\Get-CyberArkApplications.ps1
.\New-CyberArkApplication.ps1 -AppID "MyApp"
.\Add-CyberArkAppAuthentication.ps1 -AppID "MyApp" -Path "C:\App\app.exe"

# Logoff when done
.\Set-CyberArkDefaults.ps1 -LogOff
```

**Privilege Cloud:**
```powershell
# Set defaults with session token (obtain token separately)
# Assumes that Set-CyberArkDefaults.ps1 has been copied to same folder (Not required)
.\Set-CyberArkDefaults.ps1 -PCloudURL "https://mikeb.privilegecloud.cyberark.cloud" -logonToken "your-session-token"

# Now run scripts without common parameters
.\Get-CyberArkApplications.ps1
.\New-CyberArkApplication.ps1 -AppID "MyApp"
.\Add-CyberArkAppAuthentication.ps1 -AppID "MyApp" -Path "C:\App\app.exe"

# Clear when done (no logoff needed for Privilege Cloud)
.\Set-CyberArkDefaults.ps1 -Clear
```

## Script Details

### Get-CyberArkApplications

Retrieves CyberArk Applications with optional filtering.

**Parameters:**
- `PVWAUrl` - PVWA base URL
- `AppID` - Optional: Filter by application name
- `Location` - Optional: Filter by vault location
- `Credential` - Optional: PSCredential object
- `AuthenticationType` - Optional: cyberark, ldap, or radius (default: cyberark)
- `logonToken` - Optional: Pre-existing session token

**Examples:**
```powershell
# List all applications
.\Get-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com"

# Filter by AppID
.\Get-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com" -AppID "MyApp"

# Use LDAP authentication
.\Get-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com" -AuthenticationType ldap
```

### New-CyberArkApplication

Creates a new CyberArk Application.

**Parameters:**
- `PVWAUrl` - PVWA base URL
- `AppID` - Application identifier (required)
- `Description` - Optional: Application description
- `Location` - Optional: Vault location (default: "\")
- `Disabled` - Optional: Create as disabled (default: $false)
- `BusinessOwnerFName`, `BusinessOwnerLName`, `BusinessOwnerEmail`, `BusinessOwnerPhone` - Optional
- `AccessPermittedFrom`, `AccessPermittedTo` - Optional: Access time restrictions
- `ExpirationDate` - Optional: Application expiration date

**Examples:**
```powershell
# Create basic application
.\New-CyberArkApplication.ps1 -PVWAUrl "https://pvwa.company.com" -AppID "MyApp"

# Create with full details
.\New-CyberArkApplication.ps1 -PVWAUrl "https://pvwa.company.com" `
    -AppID "MyApp" `
    -Description "Production Application" `
    -BusinessOwnerEmail "owner@company.com" `
    -Location "\Applications\Production"
```

### Get-CyberArkAppAuthentication

Retrieves authentication methods configured for an application.

**Parameters:**
- `PVWAUrl` - PVWA base URL
- `AppID` - Application identifier (required)

**Examples:**
```powershell
.\Get-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" -AppID "MyApp"
```

### Add-CyberArkAppAuthentication

Adds authentication methods to an application. You can add multiple authentication methods in a single call.

**Supported Authentication Types:**
- **Path** - File or folder path
- **Hash** - Executable hash
- **OSUser** - Windows/Unix user
- **MachineAddress** - IP address or subnet
- **CertificateSerialNumber** - Certificate serial number
- **Certificate Attributes** - Certificate attributes (Subject, Issuer, SAN)

**Parameters:**
- `PVWAUrl` - PVWA base URL
- `AppID` - Application identifier (required)
- `Path` - Path to executable or folder (can provide multiple as array)
- `Hash` - File hash value (can provide multiple as array)
- `OSUser` - Windows/Unix user (can provide multiple as array)
- `MachineAddress` - IP address or subnet (can provide multiple as array)
- `CertificateSerialNumber` - Certificate serial number (can provide multiple as array)
- `CertificateIssuer` - Certificate issuer attributes (array)
- `CertificateSubject` - Certificate subject attributes (array)
- `CertificateSubjectAlternativeName` - Certificate SAN attributes (array)
- `PathIsFolder` - For Path: Is folder (default: $false)
- `PathAllowInternalScripts` - For Path: Allow scripts (default: $false)
- `HashComment` - Optional comment for Hash
- `CertificateSerialNumberComment` - Optional comment for Certificate Serial Number

**Examples:**
```powershell
# Path authentication
.\Add-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" `
    -AppID "MyApp" -Path "C:\Program Files\MyApp\app.exe"

# Add multiple authentication methods at once
.\Add-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" `
    -AppID "MyApp" `
    -Path "C:\Program Files\MyApp\app.exe" `
    -OSUser "DOMAIN\ServiceAccount" `
    -MachineAddress "192.168.1.0/24"

# Add multiple paths
.\Add-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" `
    -AppID "MyApp" `
    -Path @("C:\App\app1.exe", "C:\App\app2.exe")

# Machine Address authentication (subnet)
.\Add-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" `
    -AppID "MyApp" -MachineAddress "192.168.1.0/24"

# OS User authentication
.\Add-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" `
    -AppID "MyApp" -OSUser "DOMAIN\ServiceAccount"

# Certificate Attributes authentication
.\Add-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" `
    -AppID "MyApp" `
    -CertificateSubject @("CN=app.company.com","OU=IT") `
    -CertificateIssuer @("CN=Company Root CA")

# Hash authentication with comment
.\Add-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" `
    -AppID "MyApp" -Hash "A1B2C3D4E5F6" -HashComment "Production server hash"
```

### Remove-CyberArkAppAuthentication

Deletes an authentication method from an application.

**Parameters:**
- `PVWAUrl` - PVWA base URL
- `AppID` - Application identifier (required)
- `AuthID` - Authentication ID to delete (required)

**Examples:**
```powershell
# First, get the AuthID
.\Get-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" -AppID "MyApp"

# Delete the authentication method
.\Remove-CyberArkAppAuthentication.ps1 -PVWAUrl "https://pvwa.company.com" -AppID "MyApp" -AuthID 5
```

### Remove-CyberArkApplication

Deletes an application from CyberArk (prompts for confirmation).

**Parameters:**
- `PVWAUrl` - PVWA base URL
- `AppID` - Application identifier (required)

**Examples:**
```powershell
.\Remove-CyberArkApplication.ps1 -PVWAUrl "https://pvwa.company.com" -AppID "MyApp"
```

### Export-CyberArkApplications

Exports CyberArk Applications and their authentication methods to CSV. Supports exporting all applications or filtering by specific AppID. All authentication methods are serialized and included in the export.

**Parameters:**
- `PVWAUrl` - PVWA base URL (required)
- `CSVPath` - Path to CSV file for export (required)
- `AppID` - Optional: Filter by specific application name
- `Credential` - Optional: PSCredential object
- `AuthenticationType` - Optional: cyberark, ldap, or radius (default: cyberark)
- `logonToken` - Optional: Pre-existing session token

**Examples:**
```powershell
# Export all applications
.\Export-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com" `
    -CSVPath ".\applications.csv"

# Export specific application
.\Export-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com" `
    -AppID "MyApp" -CSVPath ".\myapp.csv"

# Export using session token
.\Export-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com" `
    -CSVPath ".\applications.csv" -logonToken $token
```

### Import-CyberArkApplications

Imports CyberArk Applications and their authentication methods from CSV. Creates applications and automatically adds all authentication methods defined in the CSV file.

**Parameters:**
- `PVWAUrl` - PVWA base URL (required)
- `CSVPath` - Path to CSV file for import (required)
- `Credential` - Optional: PSCredential object
- `AuthenticationType` - Optional: cyberark, ldap, or radius (default: cyberark)
- `logonToken` - Optional: Pre-existing session token

**Examples:**
```powershell
# Import applications from CSV
.\Import-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com" `
    -CSVPath ".\applications.csv"

# Import using session token
.\Import-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com" `
    -CSVPath ".\applications.csv" -logonToken $token

# Import using LDAP authentication
.\Import-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com" `
    -CSVPath ".\applications.csv" -AuthenticationType ldap
```

**CSV Format:**
The CSV file contains application details and authentication methods in a serialized format. Authentication methods are stored in the `Authentications` column using the format: `AuthType=value;Property=value|AuthType=value;Property=value`

**Supported Authentication Types in CSV:**
- path, hash, osUser, machineAddress, certificateserialnumber, certificateattr

### Export-Import-Applications (Legacy)

Exports CyberArk Applications and their authentication methods to CSV, or imports applications from CSV. This script supports bulk operations for backing up or migrating application configurations. The script supports v9.10 of PVWA and up.

**Modes:**
- **Export** - Exports applications with all authentication methods to CSV
- **Import** - Creates applications and authentication methods from CSV

**Parameters:**
- `PVWAURL` - PVWA base URL (required)
- `CSVPath` - Path to CSV file for export/import (required)
- `Export` - Switch to enable export mode
- `Import` - Switch to enable import mode
- `AuthType` - Optional: Authentication type (default: cyberark)
- `AppID` - Optional (Export only): Filter by specific application name

**Export Examples:**
```powershell
# Export all applications to CSV
..\Export-Import-Applications.ps1 -Export `
    -PVWAURL "https://pvwa.company.com/PasswordVault" `
    -CSVPath ".\myApps.csv"

# Export specific application
..\Export-Import-Applications.ps1 -Export `
    -PVWAURL "https://pvwa.company.com/PasswordVault" `
    -AppID "App1" `
    -CSVPath ".\myApps.csv"

# Export using LDAP authentication
..\Export-Import-Applications.ps1 -Export `
    -PVWAURL "https://pvwa.company.com/PasswordVault" `
    -AuthType ldap `
    -CSVPath ".\myApps.csv"
```

**Import Examples:**
```powershell
# Import applications from CSV
..\Export-Import-Applications.ps1 -Import `
    -PVWAURL "https://pvwa.company.com/PasswordVault" `
    -CSVPath ".\myApps.csv"

# Import using LDAP authentication
..\Export-Import-Applications.ps1 -Import `
    -PVWAURL "https://pvwa.company.com/PasswordVault" `
    -AuthType ldap `
    -CSVPath ".\myApps.csv"
```

**CSV Format:**
The CSV file contains all application details and authentication methods. The exported CSV can be modified as needed before importing to adjust application configurations.

**Use Cases:**
- Backup application configurations
- Migrate applications between environments
- Bulk application creation
- Disaster recovery
- Environment synchronization

## Common Parameters

All scripts support these common parameters:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `PVWAUrl` | String | Yes | Base URL of PVWA (e.g., https://pvwa.company.com) |
| `Credential` | PSCredential | No | Credentials for authentication (prompts if not provided) |
| `AuthenticationType` | String | No | Authentication type: cyberark, ldap, radius (default: cyberark) |
| `OTP` | String | No | RADIUS one-time password |
| `logonToken` | String/Object | No | Pre-existing session token (aliases: session, sessionToken) |
| `DisableCertificateValidation` | Switch | No | Disable SSL validation (testing only) |

## Session Token Behavior

- **Without `-logonToken`**: Script authenticates and logs off automatically
- **With `-logonToken`**: Script uses existing token and does NOT log off

This enables efficient batch operations by reusing authentication.

## Authentication Types

### CyberArk (Default)
Standard CyberArk vault authentication.

```powershell
.\Get-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com"
```

### LDAP
Authenticate using LDAP credentials.

```powershell
.\Get-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com" -AuthenticationType ldap
```

### RADIUS
Authenticate using RADIUS with OTP.

```powershell
.\Get-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com" `
    -AuthenticationType radius -OTP "123456"
```

## Show-CyberArkAppWorkflow

Complete demonstration script showing the full application management workflow with session token reuse. Demonstrates all authentication types and export/import functionality.

**Features:**
- Single authentication with session token reuse across all operations
- Creates test application with 8 different authentication types
- Exports application with all authentication methods to CSV
- Modifies and imports application from CSV
- Displays authentication methods for both original and imported applications
- Automated cleanup option
- Supports interactive and automated modes

**Parameters:**
- `PVWAUrl` - PVWA base URL (required)
- `Credential` - Optional: PSCredential object
- `AuthenticationType` - Optional: cyberark, ldap, or radius (default: cyberark)
- `logonToken` - Optional: Pre-existing session token
- `Automated` - Optional: Run without prompts (auto yes to export/import, auto cleanup apps, keep CSV files)

**Demonstrated Authentication Types:**
1. **Path** - File/folder path authentication
2. **OSUser** - Windows user account authentication
3. **MachineAddress** - IP address/subnet authentication
4. **Hash** - File hash authentication
5. **CertificateSerialNumber** - Certificate serial number
6. **CertificateSubject** - Certificate subject attributes
7. **CertificateIssuer** - Certificate issuer attributes
8. **CertificateSubjectAlternativeName** - Certificate SAN

**Examples:**
```powershell
# Interactive mode - prompts for confirmation at each step
.\Show-CyberArkAppWorkflow.ps1 -PVWAUrl "https://pvwa.company.com"

# Automated mode - runs complete workflow hands-free
.\Show-CyberArkAppWorkflow.ps1 -PVWAUrl "https://pvwa.company.com" -Automated

# With credentials
$cred = Get-Credential
.\Show-CyberArkAppWorkflow.ps1 -PVWAUrl "https://pvwa.company.com" -Credential $cred -Automated

# Using session token
.\Show-CyberArkAppWorkflow.ps1 -PVWAUrl "https://pvwa.company.com" -logonToken $token
```

**Workflow Steps:**
1. Authenticate (or use provided token)
2. List all existing applications
3. Create test application
4. Add 8 authentication methods (all types)
5. Retrieve and display authentication methods
6. Export application to CSV
7. Modify CSV (rename AppID, update description)
8. Import modified application from CSV
9. Display both original and imported applications with all authentication methods
10. Cleanup (delete applications, keep CSV for inspection)
11. Logoff (if authenticated in this script)

## Example Usage

See [Show-CyberArkAppWorkflow.ps1](Show-CyberArkAppWorkflow.ps1) for a complete working example.
- Single authentication with token reuse
- Creating applications
- Adding authentication methods
- Retrieving configuration
- Proper cleanup

Run the example:
```powershell
.\Show-CyberArkAppWorkflow.ps1 -PVWAUrl "https://pvwa.company.com"
```

## Integration with Other Scripts

These scripts use standard parameters and session token patterns compatible with other CyberArk scripts in this repository. For maximum efficiency, use with [Set-CyberArkDefaults.ps1](../Defaults) to set common parameters once and reuse across all scripts.

## Requirements

- PowerShell 5.1 or higher
- Network access to CyberArk PVWA
- Valid CyberArk credentials with appropriate permissions
- CyberArk PAS v10.4 or higher (for REST API support)

### Required Permissions

Users running these scripts need:
- **Manage Applications** permission in CyberArk
- Access to the relevant Safe/Location where applications are stored

## Error Handling

All scripts include:
- Comprehensive error messages with API details
- Automatic credential cleanup from memory
- Conditional logoff based on session token source
- Verbose logging support (`-Verbose` parameter)

## Security Best Practices

1. ❌ **Never hard-code credentials** in scripts
2. ✅ **Use PSCredential objects** or prompts for interactive sessions
3. ✅ **Use session tokens** for batch operations to minimize authentication
4. ✅ **Always log off** when using direct authentication
5. ✅ **Use TLS 1.2 or higher** (configured automatically)
6. ❌ **Avoid `-DisableCertificateValidation`** in production

## Troubleshooting

### Common Issues

**"Credentials are required to proceed"**
- Provide `-Credential` parameter or pass `-logonToken`

**"Application already exists"**
- Check existing applications with `Get-CyberArkApplications.ps1`
- Use unique AppID or delete existing application first

**Authentication fails with LDAP**
- Verify PVWA is configured for LDAP authentication
- Check LDAP user DN format matches PVWA configuration

**"Session token was provided - NOT logging off"**
- This is expected when using `-logonToken`
- Session management is caller's responsibility

### Enable Verbose Logging

```powershell
.\Get-CyberArkApplications.ps1 -PVWAUrl "https://pvwa.company.com" -Verbose
```

## References

- [CyberArk REST API Documentation](https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/api-ref-intro.htm)
- [CyberArk Application Identity Manager](https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/application-identity-manager.htm)
- [CyberArk Authentication Methods](https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/applications-configure-app-authentication.htm)

---

**Note**: These scripts are provided as-is. Always test in a non-production environment before deploying to production.
