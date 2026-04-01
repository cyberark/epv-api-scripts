# EPV-API-Common PowerShell Module

[![PowerShell Version](https://img.shields.io/badge/PowerShell-7.4%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Version](https://img.shields.io/badge/Version-0.1.7.1--Alpha-green.svg)]()
[![License](https://img.shields.io/badge/License-CyberArk-blue.svg)]()

## Overview

EPV-API-Common is a comprehensive PowerShell module that provides common functions for interacting with CyberArk's Enterprise Password Vault (EPV) APIs. This module supports PowerShell 7.4+ and provides a unified interface for managing accounts, safes, users, and other CyberArk components across multiple deployment types including on-premises PVWA and CyberArk Privileged Cloud.

## Key Features

- **🔐 Account Management**: Create, retrieve, update, and delete privileged accounts
- **🗄️ Safe Operations**: Manage safes and safe members with comprehensive permissions
- **👥 User Administration**: Handle vault users, groups, and identity management
- **🔗 Session Management**: Simplified authentication and session handling for multiple environments
- **📊 System Health**: Monitor CyberArk component health and status
- **🔍 Discovery Services**: Manage account discovery and onboarding processes
- **🌐 Multi-Environment Support**: Works with on-premises PVWA and Privileged Cloud
- **📝 Comprehensive Logging**: Built-in logging and sensitive data protection
- **🛡️ Security First**: Secure credential handling and data protection features

## Supported CyberArk Components

### Core PAS (Privileged Access Security)
- **PVWA (Password Vault Web Access)**: Account and safe management
- **CPM (Central Policy Manager)**: Account lifecycle management
- **PSM (Privileged Session Manager)**: Session monitoring and recording
- **PTA (Privileged Threat Analytics)**: Security analytics and threat detection

### Cloud and Identity Services
- **CyberArk Identity**: Identity and access management integration
- **Privileged Cloud**: SaaS-based privileged access management
- **Discovery Management**: Automated account discovery and onboarding

### Specialized Services
- **Connector Management**: Manage network connectors and pools
- **SIA (Secrets Infrastructure Automation)**: Connector deployment automation

## Installation

### Quick Installation

Extract the distribution ZIP file and run the installation script:

```powershell
# System installation (requires administrator privileges)
.\Install-Module.ps1

# User installation (current user only)
.\Install-Module.ps1 -UserScope

# Force installation (overwrites existing)
.\Install-Module.ps1 -UserScope -Force
```

### Manual Installation

1. Download the latest release from the distribution package
2. Extract to your PowerShell modules directory:
   - **System**: `C:\Program Files\PowerShell\Modules\EPV-API-Common`
   - **User**: `C:\Users\[Username]\Documents\PowerShell\Modules\EPV-API-Common`
3. Import the module: `Import-Module EPV-API-Common`

### Prerequisites

- **PowerShell 7.4 or later**
- **Network access** to CyberArk PVWA/Privileged Cloud
- **Valid CyberArk credentials** or API tokens
- **Active Directory module** (for AD-related functions)

## Quick Start

### Basic Authentication

```powershell
# Import the module
Import-Module EPV-API-Common

# Create a session for on-premises PVWA
$session = New-Session -PVWAURL "https://pvwa.company.com" -Username "admin" -Password (ConvertTo-SecureString "password" -AsPlainText -Force)

# Create a session for Privileged Cloud
$session = New-Session -PCloudSubdomain "company" -Username "admin@company.com" -Password (ConvertTo-SecureString "password" -AsPlainText -Force)
```

### Working with Accounts

```powershell
# Get all accounts in a safe
$accounts = Get-Account -PVWAURL $session.PVWAURL -LogonToken $session.LogonToken -Safe "IT-Servers"

# Retrieve a specific account password
$password = Get-AccountPassword -PVWAURL $session.PVWAURL -LogonToken $session.LogonToken -AccountID "123_45" -Reason "Maintenance"

# Create a new account
$newAccount = New-Account -PVWAURL $session.PVWAURL -LogonToken $session.LogonToken -SafeName "IT-Servers" -PlatformID "WinServerLocal" -Address "server01.company.com" -Username "admin"
```

### Managing Safes and Members

```powershell
# Create a new safe
New-Safe -PVWAURL $session.PVWAURL -LogonToken $session.LogonToken -safeName "NewSafe" -description "Application Safe" -managingCPM "PasswordManager"

# Add a member to a safe
Add-SafeMember -PVWAURL $session.PVWAURL -LogonToken $session.LogonToken -SafeName "IT-Servers" -memberName "ITAdmins" -MemberType "Group" -useAccounts $true -retrieveAccounts $true

# Get safe members
$members = Get-SafeMember -PVWAURL $session.PVWAURL -LogonToken $session.LogonToken -SafeName "IT-Servers"
```

### Discovery and Onboarding

```powershell
# Get discovered accounts
$discoveredAccounts = Get-DiscoveredAccount -DiscoveryURL "https://company.discoverymgmt.cyberark.cloud" -LogonToken $session.LogonToken -Filter "type eq 'Windows'"

# Onboard discovered accounts
Start-DiscoveredAccountOnboard -DiscoveryURL "https://company.discoverymgmt.cyberark.cloud" -LogonToken $session.LogonToken -AccountID "discovered-123" -SafeName "OnboardedAccounts"
```

## Module Structure

```
EPV-API-Common/
├── EPV-API-Common.psd1          # Module manifest
├── EPV-API-Common.psm1          # Main module file
├── Documentation/               # Comprehensive documentation
│   ├── README.md               # This file
│   ├── Functions/              # Function reference documentation
│   ├── Examples/               # Usage examples and scenarios
│   └── Troubleshooting.md      # Common issues and solutions
├── Classes/                    # PowerShell classes
├── Format/                     # Custom formatting files
└── en-US/                     # Help documentation
```

## Function Categories

### Core Session Management
- `New-Session` - Create authenticated sessions
- `Set-Session` - Configure session parameters

### Account Operations
- `Get-Account` - Retrieve account information
- `New-Account` - Create new accounts
- `Set-Account` - Update account properties
- `Remove-Account` - Delete accounts
- `Get-AccountPassword` - Retrieve account passwords
- `Set-AccountPassword` - Update account passwords

### Safe Management
- `Get-Safe` - Retrieve safe information
- `New-Safe` - Create new safes
- `Set-Safe` - Update safe properties
- `Export-Safe` - Export safe data

### Safe Member Administration
- `Get-SafeMember` - Retrieve safe members
- `Add-SafeMember` - Add members to safes
- `Set-SafeMember` - Update member permissions
- `Remove-SafeMember` - Remove members from safes
- `Export-SafeMember` - Export safe member data
- `Import-SafeMember` - Import safe member data

### User and Group Management
- `Get-VaultUser` - Retrieve vault users
- `Add-VaultUser` - Add new vault users
- `Remove-VaultUser` - Remove vault users
- `Get-IdentityUser` - Retrieve identity users
- `Get-IdentityGroup` - Retrieve identity groups

### Discovery Services
- `Get-DiscoveredAccount` - Retrieve discovered accounts
- `Add-DiscoveredAccount` - Add discovered accounts
- `Remove-DiscoveredAccount` - Remove discovered accounts
- `Start-DiscoveredAccountOnboard` - Onboard discovered accounts
- `Get-DiscoveryRuleSet` - Manage discovery rules

### System Administration
- `Get-SystemHealth` - Check component health
- `Get-Platform` - Retrieve platform information
- `Connect-AccountPSM` - Initiate PSM sessions

### Utility Functions
- `Write-LogMessage` - Comprehensive logging
- `Remove-SensitiveData` - Data sanitization
- `Get-UPN` - Active Directory UPN lookup
- `Get-SamAccountName` - Active Directory SAM lookup

## Configuration

### Environment Variables

```powershell
# Enable sensitive data logging (debugging only)
$global:LogSensitiveData = $true

# Set default log file location
$global:LogFile = "C:\Logs\EPV-API-Common.log"
```

### Logging Configuration

The module provides comprehensive logging capabilities:

```powershell
# Configure logging
Write-LogMessage -MSG "Operation started" -type Info -LogFile "C:\Logs\operations.log"
Write-LogMessage -MSG "Warning message" -type Warning
Write-LogMessage -MSG "Error occurred" -type Error
```

## Advanced Usage

### Pipeline Support

Many functions support PowerShell pipeline operations:

```powershell
# Get all safes and their members
Get-Safe -PVWAURL $session.PVWAURL -LogonToken $session.LogonToken | 
    ForEach-Object { Get-SafeMember -SafeName $_.SafeName }

# Bulk account operations
$accountList | Get-Account -PVWAURL $session.PVWAURL -LogonToken $session.LogonToken |
    Where-Object { $_.lastModifiedTime -lt (Get-Date).AddDays(-30) }
```

### Error Handling

```powershell
try {
    $account = Get-Account -PVWAURL $session.PVWAURL -LogonToken $session.LogonToken -AccountID "123_45"
    Write-LogMessage -MSG "Account retrieved successfully" -type Success
}
catch {
    Write-LogMessage -MSG "Failed to retrieve account: $($_.Exception.Message)" -type Error
    throw
}
```

### Batch Operations

```powershell
# Batch process multiple accounts
$accounts = @("account1", "account2", "account3")
$results = $accounts | ForEach-Object -Parallel {
    Get-Account -PVWAURL $using:session.PVWAURL -LogonToken $using:session.LogonToken -AccountID $_
} -ThrottleLimit 5
```

## Best Practices

### Security
1. **Always use secure strings** for passwords and sensitive data
2. **Enable logging** but be mindful of sensitive data exposure
3. **Use least privilege** principles for service accounts
4. **Implement proper error handling** to prevent credential exposure

### Performance
1. **Use pipeline operations** for bulk processing
2. **Implement throttling** for large-scale operations
3. **Cache session tokens** when possible
4. **Use parallel processing** for independent operations

### Maintenance
1. **Regular module updates** to get latest features and fixes
2. **Monitor logs** for operational insights
3. **Test in development** before production deployment
4. **Document custom configurations** and extensions

## Troubleshooting

### Common Issues

**Authentication Failures**
```powershell
# Verify session creation
$session = New-Session -PVWAURL "https://pvwa.company.com" -Username "admin" -Password $securePassword -Verbose

# Test connectivity
Test-NetConnection -ComputerName "pvwa.company.com" -Port 443
```

**Module Import Issues**
```powershell
# Check module path
$env:PSModulePath -split ';'

# Force reload module
Remove-Module EPV-API-Common -Force -ErrorAction SilentlyContinue
Import-Module EPV-API-Common -Force
```

**Permission Errors**
```powershell
# Check required permissions in CyberArk
Get-VaultUser -PVWAURL $session.PVWAURL -LogonToken $session.LogonToken -UserName $session.Username
```

For detailed troubleshooting information, see [Troubleshooting.md](Troubleshooting.md).

## Contributing

This module is maintained by CyberArk. For issues, feature requests, or contributions:

1. Review existing issues and documentation
2. Follow PowerShell best practices and coding standards
3. Include comprehensive tests for new functionality
4. Update documentation for any changes

## Support

- **Documentation**: Complete function reference available in the `Documentation/Functions/` directory
- **Examples**: Practical examples in the `Documentation/Examples/` directory
- **Logging**: Enable verbose logging for detailed operation information

## Version History

### 0.1.2-Alpha (Current)
- Enhanced function documentation
- Improved error handling and logging
- Added distribution packaging with installation script
- Extended Privileged Cloud support
- Added Discovery Management functions

### Previous Versions
- 0.1.1: Initial discovery and connector management functions
- 0.1.0: Core PAS functionality and session management

## License

This module is provided by CyberArk. Please refer to your CyberArk license agreement for usage terms and conditions.

---


**Note**: This module requires PowerShell 7.4+ and is designed for CyberArk administrators and developers working with CyberArk APIs. Always follow your organization's security policies when using privileged access management tools.
