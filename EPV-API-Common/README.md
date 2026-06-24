# EPV-API-Common PowerShell Module

[![PowerShell Version](https://img.shields.io/badge/PowerShell-7.4%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Version](https://img.shields.io/badge/Version-0.1.8-green.svg)]()
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

### Session Management
- `New-Session` - Create authenticated sessions
- `Set-Session` - Configure session parameters
- `Connect-PASUser` - Logon to PVWA
- `Connect-PTAUser` - Logon to PTA
- `Connect-SAMLUser` - Logon via SAML
- `Connect-SharedPASUser` - Logon as shared user
- `Disconnect-PASUser` - Logoff from PVWA
- `Disconnect-SharedPASUser` - Logoff shared user session

### Account Operations
- `Get-Account` - Retrieve accounts
- `Get-AccountDetails` - Retrieve full account details
- `Get-AccountActivity` - Retrieve account activity log
- `Get-AccountAdvancedSearchProperty` - Get advanced search properties
- `New-Account` - Create a new account
- `New-PersonalPrivilegedAccount` - Create a personal privileged account
- `Set-Account` - Update account properties
- `Remove-Account` - Delete an account

### Account Actions
- `Get-AccountPassword` - Retrieve an account password
- `Get-AccountPrivateSSHKey` - Retrieve an account SSH private key
- `Get-AccountSecretVersions` - List secret versions for an account
- `New-AccountPassword` - Generate a new account password
- `Set-AccountPassword` - Set an account password
- `Set-AccountNextPassword` - Set the next password for an account
- `Invoke-AccountPasswordChange` - Trigger a password change
- `Invoke-AccountVerify` - Trigger account verification
- `Invoke-AccountReconcile` - Trigger account reconciliation
- `Invoke-AccountCheckIn` - Check in an exclusive account
- `Unlock-Account` - Unlock a locked account
- `Grant-AccountAdministrativeAccess` - Grant administrative access to an account
- `Revoke-AccountAdministrativeAccess` - Revoke administrative access from an account
- `Connect-AccountPSM` - Initiate a PSM session for an account
- `Connect-AccountPSMAdHoc` - Initiate an ad-hoc PSM connection

### Bulk Account Actions
- `New-BulkAction` - Create a new bulk action job
- `Get-BulkAction` - Retrieve a bulk action job
- `Get-BulkActionDetails` - Retrieve bulk action job details
- `Invoke-AccountChangeBulk` - Bulk password change
- `Invoke-AccountVerifyBulk` - Bulk account verification
- `Invoke-AccountReconcileBulk` - Bulk account reconciliation
- `Set-AccountPasswordBulk` - Bulk set account passwords
- `Set-AccountNextPasswordBulk` - Bulk set next passwords
- `Sync-DependentAccountBulk` - Bulk sync dependent accounts
- `Unlock-AccountBulk` - Bulk unlock accounts

### Account Groups
- `Get-AccountGroup` - Retrieve an account group
- `Get-AccountGroups` - List all account groups
- `Get-AccountGroupMember` - Retrieve account group members
- `Add-AccountGroup` - Create an account group
- `Add-AccountGroupMember` - Add a member to an account group
- `Remove-AccountGroupMember` - Remove a member from an account group

### Linked Accounts
- `Set-AccountLink` - Link accounts together
- `Clear-AccountLink` - Remove an account link

### Dependent Accounts
- `Get-DependentAccount` - Retrieve a dependent account
- `Get-AllDependentAccounts` - List all dependent accounts
- `Get-DependentAccountDetails` - Retrieve dependent account details
- `Add-DependentAccount` - Add a dependent account
- `Add-DependentAccountLink` - Link a dependent account
- `Set-DependentAccount` - Update a dependent account
- `Remove-DependentAccount` - Remove a dependent account
- `Remove-DependentAccountLink` - Remove a dependent account link
- `Sync-DependentAccount` - Sync a dependent account
- `Sync-DependentAccountBulkSecret` - Bulk sync dependent account secrets
- `Resume-DependentAccount` - Resume a suspended dependent account
- `Resume-DependentAccountBulk` - Bulk resume dependent accounts

### PVWA Discovered Accounts
- `Get-PVWADiscoveredAccount` - Retrieve a PVWA discovered account
- `Get-PVWADiscoveredAccountDetails` - Retrieve discovered account details
- `Get-PVWADiscoveredAccountPlatform` - Retrieve discovered account platform
- `Add-PVWADiscoveredAccount` - Add a discovered account
- `Remove-PVWADiscoveredAccount` - Remove a discovered account
- `Remove-PVWADiscoveredAccountBulk` - Bulk remove discovered accounts
- `Remove-PVWADiscoveredAccounts` - Remove all discovered accounts
- `Start-PVWADiscoveredAccountOnboard` - Onboard a discovered account
- `Start-PVWADiscoveredAccountOnboardBulk` - Bulk onboard discovered accounts

### Safe Management
- `Get-Safe` - Retrieve safe information
- `Get-SafeDetails` - Retrieve full safe details
- `New-Safe` - Create a new safe
- `Set-Safe` - Update safe properties
- `Remove-Safe` - Delete a safe
- `Export-Safe` - Export safe data
- `Import-Safe` - Import safe data

### Safe Member Administration
- `Get-SafeMember` - Retrieve safe members
- `Get-SafeMemberDetails` - Retrieve detailed safe member information
- `Add-SafeMember` - Add a member to a safe
- `Set-SafeMember` - Update member permissions
- `Remove-SafeMember` - Remove a member from a safe
- `Export-SafeMember` - Export safe member data
- `Import-SafeMember` - Import safe member data

### Vault User Management
- `Get-VaultUser` - Retrieve a vault user
- `Get-VaultUserDetails` - Retrieve full vault user details
- `Get-VaultLoggedOnUser` - Get currently logged-on vault user
- `Get-VaultUserSafe` - Get safes accessible by a vault user
- `Get-VaultUserSSHKey` - Retrieve SSH keys for a vault user
- `Get-VaultUserType` - Retrieve vault user types
- `Add-VaultUser` - Create a vault user
- `Add-VaultUserGroup` - Add a vault user to a group
- `Add-VaultUserSSHKey` - Add an SSH key for a vault user
- `Add-VaultUserAllowedAuthMethod` - Allow an auth method for a vault user
- `Set-VaultUser` - Update vault user properties
- `Remove-VaultUser` - Delete a vault user
- `Remove-VaultUserGroup` - Remove a vault user from a group
- `Remove-VaultUserSSHKey` - Remove an SSH key from a vault user
- `Remove-VaultUserAllowedAuthMethod` - Remove an allowed auth method from a vault user
- `Disable-VaultUser` - Disable a vault user
- `Enable-VaultUser` - Enable a vault user
- `Invoke-VaultUserActivation` - Activate a vault user
- `Reset-VaultUserPassword` - Reset a vault user password
- `New-MFACachingSSHKey` - Create an MFA caching SSH key
- `New-MFACachingSSHKeyForUser` - Create an MFA caching SSH key for a specific user
- `Remove-MFACachingSSHKey` - Remove an MFA caching SSH key
- `Remove-MFACachingSSHKeyForUser` - Remove MFA caching SSH key for a specific user
- `Clear-MFACachingSSHKeys` - Clear all MFA caching SSH keys

### Vault User Groups
- `Get-UserGroup` - Retrieve a vault user group
- `Get-UserGroupDetails` - Retrieve full vault user group details
- `Get-PPAUserGroup` - Retrieve a PPA user group
- `New-UserGroup` - Create a vault user group
- `Set-UserGroup` - Update a vault user group
- `Remove-UserGroup` - Delete a vault user group
- `Add-UserGroupMember` - Add a member to a vault user group
- `Add-UserGroupUser` - Add a user to a vault user group
- `Remove-UserGroupMember` - Remove a member from a vault user group
- `Save-PPAUserGroupMember` - Save PPA user group membership

### Identity User Management
- `Get-IdentityUser` - Retrieve an identity user
- `Get-IdentityUserByName` - Retrieve an identity user by name
- `Get-IdentityUserInfo` - Retrieve identity user info
- `Get-IdentityUserAttributes` - Retrieve identity user attributes
- `Get-IdentityUserHierarchy` - Retrieve identity user hierarchy
- `Get-IdentityUserPicture` - Retrieve an identity user picture
- `Get-IdentityUserSecurityQuestions` - Retrieve security questions for a user
- `New-IdentityUser` - Create an identity user
- `New-IdentityUsers` - Bulk create identity users
- `Set-IdentityUser` - Update an identity user
- `Set-IdentityUserState` - Set the state of an identity user
- `Set-IdentityUserCloudLock` - Set cloud lock for an identity user
- `Set-IdentityUserPhonePin` - Set phone PIN for an identity user
- `Set-IdentityUserPicture` - Set picture for an identity user
- `Remove-IdentityUser` - Delete an identity user
- `Remove-IdentityUsers` - Bulk delete identity users
- `Reset-IdentityUserPassword` - Reset an identity user password
- `Invoke-RefreshIdentityUser` - Refresh an identity user
- `Disconnect-IdentityUserSession` - Disconnect an identity user session
- `Send-IdentityUserInvite` - Send invite to an identity user
- `Send-IdentityUserSmsInvite` - Send SMS invite to an identity user
- `Test-IdentityUserCloudLock` - Test cloud lock status for an identity user
- `Update-IdentityUserSecurityQuestions` - Update security questions for a user

### Identity Roles
- `Get-IdentityRole` - Retrieve an identity role
- `Get-IdentityRoleInDir` - Retrieve identity roles in a directory
- `Get-IdentityRoleMember` - Retrieve members of an identity role
- `Get-IdentityGroup` - Retrieve an identity group
- `New-IdentityRole` - Create an identity role
- `Add-IdentityRoleToUser` - Assign a role to an identity user
- `Add-IdentityRoleToGroup` - Assign a role to an identity group
- `Remove-IdentityRole` - Delete an identity role
- `Remove-IdentityRoleFromUser` - Remove a role from an identity user

### Directory Services
- `Get-DirectoryService` - Retrieve directory services

### LDAP Integration
- `Get-LDAPDirectory` - Retrieve an LDAP directory
- `Get-LDAPDirectoryDetails` - Retrieve LDAP directory details
- `New-LDAPDirectory` - Create an LDAP directory integration
- `Remove-LDAPDirectory` - Remove an LDAP directory integration
- `Get-LDAPDirectoryMapping` - Retrieve an LDAP directory mapping
- `Get-LDAPDirectoryMappingDetails` - Retrieve LDAP mapping details
- `New-LDAPDirectoryMapping` - Create an LDAP directory mapping
- `Edit-LDAPDirectoryMapping` - Edit an LDAP directory mapping
- `Set-LDAPDirectoryMapping` - Update an LDAP directory mapping
- `Set-LDAPDirectoryMappingOrder` - Set the order of LDAP mappings
- `Remove-LDAPDirectoryMapping` - Remove an LDAP directory mapping

### Authentication Methods
- `Get-AuthenticationMethod` - Retrieve an authentication method
- `Get-AuthenticationMethodDetails` - Retrieve authentication method details
- `New-AuthenticationMethod` - Create an authentication method
- `Set-AuthenticationMethod` - Update an authentication method
- `Remove-AuthenticationMethod` - Delete an authentication method
- `Get-OAuthProvider` - Retrieve an OAuth provider
- `New-OAuthProvider` - Create an OAuth provider
- `Set-OAuthProvider` - Update an OAuth provider
- `Remove-OAuthProvider` - Delete an OAuth provider
- `Get-OIDCProvider` - Retrieve an OIDC provider
- `Get-OIDCProviderDetails` - Retrieve OIDC provider details
- `New-OIDCProvider` - Create an OIDC provider
- `Set-OIDCProvider` - Update an OIDC provider
- `Remove-OIDCProvider` - Delete an OIDC provider
- `Get-FIDO2RegistrationOptions` - Retrieve FIDO2 registration options
- `Start-FIDO2Registration` - Start FIDO2 device registration
- `Register-FIDO2Device` - Register a FIDO2 device
- `Remove-FIDO2Device` - Remove a FIDO2 device
- `Start-OwnFIDO2Registration` - Start own FIDO2 registration
- `Register-OwnFIDO2Device` - Register own FIDO2 device
- `Remove-OwnFIDO2Device` - Remove own FIDO2 device

### Platforms
- `Get-Platform` - Retrieve a platform
- `Get-PlatformDetails` - Retrieve full platform details
- `Get-PlatformSafes` - Get safes associated with a platform
- `Get-PlatformStorage` - Retrieve platform storage
- `Get-PlatformSystemType` - Retrieve platform system types
- `Import-Platform` - Import a platform package
- `Export-Platform` - Export a platform package
- `Import-StoredPlatform` - Import a stored platform
- `Remove-PlatformStorage` - Remove platform storage
- `Get-TargetPlatform` - Retrieve a target platform
- `Get-TargetPlatformPSM` - Get PSM settings for a target platform
- `Copy-TargetPlatform` - Copy a target platform
- `Export-TargetPlatform` - Export a target platform
- `Enable-TargetPlatform` - Enable a target platform
- `Disable-TargetPlatform` - Disable a target platform
- `Set-TargetPlatformName` - Rename a target platform
- `Set-TargetPlatformPSM` - Set PSM settings for a target platform
- `Update-TargetPlatform` - Update a target platform
- `Remove-TargetPlatform` - Delete a target platform
- `Get-DependentPlatform` - Retrieve a dependent platform
- `Copy-DependentPlatform` - Copy a dependent platform
- `Copy-PlatformDependent` - Copy dependent platform settings
- `Export-DependentPlatform` - Export a dependent platform
- `Remove-DependentPlatform` - Delete a dependent platform
- `Get-GroupPlatform` - Retrieve a group platform
- `Copy-GroupPlatform` - Copy a group platform
- `Export-GroupPlatform` - Export a group platform
- `Enable-GroupPlatform` - Enable a group platform
- `Disable-GroupPlatform` - Disable a group platform
- `Remove-GroupPlatform` - Delete a group platform
- `Get-RotationalGroupPlatform` - Retrieve a rotational group platform
- `Copy-RotationalGroupPlatform` - Copy a rotational group platform
- `Export-RotationalGroupPlatform` - Export a rotational group platform
- `Enable-RotationalGroupPlatform` - Enable a rotational group platform
- `Disable-RotationalGroupPlatform` - Disable a rotational group platform
- `Remove-RotationalGroupPlatform` - Delete a rotational group platform

### Policies
- `Get-Policy` - Retrieve a policy
- `Set-Policy` - Update a policy

### Onboarding Rules
- `Get-OnboardingRule` - Retrieve onboarding rules
- `New-OnboardingRule` - Create an onboarding rule
- `Set-OnboardingRule` - Update an onboarding rule
- `Remove-OnboardingRule` - Delete an onboarding rule

### Discovery Services
- `Get-DiscoveredAccount` - Retrieve a discovered account (Discovery Management)
- `Add-DiscoveredAccount` - Add a discovered account
- `Remove-DiscoveredAccount` - Remove a discovered account
- `Clear-DiscoveredAccount` - Clear discovered account data
- `Get-DiscoveredAccountActivity` - Retrieve discovered account activity
- `Get-DiscoveredDependentAccount` - Retrieve discovered dependent accounts
- `Get-DiscoveryInsight` - Retrieve discovery insights
- `Set-DiscoveryInsight` - Update discovery insight settings
- `Get-DiscoveryRuleSet` - Retrieve discovery rule sets
- `New-DiscoveryRuleSet` - Create a discovery rule set
- `Set-DiscoveryRuleSet` - Update a discovery rule set
- `Remove-DiscoveryRuleSet` - Delete a discovery rule set
- `Deny-DiscoveryRuleSetRecommendation` - Deny a rule set recommendation
- `Get-DiscoveryRuleSetRecommendation` - Retrieve rule set recommendations

### Discovery Scans
- `Get-DiscoveryScan` - Retrieve a discovery scan
- `Get-DiscoveryScanDetails` - Retrieve discovery scan details
- `New-DiscoveryScan` - Create a discovery scan
- `Stop-DiscoveryScan` - Stop a running discovery scan
- `Remove-DiscoveryScan` - Delete a discovery scan

### Access Requests
- `New-AccessRequest` - Create an access request
- `New-MultipleAccessRequest` - Create multiple access requests
- `Get-AccessRequest` - Retrieve an access request
- `Get-AccessRequestDetails` - Retrieve access request details
- `Get-MultipleAccessRequestStatus` - Get status of multiple access requests
- `Remove-AccessRequest` - Delete an access request
- `Get-IncomingRequest` - Retrieve incoming access requests
- `Get-IncomingRequestDetails` - Retrieve incoming request details
- `Approve-IncomingRequest` - Approve an incoming request
- `Approve-IncomingRequestBulk` - Bulk approve incoming requests
- `Deny-IncomingRequest` - Deny an incoming request
- `Deny-IncomingRequestBulk` - Bulk deny incoming requests

### Live Sessions
- `Get-LiveSession` - Retrieve active live sessions
- `Get-LiveSessionDetails` - Retrieve live session details
- `Get-LiveSessionActivity` - Retrieve live session activity
- `Get-LiveSessionProperties` - Retrieve live session properties
- `Get-PSMSession` - Retrieve a PSM session
- `Invoke-LiveSessionAction` - Perform an action on a live session
- `Resume-LiveSession` - Resume a suspended live session
- `Suspend-LiveSession` - Suspend a live session
- `Stop-LiveSession` - Terminate a live session

### Recordings
- `Get-Recording` - Retrieve session recordings
- `Get-RecordingDetails` - Retrieve recording details
- `Get-RecordingActivity` - Retrieve recording activity
- `Get-RecordingProperties` - Retrieve recording properties
- `Get-RecordingPlayback` - Retrieve recording playback data
- `Test-RecordingValid` - Validate a session recording

### Reports and Tasks
- `Get-Report` - Retrieve reports
- `Get-ReportContent` - Retrieve report content
- `Get-ReportActivities` - Retrieve report activities
- `Get-ReportSettings` - Retrieve report settings
- `Get-ClassicReport` - Retrieve a classic report
- `Get-Task` - Retrieve tasks
- `New-Task` - Create a task

### OPM Commands
- `Get-OPMAccountRule` - Retrieve OPM account rules
- `Add-OPMAccountRule` - Add an OPM account rule
- `Remove-OPMAccountRule` - Remove an OPM account rule
- `Get-OPMPolicyRule` - Retrieve OPM policy rules
- `Add-OPMPolicyRule` - Add an OPM policy rule
- `Remove-OPMPolicyRule` - Remove an OPM policy rule

### Applications
- `Get-Application` - Retrieve an application
- `Get-ApplicationDetail` - Retrieve application details
- `New-Application` - Create an application
- `Remove-Application` - Delete an application
- `Get-ApplicationAuthenticationMethod` - Retrieve application auth methods
- `Add-ApplicationAuthenticationMethod` - Add an application auth method
- `Remove-ApplicationAuthenticationMethod` - Remove an application auth method

### PSM and Session Management
- `Get-PSMConnector` - Retrieve PSM connectors
- `Get-PSMServer` - Retrieve PSM servers
- `Import-ConnectionComponent` - Import a connection component

### System Health
- `Get-SystemHealth` - Retrieve CyberArk component health
- `Get-SystemHealthDetails` - Retrieve detailed component health

### PVWA Server
- `Get-PVWAServerInfo` - Retrieve PVWA server information
- `Get-PVWAServerLogo` - Retrieve the PVWA server logo
- `Get-PVWAServerVerify` - Verify PVWA server connectivity
- `Get-LicenseClient` - Retrieve license client information
- `Get-LoginsInfo` - Retrieve login information
- `Get-AllowedReferrer` - Retrieve allowed referrers
- `New-AllowedReferrer` - Add an allowed referrer
- `Get-PVWAImage` - Retrieve PVWA images
- `New-PVWAImage` - Upload a PVWA image
- `Get-Theme` - Retrieve PVWA themes
- `Get-ThemeDetails` - Retrieve PVWA theme details
- `New-Theme` - Create a PVWA theme
- `Set-Theme` - Update a PVWA theme
- `Set-ThemeDraft` - Save a theme as draft
- `Get-ActiveTheme` - Retrieve the active theme
- `Set-ActiveTheme` - Set the active theme
- `Remove-ActiveTheme` - Remove the active theme
- `Remove-Theme` - Delete a PVWA theme

### Vault Remote Manager
- `Get-VaultServiceStatus` - Retrieve vault service status
- `Get-VaultServiceConfig` - Retrieve vault service configuration
- `Get-VaultServiceConfigParam` - Retrieve a vault service config parameter
- `Set-VaultServiceConfig` - Update vault service configuration
- `Get-VaultDRSystemHealth` - Retrieve vault DR system health
- `Start-VaultService` - Start a vault service
- `Stop-VaultService` - Stop a vault service
- `Restart-VaultService` - Restart a vault service
- `Start-VaultDRFailover` - Initiate vault DR failover

### SIA (Secrets Infrastructure Automation)
- `New-Connector` - Create a new SIA connector

### Utility Functions
- `Write-LogMessage` - Comprehensive logging
- `Remove-SensitiveData` - Data sanitization
- `Get-UPN` - Active Directory UPN lookup
- `Get-SamAccountName` - Active Directory SAM lookup
- `Set-EPVTimeDisplay` - Control timestamp display (local time, UTC, or any UTC offset)
- `Add-BaseQueryParameter` - Add base query parameters to a request
- `Get-OAuthInfo` - Retrieve OAuth token information
- `Get-CPMUser` - Retrieve CPM user information

## Configuration

### Environment Variables

```powershell
# Enable sensitive data logging (debugging only)
$global:LogSensitiveData = $true

# Set default log file location
$global:LogFile = "C:\Logs\EPV-API-Common.log"
```

### Timestamp Display

All format views (Account, Safe, SafeMember, Comp, User) respect a session-level time zone setting:

```powershell
Set-EPVTimeDisplay              # Local time (default)
Set-EPVTimeDisplay -UTC         # UTC
Set-EPVTimeDisplay -UTCOffset -5   # UTC-5
Set-EPVTimeDisplay -UTCOffset 5.5  # UTC+5:30
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

## License

This module is provided by CyberArk. Please refer to your CyberArk license agreement for usage terms and conditions.

---


**Note**: This module requires PowerShell 7.4+ and is designed for CyberArk administrators and developers working with CyberArk APIs. Always follow your organization's security policies when using privileged access management tools.
