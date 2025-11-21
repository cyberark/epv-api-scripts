# CyberArk Privilege Cloud ISPSS REST API Basic Guide

This document provides a practical introduction to using the CyberArk Privilege Cloud REST API for common account management tasks. It is designed for new users and developers who want to automate Privilege Cloud operations.

For more information use the following link:

 `https://docs.cyberark.com/privilege-cloud-shared-services/latest/en/content/webservices/implementing%20privileged%20account%20security%20web%20services%20.htm`

---

## Table of Contents
- [CyberArk Privilege Cloud ISPSS REST API Basic Guide](#cyberark-privilege-cloud-ispss-rest-api-basic-guide)
  - [Table of Contents](#table-of-contents)
  - [API Overview](#api-overview)
  - [Best Practices](#best-practices)
  - [Authentication \& Authorization](#authentication--authorization)
  - [API URL Structure](#api-url-structure)
  - [Return Codes](#return-codes)
  - [Getting the $header Value (Authentication Example)](#getting-the-header-value-authentication-example)
    - [Import the CyberArk Identity Authentication module](#import-the-cyberark-identity-authentication-module)
    - [Option 1: OAuth authentication with client credentials](#option-1-oauth-authentication-with-client-credentials)
    - [Option 2: Interactive authentication with username prompt](#option-2-interactive-authentication-with-username-prompt)
    - [Option 3: Username and password credentials](#option-3-username-and-password-credentials)
  - [Account Management](#account-management)
    - [Get Accounts](#get-accounts)
      - [Get all accounts (default limit is 50)](#get-all-accounts-default-limit-is-50)
      - [Get a specific account by ID](#get-a-specific-account-by-id)
      - [Get accounts with pagination (limit and offset)](#get-accounts-with-pagination-limit-and-offset)
      - [Get accounts with sorting (by userName ascending)](#get-accounts-with-sorting-by-username-ascending)
    - [Search and Filter Accounts](#search-and-filter-accounts)
      - [Search for accounts by keyword (default searchType is "contains")](#search-for-accounts-by-keyword-default-searchtype-is-contains)
      - [Search with multiple keywords (space-separated)](#search-with-multiple-keywords-space-separated)
      - [Search with searchType "startswith"](#search-with-searchtype-startswith)
      - [Get accounts from a specific Safe using filter](#get-accounts-from-a-specific-safe-using-filter)
      - [Get accounts modified after a specific time (Unix timestamp in milliseconds)](#get-accounts-modified-after-a-specific-time-unix-timestamp-in-milliseconds)
      - [Get accounts using saved filters](#get-accounts-using-saved-filters)
      - [Combine multiple filters (Safe name AND modification time)](#combine-multiple-filters-safe-name-and-modification-time)
      - [Combine search with filter and pagination](#combine-search-with-filter-and-pagination)
    - [Account Actions](#account-actions)
      - [Add Account](#add-account)
      - [Update Account Details](#update-account-details)
      - [Delete Account](#delete-account)
      - [Linked Accounts](#linked-accounts)
        - [Link an Account](#link-an-account)
        - [Unlink an Account](#unlink-an-account)
      - [Password Management](#password-management)
        - [Change Credentials Immediately](#change-credentials-immediately)
        - [Set Next Password](#set-next-password)
        - [Change Credentials in Vault](#change-credentials-in-vault)
  - [Safe Management](#safe-management)
    - [Add Safe](#add-safe)
    - [Update Safe](#update-safe)
    - [Remove Safe](#remove-safe)
  - [Safe Member Management](#safe-member-management)
    - [Add Safe Member](#add-safe-member)
    - [Change Safe Member Permissions](#change-safe-member-permissions)
    - [Remove Safe Member](#remove-safe-member)
  - [System Health and Monitoring](#system-health-and-monitoring)
    - [Get System Health Summary](#get-system-health-summary)
    - [Get System Health](#get-system-health)
    - [Get User Licenses Report](#get-user-licenses-report)
  - [Access Request Management](#access-request-management)
    - [Get Incoming Requests](#get-incoming-requests)
    - [Confirm Request](#confirm-request)
    - [Reject Request](#reject-request)
  - [SSH Key Management](#ssh-key-management)
    - [Generate MFA Caching SSH Key](#generate-mfa-caching-ssh-key)
    - [Delete MFA Caching SSH Key](#delete-mfa-caching-ssh-key)
    - [Delete All MFA Caching SSH Keys](#delete-all-mfa-caching-ssh-keys)

---

## API Overview
- CyberArk Privilege Cloud provides a RESTful API for automating and integrating privileged account management tasks.
- Each object (such as accounts) has its own URL path.
- The API can be accessed from any tool or language that supports HTTPS requests.

## Best Practices
- Always check the response code and handle errors (e.g., 401, 403, 429).
- If a error is received be sure to check for PCloud specific error embedded in the response
- Use HTTPS and keep your session token secure.
- Implement retry logic for 429 (Too Many Requests) errors.
- Refer to the [official CyberArk documentation](https://docs.cyberark.com/privilege-cloud-shared-services/latest/en/content/webservices/implementing%20privileged%20account%20security%20web%20services%20.htm) for full API details and updates.

---

## Authentication & Authorization
- All API calls (except Logon) require an `Authorization` header with a session token.
- Obtain a session token by authenticating with the Logon API.
- Include the token in the `Authorization` header for all subsequent requests.

## API URL Structure
- **Portal URL:** `https://<subdomain>.cyberark.cloud/privilegecloud/`
- **API URL (Gen 1):** `https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/WebServices/`
- **API URL (Gen 2):** `https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/`
- **API URL (Gen 3):** `https://<subdomain>.privilegecloud.cyberark.cloud/api/`

## Return Codes
| Code | Meaning |
|------|---------|
| 200  | Success |
| 201  | Created |
| 204  | No Content (e.g., after DELETE) |
| 400  | Bad Request |
| 401  | Unauthorized |
| 403  | Forbidden |
| 404  | Not Found |
| 409  | Conflict |
| 429  | Too Many Requests (rate limiting) |
| 500  | Internal Server Error |

---

## Getting the $header Value (Authentication Example)

Before making any API calls, you must obtain a session token.

One option is to use IdentityAuth.psm1. It is located at `https://github.com/cyberark/epv-api-scripts/tree/main/Identity%20Authentication`

### Import the CyberArk Identity Authentication module
```powershell
Import-Module .\IdentityAuth.psm1
```

### Option 1: OAuth authentication with client credentials
```powershell
# Create credential object with OAuth client ID and secret
$OAuthCreds = Get-Credential
# When prompted, enter:
# Username: Your OAuth Client ID
# Password: Your OAuth Client Secret

$header = Get-IdentityHeader -PCloudURL "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault" -OAuthCreds $OAuthCreds

# $header is a hashtable with the required Authorization and X-IDAP-NATIVE-CLIENT headers
```

### Option 2: Interactive authentication with username prompt
Accounts that are using a external identity provider are currently not supported by the module

```powershell
$header = Get-IdentityHeader -PCloudURL "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault" -IdentityUserName "user@company.com"

# You will be prompted to complete MFA challenges (Push, SMS, etc.)
```

### Option 3: Username and password credentials
MFA responses are still require if configured
```powershell
$UPCreds = Get-Credential
# When prompted, enter your username and password

$header = Get-IdentityHeader -PCloudURL "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault" -UPCreds $UPCreds

# You will be prompted to complete MFA challenges (Push, SMS, etc.)
```

## Account Management

### Get Accounts

#### Get all accounts (default limit is 50)
```powershell
$getAccountsParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts"
    Headers = $header
    Method  = 'Get'
}
$response = Invoke-RestMethod @getAccountsParams
$response.value # List of accounts
$response.count # Total number of accounts returned
```

#### Get a specific account by ID
```powershell
$getAccountParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts/{accountId}/"
    Headers = $header
    Method  = 'Get'
}
$account = Invoke-RestMethod @getAccountParams
$account
```

#### Get accounts with pagination (limit and offset)
```powershell
$limit = 100
$offset = 0
$getAccountsParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts?limit=$limit&offset=$offset"
    Headers = $header
    Method  = 'Get'
}
$response = Invoke-RestMethod @getAccountsParams
$response.value
```

#### Get accounts with sorting (by userName ascending)
```powershell
$getAccountsParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts?sort=userName asc"
    Headers = $header
    Method  = 'Get'
}
$response = Invoke-RestMethod @getAccountsParams
$response.value
```

### Search and Filter Accounts

#### Search for accounts by keyword (default searchType is "contains")
```powershell
$search = 'administrator'
$getAccountsSearchParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts?search=$search"
    Headers = $header
    Method  = 'Get'
}
$searchResponse = Invoke-RestMethod @getAccountsSearchParams
$searchResponse.value # Filtered list of accounts
```

#### Search with multiple keywords (space-separated)
```powershell
$search = 'Windows admin'
$getAccountsSearchParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts?search=$search"
    Headers = $header
    Method  = 'Get'
}
$searchResponse = Invoke-RestMethod @getAccountsSearchParams
$searchResponse.value
```

#### Search with searchType "startswith"
```powershell
$search = 'prod'
$searchType = 'startswith'
$getAccountsSearchParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts?search=$search&searchType=$searchType"
    Headers = $header
    Method  = 'Get'
}
$searchResponse = Invoke-RestMethod @getAccountsSearchParams
$searchResponse.value
```

#### Get accounts from a specific Safe using filter
```powershell
$safeName = 'WindowsServers'
$getAccountsParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts?filter=safeName eq $safeName"
    Headers = $header
    Method  = 'Get'
}
$response = Invoke-RestMethod @getAccountsParams
$response.value
```

#### Get accounts modified after a specific time (Unix timestamp in milliseconds)
```powershell
$timestamp = 1640995200000 # Example: Jan 1, 2022
$getAccountsParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts?filter=modificationTime gte $timestamp"
    Headers = $header
    Method  = 'Get'
}
$response = Invoke-RestMethod @getAccountsParams
$response.value
```

#### Get accounts using saved filters
```powershell
$getAccountsParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts?savedFilter=PolicyFailures"
    Headers = $header
    Method  = 'Get'
}
$response = Invoke-RestMethod @getAccountsParams
$response.value
```

#### Combine multiple filters (Safe name AND modification time)
```powershell
$safeName = 'WindowsServers'
$timestamp = 1640995200000
$getAccountsParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts?filter=safeName eq $safeName AND modificationTime gte $timestamp"
    Headers = $header
    Method  = 'Get'
}
$response = Invoke-RestMethod @getAccountsParams
$response.value
```

#### Combine search with filter and pagination
```powershell
$search = 'admin'
$safeName = 'WindowsServers'
$limit = 50
$getAccountsSearchParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts?search=$search&filter=safeName eq $safeName&limit=$limit"
    Headers = $header
    Method  = 'Get'
}
$searchResponse = Invoke-RestMethod @getAccountsSearchParams
$searchResponse.value
```

### Account Actions

#### Add Account
```powershell
$addAccountParams = @{
    Uri         = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts"
    Headers     = $header
    Method      = 'Post'
    Body        = (@{
        name                     = 'MyAccount'
        address                  = 'server01.example.com'
        userName                 = 'administrator'
        platformId               = 'WinDomain'
        safeName                 = 'WindowsServers'
        secretType               = 'password'
        secret                   = 'MySecretPassword123!'
        platformAccountProperties = @{
            LogonDomain = 'example.com'
            Port        = '22'
        }
        secretManagement = @{
            automaticManagementEnabled = $true
        }
        remoteMachinesAccess = @{
            remoteMachines                    = 'server1.example.com;server2.example.com'
            accessRestrictedToRemoteMachines = $true
        }
    } | ConvertTo-Json)
    ContentType = 'application/json'
}
$response = Invoke-RestMethod @addAccountParams
$response
```

#### Update Account Details
```powershell
$updateAccountParams = @{
    Uri         = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts/{accountId}/"
    Headers     = $header
    Method      = 'Patch'
    Body        = @(
        @{ op = 'replace'; path = '/address'; value = '10.10.27.254' },
        @{ op = 'replace'; path = '/userName'; value = 'newuser' },
        @{ op = 'add'; path = '/platformAccountProperties'; value = @{ port = '456'; logonTo = '1.2.3.4' } }
    ) | ConvertTo-Json
    ContentType = 'application/json'
}
$response = Invoke-RestMethod @updateAccountParams
$response
```

#### Delete Account
```powershell
$deleteAccountParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts/{accountId}/"
    Headers = $header
    Method  = 'Delete'
    SkipHttpErrorCheck = $true
}
$response = Invoke-RestMethod @deleteAccountParams
if ($response.StatusCode -eq 204) {
    Write-Host "Account deleted successfully."
} else {
    Write-Host "Unexpected response: $($response.StatusCode)"
}
```

#### Linked Accounts

##### Link an Account
```powershell
$linkAccountParams = @{
    Uri         = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts/{accountId}/LinkAccount/"
    Headers     = $header
    Method      = 'Post'
    Body        = (@{
        safe               = 'WindowsServers'
        extraPasswordIndex = 3  # 1 = Logon, 2 = Enable, 3 = Reconcile
        name               = 'ReconcileAccount-server01'
        folder             = 'Root'
    } | ConvertTo-Json)
    ContentType = 'application/json'
}
$response = Invoke-RestMethod @linkAccountParams
Write-Host "Logon account linked successfully."
```

##### Unlink an Account
```powershell
$unlinkAccountParams = @{
    Uri         = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts/{accountId}/LinkAccount/{extraPasswordIndex}"
    Headers     = $header
    Method      = 'Delete'
    SkipHttpErrorCheck = $true
}
$response = Invoke-RestMethod @unlinkAccountParams
if ($response.StatusCode -eq 204) {
    Write-Host "Account unlinked successfully."
} else {
    Write-Host "Unexpected response: $($response.StatusCode)"
}
```

#### Password Management

##### Change Credentials Immediately
```powershell
$changeNowParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts/{accountId}/Change/"
    Headers = $header
    Method  = 'Post'
    ContentType = 'application/json'
}
$response = Invoke-RestMethod @changeNowParams
$response
```

##### Set Next Password
```powershell
$setNextPasswordParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts/{accountId}/SetNextPassword/"
    Headers = $header
    Method  = 'Post'
    Body    = (@{
        ChangeImmediately = $true # or $false
        NewCredentials    = 'MyNextPassword123!'
    } | ConvertTo-Json)
    ContentType = 'application/json'
}
$response = Invoke-RestMethod @setNextPasswordParams
$response
```

##### Change Credentials in Vault
```powershell
$changeInVaultParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts/{accountId}/Password/Update/"
    Headers = $header
    Method  = 'Post'
    Body    = (@{
        NewCredentials = 'MyNewVaultPassword456!'
    } | ConvertTo-Json)
    ContentType = 'application/json'
}
$response = Invoke-RestMethod @changeInVaultParams
$response
```

---

## Safe Management

### Add Safe
```powershell
$addSafeParams = @{
    Uri         = "https://<subdomain>.privilegecloud.cyberark.cloud/api/Safes"
    Headers     = $header
    Method      = 'Post'
    Body        = (@{
        safeName        = 'MyNewSafe'
        description     = 'Safe for application secrets'
        managingCPM     = 'PasswordManager'
        # Only include one of the following retention settings:
        # numberOfVersionsRetention = 5
        numberOfDaysRetention    = 30
    } | ConvertTo-Json)
    ContentType = 'application/json'
}
$response = Invoke-RestMethod @addSafeParams
$response
```

### Update Safe
```powershell
$changeSafeParams = @{
    Uri         = "https://<subdomain>.privilegecloud.cyberark.cloud/api/Safes/{SafeUrlId}/"
    Headers     = $header
    Method      = 'Put'
    Body        = (@{
        description = 'Updated description for the safe'
        # Only include one of the following retention settings:
        # numberOfVersionsRetention = 5
        numberOfDaysRetention = 60
    } | ConvertTo-Json)
    ContentType = 'application/json'
}
$response = Invoke-RestMethod @changeSafeParams
$response
```

### Remove Safe
```powershell
$removeSafeParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/api/Safes/{SafeUrlId}/"
    Headers = $header
    Method  = 'Delete'
    SkipHttpErrorCheck = $true
}
$response = Invoke-RestMethod @removeSafeParams
if ($response.StatusCode -eq 204) {
    Write-Host "Safe deleted successfully."
} else {
    Write-Host "Unexpected response: $($response.StatusCode)"
}
```

---

## Safe Member Management

### Add Safe Member
```powershell
$addSafeMemberParams = @{
    Uri         = "https://<subdomain>.privilegecloud.cyberark.cloud/api/Safes/{safeId}/Members"
    Headers     = $header
    Method      = 'Post'
    Body        = (@{
        memberName  = 'user@company.com'
        permissions = @{
            useAccounts      = $true
            retrieveAccounts = $true
            listAccounts     = $true
        }
    } | ConvertTo-Json)
    ContentType = 'application/json'
}
$response = Invoke-RestMethod @addSafeMemberParams
$response
```

### Change Safe Member Permissions
```powershell
$changeSafeMemberParams = @{
    Uri         = "https://<subdomain>.privilegecloud.cyberark.cloud/api/Safes/{safeId}/Members/{memberName}/"
    Headers     = $header
    Method      = 'Put'
    Body        = (@{
        permissions = @{
            useAccounts                            = $true
            retrieveAccounts                       = $true
            listAccounts                           = $true
            addAccounts                            = $true
            updateAccountContent                   = $false
            updateAccountProperties                = $false
            initiateCPMAccountManagementOperations = $false
            specifyNextAccountContent              = $false
            renameAccounts                         = $false
            deleteAccounts                         = $false
            unlockAccounts                         = $false
            manageSafe                             = $false
            manageSafeMembers                      = $false
            backupSafe                             = $false
            viewAuditLog                           = $true
            viewSafeMembers                        = $true
            accessWithoutConfirmation              = $false
            createFolders                          = $false
            deleteFolders                          = $false
            moveAccountsAndFolders                 = $false
            requestsAuthorizationLevel1            = $false
            requestsAuthorizationLevel2            = $false
        }
    } | ConvertTo-Json)
    ContentType = 'application/json'
}
$response = Invoke-RestMethod @changeSafeMemberParams
$response
```

### Remove Safe Member
```powershell
$removeSafeMemberParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/api/Safes/{safeId}/Members/{memberName}/"
    Headers = $header
    Method  = 'Delete'
    SkipHttpErrorCheck = $true
}
$response = Invoke-RestMethod @removeSafeMemberParams
if ($response.StatusCode -eq 204) {
    Write-Host "Safe member removed successfully."
} else {
    Write-Host "Unexpected response: $($response.StatusCode)"
}
```

---

## System Health and Monitoring

### Get System Health Summary
```powershell
$systemHealthSummaryParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/ComponentsMonitoringSummary"
    Headers = $header
    Method  = 'Get'
}
$response = Invoke-RestMethod @systemHealthSummaryParams
$response
```

### Get System Health
```powershell
$ComponentId = 'SessionManagement' # PVWA, SessionManagement, CPM, AIM
$systemHealthParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/ComponentsMonitoringDetails/{$ComponentID}"
    Headers = $header
    Method  = 'Get'
}
$response = Invoke-RestMethod @systemHealthParams
$response
```

### Get User Licenses Report
```powershell
# Get Privilege Cloud user license usage information
$licensesParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/licenses/pcloud/"
    Headers = $header
    Method  = 'Get'
}
$response = Invoke-RestMethod @licensesParams
$response.componentName # "Privilege Cloud"
$response.optionalSummary # License consumption summary
$response.licensesData # Detailed breakdown by license type

# Access specific license information
$response.licensesData.licencesElements | ForEach-Object {
    Write-Host "$($_.name): $($_.used) of $($_.total) used"
}
```

---

## Access Request Management

### Get Incoming Requests
```powershell
# Get requests waiting for approval
$incomingRequestsParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/IncomingRequests"
    Headers = $header
    Method  = 'Get'
}
$response = Invoke-RestMethod @incomingRequestsParams
$response # Returns list of requests awaiting your approval
```

### Confirm Request
```powershell
# Approve an access request
$confirmRequestParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/IncomingRequests/{requestId}/Confirm"
    Headers = $header
    Method  = 'Post'
    Body    = (@{
        Reason = 'Approved for maintenance window'
    } | ConvertTo-Json)
    ContentType = 'application/json'
}
$response = Invoke-RestMethod @confirmRequestParams
Write-Host "Request confirmed successfully."
```

### Reject Request
```powershell
# Reject an access request
$rejectRequestParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/IncomingRequests/{requestId}/Reject"
    Headers = $header
    Method  = 'Post'
    Body    = (@{
        Reason = 'Request does not meet approval criteria'
    } | ConvertTo-Json)
    ContentType = 'application/json'
}
$response = Invoke-RestMethod @rejectRequestParams
Write-Host "Request rejected."
```

---

## SSH Key Management

### Generate MFA Caching SSH Key
```powershell
# Generate an MFA caching SSH key for PSM for SSH connections
$generateSSHKeyParams = @{
    Uri         = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Users/Secret/SSHKeys/Cache/"
    Headers     = $header
    Method      = 'Post'
    Body        = (@{
        formats     = @('PEM', 'PPK', 'OpenSSH')  # Optional: Specify key formats
        keyPassword = 'MyKeyPassphrase123!'       # Optional: Passphrase to protect private key
    } | ConvertTo-Json)
    ContentType = 'application/json'
}
$response = Invoke-RestMethod @generateSSHKeyParams
$response.count           # Number of private key types
$response.creationTime    # Key creation time
$response.expirationTime  # Key expiration time
$response.publicKey       # Public key
$response.value           # Array of private keys in different formats

# Access individual key formats
$response.value | ForEach-Object {
    Write-Host "Format: $($_.format), Algorithm: $($_.keyAlg)"
    # Save private key: $_.privateKey
}
```

### Delete MFA Caching SSH Key
```powershell
# Delete your MFA caching SSH key
$deleteSSHKeyParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Users/Secret/SSHKeys/Cache/"
    Headers = $header
    Method  = 'Delete'
    SkipHttpErrorCheck = $true
}
$response = Invoke-RestMethod @deleteSSHKeyParams
if ($response.StatusCode -eq 204) {
    Write-Host "MFA caching SSH key deleted successfully."
} else {
    Write-Host "Unexpected response: $($response.StatusCode)"
}
```

### Delete All MFA Caching SSH Keys
```powershell
# Delete all MFA caching SSH keys for all users (requires Reset Users' Passwords permission)
$clearCacheParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Users/Secret/SSHKeys/ClearCache/"
    Headers = $header
    Method  = 'Delete'
    SkipHttpErrorCheck = $true
}
$response = Invoke-RestMethod @clearCacheParams
if ($response.StatusCode -eq 204) {
    Write-Host "All MFA caching SSH keys cleared successfully."
} else {
    Write-Host "Unexpected response: $($response.StatusCode)"
}
```

---

This guide covers the basics for managing accounts via the CyberArk Privilege Cloud REST API and is AI generated.

Please report any issues.
