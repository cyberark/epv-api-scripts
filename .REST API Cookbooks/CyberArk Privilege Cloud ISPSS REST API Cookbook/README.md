# CyberArk Privilege Cloud ISPSS REST API Cookbook

This document provides a practical introduction to using the CyberArk Privilege Cloud REST API with PowerShell for common account management tasks.

It is designed for new users and developers who are familiar with PowerShell and want to automate Privilege Cloud operations.

For more information use the following links:

 [Documentation about using the CyberArk Rest API](https://docs.cyberark.com/privilege-cloud-shared-services/latest/en/content/webservices/implementing%20privileged%20account%20security%20web%20services%20.htm)

 [Documentation about using PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/overview)

---

## API Overview

- CyberArk Privilege Cloud provides a RESTful API for automating and integrating privileged account management tasks.
- Each object (such as accounts) has its own URL path.
- The API can be accessed from any tool or language that supports HTTPS requests.

## Best Practices

- Always check the response code and handle errors (e.g., 401, 403, 429).
- If a error is received be sure to check for a PCloud specific error in the response
- Use HTTPS and keep your session token secure.
- Refer to the official [CyberArk Documentation](https://docs.cyberark.com/privilege-cloud-shared-services/latest/en/content/webservices/implementing%20privileged%20account%20security%20web%20services%20.htm) for full API details and updates.

---

## Authentication & Authorization

- All API calls require an `Authorization` header with a session token.
- For guidance on retrieving a session token, refer to: [Authenticate to CyberArk Identity Security Platform Shared Services](https://docs.cyberark.com/privilege-cloud-shared-services/latest/en/content/developer/developer-home.htm#AuthenticatetoCyberArkIdentitySecurityPlatformSharedServices)

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


# List of Examples


  - [Authentication](#authentication)
    - [Importing the CyberArk Identity Authentication module](#importing-the-cyberark-identity-authentication-module)
    - [OAuth authentication with client credentials](#oauth-authentication-with-client-credentials)
    - [Interactive authentication with username prompt](#interactive-authentication-with-username-prompt)
    - [Semi-interactive authentication using username and password passed using PSCredentials](#semi-interactive-authentication-using-username-and-password-passed-using-pscredentials)
  - [Get Accounts](#get-accounts)
    - [Get all accounts](#get-all-accounts)
    - [Get a specific account by ID](#get-a-specific-account-by-id)
    - [Get accounts with pagination](#get-accounts-with-pagination)
    - [Get accounts with sorting](#get-accounts-with-sorting)
    - [How to get accounts using filter and search](#how-to-get-accounts-using-filter-and-search)
      - [Search for accounts by keyword](#search-for-accounts-by-keyword)
      - [Search with multiple keywords](#search-with-multiple-keywords)
      - [Search with searchType "startswith"](#search-with-searchtype-startswith)
      - [Get accounts from a specific Safe using filter](#get-accounts-from-a-specific-safe-using-filter)
      - [Get accounts modified after a specific time](#get-accounts-modified-after-a-specific-time)
      - [Get accounts using saved filters](#get-accounts-using-saved-filters)
      - [Combine multiple filters](#combine-multiple-filters)
      - [Combine search with filter and pagination](#combine-search-with-filter-and-pagination)
  - [Account Actions](#account-actions)
    - [Add Account](#add-account)
    - [Update Account Details](#update-account-details)
    - [Delete Account](#delete-account)
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
    - [Delete All MFA Caching SSH Keys For All Users](#delete-all-mfa-caching-ssh-keys-for-all-users)
  - [Additional Examples in Other Languages](#additional-examples-in-other-languages)
    - [Python Examples](#python-examples)
      - [Authentication (Python)](#authentication-python)
      - [Add Account (Python)](#add-account-python)
      - [Get All Accounts (Python)](#get-all-accounts-python)
      - [Get a specific account by ID (Python)](#get-a-specific-account-by-id-python)
      - [Delete Account (Python)](#delete-account-python)
    - [Shell Script Examples (Bash/cURL)](#shell-script-examples-bashcurl)
      - [Authentication (Shell)](#authentication-shell)
      - [Add Account (Shell)](#add-account-shell)
      - [Get All Accounts (Shell)](#get-all-accounts-shell)
      - [Get a specific account by ID (Shell)](#get-a-specific-account-by-id-shell)
      - [Delete Account (Shell)](#delete-account-shell)

---

## Authentication

Before making any API calls, you must obtain a session token.

One option is to use IdentityAuth.psm1. It is located at `https://github.com/cyberark/epv-api-scripts/tree/main/Identity%20Authentication`

### Importing the CyberArk Identity Authentication module
```powershell
Import-Module .\IdentityAuth.psm1
```

### OAuth authentication with client credentials

```powershell
# Create credential object with OAuth client ID and secret
$OAuthCreds = Get-Credential
# When prompted, enter:
# Username: Your OAuth Client ID
# Password: Your OAuth Client Secret

$header = Get-IdentityHeader -PCloudURL "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault" -OAuthCreds $OAuthCreds

# $header is a hashtable with the required Authorization and X-IDAP-NATIVE-CLIENT headers
```

### Interactive authentication with username prompt

Accounts that are using a external identity provider are currently not supported by the module

```powershell
$header = Get-IdentityHeader -PCloudURL "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault" -IdentityUserName "user@company.com"

# You will be prompted to complete MFA challenges (Push, SMS, etc.)
```

### Semi-interactive authentication using username and password passed using PSCredentials

MFA responses are still require if configured

```powershell
$UPCreds = Get-Credential
# When prompted, enter your username and password

$header = Get-IdentityHeader -PCloudURL "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault" -UPCreds $UPCreds

# You will be prompted to complete MFA challenges (Push, SMS, etc.)
```

## Get Accounts

### Get all accounts

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

### Get a specific account by ID

```powershell
$getAccountParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts/{accountId}/"
    Headers = $header
    Method  = 'Get'
}
$account = Invoke-RestMethod @getAccountParams
$account
```

### Get accounts with pagination

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

### Get accounts with sorting

```powershell
$getAccountsParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts?sort=userName asc"
    Headers = $header
    Method  = 'Get'
}
$response = Invoke-RestMethod @getAccountsParams
$response.value
```

### How to get accounts using filter and search

#### Search for accounts by keyword

```powershell
$search = 'administrator'
$getAccountsSearchParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts?search=$search"
    Headers = $header
    Method  = 'Get'
}
$searchResponse = Invoke-RestMethod @getAccountsSearchParams
$searchResponse.value
```

#### Search with multiple keywords

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

#### Get accounts modified after a specific time

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

#### Combine multiple filters

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

## Account Actions

### Add Account

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

### Update Account Details

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

### Delete Account

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

### Link an Account

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

### Unlink an Account

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

## Password Management

### Change Credentials Immediately

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

### Set Next Password

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

### Change Credentials in Vault

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

### Delete All MFA Caching SSH Keys For All Users

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

## Additional Examples in Other Languages

### Python Examples

#### Authentication (Python)

**Important: Privilege Cloud Authentication Requirements**

Privilege Cloud authentication requires Identity authentication (MFA, OAuth, etc.). There is no simple username/password endpoint for Privilege Cloud.

In production, you must create a Python function to handle token generation through CyberArk Identity, which supports:
- Multi-factor authentication (MFA)
- OAuth client credentials
- External Identity Provider authentication
- Other Identity authentication mechanisms

For actual implementation guidance, refer to: [Authenticate to CyberArk Identity Security Platform Shared Services](https://docs.cyberark.com/privilege-cloud-shared-services/latest/en/content/developer/developer-home.htm#AuthenticatetoCyberArkIdentitySecurityPlatformSharedServices)

**Conceptual Production Pattern:**

Using a mock module name (does not exist):
```python
from cyberark_identity_auth import get_identity_token

headers = get_identity_token(
    pcloud_url="https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault",
    username="user@company.com"
)
# This would handle Identity authentication, MFA challenges, OAuth, etc.
```

The mock module would return headers in this format (like `$header` in PowerShell):
```python
headers = {
    "Authorization": "<token_from_identity_authentication>",
    "X-IDAP-NATIVE-CLIENT": "true",
    "Content-Type": "application/json"
}
```


#### Add Account (Python)
```python
import requests

# Assumes 'headers' is already set from authentication

add_account_url = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts"
account_data = {
    "name": "MyAccount",
    "address": "server01.example.com",
    "userName": "administrator",
    "platformId": "WinDomain",
    "safeName": "WindowsServers",
    "secretType": "password",
    "secret": "MySecretPassword123!",
    "platformAccountProperties": {
        "LogonDomain": "example.com"
    }
}

response = requests.post(add_account_url, headers=headers, json=account_data)
if response.status_code == 201:
    print("Account created successfully")
    account = response.json()
    print(f"Account ID: {account['id']}")
else:
    print(f"Error: {response.status_code} - {response.text}")
```
#### Get All Accounts (Python)
```python
import requests

# Assumes 'headers' is already set from authentication

# Get all accounts (default limit is 50)
get_accounts_url = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts"

response = requests.get(get_accounts_url, headers=headers)
if response.status_code == 200:
    accounts = response.json()
    print(f"Total accounts returned: {accounts['count']}")
    print("\nAccounts:")
    for account in accounts['value']:
        print(f"- {account['name']} ({account['address']}) - {account['userName']}")
else:
    print(f"Error: {response.status_code} - {response.text}")
```

#### Get a specific account by ID (Python)
```python
import requests

# Assumes 'headers' is already set from authentication

# Get specific account by ID
account_id = "your_account_id"
get_account_url = f"https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts/{account_id}"

headers = {
    "Authorization": token
}

response = requests.get(get_account_url, headers=headers)
if response.status_code == 200:
    account = response.json()
    print(f"Account Name: {account['name']}")
    print(f"Address: {account['address']}")
    print(f"Username: {account['userName']}")
else:
    print(f"Error: {response.status_code} - {response.text}")

# Get all accounts with search
search_url = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts?search=administrator&limit=50"
response = requests.get(search_url, headers=headers)
if response.status_code == 200:
    accounts = response.json()
    print(f"Found {accounts['count']} accounts")
    for account in accounts['value']:
        print(f"- {account['name']} ({account['address']})")
```

#### Delete Account (Python)
```python
import requests

# Assumes 'headers' is already set from authentication

# Delete account by ID
account_id = "your_account_id"
delete_url = f"https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts/{account_id}"

response = requests.delete(delete_url, headers=headers)
if response.status_code == 204:
    print("Account deleted successfully")
elif response.status_code == 404:
    print("Account not found")
else:
    print(f"Error: {response.status_code} - {response.text}")
```

---

### Shell Script Examples (Bash/cURL)

#### Authentication (Shell)

**Important: Privilege Cloud Authentication Requirements**

Privilege Cloud authentication requires Identity authentication (MFA, OAuth, etc.). There is no simple username/password endpoint for Privilege Cloud.

In production, you must create a shell script/function to handle token generation through CyberArk Identity, which supports:
- Multi-factor authentication (MFA)
- OAuth client credentials
- External Identity Provider authentication
- Other Identity authentication mechanisms

For actual implementation guidance, refer to: [Authenticate to CyberArk Identity Security Platform Shared Services](https://docs.cyberark.com/privilege-cloud-shared-services/latest/en/content/developer/developer-home.htm#AuthenticatetoCyberArkIdentitySecurityPlatformSharedServices)


**Conceptual Production Pattern:**

Using a mock script name (does not exist):
```bash
source ./cyberark_identity_auth.sh
get_identity_token "<subdomain>" "user@company.com"
# This would handle Identity auth, MFA, OAuth, etc.

TOKEN=$CYBERARK_TOKEN  # Token returned by function
export TOKEN
export BASE_URL="https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault"
```

The mock script would set `TOKEN` in this format (like `$header.Authorization` in PowerShell):
```bash
TOKEN="<token_from_identity_authentication>"
# You would also need to include X-IDAP-NATIVE-CLIENT header in requests
```

Variables that would be set by the authentication module:
```bash
SUBDOMAIN="<subdomain>"
BASE_URL="https://${SUBDOMAIN}.privilegecloud.cyberark.cloud/PasswordVault"
TOKEN="<your_token_from_identity_authentication>"

export TOKEN
export BASE_URL
```


#### Add Account (Shell)
```bash
#!/bin/bash

# Assumes TOKEN and BASE_URL are already set from authentication
curl -X POST "${BASE_URL}/API/Accounts" \
  -H "Authorization: ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MyAccount",
    "address": "server01.example.com",
    "userName": "administrator",
    "platformId": "WinDomain",
    "safeName": "WindowsServers",
    "secretType": "password",
    "secret": "MySecretPassword123!",
    "platformAccountProperties": {
      "LogonDomain": "example.com"
    }
  }' | jq '.'

echo "Account created successfully"
```

#### Get All Accounts (Shell)
```bash
#!/bin/bash

# Assumes TOKEN and BASE_URL are already set from authentication

# Get all accounts (default limit is 50)
echo "Getting all accounts..."
curl -s -X GET "${BASE_URL}/API/Accounts" \
  -H "Authorization: ${TOKEN}" | jq '{count: .count, accounts: .value[] | {name, address, userName}}'
```

#### Get a specific account by ID (Shell)
```bash
#!/bin/bash

# Assumes TOKEN and BASE_URL are already set from authentication

ACCOUNT_ID="your_account_id"

# Get specific account by ID
echo "Getting account ${ACCOUNT_ID}..."
curl -s -X GET "${BASE_URL}/API/Accounts/${ACCOUNT_ID}" \
  -H "Authorization: ${TOKEN}" | jq '.'

# Get all accounts with search and limit
echo -e "\nSearching for accounts..."
curl -s -X GET "${BASE_URL}/API/Accounts?search=administrator&limit=50" \
  -H "Authorization: ${TOKEN}" | jq '.value[] | {name, address, userName}'

# Get accounts from specific safe
SAFE_NAME="WindowsServers"
echo -e "\nGetting accounts from safe ${SAFE_NAME}..."
curl -s -X GET "${BASE_URL}/API/Accounts?filter=safeName%20eq%20${SAFE_NAME}" \
  -H "Authorization: ${TOKEN}" | jq '.value[] | {name, safeName}'
```

#### Delete Account (Shell)
```bash
#!/bin/bash

# Assumes TOKEN and BASE_URL are already set from authentication

ACCOUNT_ID="your_account_id"

# Delete account
echo "Deleting account ${ACCOUNT_ID}..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE \
  "${BASE_URL}/API/Accounts/${ACCOUNT_ID}" \
  -H "Authorization: ${TOKEN}")

if [ "${HTTP_CODE}" -eq 204 ]; then
  echo "Account deleted successfully"
elif [ "${HTTP_CODE}" -eq 404 ]; then
  echo "Account not found"
else
  echo "Error: HTTP ${HTTP_CODE}"
fi
```

---

This guide covers the basics for managing accounts via the CyberArk Privilege Cloud REST API and is AI generated.

Please report any issues.
