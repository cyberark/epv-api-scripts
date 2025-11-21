# CyberArk Privilege Cloud ISPSS REST API Basic Guide

This document provides a practical introduction to using the CyberArk Privilege Cloud REST API for common account management tasks. It is designed for new users and developers who want to automate Privilege Cloud operations.

---

## Table of Contents
- [CyberArk Privilege Cloud REST API Training Guide](#cyberark-privilege-cloud-rest-api-training-guide)
  - [Table of Contents](#table-of-contents)
  - [API Overview](#api-overview)
  - [Authentication \& Authorization](#authentication--authorization)
  - [API URL Structure](#api-url-structure)
  - [Return Codes](#return-codes)
  - [Getting the $header Value (Authentication Example)](#getting-the-header-value-authentication-example)
  - [Account Management Examples](#account-management-examples)
    - [Add Account](#add-account)
    - [Get Accounts](#get-accounts)
    - [Get Accounts (with search)](#get-accounts-with-search)
    - [Update Account Details](#update-account-details)
    - [Delete Account](#delete-account)
    - [Change Credentials Immediately](#change-credentials-immediately)
    - [Set Next Password](#set-next-password)
    - [Change Credentials in Vault](#change-credentials-in-vault)
  - [Safe Management Examples (PowerShell)](#safe-management-examples-powershell)
    - [Add Safe](#add-safe)
    - [Change Safe (Update Safe Details)](#change-safe-update-safe-details)
    - [Remove Safe](#remove-safe)
  - [Safe Member Management Examples (PowerShell)](#safe-member-management-examples-powershell)
    - [Add Safe Member](#add-safe-member)
    - [Change Safe Member Permissions](#change-safe-member-permissions)
    - [Remove Safe Member](#remove-safe-member)
  - [Best Practices](#best-practices)

---

## API Overview
- CyberArk Privilege Cloud provides a RESTful API for automating and integrating privileged account management tasks.
- Each object (such as accounts) has its own URL path.
- The API can be accessed from any tool or language that supports HTTPS requests.

## Authentication & Authorization
- All API calls (except Logon) require an `Authorization` header with a session token.
- Obtain a session token by authenticating with the Logon API.
- Include the token in the `Authorization` header for all subsequent requests.

## API URL Structure
- **Portal URL:** `https://<subdomain>.cyberark.cloud/privilegecloud/`
- **API URL (Gen 3):** `https://<subdomain>.privilegecloud.cyberark.cloud/api/`
- **API URL (Gen 2):** `https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/`
- **API URL (Gen 1):** `https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/WebServices/`

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

Before making any API calls, you must obtain a session token header. Use the IdentityAuth.psm1 module as shown below:

```powershell
# Import the CyberArk Identity Authentication module
Import-Module .\IdentityAuth.psm1

# Option 1: Prompt for credentials interactively
$header = Get-IdentityHeader -PCloudURL "<subdomain>.privilegecloud.cyberark.cloud" -IdentityUserName "user@company.com"

# Option 2: Use a credential object
$UPCreds = Get-Credential
$header = Get-IdentityHeader -PCloudURL "<subdomain>.privilegecloud.cyberark.cloud" -UPCreds $UPCreds

# $header is a hashtable with the required Authorization and X-IDAP-NATIVE-CLIENT headers
```

## Account Management Examples

### Add Account
```powershell
$addAccountParams = @{
    Uri         = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts"
    Headers     = $header
    Method      = 'Post'
    Body        = (@{
        name        = 'MyAccount'
        address     = 'server01.example.com'
        userName    = 'administrator'
        platformId  = 'WinDomain'
        safeName    = 'WindowsServers'
        secretType  = 'password'
        secret      = 'MySecretPassword123!'
    } | ConvertTo-Json)
    ContentType = 'application/json'
}
$response = Invoke-RestMethod @addAccountParams
$response
```
### Get Accounts
```powershell
#get all accounts
$getAccountsParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts"
    Headers = $header
    Method  = 'Get'
}
$response = Invoke-RestMethod @getAccountsParams
$response.value # List of accounts

# To get a specific account by ID:
$getAccountParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts/{accountId}"
    Headers = $header
    Method  = 'Get'
}
$account = Invoke-RestMethod @getAccountParams
$account
```

### Get Accounts (with search)
```powershell
# Get all accounts
$getAccountsParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts"
    Headers = $header
    Method  = 'Get'
}
$response = Invoke-RestMethod @getAccountsParams
$response.value # List of accounts

# Search for accounts by username or other criteria
$search = 'administrator'
$getAccountsSearchParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts?search=$search"
    Headers = $header
    Method  = 'Get'
}
$searchResponse = Invoke-RestMethod @getAccountsSearchParams
$searchResponse.value # Filtered list of accounts

# To get a specific account by ID:
$getAccountParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts/{accountId}"
    Headers = $header
    Method  = 'Get'
}
$account = Invoke-RestMethod @getAccountParams
$account
```

### Update Account Details
```powershell
# The PATCH method is used for updating account details. The body is a JSON array of operations.
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
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts/{accountId}"
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

### Change Credentials Immediately
```powershell
$changeNowParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts/{accountId}/ChangeCredentials/"
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

## Safe Management Examples (PowerShell)

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

### Change Safe (Update Safe Details)
```powershell
$changeSafeParams = @{
    Uri         = "https://<subdomain>.privilegecloud.cyberark.cloud/api/Safes/{safeId}"
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
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/api/Safes/{safeId}"
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

## Safe Member Management Examples (PowerShell)

### Add Safe Member
```powershell
$addSafeMemberParams = @{
    Uri         = "https://<subdomain>.privilegecloud.cyberark.cloud/api/Safes/{safeId}/Members"
    Headers     = $header
    Method      = 'Post'
    Body        = (@{
        memberName  = 'user@company.com'
        permissions = @('UseAccounts', 'RetrieveAccounts', 'ListAccounts')
    } | ConvertTo-Json)
    ContentType = 'application/json'
}
$response = Invoke-RestMethod @addSafeMemberParams
$response
```

### Change Safe Member Permissions
```powershell
$changeSafeMemberParams = @{
    Uri         = "https://<subdomain>.privilegecloud.cyberark.cloud/api/Safes/{safeId}/Members/{memberName}"
    Headers     = $header
    Method      = 'Put'
    Body        = (@{
        permissions = @('UseAccounts', 'RetrieveAccounts', 'ListAccounts', 'AddAccounts')
    } | ConvertTo-Json)
    ContentType = 'application/json'
}
$response = Invoke-RestMethod @changeSafeMemberParams
$response
```

### Remove Safe Member
```powershell
$removeSafeMemberParams = @{
    Uri     = "https://<subdomain>.privilegecloud.cyberark.cloud/api/Safes/{safeId}/Members/{memberName}"
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

## Best Practices
- Always check the response code and handle errors (e.g., 401, 403, 429).
- Use HTTPS and keep your session token secure.
- Implement retry logic for 429 (Too Many Requests) errors.
- Refer to the [official CyberArk documentation](https://docs.cyberark.com/privilege-cloud-shared-services/latest/en/content/webservices/implementing%20privileged%20account%20security%20web%20services%20.htm) for full API details and updates.

---

This guide covers the basics for managing accounts via the CyberArk Privilege Cloud REST API and is AI generated. 

Please report any issues. 

For more advanced operations, consult the full API documentation.
