# Optimize Address


## Main capabilities

- Used to query Account addresses against DNS to ensure they are valid.
- Can also update the format of the address to ensure that when Account discovery is ran, existing accounts are located and connected.

## Parameters

```powershell
.\Optimize-Addresses.ps1 [-logonToken] [-IdentityUserName] [-IdentityTenantURL] [-PCloudSubdomain] [-PVWACredentials] [-PVWAAddress] [-Safes] [-UpdateAccounts] [-ShowAllResults] [-SuppressErrorResults] [-ExportToCSV] [-CSVPath]
```

- logonToken
  - Logon token used to connect
- IdentityUserName
  - Username used to connect to Identity
- IdentityTenantURL
  - URL of the Identity Tenant
- PCloudSubdomain
  - Subdomain for Privileged Cloud
- PVWACredentials
  - Credentials used to authenticate 
  - Must be stored in a PSCredential object
- PVWAAddress
  - Address of the PVWA
- Safes
  - List of safes that will be reviewed
- UpdateAccounts
  - Enable updating of the address of Accounts when it is required
- ShowAllResults
  - Display Accounts that are able to be optimized or already optimized
- SuppressErrorResults
  - Do **not** display the accounts that are not optimized
- ExportToCSV
  - Export the accounts that where reviewed/updated to a .csv file
- CSVPath
  - File name and location to export results to
  - Default: ".\Optimize-Addresses-Results.csv"

## Examples

>Once a session is established, it does not need to be provided again later unless invalidated.

### Logon
```powershell
Import-Module IdentityAuth.psm1
$logonToken = Get-IdentityHeader -psPASFormat -IdentityTenantURL "something.id.cyberark.cloud" -IdentityUserName "UserToAuthenticate@cyberark.cloud.ID" -PCloudSubdomain "TestTenant"
.\Optimize-Addresses.ps1 -logonToken $logonToken -PCloudSubdomain "TestTenant"

.\Optimize-Addresses.ps1  -IdentityUserName "UserToAuthenticate@cyberark.cloud.ID" -IdentityTenantURL "something.id.cyberark.cloud" -PCloudSubdomain "TestTenant"

$creds = Get-Credential
.\Optimize-Addresses.ps1 -PVWACredentials $creds -PVWAAddress "https://pvwa.lab.local/PasswordVault"
```

### Regular Usage
```powershell
.\Optimize-Addresses.ps1

$safes = @("Safe1","Safe2","Safe3")
.\Optimize-Addresses.ps1 -Safes $safes

.\Optimize-Addresses.ps1 -UpdateAccounts

.\Optimize-Addresses.ps1 -ShowAllResults

.\Optimize-Addresses.ps1 -SuppressErrorResults

.\Optimize-Addresses.ps1 -ExportToCSV

.\Optimize-Addresses.ps1 -ExportToCSV -CSVPath ".\Export.csv"
````