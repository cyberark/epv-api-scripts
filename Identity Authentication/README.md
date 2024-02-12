# Identity Authentication Module

## Main capabilities

- `Get-IdentityHeader`: creates a hash of an authentication token with `X-IDAP-NATIVE-CLIENT = True`. The token can be output to the right format for psPAS.

- The scripts follow the recommendations for the authentication to Identity Security Platform - Shared Services (ISPSS) that can be found here: *links are outdated*

  - <https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/WebServices/ISP-Auth-APIs.htm> 

  - <https://docs.cyberark.com/Product-Doc/OnlineHelp/Idaptive/Latest/en/Content/Developer-resources.htm>

- The function will get the IdentityHeader with or without MFA. It currently supports Password/EmailPush/SMSPush/MobileAppPush/SAML options to authenticate.

Some of the scripts available in epv-api-scripts are able to consume this token to authenticate.

## List Command

```powershell
Import-Module IdentityAuth.psm1
$header = Get-IdentityHeader
```

If you want to specify information prior to running the scripts you can run:

```powershell
Import-Module IdentityAuth.psm1
$header = Get-IdentityHeader -IdentityTenantURL "something.id.cyberark.cloud" -IdentityUserName "UserToAuthenticate@cyberark.cloud.ID"
```

If you want to specify information prior to running the scripts including credentials for automatic response to a user password request you can run:

```powershell
Import-Module IdentityAuth.psm1
$UPCreds = Get-Credential
$header = Get-IdentityHeader -IdentityTenantURL "something.id.cyberark.cloud" -UPCreds $UPCreds
```

If you want to connect using OAuth:

```powershell
Import-Module IdentityAuth.psm1
$OAuth = Get-Credential
$header = Get-IdentityHeader -IdentityTenantURL "something.id.cyberark.cloud" -OAuthCreds $OAuth
```

Format output in a psPAS-compatible format. Only run $header once based on type of connection desired
```powershell
Import-Module IdentityAuth.psm1
$header = Get-IdentityHeader -IdentityTenantURL "something.id.cyberark.cloud" -psPASFormat -PCloudSubdomain "subdomain" -IdentityUserName "UserToAuthenticate@cyberark.cloud.ID"
$header = Get-IdentityHeader -IdentityTenantURL "something.id.cyberark.cloud" -psPASFormat -PCloudSubdomain "subdomain" -UPCreds $UPCreds -PCloudSubdomain "subdomain"
$header = Get-IdentityHeader -IdentityTenantURL "something.id.cyberark.cloud" -psPASFormat -PCloudSubdomain "subdomain" -OAuthCreds $OAuth 
use-PASSession $header
```

SYNTAX
````powershell
Get-IdentityHeader -IdentityTenantURL <String> -IdentityUserName <String> [-psPASFormat] [-PCloudSubdomain <String>] [<CommonParameters>]

Get-IdentityHeader -IdentityTenantURL <String> -UPCreds <PSCredential> [-psPASFormat] [-PCloudSubdomain <String>] [<CommonParameters>]

Get-IdentityHeader -IdentityTenantURL <String> -OAuthCreds <PSCredential> [-psPASFormat] [-PCloudSubdomain <String>] [<CommonParameters>]
````

# Identity User Refresh
## Main capabilities

- Initiate a refresh of an Active Directory-based account in Identity.
  - Refreshing will update attribute values and group memberships.
  - https://identity-developer.cyberark.com/reference/post_cdirectoryservice-refreshtoken *outdated link*
- Prefered to run in PowerShell 6+ to allow for use of parrell processing of jobs.
  - IdentityRefresh_5.1.ps1 is a version that has been backported to work with PowerShell 5.1, however processing is done serially.
- Multiple parameter types can be passed at once but only the highest will be processed. Order of processing: GroupName, UPB, UUID, UUIDArray.

## Usage
```powershell
.\IdentityRefresh.ps1 -logonToken $srcToken -IdentityTenantURL "https://something.id.cyberark.cloud" [-GroupName "CyberArk - Vault Users"] [-UPN "User@lab.local] [-UUID "23b7f98c-60b4-4c01-a33f-4caa99472343"] [-UUIDArray @("23b7f98c-60b4-4c01-a33f-e4caa9947703","21b74328c-60b4-4c01-a33f-4caa99472343")]
.\IdentityRefresh_5.1.1.ps1 -logonToken $srcToken -IdentityTenantURL "https://something.id.cyberark.cloud" [-GroupName "CyberArk - Vault Users"] [-UPN "User@lab.local] [-UUID "23b7f98c-60b4-4c01-a33f-4caa99472343"] [-UUIDArray @("23b7f98c-60b4-4c01-a33f-e4caa9947703","21b74328c-60b4-4c01-a33f-4caa99472343")]
```
