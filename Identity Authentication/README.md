# Identity Authentication Module

## Main capabilities

- The module allows you to run Get-IdentityHeader which creates a hash with authentication token with X-IDAP-NATIVE-CLIENT = True. It also allows for the token to be output in a format PSPas can consume.

- The scripts follows recommendation of authenticating into Identity Security Platform - Shared Services (ISPSS) that can be found here:

  - <https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/WebServices/ISP-Auth-APIs.htm>

  - <https://docs.cyberark.com/Product-Doc/OnlineHelp/Idaptive/Latest/en/Content/Developer-resources.htm>

The function will get the IdentityHeader with or without MFA. It currently supports Password/EmailPush/SMSPush/MobileAppPush/SAML options to authenticate.

Some of the scripts available in epv-api-scripts allow receiving this token to authenticate.

### List Command

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

To output in a format able to be consumed by PS PAS.
Note that you must pass the PCloudTenantAPIURL
```powershell
Import-Module IdentityAuth.psm1
$header = Get-IdentityHeader -psPASFormat -IdentityTenantURL "something.id.cyberark.cloud" -IdentityUserName "UserToAuthenticate@cyberark.cloud.ID" -PCloudSubdomain "subdomain"
use-PASSession $header
```

SYNTAX
````powershell
Get-IdentityHeader -IdentityTenantURL <String> -IdentityUserName <String> [-IdentityTenantId <String>] [-psPASFormat] [-PCloudSubdomain <String>] [<CommonParameters>]

Get-IdentityHeader -IdentityTenantURL <String> -UPCreds <PSCredential> [-IdentityTenantId <String>] [-psPASFormat] [-PCloudSubdomain <String>] [<CommonParameters>]
````
# Identity User Refresh

- This script is used to intiate a refresh of a active directory based account in Identity.
  - Refreshing will update attritbute values and group memberships
  - https://identity-developer.cyberark.com/reference/post_cdirectoryservice-refreshtoken
- Prefered to run in PowerShell 6+ to allow for use of parrell processing of jobs
  - IdentityRefresh_5.1.ps1 is a version that has been backported to work with PowerShell 5.1, however processing is done serially.
- Multiple parmater types can be passed at once, only the highest will be processed. Order or processing: GroupName, UPB, UUID, UUIDArray 

```powershell
.\IdentityRefresh.ps1 -logonToken $srcToken -IdentityTenantURL "https://something.id.cyberark.cloud" [-GroupName "CyberArk - Vault Users"] [-UPN "User@lab.local] [-UUID "23b7f98c-60b4-4c01-a33f-4caa99472343"] [-UUIDArray @("23b7f98c-60b4-4c01-a33f-e4caa9947703","21b74328c-60b4-4c01-a33f-4caa99472343")]
.\IdentityRefresh_5.1.1.ps1 -logonToken $srcToken -IdentityTenantURL "https://something.id.cyberark.cloud" [-GroupName "CyberArk - Vault Users"] [-UPN "User@lab.local] [-UUID "23b7f98c-60b4-4c01-a33f-4caa99472343"] [-UUIDArray @("23b7f98c-60b4-4c01-a33f-e4caa9947703","21b74328c-60b4-4c01-a33f-4caa99472343")]
```
