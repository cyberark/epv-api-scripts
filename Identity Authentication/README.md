# Identity Authentication

## Main capabilities

- The module allows you to run Get-IdentityHeader which creates a hash with authentication token with X-IDAP-NATIVE-CLIENT = True.

- The scripts follows recommendation of authenticating into Identity Security Platform - Shared Services (ISPSS) that can be found here:

  - <https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/WebServices/ISP-Auth-APIs.htm>

  - <https://docs.cyberark.com/Product-Doc/OnlineHelp/Idaptive/Latest/en/Content/Developer-resources.htm>

The function will get the IdentityHeader with or without MFA. It currently supports Password/EmailPush/SMSPush/MobileAppPush options to authenticate.

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
