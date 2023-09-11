# Account Platform Report


## Main capabilities
-----------------
Report of all accounts the the platform settings with each accounts


## Parameters:
```powershell
$logonToken = Get-IDentityHeader -IdentityTenantURL https://aa12345.id.cyberark.cloud -IdentityUserName brian.bors@cyberark.cloud.xxxx -psPASFormat -PCloudSubdomain testlab
.\Get-AccountPlatformReport.ps1 -logonToken $logonToken
```

