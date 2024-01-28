# Link-Accounts

>**Supported versions**:
>- CyberArk PAS version 12.0 and above 
>- CyberArk Privileged Cloud
>- REST APIs used: https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Link-account.htm


## Main Capabilities
- Allow easy linking of pre-existing accounts using a .csv file. Links include Logon, Enable and Reconcile. When an account is directly linked via the PVWA or the REST API, it will override any default settings configured at the platform level.
- `extraPasswordIndex` parameter in the .csv file refers to the type of link. The types of link are controlled by the Platform configuration. Values below are from OOTB Platforms and are subject to change:
    - 1 : Logon Account
    - 2 : Enable Account
    - 3 : Reconcile Account


## Usage
```powershell
Link-Accounts.ps1 -PVWAURL <string> -CSVPath <string> [-AuthType <string>] [-DisableSSLVerify] [-concurrentSession] [<CommonParameters>]
```

Link accounts via CSV:
--------------------------
Links pre-existing accounts to other pre-existing accounts:
```powershell
Link-Accounts.ps1 -PVWAURL <string> -CSVPath <string> [-AuthType <string>] [-DisableSSLVerify] [-concurrentSession] [<CommonParameters>]
```

Examples:
-----
### Link Accounts
```powershell
Update-Account.ps1 -PVWAURL https://mydomain.com/PasswordVault -CSVPath ./LinkAccounts.csv 
```

### Link Accounts while allowing concurrent sessions
```powershell
Update-Account.ps1 -PVWAURL https://mydomain.com/PasswordVault -CSVPath ./LinkAccounts.csv -concurrentSession
```

### Link Accounts when connecting to a PVWA with a untrusted certificate
```powershell
Update-Account.ps1 -PVWAURL https://mydomain.com/PasswordVault -CSVPath ./LinkAccounts.csv -DisableSSLVerify
```
