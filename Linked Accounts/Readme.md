# Link-Accounts

A script that allows easy linking of pre-existing accounts. These links can include Logon, Enable, and Reconconsile. When a account is directly linked via PVWA or REST it will override any default settings configured at the platform level. 


extraPasswordIndex refers to the type of connections. These types are controled by the platform configuration. The values below are the values used for OOTB platforms and are subject to change.

extraPasswordIndex 1 - Logon Account
extraPasswordIndex 2 - Enable Account
extraPasswordIndex 3 - Reconcile Account

## Usage
```powershell
Link-Accounts.ps1 -PVWAURL <string> -CSVPath <string> [-AuthType <string>] [-DisableSSLVerify]  [-concurrentSession] [<CommonParameters>]
```

Link accounts via CSV:
--------------------------
Links pre-existing accounts to other pre-existing accounts
```powershell
Link-Accounts.ps1 -PVWAURL <string> -CSVPath <string> [-AuthType <string>] [-DisableSSLVerify]   [-concurrentSession] [<CommonParameters>]
```

Examples:
-----
### Link Accounts
```powershell
Link-Accounts.ps1 -PVWAURL https://mydomain.com/PasswordVault -CSVPath ./LinkAccounts.csv 
```

### Link Accounts while allowing concurrent sessions
```powershell
Link-Accounts.ps1 -PVWAURL https://mydomain.com/PasswordVault -CSVPath ./LinkAccounts.csv -concurrentSession
```

### Link Accounts when connecting to a PVWA with a untrusted certificate
```powershell
Link-Accounts.ps1 -PVWAURL https://mydomain.com/PasswordVault -CSVPath ./LinkAccounts.csv -DisableSSLVerify
```


## Supported version
CyberArk PAS version 12.0 and above
CyberArl Privlaged Cloud

## REST APIs utilized
https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Link-account.htm
