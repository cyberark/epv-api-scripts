# Migrate Via Rest

## Main capabilities
-----------------



## Parameters:
```powershell
Migrate.ps1   

 [-SRCPVWAURL] [-SrcAuthType] [-srcOTP] [-SRCPVWACredentials] [-srclogonToken]

 [-DSTPVWAURL] [-DstAuthType] [-DSTPVWACredentials] [-dstlogonToken] 

[-export]  [-exportCSV] [-importCSV] 

[-processSafes] [-createSafes]  [-UpdateSafeMembers] [-CPMOld] [-CPMNew] [-CPMOverride] -[dstUPN]

 [-processAccounts] [-getRemoteMachines]  [-newLDAP] [-noCreate] [-allowEmpty] [-SkipCheckSecret]  

[-maxJobCount] [-ProgressDetails] [-SuppressProgress] [-DisableSSLVerify] 

```
- SRCPVWAURL
	- URL for the source environment
	- HTTPS://Source.lab.local/PasswordVault
- SrcAuthType

- srcOTP
  - In cases where RADIUS authentication is used for the source and one-time-password is needed, use this parameter to enter the OTP value
- SRCPVWACredentials
  - Credentials for use with source environment stored as PSCredentials
  - 


- DisableSSLVerify
	**(NOT RECOMMENDED)**
	- In cases when you want to test the script on a PVWA environment that does not include a valid SSL certificate, you can use this parameter



- AuthType
	- Authentication types for logon. 
	- Available values: _CyberArk, LDAP, RADIUS_
	- Default value: _CyberArk_
- OTP
	- In cases where RADIUS authentication is used and one-time-password is needed, use this parameter to enter the OTP value
- Create / Update / Delete
	The supported actions for onboarding or offboarding of accounts
- CPM_NAME
	- Sets the name of the CPM to be used. Defaults to PasswordManager
- CsvPath
	- The CSV Path for the accounts to be onboarded
- CsvDelimiter
	- The CSV delimiter to be used.
	- Available values: comma, tab
	- Default value: _comma delimited_
- TemplateSafe
	- The Template safe to copy properties from
	- Using this parameter requires that the template safe exists
	- The process will create any new safe according to the Template Safe including managing CPM and Safe Members
- NoSafeCreation
	- In case used, safes that do not exist will not be created
- DisableAutoUpdate
	- By default, the script will automatically update itself to the latest version
	- Using this switch will disable this ability and will keep the current version
- CreateOnUpdate
	- By default, the script will automatically not create new accounts when in update mode
	- Using this switch will automatic create accounts that do not exist when running in update mode
- ConcurrentSession
	- By default, Any sessions logged into will be disconnected.
	- Using this switch will allow for Concurrent Sessions for the user. This includes additional REST API calls (Which must also be set to ConcurrentSession) or allow for connected PVWA user sessions to remain.
- BypassSafeSearch
	- By default, the script will automatically search to see if the account exists or if it needs to be created
	- Using this switch in create/update mode will prevent safe searches, but may result in account operations failures if the safe does not exist. This should only be used when it is known all safes listed already exist. USE WITH EXTREME CAUTION.
- BypassAccountSearch
	- By default, the script will automatically search for requested accounts to determine if they exist. This search is done via "name" property or a combination of "username" and "address" if "name" is not present
	- Using this switch in create mode will assume that the account does not exist and will attempt to create them. If the name property is populated only duplicate "name" properties will be detected and will cause a failure.  If the "name" property is not populated, there is no checking for duplicate accounts and all other scenarios MAY result in duplicates. USE WITH EXTREME CAUTION. 

### Export Command:
```powershell
Accounts_Onboard_Utility.ps1 -PVWAURL <string> -Create [-CPM_NAME <sting>] [-AuthType <string>] [-LogonToken $token] [-OTP <string>] [-TemplateSafe <string>] [-CsvPath <string>] [-CsvDelimiter <string>] [-DisableSSLVerify] [-NoSafeCreation] [<CommonParameters>]
```

If you just want to Create Accounts:
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault"  -CsvPath .\accounts.csv -Create
```

If you want to Create Accounts and Safes according to a Safe Template:
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\accounts.csv -Create -TemplateSafe “MyTemplateSafe”
```

If you want to Create Accounts but not create the safes:
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\accounts.csv -Create -NoSafeCreation
```

If you want to Create Accounts and bypass safes searches:
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\accounts.csv -Create -BypassSafeSearch
```

If you want to Create Accounts and bypass account searches:
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\accounts.csv -Create -BypassAccountSearch
```

### ProcessSafes Command:
```powershell
Accounts_Onboard_Utility.ps1 -PVWAURL <string> -Update [-CPM_NAME <sting>] [-AuthType <string>] [-LogonToken $token] [-OTP <string>] [-CsvPath <string>] [-CsvDelimiter <string>] [-DisableSSLVerify] [-NoSafeCreation] [<CommonParameters>]
```

> **Note:** In order to update specific accounts, make sure you include the account name in the CSV. The uniqueness of an account would be the Safe name and the Account name (object name)

If you want to Update existing Accounts only (without Safe creation):
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\accounts.csv -Update -NoSafeCreation
```

If you want to Create and Update Accounts (and safes):
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\accounts.csv -Update -CreateOnUpdate
```
For any account that exists, the script will update
For accounts that do not exist, the script will create the account

If you want to Update Accounts and bypass safes searches:
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\accounts.csv -Update -BypassSafeSearch
```

### ProcessAccounts Command:
```powershell
Accounts_Onboard_Utility.ps1 -PVWAURL <string> -Delete [-AuthType <string>] [-LogonToken $token] [-OTP <string>] [-CsvPath <string>] [-CsvDelimiter <string>] [-DisableSSLVerify] [<CommonParameters>]
```

If you want to delete all accounts in the file using RADIUS authentication with one-time-password
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -AuthType "radius" -OTP 1234 -CsvPath .\accounts.csv -Delete
```
