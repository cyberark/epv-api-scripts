# Account Onboard Utility

> **Note:** The content of the sample_accounts.csv is for example only and does not represent real accounts

## Main capabilities
-----------------
- The tool Uses REST API and can support v10.4 of PVWA and up
- The tool supports basic Account and Safe Creation, much like the Password Upload Utility
- The tool supports Template Safe (currently one for all Accounts)
- The tool can take a simple CSV file with only the relevant Account information
- The tool will automatically update it self to the latest version if one exists in this GitHub folder

In order to run the tool you need to run some simple commands in Powershell.
The Tool supports three modes: [*Create*](#create-command), [*Update*](#update-command) and [*Delete*](#delete-command)

The tool will create a log file in the same folder of the script called: _"Account_Onboarding_Utility.log"_
Running the tool with common parameters of Debug and Verbose will add more information to the log

## Additional Platform Properties / File Categories
With the newer version of the REST API's (seen as 2nd gen in the CyberArk documentation), in order to be able to upload accounts that have custom platform properties (file categories) these need to be already enabled/set at the platform level of the platform that the accounts will be linked with. This is also relevant to be able to upload accounts that have linked 'login' and 'reconcile' accounts listed in the CSV file.

When accounts are attempted to be onboarded that have custom platform properties listed in the relevant columns in the csv however have not been already added at the platform level, a meaningful error will be seen relating to the fact that the account property has not been account to the platform.

There are six FC's that are required to be added to the platform if an account has a linked 'login' and 'reconcile' account set, three are for the linked 'login' account and three are for the linked 'reconcile' account. Further information on how to do this can be found in this CyberArk KB:
 "https://cyberark-customers.force.com/s/article/Add-Reconcile-and-Login-Accounts-to-an-Account-using-V10-REST-API"

## Parameters:
```powershell
Accounts_Onboard_Utility.ps1 -PVWAURL <string> [-<Create / Update / Delete>] [-AuthType] [-OTP] [-TemplateSafe] [-CsvPath] [-CsvDelimiter] [-DisableSSLVerify] [-NoSafeCreation] [-DisableAutoUpdate] [-CreateOnUpdate] -[ConcurrentSession] [-BypassSafeSearch] [-BypassAccountSearch]
```
- PVWAURL
	- The URL of the PVWA that you are working with. 
	- Note that the URL needs to include 'PasswordVault', for example: "https://myPVWA.myDomain.com/PasswordVault"
	- When working with PVWA behind a load balancer, note that the session must be defined as sticky session. Alternatively, work with a single node PVWA
- LogonToken
	- The logon token when using Privlage Cloud Shared Services (ISPSS)
	- To generate Token See https://github.com/cyberark/epv-api-scripts/tree/main/Identity%20Authentication 
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

### Create Command:
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

### Update Command:
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

### Delete Command:
```powershell
Accounts_Onboard_Utility.ps1 -PVWAURL <string> -Delete [-AuthType <string>] [-LogonToken $token] [-OTP <string>] [-CsvPath <string>] [-CsvDelimiter <string>] [-DisableSSLVerify] [<CommonParameters>]
```

If you want to delete all accounts in the file using RADIUS authentication with one-time-password
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -AuthType "radius" -OTP 1234 -CsvPath .\accounts.csv -Delete
```
