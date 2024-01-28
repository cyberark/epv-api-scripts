# Account Onboard Utility

> **Note:** The content of the sample_accounts.csv is for example only and does not represent real accounts.

## Main capabilities
-----------------
- The tool uses REST API and can support v10.4 of PVWA and up.
- The tool supports basic Account and Safe Creation, much like the Password Upload Utility.
- The tool supports Template Safe (currently one for all Accounts).
- The tool can take a simple CSV file with only the relevant Account information.
- The tool will automatically update itself to the latest version if one exists in this GitHub folder.

In order to run the tool you need to run some simple commands in Powershell.
The tool supports three modes: [*Create*](#create-command), [*Update*](#update-command) and [*Delete*](#delete-command).

The tool will create a log file in the same folder of the script called: _"Account_Onboarding_Utility.log"_.
Running the tool with common parameters of Debug and Verbose will add more information to the log.

## Additional Platform Properties / File Categories
With the newer version of the REST APIs (seen as 2nd gen in the CyberArk documentation), in order to be able to upload accounts that have custom platform properties (file categories) these need to be already enabled/set at the platform level of the platform that the accounts will be linked with. This is also relevant to be able to upload accounts that have linked 'login' and 'reconcile' accounts listed in the CSV file.

When there is an attempt to onboard accounts that have custom platform properties (listed in the relevant columns in the CSV) which have not been already added at the platform level; a meaningful error will be displayed, related to the fact that the account property has not been added to the platform.

There are six FC's that are required to be added to the platform if an account has a linked 'login' and 'reconcile' account set, three are for the linked 'login' account and three are for the linked 'reconcile' account. Further information on how to do this can be found in this CyberArk KB:
 "https://cyberark-customers.force.com/s/article/Add-Reconcile-and-Login-Accounts-to-an-Account-using-V10-REST-API"

## Parameters:
```powershell
Accounts_Onboard_Utility.ps1 -PVWAURL <string> [-<Create / Update / Delete>] [-AuthType] [-OTP] [-TemplateSafe] [-CsvPath] [-CsvDelimiter] [-DisableSSLVerify] [-NoSafeCreation] [-DisableAutoUpdate] [-CreateOnUpdate] -[ConcurrentSession] [-BypassSafeSearch] [-BypassAccountSearch]
```
- PVWAURL
	- The URL of the PVWA that you are working with. 
	- Note that the URL needs to include 'PasswordVault', for example: "https://myPVWA.myDomain.com/PasswordVault"
	- When working with PVWA behind a load balancer, note that the session must be defined as sticky session. Alternatively, work with a single node PVWA.

- LogonToken
	- The logon token when using Privilege Cloud Shared Services (ISPSS).
	- To generate Token see https://github.com/cyberark/epv-api-scripts/tree/main/Identity%20Authentication 

- DisableSSLVerify
	**(NOT RECOMMENDED)**
	- Disable the SSL verification.
	- Use only if the PVWA environment doesn't include a valid SSL certificate.

- AuthType
	- Authentication types for logon. 
	- Available values: _CyberArk, LDAP, RADIUS_
	- Default value: _CyberArk_

- OTP
	- In cases where RADIUS authentication is used and one-time-password is needed, use this parameter to enter the OTP value

- Create / Update / Delete
	- The supported actions for onboarding or offboarding the accounts.

- CPM_NAME
	- Sets the name of the CPM to be used. 
	- Default: PasswordManager

- CsvPath
	- The CSV Path for the accounts to be onboarded

- CsvDelimiter
	- The CSV delimiter to be used.
	- Available values: comma, tab
	- Default value: _comma delimited_

- TemplateSafe
	- The Template Safe to copy properties from.
	- Using this parameter requires that the template Safe exists.
	- The process will create any new safe according to the Template Safe including managing CPM and Safe Members.

- NoSafeCreation
	- Safes that don't already exist will not be created.

- DisableAutoUpdate
	- Disable the automatic update and keep the current version.
	- Default: script will update itself to the latest version.

- CreateOnUpdate
	- Enable the creation of non-existing accounts when running in [*Update*](#update-command) mode.
	- Default: script will not create new accounts in [*Update*](#update-command) mode.

- WideAccountsSearch
	- If set to "Yes": greatly increase search speeds.
	- Default: flag is set to "No". The script will not search by account object name.

- NarrowSearch
	- Search the safe by "username" and "address", then do a comparison of "name" in PowerShell.
	- Default: when "name" is populated, searches are done by getting all accounts from a Safe, then comparing names in PowerShell.

- ignoreAccountName
	- Ignores "name" when searching for accounts to update. Use this if account name could be different from the one in the Vault.
	- Default: the script will compare the account "name" when searching.

- ConcurrentSession
	- Enables Concurrent Sessions for the user. This includes additional REST API calls (which must also be set to ConcurrentSession) or allows connected PVWA user sessions to remain.
	- Default: any sessions logged into will be disconnected.

- BypassSafeSearch
	- In [*Create*](#create-command) or [*Update*](#update-command) mode: prevent Safe searches, but may result in account operations failure if the Safe does not exist. This should only be used when all Safes listed already exist. USE WITH EXTREME CAUTION.
	- Default: the script searches if the account exists or if it needs to be created.

- BypassAccountSearch
	- In [*Create*](#create-command) mode: account is assumed to **not** exist and the script will attempt to create it. 
		- If "name" property is populated: only duplicate "name" properties will be detected and will cause a failure.
		- If "name" property is not populated: no checking for duplicate accounts and all other scenarios *may* result in duplicates. USE WITH EXTREME CAUTION.
	- Default: script will search for requested accounts to determine if they already exist. This search is done via the "name" property *or* combination of "username" and "address" if there is no "name".

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

If you want to Create Accounts but not create the Safes:
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\accounts.csv -Create -NoSafeCreation
```

If you want to Create Accounts and bypass Safes searches:
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

If you want to Create and Update Accounts (and Safes):
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\accounts.csv -Update -CreateOnUpdate
```
For accounts that exist, the script will update.
For accounts that don't exist, the script will create them.

If you want to Update Accounts and bypass Safes searches:
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
