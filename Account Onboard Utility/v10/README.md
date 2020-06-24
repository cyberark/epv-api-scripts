# Account Onboard Utility

> **Note:** The content of the sample_accounts.csv is for example only and does not represent real accounts

## Main capabilities
-----------------
- The tool Uses REST API and can support v10.4 of PVWA and up
- The tool supports basic Account and Safe Creation, much like the Password Upload Utility
- The tool supports Template Safe (currently one for all Accounts)
- The tool can take a simple CSV file with only the relevant Account information

In order to run the tool you need to run some simple commands in Powershell.
The Tool supports three modes: [*Create*](#create-command), [*Update*](#update-command) and [*Delete*](#delete-command)

The tool will create a log file in the same folder of the script called: _"Account_Onboarding_Utility.log"_
Running the tool with common parameters of Debug and Verbose will add more information to the log

With the newer verson of the REST API's (now seen as 2nd gen in the CyberArk documentation), in order to be able to upload accounts that have custom file catergories these need to be already enabled/set at the platform level of the platform that the accounts will be linked with. This is also relevant to be able to upload accounts that have have linked 'login' and 'reconcile' accounts. If you try to upload accounts that have custom file catergories as columns in the csv a meaningful error will be seen relating to the FC not being linked with the platform. There are six FC's that needed to be added to the platform. three are for the linked 'login' account and three are for the linked 'reconcile' account. Further information on how to do this can be found in this CyberArk KB: https://cyberark-customers.force.com/s/article/Add-Reconcile-and-Login-Accounts-to-an-Account-using-V10-REST-API

## Parameters:
```powershell
Accounts_Onboard_Utility.ps1 -PVWAURL <string> [-<Create / Update / Delete>] [-AuthType] [-OTP] [-TemplateSafe] [-CsvPath] [-CsvDelimiter] [-DisableSSLVerify] [-NoSafeCreation]
```
- PVWAURL
	- The URL of the PVWA that you are working with. 
	- Note that the URL needs to include 'PasswordVault', for example: "https://myPVWA.myDomain.com/PasswordVault"
	- When working with PVWA behind a load balancer, note that the session must be defined as sticky session. Alternatively, work with a single node PVWA
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

### Create Command:
```powershell
Accounts_Onboard_Utility.ps1 -PVWAURL <string> -Create [-AuthType <string>] [-OTP <string>] [-TemplateSafe <string>] [-CsvPath <string>] [-CsvDelimiter <string>] [-DisableSSLVerify] [-NoSafeCreation] [<CommonParameters>]
```

If you just want to Create Accounts (including creating the Safes if they don’t exist):
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault"  -CsvPath .\accounts.csv -Create
```

If you want to Create Accounts and Safes according to a Safe Template:
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\accounts.csv -Create -TemplateSafe “MyTemplateSafe”
```

If you want to Create Accounts but not create the safes (if they don’t exist):
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\accounts.csv -Create -NoSafeCreation
```

### Update Command:
```powershell
Accounts_Onboard_Utility.ps1 -PVWAURL <string> -Update [-AuthType <string>] [-OTP <string>] [-TemplateSafe <string>] [-CsvPath <string>] [-CsvDelimiter <string>] [-DisableSSLVerify] [-NoSafeCreation] [<CommonParameters>]
```

If you want to Create and Update Accounts (and safes):
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\accounts.csv -Update
```

If you want to Create and Update Accounts (without Safe creation):
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\accounts.csv -Update -NoSafeCreation
```

### Delete Command:
```powershell
Accounts_Onboard_Utility.ps1 -PVWAURL <string> -Delete [-AuthType <string>] [-OTP <string>] [-CsvPath <string>] [-CsvDelimiter <string>] [-DisableSSLVerify] [<CommonParameters>]
```

If you want to delete all accounts in the file using RADIUS authentication with one-time-password
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -AuthType "radius" -OTP 1234 -CsvPath .\accounts.csv -Delete
```
