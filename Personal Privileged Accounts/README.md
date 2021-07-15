# Create-PersonalPrivilgedAccounts

A script that creates personal safes and personal privileged accounts in CyberArk from a CSV
In this example script you will find examples of concurrent sessions and bulk onboarding

## Usage
```powershell
Create-PersonalPrivilgedAccounts.ps1 -PVWAURL <string> -CSVPath <string> [-AuthType <cyberark,ldap,radius>] [-OTP <string>] [-SafeNamePattern <string>] [-PlatformID <string>] [-DisableSSLVerify] [<CommonParameters>]
```

## API refrence
- [Create bulk upload of accounts](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Create-bulk-upload-of-accounts-v10.htm?tocpath=Developer%7CREST%20APIs%7CAccounts%7CBulk%20upload%20of%20accounts%7C_____1)
- [Get all bulk account uploads for user](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Get-all-bulk-account-uploads-for-user-v10.htm?tocpath=Developer%7CREST%20APIs%7CAccounts%7CBulk%20upload%20of%20accounts%7C_____2)
- [Authentication (using the concurrentSession)](https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/CyberArk%20Authentication%20-%20Logon_v10.htm?tocpath=Developer%7CREST%20APIs%7CAuthentication%7CLogon%7C_____1)

## Parameters
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
- CsvPath
	- The CSV Path for the accounts to be onboarded
- SafeNamePattern
    - A string representing the template to create the personal safes in.
    - Use an asterix ('*') to decide the place holder of the user name
    - You can use only *one* asterix in the template
	- Default value: _"*_ADM"_
- PlatformID
	- The platform ID
	- Default value: _"WindDomain"_

## Examples

### Example 1 - basic scenario
Admin wants to create a personal safe for 2 users, each safe will include a single privileged account

CSV example (privAccounts.csv):
|UserName|SafeName|AccountUser|AccountAddress|AccountPlatform|Password|
|--------|--------|-----------|--------------|---------------|--------|
|User1|User1|User1_ADM|myDomain.com|WinDomainPrivileged|Ch4ng3Me!|
|User2|User2|User2_ADM|myDomain.com|WinDomainPrivileged|Ch4ng3Me!|

The command would be:
```powershell
Create-PersonalPrivilgedAccounts.ps1 "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\privAccounts.csv
```

### Example 2 - different safe pattern name
Admin wants to create a personal safe for 2 users, each safe will include a single privileged account
Using default Platform ID (WinDomain)
Safes will follow a template of "<user name>_ADM"

CSV example (privAccounts.csv):
|UserName|AccountUser|AccountAddress|Password|
|--------|-----------|--------------|--------|
|User1|User1_ADM|myDomain.com|Ch4ng3Me!|
|User2|User2_ADM|myDomain.com|Ch4ng3Me!|

The command would be:
```powershell
Create-PersonalPrivilgedAccounts.ps1 "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\privAccounts.csv -SafeNamePattern "*_ADM"
```

If we want the same thing with a different safe template of "Priv_<user name>"
The command would be:
```powershell
Create-PersonalPrivilgedAccounts.ps1 "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\privAccounts.csv -SafeNamePattern "Priv_*"
```

### Example 3 - custom properties
Admin wants to create a personal safe for 2 users, each safe will include a single privileged account
For each account we want to add a custom property called Owner
Safes will follow a template of "<user name>_ADM"

CSV example (privAccounts.csv):
|UserName|AccountUser|AccountAddress|Password|Owner|
|--------|-----------|--------------|--------|-----|
|User1|User1_ADM|myDomain.com|Ch4ng3Me!|User 1|
|User2|User2_ADM|myDomain.com|Ch4ng3Me!|User 2|

The command would be:
```powershell
Create-PersonalPrivilgedAccounts.ps1 "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\privAccounts.csv -SafeNamePattern "*_ADM"
```

If we want to exclude CPM management of accounts we can use the following CSV example (privAccounts.csv)
|UserName|AccountUser|AccountAddress|Password|Owner|enableAutoMgmt|manualMgmtReason|
|--------|-----------|--------------|--------|-----|--------------|----------------|
|User1|User1_ADM|myDomain.com|Ch4ng3Me!|User 1|True||
|User2|User2_ADM|myDomain.com|Ch4ng3Me!|User 2|False|No change|

The command would be:
```powershell
Create-PersonalPrivilgedAccounts.ps1 "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\privAccounts.csv -SafeNamePattern "*_ADM"
```

## Supported version
CyberArk PAS version 11.6 and above
