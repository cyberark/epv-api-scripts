# Create-PersonalPrivilgedAccounts

A script that creates personal safes and personal privileged accounts in CyberArk from a CSV
In this example script you will find examples of concurrent sessions and bulk onboarding

## Usage
```powershell
Create-PersonalPrivilgedAccounts.ps1 -PVWAURL <string> -CSVPath <string> [-AuthType <cyberark,ldap,radius>] [-OTP <string>] [-SafeTemplate <string>] [-DisableSSLVerify] [<CommonParameters>]
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
- SafeTemplate
    - A string representing the template to create the personal safes in.
    - Use an asterix ('*') to decide the place holder of the user name
    - You can use only *one* asterix in the template

## Examples

### Example 1
Admin wants to create a personal safe for 2 users, each safe will include a single privileged account

CSV example (privAccounts.csv):
|UserName|SafeName|AccountUser|AccountAddress|AccountPlatform|
|--------|--------|-----------|--------------|---------------|
|User1|User1|User1_ADM|myDomain.com|WinDomainPrivileged|
|User2|User2|User2_ADM|myDomain.com|WinDomainPrivileged|

The command would be:
```powershell
Create-PersonalPrivilgedAccounts.ps1 "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\privAccounts.csv
```

### Example 2
Admin wants to create a personal safe for 2 users, each safe will include a single privileged account
Safes will follow a template of "<user name>_ADM"

CSV example (privAccounts.csv):
|UserName|AccountUser|AccountAddress|AccountPlatform|
|--------|-----------|--------------|---------------|
|User1|User1_ADM|myDomain.com|WinDomainPrivileged|
|User2|User2_ADM|myDomain.com|WinDomainPrivileged|

The command would be:
```powershell
Create-PersonalPrivilgedAccounts.ps1 "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\privAccounts.csv -SafeTemplate "*_ADM"
```

If we want the same thing with a different safe template of "Priv_<user name>"
The command would be:
```powershell
Create-PersonalPrivilgedAccounts.ps1 "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\privAccounts.csv -SafeTemplate "Priv_*"
```

## Supported version
CyberArk PAS version 11.6 and above
