# OPM Rule Onboard Utility

> **Note:** The contents of the rules.csv is for example only

## Main capabilities
-----------------
- The tool Uses REST API and can support v10.4 of PVWA and up
- The tool supports basic creation of OPM rules

In order to run the tool you need to run some simple commands in Powershell.
The Tool supports create mode only.

The tool will create a log file in the same folder of the script called: _"OPM_Rule_Onboarding_Utility.log"_
Running the tool with common parameters of Debug and Verbose will add more information to the log

## Parameters:
```powershell
opm-rule-onboarding.ps1 -PVWAURL <string> [-AuthType] [-OTP]  [-CsvPath] [-CsvDelimiter] [-DisableSSLVerify]
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
- CsvPath
	- The CSV Path for the accounts to be onboarded
- CsvDelimiter
	- The CSV delimiter to be used.
	- Available values: comma, tab
	- Default value: _comma delimited_

Running the script with no parameters will cause it to prompt the user for input.

```powershell opm-rule-onboarding.ps1``` 

### Create Command:
```powershell
opm-rule-onboarding.ps1 -PVWAURL <string> [-OTP <string>] [-CsvPath <string>] [-CsvDelimiter <string>] [-DisableSSLVerify] [<CommonParameters>]
```

If you just want to Create Rules
```powershell
& .\opm-rule-onboarding.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault"  -CsvPath .\rules.csv
```
