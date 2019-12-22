# Dependent Account Onboard Utility

> **Note:** The content of the sample_dependentaccounts.csv is for example only and does not represent real accounts or dependent accounts

## Main capabilities
- The tool Uses REST API and can support v10.8 of PVWA and up
- The tool supports onboarding account dependencies for existing accounts
- The tool can take a simple CSV file with only the relevant Account information
- The tool can support comma delimited CSV files or tab delimited CSV files (based on machine locale)

## Paramters
- platformType valid options
	- "Windows Server Local, Windows Desktop Local, Windows Domain, Unix, Unix SSH Key, AWS, AWS Access Keys"

 - dependencyType valid options
	- "COM+ Application, IIS Anonymous Authentication, IIS Application Pool, Windows Scheduled Task, Windows Service"

## Usage
```powershell
Onboard-DependentAccountsFromCSV.ps1 -PVWAURL <string> [-AuthType <string> (*"cyberark"*,"ldap","radius")] [-CsvPath <string>] [<CommonParameters>]
```

### Example
Onboarding multiple Dependent Accounts
```powershell
& .\Onboard-DependentAccountsFromCSV.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault"  -CsvPath .\dependentAccounts.csv 
```