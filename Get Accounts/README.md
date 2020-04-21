# Get-Accounts

A script that allows easy reporting or enumerating of Accounts
In this example script you will find examples of Get a list of Accounts, Get specific Account details, create a report of accounts

## Usage
```powershell
Get-Accounts.ps1 -PVWAURL <string> -AuthMethod <string> -List [-Report] [-SafeName <string>] [-Keywords <string>] [-SortBy <string>] [-Limit <int>] [-AutoNextPage] [-CSVPath <string>] [<CommonParameters>]
Get-Accounts.ps1 -PVWAURL <string> -AuthMethod <string> -Details -AccountID <string> [-Report] [-CSVPath <string>] [<CommonParameters>]
```

The script supports two modes [*List*](#list) and [*Details*](#account-details)

List:
-----
List all accounts that answer a specific search criteria (by Safe or keywords)
Allows to sort, limit or get all accounts with no limit
```powershell
Get-Accounts.ps1 -PVWAURL <PVWA URL> -AuthMethod <string> -List [-SafeName <Safe Name to filter by>] [-Keywords <Keywords to search by>] [-SortBy <Property to sort by>] [-Limit <Number of accounts per 'page'>] [-AutoNextPage]
```

Report from List:
----------------
Allows to generate a report of the Accounts found by the filter
```powershell
Get-Accounts.ps1 -PVWAURL <PVWA URL> -AuthMethod <string> -List -Report -CSVPath <Path to the report CSV> [-SafeName <Safe Name to filter by>] [-Keywords <Keywords to search by>] [-SortBy <Property to sort by>] [-Limit <Number of accounts per 'page'>] [-AutoNextPage]
```

Account Details:
---------------
Get all details on a specific account
```powershell
Get-Accounts.ps1 -PVWAURL <PVWA URL> -AuthMethod <string> -Details -AccountID <Account ID>
```

Report of specific account:
--------------------------
Allows to generate a report of the specific Account found
```powershell
Get-Accounts.ps1 -PVWAURL <PVWA URL> -AuthMethod <string> -Details -Report -CSVPath <Path to the report CSV> -AccountID <Account ID> 
```

## Supported version
CyberArk PAS version 10.4 and above

## Supported authentication
Cyberark and LDAP

# Update-Accounts

A script that allows updating of multiple account properties of a specific account

## Usage
```powershell
Update-Account.ps1 -PVWAURL <string> -AuthMethod <string> -AccountID <string> -ParameterNames -ParameterValues [<CommonParameters>]
```

Examples:
-----
### Update one custom property of an account
```powershell
Update-Account.ps1 -PVWAURL https://mydomain.com/PasswordVault -AuthMethod cyberark -AccountID 12_34 -ParameterNames "Environment" -ParameterValues "Production"
```

### Update multiple custom properties of an account with multiple values
```powershell
Update-Account.ps1 -PVWAURL https://mydomain.com/PasswordVault -AuthMethod cyberark -AccountID 12_34 -ParameterNames "DataCenter","Building","ApplicationName" -ParameterValues "Washington","B1","FinancialApp"
```
The account will update the Properties with their values according to the order they were entered
DataCenter = Washington
Building = B1
ApplicationName = FinancialApp

### Update multiple custom properties of an account with partial values
```powershell
Update-Account.ps1 -PVWAURL https://mydomain.com/PasswordVault -AuthMethod cyberark -AccountID 12_34 -ParameterNames "ApplicationName","ApplicationOwner","ApplicationTeam" -ParameterValues "FinancialApp","John Doe"
```
The account will update the Properties with their values according to the order they were entered
ApplicationName = FinancialApp
ApplicationOwner = John Doe 
ApplicationTeam = John Doe

## Supported version
CyberArk PAS version 10.4 and above

## Supported authentication
Cyberark and LDAP

# Update-BulkAccounts

A script that allows updating of multiple account properties of a list of accounts

## Usage
```powershell
Update-BulkAccounts.ps1 -PVWAURL <string> -AuthMethod <string> -ICSVPath <Path to the report CSV> -ParameterNames -ParameterValues [<CommonParameters>]
```

Examples:
-----
### Update one custom property of list of accounts
```powershell
Update-BulkAccounts.ps1 -PVWAURL https://mydomain.com/PasswordVault -AuthMethod cyberark -ICSVPath <Path to the report CSV> -ParameterNames "Environment" -ParameterValues "Production"
```

### Update multiple custom properties of a list of accounts with multiple values
```powershell
Update-Account.ps1 -PVWAURL https://mydomain.com/PasswordVault -AuthMethod cyberark -ICSVPath <Path to the report CSV> -ParameterNames "DataCenter","Building","ApplicationName" -ParameterValues "Washington","B1","FinancialApp"
```
Accounts will update the Properties with their values according to the order they were entered
DataCenter = Washington
Building = B1
ApplicationName = FinancialApp

### Update multiple custom properties of list of accounts with partial values
```powershell
Update-Account.ps1 -PVWAURL https://mydomain.com/PasswordVault -AuthMethod cyberark -ICSVPath <Path to the report CSV> -ParameterNames "ApplicationName","ApplicationOwner","ApplicationTeam" -ParameterValues "FinancialApp","John Doe"
```
Accounts will update the Properties with their values according to the order they were entered
ApplicationName = FinancialApp
ApplicationOwner = John Doe 
ApplicationTeam = John Doe

## Supported version
CyberArk PAS version 10.4 and above

## Supported authentication
Cyberark and LDAP
