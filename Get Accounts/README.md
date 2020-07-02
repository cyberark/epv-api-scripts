# Get-Accounts

A script that allows easy reporting or enumerating of Accounts
In this example script you will find examples of Get a list of Accounts, Get specific Account details, create a report of accounts

## Usage
```powershell
Get-Accounts.ps1 -PVWAURL <string> -List [-Report] [-SafeName <string>] [-Keywords <string>] [-SortBy <string>] [-Limit <int>] [-AutoNextPage] [-CSVPath <string>] [<CommonParameters>]
Get-Accounts.ps1 -PVWAURL <string> -Details -AccountID <string> [-Report] [-CSVPath <string>] [<CommonParameters>]
```

The script supports two modes [*List*](#list) and [*Details*](#account-details)

List:
-----
List all accounts that answer a specific search criteria (by Safe or keywords)
Allows to sort, limit or get all accounts with no limit
```powershell
Get-Accounts.ps1 -PVWAURL <PVWA URL> -List [-SafeName <Safe Name to filter by>] [-Keywords <Keywords to search by>] [-SortBy <Property to sort by>] [-Limit <Number of accounts per 'page'>] [-AutoNextPage]
```

Report from List:
----------------
Allows to generate a report of the Accounts found by the filter
```powershell
Get-Accounts.ps1 -PVWAURL <PVWA URL> -List -Report -CSVPath <Path to the report CSV> [-SafeName <Safe Name to filter by>] [-Keywords <Keywords to search by>] [-SortBy <Property to sort by>] [-Limit <Number of accounts per 'page'>] [-AutoNextPage]
```

Account Details:
---------------
Get all details on a specific account
```powershell
Get-Accounts.ps1 -PVWAURL <PVWA URL> -Details -AccountID <Account ID>
```

Report of specific account:
--------------------------
Allows to generate a report of the specific Account found
```powershell
Get-Accounts.ps1 -PVWAURL <PVWA URL> -Details -Report -CSVPath <Path to the report CSV> -AccountID <Account ID> 
```

## Supported version
CyberArk PAS version 10.4 and above

# Update-Accounts

A script that allows updating of multiple account properties of a specific account.
You can provide any parameter name that you wish to update.
Parameter values will be based on the same list of parameter names or if only one value is provided all parameters will have the same value (last parameter value will complete any parameter that does not have a value).

## Usage
```powershell
Update-Account.ps1 -PVWAURL <string> -AccountID <string> -ParameterNames <Comma seperated parameter names> -ParameterValues <Comma seperated parameter values> [<CommonParameters>]
```

Examples:
-----
### Update one custom property of an account
```powershell
Update-Account.ps1 -PVWAURL https://mydomain.com/PasswordVault -AccountID 12_34 -ParameterNames "Environment" -ParameterValues "Production"
```

### Update multiple custom properties of an account with multiple values
```powershell
Update-Account.ps1 -PVWAURL https://mydomain.com/PasswordVault -AccountID 12_34 -ParameterNames "DataCenter","Building","ApplicationName" -ParameterValues "Washington","B1","FinancialApp"
```
The account will update the Properties with their values according to the order they were entered
DataCenter = Washington
Building = B1
ApplicationName = FinancialApp

### Update multiple custom properties of an account with partial values
```powershell
Update-Account.ps1 -PVWAURL https://mydomain.com/PasswordVault -AccountID 12_34 -ParameterNames "ApplicationName","ApplicationOwner","ApplicationTeam" -ParameterValues "FinancialApp","John Doe"
```
The account will update the Properties with their values according to the order they were entered
ApplicationName = FinancialApp
ApplicationOwner = John Doe 
ApplicationTeam = John Doe

## Supported version
CyberArk PAS version 10.4 and above

# Invoke-BulkAccountActions

A script that can run Account Actions on a List of Accounts using REST API.
This script will execute a single account action on a list of accounts according to filters (optional).
Or execute a single account action on all accounts from a file.

## Usage
```powershell
Invoke-BulkAccountActions.ps1 -PVWAURL <string> -AuthType <["cyberark","ldap","radius"]> [-DisableSSLVerify] -AccountsAction <["Verify","Change","Reconcile"]> [-SafeName <string>] [-PlatformID <string>] [-UserName <string>] [-Address <string>] [-Custom <string>] [<CommonParameters>]
```

## Available filters
- Safe Name - Search for all accounts in a specific safe
- Filter by specific keywords: 
    - 	PlatformID
    - 	UserName
    - 	Address
    - 	Custom - Using this parameter will not validate the results
> Note: All filters will be by default with OR between them
> Each filter (except custom) will be validated to bring the exact results

Examples:
-----
### Verify all root accounts from UnixSSH
```powershell
Invoke-BulkAccountActions.ps1 -PVWAURL https://mydomain.com/PasswordVault -PlatformID "UnixSSH" -UserName "root" -AccountsAction "Verify"
```

### Verify all accounts in a specific safe that are in production (custom account property)
This will verify any account that has "production" in any property in that safe
```powershell
Invoke-BulkAccountActions.ps1 -PVWAURL https://mydomain.com/PasswordVault -SafeName "PRD-ATL-App01-Admin" -Custom "production" -AccountsAction "Verify"
```


### Change all accounts on a specific server (from any platform, in any safe)
```powershell
Invoke-BulkAccountActions.ps1 -PVWAURL https://mydomain.com/PasswordVault -Address "myserver.mydomain.com" -AccountsAction "Change"
```

### Reconcile a specific account
```powershell
Invoke-BulkAccountActions.ps1 -PVWAURL https://mydomain.com/PasswordVault -UserName "Administrator" -PlatformID "WindowsServerLocal" -SafeName "WIN-IT-Admin" -Address "myserver.mydomain.com" -AccountsAction "Reconcile"
```

## Supported version
CyberArk PAS version 10.4 and above