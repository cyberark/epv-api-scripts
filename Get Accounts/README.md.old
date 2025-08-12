# Get-Accounts

> **General**
> - Supported version: CyberArk PAS version 10.4 and above
> - Allow easy reporting or enumerating of Accounts.
In this example script, you will find examples of Get a list of Accounts, Get specific Account details, Create a report of accounts.


## Usage
```powershell
Get-Accounts.ps1 -PVWAURL <string> -List [-Report] [-SafeName <string>] [-Keywords <string>] [-SortBy <string>] [-Limit <int>] [-AutoNextPage] [-CSVPath <string>] [<CommonParameters>]
Get-Accounts.ps1 -PVWAURL <string> -Details -AccountID <string> [-Report] [-CSVPath <string>] [<CommonParameters>]
```

The script supports two modes [*List*](#list) and [*Details*](#account-details).

List:
-----
List all accounts that answer to a specific search criteria (by Safe or keywords).
Allows to sort, limit or get all accounts with no limit.
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
Get all details on a specific account.
```powershell
Get-Accounts.ps1 -PVWAURL <PVWA URL> -Details -AccountID <Account ID>
```

Report of specific account:
--------------------------
Allows to generate a report of the specific Account found.
```powershell
Get-Accounts.ps1 -PVWAURL <PVWA URL> -Details -Report -CSVPath <Path to the report CSV> -AccountID <Account ID> 
```



# Update-Account

> **General**
> - Supported version: CyberArk PAS version 10.4 and above.
> - Allow the update of multiple properties for a given account. Any parameter name can be provided. The values will be set through the list `ParameterValues`. If this list is shorter than the list of `ParameterNames`, the parameters lacking a value will be completed by the last value of `ParameterValue`.


## Usage
```powershell
Update-Account.ps1 -PVWAURL <string> -AccountID <string> -ParameterNames <Comma separated parameter names> -ParameterValues <Comma separated parameter values> [<CommonParameters>]
```

## Examples:
### Update one custom property of an account
```powershell
Update-Account.ps1 -PVWAURL https://mydomain.com/PasswordVault -AccountID 12_34 -ParameterNames "Environment" -ParameterValues "Production"
```

### Update multiple custom properties of an account with multiple values
```powershell
Update-Account.ps1 -PVWAURL https://mydomain.com/PasswordVault -AccountID 12_34 -ParameterNames "DataCenter","Building","ApplicationName" -ParameterValues "Washington","B1","FinancialApp"
```
The account will update the Properties with their values according to the order they were entered:
- DataCenter = Washington,
- Building = B1,
- ApplicationName = FinancialApp.

### Update multiple custom properties of an account with partial values
```powershell
Update-Account.ps1 -PVWAURL https://mydomain.com/PasswordVault -AccountID 12_34 -ParameterNames "ApplicationName","ApplicationOwner","ApplicationTeam" -ParameterValues "FinancialApp","John Doe"
```
The account will update the Properties with their values according to the order they were entered:
- ApplicationName = FinancialApp,
- ApplicationOwner = John Doe,
- ApplicationTeam = John Doe.



# Invoke-BulkAccountActions

> **General**
> - Supported version: CyberArk PAS version 10.4 and above.
> - Run a single action on a list of Accounts, according to filters (optional) or from a file. Uses REST APIs.



## Usage
```powershell
Invoke-BulkAccountActions.ps1 -PVWAURL <string> -AuthType <["cyberark","ldap","radius"]> [-DisableSSLVerify] -AccountsAction <["Verify","Change","Reconcile"]> [-SafeName <string>] [-PlatformID <string>] [-UserName <string>] [-Address <string>] [-Custom <string>] [-FailedOnly] [<CommonParameters>]
```

## Available filters
- SafeName 
    - Search for all accounts in a specific safe
- PlatformID
- UserName
- Address
- Custom 
    - Using this parameter will not validate the results
- FailedOnly 
    - Run the action only on failed accounts
- CPMDisabled

> Note: The result will be the union of all filters' results (consider it as an "or" gate).
> Each filter (except `custom`) will be validated to bring exact results.

## Examples:

### Verify all root accounts from the UnixSSH Platform
```powershell
Invoke-BulkAccountActions.ps1 -PVWAURL https://mydomain.com/PasswordVault -PlatformID "UnixSSH" -UserName "root" -AccountsAction "Verify"
```

### Verify all accounts - in a specific Safe - that are in production (custom account property)
This will verify any account that has "production" in any property in that Safe
```powershell
Invoke-BulkAccountActions.ps1 -PVWAURL https://mydomain.com/PasswordVault -SafeName "PRD-ATL-App01-Admin" -Custom "production" -AccountsAction "Verify"
```


### Change all accounts on a specific server (from any Platform, in any Safe)
```powershell
Invoke-BulkAccountActions.ps1 -PVWAURL https://mydomain.com/PasswordVault -Address "myserver.mydomain.com" -AccountsAction "Change"
```

### Reconcile a specific account
```powershell
Invoke-BulkAccountActions.ps1 -PVWAURL https://mydomain.com/PasswordVault -UserName "Administrator" -PlatformID "WindowsServerLocal" -SafeName "WIN-IT-Admin" -Address "myserver.mydomain.com" -AccountsAction "Reconcile"
```

### Reconcile all failed accounts in a specific Safe
```powershell
Invoke-BulkAccountActions.ps1 -PVWAURL https://mydomain.com/PasswordVault -SafeName "PRD-ATL-App01-Admin" -FailedOnly -AccountsAction "Reconcile"
```

### Reconcile all CPMDisabled accounts
```powershell
Invoke-BulkAccountActions.ps1 -PVWAURL https://mydomain.com/PasswordVault -CPMDisabled -AccountsAction "Reconcile"
```

### Verify all accounts marked as CPMDisabled OR failed accounts
This uses an "or" statement, not an "and" statement. Added for backwards compatibility with older accounts.
```powershell
Invoke-BulkAccountActions.ps1 -PVWAURL https://mydomain.com/PasswordVault -CPMDisabled -FailedOnly -AccountsAction "Verify"
```

