Main capabilities
-----------------
- The tool Uses REST API and can support v10.4 of PVWA and up
- The goal for this script is to allow easy reporting or enumerating of Accounts
- In this example script you will find examples of Get a list of Accounts, Get specific Account details, create a report of accounts

Usage:
------
```powershell
Get-Accounts.ps1 -PVWAURL <string> -List [-Report] [-SafeName <string>] [-Keywords <string>] [-SortBy <string>] [-Limit <int>] [-AutoNextPage] [-CSVPath <string>] [<CommonParameters>]
Get-Accounts.ps1 -PVWAURL <string> -Details -AccountID <string> [-Report] [-CSVPath <string>] [<CommonParameters>]
```

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
