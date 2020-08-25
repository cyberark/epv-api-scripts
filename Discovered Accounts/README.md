# Discovered Accounts

> **General**
> - This script Uses REST API and can support v11.6 of PVWA and up
> - The goal for these scripts is to demonstrate use of Discovered Accounts REST API


## Usage
The Discovered Accounts Report script supports two modes: [*List*](#list-command) and [*Details*](#details-command)

```powershell
Get-DiscoveredAccountsReport.ps1 [-PVWAURL] <string> [[-AuthType] <string>] -List [[-PlatformType] <string>] [-OnlyPrivilegedAccounts] [-OnlyNonPrivilegedAccounts] [-OnlyEnabledAccounts] [-OnlyDisabledAccounts] [[-CSVPath] <string>] [-DisableSSLVerify] [<CommonParameters>]
Get-DiscoveredAccountsReport.ps1 [-PVWAURL] <string> [[-AuthType] <string>] -Details [[-DiscoveredAccountID] <string>] [[-CSVPath] <string>] [-DisableSSLVerify] [<CommonParameters>]
```

- PVWAURL
	- The URL of the PVWA that you are working with. 
	- Note that the URL needs to include 'PasswordVault', for example: "https://myPVWA.myDomain.com/PasswordVault"
	- When working with PVWA behind a load balancer, note that the session must be defined as sticky session. Alternatively, work with a single node PVWA
- AuthType
	- Authentication types for logon. 
	- Available values: _CyberArk, LDAP, RADIUS_
	- Default value: _CyberArk_
- PlatformType
	- Filter the Discovered accounts based on a specific platform
	- Available platform types: "Windows Server Local", "Windows Desktop Local", "Windows Domain", "Unix", "Unix SSH Key", "AWS", "AWS Access Keys"
	- Default value: All platform types
- OnlyPrivilegedAccounts
	- Filter only Discovered Accounts marked as Privileged
- OnlyNonPrivilegedAccounts
	- Filter only Discovered Accounts marked as Non-Privileged
- OnlyEnabledAccounts
	- Filter only Discovered Accounts marked as Enabled
- OnlyDisabledAccounts
	- Filter only Discovered Accounts marked as Disabled
- SearchKeywords
	- Filter Discovered Accounts by a specific keyword that appear in the User name, Address, Platform or Groups
- SearchType
	- Use this parameter to determine the search type
	- Available values: _Contains, StartWith_
	- Default value: _Contains_
- SortBy
	- Use this parameter to sort the Discovered Accounts results according to specified Discovered Accounts properties
	- Default sorting: _Ascending (asc)_
	- Multiple sorts are comma-separated
	- Maximum number of properties is 3
	- Example: "-SortBy 'UserName, Address desc'" to get descending sort by User name and address
	- Example: "-SortBy 'PlatformType asc'" to get ascending sort by PlatformType
- DiscoveredAccountID
	- Used with the Details mode, to return all details on a specific Discovered Account
- CsvPath
	- The CSV Path for the Discovered accounts report
	- Emitting this parameter will output the report to screen
- Limit
	- Limit the results returned by the REST API
	- Maximum value: _1000_
	- Default value: _50_ (recommended)
- AutoNextPage
	- For use cases where the REST API limit is not enough and multiple pages are returned, use this parameter to fetch automatically the next page of results
	- Default value: _False_
- DisableSSLVerify
	**(NOT RECOMMENDED)**
	- In cases when you want to test the script on a PVWA environment that does not include a valid SSL certificate, you can use this parameter
	

### Examples
Reporting all Windows Server Local Discovered Accounts with 'Admin' as a keyword to a CSV file
```powershell
Get-DiscoveredAccountsReport.ps1 -PVWAURL https://PAS.mydomain.com/PasswordVault -List -PlatformType "Windows Server Local" -SearchKeywords "Admin" -AutoNextPage -CSVPath "C:\CyberArk\DiscoveredAccounts\WinServer_Admin_August-2020.csv"
```

Reporting top 100 Enabled, Privileged Discovered Accounts sorted by User name to a CSV file
```powershell
Get-DiscoveredAccountsReport.ps1 -PVWAURL https://PAS.mydomain.com/PasswordVault -List -OnlyEnabledAccounts -OnlyPrivilegedAccounts -SortBy "UserName" -Limit 100 -CSVPath "C:\CyberArk\DiscoveredAccounts\Enabled_Privielged_August-2020.csv"
```