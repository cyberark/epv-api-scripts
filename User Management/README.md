# User Management

> **General**
> - The goal for these scripts is to demonstrate use of User Management REST API
> - These scripts uses the 2nd Gen REST API and can support v10.9 of PVWA and up

## Activate User
-----------------
- This script will activate a suspended user. It does not activate an inactive user.
- The user running this Web service must have Audit users permissions.
- Users on the same level as your user or lower in the Vault hierarchy are retrieved.

### Parameters:
```powershell
Activate-User.ps1 [-PVWAURL] <string> [-EPVUserName] <string>
```

## Get Inactive Users Report
-----------------
- In order to use the ability to filter Users according to inactivity time, you would need version 11.1 (minimum)
- The script can report the users to the screen or to a CSV file (with additional details)

The script will create a log file in the same folder of the script called: _"InactiveUsersReport.log"_
Running the script with common parameters of Debug and Verbose will add more information to the log

### Parameters:
```powershell
Get-InactiveUsersReport.ps1 [-PVWAURL] <string> [[-AuthType] <string>] [[-InactiveDays] <int>] [[-CSVPath] <string>] [-DisableSSLVerify] [<CommonParameters>]
```

- PVWAURL
	- The URL of the PVWA that you are working with. 
	- Note that the URL needs to include 'PasswordVault', for example: "https://myPVWA.myDomain.com/PasswordVault"
	- When working with PVWA behind a load balancer, note that the session must be defined as sticky session. Alternatively, work with a single node PVWA
- AuthType
	- Authentication types for logon. 
	- Available values: _CyberArk, LDAP, RADIUS_
	- Default value: _CyberArk_
- InactiveDays
	- The number of days to check for inactivity of users
	- Default value: 30 days
- CsvPath
	- The CSV Path for the inactive users report
	- Emitting this parameter will output the report to screen
- DisableSSLVerify
	**(NOT RECOMMENDED)**
	- In cases when you want to test the script on a PVWA environment that does not include a valid SSL certificate, you can use this parameter

### Output Examples:
----------------
#### Report Sample to screen
> When using v10.10 - no ability to filter users

|username           |source   |userType       |componentUser |IsEnabled |IsSuspended |LastSuccessfulLoginDate
|--------           |------   |--------       |------------- |--------- |----------- |-----------------------
|Administrator      |CyberArk |Built-InAdmins         |False     |True       |False |N/A
|Auditor            |CyberArk |Built-InAdmins         |False     |False      |False |N/A
|NotificationEngine |CyberArk |ENE                    |True      |True       |False |N/A
|AdminUser1         |CyberArk |EPVUser                |False     |True       |False |N/A
|AdminUser2         |CyberArk |EPVUser                |False     |True       |False |N/A
|PVWAGWUser         |CyberArk |PVWA                   |True      |True       |False |N/A
|PVWAAppUser        |CyberArk |PVWA                   |True      |True       |False |N/A
|PasswordManager    |CyberArk |CPM                    |True      |True       |False |N/A
|EPMAgent           |CyberArk |EPVUser                |False     |True       |False |N/A
|strong             |CyberArk |EPVUser                |False     |True       |False |N/A
|weak               |CyberArk |EPVUser                |False     |True       |False |N/A
|Backup             |CyberArk |Built-InAdmins         |False     |False      |False |N/A
|Operator           |CyberArk |Built-InAdmins         |False     |False      |False |N/A
|DR                 |CyberArk |Built-InAdmins         |False     |False      |False |N/A

#### Report Sample to file
> Using version 11.1

|username|FirstName|LastName|source|userType|componentUser|IsEnabled|IsSuspended|LastSuccessfulLoginDate|VaultAuthorization
|--------|---------|--------|------|--------|-------------|---------|-----------|-----------------------|------------------
|Administrator|||CyberArk|Built-InAdmins|False|True|False|12/16/2019 7:55:19 AM|AddUpdateUsers;AddSafes;AddNetworkAreas;ManageDirectoryMapping;ManageServerFileCategories;AuditUsers;BackupAllSafes;RestoreAllSafes;ResetUsersPasswords;ActivateUsers
|Auditor|||CyberArk|Built-InAdmins|False|False|False|12/10/2019 10:28:12 AM|AuditUsers
|NotificationEngine|||CyberArk|ENE|True|True|False|12/15/2019 9:09:44 AM|AuditUsers
|AdminUser1|||CyberArk|EPVUser|False|True|False|12/10/2019 10:29:38 AM|AddUpdateUsers;AddSafes;AddNetworkAreas;ManageDirectoryMapping;ManageServerFileCategories;AuditUsers;BackupAllSafes;RestoreAllSafes;ResetUsersPasswords;ActivateUsers
|AdminUser2|||CyberArk|EPVUser|False|True|False|12/10/2019 10:29:40 AM|AddUpdateUsers;AddSafes;AddNetworkAreas;ManageDirectoryMapping;ManageServerFileCategories;AuditUsers;BackupAllSafes;RestoreAllSafes;ResetUsersPasswords;ActivateUsers
|PVWAAppUser|||CyberArk|PVWA|True|True|False|12/15/2019 9:07:45 AM|AddSafes;AuditUsers
|PVWAGWUser|||CyberArk|PVWA|True|True|False|12/15/2019 9:07:57 AM|AuditUsers
|PasswordManager|||CyberArk|CPM|True|True|False|12/15/2019 9:10:02 AM|
|EPMAgent|||CyberArk|EPVUser|False|True|False|12/10/2019 10:38:30 AM|AuditUsers
|strong|||CyberArk|EPVUser|False|True|False|12/11/2019 10:02:06 PM|
|weak|||CyberArk|EPVUser|False|True|False|12/10/2019 12:07:03 PM|
|Backup|||CyberArk|Built-InAdmins|False|False|False|12/10/2019 10:28:12 AM|BackupAllSafes
|Operator|||CyberArk|Built-InAdmins|False|False|False|12/10/2019 10:28:12 AM|RestoreAllSafes
|DR|||CyberArk|Built-InAdmins|False|False|False|12/10/2019 10:28:12 AM|BackupAllSafes;RestoreAllSafes
