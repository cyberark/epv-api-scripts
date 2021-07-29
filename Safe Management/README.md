# Safe Management
> **Note:**The content of the sample_safes.csv is for example only and does not represent real safes

Main capabilities
-----------------
- The tool Uses REST API and can support v9.8 of PVWA and up
- The tool supports listing of Safes, Adding new safes and adding new members to safes
- The tool can take a simple CSV file with safe details or members to add or update them
- The tool can support comma delimited CSV files (default) or tab delimited CSV files

In order to run the tool you need to run some simple commands in Powershell.

The Tool supports four modes for managing the safes: [*List*](#list-command), [*Add*](#add-command), [*Update*](#update-command), [*Delete*](#delete-command) 

The Tool supports three modes for managing safes Members: [*Members*](#members-command), [*UpdateMembers*](#update-members-command), [*DeleteMembers*](#delete-members-command)

## Authentication
The script by default supports CyberArk authentication.
In order to allow also LDAP authentication to the script, make sure the [*SmartLogonEnabled*](https://docs.cyberark.com/Product-Doc/Onlinehelp/PAS/latest/en/Content/PASIMP/General-PVWA-Configurations.htm) parameter in the PVWA configuration is set to *YES* and then simply run the script with your LDAP credentials (no changes required to the script).


## Safe Management

### List Command:
```powershell
Safe-Management.ps1 -PVWAURL <string> -List [-SafeName <string>] [<CommonParameters>]
```

If you want to List all safes (Based on the running user permissions):
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -List
```

If you want to Filter a specific safe to see its details:
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -List -SafeName "MySafe"
```

### Add Command:
```powershell
Safe-Management.ps1 -PVWAURL <string> -Add [-SafeName <string>] [-Description <string>] [-ManagingCPM <string>] [-NumVersionRetention <int>] [-FilePath <string>] [<CommonParameters>]
```

>*Note:* Using the add command depends on the CSV file format you use.
>
>Providing a CSV with Safe details only, will create the safe. See example file [`safe-details-sample.csv`](safe-details-sample.csv)
>
>Providing a CSV with Safe members only, will add members to that safe (only to existing safes). See example file [`safe-members-sample.csv`](safe-members-sample.csv)
>
>Providing a CSV with both Safe details and Safe members, will create the safe and add the relevant members. See example file [`safe-details and members-sample.csv`](safe-details_and_members-sample.csv)


If you want to Create a new safe called 'MySafe':
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -Add -SafeName "MySafe"
```

If you want to Create a new safe and add a description to that safe:
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -Add -SafeName "MySafe" -Description "This is My Safe that I Created using REST API"
```

If you want to Create a new safe and set the Managing CPM and the number of versions for retention:
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -Add -SafeName "MyDMZSafe" -ManagingCPM PassManagerDMZ -NumVersionRetention 5
```

If you want to Create a list of safes from a file:
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -Add -FilePath "C:\Temp\safes-sample.csv"
```

If you want to create a list of safes and add members to it from a file:
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -Add -FilePath "C:\Temp\safes-details_and_members-sample.csv"
```

### Update Command:
```powershell
Safe-Management.ps1 -PVWAURL <string> -Update [-SafeName <string>] [-Description <string>] [-ManagingCPM <string>] [-NumVersionRetention <int>] [-FilePath <string>] [<CommonParameters>]
```

If you want to Update the safe called 'MySafe' with a new description:
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -Update -SafeName "MySafe" -Description "This is My updated Safe description that I Created using REST API"
```

If you want to Update the safe Managing CPM:
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -Update -SafeName "MyDMZSafe" -ManagingCPM PassManagerDMZ
```

If you want to Update the description and members of a list of safes from a file:
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -Add -FilePath "C:\Temp\safes-sample.csv"
```
> *Note*: This command will try to Add the members from the file to the safe. Any existing member will be skipped (will not update it's permissions)


### Delete Command:
```powershell
Safe-Management.ps1 -PVWAURL <string> -Delete [-SafeName <string>] [-FilePath <string>] [<CommonParameters>]
```

If you want to Delete a specific safe called 'MySafe':
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -Delete -SafeName "MySafe"
```

If you want to Delete a list of safes from a file:
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -Delete -FilePath "C:\Temp\safes-sample.csv"
```

## Safe Members Management

### Members Command:
```powershell
Safe-Management.ps1 -PVWAURL <string> -Members -SafeName <string> [-UserName <string>] [-MemberRole <"Admin", "Auditor", "EndUser", "Owner", "Approver">] [-UserLocation <string>] [<CommonParameters>]
```

If you want to list all members of the safe 'MySafe':
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -Members -SafeName "MySafe"
```

If you want to add a new End User (default role) member to the safe 'MySafe':
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -Members -SafeName "MySafe" -UserName "MyUser" -MemberRole "EndUser"
```

If you want to add a new Auditor member from LDAP to the safe 'MySafe':
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -Members -SafeName "MySafe" -UserName "MyAuditUser" -MemberRole "Auditor" -UserLocation "MyLDAPDomain.com"
```

### Update Members Command:
```powershell
Safe-Management.ps1 -PVWAURL <string> -UpdateMembers [-FilePath <string>] [<CommonParameters>]
```

If you want to Update a list of members from a file:
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -UpdateMembers -FilePath "C:\Temp\safe-members-sample.csv"
```

If you want to Update a list of members from a file and if member is missing attempt to add them:
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -UpdateMembers -FilePath "C:\Temp\safe-members-sample.csv" -AddonUpdate
```

### Delete Members Command:
```powershell
Safe-Management.ps1 -PVWAURL <string> -DeleteMembers [-FilePath <string>] [<CommonParameters>]
```

If you want to Update a list of members from a file:
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -DeleteMembers -FilePath "C:\Temp\safe-members-sample.csv"
```
