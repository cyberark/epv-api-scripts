The content of the sample_safes.csv is for example only and does not represent real safes

Main capabilities
-----------------
- The tool Uses REST API and can support v9.8 of PVWA and up
- The tool supports listing of Safes, Adding new safes and adding new members to safes
- The tool can take a simple CSV file with safe details and for creation (supported by the Add switch)
- The tool can support comma delimited CSV files (default) or tab delimited CSV files

In order to run the tool you need to run some simple commands in Powershell.
The Tool supports three modes: [*List*](#list-command), [*Add*](#add-command) and [*Members*](#members-command)


List Command:
---------------
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


Add Command:
---------------
```powershell
Safe-Management.ps1 -PVWAURL <string> -Add [-SafeName <string>] [-Description <string>] [-FilePath <string>] [<CommonParameters>]
```

If you want to Create a new safe called 'MySafe':
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault"  -Add -SafeName "MySafe"
```

If you want to Create a new safe and add a description to that safe:
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault"  -Add -SafeName "MySafe" -Description "This is My Safe that I Created using REST API"
```

If you want to Create a list of safes from a file:
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault"  -Add -FilePath "C:\Temp\safes-sample.csv"
```

Members Command:
---------------
```powershell
Safe-Management.ps1 -PVWAURL <string> -Members -SafeName <string> [-UserName <string>] [-MemberRole <"Admin", "Auditor", "EndUser", "Owner">] [-UserLocation <string>] [<CommonParameters>]
```

If you want to list all members of the safe 'MySafe':
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -Members -SafeName "MySafe"
```

If you want to add a new End User (default role) member to the safe 'MySafe':
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -Members -SafeName "MySafe" -UserName "MyUser" -MemberRole "EndUser"
```

If you want to add a new Auditor member from LDADP to the safe 'MySafe':
```powershell
& .\Safe-Management.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -Members -SafeName "MySafe" -UserName "MyAuditUser" -MemberRole "Auditor" -UserLocation "MyLDAPDomain.com"
```
