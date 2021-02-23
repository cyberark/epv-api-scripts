> **General**
> - These scripts Uses REST API and can support v9.10 of PVWA and up
> - The goal for these scripts is to allow easy Export and Import of applications including application authentications
> - In this example script you will find examples of Get applications, get speciifc applications authentication methods and creating applications with thier authentication methods

# Export/Import Applications
In order to run the tool you need to run some simple commands in Powershell.
The Tool supports two modes: [*Import*](#import-command) and [*Export*](#export-command)
The export will be done to a CSV file that will contain all information, the import would know to create the applications from the same CSV file.
The CSV file can be adjusted if needed

## Usage
```powershell
Export-Import-Applications.ps1 -PVWAURL <string> -Export -CSVPath <string> [-AuthType <string>] [-AppID <string>] [<CommonParameters>]
Export-Import-Applications.ps1 -PVWAURL <string> -Import -CSVPath <string> [-AuthType <string>] [<CommonParameters>]
```

### Export Command:
```powershell
Export-Import-Applications.ps1 -Export -PVWAURL <PVWA URL> -CSVPath <The path to save the applications output> -AppID <The specific Application ID to export details of>
```

Exporting all applications to a CSV file named "myApps.csv" using LDAP authentication
```powershell
Export-Import-Applications.ps1 -Export -PVWAURL https://PAS.mydomain.com/PasswordVault -AuthType ldap -CSVPath .\myApps.csv
```

Exporting a specific applications called "App1" to a file named "myApps.csv"
```powershell
Export-Import-Applications.ps1 -Export -PVWAURL https://PAS.mydomain.com/PasswordVault -AppID "App1" -CSVPath .\myApps.csv
```

### Import Command:
```powershell
Export-Import-Applications.ps1 -Import -PVWAURL <PVWA URL> -CSVPath <The path of the applications CSV to import>
```

Importing all applications from a file called "myApps.csv"
```powershell
Export-Import-Applications.ps1 -Import -PVWAURL https://PAS.mydomain.com/PasswordVault -CSVPath .\myApps.csv
```