> **General**
> - These scripts Uses REST API and can support v10.4 of PVWA and up
> - The goal for these scripts is to allow easy Export and Import of Platforms and Getting Platform details
> - In this example script you will find examples of Get Platform details, Import and Export of Platforms

# Export/Import Platform
In order to run the tool you need to run some simple commands in Powershell.
The Tool supports two modes: [*Import*](#import-command) and [*Export*](#export-command)
The tool can support a single import/export of a single platform or a list of platforms using a CSV file

## Usage
```powershell
Export-Import-Platform.ps1 -PVWAURL <string> -Import -PlatformZipPath <string> [-AuthType <string>] [<CommonParameters>]
Export-Import-Platform.ps1 -PVWAURL <string> -Export -PlatformID <string> -PlatformZipPath <string> [-AuthType <string>] [<CommonParameters>]
Export-Import-Platform.ps1 -PVWAURL <string> -Bulk -Export -CSVPath <string> [-AuthType <string>] [<CommonParameters>]
Export-Import-Platform.ps1 -PVWAURL <string> -Bulk -Import -CSVPath <string> [-AuthType <string>] [<CommonParameters>]
```

### Import Command:
```powershell
Export-Import-Platform.ps1 -Import -PVWAURL <PVWA URL> [-AuthType <string>] -PlatformZipPath <The path of the Platform ZIP to import> [<CommonParameters>]
Export-Import-Platform.ps1 -Import -PVWAURL <PVWA URL> [-AuthType <string>] -Bulk -CSVPath <The path of the CSV for import> [<CommonParameters>]
```

### Export Command:
```powershell
Export-Import-Platform.ps1 -Export -PVWAURL <PVWA URL> [-AuthType <string>] -PlatformID <Platform ID> -PlatformZipPath <The path to save the Platform ZIP output> [<CommonParameters>]
Export-Import-Platform.ps1 -Export -PVWAURL <PVWA URL> [-AuthType <string>] -Bulk -CSVPath <The path of the CSV for export> [<CommonParameters>]
```

### Examples
#### Import a single Sample Platform
```powershell
Export-Import-Platform.ps1 -Import -PVWAURL https://PAS.mydomain.com/PasswordVault -PlatformZipPath C:\Temp\SamplePlatform.zip
```

#### Import a list of Platforms
```powershell
Export-Import-Platform.ps1 -Import -PVWAURL https://PAS.mydomain.com/PasswordVault -CSVPath C:\Temp\myPlatforms.csv
```

myPlatforms.csv file:
|ZipPath|ID|
|-------|--|
|C:\Temp\SamplePlatform.zip||
|C:\Temp\SecondPlatform.zip||
|C:\Temp\ThirdPlatform.zip||


#### Export Sample Platform
```powershell
Export-Import-Platform.ps1 -Export -PVWAURL https://PAS.mydomain.com/PasswordVault -PlatformID SamplePlatform -PlatformZipPath C:\Temp\Export-SamplePlatform.zip
```

#### Export a list of platforms
```powershell
Export-Import-Platform.ps1 -Export -PVWAURL https://PAS.mydomain.com/PasswordVault -CSVPath C:\Temp\myPlatforms.csv
```
myPlatforms.csv file:
|ZipPath|ID|
|-------|--|
|C:\Temp\Export-SamplePlatform.zip|SamplePlatform|
|C:\Temp\Export-SecondPlatform.zip|SecondPlatform|
|C:\Temp\Export-ThirdPlatform.zip|ThirdPlatform|


# Import Connection Component
In order to run the tool you need to run some simple commands in Powershell.

## Usage
```powershell
Import-ConnectionComponents.ps1 -PVWAURL <string> -ConnectionComponentZipPath <string> -ConnectionComponentFolderPath <string> [<CommonParameters>]
```

### Examples
Importing a single Connection component
```powershell
Import-ConnectionComponents.ps1 -PVWAURL https://PAS.mydomain.com/PasswordVault -ConnectionComponentZipPath C:\Temp\SampleConnectionComponent.zip
```
Importing all Connection Components in a folder
```powershell
Import-ConnectionComponents.ps1 -PVWAURL https://PAS.mydomain.com/PasswordVault -ConnectionComponentFolderPath C:\Temp\DownloadedConnectionComponents\
```

# Import Platform and Connection Component
## Main capabilities
- Import a platform and a PSM Connection component and link them
- Set the PSM Server ID for the new imported platform

## Usage
```powershell
Import-Platform-ConnectionComponent.ps1 [-PVWAURL] <string> -PlatformZipPath <string> -ConnectionComponentZipPath <string> [-PSMServerID] <string> [<CommonParameters>]
```

### Examples
Importing a sample platform and connect it to a relevant sample PSM connection component using a custom PSM Server ID
```powershell
Import-Platform-ConnectionComponent.ps1 -PVWAURL https://PAS.mydomain.com/PasswordVault -PlatformZipPath C:\Temp\SamplePlatform.zip -ConnectionComponentZipPath C:\Temp\SampleConnectionComponent.zip -PSMServerID PSMServer_MyPSMSRV
```

# Get Platform details
## Usage
```powershell
Get-PlatformDetails.ps1 -PVWAURL <string> -PlatformID <string> [<CommonParameters>]
```

### Examples
Get Windows Server Local Platform details
```powershell
Get-PlatformDetails.ps1 -PVWAURL https://PAS.mydomain.com/PasswordVault -PlatformID WinServerLocal
```

# Platforms Report
Creates a report on all Active platforms and their connection components.
Supported version: 11.6 and above

## Usage
```powershell
Get-PlatformReport.ps1 [-PVWAURL] <string> [[-AuthType] <string>] [[-CSVPath] <string>] [-ExtendedReport] [-DisableSSLVerify] [<CommonParameters>]
```

### Examples
Printing all Active Platforms report on screen
```powershell
Get-PlatformReport.ps1 -PVWAURL https://PAS.mydomain.com/PasswordVault 
```

Printing all Active Platforms extended report to a CSV file (including all Connection components)
```powershell
Get-PlatformReport.ps1 -PVWAURL https://PAS.mydomain.com/PasswordVault -ExtendedReport -CSVPath "C:\CyberArk\Platforms\Active_Platforms_August-2020.csv"
```