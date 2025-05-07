> **General**
> - These scripts use REST API and can support v10.4 of PVWA and up.

# Import Connection Component
## Main capabilities
- Import a Connection Component

## Usage
```powershell
Import-ConnectionComponents.ps1 -PVWAURL <string> -ConnectionComponentZipPath <string> -ConnectionComponentFolderPath <string> [<CommonParameters>]
```

## Examples
Importing a single Connection component:
```powershell
Import-ConnectionComponents.ps1 -PVWAURL https://PAS.mydomain.com/PasswordVault -ConnectionComponentZipPath C:\Temp\SampleConnectionComponent.zip
```

Importing all Connection Components in a folder:
```powershell
Import-ConnectionComponents.ps1 -PVWAURL https://PAS.mydomain.com/PasswordVault -ConnectionComponentFolderPath C:\Temp\DownloadedConnectionComponents\
```

# Convert Connection Component
## Main capabilities

- Using PVConfiguration.xml create connection component zip files for import:

## Usage
```powershell
Import-ConnectionComponents.ps1 -PVConfiguration <string> [-Output <string> <CommonParameters>]
```
## Examples
```powershell
Convert-ConnectionComponents.ps1 -PVConfiguration .\PVConfiguration.xml -Output .\Output\
```
