> **General**
> - These scripts use REST API and can support Privilege Cloud and PAM - Self-Hosted v10.4 and up.


# Import Connection Component
## Main capabilities
- Import a Connection Component

## Usage
```powershell
Import-ConnectionComponents.ps1 -PVWAURL <string> [-LogonToken <object>] -ConnectionComponentZipPath <string> -ConnectionComponentFolderPath <string>  [<CommonParameters>]
```

## Examples
Importing a single Connection component:
```powershell
Import-ConnectionComponents.ps1 -PVWAURL "https://PAS.mydomain.com/PasswordVault" -ConnectionComponentZipPath C:\Temp\SampleConnectionComponent.zip
```

Importing all Connection Components in a folder:
```powershell
Import-ConnectionComponents.ps1 -PVWAURL "https://PAS.mydomain.com/PasswordVault" -ConnectionComponentFolderPath C:\Temp\DownloadedConnectionComponents\
```

Importing a single Connection component into Privilege Cloud:
```powershell
Import-ConnectionComponents.ps1 -PVWAURL "https://MySubDomain.privilegecloud.cyberark.cloud/PasswordVault/" -logonToken $LogonToken -ConnectionComponentZipPath C:\Temp\SampleConnectionComponent.zip
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
