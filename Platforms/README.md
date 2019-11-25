> **General**
> - These scripts Uses REST API and can support v10.4 of PVWA and up
> - The goal for these scripts is to allow easy Export and Import of Platforms and Getting Platform details
> - In this example script you will find examples of Get Platform details, Import and Export of Platforms

# Export/Import Platform
In order to run the tool you need to run some simple commands in Powershell.
The Tool supports two modes: [*Import*](#import-command) and [*Export*](#export-command)

## Usage
```powershell
Export-Import-Platform.ps1 -PVWAURL <string> -Import -PlatformZipPath <string> [<CommonParameters>]
Export-Import-Platform.ps1 -PVWAURL <string> -Export -PlatformID <string> -PlatformZipPath <string> [<CommonParameters>]
```

### Import Command:
```powershell
Export-Import-Platform.ps1 -Import -PVWAURL <PVWA URL> -PlatformZipPath <The path of the Platform ZIP to import>
```

### Export Command:
```powershell
Export-Import-Platform.ps1 -Export -PVWAURL <PVWA URL> -PlatformID <Platform ID> -PlatformZipPath <The path to save the Platform ZIP output>
```
# Import Connection Component
In order to run the tool you need to run some simple commands in Powershell.

## Usage
```powershell
Import-ConnectionComponents.ps1 -PVWAURL <string> -ConnectionComponentZipPath <string> -ConnectionComponentFolderPath <string> [<CommonParameters>]
```

### Examples
Importing a single Connection component
```powershell
Import-ConnectionComponents.ps1 -PVWAURL <string> -ConnectionComponentZipPath <The path of the Connection Component ZIP to import>
```
Importing all Connection Components in a folder
```powershell
Import-ConnectionComponents.ps1 -PVWAURL <string> -ConnectionComponentFolderPath <The path of the folder containing Connection Components ZIP to import>
```

# Import Platform and Connection Component
## Main capabilities
- Import a platform and a PSM Connection component and link them
- Set the PSM Server ID for the new imported platform

## Usage
```powershell
Import-Platform-ConnectionComponent.ps1 [-PVWAURL] <string> -PlatformZipPath <string> -ConnectionComponentZipPath <string> [-PSMServerID] <string> [<CommonParameters>]
```

# Get Platform details
## Usage
```powershell
Get-PlatformDetails.ps1 -PVWAURL <string> -PlatformID <string> [<CommonParameters>]
```
