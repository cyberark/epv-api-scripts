Main capabilities
-----------------
- These scripts Uses REST API and can support v10.4 of PVWA and up
- The goal for these scripts is to allow easy Export and Import of Platforms and Getting Platform details
- In this example script you will find examples of Get Platform details, Import and Export of Platforms

Usage (Export / Import:
------
```powershell
Export-Import-Platform.ps1 -PVWAURL <string> -Import -PlatformZipPath <string> [<CommonParameters>]
Export-Import-Platform.ps1 -PVWAURL <string> -Export -PlatformID <string> -PlatformZipPath <string> [<CommonParameters>]
```

Usage (Get Platform detailes):
------
```powershell
Get-PlatformDetails.ps1 [-PVWAURL] <string> [-PlatformID] <string> [<CommonParameters>]
```

Import Command:
---------------
```powershell
Export-Import-Platform.ps1 -Import -PVWAURL <PVWA URL> -PlatformZipPath <The path of the Platform ZIP to import>
```

Export Command:
---------------
```powershell
Export-Import-Platform.ps1 -Export -PVWAURL <PVWA URL> -PlatformID <Platform ID> -PlatformZipPath <The path to save the Platform ZIP output>
```

Get Platform Details:
--------------------
```powershell
Get-PlatformDetails.ps1 -PVWAURL <PVWA URL> -PlatformID <Platform ID>
```
