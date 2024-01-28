# System-Health

> **Note:** The content of the map.csv is for example only and does not represent real components.

## Main capabilities
This tool:
- allows for override of IP Address, Component Types, and Operating System.
- uses REST API.

## Requirements
- Both 'System-Health.ps1' and 'CyberArk-Common.psm1' must be in the same location and 'CyberArk-Common.psm1' must be loaded.
- Located at https://github.com/cyberark/epv-api-scripts/blob/main/CyberArk-Common/CyberArk-Common.psm1

## Parameters:
```powershell
.\System-Health.ps1 -PVWAURL <string> [[-AuthType <string>] [-OTP <string>] [-PVWACredentials <PSCredential>] [-AllComponentTypes] [-ComponentType <string>] [-ComponentUser <string>] [-ComponentUserFilter <string>] [-AllServers] [-ConnectedOnly] [-DisconnectedOnly] [-MapFile <string>] [-DisableSSLVerify] [-Job] [-OutputObject] [-CyberArkCommon]]
```
- PVWAURL
	- The URL of the PVWA. 
	- URL needs to include 'PasswordVault', for example: "https://myPVWA.myDomain.com/PasswordVault"
	- If PVWAs credentials will be reset, do NOT use a load balancer address. Connect directly to a PVWA website to prevent script failure due to stopping the PVWA using by the script.
- AuthType
	- Authentication types for logon. 
	- Available values: _CyberArk, LDAP, RADIUS_
	- Default value: _CyberArk_
- OTP
    - One-time-password, in case you use RADIUS authentication.
- PVWACredentials
    - Credentials used for the PVWA.
    - Set credentials by using ```$cred =  Get-Credential ```
- AllComponentTypes
    - Select all component types.
- ComponentType
    - Select specified component type.
    - Acceptably values: "CPM","PSM","PVWA","CP","AAM Credential Provider","PSM/PSMP"
- ComponentUser
    - Select specified component users. Enclose the users in quotes and seperated by comma ","
    - Example: "PSMApp_b4e7e2d,PSMApp_fg453fdsf"
- ComponentUserFilter
    - Select component Users based on a `-like` search filter.
    - Examples: "PasswordManager", "Pass*", "*Manager"
- AllServers
    - Select all servers of selected component types.
- DisconnectedOnly
    - Select only servers that are currently disconnected.
- ConnectedOnly
    - Select only servers that are currently connected.
- MapFile
    - Override parameters received from the PVWA System Health page
    - To use the file, enter the "Component User" to match the Component User found on the System Health Page.
        - IP address, Component Type, and OS can be set via the file.
        - Components users will be bypassed if the IP Address in the mapping file is set to 255.255.255.255. 
    - This file must be used with Privileged Cloud environments.
- DisableSSLVerify
	**(NOT RECOMMENDED)**
	- Disable the SSL certificate verification.
	- Use only if your PVWA environment doesn't include a valid SSL certificate.
- DisplayFields
    - The fields to be output when run interactively or as a job.
    - Permitted values; "Component Type", "Component Version", "IP Address", "Component User", "*"
- Job <`Switch`>
    - Used when running as a automated process.
- OutputObject
    - Output the results as an object instead of a table.
- CyberArkCommon
    - Location of the the 'CyberArk-Common' module if not already loaded and not located in the same folder as the script.
