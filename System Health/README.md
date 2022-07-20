# System-Health

> **Note:** The content of the map.csv is for example only and does not represent real components

## Main capabilities
-----------------
* The tool Uses REST API
* Ensure that both System-Health.ps1 and CyberArk-Common.psm1 are in the same location
* The tool allows for override of IP Address, Component Types, and Operating System

## Requirments
* Requires that CyberArk-Common.psm1 be present or loaded.
* Located at https://github.com/cyberark/epv-api-scripts/blob/main/CyberArk-Common/CyberArk-Common.psm1

## Parameters:
```powershell
.\Remote-CredFile.ps1 -PVWAURL <string> [[-AuthType <string>] [-OTP <string>] [-PVWACredentials <PSCredential>] [-AllComponentTypes] [-ComponentType <string>] [-ComponentUser <string>] [-ComponentUserFilter <string>] [-AllServers] [-ConnectedOnly] [-DisconnectedOnly] [-MapFile <string>] [-DisableSSLVerify] [-Job] [-OutputObject] [-CyberArkCommon]]
```
- PVWAURL
	- The URL of the PVWA that you are working with. 
	- Note that the URL needs to include 'PasswordVault', for example: "https://myPVWA.myDomain.com/PasswordVault"
	- If PVWAs credentials will be reset, do NOT use a load balancer address. Connect directly to a PVWA website to prevent script failure due to stopping the PVWA using by the script.

- AuthType
	- Authentication types for logon. 
	- Available values: _CyberArk, LDAP, RADIUS_
	- Default value: _CyberArk_
- OTP
	- In cases where RADIUS authentication is used and one-time-password is needed, use this parameter to enter the OTP value

- PVWACredentials
    - Used to pass credentials to be used with the PVWA via variable
        - Set credentials using ```$cred =  Get-Credential ```

- AllComponentTypes
    - Automatically selects all component types
- ComponentType
    - Automatically selects specified component type
        - Acceptably values are "CPM","PSM","PVWA","CP","AAM Credential Provider","PSM/PSMP"
- ComponentUser
    - Automatically selects specified component users. Enclose the users in quotes and seperated by comma ","
        - "PSMApp_b4e7e2d,PSMApp_fg453fdsf"
- ComponentUserFilter
    - Automatically selects component users based on search filter using "-like" filter.
        - "PasswordManager", "Pass*", "*Manager"

- AllServers
    - Automatically selects all servers of selected component types
- DisconnectedOnly
    - Automatically selects only servers that are currently disconnected
- ConnectedOnly
    - Automatically selects only servers that are currently connected

- MapFile
    - Used to override paramaters received from the PVWA System Health page
        - To use the file enter the "Component User" to match the Component User found on the System Health Page.
            - IP address, Component Type, and OS can be set via the file.
            - If the IP Address in the mapping file is set to 255.255.255.255 those components users will be bypassed. 
    - This file must be used with Privileged Cloud environments
    - If IP Address 

- DisableSSLVerify
	**(NOT RECOMMENDED)**
	- In cases when you want to test the script on a PVWA environment that does not include a valid SSL certificate, you can use this parameter

- DisplayFields
    - The fields to be outputted when run interactivly or as a job
        - Permitted values; "Component Type", "Component Version", "IP Address", "Component User", "*"
- Job
    - Used when running as a automated process

- OutputObject
    - Outputs the results as a object instead of a table

- CyberArkCommon
    - Location of the the CyberArk-Common module if not already loaded and not located in the same folder as the script
