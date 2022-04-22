# Remote-CredFile

> **Note:** The content of the map.csv is for example only and does not represent real components

## Main capabilities
-----------------
* The tool Uses REST API
* Ensure that both Remote-CredFile.ps1 and CyberArk-Common.psm1 are in the same location
* The tool connects to Windows Server using WinRM
    * If WinRM needs to be enabled you can use following resources for assistance in enabling WinRM
        * https://github.com/ansible/ansible/blob/devel/examples/scripts/ConfigureRemotingForAnsible.ps1
        * https://docs.microsoft.com/en-us/troubleshoot/windows-server/remote/how-to-enable-windows-remote-shell
* The tool currently does not work on components installed on Linux servers
    * This will be implemented in a future release
* The tool allows for override of IP Address, Component Types, and Operating System
* The tool requires administrative access to the server
    * By default connections are made using the credentials of the user running the script

## Parameters:
```powershell
.\Remote-CredFile.ps1 -PVWAURL <string> [[-DisableSSLVerify] [-AuthType] [-OTP] [-PVWACredentials] [-Jobs] [-ConnectedOnly] [-DisconnectedOnly] [-AllComponents] [-Component] [-ComponentUser] [-ComponentFilter] [-AllServers]  [-MapFile] [-PSCredentials] [-VaultAddress] [-APIAddress]
```
- PVWAURL
	- The URL of the PVWA that you are working with. 
	- Note that the URL needs to include 'PasswordVault', for example: "https://myPVWA.myDomain.com/PasswordVault"
	- If PVWAs credentials will be reset, do NOT use a load balancer address. Connect directly to a PVWA website to prevent script failure due to stopping the PVWA using by the script.
- DisableSSLVerify
	**(NOT RECOMMENDED)**
	- In cases when you want to test the script on a PVWA environment that does not include a valid SSL certificate, you can use this parameter
- AuthType
	- Authentication types for logon. 
	- Available values: _CyberArk, LDAP, RADIUS_
	- Default value: _CyberArk_
- OTP
	- In cases where RADIUS authentication is used and one-time-password is needed, use this parameter to enter the OTP value
- PVWACredentials
    - Used to pass credentials to be used with the PVWA via variable
        - Set credentials using ```$cred =  Get-Credential ```
- Jobs
    - Submits actions to reset credentials as PowerShell Jobs to allow for parallel processing
- AllComponents
    - Automatically selects all component types
- Component
    - Automatically selects specified component type
        - Acceptably values are "CPM","PSM","PVWA","CP","AAM Credential Provider","PSM/PSMP"
- ComponentUser
    - Automatically selects specified component users. Enclose the users in quotes and seperated by comma ","
        - "PSMApp_b4e7e2d,PSMApp_fg453fdsf"
- ComponentFilter
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
- PSCredentials
    - Allows for use of alternate credentials to make connections to WinRM
        - Set credentials using ```$PScred =  Get-Credential ```
- VaultAddress
    - Resets the vault address within the vault.ini file. What ever is provided will be set in the file. The new address(es) must be surrounded by double quotes ex: -vaultaddress "192.168.8.1,192.168.8.2" or -vaultaddress "vault.lab.local"
- ApiAddress
    - Resets the API Address within the vault.ini file. What ever is provided will be set in the file. The new address(es) must be surrounded by double quotes ex: -apiAddress "https://pvwa.lab.local/passwordvault" or -apiAddress "https://pvwa.lab.local/passwordvault,https://pvwa2.lab.local/passwordvault"