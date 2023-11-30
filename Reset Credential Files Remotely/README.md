# Remote-CredFile

> **Note:** The content of the 'map.csv' file is for example only and does not represent real components.

## Main capabilities
- This script will attempt to regenerate the remote Applicative Cred File and Sync it in the Vault.
- This tool uses REST API.
- Ensure that both 'Remote-CredFile.ps1' and 'CyberArk-Common.psm1' are in the same location.
- This tool connects to Windows Server using WinRM. If WinRM needs to be enabled, you can use following resources for assistance:
    - https://github.com/ansible/ansible/blob/devel/examples/scripts/ConfigureRemotingForAnsible.ps1
    - https://docs.microsoft.com/en-us/troubleshoot/windows-server/remote/how-to-enable-windows-remote-shell
- The tool currently does not work on components installed on Linux servers.
    - This will be implemented in a future release
- The tool allows override of IP Address, Component Types, and Operating System.
- The tool requires administrative access to the server.
    - By default connections are made using the credentials of the user running the script.

## Parameters:
```powershell
.\Remote-CredFile.ps1 -PVWAURL <string> [[-AuthType <string>] [-OTP <string>] [-PVWACredentials <PSCredential>] [-PSCredentials <PSCredential>] [-AllComponentTypes] [-ComponentType <string>] [-ComponentUser <string>] [-ComponentUserFilter <string>] [-AllServers] [-ConnectedOnly] [-DisconnectedOnly] [-MapFile <string>] [-VaultAddress <string>] [-APIAddress <string>] [-DisableSSLVerify] [-Jobs]]
```
- PVWAURL
	- The URL of the PVWA. 
	- Note that the URL needs to include 'PasswordVault', for example: "https://myPVWA.myDomain.com/PasswordVault"
	- If PVWAs credentials are supposed to be reset during the process, do NOT use a load balancer address. Connect directly to the PVWA to prevent script failure due to stopping the PVWA by using the script.
- AuthType
	- Authentication types for logon. 
	- Available values: _CyberArk, LDAP, RADIUS_
	- Default value: _CyberArk_
- OTP
    - One-time-password, in case you use RADIUS authentication
- PVWACredentials
    - Credentials to use for the PVWA.
    - Set credentials using ```$cred =  Get-Credential ```
- PSCredentials
    - Use alternate credentials to connect to WinRM
    - Set credentials using ```$PScred =  Get-Credential ```
- AllComponentTypes
    - Select all component types
- ComponentType <`String`>
    - Select specified component type
    - Acceptably values are "CPM", "PSM", "PVWA", "CP", "AAM Credential Provider", "PSM/PSMP".
- ComponentUser
    - Select specified component Users.
    - Enclose the users in quotes and separe them by comma ","
    - Example: "PSMApp_b4e7e2d,PSMApp_fg453fdsf".
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
- VaultAddress
    - Resets the vault address within the 'vault.ini' file.
    - Whatever is provided will be set in the file. The new address(es) must be surrounded by double quotes.
    - Examples: 
        - ``-vaultaddress "192.168.8.1,192.168.8.2"`` 
        - or ``-vaultaddress "vault.lab.local"``
- ApiAddress
    - Resets the API Address in the 'vault.ini' file. 
    - What ever is provided will be set in the file. The new address(es) must be surrounded by double quotes 
    - Examples: 
        - ``-apiAddress "https://pvwa.lab.local/passwordvault"`` 
        - or ``-apiAddress "https://pvwa.lab.local/passwordvault,https://pvwa2.lab.local/passwordvault"``
- DisableSSLVerify
	**(NOT RECOMMENDED)**
	- Disable the SSL certificate verification.
	- Use only if your PVWA environment doesn't include a valid SSL certificate.
- Jobs <`Switch`>
    - Submit actions to reset credentials as PowerShell Jobs to allow for parallel processing.
- Tries
    - Select how many attempts are made to complete work before failing.
    - Default: 5.