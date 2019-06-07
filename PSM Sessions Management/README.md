# PSM-SessionsManagement

A script to list or Terminate all Active sessions on a specific PSM server.
This allows an Administrator to verify if a specific PSM server is available for maintenance by listing all active sessions and Terminate them if needed.


## Usage
```powershell
PSM-SessionsManagement.ps1 -PVWAURL <string> [-AuthType <cyberark, ldap, radius>] [-List] [-Terminate] [-PSMServerName <string>] [<CommonParameters>]
```

The script supports two modes	[*List*](#list-command) and [*Terminate*](#terminate-command)


List Command:
---------------
Using this command lists all active session on a specific PSM server
As a result you will get all the relevant details on all active sessions on the selected PSM server
```powershell
PSM-SessionsManagement.ps1 -PVWAURL <string> [-AuthType <cyberark, ldap, radius>] -List -PSMServerName <string> [<CommonParameters>]
```

Terminate Command:
---------------
Using this command will terminate all active session (that can be terminated according to the logged in user) on a specific PSM server
Any session that could not be terminated will be loggeded in the log file
```powershell
PSM-SessionsManagement.ps1 -PVWAURL <string> [-AuthType <cyberark, ldap, radius>] -Terminate -PSMServerName <string> [<CommonParameters>]
```

## Supported version
CyberArk PAS version 10.5 and above

# Get-AdHocAccess

A script that will grant the user administrative access on a target and then opens a PSM connection to that target using the user credentials.
Using th Just-in-Time Access in CyberArk this session will be limited according to the defined timeframe on the requested target platform.

## Usage
```powershell
Get-AdHocAccess.ps1 -PVWAURL <string> [-AuthType <ldap, radius>] [-RemoteMachine <string>] [<CommonParameters>]
```

In order to use this script, the RemoteMachine needs to be a Windows target machinethat has the AdHocAccess parameter turned on the account platform.
The authentication to the script needs to be with an LDAP user
PSM needs to be installed and PSM Ad-Hoc Connection needs to be enabled (the script uses by default the PSMSecureConnect platform)

## Supported version
CyberArk PAS version 10.5 and above
