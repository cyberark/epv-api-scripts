# PSM-SessionsManagement

A script to list or Terminate all Active sessions on a specific PSM server.
This allows an Administrator to verify if a specific PSM server is available for maintenance by listing all active sessions and Terminate them if needed.

## Usage
```powershell
PSM-SessionsManagement.ps1 -PVWAURL <string> [-AuthType <cyberark, ldap, radius>] [-List] [-Terminate] [-PSMServerName <string>] [<CommonParameters>]
```

The script supports two modes [*List*](#list-command) and [*Terminate*](#terminate-command)

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

## Examples

### List all active sessions from PSMSever server ID
```powershell
PSM-SessionsManagement.ps1 -PVWAURL https://mydomain.com/PasswordVault -List -PSMServerName PSMServer
```

### List all active sessions from PSMSever server ID
```powershell
PSM-SessionsManagement.ps1 -PVWAURL https://mydomain.com/PasswordVault -List -PSMServerName PSMServer
```

The result would look like this:

|SessionID|User|FromIP|SessionStart|SessionDuration|RemoteMachine|AccountUsername|AccountAddress|Protocol|Client
|---------|----|------|------------|---------------|-------------|---------------|--------------|--------|------
|002e43e7-9fc9-4a47-aba4-e22cb4c5ce75|Admin1|1.1.1.1|01/05/2020|00:25:13|RemoteServer1|Administrator|RemoteServer1|RDP|PSM
|da701049-bd37-44d0-8364-d56f88f2c711|MyUser|1.2.2.1|01/05/2020|00:25:13|RemoteServer2|a_MyUser|mydomain.com|RDP|PSM

### Terminate all active sessions
```powershell
PSM-SessionsManagement.ps1 -PVWAURL https://mydomain.com/PasswordVault -Terminate -PSMServerName PSMServer
```

The result would look like this:

```batch
Terminating Admin1 Session to RemoteServer1 (more details: From IP: 1.1.1.1; Account User: Administrator; Account Address: RemoteServer1)
Terminating MyUser Session to RemoteServer2 (more details: From IP: 1.2.2.1; Account User: a_MyUser; Account Address: mydomain.com)
```

# Get-AdHocAccess

A script that will grant the user administrative access on a target and then opens a PSM connection to that target using the user credentials.
Using the Just-in-Time Access in CyberArk this session will be limited according to the defined time frame on the requested target platform.
The script will automatically filter only accounts that have the AdHocAccess setting (AllowDomainUserAdHocAccess) enabled in the platform.

## Usage
```powershell
Get-AdHocAccess.ps1 -PVWAURL <string> [-AuthType <ldap, radius>] [-RemoteMachine <string>] [-MachinesFilePath <string>][<CommonParameters>]
```

In order to use this script, the RemoteMachine needs to be a Windows target machine that has the AdHocAccess parameter turned on the account platform.
The authentication to the script needs to be with an LDAP user (using either LDAP or RADIUS authentication)
PSM needs to be installed and PSM Ad-Hoc Connection needs to be enabled (the script uses by default the PSMSecureConnect platform)
In order to run the script on a list of machines, have a text file ready with a list of remote machines (each on a speprate line) and use the MachinesFilePath parameter

## Supported version
CyberArk PAS version 10.6 and above

## Examples

### Connecting to a single remote machine
```powershell
Get-AdHocAccess.ps1 -PVWAURL https://mydomain.com/PasswordVault -RemoteMachine RemoteServer1
```
This would result in a RDP file download that will automatically start to the requested remote machine, where the running (LDAP) user is a local admin on the remote machine

### Connecting with RDP to a list of machines
```powershell
Get-AdHocAccess.ps1 -PVWAURL https://mydomain.com/PasswordVault -MachinesFilePath "C:\Files\MachinesList.txt"
```

The MachinesList file would look like this:
```text
RemoteServer1
RemoteServer2
RemoteServer3
```
This would result in a RDP file for each of the remote machines in the file downloaded.
This will automatically start each RDP file to each of the requested remote machines, where the running (LDAP) user is a local admin on each of these remote machines