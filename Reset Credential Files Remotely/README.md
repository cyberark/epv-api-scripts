# Reset Credential Files Remotely

Remotely regenerates CyberArk component credential files and synchronises the new password
in the Vault — without requiring an operator to log on to each component server manually.

> **Note:** `map.csv` contains example data only and does not represent real components.

---

## Scripts

| Script | Purpose | Run on |
| --- | --- | --- |
| `Invoke-CredFileReset.ps1` | **Main script** — orchestrates credential resets across component servers | Orchestrating machine |
| `Get-CyberArkComponentLog.ps1` | Retrieves the last N lines of CyberArk component log files from remote servers via WinRM | Orchestrating machine |
| `Reset-WinComponentCredential.ps1` | Windows helper functions loaded into remote PSSessions (not run directly) | Loaded automatically |
| `Reset-LinuxComponentCredential.ps1` | Linux/PSMP helper functions dot-sourced by the orchestrator (stub — not yet implemented) | Not run directly |
| `Test-RemoteConnectivity.ps1` | Pre-flight check — tests WinRM connectivity from orchestrating machine to targets | Orchestrating machine |
| `Test-WinRMConfiguration.ps1` | Diagnoses WinRM configuration on a component server | Target server (locally) |
| `Invoke-ComponentUserPasswordReset.ps1` | Updates the cyberark componenet user in the vault only! | Orchestrating machine |

---

## Requirements

- PowerShell 5.1 or later on the orchestrating machine
- WinRM (TCP 5985) access from the orchestrating machine to each component server
- CyberArk Vault Administrator or equivalent REST API permissions on the PVWA
- Local Administrator rights on each component server (via WinRM)
- `Invoke-CredFileReset.ps1`, `Reset-WinComponentCredential.ps1`, and `Reset-LinuxComponentCredential.ps1` must be in the same directory

---

## Recommended Workflow

### Step 1 — Pre-flight: check WinRM on the target servers

Run `Test-WinRMConfiguration.ps1` **locally on each component server** to verify WinRM is
configured correctly before attempting a remote credential reset:

```powershell
# Read-only inspection
.\Test-WinRMConfiguration.ps1

# Check and fix issues (prompts before each fix)
.\Test-WinRMConfiguration.ps1 -Fix

# Preview fixes without applying
.\Test-WinRMConfiguration.ps1 -Fix -WhatIf
```

### Step 2 — Pre-flight: verify connectivity from the orchestrating machine

Run `Test-RemoteConnectivity.ps1` **from the orchestrating machine** to confirm it can reach
each component server over WinRM:

```powershell
# Test one or more servers (Kerberos — domain account, no explicit credential needed)
.\Test-RemoteConnectivity.ps1 -ComputerName 'cpm01.lab.local', 'psm01.lab.local'

# Test with explicit credentials (workgroup / untrusted domain)
$cred = Get-Credential
.\Test-RemoteConnectivity.ps1 -ComputerName '192.168.1.50' -Credential $cred

# Auto-fix TrustedHosts if needed
.\Test-RemoteConnectivity.ps1 -ComputerName '192.168.1.50' -Credential $cred -Fix
```

### Step 3 — Reset credentials

Run `Invoke-CredFileReset.ps1` **from the orchestrating machine**:

```powershell
# Interactive — prompted for credentials, select components via menu
.\Invoke-CredFileReset.ps1 -PVWAURL 'https://pvwa.lab.local/PasswordVault'

# Non-interactive — reset all CPM servers in serial
$cred = Get-Credential
.\Invoke-CredFileReset.ps1 -PVWAURL 'https://pvwa.lab.local/PasswordVault' `
    -PVWACredentials $cred -ComponentType CPM -AllServers

# Parallel reset from Remote SSH (must supply explicit WinRM credentials)
$pvwaCred   = Get-Credential -Message 'PVWA credentials'
$remoteCred = Get-Credential -Message 'WinRM credentials (use DOMAIN\user)'
.\Invoke-CredFileReset.ps1 -PVWAURL 'https://pvwa.lab.local/PasswordVault' `
    -PVWACredentials $pvwaCred -RemoteCredential $remoteCred -Jobs

# Reset only disconnected components using a pre-existing logon token
.\Invoke-CredFileReset.ps1 -PVWAURL 'https://pvwa.lab.local/PasswordVault' `
    -LogonToken $token -DisconnectedOnly
```

---

## Invoke-CredFileReset.ps1 Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `PVWAURL` | Yes | PVWA base URL. Example: `https://pvwa.lab.local/PasswordVault` |
| `AuthType` | No | Authentication type: `cyberark` (default), `ldap`, `radius` |
| `OTP` | No | RADIUS one-time password. Only valid with `-AuthType radius` |
| `PVWACredentials` | No | PSCredential for PVWA REST API. Prompted if not provided |
| `LogonToken` | No | Pre-existing PVWA logon token (string or header hashtable) |
| `DisableSSLVerify` | No | Disable SSL certificate validation (NOT recommended) |
| `Jobs` | No | Process component servers in parallel using background jobs |
| `AllComponentTypes` | No | Process all component types without prompting |
| `AllServers` | No | Process all servers of the selected type without prompting |
| `DisconnectedOnly` | No | Only process servers currently disconnected from the Vault |
| `ConnectedOnly` | No | Only process servers currently connected to the Vault |
| `targetServer` | No | Process only this server (IP or hostname) |
| `ComponentType` | No | Process only this type: `CPM`, `PSM`, `PVWA`, `CP`, `AAM Credential Provider`, `PSM/PSMP` |
| `ComponentUsers` | No | Comma-separated list of specific component usernames to process |
| `ComponentUserFilter` | No | Wildcard filter for component usernames (e.g. `PasswordManager*`) |
| `MapFile` | No | Path to a CSV file that overrides IP, type, or OS per component user |
| `OldDomain` | No | Domain suffix to replace in resolved FQDNs (used with `-NewDomain`) |
| `newDomain` | No | Replacement domain suffix (used with `-OldDomain`) |
| `vaultAddress` | No | New Vault address to write into the component's `vault.ini` file |
| `apiAddress` | No | New API/DR Vault address to write into the component's `vault.ini` file |
| `RemoteCredential` | No | PSCredential for WinRM connections. Required from Remote SSH sessions |
| `WinRMUseSSL` | No | Require HTTPS (port 5986) for all WinRM connections. Default: try SSL first, fall back to HTTP |
| `WinRMUseNonSSL` | No | Force HTTP (port 5985) for all WinRM connections. Skips the SSL attempt entirely |
| `ShowLogs` | No | After each serial reset, open a fresh WinRM session and display the component log tail |
| `LogTail` | No | Number of log lines to display when `-ShowLogs` is used. Default: `30` |
| `LogName` | No | Log file name to display when `-ShowLogs` is used, or `All` for every log defined for the component type. Default: `All`. PSM: `PSMConsole.log`, `PSMTrace.log`. CPM: `PMConsole.log`, `PMTrace.log`, `pm.log`, `pm_error.log`, `CACPMScanner.log`, `Casos.Activity.log`, `Casos.Debug.log`, `Casos.Error.log`. PVWA: `CyberArk.WebApplication.log`, `CyberArk.WebTasksEngine.log`, `PVWA.App.Log`, `Cyberark.Reports.log`, `CyberArk.WebConsole.log`, `CyberArk.WebTasksService.log`. AIM: `APPConsole.log`, `APPTrace.log`, `APPAudit.log` |
| `Tries` | No | Maximum service-start attempts after reset. Default: `5` |

### Get-Help

```powershell
Get-Help .\Invoke-CredFileReset.ps1 -Full
Get-Help .\Get-CyberArkComponentLog.ps1 -Full
Get-Help .\Test-RemoteConnectivity.ps1 -Full
Get-Help .\Test-WinRMConfiguration.ps1 -Full
```

---

## Get-CyberArkComponentLog.ps1 Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `ComputerName` | Yes | One or more remote server hostnames or IP addresses. Only the first is used with `-Follow` |
| `ComponentType` | No | CyberArk component type: `PSM`, `CPM`, `PVWA`, `AIM`. If omitted, all installed components are auto-detected |
| `LogName` | No | Log file name to retrieve, or `All` for every log defined for the component type. Default: `All`. Tab-completes to logs valid for the selected `-ComponentType`. PSM: `PSMConsole.log`, `PSMTrace.log`. CPM: `PMConsole.log`, `PMTrace.log`, `pm.log`, `pm_error.log`, `CACPMScanner.log`, `Casos.Activity.log`, `Casos.Debug.log`, `Casos.Error.log`. PVWA: `CyberArk.WebApplication.log`, `CyberArk.WebTasksEngine.log`, `PVWA.App.Log`, `Cyberark.Reports.log`, `CyberArk.WebConsole.log`, `CyberArk.WebTasksService.log`. AIM: `APPConsole.log`, `APPTrace.log`, `APPAudit.log` |
| `Tail` | No | Number of lines from the end of each log to display. Default: `50` |
| `Follow` | No | Stream log entries in real time (equivalent to `tail -f`). Single server and single log only. Press Ctrl+C to stop |
| `Credential` | No | PSCredential for WinRM authentication. If omitted, implicit Kerberos is used |
| `WinRMUseSSL` | No | Force HTTPS (port 5986) for all WinRM connections. Cannot combine with `-WinRMUseNonSSL` |
| `WinRMUseNonSSL` | No | Force HTTP (port 5985) for all WinRM connections. Skips the SSL attempt. Cannot combine with `-WinRMUseSSL` |

### Examples

```powershell
# View the last 100 lines of the PSM console log
.\Get-CyberArkComponentLog.ps1 -ComputerName PSM-01.lab.local -ComponentType PSM -Tail 100

# View all logs for a CPM server
.\Get-CyberArkComponentLog.ps1 -ComputerName CPM-01.lab.local -ComponentType CPM -LogName All -Tail 30

# Live-follow the PSM console log from a Remote SSH session
$cred = Get-Credential
.\Get-CyberArkComponentLog.ps1 -ComputerName PSM-01.lab.local -ComponentType PSM `
    -LogName PSMConsole.log -Credential $cred -WinRMUseNonSSL -Follow

# Auto-detect all components on a server and show their logs
$cred = Get-Credential
.\Get-CyberArkComponentLog.ps1 -ComputerName 192.168.1.50 -Credential $cred -WinRMUseNonSSL
```

---

## map.csv — Component Override File

The `map.csv` file lets you override data returned by the PVWA System Health API — useful
when the PVWA reports wrong IP addresses, or to exclude components, or to correct component
type/OS classification.

**CSV columns:**

| Column | Description |
| --- | --- |
| `ComponentUser` | The component username as shown on the PVWA System Health page |
| `IP Address` | Override the IP address. Set to `255.255.255.255` to skip this component |
| `Component Type` | Override the component type (e.g. `CPM`, `PSM`) |
| `OS` | Override the OS: `Windows` or `Linux` |

Example `map.csv`:

```csv
ComponentUser,IP Address,Component Type,OS
PasswordManager_abc,10.0.1.50,CPM,Windows
PSMApp_xyz,255.255.255.255,,
PSMPApp_linux01,,PSM,Linux
```

Privilege Cloud environments typically require a `map.csv` because the PVWA System Health
page does not expose component IP addresses directly.

---

## WinRM Authentication Notes

- **SSL (HTTPS, port 5986) — default behaviour:** The script tries HTTPS first on every connection.
  HTTPS uses server certificate authentication, so `TrustedHosts` is **not required** regardless of
  account type. Component servers with a WinRM HTTPS listener will always connect securely.
- **HTTP fallback (port 5985):** If no HTTPS listener is found and `-WinRMUseSSL` is not set, the
  script falls back to HTTP. HTTP with explicit credentials (`-RemoteCredential`) requires the target
  to be in `TrustedHosts` on the orchestrating machine.
- **`-WinRMUseSSL`:** Prevents HTTP fallback. The connection fails if the target has no HTTPS listener.
  Use this to enforce encryption across the entire run.
- **Domain accounts (Kerberos):** No `TrustedHosts` needed on HTTP either. Use a domain account
  in `-RemoteCredential` when running from a Remote SSH session (SSH cannot delegate Kerberos
  tickets, so an explicit credential is required).
- **Local accounts (NTLM):** On HTTP connections, require the target to be added to `TrustedHosts`.
  Use `Test-RemoteConnectivity.ps1 -Fix` to add entries, or prefer SSL to avoid this entirely.
- **PVWA self-protection:** When the PVWA's own component user is included in the reset scope,
  the script automatically skips the PVWA to prevent locking out the REST API session in use.


## Resetting passwords in the vault only

Run `Invoke-ComponentUserPasswordReset.ps1` **from the orchestrating machine**:

```powershell
# Non-interactive — reset all CP component users in the vault (in series)
$cred = Get-Credential
.\Invoke-ComponentUserPasswordReset.ps1 -PVWAURL 'https://pvwa.lab.local/PasswordVault' `
    -PVWACredentials $cred -ComponentType CP -AllServers
# Reset only disconnected components passwords using a pre-existing logon token, cannot be installeruser in privilegecloud
.\Invoke-ComponentUserPasswordReset.ps1 -PVWAURL 'https://pvwa.lab.local/PasswordVault' `
    -LogonToken $token -DisconnectedOnly
```

Provide admins to reset the password using createcredfile on their local CPs (as you cannot access them with your credentials remotely). 
