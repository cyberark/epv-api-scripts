# Reset Credential Files Remotely

Remotely regenerates CyberArk component credential files and synchronises the new password
in the Vault — without requiring an operator to log on to each component server manually.

> **Note:** `map.csv` contains example data only and does not represent real components.

---

## Scripts

| Script | Purpose | Run on |
| --- | --- | --- |
| `Invoke-CredFileReset.ps1` | **Main script** — orchestrates credential resets across component servers | Orchestrating machine |
| `Reset-ComponentCredential.ps1` | Helper functions loaded into remote PSSessions (not run directly) | Loaded automatically |
| `Test-RemoteConnectivity.ps1` | Pre-flight check — tests WinRM connectivity from orchestrating machine to targets | Orchestrating machine |
| `Test-WinRMConfiguration.ps1` | Diagnoses WinRM configuration on a component server | Target server (locally) |

---

## Requirements

- PowerShell 5.1 or later on the orchestrating machine
- WinRM (TCP 5985) access from the orchestrating machine to each component server
- CyberArk Vault Administrator or equivalent REST API permissions on the PVWA
- Local Administrator rights on each component server (via WinRM)
- `Invoke-CredFileReset.ps1` and `Reset-ComponentCredential.ps1` must be in the same directory

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
| `NewDomain` | No | Replacement domain suffix (used with `-OldDomain`) |
| `VaultAddress` | No | New Vault address to write into the component's `vault.ini` |
| `ApiAddress` | No | New API/DR Vault address to write into the component's `vault.ini` |
| `RemoteCredential` | No | PSCredential for WinRM connections. Required from Remote SSH sessions |
| `Tries` | No | Maximum service-start attempts after reset. Default: `5` |

### Get-Help

```powershell
Get-Help .\Invoke-CredFileReset.ps1 -Full
Get-Help .\Test-RemoteConnectivity.ps1 -Full
Get-Help .\Test-WinRMConfiguration.ps1 -Full
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

- **Domain accounts (Kerberos):** No `TrustedHosts` configuration needed. Use a domain account
  in `-RemoteCredential` when running from a Remote SSH session (SSH cannot delegate Kerberos
  tickets, so an explicit credential is required).
- **Local accounts (NTLM):** Require the target to be added to `TrustedHosts` on the
  orchestrating machine. Use `Test-RemoteConnectivity.ps1 -Fix` to add entries.
- **PVWA self-protection:** When the PVWA's own component user is included in the reset scope,
  the script automatically skips the PVWA to prevent locking out the REST API session in use.
