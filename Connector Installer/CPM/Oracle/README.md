# Oracle Instant Client Manager

[Manage-OracleInstantClient.ps1](./Manage-OracleInstantClient.ps1) installs, verifies, configures, and removes Oracle Instant Client for CyberArk CPM or Privilege Cloud Secrets Rotation Service (SRS).

It supports Oracle Instant Client **19, 21, and 23**, separate Windows architecture folders, offline packages, existing-install reuse, and controlled removal.

> Validate installation and connectivity on your target CPM/SRS connector before production use. Setup verification is not a database connectivity test.

## Requirements and defaults

- Windows with PowerShell **5.1 or later** and the Windows ODBC cmdlets.
- An elevated PowerShell session for full setup, full-readiness prechecks, installation, configuration, permissions, and removal.
- A writable local destination, or a writable existing parent from which it can be created. Default: `C:\Oracle\`. A missing destination requires confirmation unless `-CreateDestination` is supplied.
- The matching Microsoft Visual C++ v14 runtime for installation/full-readiness checks. Keep it current according to Oracle's requirements.
- Internet access to Oracle for downloads, or trusted local ZIPs.
- Existing service principals for full setup, `-PreCheckOnly`, and `-PermissionsOnly`. The script does not create users or services.

| Setting | Default | Options |
|---|---|---|
| `-Version` | `19` | `19`, `21`, `23` |
| `-Architecture` | `64` | `32`, `64`, or `32,64` |
| `-PermissionSet` | `SRS` | `SRS`, `CPM` |
| `-Destination` | `C:\Oracle\` | Absolute local drive folder |

Version **23 supports 64-bit Windows only**. Select the architecture required by your CyberArk plugin; the 64-bit default does not imply that every CPM plugin supports it.

| Permission set | Selected principals |
|---|---|
| SRS | Local `SRSExecutionUser`, `NT SERVICE\IdiraManagementAgent` |
| CPM | Local `PluginManagerUser`, local `PasswordManagerUser` |

## Quick start

Run from an elevated PowerShell session. If the destination is needed and missing, the script asks before creating it:

```powershell
.\Manage-OracleInstantClient.ps1
```

To approve destination creation without prompting:

```powershell
.\Manage-OracleInstantClient.ps1 -Destination 'C:\Oracle' -CreateDestination
```

`-CreateDestination` approves only creating the missing destination and its missing parents.
It does not approve existing-install reuse, package overwrites, or removal. Existing destination
folders are not replaced. Parent access, path safety, disk space, and other prechecks still apply.
Creation occurs only after successful prechecks and any existing-install reuse approval.
`-PreCheckOnly` reports creation readiness without creating folders; missing required ZIPs
still fail package checks. Verification, permissions-only, and removal never create Destination.
The same option is available for DownloadOnly, ExtractOnly, and ConfigureOnly.
TNS_ADMIN creation remains part of Configure when its machine variable is unset.

With **no operation switch**, the script runs the full workflow:

```text
Discover existing drivers
  -> PreCheck
  -> Download missing clients' packages
  -> Validate packages
  -> Extract
  -> Install
  -> VerifyInstallation
  -> Configure TNS_ADMIN
  -> Permissions
  -> Completion checks and platform settings
```

Local package parameters skip downloading. Approved matching existing installations skip downloading, extracting, and installing for their architectures.

### CPM example

```powershell
.\Manage-OracleInstantClient.ps1 -Version 19 -Architecture 32 -PermissionSet CPM
```

### Version 23 example

```powershell
.\Manage-OracleInstantClient.ps1 -Version 23 -Architecture 64 -PermissionSet SRS
```

## Individual stages

Operation switches are mutually exclusive. Every invocation performs the checks relevant to its operation. A standalone stage checks its prerequisites; it does **not** silently execute earlier stages.

| Switch | Behavior | Main prerequisites |
|---|---|---|
| `-DownloadOnly` | Download and validate ZIPs | Writable destination; internet; overwrite approval if files exist |
| `-PreCheckOnly` | Check full-workflow readiness, then exit without changes | Elevation; selected principals; runtime; local ZIPs or valid registered clients |
| `-ExtractOnly` | Validate ZIPs and extract them | Writable destination; valid local packages; extraction target not registered |
| `-InstallOnly` | Install from extracted standard folders, then verify registration | Elevation; runtime; extracted files, or approved valid existing clients |
| `-VerifyInstallationOnly` | Verify selected registered clients without changes | Matching registrations and required client files |
| `-ConfigureOnly` | Verify clients and configure TNS_ADMIN; no ACL changes | Elevation; valid clients; valid existing TNS_ADMIN or writable destination for a new folder |
| `-PermissionsOnly` | Grant and verify all client/TNS_ADMIN permissions | Elevation; selected principals; valid clients; existing TNS_ADMIN folder |

`-PreCheckOnly` requires packages to be present for architectures without an existing installation. To prepare packages on another machine, use `-DownloadOnly` first.

```powershell
.\Manage-OracleInstantClient.ps1 -PreCheckOnly
.\Manage-OracleInstantClient.ps1 -VerifyInstallationOnly
```

For separate configuration and permission operations:

```powershell
.\Manage-OracleInstantClient.ps1 -ConfigureOnly -UseExistingInstallation
.\Manage-OracleInstantClient.ps1 -PermissionsOnly -UseExistingInstallation
```

## Offline installation and alternate filenames

Download on an internet-connected machine:

```powershell
.\Manage-OracleInstantClient.ps1 -DownloadOnly -Destination 'C:\Oracle' -Version 19 -Architecture 64
```

Copy the script and ZIPs to the connector. DownloadOnly prints an offline setup command using the downloaded filenames.

For alternate local filenames:

```powershell
$setup = @{
    Destination = 'C:\Oracle'
    BasicFile = 'basic.zip'
    SqlPlusFile = 'sqlplus.zip'
    OdbcFile = 'odbc.zip'
}
.\Manage-OracleInstantClient.ps1 @setup
```

- Supply **all three** parameters together.
- Filenames must refer to ZIPs directly inside Destination, not paths.
- `-BasicFile` accepts BasicLite or Basic packages.
- Names must be distinct across packages and architectures.
- Contents must match the configured client folder, package type, and architecture. Renaming a ZIP does not select a different release.
- Local-file parameters work with full setup, PreCheckOnly, ExtractOnly, CleanupOnly, or UninstallAndCleanup.
- Parameter sets prohibit local files with DownloadOnly, InstallOnly, VerifyInstallationOnly, ConfigureOnly, or PermissionsOnly.

For two architectures, filenames follow the order supplied to `-Architecture`:

```powershell
$setup = @{
    Architecture = @('32', '64')
    BasicFile = @('basic32.zip', 'basic64.zip')
    SqlPlusFile = @('sqlplus32.zip', 'sqlplus64.zip')
    OdbcFile = @('odbc32.zip', 'odbc64.zip')
}
.\Manage-OracleInstantClient.ps1 @setup
```

Default extraction locations:

```text
C:\Oracle\
  32-bit\instantclient_<configured_version>\
  64-bit\instantclient_<configured_version>\
  TNS_ADMIN\
```

## Existing installations and confirmations

The script queries **both 32-bit and 64-bit ODBC registrations** and reads each selected registration's DLL path. It does not scan all drives.

- Matching clients may reside outside Destination.
- Matching clients are checked for required files and PE architecture before reuse.
- A different Oracle release is reported, not silently substituted.
- A broken selected installation stops the operation with guidance.
- With both architectures requested, approved valid clients are reused and only missing architectures are installed.
- Unregistered copied client folders cannot be discovered through ODBC registrations.

For operations that reuse an installation, the script warns with discovered locations and requests confirmation to **continue or stop** before downloads or configuration changes.

Existing target ZIPs similarly require approval to **overwrite**, not silently reuse. The script checks all target filenames before starting downloads.

| Approval parameter | Authorizes | Does not authorize |
|---|---|---|
| `-UseExistingInstallation` | Reusing matching registered installations without prompting | Skipping validation, overwriting ZIPs, removal |
| `-OverwritePackages` | Overwriting target ZIPs during download without prompting | Skipping package validation, removal |
| `-CreateDestination` | Creating a needed, missing destination without prompting | Skipping prechecks, existing-install reuse, ZIP overwrites, removal |
| `-ForceRemoval` | Selected removal operation without prompting | Bypassing path/registration checks |

Confirmations default to **Stop**. If prompting is unavailable, a required confirmation fails unless its specific approval parameter is supplied. Read-only discovery does not require reuse approval.

```powershell
.\Manage-OracleInstantClient.ps1 -UseExistingInstallation -OverwritePackages
```

`-WhatIf` is **not supported**. Approval parameters should only be used after reviewing their scope.

## TNS_ADMIN and permissions

The machine-level `TNS_ADMIN` value is handled separately from registered client locations:

| State | Behavior |
|---|---|
| Set to an existing accessible folder | Reuse it; preserve the environment value and files |
| Unset | Configure creates `Destination\TNS_ADMIN` and sets the machine variable |
| Set to a missing or inaccessible folder | Stop; do not silently replace it |
| User/process value differs from machine | Warn; leave those scopes unchanged |

Drive/share roots and reparse-point paths are rejected for TNS_ADMIN to avoid overly broad or redirected permission changes.

The Permissions operation:

1. Checks elevation.
2. Checks both selected local users/services exist and resolves their SIDs.
3. Validates client and TNS_ADMIN folders and checks for conflicting explicit-principal deny rules.
4. Grants Traverse on required ancestors, excluding drive/share roots.
5. Grants inheritable ReadAndExecute on client folders and TNS_ADMIN.
6. Reads back and verifies the required explicit grants.

All ACLs are prepared before writes begin. Existing suitable grants are retained; unrelated ACL entries are preserved. An operating-system failure during writes can still leave partial changes, which are reported as an error.

Existing Oracle configuration files are not overwritten. Add `tnsnames.ora`, `sqlnet.ora`, or `oraaccess.xml` to the resolved TNS_ADMIN folder as needed.

The script reports Oracle-related PATH/ORACLE_HOME values but does not change them. Review PATH for the selected clients. Restart relevant services or reboot in an approved maintenance window to pick up machine environment changes; the script does not restart services.

## Uninstall and cleanup

Removal is never part of the default setup workflow.

| Switch | Result |
|---|---|
| `-UninstallAndCleanup` | Run Oracle's ODBC uninstaller, verify registration removal, then delete selected client folders and ZIPs |
| `-UninstallOnly` | Unregister selected ODBC drivers; leave files and configuration behind |
| `-CleanupOnly` | Delete selected unregistered client folders and ZIPs after a previous uninstall |

```powershell
# Unregister only
.\Manage-OracleInstantClient.ps1 -UninstallOnly

# Clean standard folders after uninstall
.\Manage-OracleInstantClient.ps1 -CleanupOnly

# Clean a client previously installed elsewhere
.\Manage-OracleInstantClient.ps1 -CleanupOnly -ClientPath 'D:\Oracle\instantclient_19_32'

# Combined operation, still prompting for approval
.\Manage-OracleInstantClient.ps1 -UninstallAndCleanup
```

For CleanupOnly, `-ClientPath` supplies exact client folders in Architecture order. Without it, cleanup uses the configured standard architecture folders. ODBC discovery cannot recover an installation path after its registration has been removed; UninstallOnly prints a suggested cleanup command.

Removal safeguards:

- Requires elevation and confirmation; `-ForceRemoval` bypasses the prompt only.
- Shows exact registration and deletion targets.
- Uses Oracle's `odbc_uninstall.exe` from the identified client directory.
- Reports affected System/current-user DSNs; does not delete them. Other users' DSNs may not be visible.
- Combined removal stops before cleanup if uninstall fails or registration remains.
- Checks registrations in both architectures before deleting any folder.
- Rejects broad/protected paths, reparse points, and client folders containing `.ora` configuration files.
- Never recursively deletes Destination itself.
- Preserves TNS_ADMIN, its environment values/files, unrelated installations, DSNs, and unrelated ACL/environment settings.
- Selects only the configured client-folder name and selected ZIP filenames. Use local-file parameters to target alternatively named ZIPs.

> An unregistered client may still be used by an application. The script cannot prove it is unused. Stop dependent applications/services and review every listed path before approving removal. Preserved DSNs and PATH/ORACLE_HOME entries may need explicit follow-up.

## Updating pinned Oracle releases

Current configuration:

| Major | Release filename suffix | URL directory | Expected client folder |
|---|---|---|---|
| 19 | `19.32.0.0.0dbru` | `1932000` | `instantclient_19_32` |
| 21 | `21.23.0.0.0dbru` | `2123000` | `instantclient_21_23` |
| 23 | `23.26.3.0.0` | `2326300` | `instantclient_23_26` |

Releases are pinned; future releases are **not automatically selected**.

1. Review Oracle's [Windows 32-bit downloads](https://www.oracle.com/database/technologies/instant-client/microsoft-windows-32-downloads.html) and [Windows x64 downloads](https://www.oracle.com/database/technologies/instant-client/winx64-64-downloads.html).
2. Locate Basic Light, SQL*Plus, and ODBC links for the desired release.
3. Update the corresponding `VersionConfig` entry in the script:
   - `Folder`: numeric URL directory immediately before the ZIP filename.
   - `Release`: complete filename suffix, including `dbru` where present.
   - `ClientFolder`: exact top-level directory inside the ZIP.
4. Confirm all packages share the expected release/folder. If architecture releases or naming conventions differ, update the configuration and URL construction explicitly.
5. Keep version-specific URLs; permanent latest links could change the requested major version.
6. Run DownloadOnly on a staging machine, inspect trusted packages, and validate installation/runtime/CyberArk compatibility on a target connector.
7. For a new major version, also update Version's ValidateSet, architecture restrictions, runtime assumptions, help, and examples. Change defaults only intentionally.

Example URL:

```text
https://download.oracle.com/otn_software/nt/instantclient/1932000/instantclient-basiclite-windows.x64-19.32.0.0.0dbru.zip
```

Both architectures use the `/nt/instantclient/` URL base. The package filename distinguishes `nt` (32-bit) from `windows.x64` (64-bit).

## Validation and limitations

- Package validation checks ZIP readability, expected paths, required package files, and PE architecture.
- Installed-client verification checks registrations, required files, and architecture.
- These checks do not verify Oracle download authenticity or guarantee every file matches the advertised patch release.
- Setup completion verifies registrations, machine TNS_ADMIN, and required explicit permission grants; it does not establish database connectivity or fully analyze group-based effective access.
- Test connectivity using the correct-architecture ODBC tools and the CyberArk plugin on the target connector.

For complete parameter help:

```powershell
Get-Help .\Manage-OracleInstantClient.ps1 -Full
```

The previous `Setup-OracleCPM.ps1` name was replaced without a compatibility wrapper. Earlier `-Stage` and `-Download` switches were replaced by `-DownloadOnly` and the default full workflow.

## References

- [CyberArk Oracle Database plugin](https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/oracledatabaseplugin.htm)
- [Oracle Instant Client](https://www.oracle.com/database/technologies/instant-client.html)
- [Oracle Windows 32-bit downloads](https://www.oracle.com/database/technologies/instant-client/microsoft-windows-32-downloads.html)
- [Oracle Windows x64 downloads](https://www.oracle.com/database/technologies/instant-client/winx64-64-downloads.html)
