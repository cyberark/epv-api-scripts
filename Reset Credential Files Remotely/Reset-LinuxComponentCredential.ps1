<#
.SYNOPSIS
    Helper script providing SSH-based remote-execution functions for CyberArk PSMP credential resets on Linux.

.DESCRIPTION
    This script is NOT intended to be run directly. It is consumed by Invoke-CredFileReset.ps1
    and provides the Linux/PSMP side of credential file reset operations.

    Unlike Reset-WinComponentCredential.ps1, this script does NOT run inside a PSSession.
    All functions here execute on the orchestrating machine and issue SSH commands to the
    target Linux server. Two SSH transports are supported:

      - ssh.exe  (Windows OpenSSH client) — used for key-based authentication
      - plink.exe (PuTTY)                 — used for username/password authentication

    CyberArk PSMP components supported:
      PSMP          — /opt/CARKpsmp      (psmpappuser.cred, psmpgwuser.cred)
      PSMPADBridge  — /opt/CARKpsmpadb  (psmpadbridgeserveruser.cred)

    Service control commands vary by OS family:
      RHEL7 / SUSE11 / SUSE12 (Legacy):
          service psmpsrv {start|stop|restart|status} [psmp|psmpadb]
      RHEL8+ (Systemd):
          systemctl {start|stop|restart|status} psmpsrv[-psmpserver|-psmpadbserver]

    Source: https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/administrating-the-psmp.htm

    Functions provided:
      Invoke-SSHCommand           — Executes a command on a remote Linux host via ssh.exe or plink.exe
      Get-LinuxOSFamily           — Detects whether the remote host is Systemd (RHEL8+) or Legacy (RHEL7/SUSE)
      Find-LinuxComponents        — Discovers installed CyberArk PSMP components via SSH
      Start-LinuxComponentService — Starts a PSMP service on a remote Linux host via SSH
      Stop-LinuxComponentService  — Stops a PSMP service on a remote Linux host via SSH
      Reset-LinuxCredFile         — Resets PSMP credential files on a Linux host via SSH
      Reset-LinuxVaultFile        — Updates vault.ini / apiAddress on a Linux host via SSH

.NOTES
    Version:    0.1 (stub — not yet implemented)
    Authors:    Brian Bors <brian.bors@cyberark.com>

    Requires:   PowerShell 5.1+
                ssh.exe  (Windows OpenSSH Client feature) for key-based auth
                plink.exe (PuTTY) for username/password auth

    Change Log:
    2026-03-27  Initial stub created — implementation pending (see LINUX-SUPPORT-PLAN.md)
#>

#Requires -Version 5.1

#region Component Definitions

# CreateCredFile command templates.
#   {0} = CyberArk username (read from existing cred file via grep)
#   {1} = new plaintext password
#
# Service command sets keyed by OS family:
#   Legacy  = RHEL7 / SUSE11 / SUSE12  (SysV-style 'service' wrapper)
#   Systemd = RHEL8+                    (native systemctl)
#
# Source: https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/administrating-the-psmp.htm
$Script:LinuxComponentDefs = @{

    PSMP = @{
        InstallPath   = '/opt/CARKpsmp'
        CredFilePath  = '/etc/opt/CARKpsmp/vault'
        BinaryPath    = '/opt/CARKpsmp/bin/psmpserver'
        CreateCredBin = '/opt/CARKpsmp/bin/createcredfile'
        CredFiles     = @(
            @{
                CredFile      = 'psmpappuser.cred'
                ComponentName = 'PSMP Application User'
                # {0} = username, {1} = password
                CreateCredCmd = '/opt/CARKpsmp/bin/createcredfile /etc/opt/CARKpsmp/vault/psmpappuser.cred Password -Username {0} -Password {1} -OSUsername root -AppType PSMPApp -ExePath /opt/CARKpsmp/bin/psmpserver -EntropyFile'
            },
            @{
                CredFile      = 'psmpgwuser.cred'
                ComponentName = 'PSMP Gateway User'
                CreateCredCmd = '/opt/CARKpsmp/bin/createcredfile /etc/opt/CARKpsmp/vault/psmpgwuser.cred Password -Username {0} -Password {1} -OSUsername root -AppType PSMPApp -ExePath /opt/CARKpsmp/bin/psmpserver -EntropyFile'
            }
        )
        Service       = @{
            Legacy  = @{
                Start   = 'service psmpsrv start psmp'
                Stop    = 'service psmpsrv stop psmp'
                Restart = 'service psmpsrv restart psmp'
                Status  = 'service psmpsrv status psmp'
            }
            Systemd = @{
                Start   = 'systemctl start psmpsrv-psmpserver'
                Stop    = 'systemctl stop psmpsrv-psmpserver'
                Restart = 'systemctl restart psmpsrv-psmpserver'
                Status  = 'systemctl status psmpsrv-psmpserver'
            }
        }
    }

    PSMPADBridge = @{
        InstallPath   = '/opt/CARKpsmpadb'
        CredFilePath  = '/etc/opt/CARKpsmpadb/vault'
        BinaryPath    = '/opt/CARKpsmpadb/bin/psmpadbserver'
        CreateCredBin = '/opt/CARKpsmpadb/bin/createcredfile'
        CredFiles     = @(
            @{
                CredFile      = 'psmpadbridgeserveruser.cred'
                ComponentName = 'PSMP AD Bridge User'
                CreateCredCmd = '/opt/CARKpsmpadb/bin/createcredfile /etc/opt/CARKpsmpadb/vault/psmpadbridgeserveruser.cred Password -Username {0} -Password {1} -OSUsername root -AppType PSMPApp -ExePath /opt/CARKpsmpadb/bin/psmpadbserver -EntropyFile'
            }
        )
        Service       = @{
            Legacy  = @{
                Start   = 'service psmpsrv start psmpadb'
                Stop    = 'service psmpsrv stop psmpadb'
                Restart = 'service psmpsrv restart psmpadb'
                Status  = 'service psmpsrv status psmpadb'
            }
            Systemd = @{
                Start   = 'systemctl start psmpsrv-psmpadbserver'
                Stop    = 'systemctl stop psmpsrv-psmpadbserver'
                Restart = 'systemctl restart psmpsrv-psmpadbserver'
                Status  = 'systemctl status psmpsrv-psmpadbserver'
            }
        }
    }
}

#endregion

#region Functions

function Invoke-SSHCommand {
    <#
    .SYNOPSIS
        Executes a command on a remote Linux host via SSH.

    .DESCRIPTION
        Dispatches to either ssh.exe (key-based) or plink.exe (password-based) depending
        on whether a key file is provided. Returns command stdout as a string array.

        ssh.exe usage (key-based):
            ssh.exe -i <KeyFile> -o StrictHostKeyChecking=no <Username>@<Server> "<Command>"

        plink.exe usage (password-based):
            plink.exe -ssh -l <Username> -pw <Password> <Server> "<Command>"

    .PARAMETER Server
        Hostname or IP address of the target Linux server.

    .PARAMETER Username
        SSH username to connect as.

    .PARAMETER Command
        The shell command to execute on the remote host.

    .PARAMETER KeyFile
        Path to a private key file. When specified, ssh.exe is used.
        When omitted, plink.exe is used (PlinkPath and Password required).

    .PARAMETER Password
        Plaintext password for plink.exe authentication. Only used when KeyFile is not set.

    .PARAMETER PlinkPath
        Full path to plink.exe. Required when KeyFile is not specified.

    .OUTPUTS
        [string[]] — Lines of stdout from the remote command.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $false)]
        [string]$KeyFile,

        [Parameter(Mandatory = $false)]
        [string]$Password,

        [Parameter(Mandatory = $false)]
        [string]$PlinkPath
    )

    # TODO: Implement SSH transport
    throw [System.NotImplementedException]::new('Invoke-SSHCommand is not yet implemented. See LINUX-SUPPORT-PLAN.md.')
}

function Get-LinuxOSFamily {
    <#
    .SYNOPSIS
        Detects whether the target Linux host uses systemd (RHEL8+) or legacy SysV service control.

    .DESCRIPTION
        Reads /etc/os-release via SSH and checks the VERSION_ID field.
        Returns 'Systemd' for RHEL8+ and 'Legacy' for RHEL7 / SUSE11 / SUSE12.

        This determines which key in $Script:LinuxComponentDefs[*].Service to use:
          - 'Systemd' -> systemctl start/stop psmpsrv-psmpserver (RHEL8)
          - 'Legacy'  -> service psmpsrv start/stop psmp         (RHEL7, SUSE11, SUSE12)

    .PARAMETER Server
        Hostname or IP address of the target Linux server.

    .PARAMETER Username
        SSH username.

    .PARAMETER KeyFile
        Optional private key file path (key-based auth).

    .PARAMETER Password
        Plaintext password for plink.exe auth. Used when KeyFile is omitted.

    .PARAMETER PlinkPath
        Full path to plink.exe. Required when KeyFile is not specified.

    .OUTPUTS
        [string] — 'Systemd' or 'Legacy'
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $false)]
        [string]$KeyFile,

        [Parameter(Mandatory = $false)]
        [string]$Password,

        [Parameter(Mandatory = $false)]
        [string]$PlinkPath
    )

    # TODO: Run 'grep VERSION_ID /etc/os-release' via Invoke-SSHCommand, parse result,
    #       return 'Systemd' if RHEL >= 8, else 'Legacy'
    throw [System.NotImplementedException]::new('Get-LinuxOSFamily is not yet implemented. See LINUX-SUPPORT-PLAN.md.')
}

function Find-LinuxComponents {
    <#
    .SYNOPSIS
        Discovers installed CyberArk PSMP components on a remote Linux host via SSH.

    .DESCRIPTION
        Checks for the presence of the install path and binary for each component defined
        in $Script:LinuxComponentDefs via 'test -d' and 'test -f' over SSH.
        Returns objects matching the shape of Find-WinComponents for uniform handling.

    .PARAMETER Server
        Hostname or IP address of the target Linux server.

    .PARAMETER Username
        SSH username.

    .PARAMETER KeyFile
        Optional private key file path (key-based auth).

    .PARAMETER Password
        Plaintext password for plink.exe auth. Used when KeyFile is omitted.

    .PARAMETER PlinkPath
        Full path to plink.exe. Required when KeyFile is not specified.

    .OUTPUTS
        [PSCustomObject[]] — Objects with Name, Path, and Version properties.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $false)]
        [string]$KeyFile,

        [Parameter(Mandatory = $false)]
        [string]$Password,

        [Parameter(Mandatory = $false)]
        [string]$PlinkPath
    )

    # TODO: For each key in $Script:LinuxComponentDefs, test-d InstallPath via SSH.
    #       Retrieve version from binary --version or rpm -q output.
    #       Return PSCustomObject @{ Name = ...; Path = ...; Version = ... }
    throw [System.NotImplementedException]::new('Find-LinuxComponents is not yet implemented. See LINUX-SUPPORT-PLAN.md.')
}

function Start-LinuxComponentService {
    <#
    .SYNOPSIS
        Starts a PSMP service on a remote Linux host via SSH.

    .DESCRIPTION
        Selects the correct start command for the component from $Script:LinuxComponentDefs
        based on the OS family returned by Get-LinuxOSFamily, then executes it over SSH.

    .PARAMETER Server
        Hostname or IP address of the target Linux server.

    .PARAMETER ComponentName
        The component key from $Script:LinuxComponentDefs (e.g. 'PSMP' or 'PSMPADBridge').

    .PARAMETER Username
        SSH username.

    .PARAMETER OSFamily
        'Systemd' or 'Legacy' as returned by Get-LinuxOSFamily.

    .PARAMETER KeyFile
        Optional private key file path (key-based auth).

    .PARAMETER Password
        Plaintext password for plink.exe auth. Used when KeyFile is omitted.

    .PARAMETER PlinkPath
        Full path to plink.exe. Required when KeyFile is not specified.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [ValidateSet('PSMP', 'PSMPADBridge')]
        [string]$ComponentName,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Systemd', 'Legacy')]
        [string]$OSFamily,

        [Parameter(Mandatory = $false)]
        [string]$KeyFile,

        [Parameter(Mandatory = $false)]
        [string]$Password,

        [Parameter(Mandatory = $false)]
        [string]$PlinkPath
    )

    # TODO: $cmd = $Script:LinuxComponentDefs[$ComponentName].Service[$OSFamily].Start
    #       Invoke-SSHCommand ... -Command $cmd
    throw [System.NotImplementedException]::new('Start-LinuxComponentService is not yet implemented. See LINUX-SUPPORT-PLAN.md.')
}

function Stop-LinuxComponentService {
    <#
    .SYNOPSIS
        Stops a PSMP service on a remote Linux host via SSH.

    .DESCRIPTION
        Selects the correct stop command for the component from $Script:LinuxComponentDefs
        based on the OS family returned by Get-LinuxOSFamily, then executes it over SSH.

    .PARAMETER Server
        Hostname or IP address of the target Linux server.

    .PARAMETER ComponentName
        The component key from $Script:LinuxComponentDefs (e.g. 'PSMP' or 'PSMPADBridge').

    .PARAMETER Username
        SSH username.

    .PARAMETER OSFamily
        'Systemd' or 'Legacy' as returned by Get-LinuxOSFamily.

    .PARAMETER KeyFile
        Optional private key file path (key-based auth).

    .PARAMETER Password
        Plaintext password for plink.exe auth. Used when KeyFile is omitted.

    .PARAMETER PlinkPath
        Full path to plink.exe. Required when KeyFile is not specified.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [ValidateSet('PSMP', 'PSMPADBridge')]
        [string]$ComponentName,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Systemd', 'Legacy')]
        [string]$OSFamily,

        [Parameter(Mandatory = $false)]
        [string]$KeyFile,

        [Parameter(Mandatory = $false)]
        [string]$Password,

        [Parameter(Mandatory = $false)]
        [string]$PlinkPath
    )

    # TODO: $cmd = $Script:LinuxComponentDefs[$ComponentName].Service[$OSFamily].Stop
    #       Invoke-SSHCommand ... -Command $cmd
    throw [System.NotImplementedException]::new('Stop-LinuxComponentService is not yet implemented. See LINUX-SUPPORT-PLAN.md.')
}

function Reset-LinuxCredFile {
    <#
    .SYNOPSIS
        Resets PSMP credential files on a remote Linux host via SSH.

    .DESCRIPTION
        For each credential file defined in $Script:LinuxComponentDefs[$ComponentName].CredFiles:
          1. Reads the current username from the cred file via:
                grep 'Username=' <credfile>
          2. Generates a new random password (New-RandomPassword).
          3. Backs up the existing cred file and entropy file with a Unix timestamp suffix.
          4. Runs the CreateCredFile command template with:
                $cmd = $def.CreateCredCmd -f $username, $newPassword
          5. On failure, restores the backup.
          6. On success, removes the backup and updates the Vault user via Set-UserPassword.

    .PARAMETER Server
        Hostname or IP address of the target Linux server.

    .PARAMETER CompInfo
        Component information object (Name, Path, Version) as returned by Find-LinuxComponents.

    .PARAMETER Username
        SSH username to connect as.

    .PARAMETER OSFamily
        'Systemd' or 'Legacy' as returned by Get-LinuxOSFamily.

    .PARAMETER KeyFile
        Optional private key file path (key-based auth).

    .PARAMETER Password
        Plaintext password for plink.exe auth. Used when KeyFile is omitted.

    .PARAMETER PlinkPath
        Full path to plink.exe. Required when KeyFile is not specified.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$CompInfo,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Systemd', 'Legacy')]
        [string]$OSFamily,

        [Parameter(Mandatory = $false)]
        [string]$KeyFile,

        [Parameter(Mandatory = $false)]
        [string]$Password,

        [Parameter(Mandatory = $false)]
        [string]$PlinkPath
    )

    # TODO: Implement PSMP credential file reset over SSH.
    #       See .DESCRIPTION above for step-by-step logic.
    #       Reference $Script:LinuxComponentDefs[$CompInfo.Name].CredFiles for templates.
    throw [System.NotImplementedException]::new('Reset-LinuxCredFile is not yet implemented. See LINUX-SUPPORT-PLAN.md.')
}

function Reset-LinuxVaultFile {
    <#
    .SYNOPSIS
        Updates vault.ini / apiAddress on a remote Linux PSMP host via SSH.

    .DESCRIPTION
        Connects to the target Linux server, backs up the existing vault.ini with a Unix
        timestamp suffix, then uses sed to update the ADDRESS= and/or APIURL= lines.

        Vault.ini locations:
          PSMP:         /etc/opt/CARKpsmp/vault/vault.ini
          PSMPADBridge: /etc/opt/CARKpsmpadb/vault/vault.ini

    .PARAMETER Server
        Hostname or IP address of the target Linux server.

    .PARAMETER CompInfo
        Component information object (Name, Path, Version) as returned by Find-LinuxComponents.

    .PARAMETER Username
        SSH username to connect as.

    .PARAMETER VaultAddress
        New Vault IP/hostname to write into vault.ini (ADDRESS= line). Optional.

    .PARAMETER ApiAddress
        New PVWA/API URL to write into vault.ini (APIURL= line). Optional.

    .PARAMETER KeyFile
        Optional private key file path (key-based auth).

    .PARAMETER Password
        Plaintext password for plink.exe auth. Used when KeyFile is omitted.

    .PARAMETER PlinkPath
        Full path to plink.exe. Required when KeyFile is not specified.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$CompInfo,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $false)]
        [string]$VaultAddress,

        [Parameter(Mandatory = $false)]
        [string]$ApiAddress,

        [Parameter(Mandatory = $false)]
        [string]$KeyFile,

        [Parameter(Mandatory = $false)]
        [string]$Password,

        [Parameter(Mandatory = $false)]
        [string]$PlinkPath
    )

    # TODO: Implement PSMP vault.ini update over SSH using sed.
    #       Back up vault.ini before modifying.
    #       Reference $Script:LinuxComponentDefs[$CompInfo.Name].CredFilePath for path.
    throw [System.NotImplementedException]::new('Reset-LinuxVaultFile is not yet implemented. See LINUX-SUPPORT-PLAN.md.')
}

#endregion
