#Requires -Version 5.1
<#
.SYNOPSIS
    Installs, configures, or removes Oracle Instant Client for CyberArk CPM/SRS.

.DESCRIPTION
    No operation switch runs the full workflow:
      Discover -> PreCheck -> Download (if needed) -> validate packages -> Extract ->
      Install -> VerifyInstallation -> Configure -> Permissions -> completion checks.

    Seven stages can also run individually. Every invocation performs operation-specific
    prechecks; a standalone stage validates its prerequisites without running earlier stages.
    Full-workflow and PreCheckOnly checks include the selected service principals.
    Permissions rechecks all principals and target folders before changing any ACL.

    Matching registered clients may be reused outside Destination after confirmation.
    For both architectures, only missing clients are downloaded/extracted/installed.
    An existing machine TNS_ADMIN folder is preserved and still receives permissions.
    Configuration files, unrelated ACLs, user-rights policies and PATH are not modified.

.PARAMETER Destination
    Local folder for ZIPs, architecture subfolders, and a new TNS_ADMIN folder.
    Default: C:\Oracle\. Existing registered clients and machine TNS_ADMIN may be elsewhere.
    If needed but missing, creation requires confirmation or CreateDestination. Read-only
    verification and removal do not require an otherwise unused Destination to exist.

.PARAMETER CreateDestination
    Approve creation of a missing Destination without prompting. Does not bypass path,
    parent access, disk-space, or other prechecks. Existing folders are left intact.
    PreCheckOnly reports planned creation but never creates folders.
    Only applies to full setup, DownloadOnly, ExtractOnly, ConfigureOnly, and PreCheckOnly.

.PARAMETER Version
    Pinned Oracle Instant Client major version: 19, 21 or 23. Default: 19.
    Release and expected archive folder are defined in VersionConfig below.
    Version 23 is available for 64-bit Windows only.

.PARAMETER Architecture
    '32', '64', or both. Default: 64. Choose the architecture required by your plugin.
    Each architecture is extracted into Destination\32-bit or Destination\64-bit.
    Duplicate architectures are rejected so local filename ordering stays unambiguous.

.PARAMETER PermissionSet
    SRS (default): local SRSExecutionUser and NT SERVICE\IdiraManagementAgent.
    CPM: local PluginManagerUser and PasswordManagerUser.
    No principals are created. All selected principals must resolve before ACL changes.

.PARAMETER BasicFile
    Local BasicLite or Basic ZIP filename under Destination; filenames only, not paths.
    Requires SqlPlusFile and OdbcFile. One filename per Architecture, in the same order.
    Enables offline full installation, PreCheckOnly, ExtractOnly, or removal of named ZIPs.
    Cannot be combined with DownloadOnly, InstallOnly, VerifyInstallationOnly,
    ConfigureOnly, or PermissionsOnly. ZIP contents must match the pinned client folder.

.PARAMETER SqlPlusFile
    Local SQL*Plus ZIP filename(s), in Architecture order. Requires BasicFile and OdbcFile.

.PARAMETER OdbcFile
    Local ODBC ZIP filename(s), in Architecture order. Requires BasicFile and SqlPlusFile.

.PARAMETER DownloadOnly
    Download and validate packages only. No elevation or service principals required.
    Existing target ZIPs require overwrite confirmation before any downloads begin.

.PARAMETER PreCheckOnly
    Check full-workflow readiness and local packages or registered clients, then exit.
    Read-only: no downloads, extraction, configuration, or permission changes.
    Requires elevation and selected principals, but does not require confirmation to inspect.

.PARAMETER ExtractOnly
    Validate local ZIPs and extract only. No service principals required.
    Refuses extraction into any registered client location.

.PARAMETER InstallOnly
    Install from the standard extracted architecture folders, then verify registration.
    Requires elevation and Visual C++ runtime; no service principals required.
    A valid existing installation requires confirmation to reuse, not reinstall.

.PARAMETER VerifyInstallationOnly
    Read-only verification of selected registered drivers and required client files.
    Reports discovered installations without requesting permission to inspect them.

.PARAMETER ConfigureOnly
    Verify clients, then reuse existing machine TNS_ADMIN or create/set it if unset.
    No ACL changes; no service principals required. Requires elevation.

.PARAMETER PermissionsOnly
    Verify clients and existing TNS_ADMIN, then grant client/TNS_ADMIN ReadAndExecute
    and ancestor Traverse permissions. Requires elevation and all selected principals.
    Does not create TNS_ADMIN or change environment variables.

.PARAMETER UseExistingInstallation
    Approve reuse of matching registered clients without prompting. Warnings still appear.
    Does not bypass file, architecture, registration, runtime, or principal validation.

.PARAMETER OverwritePackages
    Approve overwriting target ZIP files without prompting. Download operations only.
    Does not authorize uninstalling, file cleanup, or skipping package validation.

.PARAMETER UninstallOnly
    Unregister selected ODBC drivers with Oracle's odbc_uninstall.exe; leave files behind.
    Reports affected System/current-user DSNs but does not delete them.

.PARAMETER CleanupOnly
    Delete selected client folders and existing selected ZIPs after uninstalling.
    Refuses folders referenced by any ODBC registration, regardless of architecture.
    Standard client paths are used unless ClientPath is supplied.

.PARAMETER UninstallAndCleanup
    Unregister selected drivers, verify their removal, then clean up retained client paths
    and selected ZIPs. Never proceeds to cleanup if uninstallation fails.

.PARAMETER ClientPath
    Exact client folder(s) for CleanupOnly, in Architecture order. Required for clients
    previously installed outside the standard Destination architecture folders.
    The folder name must match the pinned ClientFolder and contain Oracle client files.

.PARAMETER ForceRemoval
    Bypass removal confirmation only. Does not bypass registration, path or dependency checks.
    With UninstallAndCleanup, the confirmation lists both registrations and deletion targets.

.EXAMPLE
    .\Manage-OracleInstantClient.ps1
    Full setup: version 19, 64-bit, SRS. Prompts before reuse or ZIP overwrites.

.EXAMPLE
    .\Manage-OracleInstantClient.ps1 -Version 23 -Architecture 64 -UseExistingInstallation -OverwritePackages
    Full setup with explicit approvals for existing clients and target ZIP overwrites.

.EXAMPLE
    .\Manage-OracleInstantClient.ps1 -DownloadOnly -Architecture 32,64
    Download only; copy the ZIPs and use the printed offline command on the connector.

.EXAMPLE
    .\Manage-OracleInstantClient.ps1 -BasicFile 'basic.zip' -SqlPlusFile 'sqlplus.zip' -OdbcFile 'odbc.zip'
    Full offline setup with alternate local filenames.

.EXAMPLE
    .\Manage-OracleInstantClient.ps1 -ExtractOnly -Architecture 32,64 -BasicFile 'basic32.zip','basic64.zip' -SqlPlusFile 'sqlplus32.zip','sqlplus64.zip' -OdbcFile 'odbc32.zip','odbc64.zip'
    Extract both architectures from named local ZIPs.

.EXAMPLE
    .\Manage-OracleInstantClient.ps1 -ConfigureOnly -UseExistingInstallation
    Configure TNS_ADMIN without client-folder ACL changes. Run PermissionsOnly separately.

.EXAMPLE
    .\Manage-OracleInstantClient.ps1 -PermissionsOnly -PermissionSet CPM -UseExistingInstallation
    Grant all required permissions, including existing TNS_ADMIN outside Destination.

.EXAMPLE
    .\Manage-OracleInstantClient.ps1 -UninstallOnly
    Unregister selected drivers after confirmation, leaving files/configuration intact.

.EXAMPLE
    .\Manage-OracleInstantClient.ps1 -CleanupOnly -ClientPath 'D:\Oracle\instantclient_19_32'
    Clean an explicitly identified unregistered client folder after confirmation.

.EXAMPLE
    .\Manage-OracleInstantClient.ps1 -UninstallAndCleanup -ForceRemoval
    Unregister and delete selected client folders/ZIPs without prompting, with safety checks.

.NOTES
    Version: 3.0
    Stage and Download switches were replaced by DownloadOnly and the default full workflow.
    WhatIf is not supported. Confirmation defaults to Stop; noninteractive runs must supply
    the specific approval parameter when confirmation is needed.

    Removal never deletes Destination itself, TNS_ADMIN, configuration files in TNS_ADMIN,
    System/current-user DSNs, other releases, or unrelated environment/ACL entries.
    Cleanup rejects reparse points and registered references. It cannot establish that no
    application uses an unregistered client: review the paths and stop dependent services
    before approving. CleanupOnly cannot discover paths from removed ODBC registrations;
    supply ClientPath for nonstandard locations. DSNs of other users may not be visible.

    PreCheck validates registered names/folders, required files and PE architecture, not
    Oracle download authenticity or full database compatibility. Use trusted Oracle ZIPs.
    Visual C++ checks look for the matching installed v14 runtime; keep it current according
    to Oracle's requirements. PATH is reported but not changed; review it on the connector.

    Updating pinned releases:
      1. Review Basic Light, SQL*Plus and ODBC links on both Oracle download pages:
         https://www.oracle.com/database/technologies/instant-client/microsoft-windows-32-downloads.html
         https://www.oracle.com/database/technologies/instant-client/winx64-64-downloads.html
      2. Update VersionConfig using the actual URL and ZIP, not inferred dates:
         Folder = numeric URL directory; Release = full filename suffix (including dbru);
         ClientFolder = exact top-level ZIP directory.
         Example: /1932000/instantclient-basiclite-windows.x64-19.32.0.0.0dbru.zip
         Folder='1932000'; Release='19.32.0.0.0dbru'; ClientFolder='instantclient_19_32'.
      3. Confirm all three packages use the same folder/release for each architecture.
         If releases or filename conventions differ by architecture, update configuration
         and URL generation explicitly. Do not use permanent latest links.
      4. Use DownloadOnly on a staging machine. Inspect ZIPs and validate installation,
         runtimes and CyberArk compatibility on a target CPM/SRS connector.
      5. New major versions also require updating ValidateSet, architecture availability,
         help/examples and runtime assumptions. Defaults change only when intended.
    ConfigureOnly/PermissionsOnly target the pinned ClientFolder, not older releases.

    Reference: https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/oracledatabaseplugin.htm
#>
[CmdletBinding(DefaultParameterSetName = 'Full')]
param (
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Destination = 'C:\Oracle\',

    [Parameter()]
    [ValidateSet('19', '21', '23')]
    [string]$Version = '19',

    [Parameter()]
    [ValidateSet('32', '64')]
    [string[]]$Architecture = @('64'),

    [Parameter()]
    [ValidateSet('CPM', 'SRS')]
    [string]$PermissionSet = 'SRS',

    [Parameter(Mandatory, ParameterSetName = 'FullLocal')]
    [Parameter(Mandatory, ParameterSetName = 'PreCheckLocal')]
    [Parameter(Mandatory, ParameterSetName = 'ExtractLocal')]
    [Parameter(Mandatory, ParameterSetName = 'CleanupLocal')]
    [Parameter(Mandatory, ParameterSetName = 'RemoveLocal')]
    [ValidateNotNullOrEmpty()]
    [string[]]$BasicFile,

    [Parameter(Mandatory, ParameterSetName = 'FullLocal')]
    [Parameter(Mandatory, ParameterSetName = 'PreCheckLocal')]
    [Parameter(Mandatory, ParameterSetName = 'ExtractLocal')]
    [Parameter(Mandatory, ParameterSetName = 'CleanupLocal')]
    [Parameter(Mandatory, ParameterSetName = 'RemoveLocal')]
    [ValidateNotNullOrEmpty()]
    [string[]]$SqlPlusFile,

    [Parameter(Mandatory, ParameterSetName = 'FullLocal')]
    [Parameter(Mandatory, ParameterSetName = 'PreCheckLocal')]
    [Parameter(Mandatory, ParameterSetName = 'ExtractLocal')]
    [Parameter(Mandatory, ParameterSetName = 'CleanupLocal')]
    [Parameter(Mandatory, ParameterSetName = 'RemoveLocal')]
    [ValidateNotNullOrEmpty()]
    [string[]]$OdbcFile,

    [Parameter(Mandatory, ParameterSetName = 'Download')]
    [switch]$DownloadOnly,

    [Parameter(Mandatory, ParameterSetName = 'PreCheck')]
    [Parameter(Mandatory, ParameterSetName = 'PreCheckLocal')]
    [switch]$PreCheckOnly,

    [Parameter(Mandatory, ParameterSetName = 'Extract')]
    [Parameter(Mandatory, ParameterSetName = 'ExtractLocal')]
    [switch]$ExtractOnly,

    [Parameter(Mandatory, ParameterSetName = 'Install')]
    [switch]$InstallOnly,

    [Parameter(Mandatory, ParameterSetName = 'Verify')]
    [switch]$VerifyInstallationOnly,

    [Parameter(Mandatory, ParameterSetName = 'Configure')]
    [switch]$ConfigureOnly,

    [Parameter(Mandatory, ParameterSetName = 'Permissions')]
    [switch]$PermissionsOnly,

    [Parameter(ParameterSetName = 'Full')]
    [Parameter(ParameterSetName = 'FullLocal')]
    [Parameter(ParameterSetName = 'Install')]
    [Parameter(ParameterSetName = 'Configure')]
    [Parameter(ParameterSetName = 'Permissions')]
    [switch]$UseExistingInstallation,

    [Parameter(ParameterSetName = 'Full')]
    [Parameter(ParameterSetName = 'Download')]
    [switch]$OverwritePackages,

    [Parameter(ParameterSetName = 'Full')]
    [Parameter(ParameterSetName = 'FullLocal')]
    [Parameter(ParameterSetName = 'Download')]
    [Parameter(ParameterSetName = 'Extract')]
    [Parameter(ParameterSetName = 'ExtractLocal')]
    [Parameter(ParameterSetName = 'Configure')]
    [Parameter(ParameterSetName = 'PreCheck')]
    [Parameter(ParameterSetName = 'PreCheckLocal')]
    [switch]$CreateDestination,

    [Parameter(Mandatory, ParameterSetName = 'Uninstall')]
    [switch]$UninstallOnly,

    [Parameter(Mandatory, ParameterSetName = 'Cleanup')]
    [Parameter(Mandatory, ParameterSetName = 'CleanupLocal')]
    [switch]$CleanupOnly,

    [Parameter(Mandatory, ParameterSetName = 'Remove')]
    [Parameter(Mandatory, ParameterSetName = 'RemoveLocal')]
    [switch]$UninstallAndCleanup,

    [Parameter(ParameterSetName = 'Cleanup')]
    [Parameter(ParameterSetName = 'CleanupLocal')]
    [ValidateNotNullOrEmpty()]
    [string[]]$ClientPath,

    [Parameter(ParameterSetName = 'Uninstall')]
    [Parameter(ParameterSetName = 'Cleanup')]
    [Parameter(ParameterSetName = 'CleanupLocal')]
    [Parameter(ParameterSetName = 'Remove')]
    [Parameter(ParameterSetName = 'RemoveLocal')]
    [switch]$ForceRemoval
)

if ($Version -eq '23' -and '32' -in $Architecture) {
    throw 'Oracle Instant Client 23 is unavailable for 32-bit Windows. Select Architecture 64 or Version 19/21.'
}
if (@($Architecture | Select-Object -Unique).Count -ne $Architecture.Count) {
    throw 'Specify each architecture once. Local filenames must follow Architecture order.'
}
if ($Destination -notmatch '^[A-Za-z]:\\') {
    throw 'Destination must be a local drive path, not a UNC or provider path.'
}
$Destination = [System.IO.Path]::GetFullPath($Destination).TrimEnd('\')
if ($Destination -match '^[A-Za-z]:$') { $Destination += '\' }
$fullRun = $PSCmdlet.ParameterSetName -in @('Full', 'FullLocal')
$localPackages = $PSBoundParameters.ContainsKey('BasicFile')
$removal = $UninstallOnly -or $CleanupOnly -or $UninstallAndCleanup
foreach ($name in @('DownloadOnly', 'PreCheckOnly', 'ExtractOnly', 'InstallOnly',
    'VerifyInstallationOnly', 'ConfigureOnly', 'PermissionsOnly', 'UninstallOnly',
    'CleanupOnly', 'UninstallAndCleanup')) {
    if ($PSBoundParameters.ContainsKey($name) -and -not $PSBoundParameters[$name]) {
        throw ('Do not pass -{0}:$false. Omit the operation switch to run the full workflow.' -f $name)
    }
}
$OracleVariable = 'TNS_ADMIN'
$newLine = [Environment]::NewLine

# See .NOTES for download pages and the release-maintenance checklist.
$VersionConfig = @{
    '19' = @{ Folder = '1932000'; Release = '19.32.0.0.0dbru'; ClientFolder = 'instantclient_19_32' }
    '21' = @{ Folder = '2123000'; Release = '21.23.0.0.0dbru'; ClientFolder = 'instantclient_21_23' }
    '23' = @{ Folder = '2326300'; Release = '23.26.3.0.0'; ClientFolder = 'instantclient_23_26' }
}
$ArchConfig = @{
    '32' = @{ PackagePlatform = 'nt'; OdbcPlatform = '32-bit'; Machine = 0x014c; Runtime = 'x86' }
    '64' = @{ PackagePlatform = 'windows.x64'; OdbcPlatform = '64-bit'; Machine = 0x8664; Runtime = 'x64' }
}
$clientFolder = $VersionConfig[$Version].ClientFolder
$driverName = "Oracle in $clientFolder"
$PermissionUsers = @{
    CPM = @("$env:COMPUTERNAME\PluginManagerUser", "$env:COMPUTERNAME\PasswordManagerUser")
    SRS = @("$env:COMPUTERNAME\SRSExecutionUser", 'NT SERVICE\IdiraManagementAgent')
}
$ServiceUsers = $PermissionUsers[$PermissionSet]
$ServiceSids = @{}
$plans = @(for ($index = 0; $index -lt $Architecture.Count; $index++) {
    $arch = $Architecture[$index]
    $urls = @(foreach ($package in @('basiclite', 'sqlplus', 'odbc')) {
        'https://download.oracle.com/otn_software/nt/instantclient/{0}/instantclient-{1}-{2}-{3}.zip' -f
            $VersionConfig[$Version].Folder, $package, $ArchConfig[$arch].PackagePlatform, $VersionConfig[$Version].Release
    })
    $files = if ($localPackages) {
        if ($BasicFile.Count -ne $Architecture.Count -or $SqlPlusFile.Count -ne $Architecture.Count -or
            $OdbcFile.Count -ne $Architecture.Count) {
            throw 'Each local package parameter must contain one filename per Architecture, in the same order.'
        }
        @($BasicFile[$index], $SqlPlusFile[$index], $OdbcFile[$index])
    } else { @($urls | ForEach-Object { Split-Path $_ -Leaf }) }
    [pscustomobject]@{
        Architecture = $arch
        Platform = $ArchConfig[$arch].OdbcPlatform
        Urls = $urls
        Files = $files
        StandardPath = Join-Path (Join-Path $Destination $ArchConfig[$arch].OdbcPlatform) $clientFolder
        ClientDir = $null
        Driver = $null
    }
})
$fileNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($plan in $plans) {
    foreach ($file in $plan.Files) {
        if ([string]::IsNullOrWhiteSpace($file) -or
            $file.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0 -or
            [System.IO.Path]::GetExtension($file) -ine '.zip') {
            throw "Invalid local ZIP filename '$file'. Supply filenames only, not paths."
        }
        if (-not $fileNames.Add($file)) { throw "Duplicate package filename '$file'." }
    }
}

#region Shared checks

function Assert-Administrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'This operation requires an elevated PowerShell session.'
        }
    } finally { $identity.Dispose() }
}

function Resolve-ServicePrincipals {
    $errors = [System.Collections.Generic.List[string]]::new()
    foreach ($user in $ServiceUsers) {
        try {
            if ($user.StartsWith('NT SERVICE\', [StringComparison]::OrdinalIgnoreCase)) {
                Get-Service -Name ($user -replace '^NT SERVICE\\', '') -ErrorAction Stop | Out-Null
            } else {
                $localName = ($user -split '\\')[-1]
                $accountQuery = @{
                    ClassName = 'Win32_UserAccount'
                    Filter = "LocalAccount=True AND Name='$localName' AND Domain='$env:COMPUTERNAME'"
                    ErrorAction = 'Stop'
                }
                $accounts = @(Get-CimInstance @accountQuery)
                if ($accounts.Count -ne 1) { throw "Local user '$localName' does not exist uniquely on this machine." }
            }
            $ServiceSids[$user] = [System.Security.Principal.NTAccount]::new($user).Translate(
                [System.Security.Principal.SecurityIdentifier]
            )
        } catch { $errors.Add("Cannot resolve '$user': $($_.Exception.Message)") }
    }
    if ($errors.Count) { throw ($errors -join $newLine) }
}

function Confirm-Operation {
    param([string]$Message, [string]$OverrideName, [bool]$Approved)
    Write-Warning $Message
    if ($Approved) {
        Write-Host "  Approved by -$OverrideName."
        return
    }
    if (-not [Environment]::UserInteractive -or [Environment]::CommandLine -match '(?i)-NonInteractive\b') {
        throw "Confirmation unavailable. Review the warning and supply -$OverrideName to approve explicitly."
    }
    try {
        $choices = [System.Management.Automation.Host.ChoiceDescription[]]@(
            [System.Management.Automation.Host.ChoiceDescription]::new('&Continue', 'Approve the listed operation.'),
            [System.Management.Automation.Host.ChoiceDescription]::new('&Stop', 'Stop without proceeding.')
        )
        $answer = $Host.UI.PromptForChoice('Oracle Instant Client', $Message, $choices, 1)
    } catch {
        throw "Cannot request confirmation. Supply -$OverrideName only after reviewing the operation: $($_.Exception.Message)"
    }
    if ($answer -ne 0) { throw 'Operation declined; no further changes performed.' }
}

function Get-AllDrivers {
    foreach ($platform in @('32-bit', '64-bit')) {
        Get-OdbcDriver -Platform $platform -ErrorAction Stop
    }
}

function Get-DriverPath {
    param($Driver)
    $attributes = @($Driver.Attribute | Where-Object { $_ -like 'Driver=*' })
    if ($attributes.Count -ne 1) { throw "Cannot determine DLL path for '$($Driver.Name)' [$($Driver.Platform)]." }
    $path = [Environment]::ExpandEnvironmentVariables(($attributes[0] -replace '^Driver=', '').Trim('"'))
    if (-not [System.IO.Path]::IsPathRooted($path)) { throw "Registered DLL path is not absolute: '$path'." }
    [System.IO.Path]::GetFullPath($path)
}

function Test-WithinPath {
    param([string]$Path, [string]$Parent)
    $pathValue = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $parentValue = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\')
    $pathValue.Equals($parentValue, [StringComparison]::OrdinalIgnoreCase) -or
        $pathValue.StartsWith($parentValue + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Assert-NoReparsePath {
    param([string]$Path)
    $current = $Path
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                throw "Reparse point is not supported for this operation: '$current'."
            }
        }
        $parent = Split-Path $current -Parent
        if ($parent -eq $current) { break }
        $current = $parent
    }
}

function Get-CheckedTree {
    param([string]$Path)
    Assert-NoReparsePath $Path
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($Path)
    while ($pending.Count) {
        foreach ($child in Get-ChildItem -LiteralPath $pending.Pop() -Force -ErrorAction Stop) {
            if ($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                throw "Reparse point inside target folder is not supported: '$($child.FullName)'."
            }
            if ($child.PSIsContainer) { $pending.Push($child.FullName) }
            $child
        }
    }
}

function Assert-WritableDirectory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Required writable destination folder does not exist: '$Path'. Create it before this operation."
    }
    Assert-NoReparsePath $Path
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $tokenSids = @($identity.User.Value) + @($identity.Groups | ForEach-Object Value)
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $allow = 0
        $deny = 0
        foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ($rule.IdentityReference.Value -notin $tokenSids -or
                ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
            if ($rule.AccessControlType -eq 'Deny') { $deny = $deny -bor [int]$rule.FileSystemRights }
            else { $allow = $allow -bor [int]$rule.FileSystemRights }
        }
        $required = [int][System.Security.AccessControl.FileSystemRights]::Write
        if (($deny -band $required) -ne 0 -or ($allow -band $required) -ne $required) {
            throw "Directory ACL does not permit the current token to write '$Path'."
        }
    } finally { $identity.Dispose() }
}

function Assert-DestinationReady {
    Assert-NoReparsePath $Destination
    if (Test-Path -LiteralPath $Destination) {
        Assert-WritableDirectory $Destination
        return
    }
    $parent = Split-Path $Destination -Parent
    while ($parent -and -not (Test-Path -LiteralPath $parent)) {
        $parent = Split-Path $parent -Parent
    }
    if (-not $parent) { throw "No existing parent found for Destination '$Destination'." }
    Assert-WritableDirectory $parent
    $script:destinationCreationNeeded = $true
    Write-Host "  Destination '$Destination' is missing; creation is required. Existing parent: '$parent'."
}

function Initialize-Destination {
    if (-not $destinationCreationNeeded) { return }
    $confirmation = @{
        Message = "Create missing destination folder '$Destination' (including missing parent folders)?"
        OverrideName = 'CreateDestination'
        Approved = $CreateDestination.IsPresent
    }
    Confirm-Operation @confirmation
    Assert-DestinationReady
    if (-not (Test-Path -LiteralPath $Destination -PathType Container)) {
        [System.IO.Directory]::CreateDirectory($Destination) | Out-Null
    }
    Assert-WritableDirectory $Destination
    Write-Host "  Verified destination: '$Destination'."
}

function Assert-Runtime {
    param([string]$Arch)
    $found = $false
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry32, [Microsoft.Win32.RegistryView]::Registry64)) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        try {
            $key = $base.OpenSubKey("SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\$($ArchConfig[$Arch].Runtime)")
            if ($null -ne $key) {
                try { if ($key.GetValue('Installed') -eq 1) { $found = $true } }
                finally { $key.Dispose() }
            }
        } finally { $base.Dispose() }
    }
    if (-not $found) {
        throw "Microsoft Visual C++ v14 $($ArchConfig[$Arch].Runtime) runtime not found. Install Oracle's required current redistributable."
    }
}

function Assert-PeArchitecture {
    param([System.IO.Stream]$Stream, [string]$Arch, [string]$Label)
    $reader = [System.IO.BinaryReader]::new($Stream, [System.Text.Encoding]::ASCII, $true)
    try {
        if ($reader.ReadUInt16() -ne 0x5a4d) { throw "'$Label' is not a Windows PE file." }
        $Stream.Position = 0x3c
        $offset = $reader.ReadInt32()
        if ($offset -lt 0x40 -or $offset -gt ($Stream.Length - 6)) { throw "Invalid PE header in '$Label'." }
        $Stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x00004550 -or $reader.ReadUInt16() -ne $ArchConfig[$Arch].Machine) {
            throw "'$Label' does not match the selected $Arch-bit architecture."
        }
    } finally { $reader.Dispose() }
}

function Assert-ClientFiles {
    param([string]$Path, [string]$Arch, [switch]$Installer, [switch]$Uninstaller)
    Assert-NoReparsePath $Path
    if (-not (Test-Path -LiteralPath $Path -PathType Container) -or (Split-Path $Path -Leaf) -ine $clientFolder) {
        throw "Expected existing '$clientFolder' folder: '$Path'."
    }
    $required = if ($Uninstaller) { @('odbc_uninstall.exe') } else { @('oci.dll', 'sqora32.dll', 'sqlplus.exe') }
    if ($Installer) { $required += 'odbc_install.exe' }
    foreach ($name in $required) {
        $file = Join-Path $Path $name
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Required client file missing: '$file'." }
        Assert-NoReparsePath $file
        $stream = [System.IO.File]::OpenRead($file)
        try { Assert-PeArchitecture $stream $Arch $file }
        finally { $stream.Dispose() }
    }
}

function Assert-Packages {
    param($Plan)
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    [long]$expanded = 0
    for ($index = 0; $index -lt 3; $index++) {
        $path = Join-Path $Destination $Plan.Files[$index]
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Package missing: '$path'." }
        Assert-NoReparsePath $path
        $archive = [System.IO.Compression.ZipFile]::OpenRead($path)
        try {
            $entries = @{}
            foreach ($entry in $archive.Entries) {
                $name = $entry.FullName.Replace('\', '/')
                if (-not $name.StartsWith($clientFolder + '/', [StringComparison]::OrdinalIgnoreCase) -or
                    $name -match '(^|/)\.\.?(/|$)|[<>:"|?*\x00-\x1f]|(^|/)[^/]*[. ](/|$)' -or $name.Contains('//')) {
                    throw "Unexpected or unsafe archive path '$name' in '$path'. Expected '$clientFolder/'."
                }
                if ($entries.ContainsKey($name)) { throw "Duplicate archive entry '$name' in '$path'." }
                $entries[$name] = $entry
                $expanded += $entry.Length
            }
            $markers = switch ($index) {
                0 { @('oci.dll') }
                1 { @('sqlplus.exe') }
                2 { @('sqora32.dll', 'odbc_install.exe', 'odbc_uninstall.exe') }
            }
            foreach ($marker in $markers) {
                $entry = $entries["$clientFolder/$marker"]
                if ($null -eq $entry -or $entry.Length -eq 0) { throw "Required '$marker' missing from '$path'." }
                if ($entry.Length -gt 32MB) { throw "Unexpectedly large required binary '$marker' in '$path'." }
                $inputStream = $entry.Open()
                $buffer = [System.IO.MemoryStream]::new()
                try {
                    $inputStream.CopyTo($buffer)
                    $buffer.Position = 0
                    Assert-PeArchitecture $buffer $Plan.Architecture "$path : $marker"
                } finally { $buffer.Dispose(); $inputStream.Dispose() }
            }
            Write-Host "  Validated: $path"
        } finally { $archive.Dispose() }
    }
    $expanded
}

function Assert-DiskSpace {
    param([long]$RequiredBytes)
    $drive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($Destination))
    if ($drive.AvailableFreeSpace -lt $RequiredBytes) {
        throw "Insufficient disk space on $($drive.Name): need at least $RequiredBytes bytes; available $($drive.AvailableFreeSpace)."
    }
}

function Resolve-TnsFolder {
    $machineValue = [Environment]::GetEnvironmentVariable($OracleVariable, 'Machine')
    if ([string]::IsNullOrWhiteSpace($machineValue)) {
        $folder = Join-Path $Destination 'TNS_ADMIN'
        Assert-NoReparsePath $folder
        if (Test-Path -LiteralPath $folder) {
            if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
                throw "Default TNS_ADMIN target exists but is not a folder: '$folder'."
            }
            Get-Acl -LiteralPath $folder -ErrorAction Stop | Out-Null
        }
    } else {
        $folder = [Environment]::ExpandEnvironmentVariables($machineValue.Trim('"'))
        if (-not [System.IO.Path]::IsPathRooted($folder)) { throw "Machine TNS_ADMIN must be an absolute folder path: '$machineValue'." }
        if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
            throw "Existing machine TNS_ADMIN is missing or inaccessible: '$folder'. Correct it explicitly; it will not be replaced."
        }
        Get-Acl -LiteralPath $folder -ErrorAction Stop | Out-Null
    }
    $folder = [System.IO.Path]::GetFullPath($folder)
    if ($folder.TrimEnd('\') -ieq [System.IO.Path]::GetPathRoot($folder).TrimEnd('\')) {
        throw "TNS_ADMIN must be a dedicated folder, not a drive/share root: '$folder'. Broad root permissions will not be granted."
    }
    Assert-NoReparsePath $folder
    foreach ($scope in @('User', 'Process')) {
        $value = [Environment]::GetEnvironmentVariable($OracleVariable, $scope)
        if ($value -and $value -ine $machineValue) {
            Write-Warning "$scope TNS_ADMIN='$value' differs from machine TNS_ADMIN='$machineValue'; $scope value is unchanged."
        }
    }
    [pscustomobject]@{ Path = $folder.TrimEnd('\'); MachineValue = $machineValue }
}

function Invoke-Check {
    param([System.Collections.Generic.List[string]]$Errors, [scriptblock]$Check)
    try { & $Check | Out-Null }
    catch { $Errors.Add($_.Exception.Message) }
}

function Complete-PreCheck {
    param([System.Collections.Generic.List[string]]$Errors)
    if ($Errors.Count) { throw ("PreCheck failed:${newLine} - " + ($Errors -join "${newLine} - ")) }
    Write-Host '  PreCheck passed.'
}

function Find-SelectedClients {
    param([object[]]$Drivers, [switch]$Required)
    foreach ($plan in $plans) {
        $registrations = @($Drivers | Where-Object { $_.Name -ieq $driverName -and $_.Platform -eq $plan.Platform })
        if ($registrations.Count -gt 1) { throw "Ambiguous registration for '$driverName' [$($plan.Platform)]." }
        if ($registrations.Count -eq 0) {
            if ($Required) { throw "No '$driverName' [$($plan.Platform)] registration. Install the selected client first." }
            continue
        }
        $dll = Get-DriverPath $registrations[0]
        $dir = Split-Path $dll -Parent
        Assert-ClientFiles $dir $plan.Architecture
        if (-not (Test-Path -LiteralPath $dll -PathType Leaf)) { throw "Registered DLL missing: '$dll'. Repair the registration." }
        $plan.Driver = $registrations[0]
        $plan.ClientDir = $dir
        Write-Host "  Found: '$driverName' [$($plan.Platform)] at '$dll'."
    }
}

function Confirm-ExistingClients {
    $existing = @($plans | Where-Object { $null -ne $_.Driver })
    if (-not $existing.Count) { return }
    $details = @($existing | ForEach-Object { "$driverName [$($_.Platform)] -> $($_.ClientDir)" }) -join $newLine
    $tnsDescription = if ($tns) { $tns.Path } else { '(not modified by this operation)' }
    $confirmation = @{
        Message = "Existing installations found:${newLine}${details}${newLine}Use these locations without reinstalling? TNS_ADMIN: '$tnsDescription'."
        OverrideName = 'UseExistingInstallation'
        Approved = $UseExistingInstallation.IsPresent
    }
    Confirm-Operation @confirmation
}

function Assert-CurrentRegistration {
    $currentDrivers = @(Get-AllDrivers)
    foreach ($plan in $plans | Where-Object { $null -ne $_.Driver }) {
        $current = @($currentDrivers | Where-Object { $_.Name -ieq $driverName -and $_.Platform -eq $plan.Platform })
        if ($current.Count -ne 1 -or (Get-DriverPath $current[0]) -ine (Get-DriverPath $plan.Driver)) {
            throw "Registration for '$driverName' [$($plan.Platform)] changed since discovery. Rerun to review its new location."
        }
        Assert-ClientFiles $plan.ClientDir $plan.Architecture
    }
}

function Assert-UnregisteredPath {
    param([string]$Path, [object[]]$Drivers)
    foreach ($driver in $Drivers) {
        $dll = Get-DriverPath $driver
        if (Test-WithinPath $dll $Path) {
            throw "Folder '$Path' is referenced by '$($driver.Name)' [$($driver.Platform)] at '$dll'."
        }
    }
}

function Invoke-OracleExecutable {
    param([string]$Path, [string]$Name)
    $exe = Join-Path $Path $Name
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Oracle executable missing: '$exe'." }
    Assert-NoReparsePath $exe
    $process = Start-Process -FilePath $exe -WorkingDirectory $Path -Wait -PassThru -ErrorAction Stop
    if ($process.ExitCode -ne 0) { throw "'$exe' failed with exit code $($process.ExitCode). No subsequent operation will run." }
}

#endregion

#region Permission helpers

function Get-PermissionRule {
    param([System.Security.Principal.SecurityIdentifier]$Sid, [string]$Permission)
    if ($Permission -eq 'Read') {
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            $Sid, 'ReadAndExecute, Synchronize', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
        )
    } else {
        [System.Security.AccessControl.FileSystemAccessRule]::new($Sid, 'ExecuteFile, Synchronize', 'Allow')
    }
}

function Test-ExplicitGrant {
    param($Acl, $Rule)
    $grants = @($Acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
        Where-Object {
            $_.IdentityReference -eq $Rule.IdentityReference -and $_.AccessControlType -eq 'Allow' -and
            $_.InheritanceFlags -eq $Rule.InheritanceFlags -and $_.PropagationFlags -eq $Rule.PropagationFlags -and
            ($_.FileSystemRights -band $Rule.FileSystemRights) -eq $Rule.FileSystemRights
        })
    $grants.Count -gt 0
}

function Get-PermissionTargets {
    $targets = [System.Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($folder in @($plans.ClientDir) + @($tns.Path)) {
        if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
            throw "Permission target missing: '$folder'. Run ConfigureOnly first if TNS_ADMIN is absent."
        }
        Get-Acl -LiteralPath $folder -ErrorAction Stop | Out-Null
        $targets[$folder] = 'Read'
        $parent = Split-Path $folder -Parent
        while ($parent -and $parent.TrimEnd('\') -ne [System.IO.Path]::GetPathRoot($parent).TrimEnd('\')) {
            if (-not $targets.ContainsKey($parent)) { $targets[$parent] = 'Traverse' }
            $parent = Split-Path $parent -Parent
        }
    }
    $targets
}

function Invoke-Permissions {
    Assert-Administrator
    Resolve-ServicePrincipals
    $targets = Get-PermissionTargets
    $updates = @(foreach ($path in $targets.Keys) {
        $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
        $changed = $false
        foreach ($user in $ServiceUsers) {
            $rule = Get-PermissionRule $ServiceSids[$user] $targets[$path]
            $deny = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
                Where-Object {
                    $_.IdentityReference -eq $rule.IdentityReference -and $_.AccessControlType -eq 'Deny' -and
                    ($_.FileSystemRights -band $rule.FileSystemRights) -ne 0 -and
                    -not ($_.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly)
                })
            if ($deny.Count) { throw "Conflicting deny ACL for '$user' on '$path'. Correct it explicitly before granting access." }
            if (-not (Test-ExplicitGrant $acl $rule)) { $acl.AddAccessRule($rule); $changed = $true }
        }
        [pscustomobject]@{ Path = $path; Acl = $acl; Changed = $changed }
    })
    foreach ($update in $updates) {
        if ($update.Changed) {
            Write-Host "  Granting $($targets[$update.Path]) to $($ServiceUsers -join ', ') on '$($update.Path)'."
            Set-Acl -LiteralPath $update.Path -AclObject $update.Acl -ErrorAction Stop
        }
    }
    foreach ($path in $targets.Keys) {
        $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
        foreach ($user in $ServiceUsers) {
            if (-not (Test-ExplicitGrant $acl (Get-PermissionRule $ServiceSids[$user] $targets[$path]))) {
                throw "Permission verification failed for '$user' on '$path'."
            }
        }
    }
    Write-Host '  All explicit permission grants verified; unrelated rules preserved.'
}

#endregion

#region Removal helpers

function Get-SafeCleanupItems {
    param([string[]]$Directories, [string[]]$Packages, [object[]]$Drivers, [switch]$BeforeUninstall)
    $protected = @($Destination, $HOME, $PWD.Path, $PSScriptRoot)
    foreach ($scope in @('Machine', 'User', 'Process')) {
        $value = [Environment]::GetEnvironmentVariable($OracleVariable, $scope)
        if ($value) { $protected += [Environment]::ExpandEnvironmentVariables($value.Trim('"')) }
    }
    $protected += Join-Path $Destination 'TNS_ADMIN'
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in @($Directories) + @($Packages)) {
        $resolved = [System.IO.Path]::GetFullPath($path)
        if (-not $seen.Add($resolved)) { continue }
        if (-not (Test-Path -LiteralPath $resolved)) { Write-Host "  Already absent: '$resolved'."; continue }
        Assert-NoReparsePath $resolved
        foreach ($keep in $protected) {
            if (Test-WithinPath $keep $resolved) { throw "Cleanup would remove protected path '$keep': '$resolved'." }
        }
        foreach ($driver in $Drivers) {
            if (Test-WithinPath (Get-DriverPath $driver) $resolved) {
                if ($BeforeUninstall -and $driver.Name -ieq $driverName -and $driver.Platform -in $plans.Platform) { continue }
                throw "Cleanup target '$resolved' is referenced by '$($driver.Name)' [$($driver.Platform)]."
            }
        }
        $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
        if ($item.PSIsContainer) {
            if ($resolved -notmatch '^[A-Za-z]:\\') { throw "Cleanup requires a local drive client folder, not '$resolved'." }
            if ($item.Name -ine $clientFolder) { throw "Cleanup only accepts the exact '$clientFolder' client folder: '$resolved'." }
            $archPlans = @($plans | Where-Object { $_.ClientDir -ieq $resolved })
            if ($archPlans.Count -ne 1) { throw "Cannot determine unique architecture for cleanup target '$resolved'." }
            $oci = Join-Path $resolved 'oci.dll'
            if (-not (Test-Path -LiteralPath $oci -PathType Leaf)) { throw "Not an identifiable Oracle client folder (oci.dll absent): '$resolved'." }
            $stream = [System.IO.File]::OpenRead($oci)
            try { Assert-PeArchitecture $stream $archPlans[0].Architecture $oci }
            finally { $stream.Dispose() }
            foreach ($child in Get-CheckedTree $resolved) {
                if (-not $child.PSIsContainer -and $child.Extension -ieq '.ora') {
                    throw "Cleanup would delete Oracle configuration '$($child.FullName)'. Move/preserve it explicitly first."
                }
            }
        } elseif ($item.Extension -ine '.zip' -or (Split-Path $resolved -Parent).TrimEnd('\') -ine $Destination.TrimEnd('\')) {
            throw "Cleanup package must be an explicitly selected ZIP directly under Destination: '$resolved'."
        }
        [pscustomobject]@{ Path = $resolved; Directory = $item.PSIsContainer }
    }
}

function Invoke-Removal {
    Write-Host "${newLine}PreCheck: removal readiness..."
    $errors = [System.Collections.Generic.List[string]]::new()
    Invoke-Check $errors { Assert-Administrator }
    $drivers = @(Get-AllDrivers)
    if ($CleanupOnly) {
        if ($ClientPath -and $ClientPath.Count -ne $plans.Count) { throw 'ClientPath requires one folder per Architecture, in the same order.' }
        for ($index = 0; $index -lt $plans.Count; $index++) {
            if ($ClientPath -and $ClientPath[$index] -notmatch '^[A-Za-z]:\\') {
                throw "ClientPath must be an explicit absolute local drive path: '$($ClientPath[$index])'."
            }
            $plans[$index].ClientDir = if ($ClientPath) { [System.IO.Path]::GetFullPath($ClientPath[$index]).TrimEnd('\') } else { $plans[$index].StandardPath }
            Invoke-Check $errors { Assert-UnregisteredPath $plans[$index].ClientDir $drivers }
        }
    } else {
        foreach ($plan in $plans) {
            Invoke-Check $errors {
                $registrations = @($drivers | Where-Object { $_.Name -ieq $driverName -and $_.Platform -eq $plan.Platform })
                if ($registrations.Count -ne 1) { throw "Expected one '$driverName' [$($plan.Platform)] registration; found $($registrations.Count)." }
                $plan.Driver = $registrations[0]
                $plan.ClientDir = Split-Path (Get-DriverPath $registrations[0]) -Parent
                Assert-NoReparsePath $plan.ClientDir
                Assert-ClientFiles $plan.ClientDir $plan.Architecture -Uninstaller
                foreach ($other in $drivers) {
                    if ((Test-WithinPath (Get-DriverPath $other) $plan.ClientDir) -and
                        ($other.Name -ine $driverName -or $other.Platform -ne $plan.Platform)) {
                        throw "Uninstaller folder is shared by '$($other.Name)' [$($other.Platform)]."
                    }
                }
            }
        }
    }
    Complete-PreCheck $errors
    $dsns = @(foreach ($platform in @('32-bit', '64-bit')) {
        Get-OdbcDsn -Platform $platform -ErrorAction Stop |
            Where-Object { $_.DriverName -ieq $driverName -and $_.Platform -in $plans.Platform }
    })
    foreach ($dsn in $dsns) { Write-Warning "Dependent DSN '$($dsn.Name)' [$($dsn.Platform), $($dsn.DsnType)] will not be deleted and may stop working." }
    $directories = @($plans.ClientDir)
    $packages = @(foreach ($plan in $plans) { foreach ($file in $plan.Files) { Join-Path $Destination $file } })
    foreach ($scope in @('Machine', 'User', 'Process')) {
        foreach ($variable in @('PATH', 'ORACLE_HOME')) {
            foreach ($entry in ([Environment]::GetEnvironmentVariable($variable, $scope) -split ';')) {
                if (-not $entry -or -not [System.IO.Path]::IsPathRooted($entry.Trim('"'))) { continue }
                foreach ($directory in $directories) {
                    if (Test-WithinPath ([Environment]::ExpandEnvironmentVariables($entry.Trim('"'))) $directory) {
                        Write-Warning "$scope $variable references '$directory' and will be left unchanged. Review it after removal."
                    }
                }
            }
        }
    }
    $cleanup = @()
    if (-not $UninstallOnly) {
        $cleanup = @(Get-SafeCleanupItems $directories $packages $drivers -BeforeUninstall:$UninstallAndCleanup)
    }
    $details = @()
    if (-not $CleanupOnly) { $details += @($plans | ForEach-Object { "Unregister: $driverName [$($_.Platform)] from '$($_.ClientDir)'." }) }
    $details += @($cleanup | ForEach-Object { "Delete: '$($_.Path)'." })
    if (-not $details.Count) { Write-Host 'Nothing to clean up; selected paths are already absent.'; return }
    $confirmation = @{
        Message = ($details -join $newLine) + "${newLine}TNS_ADMIN and DSNs are preserved. Stop applications using these clients before continuing."
        OverrideName = 'ForceRemoval'
        Approved = $ForceRemoval.IsPresent
    }
    Confirm-Operation @confirmation
    if (-not $CleanupOnly) {
        foreach ($plan in $plans) {
            $currentDrivers = @(Get-AllDrivers)
            $currentRegistration = @($currentDrivers |
                Where-Object { $_.Name -ieq $driverName -and $_.Platform -eq $plan.Platform })
            if ($currentRegistration.Count -ne 1 -or
                (Get-DriverPath $currentRegistration[0]) -ine (Get-DriverPath $plan.Driver)) {
                throw 'Driver registration changed after confirmation. Rerun to review the current installation.'
            }
            foreach ($other in $currentDrivers) {
                if ((Test-WithinPath (Get-DriverPath $other) $plan.ClientDir) -and
                    ($other.Name -ine $driverName -or $other.Platform -ne $plan.Platform)) {
                    throw "Uninstaller folder is now shared by '$($other.Name)' [$($other.Platform)]."
                }
            }
            Write-Host "  Uninstalling '$driverName' [$($plan.Platform)]..."
            Invoke-OracleExecutable $plan.ClientDir 'odbc_uninstall.exe'
            $remaining = @(Get-AllDrivers | Where-Object { $_.Name -ieq $driverName -and $_.Platform -eq $plan.Platform })
            if ($remaining.Count) { throw "Uninstallation did not remove '$driverName' [$($plan.Platform)]; cleanup will not run." }
        }
    }
    if (-not $UninstallOnly) {
        # Recheck all paths and both registry views after uninstall and before deleting anything.
        $approvedPaths = @($cleanup.Path)
        $cleanup = @(Get-SafeCleanupItems $directories $packages @(Get-AllDrivers))
        foreach ($item in $cleanup) {
            if ($item.Path -notin $approvedPaths) {
                throw "New cleanup target appeared after confirmation: '$($item.Path)'. Rerun to review it before deletion."
            }
        }
        foreach ($item in $cleanup) {
            Write-Host "  Deleting '$($item.Path)'..."
            if ($item.Directory) { Remove-Item -LiteralPath $item.Path -Recurse -Force -ErrorAction Stop }
            else { Remove-Item -LiteralPath $item.Path -Force -ErrorAction Stop }
            if (Test-Path -LiteralPath $item.Path) { throw "Cleanup verification failed: '$($item.Path)' remains." }
        }
    }
    Write-Host 'Removal complete. TNS_ADMIN, DSNs and unrelated installations were preserved.'
    if ($UninstallOnly) {
        $paths = @($directories | ForEach-Object { "'$($_.Replace("'", "''"))'" }) -join ','
        $scriptLiteral = $MyInvocation.ScriptName.Replace("'", "''")
        $destinationLiteral = $Destination.Replace("'", "''")
        Write-Host "For later cleanup: & '$scriptLiteral' -Destination '$destinationLiteral' -Version $Version -Architecture $($Architecture -join ',') -CleanupOnly -ClientPath $paths"
    }
}

#endregion

if ($removal) { Invoke-Removal; return }

#region Mandatory operation-specific PreCheck

Write-Host "${newLine}PreCheck: operation readiness..."
$destinationCreationNeeded = $false
$errors = [System.Collections.Generic.List[string]]::new()
$needsPrincipals = $fullRun -or $PreCheckOnly -or $PermissionsOnly
$needsAdmin = $needsPrincipals -or $InstallOnly -or $ConfigureOnly
if ($needsAdmin) { Invoke-Check $errors { Assert-Administrator } }
if ($needsPrincipals) { Invoke-Check $errors { Resolve-ServicePrincipals } }
if ($DownloadOnly -or $ExtractOnly) {
    Invoke-Check $errors { Assert-DestinationReady; Assert-DiskSpace 1 }
}
$tns = $null
if ($fullRun -or $PreCheckOnly -or $ConfigureOnly -or $PermissionsOnly) {
    Invoke-Check $errors { $script:tns = Resolve-TnsFolder }
    if ($tns -and -not $tns.MachineValue -and -not $PermissionsOnly) {
        Invoke-Check $errors { Assert-DestinationReady }
    }
    if ($PermissionsOnly -and $tns) {
        Invoke-Check $errors {
            if (-not (Test-Path -LiteralPath $tns.Path -PathType Container)) { throw "TNS_ADMIN folder absent: '$($tns.Path)'. Run ConfigureOnly first." }
        }
    }
}
$allDrivers = @()
if (-not $DownloadOnly) {
    Invoke-Check $errors { $script:allDrivers = @(Get-AllDrivers) }
    if (-not $ExtractOnly) {
        Invoke-Check $errors {
            Find-SelectedClients $allDrivers -Required:($VerifyInstallationOnly -or $ConfigureOnly -or $PermissionsOnly)
        }
    }
    foreach ($other in $allDrivers | Where-Object { $_.Name -like 'Oracle*' -and $_.Name -ine $driverName }) {
        Write-Warning "Other Oracle driver remains unchanged: '$($other.Name)' [$($other.Platform)] at '$(Get-DriverPath $other)'."
    }
}
$missingPlans = @($plans | Where-Object { $null -eq $_.Driver })
if (($fullRun -or $PreCheckOnly) -and $missingPlans.Count) {
    Invoke-Check $errors { Assert-DestinationReady; Assert-DiskSpace 1 }
}
if ($fullRun -or $PreCheckOnly -or $InstallOnly) {
    foreach ($plan in $plans) { Invoke-Check $errors { Assert-Runtime $plan.Architecture } }
}
if ($fullRun -or $PreCheckOnly -or $InstallOnly -or $ConfigureOnly) {
    foreach ($scope in @('Machine', 'User', 'Process')) {
        $oracleHome = [Environment]::GetEnvironmentVariable('ORACLE_HOME', $scope)
        if ($oracleHome) { Write-Warning "$scope ORACLE_HOME='$oracleHome' is unchanged; review for conflicts with Instant Client." }
        $oraclePaths = @([Environment]::GetEnvironmentVariable('PATH', $scope) -split ';' |
            Where-Object { $_ -match '(?i)oracle|instantclient' })
        if ($oraclePaths.Count) { Write-Warning "$scope PATH Oracle entries are unchanged: $($oraclePaths -join '; ')." }
    }
}
if ($InstallOnly) {
    foreach ($plan in $missingPlans) {
        Invoke-Check $errors {
            Assert-NoReparsePath $plan.StandardPath
            Assert-ClientFiles $plan.StandardPath $plan.Architecture -Installer
        }
    }
}
if ($ExtractOnly -or (($fullRun -and $localPackages) -or $PreCheckOnly)) {
    [long]$neededSpace = 0
    foreach ($plan in $missingPlans) {
        Invoke-Check $errors { $script:packageBytes = Assert-Packages $plan; $script:neededSpace += $packageBytes }
    }
    Invoke-Check $errors { Assert-DiskSpace $neededSpace }
}
if ($fullRun -or $ExtractOnly) {
    foreach ($plan in $missingPlans) {
        Invoke-Check $errors {
            Assert-NoReparsePath $plan.StandardPath
            Assert-UnregisteredPath $plan.StandardPath $allDrivers
            if (Test-Path -LiteralPath $plan.StandardPath -PathType Container) {
                Get-CheckedTree $plan.StandardPath | Out-Null
            }
        }
    }
}
Complete-PreCheck $errors
if ($PreCheckOnly) { Write-Host 'PreCheck complete; no changes made.'; return }
if ($VerifyInstallationOnly) { Write-Host 'Installation verified; no changes made.'; return }
if ($fullRun -or $InstallOnly -or $ConfigureOnly -or $PermissionsOnly) { Confirm-ExistingClients }
Initialize-Destination

#endregion

#region Download, Extract and Install

if ($DownloadOnly -or ($fullRun -and -not $localPackages)) {
    $downloadPlans = if ($DownloadOnly) { $plans } else { $missingPlans }
    $existingPackages = @(foreach ($plan in $downloadPlans) {
        foreach ($file in $plan.Files) {
            $path = Join-Path $Destination $file
            Assert-NoReparsePath $path
            if (Test-Path -LiteralPath $path) {
                if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "ZIP target is not a file: '$path'." }
                $path
            }
        }
    })
    if ($existingPackages.Count) {
        Confirm-Operation ("Overwrite existing packages?${newLine}" + ($existingPackages -join $newLine)) 'OverwritePackages' $OverwritePackages.IsPresent
    }
    if (@($downloadPlans).Count) { Write-Host "${newLine}Download: Oracle $($VersionConfig[$Version].Release) packages..." }
    foreach ($plan in $downloadPlans) {
        for ($index = 0; $index -lt 3; $index++) {
            $path = Join-Path $Destination $plan.Files[$index]
            Write-Host "  Downloading '$path'..."
            Invoke-WebRequest -Uri $plan.Urls[$index] -OutFile $path -UseBasicParsing -ErrorAction Stop
        }
    }
    [long]$expandedBytes = 0
    foreach ($plan in $downloadPlans) { $expandedBytes += Assert-Packages $plan }
    if ($DownloadOnly) {
        $arguments = for ($index = 0; $index -lt 3; $index++) {
            $name = @('BasicFile', 'SqlPlusFile', 'OdbcFile')[$index]
            $names = @($plans | ForEach-Object { "'$($_.Files[$index])'" }) -join ','
            "-$name $names"
        }
        Write-Host 'Download complete; packages validated. Offline setup command:'
        $scriptLiteral = $MyInvocation.MyCommand.Path.Replace("'", "''")
        $destinationLiteral = $Destination.Replace("'", "''")
        Write-Host "  & '$scriptLiteral' -Destination '$destinationLiteral' -Version $Version -Architecture $($Architecture -join ',') -PermissionSet $PermissionSet $($arguments -join ' ')"
        return
    }
    Assert-DiskSpace $expandedBytes
}
if ($fullRun -or $ExtractOnly) {
    foreach ($plan in $missingPlans) {
        Write-Host "${newLine}Extract: $($plan.Platform)..."
        Assert-UnregisteredPath $plan.StandardPath @(Get-AllDrivers)
        if (Test-Path -LiteralPath $plan.StandardPath -PathType Container) {
            Get-CheckedTree $plan.StandardPath | Out-Null
        }
        foreach ($file in $plan.Files) {
            $archiveParameters = @{
                LiteralPath = Join-Path $Destination $file
                DestinationPath = Split-Path $plan.StandardPath -Parent
                Force = $true
                ErrorAction = 'Stop'
            }
            Expand-Archive @archiveParameters
        }
        Assert-ClientFiles $plan.StandardPath $plan.Architecture -Installer
    }
    if ($ExtractOnly) { Write-Host 'Extraction complete; no drivers installed or configuration changed.'; return }
}
if ($fullRun -or $InstallOnly) {
    foreach ($plan in $missingPlans) {
        Write-Host "${newLine}Install: $($plan.Platform) at '$($plan.StandardPath)'..."
        $currentDrivers = @(Get-AllDrivers)
        if (@($currentDrivers | Where-Object { $_.Name -ieq $driverName -and $_.Platform -eq $plan.Platform }).Count) {
            throw "A selected registration appeared after PreCheck for $($plan.Platform). Rerun to review it before installation."
        }
        Assert-UnregisteredPath $plan.StandardPath $currentDrivers
        Assert-ClientFiles $plan.StandardPath $plan.Architecture -Installer
        Invoke-OracleExecutable $plan.StandardPath 'odbc_install.exe'
    }
    Assert-CurrentRegistration
    Find-SelectedClients @(Get-AllDrivers) -Required
    foreach ($plan in $missingPlans) {
        if ($plan.ClientDir -ine $plan.StandardPath) {
            throw "Installed registration points to '$($plan.ClientDir)', not '$($plan.StandardPath)'."
        }
    }
    Write-Host '  Installation verified.'
    if ($InstallOnly) { Write-Host 'Install complete; TNS_ADMIN and permissions unchanged.'; return }
}

#endregion

#region Configure and Permissions

if ($fullRun -or $ConfigureOnly) {
    Write-Host "${newLine}Configure: TNS_ADMIN..."
    Assert-CurrentRegistration
    $current = Resolve-TnsFolder
    if ($current.Path -ine $tns.Path -or $current.MachineValue -cne $tns.MachineValue) {
        throw 'Machine TNS_ADMIN changed since PreCheck. Stop and rerun to review the new value.'
    }
    if ([string]::IsNullOrWhiteSpace($tns.MachineValue)) {
        Assert-NoReparsePath $tns.Path
        New-Item -ItemType Directory -Path $tns.Path -Force -ErrorAction Stop | Out-Null
        [Environment]::SetEnvironmentVariable($OracleVariable, $tns.Path, 'Machine')
        $tns.MachineValue = $tns.Path
    } else { Write-Host "  Reusing existing machine TNS_ADMIN='$($tns.MachineValue)'." }
    if ([Environment]::GetEnvironmentVariable($OracleVariable, 'Machine') -cne $tns.MachineValue -or
        -not (Test-Path -LiteralPath $tns.Path -PathType Container)) {
        throw 'TNS_ADMIN configuration verification failed.'
    }
    Write-Host "  Verified TNS_ADMIN folder: '$($tns.Path)'. No configuration files overwritten."
    if ($ConfigureOnly) {
        Write-Host 'Configuration complete. Run PermissionsOnly to grant access; restart relevant services to pick up environment changes.'
        return
    }
}
if ($fullRun -or $PermissionsOnly) {
    Write-Host "${newLine}Permissions: $PermissionSet principals..."
    $current = Resolve-TnsFolder
    if ($current.Path -ine $tns.Path) { throw 'TNS_ADMIN changed since PreCheck. Rerun before granting permissions.' }
    Assert-CurrentRegistration
    Invoke-Permissions
    if ($PermissionsOnly) { Write-Host 'Permissions complete; no environment variables changed.'; return }
}

#endregion

if ([Environment]::GetEnvironmentVariable($OracleVariable, 'Machine') -cne $tns.MachineValue) {
    throw 'Machine TNS_ADMIN changed before completion. Rerun to review configuration and permissions.'
}
Assert-CurrentRegistration

Write-Host -ForegroundColor Cyan @"
================================================================================
SETUP COMPLETE
================================================================================
Client release   : $($VersionConfig[$Version].Release)
Architectures    : $($Architecture -join ', ')
Permission set   : $PermissionSet ($($ServiceUsers -join ', '))
TNS_ADMIN folder : $($tns.Path)

Place tnsnames.ora, sqlnet.ora, and oraaccess.xml here as needed; existing files are preserved.
Review PATH for the selected clients. Restart relevant services or reboot in a maintenance
window to pick up machine environment changes. No services were restarted by this script.
Setup checks do not prove database connectivity; test on the target CPM/SRS connector.

CyberArk Oracle platform:
https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/oracledatabaseplugin.htm
Configure ConnectionCommand under Additional Policy Settings, or use a System DSN
(not a User DSN). Test connectivity with the correct-architecture DSN wizard.
"@
foreach ($plan in $plans) {
    Write-Host @"

[$($plan.Platform)] $($plan.Driver.Name) at $($plan.ClientDir)
  DSN-less with TNSNames:
    Driver={$($plan.Driver.Name)};Dbq=%TNSSERVICENAME%;Uid=%USER%;******;
  DSN-less without TNSNames:
    Driver={$($plan.Driver.Name)};Dbq=//%ADDRESS%:%PORT%/%DATABASE%;Uid=%USER%;******;
"@
}
