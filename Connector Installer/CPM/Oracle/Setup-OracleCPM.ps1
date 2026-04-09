#Requires -Version 5.1
<#
.SYNOPSIS
    Sets up Oracle Instant Client for the CyberArk CPM Oracle Database plugin.

.DESCRIPTION
    Downloads, installs, and configures Oracle Instant Client packages required by
    the CyberArk CPM Oracle Database plugin. Performs the following steps:

      1. Downloads Oracle Instant Client packages: BasicLite, SQL*Plus, ODBC
      2. Extracts packages to the destination folder
      3. Runs the Oracle ODBC driver installer
      4. Grants PluginManagerUser and PasswordManagerUser filesystem permissions:
           - Traverse on all parent folders up to (not including) the drive root
           - Read/Execute on each Instant Client folder and the TNS_ADMIN folder
      5. Creates a central TNS_ADMIN configuration folder
      6. Sets the TNS_ADMIN machine-level environment variable
      7. Outputs ConnectionCommand values to configure in the CyberArk Oracle platform

.PARAMETER Destination
    Folder where Oracle Instant Client will be installed. Must already exist.
    Default: C:\Oracle\

.PARAMETER Architecture
    Bitness of Oracle Instant Client to install. Accepts '32', '64', or both.
    The CyberArk CPM Oracle plugin currently requires the 32-bit ODBC driver.
    Specify both values when migrating the CPM from 32-bit to 64-bit.
    Default: 32

.PARAMETER Download
    Download the Oracle Instant Client zip files from Oracle before configuring.

.PARAMETER Stage
    Download the zip files to the destination folder, then exit without configuring.
    Use this to pre-stage files on a machine that has internet access.

.PARAMETER Resume
    Skip download, file verification, extraction, and ODBC installer.
    Use when the ODBC driver is already installed but configuration steps need to run.

.EXAMPLE
    .\Setup-OracleCPM.ps1 -Destination 'C:\Oracle\' -Download

    Downloads and configures 32-bit Oracle Instant Client.

.EXAMPLE
    .\Setup-OracleCPM.ps1 -Destination 'C:\Oracle\' -Download -Architecture 32,64

    Downloads and configures both 32-bit and 64-bit Oracle Instant Client.

.EXAMPLE
    .\Setup-OracleCPM.ps1 -Destination 'C:\Oracle\' -Stage -Architecture 32,64

    Pre-stages all zip files; run without -Stage to complete the installation.

.EXAMPLE
    .\Setup-OracleCPM.ps1 -Destination 'C:\Oracle\' -Resume

    Re-runs only the configuration steps, skipping download and extraction.

.NOTES
    Version:        2.0
    Purpose/Change: Refactored with dual-architecture support, improved structure and error handling.
    Reference:      https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/oracledatabaseplugin.htm
#>
[CmdletBinding()]
param (
    [Parameter()]
    [ValidateScript({ Test-Path $PSItem })]
    [string]$Destination = 'C:\Oracle\',

    [Parameter()]
    [ValidateSet('32', '64')]
    [string[]]$Architecture = @('32'),

    [Parameter()]
    [switch]$Download,

    [Parameter()]
    [switch]$Stage,

    [Parameter()]
    [switch]$Resume
)

$Destination        = (Get-Item -Path $Destination).FullName
$OracleVariable     = 'TNS_ADMIN'
$OracleConfigFolder = Join-Path $Destination 'TNS_ADMIN'
$DriveRoot          = (Split-Path $Destination -Qualifier) + '\'

# Download URL configuration.
# 32-bit: Oracle publishes permanent redirect links that always resolve to the latest release.
# 64-bit: Oracle does not publish permanent links for 64-bit. Update the folder number and
#         file version below when a new release is listed at:
#         https://www.oracle.com/database/technologies/instant-client/winx64-64-downloads.html
$ArchConfig = @{
    '32' = @{
        Urls         = [string[]]@(
            'https://download.oracle.com/otn_software/nt/instantclient/instantclient-basiclite-nt.zip'
            'https://download.oracle.com/otn_software/nt/instantclient/instantclient-sqlplus-nt.zip'
            'https://download.oracle.com/otn_software/nt/instantclient/instantclient-odbc-nt.zip'
        )
        OdbcPlatform = '32-bit'
    }
    '64' = @{
        Urls         = [string[]]@(
            'https://download.oracle.com/otn_software/nt/instantclient/2326000/instantclient-basiclite-windows.x64-23.26.1.0.0.zip'
            'https://download.oracle.com/otn_software/nt/instantclient/2326000/instantclient-sqlplus-windows.x64-23.26.1.0.0.zip'
            'https://download.oracle.com/otn_software/nt/instantclient/2326000/instantclient-odbc-windows.x64-23.26.1.0.0.zip'
        )
        OdbcPlatform = '64-bit'
    }
}

[string[]]$CPMUsers = @('PluginManagerUser', 'PasswordManagerUser')
[string[]]$AllUrls  = foreach ($arch in $Architecture) { $ArchConfig[$arch].Urls }

#region Helper Functions

function Get-WebFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Uri
    )
    process {
        $outFile = Join-Path $Destination (Split-Path $Uri -Leaf)
        Write-Host "  Downloading $(Split-Path $Uri -Leaf)..."
        Invoke-WebRequest -Uri $Uri -OutFile $outFile
    }
}

function Update-Perms {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$UserName,

        [Parameter(Mandatory)]
        [string]$Location,

        [Parameter(Mandatory)]
        [ValidateSet('Read', 'Transverse')]
        [string]$Perms
    )
    process {
        try {
            if ($Perms -eq 'Read') {
                $rule = New-Object Security.AccessControl.FileSystemAccessRule $UserName, 'ReadAndExecute, Synchronize', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
            } else {
                $rule = New-Object Security.AccessControl.FileSystemAccessRule $UserName, 'ExecuteFile, Synchronize', 'Allow'
            }
            $acl = Get-Acl -Path $Location
            $acl.AddAccessRule($rule)
            Write-Host "  Granting $Perms on `"$Location`" to `"$UserName`""
            $acl | Set-Acl -Path $Location -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "Could not grant $Perms on `"$Location`" to `"$UserName`". Grant this access manually."
        }
    }
}

#endregion

#region Step 1: Download

if ($Download -or $Stage) {
    Write-Host "`nStep 1: Downloading Oracle Instant Client packages..."
    $AllUrls | Get-WebFile
}

if ($Stage) {
    Write-Host "`nFiles staged to `"$Destination`"."
    Write-Host "To complete setup, run:"
    Write-Host "  $($MyInvocation.MyCommand.Path) -Destination `"$Destination`" -Architecture $($Architecture -join ',')"
    return
}

#endregion

#region Steps 2-4: Verify, Extract, Install

if (-not $Resume) {
    Write-Host "`nStep 2: Verifying downloaded files..."
    $missingFiles = @(foreach ($url in $AllUrls) {
        $fileName = Split-Path $url -Leaf
        if (-not (Test-Path -Path (Join-Path $Destination $fileName))) { $fileName }
    })

    if ($missingFiles.Count -gt 0) {
        Write-Host -ForegroundColor Red "  The following files are missing from `"$Destination`":"
        foreach ($file in $missingFiles) { Write-Host -ForegroundColor Red "    $file" }
        Write-Host -ForegroundColor Red "  Run with -Download to fetch missing files, or copy them to `"$Destination`" manually."
        exit 1
    }
    Write-Host "  All files present."

    Write-Host "`nStep 3: Extracting packages..."
    foreach ($url in $AllUrls) {
        $fileName = Split-Path $url -Leaf
        Write-Host "  Extracting $fileName..."
        Expand-Archive -Path (Join-Path $Destination $fileName) -DestinationPath $Destination -Force
    }

    Write-Host "`nStep 4: Installing Oracle ODBC driver(s)..."
    $installDirs = @(
        Get-ChildItem -Directory -Path $Destination -Filter 'instantclient*' |
            Where-Object { Test-Path -Path (Join-Path $PSItem.FullName 'odbc_install.exe') }
    )

    if ($installDirs.Count -eq 0) {
        Write-Host -ForegroundColor Red "  ERROR: No odbc_install.exe found under `"$Destination\instantclient*`"."
        Write-Host -ForegroundColor Red "  Run odbc_install.exe manually from the instantclient folder, then re-run with -Resume."
        exit 1
    }

    foreach ($dir in $installDirs) {
        Write-Host "  Installing from: $($dir.FullName)"
        Start-Process -FilePath (Join-Path $dir.FullName 'odbc_install.exe') -WorkingDirectory $dir.FullName -Wait
    }
} else {
    Write-Host "`nSteps 2-4: Skipped (Resume mode)."
}

#endregion

#region Step 5: Verify ODBC Installation

Write-Host "`nStep 5: Verifying ODBC driver installation..."
[string[]]$expectedPlatforms = foreach ($arch in $Architecture) { $ArchConfig[$arch].OdbcPlatform }
$installedDrivers = @(
    Get-OdbcDriver | Where-Object { $PSItem.Name -like 'Oracle*' -and $PSItem.Platform -in $expectedPlatforms }
)

if ($installedDrivers.Count -eq 0) {
    $clientDirs = (
        Get-ChildItem -Directory -Path $Destination -Filter 'instantclient*' |
            Select-Object -ExpandProperty FullName
    ) -join "`n    "
    Write-Host -ForegroundColor Red "  ERROR: No Oracle ODBC driver found for platform(s): $($expectedPlatforms -join ', ')"
    Write-Host -ForegroundColor Red "  Manually run odbc_install.exe from:"
    Write-Host -ForegroundColor Red "    $clientDirs"
    Write-Host -ForegroundColor Red "  Then re-run with -Resume."
    exit 1
}

foreach ($driver in $installedDrivers) {
    Write-Host "  Found: '$($driver.Name)' [$($driver.Platform)]"
}

#endregion

#region Step 6: Grant Permissions

Write-Host "`nStep 6: Granting CPM service account permissions..."
$instantclientDirs = @(
    Get-ChildItem -Directory -Path $Destination -Filter 'instantclient*' |
        Select-Object -ExpandProperty FullName
)

# Use a visited set to avoid redundant ACL writes when multiple instantclient dirs share the same parents
$visitedPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($clientDir in $instantclientDirs) {
    # Walk up from the instantclient folder and grant traverse on each ancestor (stopping before drive root)
    $workPath = $clientDir
    while (-not [string]::IsNullOrEmpty($workPath)) {
        $workPath = Split-Path $workPath -Parent
        if ([string]::IsNullOrEmpty($workPath) -or $workPath -eq $DriveRoot) { break }
        if ($visitedPaths.Add($workPath)) {
            $CPMUsers | Update-Perms -Location $workPath -Perms 'Transverse'
        }
    }
    $CPMUsers | Update-Perms -Location $clientDir -Perms 'Read'
}

#endregion

#region Step 7: Configure TNS_ADMIN

Write-Host "`nStep 7: Configuring TNS_ADMIN..."
New-Item -ItemType Directory -Path $OracleConfigFolder -Force | Out-Null
[System.Environment]::SetEnvironmentVariable($OracleVariable, $OracleConfigFolder, [System.EnvironmentVariableTarget]::Machine)
Write-Host "  Created: `"$OracleConfigFolder`""
Write-Host "  Set machine environment variable: $OracleVariable = `"$OracleConfigFolder`""
$CPMUsers | Update-Perms -Location $OracleConfigFolder -Perms 'Read'

#endregion

#region Step 8: Output Platform Configuration

$connectionStrings = foreach ($driver in $installedDrivers) {
    $cmdTNS   = 'Driver={};Dbq=%TNSSERVICENAME%;Uid=%USER%;Pwd=%LOGONPASSWORD%;'   -replace 'Driver={.*}', "Driver={$($driver.Name)}"
    $cmdNoTNS = 'Driver={};Dbq=//%ADDRESS%:%PORT%/%DATABASE%;Uid=%USER%;Pwd=%LOGONPASSWORD%;' -replace 'Driver={.*}', "Driver={$($driver.Name)}"
    @"
  [$($driver.Platform)] $($driver.Name)
    DSN-less with TNSNames:
      $cmdTNS
    DSN-less without TNSNames:
      $cmdNoTNS
"@
}

Write-Host -ForegroundColor Cyan @"
================================================================================
SETUP COMPLETE
================================================================================

TNS_ADMIN Folder : "$OracleConfigFolder"
Environment Var  : $OracleVariable (machine scope, effective after reboot or new logon)

Place Oracle configuration files in the TNS_ADMIN folder as needed:
  tnsnames.ora   - required for TNSNames connection methods
  sqlnet.ora     - optional network configuration
  oraaccess.xml  - optional client-side result cache

--------------------------------------------------------------------------------
CyberArk Platform Configuration
https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/oracledatabaseplugin.htm

In Platform Management, open the Oracle Database platform.
Go to Additional Policy Settings to configure the ConnectionCommand parameter.

Method 1 - DSN:
  Create a System DSN (not a User DSN) for each Oracle database on this machine.
  Test connectivity using the DSN wizard before saving.

Method 2 and 3 - DSN-less ConnectionCommand values:
$($connectionStrings -join '')
================================================================================
"@

#endregion
