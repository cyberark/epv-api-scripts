<#
.SYNOPSIS
    Helper script providing remote-execution functions for CyberArk component credential resets.

.DESCRIPTION
    This script is NOT intended to be run directly. It is consumed in two ways:
      1. Dot-sourced locally by Invoke-CredFileReset.ps1 so that its functions are
         available in the orchestrator's local scope.
      2. Loaded into remote PSSessions via Invoke-Command -FilePath so that its functions
         execute inside the WinRM-connected component server.

    Because this script runs inside remote PSSessions it must not depend on PVWA REST API
    calls, network calls outside the remote machine, external modules, or $Script: variables
    set only in Invoke-CredFileReset.ps1. All REST communication stays on the orchestrating
    machine in Invoke-CredFileReset.ps1.

    Functions provided:
      Write-LogMessage           -  Console and file logging with type-based colour coding
      Join-ExceptionMessage      -  Formats an exception chain into a single readable string
      Get-FileVersion            -  Reads ProductVersion from a file's VersionInfo
      Get-ServiceInstallPath     -  Reads a service's executable path from the Windows registry
      Find-WinComponents         -  Discovers installed CyberArk components on the local machine
      Stop-ServiceProcess        -  Force-kills a service and its underlying process via CIM
      New-RandomPassword         -  Generates a cryptographically random password
      Convert-SecureString       -  Converts a SecureString to a plain-text string
      Start-ComponentService     -  Starts a Windows service with configurable retry logic
      Stop-ComponentService      -  Stops a Windows service with force-kill fallback
      Reset-WinCredFile          -  Invokes CreateCredFile.exe to regenerate credential files
      Reset-VaultFile            -  Updates Vault or API address entries in vault.ini

.NOTES
    Version:    1.0
    Authors:    Brian Bors <brian.bors@cyberark.com>
                Assaf Miron <assaf.miron@cyberark.com>

    Requires:   PowerShell 5.1+

    Do not add functions to this script that depend on PVWA REST API calls, external modules,
    or $Script: variables that are only set in Invoke-CredFileReset.ps1.

    Change Log:
    2020-09-13  Initial version
    2026-03-27  Refactored  -  extracted from CyberArk-Common.psm1 into a standalone script
                compatible with Invoke-Command -FilePath remote loading
#>

#Requires -Version 5.1

#region Component Definitions

# Windows service names for each component type.
# Passed to Start-ComponentService / Stop-ComponentService.
$Script:CpmServices  = @('CyberArk Password Manager', 'CyberArk Central Policy Manager Scanner')
$Script:PvwaServices = @('CyberArk Scheduled Tasks', 'W3SVC', 'IISADMIN')
$Script:PsmServices  = @('*Privileged Session Manager')
$Script:AamServices  = @('CyberArk Application Password Provider')

# Log file paths relative to each component's install directory.
# Keyed by component type → log file name → path (relative to install dir, or absolute).
# Used by Get-ComponentLog to resolve log file names to full paths on the remote machine.
# Absolute paths (PVWA temp logs) are passed as-is by [System.IO.Path]::Combine.
# Source: https://community.cyberark.com/s/article/Where-do-I-find-the-logs
$Script:LogPaths = @{
    PSM  = @{
        'PSMConsole.log' = 'Logs\PSMConsole.log'
        'PSMTrace.log'   = 'Logs\PSMTrace.log'
    }
    CPM  = @{
        'PMConsole.log'      = 'Logs\PMConsole.log'
        'PMTrace.log'        = 'Logs\PMTrace.log'
        'pm.log'             = 'Logs\pm.log'
        'pm_error.log'       = 'Logs\pm_error.log'
        'CACPMScanner.log'   = 'Logs\CACPMScanner.log'
        'Casos.Activity.log' = 'Logs\Casos.Activity.log'
        'Casos.Debug.log'    = 'Logs\Casos.Debug.log'
        'Casos.Error.log'    = 'Logs\Casos.Error.log'
    }
    PVWA = @{
        # Logs written to Windows temp by the ASP.NET app pool
        'CyberArk.WebApplication.log' = 'C:\Windows\Temp\pvwa\CyberArk.WebApplication.log'
        'CyberArk.WebTasksEngine.log' = 'C:\Windows\Temp\pvwa\CyberArk.WebTasksEngine.log'
        'PVWA.App.Log'                = 'C:\Windows\Temp\pvwa\PVWA.App.Log'
        'Cyberark.Reports.log'        = 'C:\Windows\Temp\pvwa\Cyberark.Reports.log'
        # Logs written by the Windows service under the install directory
        'CyberArk.WebConsole.log'     = 'Services\Logs\CyberArk.WebConsole.log'
        'CyberArk.WebTasksService.log'= 'Services\Logs\CyberArk.WebTasksService.log'
    }
    AIM  = @{
        'APPConsole.log' = 'Logs\APPConsole.log'
        'APPTrace.log'   = 'Logs\APPTrace.log'
        'APPAudit.log'   = 'Logs\APPAudit.log'
    }
}

# CreateCredFile.exe command templates, keyed by component type and version band.
#   {0} = CyberArk username   (read from the existing cred file)
#   {1} = new plaintext password
$Script:CredCommands = @{
    AIM  = @{
        Legacy           = '.\CreateCredFile.exe AppProviderUser.cred Password /AppType AppPrv /IpAddress /Hostname /Username {0} /Password {1}'
        v12              = '.\CreateCredFile.exe AppProviderUser.cred Password /AppType AppPrv /IpAddress /Hostname /EntropyFile /DPAPIMachineProtection /Username {0} /Password {1}'
        VersionThreshold = [version]'12.0'
    }
    CPM  = @{
        Legacy           = '.\CreateCredFile.exe user.ini Password /AppType CPM /IpAddress /Hostname /Username {0} /Password {1}'
        v12              = '.\CreateCredFile.exe user.ini Password /AppType CPM /EntropyFile /DPAPIMachineProtection /IpAddress /Hostname /Username {0} /Password {1}'
        VersionThreshold = [version]'12.1'
    }
    PSM  = @{
        App = @{
            Legacy           = '.\CreateCredFile.exe psmapp.cred Password /AppType PSMApp /IpAddress /Hostname /Username {0} /Password {1}'
            v12              = '.\CreateCredFile.exe psmapp.cred Password /AppType PSMApp /EntropyFile /DPAPIMachineProtection /IpAddress /Hostname /Username {0} /Password {1}'
            VersionThreshold = [version]'12.1'
        }
        GW  = @{
            Legacy           = '.\CreateCredFile.exe psmgw.cred Password /AppType PSMApp /IpAddress /Hostname /Username {0} /Password {1}'
            v12              = '.\CreateCredFile.exe psmgw.cred Password /AppType PSMApp /EntropyFile /DPAPIMachineProtection /IpAddress /Hostname /Username {0} /Password {1}'
            VersionThreshold = [version]'12.1'
        }
    }
    PVWA = @{
        App = @{
            Legacy           = '.\CreateCredFile.exe ..\CredFiles\appuser.ini Password /AppType PVWAApp /IpAddress /Hostname /ExePath "C:\Windows\System32\inetsrv\w3wp.exe" /Username {0} /Password {1}'
            v12              = '.\CreateCredFile.exe ..\CredFiles\appuser.ini Password /AppType PVWAApp /IpAddress /Hostname /ExePath "C:\Windows\System32\inetsrv\w3wp.exe" /EntropyFile /DPAPIMachineProtection /Username {0} /Password {1}'
            VersionThreshold = [version]'12.1'
        }
        GW  = @{
            Legacy           = '.\CreateCredFile.exe ..\CredFiles\gwuser.ini Password /AppType PVWAApp /IpAddress /Hostname /ExePath "C:\Windows\System32\inetsrv\w3wp.exe" /Username {0} /Password {1}'
            v12              = '.\CreateCredFile.exe ..\CredFiles\gwuser.ini Password /AppType PVWAApp /IpAddress /Hostname /ExePath "C:\Windows\System32\inetsrv\w3wp.exe" /EntropyFile /DPAPIMachineProtection /Username {0} /Password {1}'
            VersionThreshold = [version]'12.1'
        }
    }
}

#endregion

Function Write-LogMessage {
    <#
.SYNOPSIS
Method to log a message on screen and in a log file
.DESCRIPTION
Logging The input Message to the Screen and the Log File.
The Message Type is presented in colours on the screen based on the type
.PARAMETER LogFile
The Log File to write to. By default using the LOG_FILE_PATH
.PARAMETER MSG
The message to log
.PARAMETER Header
Adding a header line before the message
.PARAMETER SubHeader
Adding a Sub header line before the message
.PARAMETER Footer
Adding a footer line after the message
.PARAMETER Type
The type of the message to log (Info, Warning, Error, Debug)
#>
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [Switch]$Header,
        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory = $false)]
        [Switch]$Footer,
        [Parameter(Mandatory = $false)]
        [Bool]$WriteLog = $true,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Debug", "Verbose", "Success", "LogOnly")]
        [String]$type = "Info",
        [Parameter(Mandatory = $false)]
        [String]$LogFile = $LOG_FILE_PATH
    )

    If (![string]::IsNullOrEmpty($PSSenderInfo)) {
        $WriteLog = $false
    }
    Try {
        If ([string]::IsNullOrEmpty($LogFile) -and $WriteLog) {
            # User wanted to write logs, but did not provide a log file - Create a temporary file
            $LogFile = Join-Path -Path $ENV:Temp -ChildPath "$((Get-Date).ToShortDateString().Replace('/','_')).log"
            Write-Host "No log file path inputted, created a temporary file at: '$LogFile'"
        }
        If ($Header -and $WriteLog) {
            "=======================================" | Out-File -Append -FilePath $LogFile
            Write-Host "=======================================" -ForegroundColor Magenta
        }
        ElseIf ($SubHeader -and $WriteLog) {
            "------------------------------------" | Out-File -Append -FilePath $LogFile
            Write-Host "------------------------------------" -ForegroundColor Magenta
        }

        # Replace empty message with 'N/A'
        if ([string]::IsNullOrEmpty($Msg)) {
            $Msg = "N/A"
        }
        $msgToWrite = ""

        # Mask Passwords
        if ($Msg -match '((?:password|credentials|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()-_\=\+\\\/|;:\.,\[\]{}]+))') {
            $Msg = $Msg.Replace($Matches[2], "****")
        }
        # Check the message type
        switch ($type) {
            { ($_ -eq "Info") -or ($_ -eq "LogOnly") } {
                If ($_ -eq "Info") {
                    Write-Host $MSG.ToString() -ForegroundColor $(If ($Header -or $SubHeader) { "Magenta" } Else { "Gray" })
                }
                $msgToWrite = "[INFO]`t$Msg"
                break
            }
            "Success" {
                Write-Host $MSG.ToString() -ForegroundColor Green
                $msgToWrite = "[SUCCESS]`t$Msg"
                break
            }
            "Warning" {
                Write-Host $MSG.ToString() -ForegroundColor Yellow
                $msgToWrite = "[WARNING]`t$Msg"
                break
            }
            "Error" {
                Write-Host $MSG.ToString() -ForegroundColor Red
                $msgToWrite = "[ERROR]`t$Msg"
                break
            }
            "Debug" {
                if ($InDebug -or $InVerbose) {
                    Write-Debug $MSG
                    $msgToWrite = "[Debug]`t$Msg"
                }
                break
            }
            "Verbose" {
                if ($InVerbose) {
                    Write-Verbose $MSG
                    $msgToWrite = "[VERBOSE]`t$Msg"
                }
                break
            }
        }

        If ($WriteLog) {
            If (![string]::IsNullOrEmpty($msgToWrite)) {
                "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t$msgToWrite" | Out-File -Append -FilePath $LogFile
            }
        }
        If ($Footer -and $WriteLog) {
            "=======================================" | Out-File -Append -FilePath $LogFile
            Write-Host "=======================================" -ForegroundColor Magenta
        }
    }
    catch {
        Throw $(New-Object System.Exception ("Cannot write message"), $_.Exception)
    }
}

Function Join-ExceptionMessage {
    <#
.SYNOPSIS
Formats exception messages
.DESCRIPTION
Formats exception messages
.PARAMETER Exception
The Exception object to format
#>
    param(
        [Exception]$e
    )

    Begin {
    }
    Process {
        $msg = "Source:{0}; Message: {1}" -f $e.Source, $e.Message
        while ($e.InnerException) {
            $e = $e.InnerException
            $msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
        }
        return $msg
    }
    End {
    }
}

Function Get-FileVersion {
    <#
.SYNOPSIS
Method to return a file version
.DESCRIPTION
Returns the File version and Build number
Returns Null if not found
.PARAMETER FilePath
The path to the file to query
#>
    param ($filePath)
    Begin {
    }
    Process {
        $retFileVersion = $Null
        try {
            If (($null -ne $filePath) -and (Test-Path $filePath)) {
                $path = Resolve-Path $filePath
                $retFileVersion = ($path | Get-Item | Select-Object VersionInfo).VersionInfo.ProductVersion
            }
            else {
                throw "File path is empty"
            }

            return $retFileVersion
        }
        catch {
            Throw $(New-Object System.Exception ("Cannot get File ($filePath) version", $_.Exception))
        }
        finally {
        }
    }
    End {
    }
}

Function Get-ServiceInstallPath {
    <#
.SYNOPSIS
Get the installation path of a service
.DESCRIPTION
The function receive the service name and return the path or returns NULL if not found
.EXAMPLE
(Get-ServiceInstallPath $<ServiceName>) -ne $NULL
.PARAMETER ServiceName
The service name to query. Just one.
#>
    param ($ServiceName)
    Begin {
    }
    Process {
        $retInstallPath = $Null
        try {
            if ($null -eq $m_ServiceList) {
                Set-Variable -Name m_ServiceList -Value $(Get-ChildItem "HKLM:\System\CurrentControlSet\Services" | ForEach-Object { Get-ItemProperty $_.pspath }) -Scope Script
                Write-LogMessage -Type "Verbose" -MSG "Service $ServiceName has a registry path of $m_ServiceList"
            }
            $regPath = $m_ServiceList | Where-Object { $_.PSChildName -eq $ServiceName }
            If ($Null -ne $regPath) {
                $retInstallPath = $regPath.ImagePath.Substring($regPath.ImagePath.IndexOf('"'), $regPath.ImagePath.LastIndexOf('"') + 1)
                Write-LogMessage -Type "Verbose" -MSG "Service $ServiceName has a installation location of $retInstallPath"
            }
        }
        catch {
            Throw $(New-Object System.Exception ("Cannot get Service Install path for $ServiceName", $_.Exception))
        }
        return $retInstallPath
    }
    End {
    }
}

Function Find-WinComponents {
    <#
.SYNOPSIS
Method to query a local server for CyberArk components
.DESCRIPTION
Detects all CyberArk Components installed on the local server
#>
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "Vault", "CPM", "PVWA", "PSM", "AIM", "EPM", "SecureTunnel")]
        [String]$Component = "All"
    )

    Begin {
        $retArrComponents = @()
        # COMPONENTS SERVICE NAMES
        $REGKEY_VAULTSERVICE_NEW = "CyberArk Logic Container"
        $REGKEY_VAULTSERVICE_OLD = "Cyber-Ark Event Notification Engine"
        $REGKEY_CPMSERVICE_NEW = "CyberArk Central Policy Manager Scanner"
        $REGKEY_CPMSERVICE_OLD = "CyberArk Password Manager"
        $REGKEY_PVWASERVICE = "CyberArk Scheduled Tasks"
        $REGKEY_PSMSERVICEOLD = "Cyber-Ark Privileged Session Manager"
        $REGKEY_PSMSERVICE = "CyberArk Privileged Session Manager"
        $REGKEY_AIMSERVICE = "CyberArk Application Password Provider"
        $REGKEY_EPMSERVICE = "VfBackgroundWorker"
        $REGKEY_SECURETUNNELSERVICE = "CyberArkPrivilegeCloudSecureTunnel"
    }
    Process {
        if (![string]::IsNullOrEmpty($Component)) {
            Switch ($Component) {
                "Vault" {
                    try {
                        Write-LogMessage -Type "Debug" -MSG "Searching for Vault..."
                        if (($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_VAULTSERVICE_OLD))) -or ($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_VAULTSERVICE_NEW)))) {
                            Write-LogMessage -Type "Debug" -MSG "Found Vault installation"
                            $vaultPath = $componentPath.Replace("LogicContainer\BLServiceApp.exe", "").Replace("Event Notification Engine\ENE.exe", "").Replace('"', "").Trim()
                            $fileVersion = Get-FileVersion "$vaultPath\dbmain.exe"
                            return New-Object PSObject -Property @{Name = "Vault"; Path = $vaultPath; Version = $fileVersion }
                        }
                    }
                    catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "CPM" {
                    try {
                        Write-LogMessage -Type "Debug" -MSG "Searching for CPM..."
                        if (($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_CPMSERVICE_OLD))) -or ($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_CPMSERVICE_NEW)))) {
                            Write-LogMessage -Type "Debug" -MSG "Found CPM installation"
                            $cpmPath = $componentPath.Replace("Scanner\CACPMScanner.exe", "").Replace("PMEngine.exe", "").Replace("/SERVICE", "").Replace('"', "").Trim()
                            $fileVersion = Get-FileVersion "$cpmPath\PMEngine.exe"
                            return New-Object PSObject -Property @{Name = "CPM"; Path = $cpmPath; Version = $fileVersion }
                        }
                    }
                    catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "PVWA" {
                    try {
                        Write-LogMessage -Type "Debug" -MSG "Searching for PVWA..."
                        if ($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_PVWASERVICE))) {
                            Write-LogMessage -Type "Debug" -MSG "Found PVWA installation"
                            $pvwaPath = $componentPath.Replace("Services\CyberArkScheduledTasks.exe", "").Replace('"', "").Trim()
                            $fileVersion = Get-FileVersion "$pvwaPath\Services\CyberArkScheduledTasks.exe"
                            return New-Object PSObject -Property @{Name = "PVWA"; Path = $pvwaPath; Version = $fileVersion }
                        }
                    }
                    catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "PSM" {
                    try {
                        Write-LogMessage -Type "Debug" -MSG "Searching for PSM..."
                        If (![string]::IsNullOrEmpty($(Get-ServiceInstallPath $REGKEY_PSMSERVICE))) {
                            $componentPath = $(Get-ServiceInstallPath $REGKEY_PSMSERVICE)
                        }
                        else {
                            $componentPath = $(Get-ServiceInstallPath $REGKEY_PSMSERVICEOLD)
                        }
                        if ($NULL -ne $componentPath) {
                            Write-LogMessage -Type "Debug" -MSG "Found PSM installation"
                            $PSMPath = $componentPath.Replace("CAPSM.exe", "").Replace('"', "").Trim()
                            $fileVersion = Get-FileVersion "$PSMPath\CAPSM.exe"
                            return New-Object PSObject -Property @{Name = "PSM"; Path = $PSMPath; Version = $fileVersion }
                        }
                    }
                    catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "AIM" {
                    try {
                        Write-LogMessage -Type "Debug" -MSG "Searching for AIM..."
                        if ($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_AIMSERVICE))) {
                            Write-LogMessage -Type "Debug" -MSG "Found AIM installation"
                            $AIMPath = $componentPath.Replace("/mode SERVICE", "").Replace("AppProvider.exe", "").Replace('"', "").Trim()
                            $fileVersion = Get-FileVersion "$AIMPath\AppProvider.exe"
                            return New-Object PSObject -Property @{Name = "AIM"; Path = $AIMPath; Version = $fileVersion }
                        }
                    }
                    catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "EPM" {
                    try {
                        Write-LogMessage -Type "Debug" -MSG "Searching for EPM Server..."
                        if ($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_EPMSERVICE))) {
                            Write-LogMessage -Type "Debug" -MSG "Found EPM Server installation"
                            $EPMPath = $componentPath.Replace("VfBackgroundWorker.exe", "").Replace('"', "").Trim()
                            $fileVersion = Get-FileVersion "$EPMPath\VfBackgroundWorker.exe"
                            return New-Object PSObject -Property @{Name = "EPM"; Path = $EPMPath; Version = $fileVersion }
                        }
                    }
                    catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "SecureTunnel" {
                    try {
                        Write-LogMessage -Type "Debug" -MSG "Searching for Privilege Cloud Secure tunnel..."
                        if ($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_SECURETUNNELSERVICE))) {
                            Write-LogMessage -Type "Debug" -MSG "Found Privilege Cloud Secure tunnel installation"
                            $tunnelPath = $componentPath.Replace("PrivilegeCloudSecureTunnel.exe", "").Replace('"', "").Trim()
                            $fileVersion = Get-FileVersion "$tunnelPath\PrivilegeCloudSecureTunnel.exe"
                            return New-Object PSObject -Property @{Name = "SecureTunnel"; Path = $tunnelPath; Version = $fileVersion }
                        }
                    }
                    catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "All" {
                    try {
                        ForEach ($comp in @("Vault", "CPM", "PVWA", "PSM", "AIM", "EPM", "SecureTunnel")) {
                            $retArrComponents += Find-WinComponents -Component $comp
                        }
                        return $retArrComponents
                    }
                    catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting components. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
            }
        }
    }
    End {
    }
}

Function Stop-ServiceProcess {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True, ValuefromPipeline = $True)]
        [string[]]$name
    )

    Process {
        $id = Get-CimInstance -ClassName Win32_Service -Filter "Name LIKE '$name'" | Select-Object -ExpandProperty ProcessId
        if (0 -ne $id) {
            Stop-Process -Id $id -Force
        }
    }
}

Function New-RandomPassword {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidatePattern('[0-9]+')]
        [ValidateRange(1, 100)]
        [uint32]$Length,

        [Parameter(Mandatory = $false)]
        [switch]$Lowercase = $false,

        [Parameter(Mandatory = $false)]
        [switch]$Uppercase = $false,

        [Parameter(Mandatory = $false)]
        [switch]$Numbers = $false,

        [Parameter(Mandatory = $false)]
        [switch]$Symbols = $false
    )
    Begin {
        if (-not($Lowercase -or $Uppercase -or $Numbers -or $Symbols)) {
            throw "You must specify one of: -Lowercase -Uppercase -Numbers -Symbols"
        }

        $CHARSET_LOWER = 1
        $CHARSET_UPPER = 2
        $CHARSET_NUMBER = 4
        $CHARSET_SYMBOL = 8

        $charsLower = 97..122 | ForEach-Object { [Char] $_ }
        $charsUpper = 65..90 | ForEach-Object { [Char] $_ }
        $charsNumber = 48..57 | ForEach-Object { [Char] $_ }
        $charsSymbol = 33, 37, 42, 43, 45, 46, 95 | ForEach-Object { [Char] $_ }
    }
    Process {
        $charList = @()
        $charSets = 0
        if ($Lowercase) {
            $charList += $charsLower
            $charSets = $charSets -bor $CHARSET_LOWER
        }
        if ($Uppercase) {
            $charList += $charsUpper
            $charSets = $charSets -bor $CHARSET_UPPER
        }
        if ($Numbers) {
            $charList += $charsNumber
            $charSets = $charSets -bor $CHARSET_NUMBER
        }
        if ($Symbols) {
            $charList += $charsSymbol
            $charSets = $charSets -bor $CHARSET_SYMBOL
        }

        function Test-StringContents([String] $test, [Char[]] $chars) {
            foreach ($char in $test.ToCharArray()) {
                if ($chars -ccontains $char) {
                    return $true
                }
            }
            return $false
        }

        do {
            $flags = 0
            $output = ""
            1..$Length | ForEach-Object { $output += $charList[(Get-Random -Maximum $charList.Length)] }

            if ($Lowercase) {
                if (Test-StringContents $output $charsLower) { $flags = $flags -bor $CHARSET_LOWER }
            }
            if ($Uppercase) {
                if (Test-StringContents $output $charsUpper) { $flags = $flags -bor $CHARSET_UPPER }
            }
            if ($Numbers) {
                if (Test-StringContents $output $charsNumber) { $flags = $flags -bor $CHARSET_NUMBER }
            }
            if ($Symbols) {
                if (Test-StringContents $output $charsSymbol) { $flags = $flags -bor $CHARSET_SYMBOL }
            }
        }
        until ($flags -eq $charSets)
    }
    End {
        $output
    }
}

Function Convert-SecureString {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [secureString]$secureString
    )

    Process {
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }
}

function Start-ComponentService {
    param (
        [Parameter(Mandatory = $true)]
        [array]$services,

        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$session,

        [Parameter(Mandatory = $false)]
        [int]$wait = 1,

        [Parameter(Mandatory = $false)]
        [int]$attempts = 1
    )

    ForEach ($service in $services) {
        $running = $false
        $attemptCount = 0
        While (!$running) {
            Write-LogMessage -Type "Debug" -MSG "Attempting to start `"$service`" on $server"
            Invoke-Command -Session $session -ScriptBlock {
                $targetService = Get-Service -Name $args[0];
                If ($targetService.Status -ne "Running") {
                    $targetService.start();
                    $targetService.WaitForStatus('Running', (New-TimeSpan -Seconds 20))
                }
            } -ArgumentList $service -ErrorAction SilentlyContinue -ErrorVariable startResult

            if ("0" -ne $startResult.Count) {
                $attemptCount += 1
                if ($attemptCount -ge $attempts) {
                    Write-LogMessage -Type "Error" -MSG "Failed to start `"$service`" on $server after $attempts attempt(s)"
                    return $false
                }
                Write-LogMessage -Type "Debug" -MSG "Unable to start $service on $server, attempting force restart processes. Attempt $attemptCount"
                $null = Invoke-Command -Session $session -ScriptBlock { Stop-ServiceProcess -name $args[0] } -ArgumentList $service
                Start-Sleep 1
                $startResult.clear()
            }
            else {
                $running = $true
                Write-LogMessage -Type Debug -MSG "`"$service`" on $server Started"
                Start-Sleep -Seconds $wait
            }
        }
    }
    return $true
}

function Stop-ComponentService {
    param (
        [Parameter(Mandatory = $true)]
        [array]$services,

        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$session
    )

    ForEach ($service in $services) {
        Write-LogMessage -Type "Debug" -MSG "Attempting to stop `"$service`" on $server"
        Invoke-Command -Session $session -ScriptBlock { $targetService = Get-Service -Name $args[0]; $targetService.Stop(); $targetService.WaitForStatus('Stopped', (New-TimeSpan -Seconds 15)) } -ArgumentList $service -ErrorAction SilentlyContinue -ErrorVariable stopResult

        If ($stopResult.Count -gt 0) {
            If ("InvalidOperationException" -ieq $stopResult[0].FullyQualifiedErrorId) {
                $null
            }
            else {
                Write-LogMessage -Type "Debug" -MSG "Unable to stop `"$service`" on $server, force stopping processes"
                $null = Invoke-Command -Session $session -ScriptBlock { Stop-ServiceProcess -name $args[0] } -ArgumentList $service
            }
        }
        Write-LogMessage -Type Debug -MSG "`"$service`" on $server Stopped"
        $stopResult.clear()
    }
}

Function Test-TargetWinRM {
    param (
        [Parameter(Mandatory = $true)]
        [string]$server,
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )
    Write-LogMessage -type Verbose -MSG "In Test-TargetWinRM"
    Write-LogMessage -type Verbose -MSG "Parameter passed for `'server`' is `"$server`""

    try {
        $testSession = New-PSLogon -server $server -Credential $Credential
        Remove-PSSession -Session $testSession
        Write-LogMessage -type Verbose -MSG "Test-TargetWinRM completed Successfully"
        Return $true
    }
    catch {
        Write-LogMessage -type Verbose -MSG "Test-TargetWinRM failed to connect"
        Return $false
    }
    Finally {
        Write-LogMessage -type Verbose -MSG "Existing Test-TargetWinRM"
    }
}

function New-PSLogon {
    param (
        [Parameter(Mandatory = $true)]
        [string]$server,
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )
    # SSL session option: skip cert checks  -  component servers typically use self-signed certs
    $psoptions    = New-PSSessionOption -MaxConnectionRetryCount 2
    $psoptionsSSL = New-PSSessionOption -MaxConnectionRetryCount 2 -SkipCACheck -SkipCNCheck -SkipRevocationCheck

    Write-LogMessage -type Verbose -MSG "In New-PSLogon"
    Write-LogMessage -type Verbose -MSG "Parameter passed for `'server`' is `"$server`""

    Try {
        $effectiveCred = if ($null -ne $Credential) { $Credential } else { $Script:RemoteCredential }

        # Non-SSL only mode  -  skip SSL attempt entirely
        if ($Script:WinRMUseNonSSL) {
            Write-LogMessage -type Verbose -MSG "WinRMUseNonSSL set: connecting directly via non-SSL (HTTP, port 5985) to $server"
            $plainParams = @{
                ComputerName  = $server
                SessionOption = $psoptions
                ErrorAction   = 'SilentlyContinue'
                ErrorVariable = 'psSessionError'
            }
            if ($null -ne $effectiveCred) {
                Write-LogMessage -type Verbose -MSG "Using explicit credentials for $($effectiveCred.username)"
                $plainParams['Credential'] = $effectiveCred
            }
            else {
                Write-LogMessage -type Verbose -MSG "Using implicit (Kerberos) credentials"
            }
            $psSession = New-PSSession @plainParams
            if ($null -eq $psSession) {
                $reason = if ($psSessionError.Count -gt 0) { $psSessionError[0].Exception.Message } else { 'Unknown reason' }
                Write-LogMessage -type Error -MSG "Error creating non-SSL PSSession to $server : $reason"
                Throw "No PSSession (non-SSL required)"
            }
            Write-LogMessage -type Verbose -MSG "Connected to $server via non-SSL WinRM"
        }
        else {
            # Try SSL first (HTTPS, port 5986)
            Write-LogMessage -type Verbose -MSG "Attempting SSL (HTTPS, port 5986) connection to $server"
            $sslParams = @{
                ComputerName  = $server
                UseSSL        = $true
                SessionOption = $psoptionsSSL
                ErrorAction   = 'SilentlyContinue'
                ErrorVariable = 'psSessionError'
            }
            if ($null -ne $effectiveCred) {
                Write-LogMessage -type Verbose -MSG "Using explicit credentials for $($effectiveCred.username)"
                $sslParams['Credential'] = $effectiveCred
            }
            else {
                Write-LogMessage -type Verbose -MSG "Using implicit (Kerberos) credentials"
            }
            $psSession = New-PSSession @sslParams

            if ($null -eq $psSession) {
                $sslReason = if ($psSessionError.Count -gt 0) { $psSessionError[0].Exception.Message } else { 'No HTTPS listener on port 5986' }
                Write-LogMessage -type Verbose -MSG "SSL connection to $server failed: $sslReason"

                if ($Script:WinRMUseSSL) {
                    Write-LogMessage -type Error -MSG "Error creating SSL PSSession to $server : $sslReason"
                    Throw "No PSSession (SSL required)"
                }

                # Fall back to non-SSL (HTTP, port 5985)
                Write-LogMessage -type Verbose -MSG "Falling back to non-SSL (HTTP, port 5985) connection to $server"
                $plainParams = @{
                    ComputerName  = $server
                    SessionOption = $psoptions
                    ErrorAction   = 'SilentlyContinue'
                    ErrorVariable = 'psSessionError'
                }
                if ($null -ne $effectiveCred) {
                    $plainParams['Credential'] = $effectiveCred
                }
                $psSession = New-PSSession @plainParams

                if ($null -eq $psSession) {
                    $reason = if ($psSessionError.Count -gt 0) { $psSessionError[0].Exception.Message } else { 'Unknown reason' }
                    Write-LogMessage -type Error -MSG "Error creating PSSession to $server : $reason"
                    Throw "No PSSession"
                }
                Write-LogMessage -type Info -MSG "Connected to $server via non-SSL WinRM (HTTPS unavailable)"
            }
            else {
                Write-LogMessage -type Verbose -MSG "Connected to $server via SSL WinRM"
            }
        }

        Write-LogMessage -type Verbose -MSG "Created Session successfully"
        IF (![string]::IsNullOrEmpty($Script:PrePSSession)) {
            Write-LogMessage -type Verbose -MSG "Inside PrePSSession"
            Invoke-Command -Session $psSession -ScriptBlock $Script:PrePSSession -ErrorAction SilentlyContinue
            Write-LogMessage -type Verbose -MSG "Completed PrePSSession"
        }
        return $psSession
    }
    Catch {
        Write-LogMessage -type Verbose -MSG "Catch in New-PSLogon"
        Write-LogMessage -type Verbose -MSG "$_"
        Throw "No PSSession"
    }
    Finally {
        Write-LogMessage -type Verbose -MSG "Existing New-PSLogon"
    }
}

function Reset-WinCredFile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Password is generated internally by New-RandomPassword and immediately consumed by Convert-SecureString; never sourced from user input.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '',
        Justification = 'CreateCredFile.exe must be invoked via Invoke-Expression inside the remote PSSession to capture its stdout/stderr; the command string is built from a fixed template with username and a server-generated password only.')]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $true)]
        $compInfo,
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$session
    )
    $installLocation = $compInfo.path
    [version]$version = $compInfo.Version
    $component = $compInfo.name
    $CompFiles = @()

    switch ($component) {
        "AIM" {
            $CompFiles += @(
                @{
                    type              = "AIM"
                    createCredDir     = "\vault"
                    credFilesDir      = ".\"
                    credFiles         = "AppProviderUser.cred"
                    componentName     = "AAM Credential Provider"
                    CreateCredCommand = $(if ($version -ge $Script:CredCommands.AIM.VersionThreshold) { $Script:CredCommands.AIM.v12 } else { $Script:CredCommands.AIM.Legacy })
                }
            )
        }
        "CPM" {
            $CompFiles += @(
                @{
                    type              = "CPM"
                    createCredDir     = "\vault"
                    credFilesDir      = ".\"
                    credFiles         = ".\user.ini"
                    componentName     = "CPM User"
                    CreateCredCommand = $(if ($version -ge $Script:CredCommands.CPM.VersionThreshold) { $Script:CredCommands.CPM.v12 } else { $Script:CredCommands.CPM.Legacy })
                }
            )
        }
        "PSM" {
            $CompFiles += @(
                @{
                    type              = "PSM"
                    createCredDir     = "\vault"
                    credFilesDir      = ".\"
                    credFiles         = "psmapp.cred"
                    componentName     = "PSM Application User"
                    CreateCredCommand = $(if ($version -ge $Script:CredCommands.PSM.App.VersionThreshold) { $Script:CredCommands.PSM.App.v12 } else { $Script:CredCommands.PSM.App.Legacy })
                }
            )
            $CompFiles += @(
                @{
                    type              = "PSM"
                    createCredDir     = "\vault"
                    credFilesDir      = ".\"
                    credFiles         = "psmgw.cred"
                    componentName     = "PSM Gateway User"
                    CreateCredCommand = $(if ($version -ge $Script:CredCommands.PSM.GW.VersionThreshold) { $Script:CredCommands.PSM.GW.v12 } else { $Script:CredCommands.PSM.GW.Legacy })
                }
            )
        }
        "PVWA" {
            $CompFiles += @(
                @{
                    type              = "PVWA"
                    createCredDir     = "\Env"
                    credFilesDir      = "..\CredFiles\"
                    credFiles         = "appuser.ini"
                    componentName     = "PVWA Application User"
                    CreateCredCommand = $(if ($version -ge $Script:CredCommands.PVWA.App.VersionThreshold) { $Script:CredCommands.PVWA.App.v12 } else { $Script:CredCommands.PVWA.App.Legacy })
                }
            )
            $CompFiles += @(
                @{
                    type              = "PVWA"
                    createCredDir     = "\Env"
                    credFilesDir      = "..\CredFiles\"
                    credFiles         = "gwuser.ini"
                    componentName     = "PVWA Gateway User"
                    CreateCredCommand = $(if ($version -ge $Script:CredCommands.PVWA.GW.VersionThreshold) { $Script:CredCommands.PVWA.GW.v12 } else { $Script:CredCommands.PVWA.GW.Legacy })
                }
            )
        }
    }
    foreach ($comp in $CompFiles) {

        $component = $comp.type
        $file = $comp.CredFiles
        $dir = $comp.credFilesDir
        $createCredDir = "$installLocation\$($comp.createCredDir)"

        Write-LogMessage -type Verbose -MSG "Updating $component $file credential file"
        Write-LogMessage -type Verbose -MSG "Setting working directory to: $createCredDir"
        $remoteWorkDir = Invoke-Command -Session $session -ScriptBlock { Set-Location -Path ($args[0]); (Get-Location).Path } -ArgumentList $createCredDir
        Write-LogMessage -type Verbose -MSG "Remote working directory confirmed: $remoteWorkDir"
        $userItem = Invoke-Command -Session $session -ScriptBlock { ((Select-String -Path "$($args[1])\$($args[0])" -Pattern "username=").Line).split("=")[1] } -ArgumentList $file, $dir
        If ([string]::IsNullOrEmpty($userItem)) {
            Write-LogMessage -type Error -MSG "Unable to determine username for $($comp.componentName) credential file '$file' on $server. Manual intervention required."
            Throw "Unable to determine username for $($comp.componentName) on $server"
        }
        $tempPassword = New-RandomPassword -Length 14 -Lowercase -Uppercase -Numbers -Symbols | ConvertTo-SecureString -AsPlainText -Force
        Write-LogMessage -type Verbose -MSG "Username: $userItem"

        $tag = [DateTimeOffset]::Now.ToUnixTimeSeconds()
        Invoke-Command -Session $session -ScriptBlock { Rename-Item "$($args[2])\$($args[0])" -NewName "$($args[0]).$($args[1])" -Force } -ArgumentList $file, $tag, $dir
        Invoke-Command -Session $session -ScriptBlock { Rename-Item "$($args[2])\$($args[0]).entropy" -NewName "$($args[0]).entropy.$($args[1])" -Force -ErrorAction SilentlyContinue } -ArgumentList $file, $tag, $dir
        Write-LogMessage -type Verbose -MSG "Backed up $component credential files"

        $command = $comp.CreateCredCommand -f $userItem, $(Convert-SecureString($tempPassword))
        $commandMasked = $comp.CreateCredCommand -f $userItem, '****'

        # PSM: set OpenSSL env vars required for CreateCredFile.exe to function correctly
        if ($component -eq "PSM") {
            $opensslConf    = "$installLocation\Components\openssl32.cnf"
            $opensslModules = "$installLocation\Components\ossl-modules32"
            Write-LogMessage -type Verbose -MSG "Setting PSM OpenSSL environment variables in remote session"
            Write-LogMessage -type Verbose -MSG "OPENSSL_CONF    = $opensslConf"
            Write-LogMessage -type Verbose -MSG "OPENSSL_MODULES = $opensslModules"
            Invoke-Command -Session $session -ScriptBlock {
                $env:OPENSSL_CONF    = $args[0]
                $env:OPENSSL_MODULES = $args[1]
            } -ArgumentList $opensslConf, $opensslModules
        }

        Write-LogMessage -type Verbose -MSG "Running CreateCredFile for $($comp.componentName) on $server"
        Write-LogMessage -type Verbose -MSG "Working directory: $remoteWorkDir"
        Write-LogMessage -type Verbose -MSG "Command: $commandMasked"
        $credOutput = Invoke-Command -Session $session -ScriptBlock { Invoke-Expression $args[0] 2>&1 } -ArgumentList $command -ErrorAction SilentlyContinue -ErrorVariable invokeResultApp
        Remove-Variable command
        Write-LogMessage -type Verbose -MSG "CreateCredFile output: $($credOutput -join ' | ')"
        If ($invokeResultApp[0].TargetObject -ne "Command ended successfully") {
            Invoke-Command -Session $session -ScriptBlock { Rename-Item "$($args[2])\$($args[0]).$($args[1])" -NewName "$($args[0])" -Force } -ArgumentList $file, $tag, $dir | Out-Null
            Invoke-Command -Session $session -ScriptBlock { Rename-Item "$($args[2])\$($args[0]).entropy.$($args[1])" -NewName "$($args[0]).entropy" -Force -ErrorAction SilentlyContinue } -ArgumentList $file, $tag, $dir | Out-Null
            Write-LogMessage -type Error -MSG "Error resetting credential file on $server : $($invokeResultApp[0].TargetObject)"
            if ($null -ne $credOutput) {
                Write-LogMessage -type Error -MSG "CreateCredFile output: $($credOutput -join ' | ')"
            }
            if ($null -ne $invokeResultApp -and $invokeResultApp.Count -gt 0) {
                Write-LogMessage -type Error -MSG "Error exception: $($invokeResultApp[0].Exception.Message)"
                Write-LogMessage -type Error -MSG "Error category: $($invokeResultApp[0].CategoryInfo.Category)"
            }
            Throw "Error resetting credential file on $server"
        }
        else {
            Invoke-Command -Session $session -ScriptBlock { Remove-Item "$($args[2])\$($args[0]).$($args[1])" -Force } -ArgumentList $file, $tag, $dir
            Invoke-Command -Session $session -ScriptBlock { Remove-Item "$($args[2])\$($args[0]).entropy.$($args[1])" -Force -ErrorAction SilentlyContinue } -ArgumentList $file, $tag, $dir
        }

        Write-LogMessage -type Verbose -MSG "CreateCredFile on `"$($comp.componentName)`" `"$file`" successful"
        Write-LogMessage -type Verbose -MSG "Updating `"$($comp.componentName)`" via RESTAPI"
        Set-UserPassword -username $userItem -Password $tempPassword
        Write-LogMessage -type Verbose -MSG "Update of `"$($comp.componentName)`" user via RESTAPI Complete"
        Write-LogMessage -type Success -MSG "Update of user `"$useritem`" on `"$server`" completed successfully"
    }
}

function Reset-VaultFile {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $true)]
        $compInfo,
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$session,
        [Parameter(Mandatory = $false)]
        $vaultAddress,
        [Parameter(Mandatory = $false)]
        $apiAddress
    )
    $installLocation = $compInfo.path
    $component = $compInfo.name
    $CompFiles = @()

    switch ($component) {
        "AIM" {
            $CompFiles += @(
                @{
                    type          = "AIM"
                    vaultdir      = "vault"
                    componentName = "AAM"
                }
            )
        }
        "CPM" {
            $CompFiles += @(
                @{
                    type          = "CPM"
                    vaultdir      = "vault"
                    componentName = "CPM"
                }
            )
        }
        "PSM" {
            $CompFiles += @(
                @{
                    type          = "PSM"
                    vaultdir      = "vault"
                    componentName = "PSM"
                }
            )
        }
        "PVWA" {
            $CompFiles += @(
                @{
                    type          = "PVWA"
                    vaultdir      = "VaultInfo"
                    componentName = "PVWA"
                }
            )
        }
    }
    foreach ($comp in $CompFiles) {

        $component = $comp.type
        $vaultDir = "$installLocation\$($comp.vaultdir)"
        $vaultFile = "$vaultdir\vault.ini"

        Write-LogMessage -type Verbose -MSG "Updating $component vault.ini files"
        Invoke-Command -Session $session -ScriptBlock { Set-Location -Path "$($args[0])"; } -ArgumentList $vaultDir

        $tag = [DateTimeOffset]::Now.ToUnixTimeSeconds()
        Invoke-Command -Session $session -ScriptBlock { Copy-Item $($args[0]) -Destination "$($args[0]).$($args[1])" -Force } -ArgumentList $vaultFile, $tag
        Write-LogMessage -type Verbose -MSG "Backed up existing $component vault.ini file"

        try {
            Invoke-Command -Session $session -ScriptBlock { (Get-Content $args[0]) -replace '(^ADDRESS=.*)', "ADDRESS=$($args[1])" | Set-Content $args[0] } -ArgumentList $vaultFile, $vaultaddress
            Write-LogMessage -type Verbose -MSG "$component vault.ini updated successfully"
            Invoke-Command -Session $session -ScriptBlock { Remove-Item "$($args[0]).$($args[1])" -Force } -ArgumentList $vaultFile, $tag
        }
        catch {
            Invoke-Command -Session $session -ScriptBlock { Rename-Item "$($args[0]).$($args[1])" -NewName "$($args[0])" -Force } -ArgumentList $vaultFile, $tag
            Write-LogMessage -type Error -MSG "Error updating $component vault.ini file on $server"
            Throw "Error updating $component vault.ini file"
        }
        Write-LogMessage -type Success -MSG "Update of vault address in vault.ini on `"$server`" completed successfully"

        IF (![string]::IsNullOrEmpty($apiAddress)) {
            Invoke-Command -Session $session -ScriptBlock { Copy-Item $($args[0]) -Destination "$($args[0]).$($args[1])" -Force } -ArgumentList $vaultFile, $tag
            Write-LogMessage -type Verbose -MSG "Backed up existing $component vault.ini file"
            try {
                Invoke-Command -Session $session -ScriptBlock { (Get-Content $args[0]) -replace '(^Addresses=.*)', "Addresses=$($args[1])" | Set-Content $args[0] } -ArgumentList $vaultFile, $apiAddress
                Write-LogMessage -type Verbose -MSG "$component vault.ini updated successfully"
                Invoke-Command -Session $session -ScriptBlock { Remove-Item "$($args[0]).$($args[1])" -Force } -ArgumentList $vaultFile, $tag
            }
            catch {
                Invoke-Command -Session $session -ScriptBlock { Rename-Item "$($args[0]).$($args[1])" -NewName "$($args[0])" -Force } -ArgumentList $vaultFile, $tag
                Write-LogMessage -type Error -MSG "Error updating `"$component`" vault.ini file on $server"
                Throw "Error updating $component vault.ini file"
            }
            Write-LogMessage -type Success -MSG "Update of vault API in vault.ini on `"$server`" completed successfully"
        }
    }
}

function Get-ComponentLog {
    <#
.SYNOPSIS
    Retrieves log file content from a remote CyberArk component server.
.DESCRIPTION
    Discovers the component install path on the remote machine via Find-WinComponents,
    then reads the last N lines of the requested log. Runs on the orchestrating
    machine; uses an existing PSSession for all remote file access.
.PARAMETER Server
    Hostname or IP of the remote server (used for display only).
.PARAMETER Session
    An open PSSession to the remote component server.
.PARAMETER ComponentType
    The component type key: PSM, CPM, PVWA, AIM, or 'AAM Credential Provider'.
    If omitted, all installed components are auto-detected and logged.
.PARAMETER LogName
    The exact log file name to retrieve, or 'All' to retrieve every log defined for
    the component type. Default: All.
    PSM  logs : PSMConsole.log, PSMTrace.log
    CPM  logs : PMConsole.log, PMTrace.log, pm.log, pm_error.log, CACPMScanner.log,
                Casos.Activity.log, Casos.Debug.log, Casos.Error.log
    PVWA logs : CyberArk.WebApplication.log, CyberArk.WebTasksEngine.log,
                PVWA.App.Log, Cyberark.Reports.log,
                CyberArk.WebConsole.log, CyberArk.WebTasksService.log
    AIM  logs : APPConsole.log, APPTrace.log, APPAudit.log
.PARAMETER Tail
    Number of lines from the end of each log file to retrieve. Default: 50.
#>
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter(Mandatory = $false)]
        [string]$ComponentType,

        [Parameter(Mandatory = $false)]
        [ValidateSet('All',
            'PSMConsole.log', 'PSMTrace.log',
            'PMConsole.log', 'PMTrace.log', 'pm.log', 'pm_error.log',
            'CACPMScanner.log', 'Casos.Activity.log', 'Casos.Debug.log', 'Casos.Error.log',
            'CyberArk.WebApplication.log', 'CyberArk.WebTasksEngine.log',
            'PVWA.App.Log', 'Cyberark.Reports.log',
            'CyberArk.WebConsole.log', 'CyberArk.WebTasksService.log',
            'APPConsole.log', 'APPTrace.log', 'APPAudit.log')]
        [string]$LogName = 'All',

        [Parameter(Mandatory = $false)]
        [int]$Tail = 50
    )

    # Normalise caller-facing component name to the key used in $Script:LogPaths
    $typeKey = switch ($ComponentType) {
        'PSM'                     { 'PSM';  break }
        'CPM'                     { 'CPM';  break }
        'PVWA'                    { 'PVWA'; break }
        'AIM'                     { 'AIM';  break }
        'AAM Credential Provider' { 'AIM';  break }
        default                   { $ComponentType }
    }

    # Auto-detect when no type was supplied
    if ([string]::IsNullOrEmpty($typeKey)) {
        $detected = Invoke-Command -Session $Session -ScriptBlock { Find-WinComponents 'All' }
        if ($null -eq $detected -or $detected.Count -eq 0) {
            Write-LogMessage -type Warning -MSG "No CyberArk components detected on $Server"
            return
        }
        foreach ($det in $detected) {
            Get-ComponentLog -Server $Server -Session $Session -ComponentType $det.Name -LogName $LogName -Tail $Tail
        }
        return
    }

    $logDefs = $Script:LogPaths[$typeKey]
    if ($null -eq $logDefs) {
        Write-LogMessage -type Warning -MSG "No log paths defined for component type '$typeKey' on $Server"
        return
    }

    # Build the list of relative paths to retrieve
    $relPaths = @()
    if ($LogName -eq 'All') {
        $relPaths += $logDefs.Values | Where-Object { -not [string]::IsNullOrEmpty($_) }
    }
    else {
        if ($logDefs.ContainsKey($LogName)) {
            $relPaths += $logDefs[$LogName]
        }
        else {
            Write-LogMessage -type Warning -MSG "Log '$LogName' is not defined for component type '$typeKey' on $Server"
            return
        }
    }

    # Resolve the install path on the remote machine
    $compInfo = Invoke-Command -Session $Session -ScriptBlock { Find-WinComponents $args[0] } -ArgumentList $typeKey
    if ($null -eq $compInfo -or [string]::IsNullOrEmpty($compInfo.Path)) {
        Write-LogMessage -type Warning -MSG "Cannot determine install path for $typeKey on $Server  -  skipping log retrieval"
        return
    }

    foreach ($relPath in $relPaths) {
        $fullPath = [System.IO.Path]::Combine($compInfo.Path, $relPath)
        Write-LogMessage -type Info -MSG "Last $Tail lines of $fullPath on $Server" -Header
        # param() + -ArgumentList is intentional: this scriptblock is also loaded into remote
        # PSSessions via Invoke-Command -FilePath, so $using: cannot be used here — PowerShell
        # would attempt to resolve $using: references at file-load time when $fullPath is not
        # yet defined, causing a runtime error. PSUseUsingScopeModifierInNewRunspaces is a
        # false positive when -ArgumentList is used to pass variables explicitly.
        $lines = Invoke-Command -Session $Session -ScriptBlock {
            param($p, $t)
            try {
                if (Test-Path -LiteralPath $p) {
                    Get-Content -Path $p -Tail $t -ErrorAction Stop
                }
                else {
                    "Log file not found: $p"
                }
            }
            catch {
                "Error reading log: $($_.Exception.Message)"
            }
        } -ArgumentList $fullPath, $Tail
        $lines | ForEach-Object { Write-Host $_ }
        Write-LogMessage -type Info -MSG '' -Footer
    }
}
