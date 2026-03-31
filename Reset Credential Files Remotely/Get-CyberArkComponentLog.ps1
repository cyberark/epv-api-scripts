#Requires -Version 5.1
<#
.SYNOPSIS
    Retrieves CyberArk component log files from remote Windows servers via WinRM.

.DESCRIPTION
    Connects to one or more remote CyberArk component servers (PSM, CPM, PVWA, AAM Credential
    Provider) using WinRM and retrieves the last N lines of the component log file(s).

    Component install paths are discovered automatically via the Windows registry on the remote
    machine  -  no hard-coded paths required.

    Supports:
      - Standard operational logs (PSMConsole.log, PM.log, AppProvider.log, etc.)
      - Verbose trace/debug logs  (PSMTrace.log, PMTrace.log, etc.)
      - Live follow mode (-Follow) equivalent to 'tail -f', for a single server

    Uses the same WinRM connection logic as Invoke-CredFileReset.ps1 (SSL-first with HTTP
    fallback, or forced SSL/non-SSL via switches).

.PARAMETER ComputerName
    One or more remote server hostnames or IP addresses.
    When -Follow is used only the first server is processed.

.PARAMETER ComponentType
    The CyberArk component type installed on the target server(s).
    Valid values: PSM, CPM, PVWA, AIM
    If omitted, all installed components are auto-detected.

.PARAMETER LogName
    Log file name to retrieve, or 'All' to retrieve every log defined for the component type.
    Default: All. Specify a single file name when using -Follow.
    PSM  logs : PSMConsole.log, PSMTrace.log
    CPM  logs : PMConsole.log, PMTrace.log, pm.log, pm_error.log, CACPMScanner.log,
                Casos.Activity.log, Casos.Debug.log, Casos.Error.log
    PVWA logs : CyberArk.WebApplication.log, CyberArk.WebTasksEngine.log,
                PVWA.App.Log, Cyberark.Reports.log,
                CyberArk.WebConsole.log, CyberArk.WebTasksService.log
    AIM  logs : APPConsole.log, APPTrace.log, APPAudit.log

.PARAMETER Tail
    Number of lines from the end of the log to display. Default: 50.

.PARAMETER Follow
    Stream new log entries in real time (equivalent to 'tail -f').
    Only one server and one log file is supported when -Follow is used.
    Press Ctrl+C to stop.

.PARAMETER Credential
    PSCredential for WinRM authentication.
    If omitted, implicit (Kerberos) credentials are used  -  suitable when running
    from a domain-joined machine targeting domain-joined servers.
    Supply explicit credentials when running from a Remote SSH session or across domains.

.PARAMETER WinRMUseSSL
    Force HTTPS (port 5986) for all WinRM connections.
    Default behaviour is SSL-first with automatic HTTP fallback.
    Cannot be combined with -WinRMUseNonSSL.

.PARAMETER WinRMUseNonSSL
    Force HTTP (port 5985) for all WinRM connections. Skips the SSL attempt entirely.
    Useful when component servers have no WinRM HTTPS listener.
    Cannot be combined with -WinRMUseSSL.

.EXAMPLE
    # View the last 100 lines of the PSM console log
    .\Get-CyberArkComponentLog.ps1 -ComputerName PSM-01.lab.local -ComponentType PSM -Tail 100

.EXAMPLE
    # Live-follow the PSM console log from a Remote SSH session
    $cred = Get-Credential
    .\Get-CyberArkComponentLog.ps1 -ComputerName PSM-01.lab.local -ComponentType PSM `
        -LogName PSMConsole.log -Credential $cred -WinRMUseNonSSL -Follow

.EXAMPLE
    # View the PSM trace log
    .\Get-CyberArkComponentLog.ps1 -ComputerName PSM-01.lab.local -ComponentType PSM -LogName PSMTrace.log

.EXAMPLE
    # View all logs for a CPM server
    .\Get-CyberArkComponentLog.ps1 -ComputerName CPM-01.lab.local -ComponentType CPM -LogName All -Tail 30

.EXAMPLE
    # View only the CPM error log
    .\Get-CyberArkComponentLog.ps1 -ComputerName CPM-01.lab.local -ComponentType CPM -LogName pm_error.log -Tail 30

.EXAMPLE
    # View standard logs from multiple PSM servers (using implicit Kerberos from domain machine)
    .\Get-CyberArkComponentLog.ps1 -ComputerName PSM-01, PSM-02 -ComponentType PSM -Tail 50

.EXAMPLE
    # Auto-detect all components on a server and show their logs
    $cred = Get-Credential
    .\Get-CyberArkComponentLog.ps1 -ComputerName 192.168.1.50 -Credential $cred -WinRMUseNonSSL

.NOTES
    Version:    1.0
    Authors:    Brian Bors <brian.bors@cyberark.com>

    Requires:   PowerShell 5.1+
                WinRM access (TCP 5985 or 5986) from this machine to the target server(s)
                Reset-WinComponentCredential.ps1 must be in the same directory as this script

    Log file locations (source: https://community.cyberark.com/s/article/Where-do-I-find-the-logs):
      PSM  : PSMConsole.log, PSMTrace.log
      CPM  : PMConsole.log, PMTrace.log, pm.log, pm_error.log, CACPMScanner.log,
             Casos.Activity.log, Casos.Debug.log, Casos.Error.log
      PVWA : CyberArk.WebApplication.log, CyberArk.WebTasksEngine.log,
             PVWA.App.Log, Cyberark.Reports.log,
             CyberArk.WebConsole.log, CyberArk.WebTasksService.log
      AIM  : APPConsole.log, APPTrace.log, APPAudit.log
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = 'Remote server hostname(s) or IP address(es)')]
    [string[]]$ComputerName,

    [Parameter(Mandatory = $false, HelpMessage = 'CyberArk component type. If omitted, auto-detects all installed components.')]
    [ValidateSet('PSM', 'CPM', 'PVWA', 'AIM')]
    [string]$ComponentType,

    [Parameter(Mandatory = $false, HelpMessage = 'Log file name to retrieve, or All for every log defined for the component type. Tab-completes to logs valid for the selected -ComponentType.')]
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $logMap = @{
            PSM  = @('PSMConsole.log', 'PSMTrace.log')
            CPM  = @('PMConsole.log', 'PMTrace.log', 'pm.log', 'pm_error.log',
                     'CACPMScanner.log', 'Casos.Activity.log', 'Casos.Debug.log', 'Casos.Error.log')
            PVWA = @('CyberArk.WebApplication.log', 'CyberArk.WebTasksEngine.log',
                     'PVWA.App.Log', 'Cyberark.Reports.log',
                     'CyberArk.WebConsole.log', 'CyberArk.WebTasksService.log')
            AIM  = @('APPConsole.log', 'APPTrace.log', 'APPAudit.log')
        }
        $candidates = @('All')
        $ct = $fakeBoundParameters['ComponentType']
        if ($null -ne $ct -and $logMap.ContainsKey($ct)) {
            $candidates += $logMap[$ct]
        } else {
            $candidates += $logMap.Values | ForEach-Object { $_ }
        }
        $candidates | Where-Object { $_ -like "$wordToComplete*" } |
            ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
    })]
    [string]$LogName = 'All',

    [Parameter(Mandatory = $false, HelpMessage = 'Number of lines from end of file to display')]
    [int]$Tail = 50,

    [Parameter(Mandatory = $false, HelpMessage = 'Stream log in real time (tail -f). Single server only. Press Ctrl+C to stop.')]
    [switch]$Follow,

    [Parameter(Mandatory = $false, HelpMessage = 'Credentials for WinRM connection to remote server(s)')]
    [PSCredential]$Credential,

    [Parameter(Mandatory = $false, HelpMessage = 'Force SSL (HTTPS/port 5986) for WinRM. Cannot combine with -WinRMUseNonSSL.')]
    [switch]$WinRMUseSSL,

    [Parameter(Mandatory = $false, HelpMessage = 'Force non-SSL (HTTP/port 5985) for WinRM. Skips SSL attempt. Cannot combine with -WinRMUseSSL.')]
    [switch]$WinRMUseNonSSL
)

#region Init
$Script:InVerbose = $PSBoundParameters.Verbose.IsPresent
$Script:InDebug   = $PSBoundParameters.Debug.IsPresent
if ($Script:InVerbose) { $VerbosePreference = 'continue' }

$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path

# LOG_FILE_PATH  -  write to a dedicated log next to the script so Write-LogMessage
# doesn't fall back to creating a random temp file on every call.
New-Variable -Name LOG_FILE_PATH -Value "$ScriptLocation\ComponentLog-Retrieval.log" -Scope Script -Force

if ($WinRMUseSSL -and $WinRMUseNonSSL) {
    Write-Error '-WinRMUseSSL and -WinRMUseNonSSL are mutually exclusive. Specify only one.'
    return
}

$Script:WinRMUseSSL     = $WinRMUseSSL.IsPresent
$Script:WinRMUseNonSSL  = $WinRMUseNonSSL.IsPresent
$Script:RemoteCredential = $Credential
$Script:PrePSSession     = $null   # no module path fixup needed for read-only log access

# Dot-source helper functions: New-PSLogon, Get-ComponentLog, Find-WinComponents, Write-LogMessage, etc.
. "$ScriptLocation\Reset-WinComponentCredential.ps1"

#region Pre-flight: TrustedHosts advisory for non-SSL + explicit credentials
if ($null -ne $Credential -and -not $WinRMUseSSL) {
    $trustedHosts = (Get-Item 'WSMan:\localhost\Client\TrustedHosts' -ErrorAction SilentlyContinue).Value
    if ($WinRMUseNonSSL) {
        # Non-SSL always uses NTLM/Negotiate for explicit creds  -  TrustedHosts is required
        if ([string]::IsNullOrEmpty($trustedHosts)) {
            Write-Warning "-WinRMUseNonSSL with explicit credentials requires TrustedHosts. Currently empty."
            Write-Warning "Fix: Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force  (or list specific hosts)"
        }
        elseif ($trustedHosts -ne '*') {
            $missing = $ComputerName | Where-Object {
                $h = $_
                ($trustedHosts.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ieq $h }).Count -eq 0
            }
            foreach ($m in $missing) {
                Write-Warning "$m is not in WSMan:\localhost\Client\TrustedHosts  -  non-SSL WinRM may fail."
                Write-Warning "Fix: Set-Item WSMan:\localhost\Client\TrustedHosts -Value '$m' -Force"
            }
        }
    }
    else {
        # SSL-first: SSL connections don't need TrustedHosts, but HTTP fallback does
        if ([string]::IsNullOrEmpty($trustedHosts)) {
            Write-Warning "TrustedHosts is empty. SSL (port 5986) will work without it; HTTP fallback (port 5985) will fail with explicit credentials."
            Write-Warning "If SSL is unavailable on target servers, use -WinRMUseNonSSL and set TrustedHosts first."
        }
    }
}
#endregion
#endregion

#region Validation
if ($Follow -and $LogName -eq 'All') {
    Write-Error '-Follow requires a specific -LogName (e.g. PSMConsole.log, pm.log). -LogName All is not supported with -Follow.'
    return
}

$serversToProcess = $ComputerName
if ($Follow -and $ComputerName.Count -gt 1) {
    Write-Warning '-Follow supports only a single -ComputerName. Using the first server only.'
    $serversToProcess = @($ComputerName[0])
}
#endregion

#region Helper  -  resolve component type key and log file path for Follow mode
function Get-FollowLogPath {
    param(
        [string]$TypeKey,
        [string]$LogName,
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    $logDefs = $Script:LogPaths[$TypeKey]
    if ($null -eq $logDefs) {
        throw "No log paths defined for component type '$TypeKey'"
    }
    if (-not $logDefs.ContainsKey($LogName)) {
        throw "Log '$LogName' is not defined for component type '$TypeKey'. Available: $($logDefs.Keys -join ', ')"
    }
    $relPath = $logDefs[$LogName]

    $compInfo = Invoke-Command -Session $Session -ScriptBlock { Find-WinComponents $args[0] } -ArgumentList $TypeKey
    if ($null -eq $compInfo -or [string]::IsNullOrEmpty($compInfo.Path)) {
        throw "Cannot determine install path for $TypeKey on remote server"
    }

    return [System.IO.Path]::Combine($compInfo.Path, $relPath)
}
#endregion

#region Main processing loop
foreach ($server in $serversToProcess) {
    $session = $null
    try {
        Write-Host "`n$('=' * 60)" -ForegroundColor Cyan
        Write-Host "Connecting to $server" -ForegroundColor Cyan
        Write-Host "$('=' * 60)" -ForegroundColor Cyan

        $session = New-PSLogon -server $server -Credential $Credential

        # Load helper functions (Find-WinComponents, etc.) into the remote session
        Invoke-Command -Session $session -FilePath "$ScriptLocation\Reset-WinComponentCredential.ps1"

        if ($Follow) {
            # Resolve the log path, then stream it live via Get-Content -Wait.
            # Get-Content -Wait inside Invoke-Command streams each new line back to the
            # local console through the remoting channel. Press Ctrl+C to stop.
            $typeKey = switch ($ComponentType) {
                'PSM'  { 'PSM';  break }
                'CPM'  { 'CPM';  break }
                'PVWA' { 'PVWA'; break }
                'AIM'  { 'AIM';  break }
                default { $ComponentType }
            }

            if ([string]::IsNullOrEmpty($typeKey)) {
                # Auto-detect: pick first component found
                $detected = Invoke-Command -Session $session -ScriptBlock { Find-WinComponents 'All' }
                if ($null -eq $detected -or $detected.Count -eq 0) {
                    Write-Error "No CyberArk components detected on $server"
                    return
                }
                $typeKey = $detected[0].Name
                Write-Host "Auto-detected component: $typeKey" -ForegroundColor Yellow
            }

            $fullPath = Get-FollowLogPath -TypeKey $typeKey -LogName $LogName -Session $session

            Write-Host "`nFollowing: $fullPath" -ForegroundColor Green
            Write-Host "Server   : $server" -ForegroundColor Green
            Write-Host "Press Ctrl+C to stop.`n" -ForegroundColor Green

            # Show the initial tail, then stream new lines as they arrive
            Invoke-Command -Session $session -ScriptBlock {
                Get-Content -Path $args[0] -Wait -Tail $args[1] -ErrorAction SilentlyContinue
            } -ArgumentList $fullPath, $Tail
        }
        else {
            # Non-follow: read last N lines of each requested log
            Get-ComponentLog -Server $server -Session $session -ComponentType $ComponentType -LogName $LogName -Tail $Tail
        }
    }
    catch {
        Write-Error "Failed to retrieve logs from $server : $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $session) {
            Remove-PSSession $session -ErrorAction SilentlyContinue
        }
    }
}
#endregion
