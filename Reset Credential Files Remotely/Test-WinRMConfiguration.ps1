<#
.SYNOPSIS
    Inspects and diagnoses WinRM configuration on the local machine.

.DESCRIPTION
    Run LOCALLY on a target CyberArk component server (as a local Administrator) to
    inspect and diagnose WinRM configuration and firewall posture before Invoke-CredFileReset.ps1
    attempts to connect to it.

    Performs the following checks:
      Step 1  WinRM service state and startup type
      Step 2  WinRM listeners (HTTP/HTTPS, ports, addresses)
      Step 3  Authentication methods (Kerberos, Negotiate, NTLM, Basic, Certificate)
      Step 4  AllowUnencrypted setting (informational for HTTP listeners)
      Step 5  Inbound firewall rules for ports 5985 (WinRM HTTP) and 5986 (WinRM HTTPS)
      Step 6  Local group membership (Administrators and Remote Management Users)
      Step 7  Network profile — Public profile blocks WinRM by default
      Step 8  Local TrustedHosts setting (informational — client-side)

    A failure/warning summary is printed at the end.

    Read-only by default. Use -Fix to remediate fixable findings.
    Each fix requires ShouldProcess confirmation; -WhatIf and -Confirm are supported.

    After running this script on the target, run Test-RemoteConnectivity.ps1 from
    the orchestrating machine to verify end-to-end connectivity.

.PARAMETER Fix
    Attempt to remediate fixable findings:
      - Start WinRM service and set it to Automatic startup
      - Run Enable-PSRemoting to create missing listeners
      - Enable Windows Remote Management inbound firewall rules
    Each fix requires ShouldProcess confirmation.
    Use -WhatIf to preview what would change without applying anything.
    Must be run as local Administrator to apply fixes.

.EXAMPLE
    # Read-only inspection of local WinRM configuration
    .\Test-WinRMConfiguration.ps1

.EXAMPLE
    # Check and fix issues (prompts for confirmation before each fix)
    .\Test-WinRMConfiguration.ps1 -Fix

.EXAMPLE
    # Preview what -Fix would change without making any modifications
    .\Test-WinRMConfiguration.ps1 -Fix -WhatIf

.NOTES
    Version:    1.0
    Author:     Brian Bors <brian.bors@cyberark.com>

    Run this script LOCALLY on the target component server.
    Run Test-RemoteConnectivity.ps1 from the orchestrating machine to test from the outside.

    Requires:   PowerShell 5.1+
                Local Administrator rights on the target server (especially for -Fix)

    Change Log:
    2026-03-27  Initial version
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $false, HelpMessage = 'Attempt to remediate fixable findings (each fix requires confirmation)')]
    [switch]$Fix
)

#region Functions

Function Write-CheckResult {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Step,
        [Parameter(Mandatory = $true)]
        [string]$Check,
        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO', 'SKIP')]
        [string]$Result,
        [Parameter(Mandatory = $false)]
        [string]$Detail = '',
        [Parameter(Mandatory = $false)]
        [string]$Remediation = ''
    )

    $color = switch ($Result) {
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
        'INFO' { 'Cyan' }
        'SKIP' { 'DarkGray' }
    }
    $prefix = "  [$Result]".PadRight(8)
    $stepStr = "Step $Step".PadRight(7)
    $line = "$stepStr $Check"
    if (![string]::IsNullOrEmpty($Detail)) {
        $line += " — $Detail"
    }
    Write-Host "$prefix $line" -ForegroundColor $color
    if (![string]::IsNullOrEmpty($Remediation)) {
        Write-Host "           Remediation: $Remediation" -ForegroundColor Yellow
    }
}

Function Invoke-Fix {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,
        [Parameter(Mandatory = $true)]
        [string]$Action,
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        [Parameter(Mandatory = $true)]
        [int]$Step,
        [Parameter(Mandatory = $true)]
        [string]$Check,
        [Parameter(Mandatory = $true)]
        $PSCmdletRef
    )
    if ($PSCmdletRef.ShouldProcess($Target, $Action)) {
        try {
            & $ScriptBlock
            Write-CheckResult -Step $Step -Check $Check -Result 'PASS' -Detail "Fixed: $Action"
            return $true
        }
        catch {
            Write-CheckResult -Step $Step -Check $Check -Result 'FAIL' -Detail "Fix failed: $($_.Exception.Message)"
            return $false
        }
    }
    return $false
}

#endregion Functions

#region Main

$hostname = [System.Net.Dns]::GetHostName()
Write-Host ''
Write-Host '========================================' -ForegroundColor Magenta
Write-Host "  WinRM Configuration: $hostname" -ForegroundColor White
Write-Host '========================================' -ForegroundColor Magenta

$warnings = [System.Collections.Generic.List[string]]::new()
$failures = [System.Collections.Generic.List[string]]::new()

# Step 1 — WinRM service state
$winrmSvc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
if ($null -eq $winrmSvc) {
    Write-CheckResult -Step 1 -Check 'WinRM service' -Result 'FAIL' -Detail 'WinRM service not found' -Remediation 'Install-WindowsFeature -Name WinRM'
    $failures.Add('Step 1: WinRM service not found')
}
elseif ($winrmSvc.Status -ne 'Running') {
    Write-CheckResult -Step 1 -Check 'WinRM service' -Result 'FAIL' -Detail "Status: $($winrmSvc.Status)" -Remediation 'Start-Service WinRM; Set-Service WinRM -StartupType Automatic'
    $failures.Add("Step 1: WinRM service is $($winrmSvc.Status)")
    if ($Fix) {
        $null = Invoke-Fix -Target 'WinRM service' -Action 'Start-Service WinRM' -Step 1 -Check 'WinRM service' -PSCmdletRef $PSCmdlet -ScriptBlock {
            Start-Service WinRM; Set-Service WinRM -StartupType Automatic
        }
    }
}
else {
    Write-CheckResult -Step 1 -Check 'WinRM service' -Result 'PASS' -Detail "Running (StartType: $($winrmSvc.StartType))"
}

# Step 2 — WinRM listeners
try {
    $listeners = @(Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate -ErrorAction Stop)
    if ($listeners.Count -eq 0) {
        Write-CheckResult -Step 2 -Check 'WinRM listeners' -Result 'FAIL' -Detail 'No listeners configured' -Remediation 'Enable-PSRemoting -Force'
        $failures.Add('Step 2: No WinRM listeners configured')
        if ($Fix) {
            $null = Invoke-Fix -Target 'WinRM listeners' -Action 'Enable-PSRemoting -Force' -Step 2 -Check 'WinRM listeners' -PSCmdletRef $PSCmdlet -ScriptBlock {
                Enable-PSRemoting -Force
            }
        }
    }
    else {
        foreach ($listener in $listeners) {
            Write-CheckResult -Step 2 -Check 'WinRM listeners' -Result 'PASS' -Detail "Transport: $($listener.Transport)  Port: $($listener.Port)  Address: $($listener.Address)"
        }
    }
}
catch {
    Write-CheckResult -Step 2 -Check 'WinRM listeners' -Result 'FAIL' -Detail $_.Exception.Message -Remediation 'Enable-PSRemoting -Force'
    $failures.Add("Step 2: Cannot enumerate listeners — $($_.Exception.Message)")
}

# Step 3 — Authentication methods
try {
    $auth = Get-WSManInstance winrm/config/service/auth -ErrorAction Stop
    $authEnabled = @()
    $authDisabled = @()
    foreach ($method in @('Kerberos', 'Negotiate', 'NTLM', 'Basic', 'Certificate')) {
        $val = $auth.$method
        if ($val -ieq 'true') { $authEnabled += $method } else { $authDisabled += $method }
    }
    $detail = "Enabled: $($authEnabled -join ', ')"
    if ($authDisabled.Count -gt 0) { $detail += "  Disabled: $($authDisabled -join ', ')" }
    Write-CheckResult -Step 3 -Check 'Authentication methods' -Result 'PASS' -Detail $detail
}
catch {
    Write-CheckResult -Step 3 -Check 'Authentication methods' -Result 'WARN' -Detail "Cannot read auth config: $($_.Exception.Message)"
    $warnings.Add("Step 3: Cannot read authentication config — $($_.Exception.Message)")
}

# Step 4 — AllowUnencrypted check
try {
    $svcConfig = Get-WSManInstance winrm/config/service -ErrorAction Stop
    $httpListeners = @($listeners | Where-Object { $_.Transport -eq 'HTTP' })
    if ($svcConfig.AllowUnencrypted -ieq 'false' -and $httpListeners.Count -gt 0) {
        Write-CheckResult -Step 4 -Check 'AllowUnencrypted' -Result 'WARN' -Detail 'AllowUnencrypted=false with HTTP listener — Negotiate/Kerberos auth will encrypt the session. Only a problem if Basic auth is required.'
        $warnings.Add('Step 4: AllowUnencrypted=false with HTTP listener (informational)')
    }
    else {
        Write-CheckResult -Step 4 -Check 'AllowUnencrypted' -Result 'INFO' -Detail "AllowUnencrypted=$($svcConfig.AllowUnencrypted)"
    }
}
catch {
    Write-CheckResult -Step 4 -Check 'AllowUnencrypted' -Result 'WARN' -Detail "Cannot read service config: $($_.Exception.Message)"
}

# Step 5 — Firewall rules for WinRM ports
$fwChecks = @(
    @{ Port = 5985; Name = 'WinRM HTTP' },
    @{ Port = 5986; Name = 'WinRM HTTPS' }
)
foreach ($fwCheck in $fwChecks) {
    try {
        $rules = @(Get-NetFirewallRule -Enabled True -Direction Inbound -ErrorAction Stop |
            Where-Object { $_.DisplayName -imatch 'WinRM|Windows Remote Management' })

        $portRules = @()
        foreach ($rule in $rules) {
            $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
            if ($null -ne $portFilter -and ($portFilter.LocalPort -contains $fwCheck.Port -or $portFilter.LocalPort -contains 'Any')) {
                $portRules += $rule
            }
        }

        if ($portRules.Count -gt 0) {
            Write-CheckResult -Step 5 -Check "Firewall port $($fwCheck.Port) ($($fwCheck.Name))" -Result 'PASS' -Detail "Rule(s): $($portRules.DisplayName -join ', ')"
        }
        else {
            $step5Rem = "Enable-NetFirewallRule -DisplayGroup 'Windows Remote Management' (or create a new inbound rule for port $($fwCheck.Port))"
            Write-CheckResult -Step 5 -Check "Firewall port $($fwCheck.Port) ($($fwCheck.Name))" -Result $(if ($fwCheck.Port -eq 5985) { 'FAIL' } else { 'INFO' }) -Detail 'No enabled inbound rule found' -Remediation $step5Rem

            if ($fwCheck.Port -eq 5985) {
                $failures.Add("Step 5: No enabled inbound firewall rule for port 5985")
                if ($Fix) {
                    $null = Invoke-Fix -Target "TCP $($fwCheck.Port)" -Action 'Enable Windows Remote Management firewall rules' -Step 5 -Check "Firewall port $($fwCheck.Port)" -PSCmdletRef $PSCmdlet -ScriptBlock {
                        Enable-NetFirewallRule -DisplayGroup 'Windows Remote Management' -ErrorAction Stop
                    }
                }
            }
        }
    }
    catch {
        Write-CheckResult -Step 5 -Check "Firewall port $($fwCheck.Port) ($($fwCheck.Name))" -Result 'WARN' -Detail "Cannot query firewall rules: $($_.Exception.Message)"
        $warnings.Add("Step 5: Cannot query firewall rules — $($_.Exception.Message)")
    }
}

# Step 6 — Remote Management Users / Administrators group membership
try {
    $groups = @('Remote Management Users', 'Administrators')
    foreach ($group in $groups) {
        try {
            $members = Get-LocalGroupMember -Group $group -ErrorAction Stop
            $memberNames = ($members | Select-Object -ExpandProperty Name) -join ', '
            Write-CheckResult -Step 6 -Check "$group members" -Result 'INFO' -Detail $memberNames
        }
        catch {
            Write-CheckResult -Step 6 -Check "$group members" -Result 'WARN' -Detail $_.Exception.Message
        }
    }
    Write-Host "           Note: Add accounts to 'Remote Management Users' to grant WinRM access without local admin rights." -ForegroundColor DarkGray
}
catch {
    Write-CheckResult -Step 6 -Check 'Local group membership' -Result 'WARN' -Detail $_.Exception.Message
}

# Step 7 — Network profile check
try {
    $profiles = Get-NetConnectionProfile -ErrorAction Stop
    $publicAdapters = @($profiles | Where-Object { $_.NetworkCategory -eq 'Public' })
    if ($publicAdapters.Count -gt 0) {
        $adapterNames = ($publicAdapters | Select-Object -ExpandProperty InterfaceAlias) -join ', '
        Write-CheckResult -Step 7 -Check 'Network profile' -Result 'WARN' -Detail "Adapter(s) on Public profile: $adapterNames" -Remediation "Set-NetConnectionProfile -InterfaceAlias '<AdapterName>' -NetworkCategory Private (WARNING: may drop current session)"
        $warnings.Add("Step 7: Adapter(s) on Public network profile — WinRM blocked by default: $adapterNames")
    }
    else {
        $summary = ($profiles | ForEach-Object { "$($_.InterfaceAlias): $($_.NetworkCategory)" }) -join '; '
        Write-CheckResult -Step 7 -Check 'Network profile' -Result 'PASS' -Detail $summary
    }
}
catch {
    Write-CheckResult -Step 7 -Check 'Network profile' -Result 'WARN' -Detail "Cannot read network profiles: $($_.Exception.Message)"
}

# Step 8 — Local TrustedHosts (informational)
try {
    $localTrustedHosts = (Get-Item 'WSMan:\localhost\Client\TrustedHosts' -ErrorAction Stop).Value
    $displayValue = if ([string]::IsNullOrEmpty($localTrustedHosts)) { '(empty)' } else { $localTrustedHosts }
    Write-CheckResult -Step 8 -Check 'TrustedHosts (this machine as client)' -Result 'INFO' -Detail $displayValue
    if ($Fix -and [string]::IsNullOrEmpty($localTrustedHosts)) {
        Write-Host "           No TrustedHosts configured on this machine. Use -Fix on Test-RemoteConnectivity.ps1 from the orchestrating machine to add entries there." -ForegroundColor DarkGray
    }
}
catch {
    Write-CheckResult -Step 8 -Check 'TrustedHosts (this machine as client)' -Result 'WARN' -Detail $_.Exception.Message
}

# Summary
Write-Host ''
Write-Host '========================================' -ForegroundColor Magenta
Write-Host '  SUMMARY' -ForegroundColor White
Write-Host '========================================' -ForegroundColor Magenta

if ($failures.Count -gt 0) {
    Write-Host "FAILURES ($($failures.Count)):" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}
if ($warnings.Count -gt 0) {
    Write-Host "WARNINGS ($($warnings.Count)):" -ForegroundColor Yellow
    $warnings | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
}
if ($failures.Count -eq 0 -and $warnings.Count -eq 0) {
    Write-Host 'All checks passed. This machine should be reachable via WinRM.' -ForegroundColor Green
}
elseif ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host "WinRM connectivity issues detected. Re-run with -Fix to attempt remediation." -ForegroundColor Yellow
}

#endregion Main
