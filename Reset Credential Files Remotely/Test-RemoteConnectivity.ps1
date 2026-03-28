<#
.SYNOPSIS
    Tests WinRM connectivity from the orchestrating machine to CyberArk component servers.

.DESCRIPTION
    Run from the ORCHESTRATING machine before using Invoke-CredFileReset.ps1 to verify that
    WinRM connectivity is properly configured to your target component servers.

    Performs the following checks for each target:
      Step 1  DNS resolution
      Step 2  ICMP reachability (WARN only — ICMP may be legitimately blocked)
      Step 3  TCP port 5985 (WinRM HTTP) — required for Invoke-CredFileReset.ps1
      Step 4  TCP port 5986 (WinRM HTTPS) — informational only
      Step 5  TrustedHosts entry — required when using -Credential (explicit auth)
      Step 6  WSMan identify probe — confirms the WinRM service responds
      Step 7  PSSession creation — full end-to-end authentication test
      Step 8  Identity round-trip — confirms remote code execution works

    A summary table is printed after all targets are checked. For any target with
    failures, run Test-WinRMConfiguration.ps1 locally on that server to diagnose from
    the inside.

    Use -Fix to remediate fixable findings (currently: updating TrustedHosts).
    Each fix requires ShouldProcess confirmation; -WhatIf and -Confirm are supported.

.PARAMETER ComputerName
    One or more target hostnames or IP addresses to test.
    Accepts an array or comma-separated list.

.PARAMETER Credential
    Optional PSCredential for explicit WinRM authentication.
    Required when connecting to workgroup machines or machines in untrusted domains.
    Not needed when using Kerberos (domain-joined orchestrating machine to domain targets).
    Note: When -Credential is specified, the target must be in TrustedHosts unless it
          is reachable by FQDN in the same domain.

.PARAMETER Fix
    Attempt to remediate fixable findings (currently: add targets to TrustedHosts).
    Each fix requires ShouldProcess confirmation.
    Use -WhatIf to preview what would change without applying anything.
    Must be run as Administrator to modify TrustedHosts.

.EXAMPLE
    # Test a single server using Kerberos (no explicit credential needed)
    .\Test-RemoteConnectivity.ps1 -ComputerName 'cpm-server.lab.local'

.EXAMPLE
    # Test multiple servers at once
    .\Test-RemoteConnectivity.ps1 -ComputerName 'cpm01.lab.local', 'psm01.lab.local', 'pvwa01.lab.local'

.EXAMPLE
    # Test with explicit credentials and auto-fix TrustedHosts
    $cred = Get-Credential
    .\Test-RemoteConnectivity.ps1 -ComputerName '192.168.1.50' -Credential $cred -Fix

.EXAMPLE
    # Preview what -Fix would change without applying anything
    $cred = Get-Credential
    .\Test-RemoteConnectivity.ps1 -ComputerName '192.168.1.50' -Credential $cred -Fix -WhatIf

.NOTES
    Version:    1.0
    Author:     Brian Bors <brian.bors@cyberark.com>

    Run this script FROM the orchestrating machine (the machine running Invoke-CredFileReset.ps1).
    Run Test-WinRMConfiguration.ps1 ON the target servers to diagnose their local WinRM config.

    Requires:   PowerShell 5.1+
                Network access to target servers on TCP 5985
                Administrator rights if using -Fix to modify TrustedHosts

    Change Log:
    2026-03-27  Initial version
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true, HelpMessage = 'One or more target hostnames or IP addresses to test')]
    [string[]]$ComputerName,

    [Parameter(Mandatory = $false, HelpMessage = 'Credentials for explicit WinRM authentication (for workgroups / untrusted domains)')]
    [PSCredential]$Credential,

    [Parameter(Mandatory = $false, HelpMessage = 'Attempt to remediate fixable findings (requires confirmation for each fix)')]
    [switch]$Fix
)

#region Functions

Function Write-CheckResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Computer,
        [Parameter(Mandatory = $true)]
        [int]$Step,
        [Parameter(Mandatory = $true)]
        [string]$Check,
        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO', 'SKIP')]
        [string]$Result,
        [Parameter(Mandatory = $false)]
        [string]$Detail = ''
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
}

Function Get-TrustedHostsValue {
    try {
        $raw = (Get-Item 'WSMan:\localhost\Client\TrustedHosts' -ErrorAction Stop).Value
        return $raw
    }
    catch {
        return ''
    }
}

Function Test-IsTrustedHost {
    param([string]$Target, [string]$TrustedHosts)
    if ([string]::IsNullOrEmpty($TrustedHosts)) { return $false }
    if ($TrustedHosts -eq '*') { return $true }
    foreach ($entry in $TrustedHosts.Split(',')) {
        $entry = $entry.Trim()
        if ($entry -ieq $Target) { return $true }
        # Wildcard entry like *.domain.com
        if ($entry.StartsWith('*') -and $Target -ilike $entry) { return $true }
    }
    return $false
}

#endregion Functions

#region Main

$results = [System.Collections.Generic.List[PSObject]]::new()
$trustedHosts = Get-TrustedHostsValue

foreach ($computer in $ComputerName) {
    Write-Host ''
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host "  Testing: $computer" -ForegroundColor White
    Write-Host "========================================" -ForegroundColor Magenta

    $stepResults = [ordered]@{}

    # Step 1 — DNS resolution
    $resolvedIP = $null
    try {
        $dnsResult = Resolve-DnsName -Name $computer -ErrorAction Stop | Select-Object -First 1
        $resolvedIP = $dnsResult.IPAddress
        Write-CheckResult -Computer $computer -Step 1 -Check 'DNS resolution' -Result 'PASS' -Detail "Resolved to $resolvedIP"
        $stepResults['DNS'] = $true
    }
    catch {
        Write-CheckResult -Computer $computer -Step 1 -Check 'DNS resolution' -Result 'FAIL' -Detail $_.Exception.Message
        $stepResults['DNS'] = $false
    }

    # Step 2 — ICMP reachability
    try {
        $ping = Test-Connection -ComputerName $computer -Count 1 -ErrorAction Stop
        Write-CheckResult -Computer $computer -Step 2 -Check 'ICMP ping' -Result 'PASS' -Detail "RTT $($ping.ResponseTime)ms"
        $stepResults['ICMP'] = $true
    }
    catch {
        Write-CheckResult -Computer $computer -Step 2 -Check 'ICMP ping' -Result 'WARN' -Detail 'No ICMP response (ICMP may be blocked — not a hard failure)'
        $stepResults['ICMP'] = $false
    }

    # Step 3 — TCP port 5985 (WinRM HTTP)
    try {
        $tcp5985 = Test-NetConnection -ComputerName $computer -Port 5985 -ErrorAction Stop -WarningAction SilentlyContinue
        if ($tcp5985.TcpTestSucceeded) {
            Write-CheckResult -Computer $computer -Step 3 -Check 'TCP 5985 (WinRM HTTP)' -Result 'PASS'
            $stepResults['TCP5985'] = $true
        }
        else {
            Write-CheckResult -Computer $computer -Step 3 -Check 'TCP 5985 (WinRM HTTP)' -Result 'FAIL' -Detail 'Port closed or filtered'
            $stepResults['TCP5985'] = $false
        }
    }
    catch {
        Write-CheckResult -Computer $computer -Step 3 -Check 'TCP 5985 (WinRM HTTP)' -Result 'FAIL' -Detail $_.Exception.Message
        $stepResults['TCP5985'] = $false
    }

    # Step 4 — TCP port 5986 (WinRM HTTPS) — informational only
    try {
        $tcp5986 = Test-NetConnection -ComputerName $computer -Port 5986 -ErrorAction Stop -WarningAction SilentlyContinue
        if ($tcp5986.TcpTestSucceeded) {
            Write-CheckResult -Computer $computer -Step 4 -Check 'TCP 5986 (WinRM HTTPS)' -Result 'INFO' -Detail 'Open (HTTPS listener present)'
        }
        else {
            Write-CheckResult -Computer $computer -Step 4 -Check 'TCP 5986 (WinRM HTTPS)' -Result 'INFO' -Detail 'Closed (HTTP-only configuration)'
        }
    }
    catch {
        Write-CheckResult -Computer $computer -Step 4 -Check 'TCP 5986 (WinRM HTTPS)' -Result 'INFO' -Detail 'Unable to test'
    }

    # Step 5 — TrustedHosts check
    $isTrusted = Test-IsTrustedHost -Target $computer -TrustedHosts $trustedHosts
    if ($null -ne $Credential -and !$isTrusted) {
        Write-CheckResult -Computer $computer -Step 5 -Check 'TrustedHosts' -Result 'FAIL' -Detail "$computer is not in TrustedHosts. NTLM/explicit-credential auth will fail."
        Write-Host "         Remediation: Set-Item WSMan:\localhost\Client\TrustedHosts -Value '$computer' -Force" -ForegroundColor Yellow
        if ($Fix -and $PSCmdlet.ShouldProcess("WSMan:\localhost\Client\TrustedHosts", "Add '$computer'")) {
            try {
                $current = $trustedHosts.TrimEnd(',')
                $newValue = if ([string]::IsNullOrEmpty($current)) { $computer } else { "$current,$computer" }
                Set-Item -Path 'WSMan:\localhost\Client\TrustedHosts' -Value $newValue -Force
                $trustedHosts = Get-TrustedHostsValue
                Write-CheckResult -Computer $computer -Step 5 -Check 'TrustedHosts' -Result 'PASS' -Detail "Added '$computer' to TrustedHosts"
            }
            catch {
                Write-CheckResult -Computer $computer -Step 5 -Check 'TrustedHosts' -Result 'FAIL' -Detail "Fix failed: $($_.Exception.Message)"
            }
        }
        $stepResults['TrustedHosts'] = $false
    }
    elseif ($null -eq $Credential) {
        Write-CheckResult -Computer $computer -Step 5 -Check 'TrustedHosts' -Result 'INFO' -Detail 'Not checked (no -Credential provided; using Kerberos)'
        $stepResults['TrustedHosts'] = $true
    }
    else {
        Write-CheckResult -Computer $computer -Step 5 -Check 'TrustedHosts' -Result 'PASS' -Detail "Covered by TrustedHosts entry: '$trustedHosts'"
        $stepResults['TrustedHosts'] = $true
    }

    # Step 6 — WSMan service responds
    try {
        $wsmanResult = Test-WSMan -ComputerName $computer -ErrorAction Stop
        Write-CheckResult -Computer $computer -Step 6 -Check 'WSMan identify' -Result 'PASS' -Detail "ProductVersion: $($wsmanResult.ProductVersion)"
        $stepResults['WSMan'] = $true
    }
    catch {
        Write-CheckResult -Computer $computer -Step 6 -Check 'WSMan identify' -Result 'FAIL' -Detail $_.Exception.Message
        $stepResults['WSMan'] = $false
    }

    # Step 7 — PSSession open
    $psSession = $null
    if ($stepResults['TCP5985'] -and $stepResults['TrustedHosts']) {
        try {
            $sessionParams = @{
                ComputerName  = $computer
                ErrorAction   = 'Stop'
                SessionOption = (New-PSSessionOption -MaxConnectionRetryCount 1)
            }
            if ($null -ne $Credential) {
                $sessionParams['Credential'] = $Credential
            }
            $psSession = New-PSSession @sessionParams
            Write-CheckResult -Computer $computer -Step 7 -Check 'PSSession open' -Result 'PASS' -Detail "Session Id $($psSession.Id)"
            $stepResults['PSSession'] = $true
        }
        catch {
            Write-CheckResult -Computer $computer -Step 7 -Check 'PSSession open' -Result 'FAIL' -Detail $_.Exception.Message
            $stepResults['PSSession'] = $false
        }
    }
    else {
        Write-CheckResult -Computer $computer -Step 7 -Check 'PSSession open' -Result 'SKIP' -Detail 'Skipped (TCP or TrustedHosts check failed)'
        $stepResults['PSSession'] = $false
    }

    # Step 8 — whoami round-trip
    if ($null -ne $psSession) {
        try {
            $identity = Invoke-Command -Session $psSession -ScriptBlock { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } -ErrorAction Stop
            Write-CheckResult -Computer $computer -Step 8 -Check 'Identity round-trip' -Result 'PASS' -Detail "Authenticated as: $identity"
        }
        catch {
            Write-CheckResult -Computer $computer -Step 8 -Check 'Identity round-trip' -Result 'FAIL' -Detail $_.Exception.Message
        }
        finally {
            Remove-PSSession -Session $psSession -ErrorAction SilentlyContinue
        }
    }
    else {
        Write-CheckResult -Computer $computer -Step 8 -Check 'Identity round-trip' -Result 'SKIP' -Detail 'Skipped (no PSSession)'
    }

    $record = [PSCustomObject]@{
        Computer    = $computer
        DNS         = $stepResults['DNS']
        ICMP        = $stepResults['ICMP']
        TCP5985     = $stepResults['TCP5985']
        TrustedHost = $stepResults['TrustedHosts']
        WSMan       = $stepResults['WSMan']
        PSSession   = $stepResults['PSSession']
    }
    $results.Add($record)
}

# Summary table
Write-Host ''
Write-Host '========================================' -ForegroundColor Magenta
Write-Host '  SUMMARY' -ForegroundColor White
Write-Host '========================================' -ForegroundColor Magenta
$results | Format-Table -AutoSize

$failures = $results | Where-Object { $_.DNS -eq $false -or $_.TCP5985 -eq $false -or $_.WSMan -eq $false -or $_.PSSession -eq $false }
if ($null -ne $failures -and @($failures).Count -gt 0) {
    Write-Host "One or more targets have connectivity failures. Run Test-WinRMConfiguration.ps1 locally on the affected servers to diagnose further." -ForegroundColor Yellow
}
else {
    Write-Host "All targets passed connectivity checks." -ForegroundColor Green
}

#endregion Main
