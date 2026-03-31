<#
.SYNOPSIS
    Tests WinRM connectivity from the orchestrating machine to CyberArk component servers.

.DESCRIPTION
    Run from the ORCHESTRATING machine before using Invoke-CredFileReset.ps1 to verify that
    WinRM connectivity is properly configured to your target component servers.

    Performs the following checks for each target:
      Step 1  DNS resolution
      Step 2  ICMP reachability (WARN only — ICMP may be legitimately blocked)
      Step 3  TCP port 5985 (WinRM HTTP) — fallback port used when HTTPS is unavailable
      Step 4  TCP port 5986 (WinRM HTTPS) — primary port; Invoke-CredFileReset.ps1 tries this first
      Step 5  TrustedHosts entry — only needed for non-SSL connections with explicit credentials
      Step 6  WSMan identify probe — confirms the WinRM service responds
      Step 7  PSSession creation — tries SSL (port 5986) first, falls back to HTTP (port 5985)
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
    Provide explicit credentials when:
      - Running from a Remote SSH session (SSH cannot delegate Kerberos tickets)
      - Connecting to workgroup machines (no domain Kerberos available)
      - Connecting to machines in untrusted domains
    For domain-joined targets from a domain-joined orchestrating machine, leave this empty
    and implicit Kerberos authentication is used automatically.
    Prefer a domain account (DOMAIN\user) — domain accounts authenticate via Kerberos and
    work without TrustedHosts configuration. Local accounts authenticate via NTLM and
    require the target to be in TrustedHosts unless the connection uses SSL (port 5986).
    Note: SSL (HTTPS, port 5986) connections do NOT require TrustedHosts regardless of
    account type. TrustedHosts is only needed for non-SSL connections with local/NTLM accounts.

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
                Network access to target servers on TCP 5986 (WinRM HTTPS, preferred) or
                TCP 5985 (WinRM HTTP, fallback)
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
    $line = "[$Computer] $stepStr $Check"
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

    # Step 3 — TCP port 5985 (WinRM HTTP) — fallback port; INFO if closed since SSL is tried first
    try {
        $tcp5985 = Test-NetConnection -ComputerName $computer -Port 5985 -ErrorAction Stop -WarningAction SilentlyContinue
        if ($tcp5985.TcpTestSucceeded) {
            Write-CheckResult -Computer $computer -Step 3 -Check 'TCP 5985 (WinRM HTTP fallback)' -Result 'PASS'
            $stepResults['TCP5985'] = $true
        }
        else {
            Write-CheckResult -Computer $computer -Step 3 -Check 'TCP 5985 (WinRM HTTP fallback)' -Result 'INFO' -Detail 'Closed — only needed if HTTPS (port 5986) is also unavailable'
            $stepResults['TCP5985'] = $false
        }
    }
    catch {
        Write-CheckResult -Computer $computer -Step 3 -Check 'TCP 5985 (WinRM HTTP fallback)' -Result 'INFO' -Detail $_.Exception.Message
        $stepResults['TCP5985'] = $false
    }

    # Step 4 — TCP port 5986 (WinRM HTTPS) — primary port tried first by Invoke-CredFileReset.ps1
    try {
        $tcp5986 = Test-NetConnection -ComputerName $computer -Port 5986 -ErrorAction Stop -WarningAction SilentlyContinue
        if ($tcp5986.TcpTestSucceeded) {
            Write-CheckResult -Computer $computer -Step 4 -Check 'TCP 5986 (WinRM HTTPS)' -Result 'PASS' -Detail 'Open — SSL connections will be used (no TrustedHosts required)'
            $stepResults['TCP5986'] = $true
        }
        else {
            Write-CheckResult -Computer $computer -Step 4 -Check 'TCP 5986 (WinRM HTTPS)' -Result 'WARN' -Detail 'Closed — will fall back to HTTP (port 5985); TrustedHosts may be required'
            $stepResults['TCP5986'] = $false
        }
    }
    catch {
        Write-CheckResult -Computer $computer -Step 4 -Check 'TCP 5986 (WinRM HTTPS)' -Result 'WARN' -Detail "Unable to test: $($_.Exception.Message)"
        $stepResults['TCP5986'] = $false
    }

    # Step 5 — TrustedHosts check
    # SSL connections (port 5986) bypass TrustedHosts entirely — this is WARN not FAIL.
    $isTrusted = Test-IsTrustedHost -Target $computer -TrustedHosts $trustedHosts
    if ($null -ne $Credential -and !$isTrusted) {
        Write-CheckResult -Computer $computer -Step 5 -Check 'TrustedHosts' -Result 'WARN' -Detail "$computer not in TrustedHosts — SSL (port 5986) bypasses this; only needed for HTTP fallback with local/NTLM accounts"
        Write-Host "         Remediation (if HTTP fallback needed): Set-Item WSMan:\localhost\Client\TrustedHosts -Value '$computer' -Force" -ForegroundColor Yellow
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

    # Step 7 — PSSession open: try SSL first (port 5986), fall back to HTTP (port 5985)
    # This mirrors the behaviour of Invoke-CredFileReset.ps1's New-PSLogon function.
    $psSession = $null
    if ($stepResults['TrustedHosts']) {
        $psoptionsSSL = New-PSSessionOption -MaxConnectionRetryCount 1 -SkipCACheck -SkipCNCheck -SkipRevocationCheck
        $psoptions    = New-PSSessionOption -MaxConnectionRetryCount 1
        $sessionParamsSSL = @{
            ComputerName  = $computer
            UseSSL        = $true
            SessionOption = $psoptionsSSL
            ErrorAction   = 'Stop'
        }
        $sessionParams = @{
            ComputerName  = $computer
            ErrorAction   = 'Stop'
            SessionOption = $psoptions
        }
        if ($null -ne $Credential) {
            $sessionParamsSSL['Credential'] = $Credential
            $sessionParams['Credential']    = $Credential
        }
        # Try SSL first
        try {
            $psSession = New-PSSession @sessionParamsSSL
            Write-CheckResult -Computer $computer -Step 7 -Check 'PSSession open (SSL)' -Result 'PASS' -Detail "Session Id $($psSession.Id) via HTTPS port 5986"
            $stepResults['PSSession'] = $true
        }
        catch {
            $sslErr = $_.Exception.Message
            Write-CheckResult -Computer $computer -Step 7 -Check 'PSSession open (SSL)' -Result 'WARN' -Detail "SSL failed: $sslErr — trying HTTP fallback"
            # Fall back to HTTP
            if ($stepResults['TCP5985']) {
                try {
                    $psSession = New-PSSession @sessionParams
                    Write-CheckResult -Computer $computer -Step 7 -Check 'PSSession open (HTTP fallback)' -Result 'PASS' -Detail "Session Id $($psSession.Id) via HTTP port 5985"
                    $stepResults['PSSession'] = $true
                }
                catch {
                    Write-CheckResult -Computer $computer -Step 7 -Check 'PSSession open (HTTP fallback)' -Result 'FAIL' -Detail $_.Exception.Message
                    $stepResults['PSSession'] = $false
                }
            }
            else {
                Write-CheckResult -Computer $computer -Step 7 -Check 'PSSession open (HTTP fallback)' -Result 'SKIP' -Detail 'Skipped (TCP 5985 not reachable)'
                $stepResults['PSSession'] = $false
            }
        }
    }
    else {
        Write-CheckResult -Computer $computer -Step 7 -Check 'PSSession open' -Result 'SKIP' -Detail 'Skipped (TrustedHosts check failed)'
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
        TCP5986     = $stepResults['TCP5986']
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

$failures = $results | Where-Object { $_.DNS -eq $false -or $_.WSMan -eq $false -or $_.PSSession -eq $false }
if ($null -ne $failures -and @($failures).Count -gt 0) {
    Write-Host "One or more targets have connectivity failures. Run Test-WinRMConfiguration.ps1 locally on the affected servers to diagnose further." -ForegroundColor Yellow
    Write-Host "Tip: Failures on PSSession with both TCP5985=False and TCP5986=False indicate no WinRM listener is reachable on either port." -ForegroundColor Yellow
}
else {
    Write-Host "All targets passed connectivity checks." -ForegroundColor Green
}

#endregion Main
