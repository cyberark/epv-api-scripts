<#
.SYNOPSIS
    Run CPM account actions on accounts via CSV or filter criteria, individually or using bulk APIs.

.DESCRIPTION
    Operates in two modes selected by ParameterSet:

    Filters mode (default)
        Filters accounts from PVWA by safe, platform, username, address, search keywords,
        or using the API's savedFilter and filter parameters, then applies a single
        AccountsAction to all matches. Produces timestamped good/bad CSVs in the script folder.

    CSV mode (-CsvPath)
        Reads accounts from a CSV file. Each row specifies an Action column
        (Verify / Change / Reconcile / Resume / Disable / CheckIn / Cancel /
        SetNextPassword / ChangeInVault) and identifies the account either by:
          - AccountID column (fast path — bypasses search), or
          - safe + username + address columns (with optional platformID and name).
        Produces <CsvPath>.good.csv and <CsvPath>.bad.csv alongside the input file.

    Bulk API modes (-BulkOnPrem / -BulkPCloud)
        Add -BulkOnPrem (on-prem PVWA v15.2+) or -BulkPCloud (Privilege Cloud) to submit
        accounts in batches instead of one call per account. Bulk mode enables additional
        actions beyond the individual endpoints:
          On-prem bulk:   Verify, Change, Reconcile, Resume, CheckIn, Cancel
          PCloud bulk:    Verify, Change, Reconcile, Resume, CheckIn (unlock), Delete
        PCloud bulk is asynchronous; the script polls until each batch completes and writes
        per-account success/failure to good/bad CSVs. On-prem bulk is synchronous per batch.

    Privilege Cloud URL detection
        PCloud is detected automatically from the PVWA URL pattern
        (*.privilegecloud.cyberark.cloud or *.privilegecloud.cyberark.com).
        Incorrect URLs such as https://<sub>.cyberark.cloud/privilegecloud are corrected
        automatically.

    Both modes write a timestamped log file to the script folder.

.PARAMETER PVWAURL
    Base URL of the PVWA instance, e.g. https://pvwa.example.com/PasswordVault

.PARAMETER AccountsAction
    (Filters mode) CPM action to apply to all filtered accounts.
    See the README for the full list of supported actions.

.PARAMETER CsvPath
    (CSV mode) Path to the input CSV file. Required columns: Action, and either AccountID or
    safe + username + address. Optional columns: platformID, name, DisableReason,
    NewCredentials, ChangeImmediately.

.EXAMPLE
    # Filters mode — verify all accounts in a safe
    .\Invoke-AccountActions.ps1 -PVWAURL https://pvwa.example.com/PasswordVault -AccountsAction Verify -SafeName MySafe

.EXAMPLE
    # Filters mode — change all accounts where the last change failed
    .\Invoke-AccountActions.ps1 -PVWAURL https://pvwa.example.com/PasswordVault -AccountsAction Change -PlatformID WinDomain -SavedFilter FailedChange

.EXAMPLE
    # Filters mode — resume all CPM-disabled accounts in a safe
    .\Invoke-AccountActions.ps1 -PVWAURL https://pvwa.example.com/PasswordVault -AccountsAction Resume -SafeName MySafe -SavedFilter DisabledPasswordByCPM

.EXAMPLE
    # CSV mode — per-row actions driven by a CSV file
    .\Invoke-AccountActions.ps1 -PVWAURL https://pvwa.example.com/PasswordVault -CsvPath .\accounts.csv

.EXAMPLE
    # CSV mode with a pre-existing logon token
    .\Invoke-AccountActions.ps1 -PVWAURL https://pvwa.example.com/PasswordVault -CsvPath .\accounts.csv -logonToken $token

.NOTES
    CyberArk PVWA v10.4 and above. On-prem bulk API requires v15.2+.
#>
[CmdletBinding(DefaultParameterSetName = 'Filters')]
param(
    [Parameter(Mandatory = $true, HelpMessage = 'Enter the PVWA URL')]
    [Alias('url')]
    [String]$PVWAURL,

    [Parameter(Mandatory = $false, HelpMessage = 'Authentication type (Default: CyberArk)')]
    [ValidateSet('cyberark', 'ldap', 'radius')]
    [String]$AuthType = 'cyberark',

    [Parameter(Mandatory = $false)]
    [ValidateScript({ $AuthType -eq 'radius' })]
    [String]$OTP,

    [Parameter(Mandatory = $false)]
    [Switch]$DisableSSLVerify,

    [Parameter(Mandatory = $false)]
    [PSCredential]$PVWACredentials,

    [Parameter(Mandatory = $false)]
    $logonToken,

    [Parameter(Mandatory = $false)]
    [Switch]$concurrentSession,

    [Parameter(Mandatory = $false, DontShow)]
    [Switch]$IncludeCallStack,

    [Parameter(Mandatory = $false, DontShow)]
    [Switch]$UseVerboseFile,

    # CSV ParameterSet
    [Parameter(ParameterSetName = 'CSV', Mandatory = $true, HelpMessage = 'Path to the accounts CSV file')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [Alias('path')]
    [String]$CsvPath,

    [Parameter(ParameterSetName = 'CSV', Mandatory = $false)]
    [ValidateSet('Comma', 'Tab')]
    [String]$CsvDelimiter = 'Comma',

    # Filters ParameterSet
    [Parameter(ParameterSetName = 'Filters', Mandatory = $true, HelpMessage = 'Account action: Verify, Change, Reconcile, Resume, Disable, CheckIn, Cancel, SetNextPassword, ChangeInVault (on-prem bulk), Delete (PCloud bulk)')]
    [ValidateSet('Verify', 'Change', 'Reconcile', 'Resume', 'Disable', 'CheckIn', 'Cancel', 'SetNextPassword', 'ChangeInVault', 'Delete')]
    [Alias('Action')]
    [String]$AccountsAction,

    [Parameter(ParameterSetName = 'Filters', Mandatory = $false, HelpMessage = 'Safe name filter (max 28 chars)')]
    [ValidateScript({ $_.Length -le 28 })]
    [Alias('Safe')]
    [String]$SafeName,

    [Parameter(ParameterSetName = 'Filters', Mandatory = $false)]
    [String]$PlatformID,

    [Parameter(ParameterSetName = 'Filters', Mandatory = $false)]
    [String]$UserName,

    [Parameter(ParameterSetName = 'Filters', Mandatory = $false)]
    [String]$Address,

    [Parameter(ParameterSetName = 'Filters', Mandatory = $false, HelpMessage = 'Space-separated keywords (passed to search= in the API)')]
    [String]$Search,

    [Parameter(ParameterSetName = 'Filters', Mandatory = $false, HelpMessage = 'Freeform filter expression passed directly to filter= (e.g. "Username Contains admin")')]
    [String]$Filter,

    [Parameter(ParameterSetName = 'Filters', Mandatory = $false, HelpMessage = 'Named saved filter passed directly to savedFilter= (e.g. DisabledPasswordByCPM, FailedChange)')]
    [String]$SavedFilter,

    [Parameter(ParameterSetName = 'Filters', Mandatory = $false)]
    [ValidateSet('contains', 'startswith')]
    [String]$SearchType,

    # Bulk API modes — mutually exclusive
    [Parameter(ParameterSetName = 'Filters', Mandatory = $false)]
    [Parameter(ParameterSetName = 'CSV', Mandatory = $false)]
    [Switch]$BulkOnPrem,

    [Parameter(ParameterSetName = 'Filters', Mandatory = $false)]
    [Parameter(ParameterSetName = 'CSV', Mandatory = $false)]
    [Switch]$BulkPCloud,

    [Parameter(Mandatory = $false, HelpMessage = 'Accounts per bulk batch (1-10000, default 100)')]
    [ValidateRange(1, 10000)]
    [int]$BatchSize = 100,

    # Only applies to on-prem Change bulk; sets ChangeEntireGroup on every item
    [Parameter(Mandatory = $false)]
    [Switch]$ChangeEntireGroup,

    [Parameter(Mandatory = $false, HelpMessage = 'Seconds between PCloud bulk status polls (default 5)')]
    [ValidateRange(1, 300)]
    [int]$PollInterval = 5,

    [Parameter(Mandatory = $false, HelpMessage = 'Reason stored when disabling CPM management (default: [No Reason])')]
    [String]$DisableReason = '[No Reason]',

    # Required for SetNextPassword and ChangeInVault; use Read-Host -AsSecureString or ConvertTo-SecureString
    [Parameter(Mandatory = $false)]
    [SecureString]$NewCredentials,

    # Only applies to SetNextPassword: trigger CPM change immediately instead of at next scheduled interval
    [Parameter(Mandatory = $false)]
    [Switch]$ChangeImmediately
)

$ScriptFullPath = $MyInvocation.MyCommand.Path
$ScriptLocation = Split-Path -Parent $ScriptFullPath
$ScriptVersion = '1.0'

$ScriptParameters = @()
$PSBoundParameters.GetEnumerator() | ForEach-Object { $ScriptParameters += ("-{0} '{1}'" -f $_.Key, $_.Value) }
$global:g_ScriptCommand = '{0} {1}' -f $ScriptFullPath, ($ScriptParameters -join ' ')

$global:LOG_DATE = (Get-Date -Format yyyyMMdd) + '-' + (Get-Date -Format HHmmss)
$global:LOG_FILE_PATH = "$ScriptLocation\Account_Actions_Utility_$($global:LOG_DATE).log"

$InDebug = $PSBoundParameters.Debug.IsPresent
$InVerbose = $PSBoundParameters.Verbose.IsPresent
$global:IncludeCallStack = $IncludeCallStack.IsPresent
$global:UseVerboseFile = $UseVerboseFile.IsPresent

[hashtable]$Global:BadAccountHashTable = @{}

#region Helper Functions
function Write-LogMessage {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [Switch]$Header,
        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory = $false)]
        [Switch]$Footer,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Debug', 'Verbose')]
        [String]$type = 'Info',
        [Parameter(Mandatory = $false)]
        [String]$LogFile = $LOG_FILE_PATH,
        [Parameter(Mandatory = $false)]
        [int]$pad = 20
    )
    $verboseFile = $LOG_FILE_PATH.Replace('.log', '_Verbose.log')
    try {
        if ($Header) {
            '=======================================' | Out-File -Append -FilePath $LOG_FILE_PATH
            Write-Host '======================================='
        }
        elseif ($SubHeader) {
            '------------------------------------' | Out-File -Append -FilePath $LOG_FILE_PATH
            Write-Host '------------------------------------'
        }
        $LogTime = "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')]`t"
        $msgToWrite = $LogTime
        $writeToFile = $true
        if ([string]::IsNullOrEmpty($Msg)) { $Msg = 'N/A' }
        $Msg = Remove-SensitiveData -message $Msg
        switch ($type) {
            'Info' {
                Write-Host $MSG.ToString()
                $msgToWrite += "[INFO]`t`t$Msg"
            }
            'Warning' {
                Write-Host $MSG.ToString() -ForegroundColor DarkYellow
                $msgToWrite += "[WARNING]`t$Msg"
                if ($global:UseVerboseFile) { $msgToWrite | Out-File -Append -FilePath $verboseFile }
            }
            'Error' {
                Write-Host $MSG.ToString() -ForegroundColor Red
                $msgToWrite += "[ERROR]`t`t$Msg"
                if ($global:UseVerboseFile) { $msgToWrite | Out-File -Append -FilePath $verboseFile }
            }
            'Debug' {
                if ($InDebug -or $InVerbose) {
                    Write-Debug $MSG
                    $writeToFile = $true
                    $msgToWrite += "[DEBUG]`t`t$Msg"
                }
                else { $writeToFile = $false }
            }
            'Verbose' {
                if ($InVerbose -or $global:UseVerboseFile) {
                    $arrMsg = $msg.Split(":`t", 2)
                    if ($arrMsg.Count -gt 1) { $msg = $arrMsg[0].PadRight($pad) + $arrMsg[1] }
                    $msgToWrite += "[VERBOSE]`t$Msg"
                    if ($global:IncludeCallStack) {
                        function Get-CallStack {
                            $stack = ''
                            $excludeItems = @('Write-LogMessage', 'Get-CallStack', '<ScriptBlock>')
                            Get-PSCallStack | ForEach-Object {
                                if ($PSItem.Command -notin $excludeItems) {
                                    $command = $PSItem.Command
                                    if ($command -eq $Global:scriptName) { $command = 'Base' }
                                    elseif ([string]::IsNullOrEmpty($command)) { $command = '**Blank**' }
                                    $stack += "$command $($PSItem.Location); "
                                }
                            }
                            return $stack
                        }
                        $stack = Get-CallStack
                        $stackMsg = "CallStack:`t$stack"
                        $arrStackMsg = $stackMsg.Split(":`t", 2)
                        if ($arrMsg.Count -gt 1) { $stackMsg = $arrStackMsg[0].PadRight($pad) + $arrStackMsg[1].Trim() }
                        Write-Verbose $stackMsg
                        $msgToWrite += "`n$LogTime"
                        $msgToWrite += "[STACK]`t`t$stackMsg"
                    }
                    if ($InVerbose) { Write-Verbose $MSG }
                    else { $writeToFile = $false }
                    if ($global:UseVerboseFile) { $msgToWrite | Out-File -Append -FilePath $verboseFile }
                }
                else { $writeToFile = $false }
            }
        }
        if ($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH }
        if ($Footer) {
            '=======================================' | Out-File -Append -FilePath $LOG_FILE_PATH
            Write-Host '======================================='
        }
    }
    catch {
        Write-Error "Error in writing log: $($_.Exception.Message)"
    }
}

function Remove-SensitiveData {
    [CmdletBinding()]
    param(
        [Alias('MSG', 'value', 'string')]
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$message
    )
    begin { $cleanedMessage = $message }
    process {
        if ($global:LogSensitiveData -eq $true) { return $message }
        $checkFor = @('password', 'secret', 'NewCredentials', 'access_token', 'client_secret', 'auth', 'Authorization', 'Answer', 'Token')
        $checkFor | ForEach-Object {
            if ($cleanedMessage -imatch "[{\\""']{2,}\s{0,}$PSItem\s{0,}[\\""']{2,}\s{0,}[:=][\\""']{2,}\s{0,}(?<Sensitive>.*?)\s{0,}[\\""']{2,}(?=[,:;])") {
                $cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
            }
            elseif ($cleanedMessage -imatch "[""']{1,}\s{0,}$PSItem\s{0,}[""']{1,}\s{0,}[:=][""']{1,}\s{0,}(?<Sensitive>.*?)\s{0,}[""']{1,}") {
                $cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
            }
            elseif ($cleanedMessage -imatch "(?:\s{0,}$PSItem\s{0,}[:=])\s{0,}(?<Sensitive>.*?)(?=; |:|,|}|\))") {
                $cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
            }
        }
    }
    end { return $cleanedMessage }
}

function Join-ExceptionMessage {
    param([Exception]$e)
    process {
        $msg = 'Source:{0}; Message: {1}' -f $e.Source, $e.Message
        while ($e.InnerException) {
            $e = $e.InnerException
            $msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
        }
        return $msg
    }
}

function ConvertTo-URL {
    param([string]$sText)
    if ($sText.Trim() -ne '') {
        Write-LogMessage -type Debug -MSG "Returning URL Encode of $sText"
        return [URI]::EscapeDataString($sText)
    }
    else { return $sText }
}

function Get-TrimmedString {
    param([string]$sText)
    if ($null -ne $sText) { return $sText.Trim() }
    return $sText
}

function Format-PVWAURL {
    param([Parameter()][string]$PVWAURL)
    if ($PVWAURL -match '^(?<scheme>https:\/\/|http:\/\/|).*$') {
        if ('http://' -eq $Matches['scheme'] -and $AllowInsecureURL -eq $false) {
            $PVWAURL = $PVWAURL.Replace('http://', 'https://')
            Write-LogMessage -type Warning -MSG "Detected insecure scheme in URL`nThe URL was automatically updated to: $PVWAURL`nPlease ensure you are using the correct scheme in the URL"
        }
        elseif ([string]::IsNullOrEmpty($Matches['scheme'])) {
            $PVWAURL = "https://$PVWAURL"
            Write-LogMessage -type Warning -MSG "Detected no scheme in URL`nThe URL was automatically updated to: $PVWAURL`nPlease ensure you are using the correct scheme in the URL"
        }
    }
    if ($PVWAURL -match '^(?:https|http):\/\/(?<sub>.*).cyberark.(?<top>cloud|com)\/privilegecloud.*$') {
        $PVWAURL = "https://$($Matches['sub']).privilegecloud.cyberark.$($Matches['top'])/PasswordVault/"
        Write-LogMessage -type Warning -MSG "Detected improperly formatted Privilege Cloud URL`nThe URL was automatically updated to: $PVWAURL`nPlease ensure you are using the correct URL. Pausing for 10 seconds.`n"
        Start-Sleep 10
    }
    elseif ($PVWAURL -notmatch '^.*PasswordVault(?:\/|)$') {
        $PVWAURL = "$PVWAURL/PasswordVault/"
        Write-LogMessage -type Warning -MSG "Detected improperly formatted Privileged Access Manager URL`nThe URL was automatically updated to: $PVWAURL`nPlease ensure you are using the correct URL. Pausing for 10 seconds.`n"
        Start-Sleep 10
    }
    return $PVWAURL
}

function Test-CommandExists {
    param($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try { if (Get-Command $command) { return $true } }
    catch { Write-Host "$command does not exist"; return $false }
    finally { $ErrorActionPreference = $oldPreference }
}

function Disable-SSLVerification {
    [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    if (-not ('DisableCertValidationCallback' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class DisableCertValidationCallback {
    public static bool ReturnTrue(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) { return true; }
    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(DisableCertValidationCallback.ReturnTrue);
    }
}
'@
    }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [DisableCertValidationCallback]::GetDelegate()
}
#endregion

#region REST Functions
function Invoke-Rest {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'DELETE', 'PATCH', 'PUT')]
        [Alias('Method')]
        [String]$Command,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$URI,
        [Parameter(Mandatory = $false)]
        [Alias('Headers')]
        $Header,
        [Parameter(Mandatory = $false)]
        $Body,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Continue', 'Ignore', 'Inquire', 'SilentlyContinue', 'Stop', 'Suspend')]
        [String]$ErrAction = 'Continue',
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSec = 2700,
        [Parameter(Mandatory = $false)]
        [string]$ContentType = 'application/json'
    )
    Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tStart"
    $restResponse = ''
    try {
        if ([string]::IsNullOrEmpty($Body)) {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tInvoke-RestMethod -Uri $URI -Method $Command -ContentType $ContentType -TimeoutSec $TimeoutSec"
            $restMethodParams = @{
                Uri         = $URI
                Method      = $Command
                Header      = $Header
                ContentType = $ContentType
                TimeoutSec  = $TimeoutSec
                ErrorAction = $ErrAction
                Verbose     = $false
                Debug       = $false
            }
            $restResponse = Invoke-RestMethod @restMethodParams
        }
        else {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tInvoke-RestMethod -Uri $URI -Method $Command -ContentType $ContentType -Body $($Body | ConvertTo-Json -Compress) -TimeoutSec $TimeoutSec"
            $restMethodParams = @{
                Uri         = $URI
                Method      = $Command
                Header      = $Header
                ContentType = $ContentType
                Body        = [System.Text.Encoding]::UTF8.GetBytes($Body)
                TimeoutSec  = $TimeoutSec
                ErrorAction = $ErrAction
                Verbose     = $false
                Debug       = $false
            }
            $restResponse = Invoke-RestMethod @restMethodParams
        }
        Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tInvoke-RestMethod completed without error"
    }
    catch [System.Net.WebException] {
        Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tCaught WebException"
        if ($ErrAction -match '\bContinue\b|\bInquire\b|\bStop\b|\bSuspend\b') {
            Write-LogMessage -type Error -MSG "Error Message: $_"
            Write-LogMessage -type Error -MSG "Exception Message: $($_.Exception.Message)"
            Write-LogMessage -type Error -MSG "Status Code: $($_.Exception.Response.StatusCode.value__)"
            Write-LogMessage -type Error -MSG "Status Description: $($_.Exception.Response.StatusDescription)"
            $restResponse = $null
            Throw
        }
        else { Throw $PSItem }
    }
    catch [Microsoft.PowerShell.Commands.HttpResponseException] {
        Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tCaught HttpResponseException"
        $httpException = $PSItem
        $errorBody = $PSItem.ErrorDetails.Message
        $Details = $null
        try { $Details = ($errorBody | ConvertFrom-Json) }
        catch {
            # Error body is not JSON (e.g. HTML error page) — rethrow the original HTTP error, not the JSON parse error
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tError body is not JSON: $errorBody"
            Throw $httpException
        }
        if ('SFWS0007' -eq $Details.ErrorCode) {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.ErrorMessage)"
            Throw $PSItem
        }
        elseif ('PASWS013E' -eq $Details.ErrorCode) {
            Write-LogMessage -type Error -MSG "$($Details.ErrorMessage)" -Header -Footer
            Throw "$($Details.ErrorMessage)"
        }
        elseif ('SFWS0002' -eq $Details.ErrorCode) {
            Write-LogMessage -type Warning -MSG "$($Details.ErrorMessage)"
            Throw "$($Details.ErrorMessage)"
        }
        elseif ('SFWS0012' -eq $Details.ErrorCode) {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.ErrorMessage)"
            Throw $PSItem
        }
        elseif ('PASWS011E' -eq $Details.Details.Errorcode) {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.Details.ErrorMessage)"
            Throw $PSItem
        }
        elseif ($null -eq $Details.Details.Errorcode) {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tError in running $Command on '$URI'"
            if (-not [string]::IsNullOrEmpty($Details.ErrorMessage)) {
                Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.ErrorMessage)"
                Throw "$($Details.ErrorMessage)"
            }
            else {
                Throw $PSItem.Exception
            }
        }
        else {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tError in running $Command on '$URI', $($Details.Details.ErrorMessage -join ';')"
            Throw $($Details.Details.ErrorMessage)
        }
    }
    catch {
        Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tCaught Exception"
        Write-LogMessage -type Error -MSG "Error in running $Command on '$URI', $_.Exception"
        Throw $(New-Object System.Exception ("Error in running $Command on '$URI'", $_.Exception))
    }
    Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tResponse: $restResponse"
    return $restResponse
}

function Get-LogonHeader {
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials,
        [Parameter(Mandatory = $false)]
        [bool]$concurrentSession,
        [Parameter(Mandatory = $false)]
        [string]$RadiusOTP
    )
    if ($concurrentSession) {
        $logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password; concurrentSession = 'true' } | ConvertTo-Json -Compress
    }
    else {
        $logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password } | ConvertTo-Json -Compress
    }
    if (![string]::IsNullOrEmpty($RadiusOTP)) {
        $logonBody.Password += ",$RadiusOTP"
    }
    try {
        $logonToken = Invoke-Rest -Command Post -URI $URL_Logon -Body $logonBody
        $logonBody = ''
    }
    catch {
        Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.Exception.Response.StatusDescription)", $_.Exception))
    }
    if ([string]::IsNullOrEmpty($logonToken)) {
        Throw 'Get-LogonHeader: Logon Token is Empty - Cannot login'
    }
    return @{Authorization = $logonToken }
}

function Invoke-Logoff {
    try {
        if ($null -ne $g_LogonHeader) {
            Write-LogMessage -type Info -MSG 'Logoff Session...'
            $logoffParams = @{
                Command = 'POST'
                URI     = $URL_Logoff
                Header  = $g_LogonHeader
            }
            Invoke-Rest @logoffParams | Out-Null
            Set-Variable -Name g_LogonHeader -Value $null -Scope global
        }
    }
    catch {
        Throw $(New-Object System.Exception ('Invoke-Logoff: Failed to logoff session', $_.Exception))
    }
}
#endregion

#region Account Functions
function Get-Account {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$safeName,
        [Parameter(Mandatory = $false)]
        [String]$accountName,
        [Parameter(Mandatory = $false)]
        [String]$accountAddress,
        [Parameter(Mandatory = $false)]
        [String]$accountPlatformID,
        [Parameter(Mandatory = $false)]
        [String]$accountObjectName,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Continue', 'Ignore', 'Inquire', 'SilentlyContinue', 'Stop', 'Suspend')]
        [String]$ErrAction = 'Continue'
    )
    $GetAccountsList = @()
    $WhereArray = @()

    $searchURL = $URL_Accounts + "?filter=safename eq $(ConvertTo-URL $safeName)"
    if (-not [string]::IsNullOrEmpty($accountName) -or -not [string]::IsNullOrEmpty($accountAddress)) {
        $searchURL += "&search=$(ConvertTo-URL $accountName) $(ConvertTo-URL $accountAddress)"
    }

    if (-not [string]::IsNullOrEmpty($accountName)) { $WhereArray += '$_.userName -eq $accountName' }
    if (-not [string]::IsNullOrEmpty($accountAddress)) { $WhereArray += '$_.address -eq $accountAddress' }
    if (-not [string]::IsNullOrEmpty($accountPlatformID)) { $WhereArray += '$_.platformId -eq $accountPlatformID' }
    if (-not [string]::IsNullOrEmpty($accountObjectName)) { $WhereArray += '$_.name -eq $accountObjectName' }

    try {
        $getAccountsParams = @{
            Command   = 'Get'
            URI       = $searchURL
            Header    = $global:g_LogonHeader
            ErrAction = $ErrAction
        }
        $response = Invoke-Rest @getAccountsParams
        $GetAccountsList += $response.value
        Write-LogMessage -type Debug -MSG "Found $($GetAccountsList.Count) accounts so far..."
        $nextLink = $response.nextLink
        while (-not [string]::IsNullOrEmpty($nextLink)) {
            $nextPageParams = @{
                Command = 'Get'
                URI     = "$PVWAURL/$nextLink"
                Header  = $global:g_LogonHeader
            }
            $response = Invoke-Rest @nextPageParams
            $nextLink = $response.nextLink
            $GetAccountsList += $response.value
            Write-LogMessage -type Debug -MSG "Found $($GetAccountsList.Count) accounts so far..."
        }
    }
    catch [System.Net.WebException] {
        Throw $(New-Object System.Exception ("Get-Account: Error getting accounts. Error: $($_.Exception.Response.StatusDescription)", $_.Exception))
    }

    if ($WhereArray.Count -gt 0) {
        $WhereFilter = [scriptblock]::Create(($WhereArray -join ' -and '))
        return ($GetAccountsList | Where-Object $WhereFilter)
    }
    return $GetAccountsList
}

function Get-FilteredAccounts {
    param(
        [Parameter(Mandatory = $false)][string]$sSafeName,
        [Parameter(Mandatory = $false)][string]$sPlatformID,
        [Parameter(Mandatory = $false)][string]$sUserName,
        [Parameter(Mandatory = $false)][string]$sAddress,
        [Parameter(Mandatory = $false)][string]$sSearch,
        [Parameter(Mandatory = $false)][string]$sFilter,
        [Parameter(Mandatory = $false)][string]$sSavedFilter,
        [Parameter(Mandatory = $false)][string]$sSearchType
    )
    $GetAccountsList = @()
    try {
        $keywords = "$sPlatformID $sUserName $sAddress $sSearch".Trim()
        $filterURL = $URL_Accounts + '?'
        if (-not [string]::IsNullOrEmpty($keywords)) {
            $filterURL += "search=$(ConvertTo-URL $keywords)&"
        }
        if (-not [string]::IsNullOrEmpty($sSearchType)) {
            $filterURL += "searchType=$sSearchType&"
        }
        # Build filter= clause: combine safeName and freeform -Filter if both present
        $filterClauses = @()
        if (-not [string]::IsNullOrEmpty($sSafeName)) {
            $filterClauses += "safename eq $(ConvertTo-URL $sSafeName)"
        }
        if (-not [string]::IsNullOrEmpty($sFilter)) {
            $filterClauses += $sFilter
        }
        if ($filterClauses.Count -gt 0) {
            $filterURL += "filter=$($filterClauses -join ' AND ')&"
        }
        if (-not [string]::IsNullOrEmpty($sSavedFilter)) {
            $filterURL += "savedFilter=$sSavedFilter&"
        }
        $filterURL += 'limit=500'
        Write-LogMessage -type Debug -MSG "Filter accounts using: $filterURL"
    }
    catch {
        Throw $(New-Object System.Exception ('Get-FilteredAccounts: Error creating filter URL', $_.Exception))
    }
    try {
        $getParams = @{
            Command = 'Get'
            URI     = $filterURL
            Header  = $global:g_LogonHeader
        }
        $response = Invoke-Rest @getParams
        $GetAccountsList += $response.value
        Write-LogMessage -type Info -MSG "Found $($GetAccountsList.Count) accounts so far..."
        $nextLink = $response.nextLink
        while (-not [string]::IsNullOrEmpty($nextLink)) {
            $nextParams = @{
                Command = 'Get'
                URI     = "$PVWAURL/$nextLink"
                Header  = $global:g_LogonHeader
            }
            $response = Invoke-Rest @nextParams
            $nextLink = $response.nextLink
            $GetAccountsList += $response.value
            Write-LogMessage -type Info -MSG "Found $($GetAccountsList.Count) accounts so far..."
        }
        # Post-filter for exact matches where search= is fuzzy
        $WhereArray = @()
        if (-not [string]::IsNullOrEmpty($sUserName)) { $WhereArray += '$_.userName -eq $sUserName' }
        if (-not [string]::IsNullOrEmpty($sAddress)) { $WhereArray += '$_.address -eq $sAddress' }
        if (-not [string]::IsNullOrEmpty($sPlatformID)) { $WhereArray += '$_.platformId -eq $sPlatformID' }
        if ($WhereArray.Count -gt 0) {
            $WhereFilter = [scriptblock]::Create(($WhereArray -join ' -and '))
            return ($GetAccountsList | Where-Object $WhereFilter)
        }
        return $GetAccountsList
    }
    catch {
        Throw $(New-Object System.Exception ('Get-FilteredAccounts: Error getting accounts', $_.Exception))
    }
}

function Invoke-AccountAction {
    param(
        [Parameter(Mandatory = $true)][string]$AccountID,
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $false)][string]$Reason = '[No Reason]',
        [Parameter(Mandatory = $false)][string]$NewCredentials = '',
        [Parameter(Mandatory = $false)][bool]$ChangeImmediately = $false
    )
    # Resume and Disable use PATCH on the account — no dedicated POST endpoints
    if ($Action -eq 'Resume' -or $Action -eq 'Disable') {
        $enabled = if ($Action -eq 'Resume') { 'true' } else { 'false' }
        Write-LogMessage -type Verbose -MSG "Invoke-AccountAction:`tPatching account $AccountID automaticManagementEnabled=$enabled"
        $patchOp = [PSCustomObject]@{ op = 'replace'; path = '/secretManagement/automaticManagementEnabled'; value = $enabled }
        $patchBody = '[' + ($patchOp | ConvertTo-Json -Compress) + ']'
        if ($Action -eq 'Disable') {
            $reasonStr = if ([string]::IsNullOrEmpty($Reason)) { '[No Reason]' } else { $Reason }
            # PVWA silently discards reasons starting with (CPM) — that prefix is reserved for the CPM service
            if ($reasonStr -match '^\(CPM\)') {
                Write-LogMessage -type Warning -MSG "DisableReason starts with '(CPM)' which is reserved for the CPM service — PVWA will silently discard it. Use a different reason."
            }
            $reasonOp = [PSCustomObject]@{ op = 'add'; path = '/secretManagement/manualManagementReason'; value = $reasonStr }
            $patchBody = '[' + ($patchOp | ConvertTo-Json -Compress) + ',' + ($reasonOp | ConvertTo-Json -Compress) + ']'
        }
        $resumeParams = @{
            Command = 'PATCH'
            URI     = $URL_AccountsDetails -f $AccountID
            Header  = $global:g_LogonHeader
            Body    = $patchBody
        }
        $null = Invoke-Rest @resumeParams
        return
    }
    $actionURL = switch ($Action) {
        'Verify'           { $URL_AccountVerify -f $AccountID }
        'Change'           { $URL_AccountChange -f $AccountID }
        'Reconcile'        { $URL_AccountReconcile -f $AccountID }
        'CheckIn'          { $URL_AccountCheckIn -f $AccountID }
        'Cancel'           { $URL_AccountCancel -f $AccountID }
        'SetNextPassword'  { $URL_AccountSetNextPassword -f $AccountID }
        'ChangeInVault'    { $URL_AccountChangeInVault -f $AccountID }
    }
    $actionBody = ''
    if ($Action -eq 'SetNextPassword') {
        $actionBody = @{ NewCredentials = $NewCredentials; ChangeImmediately = $ChangeImmediately } | ConvertTo-Json -Compress
    }
    elseif ($Action -eq 'ChangeInVault') {
        $actionBody = @{ NewCredentials = $NewCredentials } | ConvertTo-Json -Compress
    }
    Write-LogMessage -type Verbose -MSG "Invoke-AccountAction:`tPosting $Action to account $AccountID"
    $actionParams = @{
        Command = 'POST'
        URI     = $actionURL
        Header  = $global:g_LogonHeader
        Body    = $actionBody
    }
    $null = Invoke-Rest @actionParams
}

# Valid action names per bulk mode
$script:BulkOnPremActions = @('Verify', 'Change', 'Reconcile', 'Resume', 'CheckIn', 'Cancel')
$script:PCloudActionMap = @{
    'Verify'    = 'verify-secret'
    'Change'    = 'change-secret'
    'Reconcile' = 'reconcile-secret'
    'Resume'    = 'resume'
    'CheckIn'   = 'unlock'
    'Delete'    = 'delete'
}

function Get-PVWAVersion {
    # Returns [version] from on-prem server info endpoint, or $null if unavailable
    try {
        $serverParams = @{
            Command   = 'Get'
            URI       = $URL_PVWAServerInfo
            Header    = $global:g_LogonHeader
            ErrAction = 'SilentlyContinue'
        }
        $serverInfo = Invoke-Rest @serverParams
        if ($null -ne $serverInfo -and -not [string]::IsNullOrEmpty($serverInfo.ExternalVersion)) {
            $versionString = ($serverInfo.ExternalVersion -split '\s')[0]
            return [version]$versionString
        }
    }
    catch {
        Write-LogMessage -type Warning -MSG "Could not retrieve server version: $($_.Exception.Message)"
    }
    return $null
}

function Invoke-BulkAccountActionOnPrem {
    param(
        [Parameter(Mandatory = $true)][string[]]$AccountIDs,
        [Parameter(Mandatory = $true)][string]$Action
    )
    $totalBatches = [math]::Ceiling($AccountIDs.Count / $BatchSize)
    Write-LogMessage -type Info -MSG "Submitting $($AccountIDs.Count) accounts in $totalBatches on-prem bulk batch(es) of up to $BatchSize"
    $batchNum = 0
    for ($i = 0; $i -lt $AccountIDs.Count; $i += $BatchSize) {
        $batchNum++
        $batchEnd = [math]::Min($i + $BatchSize - 1, $AccountIDs.Count - 1)
        $batchIDs = $AccountIDs[$i..$batchEnd]
        $bulkItems = @()
        foreach ($id in $batchIDs) {
            $item = @{ accountId = $id }
            if ($Action -eq 'Change' -and $ChangeEntireGroup.IsPresent) {
                $item['ChangeEntireGroup'] = $true
            }
            $bulkItems += $item
        }
        $body = @{ bulkItems = $bulkItems } | ConvertTo-Json -Depth 3 -Compress
        Write-LogMessage -type Debug -MSG "On-prem bulk batch $batchNum/$totalBatches ($($batchIDs.Count) accounts)"
        $bulkParams = @{
            Command = 'POST'
            URI     = $URL_AccountsBulkOnPrem -f $Action
            Header  = $global:g_LogonHeader
            Body    = $body
        }
        $null = Invoke-Rest @bulkParams
        Write-LogMessage -type Info -MSG "Batch $batchNum/$totalBatches submitted successfully."
    }
}

function Get-PCloudBulkStatus {
    param(
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][string]$BulkId
    )
    $statusParams = @{
        Command = 'Get'
        URI     = ($URL_AccountsBulkPCloudStatus -f $Action, $BulkId) + '?projection=regular'
        Header  = $global:g_LogonHeader
    }
    return Invoke-Rest @statusParams
}

function Invoke-BulkAccountActionPCloud {
    param(
        [Parameter(Mandatory = $true)][string[]]$AccountIDs,
        [Parameter(Mandatory = $true)][string]$Action
    )
    $pcloudAction = $script:PCloudActionMap[$Action]
    $totalBatches = [math]::Ceiling($AccountIDs.Count / $BatchSize)
    Write-LogMessage -type Info -MSG "Submitting $($AccountIDs.Count) accounts in $totalBatches PCloud bulk batch(es) of up to $BatchSize (action: $pcloudAction)"
    $allResults = @()
    $batchNum = 0
    for ($i = 0; $i -lt $AccountIDs.Count; $i += $BatchSize) {
        $batchNum++
        $batchEnd = [math]::Min($i + $BatchSize - 1, $AccountIDs.Count - 1)
        $batchIDs = $AccountIDs[$i..$batchEnd]
        $body = @{ accountIds = @($batchIDs) } | ConvertTo-Json -Compress
        Write-LogMessage -type Debug -MSG "PCloud bulk batch $batchNum/$totalBatches ($($batchIDs.Count) accounts)"
        $bulkParams = @{
            Command = 'POST'
            URI     = $URL_AccountsBulkPCloud -f $pcloudAction
            Header  = $global:g_LogonHeader
            Body    = $body
        }
        $submitResponse = Invoke-Rest @bulkParams
        $bulkId = $submitResponse.id
        Write-LogMessage -type Info -MSG "Batch $batchNum/$totalBatches submitted. BulkId: $bulkId — polling every $PollInterval s..."
        $pollAttempts = 0
        $maxPollAttempts = [int](3600 / $PollInterval)
        $statusResponse = $null
        do {
            Start-Sleep -Seconds $PollInterval
            $pollAttempts++
            $statusResponse = Get-PCloudBulkStatus -Action $pcloudAction -BulkId $bulkId
            Write-LogMessage -type Debug -MSG "Batch $batchNum status: $($statusResponse.status) — succeeded: $($statusResponse.succeeded), failed: $($statusResponse.failed), pending: $($statusResponse.pending)"
            if ($pollAttempts -ge $maxPollAttempts) {
                Write-LogMessage -type Warning -MSG "Batch $batchNum polling timed out after 1 hour. BulkId: $bulkId. Results may be incomplete."
                break
            }
        } while ($null -eq $statusResponse -or $statusResponse.status -notin @('COMPLETED', 'CANCELLING'))
        Write-LogMessage -type Info -MSG "Batch $batchNum/$totalBatches done — succeeded: $($statusResponse.succeeded)/$($batchIDs.Count), failed: $($statusResponse.failed)/$($batchIDs.Count)"
        if ($null -ne $statusResponse -and $null -ne $statusResponse.results) {
            foreach ($subTask in $statusResponse.results) {
                $allResults += $subTask
            }
        }
    }
    return $allResults
}
#endregion

#region Record Tracking
function New-BadRecord {
    [CmdletBinding()]
    param([Parameter()][string]$ErrorMessage)
    try {
        if (-not [string]::IsNullOrEmpty($ErrorMessage)) {
            $global:workAccount | Add-Member -MemberType NoteProperty -Name 'ErrorMessage' -Value $ErrorMessage -Force
        }
        $recordID = if ($null -ne $global:workAccount.name) {
            $global:workAccount.name
        }
        else {
            "$($global:workAccount.userName)@$($global:workAccount.address)#$($global:workAccount.platformID)"
        }
        if ($Global:BadAccountHashTable[$recordID].Count -eq 0) {
            $Global:BadAccountHashTable.Add($recordID, $global:workAccount)
            try {
                $global:workAccount | Export-Csv -Append -NoTypeInformation $global:csvPathBad -Force
                Write-LogMessage -type Debug -MSG 'Output bad record to CSV'
                Write-LogMessage -type Verbose -MSG "Bad Record:`t$global:workAccount"
            }
            catch {
                Write-LogMessage -type Error -MSG "Unable to output bad record to file: $global:csvPathBad"
            }
        }
        else {
            Write-LogMessage -type Debug -MSG 'Bad record already output — skipping duplicate'
        }
    }
    catch {
        Write-LogMessage -type Error -MSG "Unable to output bad record: $global:csvPathBad"
        $Global:BadAccountHashTable.Add($global:csvLine, $global:workAccount)
    }
}

function New-GoodRecord {
    try {
        if ($null -ne $global:workAccount.Password) { $global:workAccount.Password = $null }
        $global:workAccount | Export-Csv -Append -NoTypeInformation $global:csvPathGood
        Write-LogMessage -type Debug -MSG 'Output good record to CSV'
        Write-LogMessage -type Verbose -MSG "Good Record:`t$global:workAccount"
    }
    catch {
        Write-LogMessage -type Error -MSG "Unable to output good record to file: $global:csvPathGood"
    }
}
#endregion

# Global URLs
$URL_PVWAURL = Format-PVWAURL $PVWAURL
$URL_PVWAAPI = $URL_PVWAURL.TrimEnd('/') + '/api'
$URL_Authentication = $URL_PVWAAPI + '/auth'
$URL_Logon = $URL_Authentication + "/$AuthType/Logon"
$URL_Logoff = $URL_Authentication + '/Logoff'

$URL_Accounts = $URL_PVWAAPI + '/Accounts'
$URL_AccountsDetails = $URL_Accounts + '/{0}'
$URL_AccountVerify = $URL_AccountsDetails + '/Verify'
$URL_AccountChange = $URL_AccountsDetails + '/Change'
$URL_AccountReconcile = $URL_AccountsDetails + '/Reconcile'
$URL_AccountCheckIn = $URL_AccountsDetails + '/CheckIn'
$URL_AccountCancel = $URL_AccountsDetails + '/Cancel'
$URL_AccountSetNextPassword = $URL_AccountsDetails + '/SetNextPassword'
$URL_AccountChangeInVault = $URL_AccountsDetails + '/Password/Update'

# On-prem bulk endpoints (v15.2+): POST /api/Accounts/{Action}/Bulk
$URL_AccountsBulkOnPrem = $URL_PVWAAPI + '/Accounts/{0}/Bulk'
# PCloud bulk endpoints: POST /api/accounts/{action}/bulk (kebab-case action names)
$URL_AccountsBulkPCloud = $URL_PVWAAPI + '/accounts/{0}/bulk'
$URL_AccountsBulkPCloudStatus = $URL_PVWAAPI + '/accounts/{0}/bulk/{1}'
# Gen-1 server info endpoint used to verify on-prem version before bulk
$URL_PVWAServerInfo = $URL_PVWAURL.TrimEnd('/') + '/WebServices/PIMServices.svc/Server/'
$global:isPCloud = $URL_PVWAURL -match '\.privilegecloud\.cyberark\.(cloud|com)\b'

$global:g_LogonHeader = ''
$global:g_LogAccountName = ''

Write-LogMessage -type Info -MSG 'Welcome to Account Actions Utility' -Header
Write-LogMessage -type Verbose -MSG "Base:`t$g_ScriptCommand"
Write-LogMessage -type Info -MSG "Starting script (v$ScriptVersion)" -SubHeader

if ($DisableSSLVerify) {
    try {
        Write-Warning 'It is not recommended to disable SSL verification' -WarningAction Inquire
        Disable-SSLVerification
    }
    catch {
        Write-LogMessage -type Error -MSG 'Could not change SSL validation'
        Write-LogMessage -type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction SilentlyContinue
        return
    }
}
else {
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    }
    catch {
        Write-LogMessage -type Error -MSG 'Could not set TLS 1.2'
    }
}

if ([string]::IsNullOrEmpty($PVWAURL)) {
    Write-LogMessage -type Error -MSG 'PVWA URL cannot be empty'
    return
}

try {
    $validateParams = @{
        UseBasicParsing  = $true
        DisableKeepAlive = $true
        Uri              = $URL_PVWAURL
        Method           = 'Head'
        TimeoutSec       = 30
    }
    Invoke-WebRequest @validateParams | Out-Null
}
catch [System.Net.WebException] {
    if (![string]::IsNullOrEmpty($_.Exception.Response.StatusCode.Value__)) {
        Write-LogMessage -type Error -MSG "Received error $($_.Exception.Response.StatusCode.Value__) when validating PVWA URL"
        Write-LogMessage -type Error -MSG 'Check your connection to PVWA and the PVWA URL'
        Throw
    }
}
catch {
    Write-LogMessage -type Error -MSG 'PVWA URL could not be validated'
    Write-LogMessage -type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction SilentlyContinue
    Throw
}

Write-LogMessage -type Info -MSG 'Getting PVWA Credentials' -SubHeader

if ($null -ne $logonToken) {
    if ($logonToken.GetType().name -eq 'String') {
        $logonHeader = @{Authorization = $logonToken }
        Set-Variable -Scope Global -Name g_LogonHeader -Value $logonHeader
    }
    else {
        Set-Variable -Scope Global -Name g_LogonHeader -Value $logonToken
    }
}
else {
    if ($null -ne $PVWACredentials) {
        $creds = $PVWACredentials
    }
    else {
        $caption = 'Account Actions Utility'
        $msg = "Enter your $AuthType User name and Password"
        $creds = $Host.UI.PromptForCredential($caption, $msg, '', '')
    }
    if ($null -eq $creds) {
        Write-LogMessage -type Error -MSG 'No credentials were entered'
        return
    }
    if ($AuthType -eq 'radius' -and ![string]::IsNullOrEmpty($OTP)) {
        $logonHeaderParams = @{
            Credentials       = $creds
            concurrentSession = $concurrentSession.IsPresent
            RadiusOTP         = $OTP
        }
    }
    else {
        $logonHeaderParams = @{
            Credentials       = $creds
            concurrentSession = $concurrentSession.IsPresent
        }
    }
    try {
        Set-Variable -Scope Global -Name g_LogonHeader -Value (Get-LogonHeader @logonHeaderParams)
    }
    catch {
        Write-LogMessage -type Error -MSG "Error logging on. Error: $(Join-ExceptionMessage $_.Exception)"
        return
    }
    if ($null -eq $g_LogonHeader) { return }
}

$counter = 0
$rowCount = 0
$isBulkMode = $BulkOnPrem.IsPresent -or $BulkPCloud.IsPresent

# Mutual exclusion guard
if ($BulkOnPrem.IsPresent -and $BulkPCloud.IsPresent) {
    Write-LogMessage -type Error -MSG '-BulkOnPrem and -BulkPCloud are mutually exclusive'
    if ($null -eq $logonToken) { Invoke-Logoff }
    return
}

if ($isBulkMode) {
    if ($BulkPCloud.IsPresent -and -not $global:isPCloud) {
        Write-LogMessage -type Warning -MSG '-BulkPCloud specified but the PVWA URL does not appear to be a Privilege Cloud instance'
    }
    if ($BulkOnPrem.IsPresent -and $global:isPCloud) {
        Write-LogMessage -type Warning -MSG '-BulkOnPrem specified but the URL appears to be Privilege Cloud — consider using -BulkPCloud instead'
    }
    if ($BulkOnPrem.IsPresent) {
        Write-LogMessage -type Info -MSG 'Checking server version for on-prem bulk API compatibility...'
        $serverVersion = Get-PVWAVersion
        if ($null -ne $serverVersion -and $serverVersion -lt [version]'15.2') {
            Write-LogMessage -type Error -MSG "On-prem bulk APIs require PVWA v15.2 or higher. Detected: $serverVersion"
            if ($null -eq $logonToken) { Invoke-Logoff }
            return
        }
        if ($null -eq $serverVersion) {
            Write-LogMessage -type Warning -MSG 'Could not verify server version. On-prem bulk APIs require v15.2+. Proceeding...'
        }
        else {
            Write-LogMessage -type Info -MSG "Server version $serverVersion confirmed — on-prem bulk API supported"
        }
    }
}

# Filters mode action compatibility check
if ($PSCmdlet.ParameterSetName -eq 'Filters') {
    # Delete is the only action that has no individual endpoint (PCloud SRS bulk only)
    $bulkOnlyActions = @('Delete')
    if (-not $isBulkMode -and $AccountsAction -in $bulkOnlyActions) {
        Write-LogMessage -type Error -MSG "Action '$AccountsAction' is only available with -BulkOnPrem or -BulkPCloud"
        if ($null -eq $logonToken) { Invoke-Logoff }
        return
    }
    if ($BulkPCloud.IsPresent -and $AccountsAction -eq 'Cancel') {
        Write-LogMessage -type Error -MSG "'Cancel' is not supported by the Privilege Cloud bulk API. Use -BulkOnPrem."
        if ($null -eq $logonToken) { Invoke-Logoff }
        return
    }
    if ($BulkOnPrem.IsPresent -and $AccountsAction -eq 'Delete') {
        Write-LogMessage -type Error -MSG "'Delete' is not supported by the on-prem bulk API. Use -BulkPCloud."
        if ($null -eq $logonToken) { Invoke-Logoff }
        return
    }
    # SetNextPassword and ChangeInVault require per-account credentials; bulk sends no credentials
    $credentialActions = @('SetNextPassword', 'ChangeInVault')
    if ($isBulkMode -and $AccountsAction -in $credentialActions) {
        Write-LogMessage -type Error -MSG "Action '$AccountsAction' requires per-account credentials and is not supported in bulk mode"
        if ($null -eq $logonToken) { Invoke-Logoff }
        return
    }
    if ($AccountsAction -in $credentialActions -and ($null -eq $NewCredentials -or $NewCredentials.Length -eq 0)) {
        Write-LogMessage -type Error -MSG "Action '$AccountsAction' requires -NewCredentials"
        if ($null -eq $logonToken) { Invoke-Logoff }
        return
    }
}

# Determine which CSV action values are valid for the active mode
if ($BulkPCloud.IsPresent) {
    $validCSVActions = @('Verify', 'Change', 'Reconcile', 'Resume', 'Disable', 'CheckIn', 'Delete')
}
elseif ($BulkOnPrem.IsPresent) {
    $validCSVActions = @('Verify', 'Change', 'Reconcile', 'Resume', 'Disable', 'CheckIn', 'Cancel')
}
else {
    $validCSVActions = @('Verify', 'Change', 'Reconcile', 'Resume', 'Disable', 'CheckIn', 'Cancel', 'SetNextPassword', 'ChangeInVault')
}

if ($PSCmdlet.ParameterSetName -eq 'CSV') {
    $delimiter = if ($CsvDelimiter -eq 'Comma') { ',' } else { "`t" }

    $global:csvPathGood = "$CsvPath.good.csv"
    $global:csvPathBad = "$CsvPath.bad.csv"
    Remove-Item $global:csvPathGood -Force -ErrorAction SilentlyContinue
    Remove-Item $global:csvPathBad -Force -ErrorAction SilentlyContinue

    Write-LogMessage -type Info -MSG "Reading CSV from: $CsvPath"
    $accountsCSV = Import-Csv $CsvPath -Delimiter $delimiter
    $accountsCSV = $accountsCSV | Select-Object -ExcludeProperty ErrorMessage
    $rowCount = $accountsCSV.Count
    $global:csvLine = 1

    Write-LogMessage -type Info -MSG "Starting to process $rowCount accounts" -SubHeader

    if ($isBulkMode) {
        # First pass: resolve all accounts and collect valid items; bad rows go to CSV immediately
        $resolvedItems = @()
        foreach ($row in $accountsCSV) {
            if ($null -ne $row) {
                $global:csvLine++
                $global:workAccount = $row
                try {
                    $normalizedAction = (Get-Culture).TextInfo.ToTitleCase($row.Action.ToLower())
                    if ([string]::IsNullOrEmpty($row.Action) -or $normalizedAction -notin $validCSVActions) {
                        throw "Action '$($row.Action)' is invalid or not supported in the current bulk mode"
                    }
                    $resolvedID = $null
                    $logName = $null
                    if (-not [string]::IsNullOrEmpty($row.AccountID)) {
                        # Trust the supplied ID; the bulk API returns per-item failure if invalid
                        $resolvedID = $row.AccountID
                        $logName = $row.AccountID
                        Write-LogMessage -type Verbose -MSG "Base:`tUsing AccountID fast path: $resolvedID"
                    }
                    else {
                        $searchParams = @{
                            safeName          = $row.safe
                            accountName       = $row.username
                            accountAddress    = $row.address
                            accountPlatformID = $row.platformID
                            accountObjectName = $row.name
                            ErrAction         = 'SilentlyContinue'
                        }
                        $searchResult = Get-Account @searchParams
                        if ($null -eq $searchResult -or $searchResult.Count -eq 0) {
                            throw "Account not found for '$($row.username)@$($row.address)' in safe '$($row.safe)'"
                        }
                        if ($searchResult.Count -gt 1) {
                            throw "Ambiguous match: $($searchResult.Count) accounts found for '$($row.username)@$($row.address)' in safe '$($row.safe)'"
                        }
                        $resolvedID = $searchResult.id
                        if ($searchResult.name) { $logName = $searchResult.name } else { $logName = "$($searchResult.userName)@$($searchResult.address)" }
                        $resolvedAccount = $searchResult
                    }
                    $resolvedItems += [PSCustomObject]@{
                        ID      = $resolvedID
                        Row     = $row
                        Action  = $normalizedAction
                        LogName = $logName
                        Account = $resolvedAccount
                    }
                }
                catch {
                    New-BadRecord -ErrorMessage $PSItem.Exception.Message
                    Write-LogMessage -type Error -MSG "[$global:csvLine] $PSItem"
                }
            }
        }

        # Second pass: group by action and submit bulk batches
        $actionGroups = $resolvedItems | Group-Object -Property Action
        foreach ($group in $actionGroups) {
            $action = $group.Name
            $ids = @($group.Group | ForEach-Object { $_.ID })
            Write-LogMessage -type Info -MSG "Submitting $($ids.Count) account(s) for action '$action' via bulk API"

            if ($BulkOnPrem.IsPresent) {
                try {
                    Invoke-BulkAccountActionOnPrem -AccountIDs $ids -Action $action
                    foreach ($item in $group.Group) {
                        $counter++
                        $global:workAccount = $item.Row
                        if ($null -ne $item.Account) {
                            $global:workAccount | Add-Member -MemberType NoteProperty -Name 'AccountID'   -Value $item.Account.id         -Force
                            $global:workAccount | Add-Member -MemberType NoteProperty -Name 'AccountName' -Value $item.Account.name       -Force
                            $global:workAccount | Add-Member -MemberType NoteProperty -Name 'SafeName'    -Value $item.Account.safeName   -Force
                            $global:workAccount | Add-Member -MemberType NoteProperty -Name 'UserName'    -Value $item.Account.userName   -Force
                            $global:workAccount | Add-Member -MemberType NoteProperty -Name 'Address'     -Value $item.Account.address    -Force
                            $global:workAccount | Add-Member -MemberType NoteProperty -Name 'PlatformID'  -Value $item.Account.platformId -Force
                        }
                        New-GoodRecord
                        Write-LogMessage -type Info -MSG "Bulk $action submitted for $($item.LogName) successfully."
                    }
                }
                catch {
                    $errMsg = $PSItem.Exception.Message
                    foreach ($item in $group.Group) {
                        $global:workAccount = $item.Row
                        if ($null -ne $item.Account) {
                            $global:workAccount | Add-Member -MemberType NoteProperty -Name 'AccountID'   -Value $item.Account.id         -Force
                            $global:workAccount | Add-Member -MemberType NoteProperty -Name 'AccountName' -Value $item.Account.name       -Force
                            $global:workAccount | Add-Member -MemberType NoteProperty -Name 'SafeName'    -Value $item.Account.safeName   -Force
                            $global:workAccount | Add-Member -MemberType NoteProperty -Name 'UserName'    -Value $item.Account.userName   -Force
                            $global:workAccount | Add-Member -MemberType NoteProperty -Name 'Address'     -Value $item.Account.address    -Force
                            $global:workAccount | Add-Member -MemberType NoteProperty -Name 'PlatformID'  -Value $item.Account.platformId -Force
                        }
                        New-BadRecord -ErrorMessage $errMsg
                    }
                    Write-LogMessage -type Error -MSG "On-prem bulk $action batch failed. Error: $errMsg"
                }
            }
            else {
                try {
                    $bulkResults = Invoke-BulkAccountActionPCloud -AccountIDs $ids -Action $action
                    $idToItem = @{}
                    foreach ($item in $group.Group) { $idToItem[$item.ID] = $item }
                    foreach ($subTask in $bulkResults) {
                        $item = $idToItem[$subTask.entityId]
                        if ($null -ne $item) {
                            $global:workAccount = $item.Row
                            if ($null -ne $item.Account) {
                                $global:workAccount | Add-Member -MemberType NoteProperty -Name 'AccountID'   -Value $item.Account.id         -Force
                                $global:workAccount | Add-Member -MemberType NoteProperty -Name 'AccountName' -Value $item.Account.name       -Force
                                $global:workAccount | Add-Member -MemberType NoteProperty -Name 'SafeName'    -Value $item.Account.safeName   -Force
                                $global:workAccount | Add-Member -MemberType NoteProperty -Name 'UserName'    -Value $item.Account.userName   -Force
                                $global:workAccount | Add-Member -MemberType NoteProperty -Name 'Address'     -Value $item.Account.address    -Force
                                $global:workAccount | Add-Member -MemberType NoteProperty -Name 'PlatformID'  -Value $item.Account.platformId -Force
                            }
                            if ($subTask.status -eq 'SUCCEEDED') {
                                $counter++
                                New-GoodRecord
                                Write-LogMessage -type Info -MSG "PCloud bulk $action succeeded for $($item.LogName)."
                            }
                            else {
                                New-BadRecord -ErrorMessage "Status: $($subTask.status). $($subTask.details)"
                                Write-LogMessage -type Error -MSG "PCloud bulk $action $($subTask.status) for $($item.LogName). $($subTask.details)"
                            }
                        }
                    }
                }
                catch {
                    $errMsg = $PSItem.Exception.Message
                    foreach ($item in $group.Group) {
                        $global:workAccount = $item.Row
                        if ($null -ne $item.Account) {
                            $global:workAccount | Add-Member -MemberType NoteProperty -Name 'AccountID'   -Value $item.Account.id         -Force
                            $global:workAccount | Add-Member -MemberType NoteProperty -Name 'AccountName' -Value $item.Account.name       -Force
                            $global:workAccount | Add-Member -MemberType NoteProperty -Name 'SafeName'    -Value $item.Account.safeName   -Force
                            $global:workAccount | Add-Member -MemberType NoteProperty -Name 'UserName'    -Value $item.Account.userName   -Force
                            $global:workAccount | Add-Member -MemberType NoteProperty -Name 'Address'     -Value $item.Account.address    -Force
                            $global:workAccount | Add-Member -MemberType NoteProperty -Name 'PlatformID'  -Value $item.Account.platformId -Force
                        }
                        New-BadRecord -ErrorMessage $errMsg
                    }
                    Write-LogMessage -type Error -MSG "PCloud bulk $action submission failed. Error: $errMsg"
                }
            }
        }
    }
    else {
        foreach ($row in $accountsCSV) {
            if ($null -ne $row) {
                $global:csvLine++
                $global:workAccount = $row
                try {
                    if ([string]::IsNullOrEmpty($row.Action) -or $row.Action -notmatch '^(?:Verify|Change|Reconcile)$') {
                        throw "Invalid or missing Action value: '$($row.Action)'"
                    }
                    # Normalize casing so switch in Invoke-AccountAction matches
                    $normalizedAction = (Get-Culture).TextInfo.ToTitleCase($row.Action.ToLower())
                    $resolvedAccount = $null

                    if (-not [string]::IsNullOrEmpty($row.AccountID)) {
                        Write-LogMessage -type Verbose -MSG "Base:`tUsing AccountID fast path: $($row.AccountID)"
                        try {
                            $resolvedAccount = Invoke-Rest -Command Get -URI ($URL_AccountsDetails -f $row.AccountID) -Header $global:g_LogonHeader
                        }
                        catch {
                            throw "AccountID '$($row.AccountID)' not found"
                        }
                    }
                    else {
                        $searchParams = @{
                            safeName          = $row.safe
                            accountName       = $row.username
                            accountAddress    = $row.address
                            accountPlatformID = $row.platformID
                            accountObjectName = $row.name
                            ErrAction         = 'SilentlyContinue'
                        }
                        $searchResult = Get-Account @searchParams
                        if ($null -eq $searchResult -or $searchResult.Count -eq 0) {
                            throw "Account not found for '$($row.username)@$($row.address)' in safe '$($row.safe)'"
                        }
                        if ($searchResult.Count -gt 1) {
                            throw "Ambiguous match: $($searchResult.Count) accounts found for '$($row.username)@$($row.address)' in safe '$($row.safe)'"
                        }
                        $resolvedAccount = $searchResult
                    }

                    if ($resolvedAccount.name) { $global:g_LogAccountName = $resolvedAccount.name } else { $global:g_LogAccountName = "$($resolvedAccount.userName)@$($resolvedAccount.address)" }

                    # Enrich the work account row with the full details we fetched
                    $global:workAccount | Add-Member -MemberType NoteProperty -Name 'AccountID'   -Value $resolvedAccount.id          -Force
                    $global:workAccount | Add-Member -MemberType NoteProperty -Name 'AccountName' -Value $resolvedAccount.name        -Force
                    $global:workAccount | Add-Member -MemberType NoteProperty -Name 'SafeName'    -Value $resolvedAccount.safeName    -Force
                    $global:workAccount | Add-Member -MemberType NoteProperty -Name 'UserName'    -Value $resolvedAccount.userName    -Force
                    $global:workAccount | Add-Member -MemberType NoteProperty -Name 'Address'     -Value $resolvedAccount.address     -Force
                    $global:workAccount | Add-Member -MemberType NoteProperty -Name 'PlatformID'  -Value $resolvedAccount.platformId  -Force

                    $rowReason = if ($null -ne $row.DisableReason -and -not [string]::IsNullOrEmpty($row.DisableReason)) { $row.DisableReason } else { $DisableReason }
                    $rowNewCreds = ''
                    if ($null -ne $row.PSObject.Properties['NewCredentials'] -and -not [string]::IsNullOrEmpty($row.NewCredentials)) {
                        $rowNewCreds = $row.NewCredentials
                    }
                    elseif ($null -ne $NewCredentials -and $NewCredentials.Length -gt 0) {
                        $rowNewCreds = [PSCredential]::new('x', $NewCredentials).GetNetworkCredential().Password
                    }
                    if ($normalizedAction -in @('SetNextPassword', 'ChangeInVault') -and [string]::IsNullOrEmpty($rowNewCreds)) {
                        throw "Action '$normalizedAction' requires NewCredentials — add a NewCredentials column to the CSV or pass -NewCredentials"
                    }
                    $rowChangeImmediately = if ($null -ne $row.PSObject.Properties['ChangeImmediately'] -and -not [string]::IsNullOrEmpty($row.ChangeImmediately)) { [bool]::Parse($row.ChangeImmediately) } else { $ChangeImmediately.IsPresent }
                    Invoke-AccountAction -AccountID $resolvedAccount.id -Action $normalizedAction -Reason $rowReason -NewCredentials $rowNewCreds -ChangeImmediately $rowChangeImmediately
                    $counter++
                    New-GoodRecord
                    Write-LogMessage -type Info -MSG "[$global:csvLine] $normalizedAction submitted for $global:g_LogAccountName successfully."
                }
                catch {
                    New-BadRecord -ErrorMessage $PSItem.Exception.Message
                    Write-LogMessage -type Error -MSG "[$global:csvLine] $PSItem"
                }
            }
        }
    }
}
else {
    $global:csvPathGood = "$ScriptLocation\AccountActions_$($global:LOG_DATE).good.csv"
    $global:csvPathBad = "$ScriptLocation\AccountActions_$($global:LOG_DATE).bad.csv"

    Write-LogMessage -type Info -MSG "Running $AccountsAction on filtered accounts"
    $filterParams = @{
        sSafeName    = $SafeName
        sPlatformID  = $PlatformID
        sUserName    = $UserName
        sAddress     = $Address
        sSearch      = $Search
        sFilter      = $Filter
        sSavedFilter = $SavedFilter
        sSearchType  = $SearchType
    }
    $filteredAccounts = Get-FilteredAccounts @filterParams
    $rowCount = $filteredAccounts.Count
    Write-LogMessage -type Info -MSG "Going over $rowCount filtered accounts"

    if ($isBulkMode) {
        $allIDs = @($filteredAccounts | ForEach-Object { $_.id })
        if ($BulkOnPrem.IsPresent) {
            try {
                Invoke-BulkAccountActionOnPrem -AccountIDs $allIDs -Action $AccountsAction
                $counter = $rowCount
                foreach ($account in $filteredAccounts) {
                    $accountRecord = [PSCustomObject]@{
                        AccountID   = $account.id
                        AccountName = $account.name
                        SafeName    = $account.safeName
                        UserName    = $account.userName
                        Address     = $account.address
                        PlatformID  = $account.platformId
                        Action      = $AccountsAction
                    }
                    try { $accountRecord | Export-Csv -Append -NoTypeInformation $global:csvPathGood -Force }
                    catch { Write-LogMessage -type Error -MSG "Unable to write good record: $global:csvPathGood" }
                }
                Write-LogMessage -type Info -MSG "On-prem bulk $AccountsAction submitted for $rowCount accounts."
            }
            catch {
                $errMsg = $PSItem.Exception.Message
                foreach ($account in $filteredAccounts) {
                    $accountRecord = [PSCustomObject]@{
                        AccountID    = $account.id
                        AccountName  = $account.name
                        SafeName     = $account.safeName
                        UserName     = $account.userName
                        Address      = $account.address
                        PlatformID   = $account.platformId
                        Action       = $AccountsAction
                        ErrorMessage = $errMsg
                    }
                    try { $accountRecord | Export-Csv -Append -NoTypeInformation $global:csvPathBad -Force }
                    catch { Write-LogMessage -type Error -MSG "Unable to write bad record: $global:csvPathBad" }
                }
                Write-LogMessage -type Error -MSG "On-prem bulk $AccountsAction failed. Error: $errMsg"
            }
        }
        else {
            try {
                $bulkResults = Invoke-BulkAccountActionPCloud -AccountIDs $allIDs -Action $AccountsAction
                $idToAccount = @{}
                foreach ($account in $filteredAccounts) { $idToAccount[$account.id] = $account }
                foreach ($subTask in $bulkResults) {
                    $account = $idToAccount[$subTask.entityId]
                    if ($null -ne $account) {
                        $accountRecord = [PSCustomObject]@{
                            AccountID   = $account.id
                            AccountName = $account.name
                            SafeName    = $account.safeName
                            UserName    = $account.userName
                            Address     = $account.address
                            PlatformID  = $account.platformId
                            Action      = $AccountsAction
                        }
                        if ($subTask.status -eq 'SUCCEEDED') {
                            $counter++
                            try { $accountRecord | Export-Csv -Append -NoTypeInformation $global:csvPathGood -Force }
                            catch { Write-LogMessage -type Error -MSG "Unable to write good record: $global:csvPathGood" }
                            Write-LogMessage -type Info -MSG "PCloud bulk $AccountsAction succeeded for $($account.id)."
                        }
                        else {
                            $accountRecord | Add-Member -MemberType NoteProperty -Name 'ErrorMessage' -Value "Status: $($subTask.status). $($subTask.details)" -Force
                            try { $accountRecord | Export-Csv -Append -NoTypeInformation $global:csvPathBad -Force }
                            catch { Write-LogMessage -type Error -MSG "Unable to write bad record: $global:csvPathBad" }
                            Write-LogMessage -type Error -MSG "PCloud bulk $AccountsAction $($subTask.status) for $($account.id). $($subTask.details)"
                        }
                    }
                }
            }
            catch {
                Write-LogMessage -type Error -MSG "PCloud bulk $AccountsAction failed. Error: $($PSItem.Exception.Message)"
            }
        }
    }
    else {
        foreach ($account in $filteredAccounts) {
            $global:workAccount = [PSCustomObject]@{
                AccountID   = $account.id
                AccountName = $account.name
                SafeName    = $account.safeName
                UserName    = $account.userName
                Address     = $account.address
                PlatformID  = $account.platformId
                Action      = $AccountsAction
            }
            if ($account.name) { $global:g_LogAccountName = $account.name } else { $global:g_LogAccountName = "$($account.userName)@$($account.address)" }

            try {
                $newCredsPlain = if ($null -ne $NewCredentials -and $NewCredentials.Length -gt 0) { [PSCredential]::new('x', $NewCredentials).GetNetworkCredential().Password } else { '' }
                Invoke-AccountAction -AccountID $account.id -Action $AccountsAction -Reason $DisableReason -NewCredentials $newCredsPlain -ChangeImmediately $ChangeImmediately.IsPresent
                $counter++
                try { $global:workAccount | Export-Csv -Append -NoTypeInformation $global:csvPathGood -Force }
                catch { Write-LogMessage -type Error -MSG "Unable to output good record to file: $global:csvPathGood" }
                Write-LogMessage -type Info -MSG "$AccountsAction submitted for $global:g_LogAccountName successfully."
            }
            catch {
                $errorMessage = $PSItem.Exception.Message
                $global:workAccount | Add-Member -MemberType NoteProperty -Name 'ErrorMessage' -Value $errorMessage -Force
                try { $global:workAccount | Export-Csv -Append -NoTypeInformation $global:csvPathBad -Force }
                catch { Write-LogMessage -type Error -MSG "Unable to output bad record to file: $global:csvPathBad" }
                Write-LogMessage -type Error -MSG "Error submitting $AccountsAction for $global:g_LogAccountName. Error: $errorMessage"
            }
        }
    }
}

if ($null -ne $logonToken) {
    Write-Host 'LogonToken passed, session NOT logged off'
}
else {
    Invoke-Logoff
}

Write-LogMessage -type Info -MSG "Completed processing $counter out of $rowCount accounts successfully." -Footer
