<#
.SYNOPSIS
    CyberArk PVWA API load-testing tool.

.DESCRIPTION
    Authenticates to the CyberArk PVWA REST API using a single session (one login,
    one logoff) and continuously fires parallel Accounts list requests to simulate
    concurrent load. Requests run indefinitely until you press Ctrl+C.

    Key behaviors:
      - Thread concurrency ramps from StartThreadCount up to MaxThreadCount, adding
        one thread every RampUpSec seconds, letting you observe performance degradation
        gradually rather than hitting the server with full load immediately.
      - Each request uses a randomly chosen page size (between MinLimit and MaxLimit)
        so the server sees a realistic mix of response sizes.
      - All results, warnings, and errors are written to a rolling log file in the
        same folder as the script. The log rotates automatically when it reaches
        MaxLogSizeMB.
      - Individual thread failures are logged and a replacement job is queued
        immediately — the test never stops due to a single failed request. Only
        Ctrl+C stops the run.

    Output columns (console and log):
      Thread     : Unique sequential job number
      Limit      : The ?limit= value sent in this request
      Returned   : Number of account records actually returned
      Total      : Total account count reported by the vault
      Duration   : Time in seconds for this individual request
      Completed  : Total successful requests since start
      QueueSize  : Number of jobs currently queued or running
      Concurrency: Current / maximum thread count

.PARAMETER PvwaUrl
    The PVWA server URL, including /PasswordVault. The script appends /API
    to build the full API base URL.

    Example:
        https://pvwa.lab.local/PasswordVault

.PARAMETER Credential
    A PSCredential object containing your CyberArk username and password.
    Use Get-Credential to create one interactively:

        $cred = Get-Credential

    Either -Credential OR -Username / -Password must be supplied, not both.

.PARAMETER Username
    CyberArk username for authentication. Must be used with -Password.
    Ignored when -Credential is supplied.

.PARAMETER Password
    Password for the CyberArk user. Accepts any of the following:
      - Plain-text string  : -Password 'MyP@ssword'
      - SecureString       : -Password (Read-Host -AsSecureString)
      - Omitted            : you will be prompted securely at runtime

    Plain-text values are converted to a SecureString internally and are
    never written to disk or to the log file.

.PARAMETER MaxLogSizeMB
    Maximum size of the log file in megabytes. When the log exceeds this
    size it is archived as CyberArk_Performance.log.old and a fresh log
    is started. The archive overwrites any previous .old file.
    Default: 100

.PARAMETER TimeoutSec
    HTTP request timeout in seconds. Requests that exceed this value will
    fail with a timeout error, which is logged as FAILURE. The thread is
    replaced immediately and the test continues.
    Default: 60

.PARAMETER WarnAfterSec
    Response-time threshold in seconds. If a request takes longer than
    this value, a WARNING entry is written to the log and console in
    addition to the SUCCESS entry. The test continues normally.
    Default: 5

.PARAMETER StartThreadCount
    Number of concurrent threads to use at the start of the test. Thread
    count ramps up automatically; set equal to MaxThreadCount to skip
    ramping and start at full concurrency immediately.
    Default: 1

.PARAMETER MaxThreadCount
    The maximum number of concurrent threads. Once reached, concurrency
    stays fixed for the remainder of the run. Must be >= StartThreadCount.
    Default: 10

.PARAMETER RampUpSec
    Seconds between each +1 thread increment. The test adds one thread
    every RampUpSec seconds until MaxThreadCount is reached. Increase
    this value for a slow, steady ramp (e.g. 300 for 5-minute steps).
    Default: 30

.PARAMETER QueueDepth
    How many jobs to pre-load into the runspace pool at startup. The pool
    runs up to the current thread count in parallel; remaining jobs queue
    behind them. A new job is added the instant any job finishes, keeping
    the queue at this depth throughout the run.
    Increase for a larger work backlog ahead of active threads.
    Default: 100

.PARAMETER MinLimit
    Minimum value for the ?limit= query parameter sent with each request.
    Each request picks a random integer in [MinLimit, MaxLimit] to vary
    the payload size. Default: 100

.PARAMETER MaxLimit
    Maximum value for the ?limit= query parameter. Must be >= MinLimit.
    Note: the CyberArk API caps results at 1000 records per page
    regardless of the value supplied. Default: 1000

.EXAMPLE
    .\.Invoke-PVWALoadTest.ps1 -PvwaUrl 'https://pvwa.lab.local/PasswordVault' -Credential (Get-Credential)

    Prompts for credentials and starts with default settings:
    1 thread ramping to 10, one new thread every 30 seconds.

.EXAMPLE
    $cred = Get-Credential
    .\.Invoke-PVWALoadTest.ps1 -PvwaUrl 'https://pvwa.lab.local/PasswordVault' -Credential $cred -StartThreadCount 5 -MaxThreadCount 20 -RampUpSec 60

    Starts at 5 threads and ramps to 20, adding one thread per minute.

.EXAMPLE
    .\.Invoke-PVWALoadTest.ps1 -PvwaUrl 'https://pvwa.lab.local/PasswordVault' -Username 'svc_load' -Password 'MyP@ss!'

    Plain-text password is accepted and converted to SecureString automatically.
    Starts with default ramp settings.

.EXAMPLE
    .\.Invoke-PVWALoadTest.ps1 -PvwaUrl 'https://pvwa.lab.local/PasswordVault' -Username 'svc_load'

    Password is omitted — the script prompts for it securely at runtime.

.EXAMPLE
    .\.Invoke-PVWALoadTest.ps1 -PvwaUrl 'https://pvwa.lab.local/PasswordVault' -Credential $cred `
        -StartThreadCount 10 -MaxThreadCount 10 -QueueDepth 200 `
        -MinLimit 500 -MaxLimit 1000 -WarnAfterSec 2

    Steady-state soak test at exactly 10 threads (no ramp), 200-job queue,
    large page sizes only, warning threshold of 2 seconds.
#>

[CmdletBinding(DefaultParameterSetName = 'Credential')]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^https://')]
    [string]$PvwaUrl,

    # Accept a PSCredential (e.g. from Get-Credential)
    [Parameter(Mandatory = $true, ParameterSetName = 'Credential')]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential,

    # Or supply username + SecureString password separately
    [Parameter(Mandatory = $true, ParameterSetName = 'UsernamePassword')]
    [string]$Username,

    [Parameter(ParameterSetName = 'UsernamePassword')]
    [object]$Password,

    [Parameter()]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$MaxLogSizeMB = 100,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$TimeoutSec = 60,

    [Parameter()]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$WarnAfterSec = 5,

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$StartThreadCount = 1,

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$MaxThreadCount = 10,

    [Parameter()]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$RampUpSec = 30,

    [Parameter()]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$QueueDepth = 100,

    [Parameter()]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$MinLimit = 100,

    [Parameter()]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$MaxLimit = 1000
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- Resolve credentials from whichever parameter set was used ---
if ($PSCmdlet.ParameterSetName -eq 'Credential') {
    $Username = $Credential.UserName
    $Password = $Credential.Password
} else {
    # Resolve Password: prompt if omitted, convert plain text to SecureString if needed
    if (-not $Password) {
        $Password = Read-Host -Prompt "Password for $Username" -AsSecureString
    } elseif ($Password -is [string]) {
        $Password = ConvertTo-SecureString -String $Password -AsPlainText -Force
    }
}

# --- Derived Configuration ---
$BaseUrl   = $PvwaUrl.TrimEnd('/') + '/API'
$MaxLogSize = $MaxLogSizeMB * 1MB
$ScriptDir  = if ($PSScriptRoot) { $PSScriptRoot } else { $PWD.Path }
$LogFile    = Join-Path $ScriptDir 'CyberArk_Performance.log'

# --- Function: Log with Size Protection ---
function Write-Log {
    param([string]$Message)

    if (Test-Path $LogFile) {
        if ((Get-Item $LogFile).Length -gt $MaxLogSize) {
            Move-Item -Path $LogFile -Destination "$LogFile.old" -Force
        }
    }
    $TimeStamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$TimeStamp : $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

# --- Worker scriptblock: each runspace gets its own HttpClient ---
# HttpClient has its own connection pool per instance, bypassing ServicePointManager throttling.
$AccountScriptBlock = {
    param(
        [string]$Uri,
        [string]$Token,
        [int]$TimeoutSec,
        [int]$ThreadId,
        [int]$Limit
    )
    $Timer  = [System.Diagnostics.Stopwatch]::StartNew()
    $Client = $null
    try {
        $Client = [System.Net.Http.HttpClient]::new()
        $Client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
        $null = $Client.DefaultRequestHeaders.TryAddWithoutValidation('Authorization', $Token)

        $Response = $Client.GetAsync("$Uri`?limit=$Limit").GetAwaiter().GetResult()
        $null = $Response.EnsureSuccessStatusCode()
        $Content  = $Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $Result   = $Content | ConvertFrom-Json
        $Timer.Stop()

        [PSCustomObject]@{
            ThreadId = $ThreadId
            Success  = $true
            Returned = $Result.value.Count
            Total    = $Result.count
            Limit    = $Limit
            Duration = [Math]::Round($Timer.Elapsed.TotalSeconds, 2)
            Error    = $null
        }
    }
    catch {
        $Timer.Stop()
        [PSCustomObject]@{
            ThreadId = $ThreadId
            Success  = $false
            Returned = 0
            Total    = 0
            Limit    = $Limit
            Duration = [Math]::Round($Timer.Elapsed.TotalSeconds, 2)
            Error    = $PSItem.Exception.Message
        }
    }
    finally {
        if ($Client) { $Client.Dispose() }
    }
}

# --- One-time login, main loop, one-time logoff ---
$Token        = $null
$PlainPass    = $null
$BSTR         = $null
$RunspacePool = $null
$ActiveJobs   = [System.Collections.Generic.List[object]]::new()

try {
    # Decode SecureString only for the login call
    $BSTR      = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $PlainPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    $LoginParams = @{
        Uri         = "$BaseUrl/auth/Cyberark/Logon"
        Method      = 'Post'
        ContentType = 'application/json'
        Body        = (@{ username = $Username; password = $PlainPass } | ConvertTo-Json)
        TimeoutSec  = $TimeoutSec
    }
    $Token = Invoke-RestMethod @LoginParams

    if ($MaxThreadCount -lt $StartThreadCount) {
        throw "MaxThreadCount ($MaxThreadCount) must be >= StartThreadCount ($StartThreadCount)"
    }
    if ($MaxLimit -lt $MinLimit) {
        throw "MaxLimit ($MaxLimit) must be >= MinLimit ($MinLimit)"
    }

    Write-Log "LOGIN | User: $Username | StartThreads: $StartThreadCount | MaxThreads: $MaxThreadCount | RampUpSec: $RampUpSec | QueueDepth: $QueueDepth"
    Write-Host "Logged in as '$Username'. Starting at $StartThreadCount thread(s), ramping to $MaxThreadCount every $RampUpSec s. Pre-loading $QueueDepth jobs..." -ForegroundColor Green

    $AccountUri = "$BaseUrl/Accounts"

    # Pool starts at StartThreadCount max; SetMaxRunspaces grows it during ramp-up
    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxThreadCount)
    $RunspacePool.Open()
    $null = $RunspacePool.SetMaxRunspaces($StartThreadCount)
    $CurrentThreadCount = $StartThreadCount

    function Start-RSJob {
        param([int]$JobId, [int]$Limit)
        $PS = [PowerShell]::Create()
        $PS.RunspacePool = $RunspacePool
        $null = $PS.AddScript($AccountScriptBlock)
        $null = $PS.AddParameter('Uri',        $AccountUri)
        $null = $PS.AddParameter('Token',      $Token)
        $null = $PS.AddParameter('TimeoutSec', $TimeoutSec)
        $null = $PS.AddParameter('ThreadId',   $JobId)
        $null = $PS.AddParameter('Limit',      $Limit)
        [PSCustomObject]@{ PS = $PS; Handle = $PS.BeginInvoke(); Id = $JobId }
    }

    # Phase 1: pre-load all TotalRuns jobs into the pool queue before waiting on any.
    # The pool executes ThreadCount at a time; the rest wait in the internal queue.
    for ($i = 1; $i -le $QueueDepth; $i++) {
        $ActiveJobs.Add((Start-RSJob -JobId $i -Limit (Get-Random -Minimum $MinLimit -Maximum ($MaxLimit + 1))))
    }
    $NextJobId  = $QueueDepth + 1
    $Completed  = 0
    $RampTimer  = [System.Diagnostics.Stopwatch]::StartNew()

    while ($true) {
        Start-Sleep -Milliseconds 100

        # Ramp-up: increase thread count every RampUpSec until MaxThreadCount
        if ($CurrentThreadCount -lt $MaxThreadCount -and $RampTimer.Elapsed.TotalSeconds -ge $RampUpSec) {
            $CurrentThreadCount++
            $null = $RunspacePool.SetMaxRunspaces($CurrentThreadCount)
            $RampMsg = "RAMP | Thread count increased to $CurrentThreadCount / $MaxThreadCount"
            Write-Log $RampMsg
            Write-Host $RampMsg -ForegroundColor Yellow
            $RampTimer.Restart()
        }

        $Done = @($ActiveJobs | Where-Object { $PSItem.Handle.IsCompleted })

        foreach ($Job in $Done) {
            $Result = ($Job.PS.EndInvoke($Job.Handle))[0]
            $Job.PS.Dispose()
            $null = $ActiveJobs.Remove($Job)
            $Completed++

            if (-not $Result -or -not $Result.Success) {
                $ErrThread = if ($Result) { $Result.ThreadId } else { '?' }
                $ErrDur    = if ($Result) { "$($Result.Duration)s" } else { 'N/A' }
                $ErrDetail = if ($Result) { $Result.Error } else { 'Runspace produced no output' }
                $ErrorMsg  = "FAILURE | Thread: $ErrThread | Duration: $ErrDur | Error: $ErrDetail"
                Write-Log $ErrorMsg
                Write-Host $ErrorMsg -ForegroundColor Red
                # Queue a replacement job to maintain concurrency and continue
                $ActiveJobs.Add((Start-RSJob -JobId $NextJobId -Limit (Get-Random -Minimum $MinLimit -Maximum ($MaxLimit + 1))))
                $NextJobId++
                continue
            }

            $SuccessMsg = "SUCCESS | Thread: $($Result.ThreadId) | Limit: $($Result.Limit) | Returned: $($Result.Returned) | Total: $($Result.Total) | Duration: $($Result.Duration)s | Completed: $Completed | QueueSize: $($ActiveJobs.Count) | Concurrency: $CurrentThreadCount/$MaxThreadCount"
            Write-Log $SuccessMsg
            Write-Host $SuccessMsg -ForegroundColor Cyan

            if ($Result.Duration -gt $WarnAfterSec) {
                $WarnMsg = "WARNING | Thread: $($Result.ThreadId) | Slow response: $($Result.Duration)s exceeded threshold of $($WarnAfterSec)s"
                Write-Log $WarnMsg
                Write-Warning $WarnMsg
            }

            # Always queue the next job — only stops on Ctrl+C
            $ActiveJobs.Add((Start-RSJob -JobId $NextJobId -Limit (Get-Random -Minimum $MinLimit -Maximum ($MaxLimit + 1))))
            $NextJobId++
        }
    }
}
catch {
    $ErrorMsg = "FATAL | $($PSItem.Exception.Message)"
    Write-Log $ErrorMsg
    Write-Host $ErrorMsg -ForegroundColor Red
}
finally {
    # If jobs are still active we were interrupted (Ctrl+C or unhandled error)
    if ($ActiveJobs.Count -gt 0) {
        $InterruptMsg = "STOP RECEIVED | Interrupted with $($ActiveJobs.Count) active job(s) still running. Completed: $Completed. Cleaning up..."
        Write-Log $InterruptMsg
        Write-Host $InterruptMsg -ForegroundColor Yellow
    }

    # Dispose all runspaces still active (covers Ctrl+C, errors, and normal exit)
    foreach ($Job in $ActiveJobs) {
        try { $Job.PS.Stop()    } catch {}
        try { $Job.PS.Dispose() } catch {}
    }
    $ActiveJobs.Clear()
    if ($RunspacePool) {
        $RunspacePool.Close()
        $RunspacePool.Dispose()
    }

    # Always clear sensitive data
    if ($BSTR) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR) }
    $PlainPass = $null

    # One-time logoff
    if ($Token) {
        try {
            $LogoffParams = @{
                Uri        = "$BaseUrl/auth/Logoff"
                Method     = 'Post'
                Headers    = @{ Authorization = $Token }
                TimeoutSec = $TimeoutSec
            }
            $null = Invoke-RestMethod @LogoffParams
            Write-Log 'LOGOFF | Session closed successfully'
            Write-Host 'Logged off successfully.' -ForegroundColor Green
        }
        catch {
            Write-Warning "Logoff failed: $($PSItem.Exception.Message)"
        }
    }
}
