# PVWA Load Testing

## Overview

`Invoke-PVWALoadTest.ps1` is a CyberArk PVWA REST API load-testing tool. It authenticates once, then continuously fires parallel **Accounts list** requests to simulate concurrent load, logging all results to a rolling log file. The test runs indefinitely until stopped with **Ctrl+C**.

## Features

- **Single session** — one login, one logoff, regardless of how many requests are made
- **Thread ramping** — concurrency increases from `StartThreadCount` to `MaxThreadCount`, adding one thread every `RampUpSec` seconds
- **Random page sizes** — each request uses a randomly chosen `?limit=` value between `MinLimit` and `MaxLimit`
- **Rolling log file** — results are written to `CyberArk_Performance.log`; rotated automatically when the file exceeds `MaxLogSizeMB`
- **Self-healing** — individual thread failures are logged and a replacement job is queued immediately; the test never stops due to a single failure
- **Slow response warnings** — requests exceeding `WarnAfterSec` emit a WARNING in addition to the SUCCESS entry
- **Secure credential handling** — passwords are never written to disk or log files; memory is zeroed in the `finally` block

## Requirements

- PowerShell 5.1 or later
- Network access to the CyberArk PVWA
- A CyberArk account with permission to list Accounts via REST API

## Usage

### Basic — prompt for credentials

```powershell
.\Invoke-PVWALoadTest.ps1 -PvwaUrl 'https://pvwa.lab.local/PasswordVault' -Credential (Get-Credential)
```

### Ramp from 5 to 20 threads, one new thread per minute

```powershell
$cred = Get-Credential
.\Invoke-PVWALoadTest.ps1 -PvwaUrl 'https://pvwa.lab.local/PasswordVault' `
    -Credential $cred `
    -StartThreadCount 5 -MaxThreadCount 20 -RampUpSec 60
```

### Username/password parameters (plain text converted to SecureString automatically)

```powershell
.\Invoke-PVWALoadTest.ps1 -PvwaUrl 'https://pvwa.lab.local/PasswordVault' `
    -Username 'svc_load' -Password 'MyP@ss!'
```

### Username only — password prompted securely at runtime

```powershell
.\Invoke-PVWALoadTest.ps1 -PvwaUrl 'https://pvwa.lab.local/PasswordVault' -Username 'svc_load'
```

### Steady-state soak test — no ramp, large pages, tight warning threshold

```powershell
.\Invoke-PVWALoadTest.ps1 -PvwaUrl 'https://pvwa.lab.local/PasswordVault' -Credential $cred `
    -StartThreadCount 10 -MaxThreadCount 10 -QueueDepth 200 `
    -MinLimit 500 -MaxLimit 1000 -WarnAfterSec 2
```

## Parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `PvwaUrl` | string | *(required)* | PVWA URL including `/PasswordVault`. Must start with `https://`. |
| `Credential` | PSCredential | *(required\*)* | PSCredential from `Get-Credential`. |
| `Username` | string | *(required\*)* | Username when not using `-Credential`. |
| `Password` | object | *(prompted)* | Plain string or SecureString. Prompted if omitted. |
| `MaxLogSizeMB` | int | `100` | Log file size limit in MB before rotation. |
| `TimeoutSec` | int | `60` | HTTP request timeout in seconds (1–300). |
| `WarnAfterSec` | int | `5` | Response-time threshold in seconds for slow-response warnings. |
| `StartThreadCount` | int | `1` | Initial number of concurrent threads (1–100). |
| `MaxThreadCount` | int | `10` | Maximum number of concurrent threads (1–100). Must be ≥ `StartThreadCount`. |
| `RampUpSec` | int | `30` | Seconds between each +1 thread increment during ramp-up. |
| `QueueDepth` | int | `100` | Number of jobs pre-loaded into the runspace pool at startup. |
| `MinLimit` | int | `100` | Minimum `?limit=` value per request. |
| `MaxLimit` | int | `1000` | Maximum `?limit=` value per request. Must be ≥ `MinLimit`. Note: the CyberArk API caps results at 1000 per page. |

\* Either `-Credential` **or** `-Username`/`-Password` must be provided, not both.

## Output

### Console columns

| Column | Description |
| --- | --- |
| Thread | Unique sequential job number |
| Limit | The `?limit=` value sent with this request |
| Returned | Number of account records returned |
| Total | Total account count reported by the vault |
| Duration | Time in seconds for this request |
| Completed | Total successful requests since the test started |
| QueueSize | Number of jobs currently queued or running |
| Concurrency | Current / maximum thread count |

### Log file

Results are appended to `CyberArk_Performance.log` in the same directory as the script. Each line is prefixed with a timestamp:

```text
2026-04-02 14:32:01 : SUCCESS | Thread: 42 | Limit: 750 | Returned: 750 | Total: 3200 | Duration: 1.23s | Completed: 150 | QueueSize: 99 | Concurrency: 8/10
2026-04-02 14:32:03 : WARNING | Thread: 43 | Slow response: 6.11s exceeded threshold of 5s
2026-04-02 14:32:03 : FAILURE | Thread: 44 | Duration: 60.00s | Error: The operation has timed out.
2026-04-02 14:32:05 : RAMP    | Thread count increased to 9 / 10
```

When the log file exceeds `MaxLogSizeMB`, it is archived as `CyberArk_Performance.log.old` and a new log is started. Any previous `.old` file is overwritten.

## How It Works

1. The script authenticates once and obtains a session token.
2. A runspace pool is created with a max size of `StartThreadCount`.
3. `QueueDepth` jobs are submitted to the pool immediately. The pool executes up to the current thread count in parallel; the rest queue behind them.
4. As each job completes, a replacement job is queued immediately, keeping continuous load on the server.
5. Every `RampUpSec` seconds the pool's max runspaces increases by one until `MaxThreadCount` is reached.
6. On **Ctrl+C** (or any fatal error), all active runspaces are stopped and disposed, and the session is logged off cleanly.

## Security Notes

- Passwords are converted to `SecureString` immediately and the plain-text value is zeroed in the `finally` block using `Marshal.ZeroFreeBSTR`.
- Credentials are never written to the log file.
- Certificate validation uses the system default; if your PVWA uses a self-signed certificate, install it in the trusted store before running.
- TLS 1.2 is enforced via `[Net.ServicePointManager]::SecurityProtocol`.
