

[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[Alias("url")]
    # Identity URL
	[String]$IdentityTenantURL,
#
	[Parameter(Mandatory = $false)]
	$GroupName,

	[Parameter(Mandatory = $false)]
	$UPN,

    [Parameter(Mandatory = $false)]
    $UserUUID,

    [Parameter(Mandatory = $false)]
	$UUIDArray,

	[Parameter(Mandatory = $true)]
	$logonToken
)

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
        [ValidateSet("Info", "Warning", "Error", "Debug", "Verbose", "Success", "LogOnly", "ErrorThrow")]
        [String]$type = "Info",
        [Parameter(Mandatory = $false)]
        [String]$LogFile = $LOG_FILE_PATH
    )
    Try {
        If ([string]::IsNullOrEmpty($LogFile) -and $WriteLog) {
            # User wanted to write logs, but did not provide a log file - Create a temporary file
            $LogFile = Join-Path -Path $ENV:Temp -ChildPath "$((Get-Date).ToShortDateString().Replace('/','_')).log"
            Write-Host "No log file path inputted, created a temporary file at: '$LogFile'"
        }
        If ($Header -and $WriteLog) {
            "=======================================" | Out-File -Append -FilePath $LogFile
            Write-Host "=======================================" -ForegroundColor Magenta
        } ElseIf ($SubHeader -and $WriteLog) {
            "------------------------------------" | Out-File -Append -FilePath $LogFile
            Write-Host "------------------------------------" -ForegroundColor Magenta
        }

        # Replace empty message with 'N/A'
        if ([string]::IsNullOrEmpty($Msg)) {
            $Msg = "N/A"
        }
        $msgToWrite = ""

        # Change SecretType if password to prevent masking issues

        $Msg = $Msg.Replace('"secretType":"password"', '"secretType":"pass"')

        # Mask Passwords
        if ($Msg -match '((?:password|credentials|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()-_\=\+\\\/|;:\.,\[\]{}]+))') {
            $Msg = $Msg.Replace($Matches[2], "****")
        }
        $Msg = $Msg.Replace('"secretType":"pass"', '"secretType":"password"')

        # Check the message type
        switch ($type) {
            { ($PSItem -eq "Info") -or ($PSItem -eq "LogOnly") } {
                If ($PSItem -eq "Info") {
                    Write-Host $MSG.ToString() -ForegroundColor $(If ($Header -or $SubHeader) {
                            "Magenta"
                        } Else {
                            "Gray"
                        })
                }
                $msgToWrite = "[INFO]`t`t$Msg"
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
            "ErrorThrow" {
                $msgToWrite = "[THROW]`t$Msg"
                #Error will be thrown manually after use
                break
            }
            "Debug" {
                if ($InDebug -or $InVerbose) {
                    Write-Debug -Message $MSG
                    $msgToWrite = "[Debug]`t`t$Msg"
                }
                break
            }
            "Verbose" {
                if ($InVerbose) {
                    Write-Verbose -Message $MSG
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
    } catch {
        Throw $(New-Object System.Exception ("Cannot write message"), $PSItem.Exception)
    }
}
$funWLM = ${function:Write-LogMessage}.ToString()
# Get Script Location
$ScriptFullPath = $MyInvocation.MyCommand.Path
$ScriptLocation = Split-Path -Parent $ScriptFullPath
$ScriptParameters = @()
$PSBoundParameters.GetEnumerator() | ForEach-Object { $ScriptParameters += ("-{0} '{1}'" -f $_.Key, $_.Value) }
$global:g_ScriptCommand = "{0} {1}" -f $ScriptFullPath, $($ScriptParameters -join ' ')

# Script Version
$ScriptVersion = "0.1.0"

# Set Log file path
$global:LOG_FILE_PATH = "$ScriptLocation\Account_Refresh_Tool.log"
$errorList = ".\ErrorList.log"

$InDebug = $PSBoundParameters.Debug.IsPresent
$InVerbose = $PSBoundParameters.Verbose.IsPresent


$usersToRefresh = [PSCustomObject]@()
If (!$([string]::IsNullOrEmpty($GroupName))) {
	$usersToRefresh += $GroupName | ForEach-Object {
		Get-ADGroupMember "$PSItem" | Get-ADUser | Select-Object UserPrincipalName, ObjectGUID
	}
}
If (!$([string]::IsNullOrEmpty($UPN))) {
	$usersToRefresh += $UPN | ForEach-Object {
		Get-ADUser -Filter "UserPrincipalName -like `"$PSItem`"" | Select-Object -Property UserPrincipalName, ObjectGUID
	}
}
If (!$([string]::IsNullOrEmpty($UUID))) {
	$usersToRefresh += $UUID | ForEach-Object {
		[PSCustomObject]@{
			UserPrincipalName = "User UUID Passed Directly - $PSItem"
			ObjectGUID        = $PSItem
		}
	}
}
If ([String]::IsNullOrEmpty($usersToRefresh)) {
	Write-LogMessage -type Error "No group, UPN, or UUID passed."
	continue
}
Write-LogMessage -type info "$($usersToRefresh.count) users found"
Write-LogMessage -type verbose "Passed LogonToken: $($logonToken|ConvertTo-Json -Depth 9)"
Write-LogMessage -type verbose "usersToRefresh: $($usersToRefresh|ConvertTo-Json -Depth 9)"

$refreshReport = $usersToRefresh |ForEach-Object  {
	Write-LogMessage -type Info "Working user with UPN of `"$($PSItem.UserPrincipalName)`""
	Write-LogMessage -type Verbose "User ObjectGUID: `"$($PSItem.ObjectGUID)`""
	$url = "$IdentityTenantURL/CDirectoryService/RefreshToken?ID=$($PSitem.ObjectGUID)"
	Write-LogMessage -type verbose "Invokeing: Invoke-RestMethod $url -Method 'POST' -Headers $logonToken"
    $RefreshResponce = Invoke-RestMethod $url -Method 'POST' -Headers $logonToken -errorAction SilentlyContinue
	Write-LogMessage -type Info "User `"$($Psitem.UserPrincipalName)`" refreshed succesfully: $($RefreshResponce.success)"
	$result = [PSCustomObject]@{
		UserPrincipalName = $Psitem.UserPrincipalName
		ObjectGUID = $PSItem.ObjectGUID
		Succesful = $RefreshResponce.success
	}
	Return $result
}

IF ( 0 -ne $($refreshReport |Where-object -not Succesful).Count) {
    $refreshReport |Where-object -not Succesful |Select-Object -Property UserPrincipalName,ObjectGUID | Out-File $errorList
    Write-LogMessage -type Error "List of failures outputted to $errorList"
}
Write-LogMessage -type Info "$($($refreshReport| Where-Object Succesful).Count) out of $($($refreshReport).Count) completed succedfully"
