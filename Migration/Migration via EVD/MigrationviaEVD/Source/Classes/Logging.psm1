enum LogType {
    Info
    Warning
    Error
    Debug 
    Verbose
    Super
    Success
    LogOnly
}

[NoRunspaceAffinity()]
Class Logging {
    hidden static [string]$_LogFile = ".\Log.Log"
    hidden [string]$LogFile = [Logging]::_LogFile
    static [bool]$WriteToLog = $true
    hidden static [bool]$OutputDebug = $false
    hidden static [bool]$OutputVerbose = $false
    hidden static [bool]$OutputSuper = $false
    hidden static [bool]$OverRideMasking = $false

    Logging() {
    }

    Logging([string]$LogFile) {
        IF (
            Test-Path -PathType -Path $(Split-Path -Parent $LogFile)) {
            $This._LogFile = $LogFile
        } else {
            Write-Host -ForegroundColor Red "The path `"$(Split-Path -Parent $LogFile)`" is invaild. Setting log file path to $($This.LogFile)"
            $This._LogFile = = "$($This.LogFile)"
        }
    }
    [void] WriteLog([string]$Message, [LogType]$Type, [bool]$AuthHeader, [bool]$SubHeader, [bool]$footer) {
        $ThreadId = [Threading.Thread]::CurrentThread.ManagedThreadId
        $RunspaceId = [runspace]::DefaultRunspace.Id
        $InVerbose = $MyInvocation.BoundParameters["Verbose"].IsPresent
        $InSuper = $This.OutputSuper
        if (!$InVerbose -or ([string]::IsNullOrEmpty($InVerbose))) { $InVerbose = $This.OutputVerbose
        }
        $InDebug = $MyInvocation.BoundParameters["Debug"].IsPresent
        if (!$InDebug -or ([string]::IsNullOrEmpty($InDebug))) { $InDebug = $This.OutputDebug
        }
        $InSuper = $This.OutputSuper

        If ([string]::IsNullOrEmpty($this.LogFile) -and $(!([string]::IsNullOrEmpty($global:LOG_FILE_PATH)))) {
            $this.LogFile = $script:LOG_FILE_PATH = $Global:LOG_FILE_PATH = [Logging]::_LogFile
            Write-Host "No log file path passed or found in the module, setting log file path to the global value of: `"$($this.LogFile)`""
        } elseIf ([string]::IsNullOrEmpty($this.LogFile) -and $This.WriteLog) {
            # User wanted to write logs, but did not provide a log file - Create a temporary file
            $this.LogFile = Join-Path -Path $ENV:Temp -ChildPath "$((Get-Date).ToShortDateString().Replace('/','_')).log"
            $script:LOG_FILE_PATH = $this.LogFile
            Write-Host "No log file path inputted and no global value found, setting modoule log file path to: `"$($this.LogFile)`""
        }
        If ($This.Header -and $This.WriteLog) {
            "=======================================" | Out-File -Append -FilePath $($this.LogFile)
            Write-Host "=======================================" -ForegroundColor Magenta
        } ElseIf ($This.SubHeader -and $This.WriteLog) {
            "------------------------------------" | Out-File -Append -FilePath $($this.LogFile)
            Write-Host "------------------------------------" -ForegroundColor Magenta
        }
        # Replace empty message with 'N/A'
        if ([string]::IsNullOrEmpty($Message)) {
            $Message = "N/A"
        }
        $MessageToWrite = ""
        # Change SecretType if password to prevent masking issues
        $Message = $Message.Replace('"secretType":"password"', '"secretType":"pass"')
        # Mask Passwords
        if ($Message -match '((?:password|credentials|secret|client_secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()-_\=\+\\\/|;:\.,\[\]{}]+))') {
            if ($This.OverRideMasking) {
                $Warning = @(
                    'Masking of sensitive data is in a disabled state.'
                    'Logs should be securely deleted when no longer needed.'
                    'All exposed credentials should be changed when completed '
                    'For use when debugging only '
                ) -join ' '
                If ($($(Get-Host).UI.PromptForChoice($Warning, 'Are you sure you want to proceed?', @('&Yes'; '&No'), 1))) {
                    $Message = $Message.Replace($Matches[2], "****")
                }
            } else {
                $Message = $Message.Replace($Matches[2], "****")
            }
        }
        # Check the message type
        switch ($Type) {
            { ($_ -eq "Info") -or ($_ -eq "LogOnly") } {
                If ($_ -eq "Info") {
                    Write-Host $Message.ToString() -ForegroundColor $(If ($AuthHeader -or $SubHeader) {
                            "Magenta"
                        } Else {
                            "Gray"
                        })
                }
                $MessageToWrite = "[INFO]`t`t$Message"
                break
            }
            "Success" {
                Write-Host $Message.ToString() -ForegroundColor Green
                $MessageToWrite = "[SUCCESS]`t$Message"
                break
            }
            "Warning" {
                Write-Host $Message.ToString() -ForegroundColor Yellow
                $MessageToWrite = "[WARNING]`t$Message"
                break
            }
            "Error" {
                Write-Host $Message.ToString() -ForegroundColor Red
                $MessageToWrite = "[ERROR]`t`t$Message"
                break
            }
            "Debug" {
                if ($InDebug -or $InVerbose) {
                    Write-Debug -Msg $Message
                    $MessageToWrite = "[Debug]`t`t$Message"
                }
                break
            }
            "Verbose" {
                if ($InVerbose) {
                    Write-Verbose -Msg $Message
                    $MessageToWrite = "[VERBOSE]`t$Message"
                }
                break
            }
            "Super" {
                if ($InSuper) {
                    Write-Verbose -Msg $Message
                    $MessageToWrite = "[SUPER]`t`t$Message"
                }
                break
            }
        }
        If ([logging]::WriteToLog) {
            If (![string]::IsNullOrEmpty($MessageToWrite)) {
                $written = $false
                While (!$written) {
                    Try {
                        "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t[Tr$($($ThreadId).ToString().PadLeft(3,"0")) Rs$($($RunspaceId).ToString().PadLeft(3,"0"))]`t$MessageToWrite" | Out-File -Append -FilePath $($this.LogFile)
                        $written = $true        
                    } catch {
                    }
                }
            }
        }
        If ($Footer -and [logging]::WriteToLog) {
            "=======================================" | Out-File -Append -FilePath $($this.LogFile)
            Write-Host "=======================================" -ForegroundColor Magenta
        }

    }
    [void] WriteLog([string]$Message, [LogType]$Type, [bool]$AuthHeader, [bool]$SubHeader) {
        $This.WriteLog($Message, $Type, $AuthHeader, $SubHeader, $false)
    }
    [void] WriteLog([string]$Message, [LogType]$Type, [bool]$AuthHeader) {
        $This.WriteLog($Message, $Type, $AuthHeader, $false, $false)
    }
    [void] WriteLog([string]$Message, [LogType]$Type) {
        $This.WriteLog($Message, $Type, $false, $false, $false)
    }
    [void] WriteLogOnly([string]$Message) {
        $This.WriteLog($Message, "LogOnly", $false, $false, $false)
    }
    [void] WriteLog([string]$Message) {
        $This.WriteLog($Message, "Info", $false, $false, $false)
    }
    [void] WriteInfo([string]$Message) {
        $This.WriteLog($Message, "Info", $false, $false, $false)
    }
    [void] WriteWarning([string]$Message) {
        $This.WriteLog($Message, "Warning", $false, $false, $false)
    }
    [void] WriteError([string]$Message) {
        $This.WriteLog($Message, "Error", $false, $false, $false)
    }
    [void] WriteDebug([string]$Message) {
        $This.WriteLog($Message, "Debug", $false, $false, $false)
    }
    [void] WriteVerbose([string]$Message) {
        $This.WriteLog($Message, "Verbose", $false, $false, $false)
    }
    [void] WriteSuperVerbose([string]$Message) {
        $This.WriteLog($Message, "Super", $false, $false, $false)
    }


}