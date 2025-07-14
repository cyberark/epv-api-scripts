# Load the namespace to allow different colors with Write-LogMessage
using namespace System.Management.Automation

function Format-Token {
    [CmdletBinding()]
    param (
        $AuthToken
    )
    $IdentityHeaders = New-Object System.Collections.Generic.Dictionary"[String,string]"
    $IdentityHeaders.add('Authorization', "Bearer $AuthToken")
    $IdentityHeaders.add('X-IDAP-NATIVE-CLIENT', 'true')
    Return $IdentityHeaders
}
function Get-IdentityURL {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Base URL of the CyberArk Identity platform',
            ValueFromPipelineByPropertyName = $true)]
        [string]$PCloudURL,
        [Parameter(ValueFromRemainingArguments = $true,
            DontShow = $true)]
        $CatchAll
    )
    Begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null
        $PCloudURL -match '^(?:https|http):\/\/(?<sub>.*).privilegecloud.cyberark.(?<top>cloud|com)\/PasswordVault.*$' | Out-Null
        $PCloudBaseURL = "https://$($matches['sub']).cyberark.$($matches['top'])"
    }
    Process {
        If ($PSVersionTable.PSVersion.Major -gt 5) {
            $IdentityBaseURL = $(Invoke-WebRequest $PCloudBaseURL -WebSession $global:websession.value).BaseResponse.RequestMessage.RequestUri.Host
        }
        Else {
            $IdentityBaseURL = $(Invoke-WebRequest $PCloudBaseURL -WebSession $global:websession.value).BaseResponse.ResponseURI.Host
        }
    }
    end {
        # Return the Identity URL
        $IdentityURL = "https://$IdentityBaseURL"
        return $IdentityURL
    }
}
Function Write-LogMessage {

    # Load the namespace to allow different colors with Write-LogMessage
    # Uncomment the following line to load the namespace to allow different colors with Write-LogMessage if not using the module
    #using namespace System.Management.Automation

    <#
.SYNOPSIS
    Writes a log message to the console and optionally to a log file with various formatting options.

.DESCRIPTION
    The Write-LogMessage function logs messages to the console with optional headers, subheaders, and footers.
    It also supports writing messages to a log file. The function can handle different message types such as
    Info, Warning, Error, Debug, Verbose, Success, LogOnly, and ErrorThrow. It also masks sensitive information
    like passwords in the messages.

.PARAMETER MSG
    The message to log. This parameter is mandatory and accepts pipeline input.

.PARAMETER Header
    Adds a header line before the message. This parameter is optional.

.PARAMETER SubHeader
    Adds a subheader line before the message. This parameter is optional.

.PARAMETER Footer
    Adds a footer line after the message. This parameter is optional.

.PARAMETER WriteLog
    Indicates whether to write the output to a log file. The default value is $true.

.PARAMETER type
    The type of the message to log. Valid values are 'Info', 'Warning', 'Error', 'Debug', 'Verbose', 'Success',
    'LogOnly', and 'ErrorThrow'. The default value is 'Info'.

.PARAMETER LogFile
    The log file to write to. if not provided and WriteLog is $true, a temporary log file named 'Log.Log' will be created.

.EXAMPLE
    Write-LogMessage -MSG "This is an info message" -type Info

    Logs an info message to the console and the default log file.

.EXAMPLE
    "This is a warning message" | Write-LogMessage -type Warning

    Logs a warning message to the console and the default log file using pipeline input.

.EXAMPLE
    Write-LogMessage -MSG "This is an error message" -type Error -LogFile "C:\Logs\error.log"

    Logs an error message to the console and to the specified log file.

.NOTES
    The function masks sensitive information like passwords in the messages to prevent accidental exposure.
#>

    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Scope = 'Function' , Justification = 'In TODO list to remove')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [Alias('Message')]
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
        [ValidateSet('Info', 'Important', 'Warning', 'Error', 'Debug', 'Verbose', 'Success', 'LogOnly', 'ErrorThrow')]
        [String]$type = 'Info',
        [Parameter(Mandatory = $false)]
        [String]$LogFile,
        [Parameter(Mandatory = $false)]
        [int]$pad = 20,
        [Parameter(Mandatory = $false, DontShow = $true)]
        [Switch]$maskAnswer
    )

    begin {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        if ([string]::IsNullOrEmpty($LogFile) -and [string]::IsNullOrEmpty($global:LogFile) -and $WriteLog) {
            $LogFile = "$PSScriptRoot\Log.Log"
            $global:LogFile = $LogFile
            Write-Warning "LogFile not specified. Using default: $LogFile"
        }
        elseif (![string]::IsNullOrEmpty($LogFile) -and $WriteLog) {
            $global:LogFile = $LogFile
        }
        elseif ($WriteLog) {
            $LogFile = $global:LogFile
        }
        $verboseFile = $($LogFile.replace('.log', '_Verbose.log'))
    }
    process {
        try {
            if ($Header -and $WriteLog) {
                '=======================================' | Out-File -Append -FilePath $LogFile
                Write-Information '=======================================' -InformationAction Continue
            }
            Elseif ($SubHeader -and $WriteLog) {
                '------------------------------------' | Out-File -Append -FilePath $LogFile
                Write-Information '------------------------------------' -InformationAction Continue
            }
            $LogTime = "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')]`t"
            $msgToWrite += "$LogTime"
            $writeToFile = $true
            # Replace empty message with 'N/A'
            if ([string]::IsNullOrEmpty($Msg)) {
                $Msg = 'N/A'
            }
            # Added to prevent body messages from being masked
            $Msg = Remove-SensitiveData -Msg $Msg
            # Check the message type
            switch ($type) {
                'LogOnly' {
                    $msgToWrite = ''
                    $msgToWrite += "[INFO]`t`t$Msg"
                    break
                }
                'Important' {
                    $msgdata = [HostInformationMessage]@{
                        message         = "[IMPORTANT]`t"
                        ForegroundColor = IF ($Host.UI.RawUI.ForegroundColor -eq 'Black') { 'Red' } else { 'Black' }
                        BackgroundColor = IF ($Host.UI.RawUI.BackgroundColor -eq 'Red') { 'White' } else { 'Red' }
                        NoNewLine       = $true
                    }
                    Write-Information $msgdata -InformationAction Continue
                    Write-Information $MSG.ToString() -InformationAction Continue
                    $msgToWrite = ''
                    $msgToWrite += "[IMPORTANT]`t`t$Msg"
                    break
                }
                'Info' {
                    $msgToWrite = ''
                    Write-Information $MSG.ToString() -InformationAction Continue
                    $msgToWrite += "[INFO]`t`t$Msg"
                    break
                }
                'Warning' {
                    Write-Warning $MSG.ToString() -WarningAction Continue
                    $msgToWrite += "[WARNING]`t$Msg"
                    if ($UseVerboseFile) {
                        $msgToWrite | Out-File -Append -FilePath $verboseFile
                    }
                    break
                }
                'Error' {
                    Write-Error $MSG.ToString() -ErrorAction Continue
                    $msgToWrite += "[ERROR]`t$Msg"
                    if ($UseVerboseFile) {
                        $msgToWrite | Out-File -Append -FilePath $verboseFile
                    }
                    break
                }
                'ErrorThrow' {
                    $msgToWrite = "[THROW]`t`t$Msg"
                    break
                }
                'Debug' {
                    if ($DebugPreference -ne 'SilentlyContinue' -or $VerbosePreference -ne 'SilentlyContinue' -or $UseVerboseFile) {
                        $msgToWrite += "[DEBUG]`t$Msg"
                    }
                    else {
                        $writeToFile = $False
                        break
                    }
                    if ($DebugPreference -ne 'SilentlyContinue' -or $VerbosePreference -ne 'SilentlyContinue') {
                        Write-Debug $MSG
                    }
                    if ($UseVerboseFile) {
                        $msgToWrite | Out-File -Append -FilePath $verboseFile
                    }
                }
                'Verbose' {
                    if ($VerbosePreference -ne 'SilentlyContinue' -or $UseVerboseFile) {
                        $arrMsg = $msg.split(":`t", 2)
                        if ($arrMsg.Count -gt 1) {
                            $msg = $arrMsg[0].PadRight($pad) + $arrMsg[1]
                        }
                        $msgToWrite += "[VERBOSE]`t$Msg"
                        #TODO Need to decide where to put IncludeCallStack
                        if ($global:IncludeCallStack) {
                            function Get-CallStack {
                                $stack = ''
                                $excludeItems = @('Write-LogMessage', 'Get-CallStack', '<ScriptBlock>')
                                Get-PSCallStack | ForEach-Object {
                                    if ($PSItem.Command -notin $excludeItems) {
                                        $command = $PSitem.Command
                                        #TODO Rewrite to get the script name from the script itself
                                        if ($command -eq $Global:scriptName) {
                                            $command = 'Base'
                                        }
                                        elseif ([string]::IsNullOrEmpty($command)) {
                                            $command = '**Blank**'
                                        }
                                        $Location = $PSItem.Location
                                        $stack = $stack + "$command $Location; "
                                    }
                                }
                                return $stack
                            }
                            $stack = Get-CallStack
                            $stackMsg = "CallStack:`t$stack"
                            $arrstackMsg = $stackMsg.split(":`t", 2)
                            if ($arrMsg.Count -gt 1) {
                                $stackMsg = $arrstackMsg[0].PadRight($pad) + $arrstackMsg[1].trim()
                            }
                            Write-Verbose $stackMsg
                            $msgToWrite += "`n$LogTime"
                            $msgToWrite += "[STACK]`t`t$stackMsg"
                        }
                        if ($VerbosePreference -ne 'SilentlyContinue') {
                            Write-Verbose $MSG
                            $writeToFile = $true
                        }
                        else {
                            $writeToFile = $False
                        }
                        if ($UseVerboseFile) {
                            $msgToWrite | Out-File -Append -FilePath $verboseFile
                        }
                    }
                    else {
                        $writeToFile = $False
                    }
                }
                'Success' {
                    Write-Output $MSG.ToString()
                    $msgToWrite += "[SUCCESS]`t$Msg"
                    break
                }
            }
            if ($writeToFile) {
                $msgToWrite | Out-File -Append -FilePath $LogFile
            }
            if ($Footer) {
                '=======================================' | Out-File -Append -FilePath $LogFile
                Write-Information '=======================================' -InformationAction Continue
            }
            If ($type -eq 'ErrorThrow') {
                Throw $MSG
            }
        }
        catch {
            IF ($type -eq 'ErrorThrow') {
                Throw $MSG
            }
            Throw $(New-Object System.Exception ('Cannot write message'), $PSItem.Exception)
        }
    }
}
function Remove-SensitiveData {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Alias('MSG', 'value', 'string')]
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $message
    )
    Begin {
        $cleanedMessage = $message
    }
    process {
        If ($global:LogSensitiveData -eq $true) {
            # Allows sensitive data to be logged this is useful for debugging authentication issues
            return $message
        }
        # List of fields that contain sensitive data to check for
        $checkFor = @('password', 'secret', 'NewCredentials', 'access_token', 'client_secret', 'auth', 'Authorization', 'Answer', 'Token')
        # Check for sensitive data in the message that is escaped with quotes or double quotes
        $checkFor | ForEach-Object {
            if ($cleanedMessage -imatch "[{\\""']{2,}\s{0,}$PSitem\s{0,}[\\""']{2,}\s{0,}[:=][\\""']{2,}\s{0,}(?<Sensitive>.*?)\s{0,}[\\""']{2,}(?=[,:;])") {
                $cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
            }
            # Check for sensitive data in the message that is not escaped with quotes or double quotes
            elseif ($cleanedMessage -imatch "[""']{1,}\s{0,}$PSitem\s{0,}[""']{1,}\s{0,}[:=][""']{1,}\s{0,}(?<Sensitive>.*?)\s{0,}[""']{1,}") {
                $cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
            }
            # Check for Sensitive data in pure JSON without quotes
            elseif ( $cleanedMessage -imatch "(?:\s{0,}$PSitem\s{0,}[:=])\s{0,}(?<Sensitive>.*?)(?=; |: )") {
                $cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
            }
        }
    }
    end {
        # Return the modified string
        return $cleanedMessage
    }
}
#
function Get-CallerPreference {
    <#
.Synopsis
    Retrieves and sets caller preference variables.
  .DESCRIPTION
    The Get-CallerPreference function retrieves specific preference variables from the caller's session state and sets them in the current session state or a specified session state.
    It ensures that the preference variables such as ErrorActionPreference, VerbosePreference, and DebugPreference are correctly set based on the caller's context.
  .EXAMPLE
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    This example retrieves the caller preference variables from the current session state and sets them accordingly.
  .EXAMPLE
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $CustomSessionState
    This example retrieves the caller preference variables from the current session state and sets them in a custom session state.
  .INPUTS
    [System.Management.Automation.PSScriptCmdlet]
      The cmdlet from which to retrieve the caller preference variables.
    [System.Management.Automation.SessionState]
      The session state where the preference variables will be set.
  .OUTPUTS
    None
  .NOTES
    This function is useful for ensuring that preference variables are consistently set across different session states.
  .COMPONENT
    EPV-API-Common
  .ROLE
    Utility
  .FUNCTIONALITY
    Preference Management
  #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_.GetType().FullName -eq 'System.Management.Automation.PSScriptCmdlet' })]
        $Cmdlet,
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.SessionState]
        $SessionState
    )

    $vars = @{
        'ErrorView'             = $null
        'ErrorActionPreference' = 'ErrorAction'
        'VerbosePreference'     = 'Verbose'
        'DebugPreference'       = 'Debug'
    }

    foreach ($entry in $vars.GetEnumerator()) {
        if ([string]::IsNullOrEmpty($entry.Value) -or -not $Cmdlet.MyInvocation.BoundParameters.ContainsKey($entry.Value)) {
            $variable = $Cmdlet.SessionState.PSVariable.Get($entry.Key)
            if ($null -ne $variable) {
                if ($SessionState -eq $ExecutionContext.SessionState) {
                    Set-Variable -Scope 1 -Name $variable.Name -Value $variable.Value -Force -Confirm:$false -WhatIf:$false
                }
                else {
                    $SessionState.PSVariable.Set($variable.Name, $variable.Value)
                }
            }
        }
    }
}
Function Invoke-Rest {
    <#
.SYNOPSIS
    Invokes a REST API call with the specified parameters.

.DESCRIPTION
    The Invoke-Rest function is designed to make REST API calls using various HTTP methods such as GET, POST, DELETE, PATCH, and PUT.
    It supports custom headers, request bodies, and content types. The function also includes error handling and logging mechanisms.

.PARAMETER Command
    Specifies the HTTP method to use for the REST API call.
    Valid values are 'GET', 'POST', 'DELETE', 'PATCH', and 'PUT'. This parameter is mandatory.

.PARAMETER URI
    Specifies the URI of the REST API endpoint. This parameter is mandatory.

.PARAMETER Header
    Specifies the headers to include in the REST API call. This parameter is optional.

.PARAMETER Body
    Specifies the body content to include in the REST API call. This parameter is optional.

.PARAMETER ContentType
    Specifies the content type of the request body. The default value is 'application/json'. This parameter is optional.

.PARAMETER ErrAction
    Specifies the action to take if an error occurs.
    Valid values are 'Continue', 'Ignore', 'Inquire', 'SilentlyContinue', 'Stop', and 'Suspend'. The default value is 'Continue'. This parameter is optional.

.EXAMPLE
    Invoke-Rest -Command GET -URI "https://api.example.com/data" -Header @{Authorization = "Bearer token"}

    This example makes a GET request to the specified URI with an authorization header.

.EXAMPLE
    Invoke-Rest -Command POST -URI "https://api.example.com/data" -Body '{"name":"value"}' -ContentType "application/json"

    This example makes a POST request to the specified URI with a JSON body.

.NOTES
    This function includes extensive logging for debugging purposes. It logs the entry and exit points, as well as detailed information about the request and response.
#>

    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Scope = 'Function', Justification = 'Used in deep debugging')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Alias('Method')]
        [ValidateSet('GET', 'POST', 'DELETE', 'PATCH', 'PUT')]
        [String]$Command,

        [Alias('PCloudURL', 'IdentityURL', 'URL')]
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$URI,

        [Alias('LogonToken', 'Headers')]
        [Parameter(Mandatory = $false)]
        $Header,

        [Parameter(Mandatory = $false)]
        $Body,

        [Parameter(Mandatory = $false)]
        [String]$ContentType = 'application/json',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Continue', 'Ignore', 'Inquire', 'SilentlyContinue', 'Stop', 'Suspend')]
        [String]$ErrAction = 'Continue',

        [Parameter(Mandatory = $false)]
        [String]$SessionVariable,

        [Parameter(Mandatory = $false, DontShow = $true)]
        [switch]$WaitInProgress,

        [Parameter(Mandatory = $false, DontShow = $true)]
        [int]$WaitCount = 0
    )

    Process {
        If ($WaitInProgress) {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tEntering Invoke-Rest but WaitInProgress is true, suppressing standard logging. Loop number: $WaitCount"
        }
        else {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tEntering Invoke-Rest"
        }
        $restResponse = ''
        try {
            If (!$WaitInProgress) {
                Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tCommand:`t$Command`tURI:  $URI"
            }
            $RestCall = @{
                Uri         = $URI
                Method      = $Command
                ContentType = $ContentType
                TimeoutSec  = 2700
                ErrorAction = $ErrAction
            }
            If ($WaitInProgress) {
                $restCall.Add('Verbose', $false)
                $restCall.Add('Debug', $false)
            }
            IF ($global:WebSession) {
                If (!$WaitInProgress) {
                    Write-LogMessage -type Verbose -MSG "WebSession Found: `t$($global:WebSession |ConvertTo-Json -Depth 9 -Compress)"
                }
                $RestCall.Add('WebSession', $global:WebSession)
            }
            elseif ($Header) {
                if (!$WaitInProgress) {
                    Write-LogMessage -type Verbose -MSG "Header Found: `t$Header"
                }$RestCall.Add('Header', $Header)
            }
            else {
                $SessionVariable = 'IdentitySession'
                if (!$WaitInProgress) {
                    Write-LogMessage -type Verbose -MSG "SessionVariable Not Found: `tSetting to $SessionVariable"
                }$RestCall.Add('SessionVariable', $SessionVariable)
            }
            IF ($Body) {
                if (!$WaitInProgress) {
                    Write-LogMessage -type Verbose -MSG "Body Found: `t$($Body | ConvertTo-Json -Depth 9 -Compress)"
                }
                $RestCall.Add('Body', $Body)
            }

            $restResponse = Invoke-RestMethod @RestCall

        }
        catch [System.Net.WebException] {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tCaught WebException"
            if ($ErrAction -match ('\bContinue\b|\bInquire\b|\bStop\b|\bSuspend\b')) {
                Write-LogMessage -type Error -MSG "Error Message: $PSItem"
                Write-LogMessage -type Error -MSG "Exception Message: $($PSItem.Exception.Message)"
                Write-LogMessage -type Error -MSG "Status Code: $($PSItem.Exception.Response.StatusCode.value__)"
                Write-LogMessage -type Error -MSG "Status Description: $($PSItem.Exception.Response.StatusDescription)"
                $restResponse = $null
                Throw
                Else {
                    Throw $PSItem
                }
            }
        }
        catch [Microsoft.PowerShell.Commands.HttpResponseException] {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tCaught HttpResponseException"
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tCommand:`t$Command`tURI:  $URI"
            If (-not [string]::IsNullOrEmpty($Body)) {
                Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tBody:`t $Body"
            }
            $Details = ($PSItem.ErrorDetails.Message | ConvertFrom-Json)
            If ('SFWS0007' -eq $Details.ErrorCode) {
                Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.ErrorMessage)"
                Throw $PSItem
            }
            elseif ('ITATS127E' -eq $Details.ErrorCode) {
                Write-LogMessage -type Error -MSG 'Was able to connect to the PVWA successfully, but the account was locked'
                Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.ErrorMessage)"
                Throw [System.Management.Automation.RuntimeException] 'Account Locked'
            }
            elseif ('PASWS013E' -eq $Details.ErrorCode) {
                Write-LogMessage -type Error -MSG "$($Details.ErrorMessage)" -Header -Footer
            }
            elseif ('SFWS0002' -eq $Details.ErrorCode) {
                Write-LogMessage -type Warning -MSG "$($Details.ErrorMessage)"
                Throw "$($Details.ErrorMessage)"
            }
            If ('SFWS0012' -eq $Details.ErrorCode) {
                Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.ErrorMessage)"
                Throw $PSItem
            }
            elseif (!($errorDetails.ErrorCode -in $global:SkipErrorCode)) {
                Write-LogMessage -type Error -MSG 'Was able to connect to the PVWA successfully, but the command resulted in an error'
                Write-LogMessage -type Error -MSG "Returned ErrorCode: $($errorDetails.ErrorCode)"
                Write-LogMessage -type Error -MSG "Returned ErrorMessage: $($errorDetails.ErrorMessage)"
                Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tExiting Invoke-Rest"
                Throw $PSItem
            }
            Else {
                Write-LogMessage -type Error -MSG "Error in running '$Command' on '$URI', $($PSItem.Exception)"
                Throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $PSItem.Exception))
            }
        }
        catch {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tCaught Exception"
            If ($ErrAction -ne 'SilentlyContinue') {
                Write-LogMessage -type Error -MSG "Error in running $Command on '$URI', $PSItem.Exception"
                Write-LogMessage -type Error -MSG "Error Message: $PSItem"
            }
            else {
                Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tError in running $Command on '$URI', $PSItem.Exception"
                Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tError Message: $PSItem"
            }
            Throw $(New-Object System.Exception ("Error in running $Command on '$URI'", $PSItem.Exception))
        }
        If (!$WaitInProgress) {
            if ($URI -match 'Password/Retrieve') {
                Write-LogMessage -type Verbose -MSG 'Invoke-Rest:`tInvoke-REST Response: ***********'
            }
            else {
                if ($global:SuperVerbose) {
                    Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tInvoke-REST Response Type: $($restResponse.GetType().Name)"
                    $type = $restResponse.GetType().Name
                    if ('String' -ne $type) {
                        Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tInvoke-REST ConvertTo-Json Response: $($restResponse | ConvertTo-Json -Depth 9 -Compress)"
                    }
                    else {
                        Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tInvoke-REST Response: $restResponse"
                    }
                }
                else {
                    Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tInvoke-REST Response: $restResponse"
                }
            }
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tExiting Invoke-Rest"
        }
        return $restResponse
    }
}
Function Invoke-AdvancedAuthBody {
`
        [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Session ID of the mechanism')]
        [string]$SessionId,
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Mechanism of Authentication')]
        $Mechanism,
        #The URL of the tenant. you can find it if you go to Identity Admin Portal > Settings > Customization > Tenant URL.
        [Alias('IdentityURL')]
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Identity Tenant URL')]
        [string]$PCloudIdentityURL,
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Credentials to pass if option is UP')]
        [pscredential]$UPCreds
    )
    $startPlatformAPIAdvancedAuth = "$PCloudIdentityURL/Security/AdvanceAuthentication"
    $MechanismId = $Mechanism.MechanismId
    #need to do this if/elseif as a function so we do not double code here.
    If ($Mechanism.AnswerType -eq 'StartTextOob') {
        #We got two options here 1 text and one Push notification. We will need to do the while statement in this option.
        $Action = 'StartOOB'
        $startPlatformAPIAdvancedAuthBody = @{SessionId = $SessionId; MechanismId = $MechanismId; Action = $Action; } | ConvertTo-Json -Compress
        Write-LogMessage -type 'Info' -MSG 'Waiting for Push to be pressed'
    }
    ElseIf ($Mechanism.AnswerType -eq 'Text') {
        $Action = 'Answer'
        IF (($Mechanism.Name -eq 'UP') -and ($UPCreds)) {
            Write-Host 'Responding with stored credentials'
            $answer = $UPCreds.Password
        }
        else {
            $Answer = Read-Host $($Mechanism.PromptMechChosen) -AsSecureString
        }
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Answer)
        $startPlatformAPIAdvancedAuthBody = @{SessionId = $SessionId; MechanismId = $MechanismId; Action = $Action; Answer = ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)) } | ConvertTo-Json -Compress
    }
    #Rest API
    Try {
        $AnswerToResponse = Invoke-Rest -Uri $startPlatformAPIAdvancedAuth -Method Post -Body $startPlatformAPIAdvancedAuthBody
    }
    Catch {
        Write-LogMessage -type Error -MSG $PSitem.ErrorDetails.Message
    }
    while ($AnswerToResponse.Result.Summary -eq 'OobPending') {
        Start-Sleep -Seconds 2
        $pollBody = @{SessionId = $SessionId; MechanismId = $MechanismId; Action = 'Poll'; } | ConvertTo-Json -Compress
        $AnswerToResponse = Invoke-Rest -Uri $startPlatformAPIAdvancedAuth -Method Post -Body $pollBody
        Write-LogMessage -type 'Info' -MSG "$($AnswerToResponse.Result.Summary)"
    }
    return $AnswerToResponse
}
Function Invoke-Challenge {
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $true)]
        [array]$IdaptiveResponse,
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Credentials to pass if option is UP')]
        [pscredential]$UPCreds,
        #The URL of the tenant. you can find it if you go to Identity Admin Portal > Settings > Customization > Tenant URL.
        [Alias('IdentityURL')]
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Identity Tenant URL')]
        [string]$PCloudIdentityURL,
        [Parameter(
            DontShow = $true)]
        [int]$SAMLTimeout = 5 #Default 5 minutes
    )
    IF ($($IdaptiveResponse.Result.IdpRedirectShortUrl)) {
        Write-LogMessage -type 'Important' -MSG "Use the following adddress to complete logon: $($IdaptiveResponse.Result.IdpRedirectShortUrl)" -Header -Footer
        $counter = 0
        Do {
            $status = Invoke-Rest -Uri "$PCloudIdentityURL/Security/OobAuthStatus?sessionId=$($IdaptiveResponse.Result.IdpLoginSessionId)" -Method Post -WaitInProgress -WaitCount $counter
            $status
            Start-Sleep 1
            $counter += 1
            If ($counter % 60 -eq 0) {
                Write-LogMessage -type 'Warning' -MSG "Waiting for SAML authentication to complete. $(IF ($counter -eq 60) {'1 minute'} else {"$($counter/60) minutes"}) passed. Attempt will timeout after $SAMLTimeout minutes."
            }
            elseif ($counter % 15 -eq 0) {
                Write-LogMessage -type 'Info' -MSG 'Waiting for SAML authentication to complete. '
            }
            If ($counter -gt $($SAMLTimeout * 60)) {
                Write-LogMessage -type ErrorThrow -MSG 'SAML authentication timeout by the script and not the Identity Provider.'
                Break
            }
        }
        Until(-not($status.result.State -eq 'Pending'))
        if ($status.result.State -eq 'NotFound') {
            Write-LogMessage -type ErrorThrow -MSG 'SAML authentication timeout by Identity Provider and not the script.'
            Break
        }
        Write-LogMessage -type 'Verbose' -MSG "SAML authentication completed with status: $($status.result.State)"
        Return $status
    }
    $j = 1
    ForEach ($challenge in $IdaptiveResponse.Result.Challenges) {
        #reseting variables
        $Mechanism = $null
        $ChallengeCount = 0
        $ChallengeCount = $challenge.mechanisms.count
        Write-LogMessage -type 'Info' -MSG "Challenge $($j):"
        #Multi mechanisms option response
        If ($ChallengeCount -gt 1) {
            Write-LogMessage -type 'Info' -MSG "There are $ChallengeCount options to choose from."
            $mechanisms = $challenge.mechanisms
            #Displaying the two options for MFA at this challenge part
            $i = 1
            ForEach ($mechanismsOption in $mechanisms) {
                $mechanismsName = $mechanismsOption.Name
                $MechanismsMechChosen = $mechanismsOption.PromptMechChosen
                Write-LogMessage -type 'Info' -MSG "$i - is $mechanismsName - $MechanismsMechChosen"
                $i = $i + 1
            }
            #Requesting to know which option the user wants to use
            $Option = $Null
            While ($Option -gt $ChallengeCount -or $Option -lt 1 -or $Null -eq $Option) {
                $Option = Read-Host "Please enter the option number you want to use. from 1-$ChallengeCount"
                Try {
                    $Option = [Int]$Option
                }
                Catch {
                    Write-LogMessage -type Error -MSG $PSitem.ErrorDetails.Message
                }
            }
            #Getting the mechanism
            $Mechanism = $challenge.mechanisms[$Option - 1] #This is an array so number-1 means the actual position
            #Completing step of authentication
            $AnswerToResponse = Invoke-AdvancedAuthBody -SessionId $SessionId -Mechanism $Mechanism -PCloudIdentityURL $PCloudIdentityURL -UPCreds $UPCreds
            Write-LogMessage -type 'Verbose' -MSG "AnswerToResponce - $($AnswerToResponse |ConvertTo-Json -Depth 9 -Compress)"
        }
        #One mechanism
        Else {
            $Mechanism = $challenge.mechanisms
            $MechanismName = $Mechanism.Name
            $MechanismPrmpt = $Mechanism.PromptMechChosen
            Write-LogMessage -type 'Info' -MSG "$MechanismName - $MechanismPrmpt"
            $AnswerToResponse = Invoke-AdvancedAuthBody -SessionId $SessionId -Mechanism $Mechanism -PCloudIdentityURL $PCloudIdentityURL -UPCreds $UPCreds
            Write-LogMessage -type 'Verbose' -MSG "AnswerToResponce - $($AnswerToResponse |ConvertTo-Json -Depth 9 -Compress)"
        }
        #Need Better logic here to make sure that we are done with all the challenges correctly and got next challenge.
        $j = + 1 #incrementing the challenge number
    }
    Return $AnswerToResponse
}
function Get-IdentityOAuthToken {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromRemainingArguments, DontShow)]
        $CatchAll,
        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [pscredential]$OAuthCreds,
        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string]$PCloudIdentityURL
    )
    Begin {
        $PSBoundParameters.Remove('CatchAll') | Out-Null
    }
    Process {
        # Check if the OAuth credentials are provided
        if (-not $OAuthCreds) {
            Write-LogMessage -type Error -MSG 'OAuth credentials are required.'
            return
        }
        # Check if the OAuth credentials are valid
        if ($OAuthCreds.GetNetworkCredential().UserName -and $OAuthCreds.GetNetworkCredential().Password) {
            Write-LogMessage -type Verbose -MSG 'Valid OAuth credentials provided.'
        }
        else {
            Write-LogMessage -type Error -MSG 'Invalid OAuth credentials.'
            return
        }
    }
    End {
        $body = @{
            'grant_type'    = 'client_credentials'
            'client_id'     = $($OAuthCreds.GetNetworkCredential().UserName)
            'client_secret' = $($OAuthCreds.GetNetworkCredential().Password)
        }
        $token = Invoke-Rest "$PCloudIdentityURL/oauth2/platformtoken/" -Method 'POST' -Body $body -ContentType 'application/x-www-form-urlencoded'
        return $token
    }
}
Function Get-IdentityHeader {
    [CmdletBinding(DefaultParameterSetName = 'IdentityUserName')]
    Param (
        #The Username that will log into the system. It just needs the username, we will ask for PW, Push etc when doing the authentication.
        [Parameter(
            ParameterSetName = 'IdentityUserName',
            Mandatory = $true,
            HelpMessage = 'User to authenticate into the platform')]
        [string]$IdentityUserName,
        #Username and Password to use when prompted for user password. Replaces the parameter IdentityUserName
        [Parameter(
            ParameterSetName = 'UPCreds',
            Mandatory = $true,
            HelpMessage = 'Credentials to pass if option is UP')]
        [pscredential]$UPCreds,
        #Username and shared secret to use when connecting via OAuth. Replaces the parameter IdentityUserName
        [Parameter(
            ParameterSetName = 'OAuthCreds',
            Mandatory = $true,
            HelpMessage = 'Credentials to pass if option is UP')]
        [pscredential]$OAuthCreds,
        #The URL of the tenant. you can find it if you go to Identity Admin Portal > Settings > Customization > Tenant URL.
        [Alias('IdentityURL')]
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Identity Tenant URL')]
        [string]$IdentityTenantURL,
        #The Subdomain assigned to the privileged cloud environment.
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'Subdomain of the privileged cloud environment')]
        [string]$PCloudSubdomain,
        [Parameter(
            Mandatory = $false,
            HelpMessage = 'URL of the privileged cloud environment')]
        [string]$PCloudURL,
        [Parameter(
            DontShow = $true,
            Mandatory = $false,
            HelpMessage = 'Use customized URL for the Identity Tenant and PCloud environment',
            ParameterSetName = 'UseCustomURL')]
        [switch]$UseCustomURL,
        [Parameter(
            DontShow = $true,
            Mandatory = $true,
            ParameterSetName = 'UseCustomURL',
            HelpMessage = 'Custom URL for the Identity Tenant and PCloud environment')]
        [string]$IdentityURLOverride,
        [Parameter(
            DontShow = $true,
            Mandatory = $true,
            ParameterSetName = 'UseCustomURL',
            HelpMessage = 'Custom URL for the PCloud environment')]
        [string]$PCloudURLOverride
    )


    IF ($UseCustomURL) {
        # If UseCustomURL is set, override the IdentityTenantURL and PCloudURL with the provided custom URLs
        $IdentityTenantURL = $IdentityURLOverride
        $PCloudURL = $PCloudURLOverride
        Write-LogMessage -type 'Verbose' -MSG "Using custom URLs: IdentityTenantURL: $IdentityTenantURL, PCloudURL: $PCloudURL"
    }
    else {
        if ([string]::IsNullOrEmpty("$PCloudURL$IdentityTenantURL")) {
            Write-LogMessage -type Error -MSG 'You must provide either PCloudURL or IdentityTenantURL'
            return
        }
        IF ($PCloudURL -and [string]::IsNullOrEmpty($IdentityTenantURL)) {
            $IdentityTenantURL = Get-IdentityURL -PCloudURL $PCloudURL
        }
    }
    $global:WebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $global:websession.headers.Add('OobIdPAuth', $true)
    $global:WebSession.Headers.Add('X-IDAP-NATIVE-CLIENT', 'true')
    $PSDefaultParameterValues['*:PVWAURL'] = $PCloudURL
    $PSDefaultParameterValues['*:IdentityURL'] = $IdentityTenantURL

    Write-LogMessage -type 'Verbose' -MSG "Base URL used : $IdentityTenantURL"
    $IdentityBasePlatformSecURL = "$IdentityTenantURL/Security"
    $startPlatformAPIAuth = "$IdentityBasePlatformSecURL/StartAuthentication"
    iF ('OAuthCreds' -eq $PSCmdlet.ParameterSetName) {
        Write-LogMessage -type 'Verbose' -MSG 'OAuthCreds Passed'
        $OAuthToken = Get-IdentityOAuthToken -PCloudIdentityURL $IdentityTenantURL -UPCreds $UPCreds -OAuthCreds $OAuthCreds
        #Creating the header for the request to the Identity URL
        $identityHeaders = Format-Token($($OAuthToken.access_token))
        Write-LogMessage -type 'Verbose' -MSG "IdentityHeaders - $($IdentityHeaders |ConvertTo-Json -Depth 9 -Compress)"
        Write-LogMessage -type 'Info' -MSG 'Identity Token Set Successfully'
        $PSDefaultParameterValues['*:LogonToken'] = $identityHeaders
        $global:WebSession.Headers.Add('Authorization', "$($identityHeaders.Authorization)")
        Set-Variable -Name PSDefaultParameterValues -Scope 2 -Value $PSDefaultParameterValues
        return $identityHeaders
    }
    ElseIf ('UPCreds' -eq $PSCmdlet.ParameterSetName) {
        $IdentityUserName = $UPCreds.UserName
    }
    $startPlatformAPIBody = [PSCustomObject]@{
        User    = $IdentityUserName
        Version = '1.0'
    }
    #Reformat the body to JSON per Identity API requirements
    $startPlatformAPIBody = $startPlatformAPIBody | ConvertTo-Json -Depth 9 -Compress
    $IdentityResponse = Invoke-Rest -Uri $startPlatformAPIAuth -Method Post -Body $startPlatformAPIBody
    $SessionId = $($IdentityResponse.Result.SessionId)
    Write-LogMessage -type 'Verbose' -MSG "SessionId : $($SessionId |ConvertTo-Json -Depth 9 -Compress)"
    $AnswerToResponse = Invoke-Challenge $IdentityResponse -UPCreds $UPCreds -PCloudIdentityURL $IdentityTenantURL
    If ($AnswerToResponse.success) {
        $identityHeaders = Format-Token($AnswerToResponse.Result.Token.trim())
        Write-LogMessage -type 'Verbose' -MSG "IdentityHeaders - $($IdentityHeaders |ConvertTo-Json -Depth 9 -Compress)"
        Write-LogMessage -type 'Info' -MSG 'Identity Token Set Successfully'
        $PSDefaultParameterValues['*:LogonToken'] = $identityHeaders
        $global:WebSession.Headers.Add('Authorization', "$($identityHeaders.Authorization)")
        Set-Variable -Name PSDefaultParameterValues -Scope 2 -Value $PSDefaultParameterValues
        return $identityHeaders
    }
    else {
        Write-LogMessage -type 'Verbose' -MSG "identityHeaders: $($AnswerToResponse|ConvertTo-Json -Depth 9 -Compress)"
        Write-LogMessage -type Error -MSG "Error during logon : $($AnswerToResponse.Message)"
    }
}
