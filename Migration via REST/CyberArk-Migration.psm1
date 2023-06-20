[CmdletBinding()]

# Global URLS
# -----------
#region Global Variables
$URL_PVWAAPI = $global:PVWAURL + "/api"
$URL_Authentication = $URL_PVWAAPI + "/auth"
$URL_Logon = $URL_Authentication + "/$global:AuthType/Logon"
$URL_Logoff = $URL_Authentication + "/Logoff"

$URL_UserSearch = $URL_PVWAAPI + "/Users?filter=componentUser&search={0}"
$URL_UserResetPassword = $URL_PVWAAPI + "/Users/{0}/ResetPassword"
$URL_Activate = $URL_PVWAAPI + "/Users/{0}/Activate"

$URL_Accounts = $URL_PVWAAPI + "/Accounts"
$URL_AccountsDetails = $URL_PVWAAPI + "/Accounts/{0}"
$URL_Platforms = $URL_PVWAAPI + "/Platforms/{0}"

if ($InVerbose) {
    $VerbosePreference = "continue"
}
#endregion

# Initialize Script Variables
# ---------------------------

# @FUNCTION@ ======================================================================================================================
# Name...........: Write-LogMessage
# Description....: Writes the message to log and screen
# Parameters.....: LogFile, MSG, (Switch)Header, (Switch)SubHeader, (Switch)Footer, Type
# Return Values..: None
# =================================================================================================================================

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
        [ValidateSet("Info", "Warning", "Error", "Debug", "Verbose", "Success", "LogOnly")]
        [String]$type = "Info",
        [Parameter(Mandatory = $false)]
        [String]$LogFile = $LOG_FILE_PATH
    )

    If (![string]::IsNullOrEmpty($PSSenderInfo)) {
        $WriteLog = $false
    }
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
            { ($_ -eq "Info") -or ($_ -eq "LogOnly") } { 
                If ($_ -eq "Info") {
                    Write-Host $MSG.ToString() -ForegroundColor $(If ($Header -or $SubHeader) {
                            "Magenta" 
                        } Else {
                            "Gray" 
                        })
                }
                $msgToWrite = "[INFO]`t$Msg"
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
            "Debug" { 
                if ($InDebug -or $InVerbose) {
                    Write-Debug -Msg $MSG
                    $msgToWrite = "[Debug]`t$Msg"
                }
                break
            }
            "Verbose" { 
                if ($InVerbose) {
                    Write-Verbose -Msg $MSG
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
        Throw $(New-Object System.Exception ("Cannot write message"), $_.Exception)
    }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Join-ExceptionMessage
# Description....: Formats exception messages
# Parameters.....: Exception
# Return Values..: Formatted String of Exception messages
# =================================================================================================================================
Function Join-ExceptionMessage {
    <#
.SYNOPSIS
	Formats exception messages
.DESCRIPTION
	Formats exception messages
.PARAMETER Exception
	The Exception object to format
#>
    param(
        [Exception]$e
    )

    Begin {
    }
    Process {
        $msg = "Source:{0}; Message: {1}" -f $e.Source, $e.Message
        while ($e.InnerException) {
            $e = $e.InnerException
            $msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
        }
        return $msg
    }
    End {
    }
}
#endregion

#region Helper Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Test-CommandExists
# Description....: Tests if a command exists
# Parameters.....: Command
# Return Values..: True / False
# =================================================================================================================================
Function Test-CommandExists {
    <# 
.SYNOPSIS 
	Tests if a command exists
.DESCRIPTION
	Tests if a command exists
.PARAMETER Command
	The command to test
#>
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {
        if (Get-Command $command) {
            RETURN $true
        }
    } Catch {
        Write-Host "$command does not exist"; RETURN $false
    } Finally {
        $ErrorActionPreference = $oldPreference
    }
} #end function test-CommandExists

# @FUNCTION@ ======================================================================================================================
# Name...........: ConvertTo-URL
# Description....: HTTP Encode test in URL
# Parameters.....: Text to encode
# Return Values..: Encoded HTML URL text
# =================================================================================================================================
Function Convert-ToURL($sText) {
    <#
.SYNOPSIS
	HTTP Encode test in URL
.DESCRIPTION
	HTTP Encode test in URL
.PARAMETER sText
	The text to encode
#>
    if ($sText.Trim() -ne "") {
        Write-LogMessage -type Verbose -Msg "Returning URL Encode of $sText"
        return [URI]::EscapeDataString($sText)
    } else {
        return $sText
    }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Convert-ToBool
# Description....: Converts text to Bool
# Parameters.....: Text
# Return Values..: Boolean value of the text
# =================================================================================================================================
Function Convert-ToBool {
    <#
.SYNOPSIS
	Converts text to Bool
.DESCRIPTION
	Converts text to Bool
.PARAMETER txt
	The text to convert to bool (True / False)
#>
    param (
        [string]$txt
    )
    $retBool = $false
	
    if ($txt -match "^y$|^yes$") {
        $retBool = $true 
    } elseif ($txt -match "^n$|^no$") {
        $retBool = $false 
    } else {
        [bool]::TryParse($txt, [ref]$retBool) | Out-Null 
    }
    
    return $retBool
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-TrimmedString
# Description....: Returns the trimmed text from a string
# Parameters.....: Text
# Return Values..: Trimmed text
# =================================================================================================================================
Function Get-TrimmedString($sText) {
    <# 
.SYNOPSIS 
	Returns the trimmed text from a string
.DESCRIPTION
	Returns the trimmed text from a string
.PARAMETER txt
	The text to handle
#>
    if ($null -ne $sText) {
        return $sText.Trim()
    }
    # Else
    return $sText
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Invoke-Rest
# Description....: Invoke REST Method
# Parameters.....: Command method, URI, Header, Body
# Return Values..: REST response
# =================================================================================================================================
Function Invoke-Rest {
    <# 
.SYNOPSIS 
	Invoke REST Method
.DESCRIPTION
	Invoke REST Method
.PARAMETER Command
	The REST Command method to run (GET, POST, PATCH, DELETE)
.PARAMETER URI
	The URI to use as REST API
.PARAMETER Header
	The Header as Dictionary object
.PARAMETER Body
	(Optional) The REST Body
.PARAMETER ErrAction
	(Optional) The Error Action to perform in case of error. By default "Continue"
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("GET", "POST", "DELETE", "PATCH", "PUT")]
        [String]$Command, 
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()] 
        [String]$URI, 
        [Parameter(Mandatory = $false)]
        $Header, 
        [Parameter(Mandatory = $false)]
        [String]$Body, 
        [Parameter(Mandatory = $false)]
        [ValidateSet("Continue", "Ignore", "Inquire", "SilentlyContinue", "Stop", "Suspend")]
        [String]$ErrAction = "Continue"
    )
	
    If ((Test-CommandExists Invoke-RestMethod) -eq $false) {
        Throw "This script requires PowerShell version 3 or above"
    }
    $restResponse = ""
    try {
        if ([string]::IsNullOrEmpty($Body)) {
            Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -TimeoutSec 2700"
            $restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -TimeoutSec 2700 -ErrorAction $ErrAction
        } else {
            Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body -TimeoutSec 2700"
            $restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body -TimeoutSec 2700 -ErrorAction $ErrAction
        }
    } catch [System.Net.WebException] {

        if ($ErrAction -match ("\bContinue\b|\bInquire\b|\bStop\b|\bSuspend\b")) {
            IF (![string]::IsNullOrEmpty($(($_.ErrorDetails.Message | ConvertFrom-Json).ErrorCode))) {
                If (($($_.ErrorDetails.Message | ConvertFrom-Json).ErrorCode -eq "ITATS127E")) {
                    
                    Write-LogMessage -Type Error -Msg "Was able to connect to the PVWA successfully, but the account was locked" 
                    Write-LogMessage -Type Error -Msg "URI:  $URI"
                    Throw [System.Management.Automation.RuntimeException] "Account Locked"
                } ElseIf (!($($_.ErrorDetails.Message | ConvertFrom-Json).ErrorCode -in $global:SkipErrorCode)) {
                    Write-LogMessage -Type Error -Msg "Was able to connect to the PVWA successfully, but the command resulted in a error"
                    Write-LogMessage -Type Error -Msg "URI:  $URI"
                    Write-LogMessage -Type Error -Msg "Command:  $Command"
                    Write-LogMessage -Type Error -Msg "Body:  $Body"
                    Write-LogMessage -Type Error -Msg "Returned ErrorCode: $(($_.ErrorDetails.Message|ConvertFrom-Json).ErrorCode)"
                    Write-LogMessage -Type Error -Msg "Returned ErrorMessage: $(($_.ErrorDetails.Message|ConvertFrom-Json).ErrorMessage)"
                }
            } Else {
                Write-LogMessage -Type Error -Msg "Error Message: $_"
                Write-LogMessage -Type Error -Msg "Exception Message: $($_.Exception.Message)"
                Write-LogMessage -Type Error -Msg "Status Code: $($_.Exception.Response.StatusCode.value__)"
                Write-LogMessage -Type Error -Msg "Status Description: $($_.Exception.Response.StatusDescription)"
               
            }
        }
        $restResponse = $null
    } catch { 
        Throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $_.Exception))
    }
    Write-LogMessage -Type Verbose -Msg "Invoke-REST Response: $restResponse"
    return $restResponse
}
If ((Test-CommandExists Invoke-RestMethod) -eq $false) {
    Write-LogMessage -Type Error -MSG "This script requires PowerShell version 3 or above"
    return
}

Function New-SearchCriteria {
    param ([string]$sURL, [string]$sSearch, [string]$sSortParam, [string]$sSafeName, [boolean]$startswith, [int]$iLimitPage, [int]$iOffsetPage = 0)
    [string]$retURL = $sURL
    $retURL += "?"
	
    if (![string]::IsNullOrEmpty($sSearch)) {
        Write-LogMessage -Type Debug -Msg "Search: $sSearch"
        $retURL += "search=$(Convert-ToURL $sSearch)&"
    }
    if (![string]::IsNullOrEmpty($sSafeName)) {
        Write-LogMessage -Type Debug -Msg "Safe: $sSafeName"
        $retURL += "filter=safename eq $(Convert-ToURL $sSafeName)&"
    }
    if (![string]::IsNullOrEmpty($sSortParam)) {
        Write-LogMessage -Type Debug -Msg "Sort: $sSortParam"
        $retURL += "sort=$(Convert-ToURL $sSortParam)&"

    }
    if ($startswith) {
        Write-LogMessage -Type Debug -Msg "startswith: $sSortParam"
        $retURL += "searchtype=startswith"
    }
    if ($iLimitPage -gt 0) {
        Write-LogMessage -Type Debug -Msg "Limit: $iLimitPage"
        $retURL += "limit=$iLimitPage&"
    }
		
    if ($retURL[-1] -eq '&') {
        $retURL = $retURL.substring(0, $retURL.length - 1) 
    }
    Write-LogMessage -Type Debug -Msg "URL: $retURL"
	
    return $retURL
}
Function Update-SearchCriteria {
    param (
        [string]$nextLinkURL,
        [int]$counter = 1,
        [int]$limit
    )

    # In order to get all the results, we need to increase the Limit
    $newNextLink = $nextLinkURL
    # First find the limit in the next link URL
    if ($nextLinkURL -match "(?:limit=)(\d{1,})") {
        $limitText = $Matches[0]
        $limitNumber = [int]$Matches[1]
        # Verify that we have an increased the limit
        if ($limitNumber -ge $limit) {
            $newNextLink = $nextLinkURL.Replace($limitText, "limit={0}" -f "1000")

        } else {
            Write-LogMessage -Type Debug -Msg "Limits are not correct. Next Link limit: $limitNumber; current limit: $limit; Next limit should be: $($limit * $counter)"
            # No change to the next link URL
        }
    }

    return $newNextLink
}

Function Get-AccountDetail {
    param (
        [Parameter(Mandatory = $false)]
        [string]$url = $global:PVWAURL,
        [Parameter(Mandatory = $true)]
        [string]$AccountID,
        [Parameter(Mandatory = $false)]
        [hashtable]$logonHeader = $g_LogonHeader
    )

    $URL_AccountsDetails = "$url/api/Accounts/$AccountID"

    return Invoke-Rest -Command Get -Uri $URL_AccountsDetails -Header $logonHeader 
}
Function Get-Accounts {
    param (
        [Parameter(Mandatory = $false)]
        [string]$url = $global:PVWAURL,
        [Parameter(Mandatory = $false)]
        [string]$Keywords,
        [Parameter(Mandatory = $false)]
        [string]$SortBy,
        [Parameter(Mandatory = $false)]
        [string]$SafeName,
        [Parameter(Mandatory = $false)]
        [string]$Limit,
        [Parameter(Mandatory = $false)]
        [boolean]$startswith,
        [Parameter(Mandatory = $false)]
        [hashtable]$logonHeader = $g_LogonHeader
    )
    Write-LogMessage -Type Debug -Msg "Retrieving accounts..."
			
    $URL_Accounts = "$URL/api/accounts/"

    try {
        $AccountsURLWithFilters = ""
        $AccountsURLWithFilters = $(New-SearchCriteria -sURL $URL_Accounts -sSearch $Keywords -sSortParam $SortBy -sSafeName $SafeName -iLimitPage $Limit -startswith $startswith)
        Write-LogMessage -Type Debug -Msg $AccountsURLWithFilters
    } catch {
        Write-LogMessage -Type Error -Msg $_.Exception
    }
    try {
        $GetAccountsResponse = Invoke-Rest -Command Get -Uri $AccountsURLWithFilters -Header $logonHeader
    } catch {
        Write-LogMessage -Type Error -Msg $_.Exception.Response.StatusDescription
    }
						
    $GetAccountsList = @()
    $counter = 1
    $GetAccountsList += $GetAccountsResponse.value
    Write-LogMessage -Type debug -Msg "Found $($GetAccountsList.count) accounts so far..."
    $nextLink = $("$URL/$($GetAccountsResponse.nextLink)")
    If (![string]::IsNullOrEmpty($GetAccountsResponse.nextLink)) {
        $nextLink = $("$URL/$($GetAccountsResponse.nextLink)")
        Write-LogMessage -Type Debug -Msg "Getting accounts next link: $nextLink"
    } else {
        $nextLink = $null
    }
    While (-not [string]::IsNullOrEmpty($nextLink)) {
        $GetAccountsResponse = Invoke-Rest -Command Get -Uri $nextLink -Header $logonHeader
        $GetAccountsList += $GetAccountsResponse.value
        Write-LogMessage -Type info -Msg "Found $($GetAccountsList.count) accounts so far..."
        # Increase the counter
        $counter++
        If (![string]::IsNullOrEmpty($GetAccountsResponse.nextLink)) {
            $nextLink = $("$URL/$($GetAccountsResponse.nextLink)")
            Write-LogMessage -Type Debug -Msg "Getting accounts next link: $nextLink"
        } else {
            $nextLink = $null
        }
    }
				
    Write-LogMessage -Type debug -Msg "Completed retriving $($GetAccountsList.count) accounts"
    $response = $GetAccountsList

    return $response
}

Function Set-SSLVerify {
    [Parameter(Mandatory = $false)]
    [switch]$DisableSSLVerify = $false

    If ($DisableSSLVerify) {
        try {
            Write-LogMessage -Type Warning -Msg "It is not Recommended to disable SSL verification" -WarningAction Inquire
            # Using Proxy Default credentials if the Server needs Proxy credentials
            [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
            # Using TLS 1.2 as security protocol verification
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
            # Disable SSL Verification
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
        } catch {
            Write-LogMessage -Type Error -MSG "Could not change SSL validation"
            Write-LogMessage -Type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
            return
        }
    } Else {
        try {
            Write-LogMessage -Type Debug -MSG "Setting script to use TLS 1.2"
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        } catch {
            Write-LogMessage -Type Error -MSG "Could not change SSL settings to use TLS 1.2"
            Write-LogMessage -Type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
        }
    }
}
Function Test-PVWA {
    param(
        [Parameter(Mandatory = $true)]
        [String]$PVWAURL
    )

    If (![string]::IsNullOrEmpty($PVWAURL)) {
        If ($PVWAURL.Substring($PVWAURL.Length - 1) -eq "/") {
            $PVWAURL = $PVWAURL.Substring(0, $PVWAURL.Length - 1)
        }
        try {
            # Validate PVWA URL is OK
            Write-LogMessage -Type Debug -MSG "Trying to validate URL: $PVWAURL"
            Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $PVWAURL -Method 'Head' -TimeoutSec 30 | Out-Null
        } catch [System.Net.WebException] {
            If (![string]::IsNullOrEmpty($_.Exception.Response.StatusCode.Value__)) {
                Write-LogMessage -Type Error -MSG "Received error $($_.Exception.Response.StatusCode.Value__) when trying to validate PVWA URL"
                Write-LogMessage -Type Error -MSG "Check your connection to PVWA and the PVWA URL"
                return
            }
        } catch {		
            Write-LogMessage -Type Error -MSG "PVWA URL could not be validated"
            Write-LogMessage -Type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
        }
        
    } else {
        Write-LogMessage -Type Error -MSG "PVWA URL can not be empty"
        return
    }
    
}
Function Invoke-Logon {
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials,
        [Parameter(Mandatory = $false)]

        [String]$url = $global:PVWAURL,
        [Parameter(Mandatory = $false)]
        [String]$AuthType = $global:AuthType

    )

    # Get Credentials to Login
    # ------------------------
    $caption = "Reset Remote Cred File Utility"
    $msg = "Enter your $AuthType User name and Password"; 
    if ($null -eq $Credentials) {
        $Credentials = $Host.UI.PromptForCredential($caption, $msg, "", "")
    }
    if ($null -ne $Credentials) {
        if ($AuthType -eq "radius" -and ![string]::IsNullOrEmpty($OTP)) {
            Set-Variable -Scope Global -Force -Name g_LogonHeader -Value $(Get-LogonHeader -Credentials $Credentials -AuthType $AuthType -RadiusOTP $OTP )
        } else {
            Set-Variable -Scope Global -Force -Name g_LogonHeader -Value $(Get-LogonHeader -Credentials $Credentials -AuthType $AuthType)

        }
        # Verify that we successfully logged on
        If ($null -eq $g_LogonHeader) { 
            return # No logon header, end script 
        }
    } else { 
        Write-LogMessage -Type Error -MSG "No Credentials were entered" -Footer
        return
    }
}

Function Get-Logon {
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials,
        [Parameter(Mandatory = $false)]
        [string]$url = $global:PVWAURL,
        [Parameter(Mandatory = $false)]
        [string]$AuthType = $global:AuthType,
        [Parameter(Mandatory = $false)]
        [string]$OTP

    )

    $URL_Logon = "$url/api/auth/$AuthType/Logon"
    # Get Credentials to Login
    # ------------------------
    $caption = "Reset Remote Cred File Utility"
    $msg = "Enter your $AuthType User name and Password"; 
    if ($null -eq $Credentials) {
        $Credentials = $Host.UI.PromptForCredential($caption, $msg, "", "")
    }
    if ($null -ne $Credentials) {
        if ($AuthType -eq "radius" -and ![string]::IsNullOrEmpty($OTP)) {
            return $(Get-LogonHeader -Credentials $Credentials -RadiusOTP $OTP -URL $URL_Logon)
        } else {
            return $(Get-LogonHeader -Credentials $Credentials -URL $URL_Logon)
        }
    } else { 
        Write-LogMessage -Type Error -MSG "No Credentials were entered" -Footer
        return
    }
}

Function Invoke-Logoff {
    param(
        [Parameter(Mandatory = $false)]
        [String]$url = $global:PVWAURL,
        [Parameter(Mandatory = $false)]
        [hashtable]$logonHeader = $global:g_LogonHeader
    )

    $URL_Logoff = $url + "/api/auth/Logoff"
    $null = Invoke-Rest -Uri $URL_Logoff -Header $logonHeader -Command "Post"
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-LogonHeader
# Description....: Invoke REST Method
# Parameters.....: Credentials
# Return Values..: Logon Header
# =================================================================================================================================
Function Get-LogonHeader {
    <# 
.SYNOPSIS 
	Get-LogonHeader
.DESCRIPTION
	Get-LogonHeader
.PARAMETER Credentials
	The REST API Credentials to authenticate
#>
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials,
        [Parameter(Mandatory = $false)]
        [string]$RadiusOTP,
        [Parameter(Mandatory = $false)]
        [string]$URL = $URL_Logon
    )

    # Create the POST Body for the Logon
    # ----------------------------------
    $logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password; concurrentSession = "true" } | ConvertTo-Json -Compress
    If (![string]::IsNullOrEmpty($RadiusOTP)) {
        $logonBody.Password += ",$RadiusOTP"
    }
    try {
        # Logon
        $logonToken = Invoke-Rest -Command Post -Uri $URL -Body $logonBody
        # Clear logon body
        $logonBody = ""
    } catch {
        $($_.Exception.Response.StatusDescription)
        $_.Exception
        Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.Exception.Response.StatusDescription)", $_.Exception))
    }
    $logonHeader = $null
    If ([string]::IsNullOrEmpty($logonToken)) {
        Throw "Get-LogonHeader: Logon Token is Empty - Cannot login"
    }
	
    # Create a Logon Token Header (This will be used through out all the script)
    # ---------------------------
    $logonHeader = @{Authorization = $logonToken }
    return $logonHeader
}
# @FUNCTION@ ======================================================================================================================
# Name...........: Get-LogonHeader
# Description....: Invoke REST Method
# Parameters.....: Credentials
# Return Values..: Logon Header
# =================================================================================================================================
Function Set-LogonHeader {
    <# 
.SYNOPSIS 
	Get-LogonHeader
.DESCRIPTION
	Get-LogonHeader
.PARAMETER Credentials
	The REST API Credentials to authenticate
#>
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials,
        [Parameter(Mandatory = $false)]
        [string]$RadiusOTP
    )
    # Create the POST Body for the Logon
    # ----------------------------------
    $logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password; concurrentSession = "true" } | ConvertTo-Json -Compress
    If (![string]::IsNullOrEmpty($RadiusOTP)) {
        $logonBody.Password += ",$RadiusOTP"
    }
    try {
        # Logon
        Write-Warning - $logonBody
        $logonToken = Invoke-Rest -Command Post -Uri $URL_Logon -Body $logonBody
        # Clear logon body
        $logonBody = ""
    } catch {
        Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.Exception.Response.StatusDescription)", $_.Exception))
    }
    $logonHeader = $null
    If ([string]::IsNullOrEmpty($logonToken)) {
        Throw "Get-LogonHeader: Logon Token is Empty - Cannot login"
    }
	
    # Create a Logon Token Header (This will be used through out all the script)
    # ---------------------------
    $logonHeader = @{Authorization = $logonToken }
    return $logonHeader
}
# @FUNCTION@ ======================================================================================================================
# Name...........: Set-SSLVerify
# Description....: Controls if SSL should be verified REST Method
# Parameters.....: Command method, URI, Header, Body
# Return Values..: REST response
# =================================================================================================================================
Function Set-DisableSSLVerify {
    <# 
.SYNOPSIS 
	Invoke REST Method
.DESCRIPTION
	Controls if SSL should be verified REST Method
.PARAMETER DisableSSLVerify
	Boolean to determine if SSL should be verified
.PARAMETER ErrAction
	(Optional) The Error Action to perform in case of error. By default "Continue"
#>

    [Parameter(Mandatory = $true)]
    [Switch]$DisableSSLVerify

    If ($DisableSSLVerify) {
        try {
            Write-LogMessage -Type Warning -Msg "It is not Recommended to disable SSL verification" -WarningAction Inquire
            # Using Proxy Default credentials if the Server needs Proxy credentials
            [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
            # Using TLS 1.2 as security protocol verification
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
            # Disable SSL Verification
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
        } catch {
            Write-LogMessage -Type Error -MSG "Could not change SSL validation"
            Write-LogMessage -Type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
            return
        }
    } Else {
        try {
            Write-LogMessage -type Verbose -MSG "Setting script to use TLS 1.2"
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        } catch {
            Write-LogMessage -Type Error -MSG "Could not change SSL settings to use TLS 1.2"
            Write-LogMessage -Type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
        }
    }
}
#endregion
# @FUNCTION@ ======================================================================================================================
# Name...........: Get-LogonTimeUnixTime
# Description....: Translates Unix time to readable time
# Parameters.....: Unixtime stamp
# Return Values..: Data/Time object
# =================================================================================================================================
Function Get-LogonTimeUnixTime {
    param (
        [Parameter()]
        [string]$unixTime
    )
    [datetime]$origin = '1970-01-01 00:00:00'
    return $origin.AddSeconds($unixTime).ToLocalTime()
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-FileVersion
# Description....: Method to return a file version
# Parameters.....: File Path
# Return Values..: File version
# =================================================================================================================================
Function Get-FileVersion {
    <#
.SYNOPSIS
	Method to return a file version
.DESCRIPTION
	Returns the File version and Build number
	Returns Null if not found
.PARAMETER FilePath
	The path to the file to query
#>
    param ($filePath)
    Begin {

    }
    Process {
        $retFileVersion = $Null
        try {
            If (($null -ne $filePath) -and (Test-Path $filePath)) {
                $path = Resolve-Path $filePath
                $retFileVersion = ($path | Get-Item | Select-Object VersionInfo).VersionInfo.ProductVersion
            } else {
                throw "File path is empty"
            }

            return $retFileVersion
        } catch {
            Throw $(New-Object System.Exception ("Cannot get File ($filePath) version", $_.Exception))
        } finally {

        }
    }
    End {

    }
}
# Function for colorized Write-Output
function Use-Color ($fc) {
    process {
        Write-Host $_ -ForegroundColor $fc 
    }
}
Function Set-UserPassword {
    <# 
.SYNOPSIS 
	Get-LogonHeader
.DESCRIPTION
	Get-LogonHeader
.PARAMETER Credentials
	The REST API Credentials to authenticate
#>
    param(
        [Parameter(Mandatory = $true)]
        [String]$Username,
        [Parameter(Mandatory = $true)]
        [SecureString]$Password
    )
    Process {
        Write-LogMessage -type Verbose -MSG "URL for PVWA: $PVWAURL"
        Write-LogMessage -type Verbose -MSG "URL for PVWA API: $URL_PVWAAPI"
        $urlSearch = $Script:URL_UserSearch -f $Username
        Write-LogMessage -type Verbose -MSG "URL for user search: $urlSearch"
        $searchResult = $(Invoke-Rest -Uri $urlSearch -Header $g_LogonHeader -Command "Get")
        if ($searchResult.Total -gt 0) {
            $userFound = $false
            foreach ($account in $searchResult.users) {
                if ($account.username -ieq $Username -and $account.componentUser) {
                    try {       
                        $userFound = $true
                        $accountID = $account.id
                        
                        $bodyActivate = @{id = $accountID } | ConvertTo-Json -Depth 3 -Compress
                        $urlActivate = $Script:URL_Activate -f $accountID
                        $null = Invoke-Rest -Uri $urlActivate -Header $g_LogonHeader -Command "Post" -Body $bodyActivate

                        $bodyReset = @{ id = $accountID; newPassword = $(Convert-SecureString($Password)) } | ConvertTo-Json -Depth 3 -Compress
                        $urlReset = $Script:URL_UserResetPassword -f $accountID
                        $null = Invoke-Rest -Uri $urlReset -Header $g_LogonHeader -Command "Post" -Body $bodyReset
                    } catch {
                        Throw $_   
                    }
                }
            }
            If (!$userFound) {
                Write-LogMessage -type Verbose -MSG "Unable to locate component account for $Username"
            }
        } else {
            Write-LogMessage -type Verbose -MSG "Unable to locate component account for $Username"
        } 
    }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: New-RandomPassword
# Description....: Creates a new random password
# Parameters.....: Length, (Switch)Lowercase, (Switch)Uppercase, (Switch)Numbers, (Switch)Symbols
# Return Values..: A random password based on the requirements
# =================================================================================================================================
Function New-RandomPassword {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # Length, Type uint32, Length of the random string to create.
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidatePattern('[0-9]+')]
        [ValidateRange(1, 100)]
        [uint32]$Length,

        # Lowercase, Type switch, Use lowercase characters.
        [Parameter(Mandatory = $false)]
        [switch]$Lowercase = $false,
        
        # Uppercase, Type switch, Use uppercase characters.
        [Parameter(Mandatory = $false)]
        [switch]$Uppercase = $false,

        # Numbers, Type switch, Use alphanumeric characters.
        [Parameter(Mandatory = $false)]
        [switch]$Numbers = $false,

        # Symbols, Type switch, Use symbol characters.
        [Parameter(Mandatory = $false)]
        [switch]$Symbols = $false
    )
    Begin {
        if (-not($Lowercase -or $Uppercase -or $Numbers -or $Symbols)) {
            throw "You must specify one of: -Lowercase -Uppercase -Numbers -Symbols"
        }

        # Specifies bitmap values for character sets selected.
        $CHARSET_LOWER = 1
        $CHARSET_UPPER = 2
        $CHARSET_NUMBER = 4
        $CHARSET_SYMBOL = 8

        # Creates character arrays for the different character classes, based on ASCII character values.
        $charsLower = 97..122 | ForEach-Object { [Char] $_ }
        $charsUpper = 65..90 | ForEach-Object { [Char] $_ }
        $charsNumber = 48..57 | ForEach-Object { [Char] $_ }
        $charsSymbol = 33, 35, 37, 42, 43, 44, 45, 46, 95 | ForEach-Object { [Char] $_ }

        Write-LogMessage -type Verbose -MSG "The following symbols may be selected $charSymbol"
        
    }
    Process {
        # Contains the array of characters to use.
        $charList = @()
        $charSets = 0
        if ($Lowercase) {
            $charList += $charsLower
            $charSets = $charSets -bor $CHARSET_LOWER
        }
        if ($Uppercase) {
            $charList += $charsUpper
            $charSets = $charSets -bor $CHARSET_UPPER
        }
        if ($Numbers) {
            $charList += $charsNumber
            $charSets = $charSets -bor $CHARSET_NUMBER
        }
        if ($Symbols) {
            $charList += $charsSymbol
            $charSets = $charSets -bor $CHARSET_SYMBOL
        }

        <#
        .SYNOPSIS
            Test string for existence specified character.
        .DESCRIPTION
            examine each character of a string to determine if it contains a specified characters
        .EXAMPLE
            Test-StringContents in string
        #>
        function Test-StringContents([String] $test, [Char[]] $chars) {
            foreach ($char in $test.ToCharArray()) {
                if ($chars -ccontains $char) {
                    return $true 
                }
            }
            return $false
        }

        do {
            # No character classes matched yet.
            $flags = 0
            $output = ""
            # Create output string containing random characters.
            1..$Length | ForEach-Object { $output += $charList[(Get-Random -Maximum $charList.Length)] }

            # Check if character classes match.
            if ($Lowercase) {
                if (Test-StringContents $output $charsLower) {
                    $flags = $flags -bor $CHARSET_LOWER
                }
            }
            if ($Uppercase) {
                if (Test-StringContents $output $charsUpper) {
                    $flags = $flags -bor $CHARSET_UPPER
                }
            }
            if ($Numbers) {
                if (Test-StringContents $output $charsNumber) {
                    $flags = $flags -bor $CHARSET_NUMBER
                }
            }
            if ($Symbols) {
                if (Test-StringContents $output $charsSymbol) {
                    $flags = $flags -bor $CHARSET_SYMBOL
                }
            }
        }
        until ($flags -eq $charSets)
    }
    End {   
        $output
    }
}



Function Format-URL($sText) {
    if ($sText.Trim() -ne "") {
        Write-LogMessage -Type Debug -Msg "Returning URL Encode of $sText"
        return [System.Web.HttpUtility]::UrlEncode($sText.Trim())
    } else {
        return ""
    }
}

Function Get-Secret {
    [OutputType([SecureString])]
    Param
    (
        [Parameter(Mandatory = $false)]
        [string]$url = $global:PVWAURL,
        [Parameter(Mandatory = $false)]
        [String]$ID,
        [Parameter(Mandatory = $false)]
        [hashtable]$logonHeader = $g_LogonHeader

    )


    $URL_GetSecret = "$url/api/Accounts/$id/Password/Retrieve" 

    $SecretBody = @{reason = "Pulled for comparison via REST" } | ConvertTo-Json -Compress
    try {
        $secret = Invoke-Rest -Command Post -Uri $URL_GetSecret -Body $SecretBody -header $logonHeader
        If (![string]::IsNullOrEmpty($secret)) {
            $secureSecret = ConvertTo-SecureString $secret -AsPlainText -Force
            Remove-Variable secret
            return $secureSecret
        } else {
            return $null
        }
    } catch [System.Management.Automation.RuntimeException] {
        If ("Account Locked" -eq $_.Exception.Message) {
            Throw "Account Locked"
        }
    }
}

Function Compare-SecureString {

    Param
    (
        [Parameter(Mandatory = $true)]
        [SecureString]$pwd1,
        [Parameter(Mandatory = $true)]
        [SecureString]$pwd2

    )

    return ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd1)) -ceq [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd2)))
}

Function Set-Secret {

    Param
    (
        [Parameter(Mandatory = $false)]
        [string]$url = $global:PVWAURL,
        [Parameter(Mandatory = $false)]
        [String]$ID,
        [Parameter(Mandatory = $false)]
        [hashtable]$logonHeader = $g_LogonHeader,
        [Parameter(Mandatory = $false)]
        [SecureString]$secret
    )
    
    $URL_SetSecret = "$url/api/Accounts/$id/Password/Update" 
    
    Invoke-Rest -Command Post -Uri $URL_SetSecret -Body $(@{NewCredentials = $([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret))) } | ConvertTo-Json -Compress) -header $logonHeader
}

Function Set-NextPassword {

    Param
    (
        [Parameter(Mandatory = $false)]
        [string]$url = $global:PVWAURL,
        [Parameter(Mandatory = $false)]
        [String]$ID,
        [Parameter(Mandatory = $false)]
        [hashtable]$logonHeader = $g_LogonHeader,
        [Parameter(Mandatory = $false)]
        [SecureString]$secret
    )
    
    $URL_SetSecret = "$url/api/Accounts/$id/SetNextPassword/" 
    
    Invoke-Rest -Command Post -Uri $URL_SetSecret -Body $(@{ChangeImmediately = "true";NewCredentials = $([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret))) } | ConvertTo-Json -Compress) -header $logonHeader
}

Function New-Account {
    Param
    (
        [Parameter(Mandatory = $false)]
        [string]$url = $global:PVWAURL,
        [Parameter(Mandatory = $false)]
        [hashtable]$logonHeader = $g_LogonHeader,
        [Parameter(Mandatory = $true)]
        $account,
        [Parameter(Mandatory = $true)]
        [SecureString]$secret
    )
    $URL_NewAccount = "$url/api/Accounts/"
    $account | Add-Member -NotePropertyName secret -NotePropertyValue ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)))
    
    return Invoke-Rest -Command Post -Uri $URL_NewAccount -header $logonHeader -Body $($account | ConvertTo-Json -Compress)
    
}

Function Get-Safe {
    Param
    (
        [Parameter(Mandatory = $false)]
        [string]$url = $global:PVWAURL,
        [Parameter(Mandatory = $false)]
        [hashtable]$logonHeader = $g_LogonHeader,
        [Parameter(Mandatory = $true)]
        $safe
    )

    $URL_GetSafe = "$url/api/Safes/$safe"
    
    return Invoke-Rest -Command Get -Uri $URL_GetSafe -header $logonHeader
}

Function Get-SafeMembers {
    Param
    (
        [Parameter(Mandatory = $false)]
        [string]$url = $global:PVWAURL,
        [Parameter(Mandatory = $false)]
        [hashtable]$logonHeader = $g_LogonHeader,
        [Parameter(Mandatory = $true)]
        $safe
    )

    $URL_GetSafeMembers = "$url/api/Safes/$safe/Members"
    
    return Invoke-Rest -Command GET -Uri $URL_GetSafeMembers -header $logonHeader
}

Function New-Safe {
    Param
    (
        [Parameter(Mandatory = $false)]
        [string]$url = $global:PVWAURL,
        [Parameter(Mandatory = $false)]
        [hashtable]$logonHeader = $g_LogonHeader,
        [Parameter(Mandatory = $true)]
        $safe,
        [Parameter(Mandatory = $false)]
        [string]$cpnNameOld,
        [Parameter(Mandatory = $false)]
        [string]$cpnNameNew
    )
    $URL_NewSafe = "$url/api/Safes/"

    $safe = $safe | Select-Object -Property numberOfDaysRetention, numberOfVersionsRetention, oLACEnabled, autoPurgeEnabled, managingCPM, safeName, description, location

    If ((![string]::IsNullOrEmpty($cpnNameOld)) -and (![string]::IsNullOrEmpty($cpnNameNew))) {
        return Invoke-Rest -Command Post -Uri $URL_NewSafe -header $logonHeader -Body $($safe | ConvertTo-Json -Compress).replace($cpnNameOld, $cpnNameNew)
    } else {
        return Invoke-Rest -Command Post -Uri $URL_NewSafe -header $logonHeader -Body $($safe | ConvertTo-Json -Compress)
    }
}

Function New-SafeMember {
    Param
    (
        [Parameter(Mandatory = $false)]
        [string]$url = $global:PVWAURL,
        [Parameter(Mandatory = $false)]
        [hashtable]$logonHeader = $g_LogonHeader,
        [Parameter(Mandatory = $true)]
        $safe,
        [Parameter(Mandatory = $true)]
        $safeMember,
        [Parameter(Mandatory = $false)]
        $newLDAP
    )
    $URL_SafeMembers = "$url/api/Safes/$safe/Members"
    
    if($safeMember.searchIn -eq "LDAP") {
        $safeMember.searchIn = $newLDAP
    }

    $safeMember = $safeMember | Select-Object -Property memberName, searchIn, membershipExpirationDate, permissions
    
    return Invoke-Rest -Command Post -Uri $URL_SafeMembers -header $logonHeader -Body $($safeMember | ConvertTo-Json -Compress)
    
}
Function Get-UserSource {
    Param
    (
        [Parameter(Mandatory = $false)]
        [string]$url = $global:PVWAURL,
        [Parameter(Mandatory = $false)]
        [hashtable]$logonHeader = $g_LogonHeader,
        [Parameter(Mandatory = $true)]
        $safeMember
    )

    $URL_UserDetail = "$url/api/Users/$($safeMember.memberId)"
    Write-LogMessage -Type Debug -Msg "Getting member source: $URL_UserDetail"
    Write-LogMessage -Type Debug -Msg "Using Member: $safeMember"

    $user = Invoke-Rest -Command GET -Uri $URL_UserDetail -header $logonHeader
    if ($user.source -eq "Cyberark"){
        return "vault"
    } else {
        return $user.source
    }
    
}

Function Get-GroupSource {
    Param
    (
        [Parameter(Mandatory = $false)]
        [string]$url = $global:PVWAURL,
        [Parameter(Mandatory = $false)]
        [hashtable]$logonHeader = $g_LogonHeader,
        [Parameter(Mandatory = $true)]
        $safeMember
    )

    $URL_Groups = "$url/api/UserGroups?search=$($safeMember.memberName)"
    Write-LogMessage -Type Debug -Msg "Getting member source: $URL_Groups"
    Write-LogMessage -Type Debug -Msg "Using Member: $safeMember"

    $groups = Invoke-Rest -Command GET -Uri $URL_Groups -header $logonHeader

    foreach ($group in $groups.value) {
        if ($safeMember.memberName -eq $group.groupName) {
            if ([string]::IsNullOrEmpty($group.directory)){
                return "vault"
            } else{
                return $group.directory
            }
        }
    }
}
Function Update-SafeMember {
    Param
    (
        [Parameter(Mandatory = $false)]
        [string]$url = $global:PVWAURL,
        [Parameter(Mandatory = $false)]
        [hashtable]$logonHeader = $g_LogonHeader,
        [Parameter(Mandatory = $true)]
        $safe,
        [Parameter(Mandatory = $true)]
        $safeMember,
        [Parameter(Mandatory = $false)]
        $newLDAP
    )
    $URL_SafeMembers = "$url/api/Safes/$safe/Members/$($safeMember.memberName)"
    
    Write-LogMessage -Type Debug -Msg "Updating Safe Member: $safeMember"

    $safeMember = $safeMember | Select-Object -Property memberName, searchIn, membershipExpirationDate, permissions

    return Invoke-Rest -Command PUT -Uri $URL_SafeMembers -header $logonHeader -Body $($safeMember | ConvertTo-Json -Compress)

    
}

Function Update-RemoteMachine {
    Param
    (
        [Parameter(Mandatory = $false)]
        [string]$url = $global:PVWAURL,
        [Parameter(Mandatory = $false)]
        [hashtable]$logonHeader = $g_LogonHeader,
        [Parameter(Mandatory = $true)]
        $dstaccount,
        [Parameter(Mandatory = $true)]
        $srcaccount
    )
    $d_AccountBody = @()

    $URL_AccountsDetails = "$url/api/Accounts/$($dstAccount.id)"

    $_bodyOpRest = "" | Select-Object "op", "path", "value"

    if ([string]::IsNullOrEmpty($($srcAccount.remoteMachinesAccess.remoteMachines))) {
        Write-LogMessage -Type Debug -Msg "Source account has no value set for `"Limit Domain Access To`", Removing destination values"
        $op = "Remove"
        $_bodyOpMachine = "" | Select-Object "op", "path"
    } elseif (($($srcAccount.remoteMachinesAccess.remoteMachines) -eq $($dstAccount.remoteMachinesAccess.remoteMachines)) -and ($($srcAccount.remoteMachinesAccess.accessRestrictedToRemoteMachines) -eq $($dstAccount.remoteMachinesAccess.accessRestrictedToRemoteMachines)) ) {
        Write-LogMessage -Type Debug -Msg "`"Limit Domain Access To`" and '`"Allow User Connections to Other Machines`"is equal, no update required"
        return
    } elseif ([string]::IsNullOrEmpty($($dstAccount.remoteMachinesAccess.remoteMachines))) {
        Write-LogMessage -Type Debug -Msg "Destination account has no value set for `"Limit Domain Access To`", setting operation to ADD"
        $op = "Add"
        $_bodyOpMachine = "" | Select-Object "op", "path", "value"
    } else {
        Write-LogMessage -Type Debug -Msg "Destination account has value set for `"Limit Domain Access To`", setting operation to REPLACE"
        $op = "Replace"
        $_bodyOpMachine = "" | Select-Object "op", "path", "value"
    }

    $_bodyOpRest.op = $op
    $_bodyOpRest.path = "/remoteMachinesAccess/accessRestrictedToRemoteMachines"
    if ($op -ne "Remove") {
        $_bodyOpRest.value = $srcAccount.remoteMachinesAccess.accessRestrictedToRemoteMachines

    } Else {

        $_bodyOpRest.op = "Replace"
        $_bodyOpRest.value = "false"
    }
    $d_AccountBody += $_bodyOpRest

    $_bodyOpMachine.op = $op
    $_bodyOpMachine.path = "/remoteMachinesAccess/remoteMachines"
    if ($op -ne "Remove") {
        $_bodyOpMachine.value = $srcAccount.remoteMachinesAccess.remoteMachines
    }
    $d_AccountBody += $_bodyOpMachine


    $restBody = ConvertTo-Json $d_AccountBody -Depth 5 -Compress
    $urlUpdateAccount = $URL_AccountsDetails
    $UpdateAccountResult = $(Invoke-Rest -Uri $urlUpdateAccount -Header $logonHeader -Body $restBody -Command "PATCH")
    if ($null -ne $UpdateAccountResult) {
        Write-LogMessage -Type Debug -MSG "Account with Username `"$($dstaccount.userName)`" at address of `"$($dstaccount.address)`" in safe `"$($dstaccount.safeName)`" properties updated successfully"
    }
}

