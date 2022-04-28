<# 
###########################################################################
NAME: 
    CyberArk-Common.psm1 
AUTHOR:  
    Brian Bors <brian.bors@cyberark.com>
COMMENT: 
    Module used by other CyberArk scripts
Version: 
    0.1
Change Log:
    2020-09-13 
        Initial Version
########################################################################### 
#>


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

$URL_HealthSummery = $URL_PVWAAPI + "/ComponentsMonitoringSummary"
$URL_HealthDetails = $URL_PVWAAPI + "/ComponentsMonitoringDetails/{0}"

$g_cpmservices = @("CyberArk Password Manager", "CyberArk Central Policy Manager Scanner")
$g_pvwaservices = @("CyberArk Scheduled Tasks", "W3SVC", "IISADMIN")
$g_psmservices = @("Cyber-Ark Privileged Session Manager")
$g_aamservices = @("CyberArk Application Password Provider")

#Commands to reset PVWA credential files
$g_pvwagwuserCredv12 = ".\CreateCredFile.exe ..\CredFiles\gwuser.ini Password /Username {0} /AppType PVWAApp /IpAddress /Hostname /ExePath `"C:\Windows\System32\inetsrv\w3wp.exe`" /EntropyFile /DPAPIMachineProtection /Password {1}"
$g_pvwaappuserCredv12 = ".\CreateCredFile.exe ..\CredFiles\appuser.ini Password /Username {0} /AppType PVWAApp /IpAddress /Hostname /ExePath `"C:\Windows\System32\inetsrv\w3wp.exe`" /EntropyFile /DPAPIMachineProtection /Password {1}"

$g_pvwagwuserCred = ".\CreateCredFile.exe ..\CredFiles\gwuser.ini Password /Username {0} /AppType PVWAApp /IpAddress /Hostname /ExePath `"C:\Windows\System32\inetsrv\w3wp.exe`" /Password {1}"
$g_pvwaappuserCred = ".\CreateCredFile.exe ..\CredFiles\appuser.ini Password /Username {0} /AppType PVWAApp /IpAddress /Hostname /ExePath `"C:\Windows\System32\inetsrv\w3wp.exe`" /Password {1}"

#commands to reset PSM credential files
$g_psmappuserCredv12 = ".\CreateCredFile.exe psmapp.cred Password /Username {0} /AppType PSMApp  /EntropyFile /DPAPIMachineProtection /IpAddress /Hostname /Password {1}"
$g_psmgwuserCredv12 = ".\CreateCredFile.exe psmgw.cred Password /Username {0} /AppType PSMApp  /EntropyFile /DPAPIMachineProtection /IpAddress /Hostname /Password {1}"

$g_psmappuserCred = ".\CreateCredFile.exe psmapp.cred Password /Username {0} /AppType PSMApp /IpAddress /Hostname /Password {1}"
$g_psmgwuserCred = ".\CreateCredFile.exe psmgw.cred Password /Username {0} /AppType PSMApp /IpAddress /Hostname /Password {1}"

#commands to reset CPM credential files
$g_cpmuserCredv12 = ".\CreateCredFile.exe user.ini Password /Username {0} /AppType CPM /EntropyFile /DPAPIMachineProtection /IpAddress /Hostname /Password {1}"

$g_cpmuserCred = ".\CreateCredFile.exe user.ini Password /Username {0} /AppType CPM /IpAddress /Hostname /Password {1}"

#commands to reset AAM credential files
$g_aamuserwinCredv12 = ".\CreateCredFile.exe AppProviderUser.cred Password /Username {0} /AppType AppPrv /IpAddress /Hostname /EntropyFile /DPAPIMachineProtection /Password {1}"

$g_aamuserwinCred = ".\CreateCredFile.exe AppProviderUser.cred Password /Username {0} /AppType AppPrv /IpAddress /Hostname /Password {1}"

#vault.ini locations
$g_aamvault = "\vault\vault.ini"
$g_cpmvault = ".\vault.ini"
$g_psmvault = ".\vault.ini"
$g_pvwavault = ".\vault.ini"

$g_prePSSession = { $env:PSModulePath = "C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules;" }

if ($InVerbose) {
    $VerbosePreference = "continue"
}

Write-Verbose  "Version of CyberArk-Common.psm1 : Fix branch v1.0"

#endregion

# Initialize Script Variables
# ---------------------------


Function Write-LogMessage {
    # @FUNCTION@ ======================================================================================================================
    # Name...........: Write-LogMessage
    # Description....: Writes the message to log and screen
    # Parameters.....: LogFile, MSG, (Switch)Header, (Switch)SubHeader, (Switch)Footer, Type
    # Return Values..: None
    # =================================================================================================================================

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
        }
        ElseIf ($SubHeader -and $WriteLog) { 
            "------------------------------------" | Out-File -Append -FilePath $LogFile 
            Write-Host "------------------------------------" -ForegroundColor Magenta
        }
		
        # Replace empty message with 'N/A'
        if ([string]::IsNullOrEmpty($Msg)) {
            $Msg = "N/A" 
        }
        $msgToWrite = ""
		
        # Mask Passwords
        if ($Msg -match '((?:password|credentials|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()-_\=\+\\\/|;:\.,\[\]{}]+))') {
            $Msg = $Msg.Replace($Matches[2], "****")
        }
        # Check the message type
        switch ($type) {
            { ($_ -eq "Info") -or ($_ -eq "LogOnly") } { 
                If ($_ -eq "Info") {
                    Write-Host $MSG.ToString() -ForegroundColor $(If ($Header -or $SubHeader) {
                            "Magenta" 
                        }
                        Else {
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
                    Write-Debug $MSG
                    $msgToWrite = "[Debug]`t$Msg"
                }
                break
            }
            "Verbose" { 
                if ($InVerbose) {
                    Write-Verbose $MSG
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
    }
    catch {
        Throw $(New-Object System.Exception ("Cannot write message"), $_.Exception)
    }
}

Function Join-ExceptionMessage {
    # @FUNCTION@ ======================================================================================================================
    # Name...........: Join-ExceptionMessage
    # Description....: Formats exception messages
    # Parameters.....: Exception
    # Return Values..: Formatted String of Exception messages
    # =================================================================================================================================

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
Function Test-CommandExists {
    # @FUNCTION@ ======================================================================================================================
    # Name...........: Test-CommandExists
    # Description....: Tests if a command exists
    # Parameters.....: Command
    # Return Values..: True / False
    # =================================================================================================================================
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
    }
    Catch {
        Write-Host "$command does not exist"; RETURN $false
    }
    Finally {
        $ErrorActionPreference = $oldPreference
    }
} #end function test-CommandExists

Function ConvertTo-URL($sText) {
    # @FUNCTION@ ======================================================================================================================
    # Name...........: ConvertTo-URL
    # Description....: HTTP Encode test in URL
    # Parameters.....: Text to encode
    # Return Values..: Encoded HTML URL text
    # =================================================================================================================================

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
    }
    else {
        return $sText
    }
}

Function Convert-ToBool {
    # @FUNCTION@ ======================================================================================================================
    # Name...........: Convert-ToBool
    # Description....: Converts text to Bool
    # Parameters.....: Text
    # Return Values..: Boolean value of the text
    # =================================================================================================================================
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
    }
    elseif ($txt -match "^n$|^no$") {
        $retBool = $false 
    }
    else {
        [bool]::TryParse($txt, [ref]$retBool) | Out-Null 
    }
    
    return $retBool
}

Function Get-TrimmedString($sText) {
    # @FUNCTION@ ======================================================================================================================
    # Name...........: Get-TrimmedString
    # Description....: Returns the trimmed text from a string
    # Parameters.....: Text
    # Return Values..: Trimmed text
    # =================================================================================================================================
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

Function Invoke-Rest {
    # @FUNCTION@ ======================================================================================================================
    # Name...........: Invoke-Rest
    # Description....: Invoke REST Method
    # Parameters.....: Command method, URI, Header, Body
    # Return Values..: REST response
    # =================================================================================================================================

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
        [ValidateSet("GET", "POST", "DELETE", "PATCH")]
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
        }
        else {
            Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body -TimeoutSec 2700"
            $restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body -TimeoutSec 2700 -ErrorAction $ErrAction
        }
    }
    catch [System.Net.WebException] {
        if ($ErrAction -match ("\bContinue\b|\bInquire\b|\bStop\b|\bSuspend\b")) {
            Write-LogMessage -Type Error -Msg "Error Message: $_"
            Write-LogMessage -Type Error -Msg "Exception Message: $($_.Exception.Message)"
            Write-LogMessage -Type Error -Msg "Status Code: $($_.Exception.Response.StatusCode.value__)"
            Write-LogMessage -Type Error -Msg "Status Description: $($_.Exception.Response.StatusDescription)"
        }
        $restResponse = $null
    }
    catch { 
        Throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $_.Exception))
    }
    Write-LogMessage -Type Verbose -Msg "Invoke-REST Response: $restResponse"
    return $restResponse
}
If ((Test-CommandExists Invoke-RestMethod) -eq $false) {
    Write-LogMessage -Type Error -MSG "This script requires PowerShell version 3 or above"
    return
}
Function Set-PSSessionCred {
    param(
        [Parameter(Mandatory = $false)]
        [PSCredential]$PSCredentials
    )
    if ($null -eq $PSCredentials) {
        $PSCredentials = $Host.UI.PromptForCredential($caption, $msg, "", "")
    }
}
Function Set-PSSessionCred {

    param(
        [Parameter(Mandatory = $false)]
        [PSCredential]$PSCredentials

    )
    if ($null -eq $PSCredentials) {
        $PSCredentials = $Host.UI.PromptForCredential($caption, $msg, "", "")
    }
}

Function Invoke-Logon {
    param(
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credentials
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
            Set-Variable -Scope Global -Force -Name g_LogonHeader -Value $(Get-LogonHeader -Credentials $Credentials -RadiusOTP $OTP)
        }
        else {
            Set-Variable -Scope Global -Force -Name g_LogonHeader -Value $(Get-LogonHeader -Credentials $Credentials)
        }
        # Verify that we successfully logged on
        If ($null -eq $g_LogonHeader) { 
            return # No logon header, end script 
        }
    }
    else { 
        Write-LogMessage -Type Error -MSG "No Credentials were entered" -Footer
        return
    }
}
Function Get-LogonHeader {
    # @FUNCTION@ ======================================================================================================================
    # Name...........: Get-LogonHeader
    # Description....: Invoke REST Method
    # Parameters.....: Credentials
    # Return Values..: Logon Header
    # =================================================================================================================================
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
        $logonToken = Invoke-Rest -Command Post -Uri $URL_Logon -Body $logonBody
        # Clear logon body
        $logonBody = ""
    }
    catch {
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

Function Set-DisableSSLVerify {
    # @FUNCTION@ ======================================================================================================================
    # Name...........: Set-SSLVerify
    # Description....: Controls if SSL should be verified REST Method
    # Parameters.....: Command method, URI, Header, Body
    # Return Values..: REST response
    # =================================================================================================================================

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
            Write-Warning "It is not Recommended to disable SSL verification" -WarningAction Inquire
            # Using Proxy Default credentials if the Server needs Proxy credentials
            [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
            # Using TLS 1.2 as security protocol verification
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
            # Disable SSL Verification
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
        }
        catch {
            Write-LogMessage -Type Error -MSG "Could not change SSL validation"
            Write-LogMessage -Type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
            return
        }
    }
    Else {
        try {
            Write-LogMessage -type Verbose -MSG "Setting script to use TLS 1.2"
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        }
        catch {
            Write-LogMessage -Type Error -MSG "Could not change SSL settings to use TLS 1.2"
            Write-LogMessage -Type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
        }
    }
}
#endregion
Function Get-LogonTimeUnixTime {
    # @FUNCTION@ ======================================================================================================================
    # Name...........: Get-LogonTimeUnixTime
    # Description....: Translates Unix time to readable time
    # Parameters.....: Unixtime stamp
    # Return Values..: Data/Time object
    # =================================================================================================================================

    param (
        [Parameter()]
        [string]$unixTime
    )
    [datetime]$origin = '1970-01-01 00:00:00'
    return $origin.AddSeconds($unixTime).ToLocalTime()
}

Function Get-FileVersion {
    # @FUNCTION@ ======================================================================================================================
    # Name...........: Get-FileVersion
    # Description....: Method to return a file version
    # Parameters.....: File Path
    # Return Values..: File version
    # =================================================================================================================================

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
            }
            else {
                throw "File path is empty"
            }

            return $retFileVersion
        }
        catch {
            Throw $(New-Object System.Exception ("Cannot get File ($filePath) version", $_.Exception))
        }
        finally {

        }
    }
    End {

    }
}
function Import-ModuleRemotely([string] $moduleName, [System.Management.Automation.Runspaces.PSSession] $session) {
    $localModule = Get-Module $moduleName;
    if (! $localModule) { 
        Write-Warning "No local module by that name exists"; 
        return; 
    }
    function Exports([string] $paramName, $dictionary) { 
        if ($dictionary.Keys.Count -gt 0) {
            $keys = $dictionary.Keys -join ",";
            return " -$paramName $keys"
        }
    }
    $fns = Exports "Function" $localModule.ExportedFunctions;
    $aliases = Exports "Alias" $localModule.ExportedAliases;
    $cmdlets = Exports "Cmdlet" $localModule.ExportedCmdlets;
    $vars = Exports "Variable" $localModule.ExportedVariables;
    $exports = "Export-ModuleMember $fns $aliases $cmdlets $vars;";

    $moduleString = @"
if (get-module $moduleName)
{
    remove-module $moduleName;
}
New-Module -name $moduleName {
$($localModule.Definition)
$exports;
}  | import-module
"@
    $script = [ScriptBlock]::Create($moduleString);
    Invoke-Command -Session $session -ScriptBlock $script;
}

Function Invoke-Logoff {
    $null = Invoke-Rest -Uri $URL_Logoff -Header $g_LogonHeader -Command "Post"
}
Function Get-ServiceInstallPath {
    # @FUNCTION@ ======================================================================================================================
    # Name...........: Get-ServiceInstallPath
    # Description....: Get the installation path of a service
    # Parameters.....: Service Name
    # Return Values..: $true
    #                  $false
    # =================================================================================================================================
    # Save the Services List
    <#
  .SYNOPSIS
  Get the installation path of a service
  .DESCRIPTION
  The function receive the service name and return the path or returns NULL if not found
  .EXAMPLE
  (Get-ServiceInstallPath $<ServiceName>) -ne $NULL
  .PARAMETER ServiceName
  The service name to query. Just one.
 #>
    param ($ServiceName)
    Begin {

    }
    Process {
        $retInstallPath = $Null
        try {
            if ($null -eq $m_ServiceList) {
                Set-Variable -Name m_ServiceList -Value $(Get-ChildItem "HKLM:\System\CurrentControlSet\Services" | ForEach-Object { Get-ItemProperty $_.pspath }) -Scope Script
                Write-LogMessage -Type "Verbose" -MSG "Service $ServiceName has a registry path of $m_ServiceList"
            }
            $regPath = $m_ServiceList | Where-Object { $_.PSChildName -eq $ServiceName }
            If ($Null -ne $regPath) {
                $retInstallPath = $regPath.ImagePath.Substring($regPath.ImagePath.IndexOf('"'), $regPath.ImagePath.LastIndexOf('"') + 1)
                Write-LogMessage -Type "Verbose" -MSG "Service $ServiceName has a installation location of $retInstallPath"
            }
        }
        catch {
            Throw $(New-Object System.Exception ("Cannot get Service Install path for $ServiceName", $_.Exception))
        }
        return $retInstallPath
    }
    End {

    }
}
Function Find-WinComponents {
    # @FUNCTION@ ======================================================================================================================
    # Name...........: Find-WinComponents
    # Description....: Detects all CyberArk Components installed on the local server
    # Parameters.....: None
    # Return Values..: Array of detected components on the local server
    # =================================================================================================================================
    <#
.SYNOPSIS
	Method to query a local server for CyberArk components
.DESCRIPTION
	Detects all CyberArk Components installed on the local server
#>
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "Vault", "CPM", "PVWA", "PSM", "AIM", "EPM", "SecureTunnel")]
        [String]$Component = "All"
    )

    Begin {
        $retArrComponents = @()
        # COMPONENTS SERVICE NAMES
        $REGKEY_VAULTSERVICE_NEW = "CyberArk Logic Container"
        $REGKEY_VAULTSERVICE_OLD = "Cyber-Ark Event Notification Engine"
        $REGKEY_CPMSERVICE_NEW = "CyberArk Central Policy Manager Scanner"
        $REGKEY_CPMSERVICE_OLD = "CyberArk Password Manager"
        $REGKEY_PVWASERVICE = "CyberArk Scheduled Tasks"
        $REGKEY_PSMSERVICE = "Cyber-Ark Privileged Session Manager"
        $REGKEY_AIMSERVICE = "CyberArk Application Password Provider"
        $REGKEY_EPMSERVICE = "VfBackgroundWorker"
        $REGKEY_SECURETUNNELSERVICE = "CyberArkPrivilegeCloudSecureTunnel"
    }
    Process {
        if (![string]::IsNullOrEmpty($Component)) {
            Switch ($Component) {
                "Vault" {
                    try {
                        # Check if Vault is installed
                        Write-LogMessage -Type "Debug" -MSG "Searching for Vault..."
                        if (($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_VAULTSERVICE_OLD))) -or ($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_VAULTSERVICE_NEW)))) {
                            Write-LogMessage -Type "Debug" -MSG "Found Vault installation"
                            $vaultPath = $componentPath.Replace("LogicContainer\BLServiceApp.exe", "").Replace("Event Notification Engine\ENE.exe", "").Replace('"', "").Trim()
                            $fileVersion = Get-FileVersion "$vaultPath\dbmain.exe"
                            return New-Object PSObject -Property @{Name = "Vault"; Path = $vaultPath; Version = $fileVersion }
                        }
                    }
                    catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "CPM" {
                    try {
                        # Check if CPM is installed
                        Write-LogMessage -Type "Debug" -MSG "Searching for CPM..."
                        if (($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_CPMSERVICE_OLD))) -or ($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_CPMSERVICE_NEW)))) {
                            # Get the CPM Installation Path
                            Write-LogMessage -Type "Debug" -MSG "Found CPM installation"
                            $cpmPath = $componentPath.Replace("Scanner\CACPMScanner.exe", "").Replace("PMEngine.exe", "").Replace("/SERVICE", "").Replace('"', "").Trim()
                            $fileVersion = Get-FileVersion "$cpmPath\PMEngine.exe"
                            return New-Object PSObject -Property @{Name = "CPM"; Path = $cpmPath; Version = $fileVersion }
                        }
                    }
                    catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "PVWA" {
                    try {
                        # Check if PVWA is installed
                        Write-LogMessage -Type "Debug" -MSG "Searching for PVWA..."
                        if ($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_PVWASERVICE))) {
                            Write-LogMessage -Type "Debug" -MSG "Found PVWA installation"
                            $pvwaPath = $componentPath.Replace("Services\CyberArkScheduledTasks.exe", "").Replace('"', "").Trim()
                            $fileVersion = Get-FileVersion "$pvwaPath\Services\CyberArkScheduledTasks.exe"
                            return New-Object PSObject -Property @{Name = "PVWA"; Path = $pvwaPath; Version = $fileVersion }
                        }
                    }
                    catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "PSM" {
                    try {
                        # Check if PSM is installed
                        Write-LogMessage -Type "Debug" -MSG "Searching for PSM..."
                        if ($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_PSMSERVICE))) {
                            Write-LogMessage -Type "Debug" -MSG "Found PSM installation"
                            $PSMPath = $componentPath.Replace("CAPSM.exe", "").Replace('"', "").Trim()
                            $fileVersion = Get-FileVersion "$PSMPath\CAPSM.exe"
                            return New-Object PSObject -Property @{Name = "PSM"; Path = $PSMPath; Version = $fileVersion }
                        }
                    }
                    catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "AIM" {
                    try {
                        # Check if AIM is installed
                        Write-LogMessage -Type "Debug" -MSG "Searching for AIM..."
                        if ($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_AIMSERVICE))) {
                            Write-LogMessage -Type "Debug" -MSG "Found AIM installation"
                            $AIMPath = $componentPath.Replace("/mode SERVICE", "").Replace("AppProvider.exe", "").Replace('"', "").Trim()
                            $fileVersion = Get-FileVersion "$AIMPath\AppProvider.exe"
                            return New-Object PSObject -Property @{Name = "AIM"; Path = $AIMPath; Version = $fileVersion }
                        }
                    }
                    catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "EPM" {
                    try {
                        # Check if EPM Server is installed
                        Write-LogMessage -Type "Debug" -MSG "Searching for EPM Server..."
                        if ($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_EPMSERVICE))) {
                            Write-LogMessage -Type "Debug" -MSG "Found EPM Server installation"
                            $EPMPath = $componentPath.Replace("VfBackgroundWorker.exe", "").Replace('"', "").Trim()
                            $fileVersion = Get-FileVersion "$EPMPath\VfBackgroundWorker.exe"
                            return New-Object PSObject -Property @{Name = "EPM"; Path = $EPMPath; Version = $fileVersion }
                        }
                    }
                    catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "SecureTunnel" {
                    try {
                        # Check if Privilege Cloud Secure tunnel is installed
                        Write-LogMessage -Type "Debug" -MSG "Searching for Privilege Cloud Secure tunnel..."
                        if ($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_SECURETUNNELSERVICE))) {
                            Write-LogMessage -Type "Debug" -MSG "Found Privilege Cloud Secure tunnel installation"
                            $tunnelPath = $componentPath.Replace("PrivilegeCloudSecureTunnel.exe", "").Replace('"', "").Trim()
                            $fileVersion = Get-FileVersion "$tunnelPath\PrivilegeCloudSecureTunnel.exe"
                            return New-Object PSObject -Property @{Name = "SecureTunnel"; Path = $tunnelPath; Version = $fileVersion }
                        }
                    }
                    catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "All" {
                    try {
                        ForEach ($comp in @("Vault", "CPM", "PVWA", "PSM", "AIM", "EPM", "SecureTunnel")) {
                            $retArrComponents += Find-WinComponents -Component $comp
                        }
                        return $retArrComponents
                    }
                    catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting components. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
            }
        }
    }
    End {
    }
}
function Start-ComponentService {
    param (
        [Parameter(Mandatory = $true)]
        [array]$services,

        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$session,

        [Parameter(Mandatory = $false)]
        [int]$wait = 1,

        [Parameter(Mandatory = $false)]
        [int]$attempts = 1
    )

    ForEach ($service in $services) {
        $running = $false
        $attemptCount = 0
        While (!$running) {
            Write-LogMessage -Type "Debug" -MSG "Attempting to start `"$service`" on $server"
            Invoke-Command -Session $session -ScriptBlock { $targetService = Get-Service -Name $args[0]; $targetService.start(); $targetService.WaitForStatus('Running', (New-TimeSpan -Seconds 20)) } -ArgumentList $service -ErrorAction SilentlyContinue -ErrorVariable startResult

            IF ($attemptCount -ge $attempts) {
                return $false
            }
            elseIf ("0" -ne $startResult.Count) {
                $attemptCount += 1
                Write-LogMessage -Type "Debug" -MSG "Unable to start $service on $server, attempting force restart processes. Attempt $attemptCount"
                $null = Invoke-Command -Session $session -ScriptBlock { Stop-ServiceProcess -name $args[0] } -ArgumentList $service 
                Start-Sleep 1
                $startResult.clear()
            }
            else {
                $running = $true
                Write-LogMessage -Type Debug -MSG "`"$service`" on $server Started"
                Start-Sleep -Seconds $wait
            }
        }
    }
    return $true
}
function Stop-ComponentService {
    param (
        [Parameter(Mandatory = $true)]
        [array]$services,

        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$session

    )

    ForEach ($service in $services) {
        Write-LogMessage -Type "Debug" -MSG "Attempting to stop `"$service`" on $server"
        Invoke-Command -Session $session -ScriptBlock { $targetService = Get-Service -Name $args[0]; $targetService.Stop(); $targetService.WaitForStatus('Stopped', (New-TimeSpan -Seconds 15)) } -ArgumentList $service -ErrorAction SilentlyContinue -ErrorVariable stopResult

        If ($stopResult.Count -gt 0) {
            If ("InvalidOperationException" -ieq $stopResult[0].FullyQualifiedErrorId) {
                $null
            }
            else {
                Write-LogMessage -Type "Debug" -MSG "Unable to stop `"$service`" on $server, force stopping processes"
                $null = Invoke-Command -Session $session -ScriptBlock { Stop-ServiceProcess -name $args[0] } -ArgumentList $service
            }
        }
        Write-LogMessage -Type Debug -MSG "`"$service`" on $server Started"
        $stopResult.clear()
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
                    }
                    catch {
                        Throw $_   
                    }
                }
            }
            If (!$userFound) {
                Write-LogMessage -type Verbose -MSG "Unable to locate component account for $Username"
            }
        }
        else {
            Write-LogMessage -type Verbose -MSG "Unable to locate component account for $Username"
        } 
    }
}
Function New-RandomPassword {

    # @FUNCTION@ ======================================================================================================================
    # Name...........: New-RandomPassword
    # Description....: Creates a new random password
    # Parameters.....: Length, (Switch)Lowercase, (Switch)Uppercase, (Switch)Numbers, (Switch)Symbols
    # Return Values..: A random password based on the requirements
    # =================================================================================================================================

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
Function Convert-SecureString {

    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # Length, Type uint32, Length of the random string to create.    [Parameter(Mandatory=$true, Position=0)]
        [secureString]$secureString
    )

    Process {

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }
}
Function Stop-ServiceProcess {
    [CmdletBinding()]
    
    Param
    (
        [Parameter(Mandatory = $True, ValuefromPipeline = $True)]
        [string[]]$name
    )
    
    Process {
        $name
        $id = Get-WmiObject -Class Win32_Service -Filter "Name LIKE '$name'" | Select-Object -ExpandProperty ProcessId
        if (0 -ne $id) {
            Stop-Process -Id $id -Force
        }
    }
}
function Reset-Credentials {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComponentType,

        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [string]$OS,

        [Parameter(Mandatory = $false)]
        [string]$vaultAddress,

        [Parameter(Mandatory = $false)]
        [string]$apiAddress
    )

    $checkPVWA = $PVWAURL.replace("\", "/").replace("https://", "").Split("/").ToLower()
    If ($checkPVWA[0] -eq $server.ToLower()) {
        Write-LogMessage -type Error -MSG "Unable to reset PVWA credentials on $server because it is being used by script" -Footer
        continue
    }
    IF ("Windows" -eq $os) {
        switch ($ComponentType) {
            "CPM" { 
                Reset-WinComponent -Server $server -component "CPM" -componentName $ComponentType -services $g_cpmservices -vaultaddress $vaultAddress -apiAddress $apiAddress; break 
            }
            "PVWA" { 
                Reset-WinComponent -Server $server -component "PVWA" -componentName $ComponentType -services $g_pvwaservices -vaultaddress $vaultAddress; break  
            }
            "PSM" { 
                Reset-WinComponent -Server $server -component "PSM" -componentName $ComponentType -services $g_psmservices -vaultaddress $vaultAddress -apiAddress $apiAddress; break  
            }
            "AAM Credential Provider" { 
                Reset-WinComponent -Server $server -component "AIM" -componentName $ComponentType -services $g_aamservices -vaultaddress $vaultAddress; break 
            }
            "Secrets Manager Credential Providers" { 
                Reset-WinComponent -Server $server -component "AIM" -componentName $ComponentType -services $g_aamservices -vaultaddress $vaultAddress; break 
            }
            default {
                Write-LogMessage -type Error -MSG "No Component Type passed for $server"
            }
        }
    }
    elseIf ("Linux" -eq $os) {
        Write-LogMessage -type Error -msg "Unable to reset PSMP credentials at this time. Manual reset required for $server"
    }
    else {
        Write-LogMessage -type Error -msg "Unable to determine OS type for $server"
    }
}
function Reset-WinCredFile {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $true)]
        $compInfo,
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$session
    )
    $installLocation = $compInfo.path
    [version]$version = $compInfo.Version
    $component = $compInfo.name

    switch ($component) {
        "AIM" {
            $CompFiles += @(
                @{
                    type              = "AIM"
                    createCredDir     = "\vault"
                    credFilesDir      = ".\"
                    credFiles         = "AppProviderUser.cred"
                    componentName     = "AAM Credential Provider"
                    CreateCredCommand = $(if ($version -ge [version]'12.0') {
                            $g_aamuserwinCredv12
                        }
                        else {
                            $g_aamuserwinCred
                        })
                }
            )
        }
        "CPM" {
            $CompFiles += @( 
                @{
                    type              = "CPM"
                    createCredDir     = "\vault"
                    credFilesDir      = ".\"
                    credFiles         = ".\user.ini"
                    componentName     = "CPM User"
                    CreateCredCommand = $(if ($version -ge [version]'12.1') {
                            $g_cpmuserCredv12
                        }
                        else {
                            $g_cpmuserCred
                        })
                }
            )
        }
        "PSM" {
            $CompFiles += @(
                @{
                    type              = "PSM"
                    createCredDir     = "\vault"
                    credFilesDir      = ".\"
                    credFiles         = "psmapp.cred"
                    componentName     = "PSM Application User"
                    CreateCredCommand = $(if ($version -ge [version]'12.1') {
                            $g_psmappuserCredv12
                        }
                        else {
                            $g_psmappuserCred
                        })
                }
            )
            $CompFiles += @(
                @{
                    type              = "PSM"
                    createCredDir     = "\vault"
                    credFilesDir      = ".\"
                    credFiles         = "psmgw.cred"
                    componentName     = "PSM Gateway User"
                    CreateCredCommand = $(if ($version -ge [version]'12.1') {
                            $g_psmgwuserCredv12
                        }
                        else {
                            $g_psmgwuserCred
                        })
                }
            )
        }
        "PVWA" {
            $CompFiles += @(
                @{
                
                    type              = "PVWA"
                    createCredDir     = "\Env"
                    credFilesDir      = "..\CredFiles\"
                    credFiles         = "appuser.ini"
                    componentName     = "PVWA Application User"
                    CreateCredCommand = $(if ($version -ge [version]'12.1') {
                            $g_pvwaappuserCredv12
                        }
                        else {
                            $g_pvwaappuserCred
                        })
                }
            )
            $CompFiles += @( 
                @{
                    type              = "PVWA"
                    createCredDir     = "\Env"
                    credFilesDir      = "..\CredFiles\"
                    credFiles         = "gwuser.ini"
                    componentName     = "PVWA Gateway User"
                    CreateCredCommand = $(if ($version -ge [version]'12.1') {
                            $g_pvwagwuserCredv12
                        }
                        else {
                            $g_pvwagwuserCred
                        })
                }
            )
        }
    } 
    foreach ($comp in $CompFiles) {

        $component = $comp.type
        $file = $comp.CredFiles
        $dir = $comp.credFilesDir
        $createCredDir = "$installLocation\$($comp.createCredDir)"

        Write-LogMessage -type Verbose -MSG "Updating $component $file credential file"
        Invoke-Command -Session $session -ScriptBlock { Set-Location -Path ($args[0]); } -ArgumentList $createCredDir
        $userItem = Invoke-Command -Session $session -ScriptBlock { ((Select-String -Path "$($args[1])\$($args[0])" -Pattern "username=").Line).split("=")[1] } -ArgumentList $file, $dir
        $tempPassword = New-RandomPassword -Length 14 -Lowercase -Uppercase -Numbers -Symbols | ConvertTo-SecureString -AsPlainText -Force 
        Write-LogMessage -type Verbose -MSG "Username: $userItem"

        $tag = [DateTimeOffset]::Now.ToUnixTimeSeconds()
        Invoke-Command -Session $session -ScriptBlock { Rename-Item "$($args[2])\$($args[0])" -NewName "$($args[0]).$($args[1])" -Force } -ArgumentList $file, $tag, $dir
        Invoke-Command -Session $session -ScriptBlock { Rename-Item "$($args[2])\$($args[0]).entropy" -NewName "$($args[0]).entropy.$($args[1])" -Force -ErrorAction SilentlyContinue } -ArgumentList $file, $tag, $dir
        Write-LogMessage -type Verbose -MSG "Backed up $component credential files"
    
        $command = $comp.CreateCredCommand -f $userItem, $(Convert-SecureString($tempPassword))

        Invoke-Command -Session $session -ScriptBlock { Invoke-Expression $args[0]; } -ArgumentList $command -ErrorAction SilentlyContinue -ErrorVariable invokeResultApp
        Remove-Variable command
        If ($invokeResultApp[0].TargetObject -ne "Command ended successfully") {
            Invoke-Command -Session $session -ScriptBlock { Rename-Item "$($args[2])\$($args[0]).$($args[1])" -NewName "$($args[0])" -Force } -ArgumentList $file, $tag, $dir | Out-Null
            Invoke-Command -Session $session -ScriptBlock { Rename-Item "$($args[2])\$($args[0]).entropy.$($args[1])" -NewName "$($args[0]).entropy" -Force -ErrorAction SilentlyContinue } -ArgumentList $file, $tag, $dir | Out-Null

            Write-LogMessage -type Error -MSG "Error resetting credential file on $server"
            Throw "Error resetting credential file on $server"
        }
        else {
            Invoke-Command -Session $session -ScriptBlock { Remove-Item "$($args[2])\$($args[0]).$($args[1])" -Force } -ArgumentList $file, $tag, $dir
            Invoke-Command -Session $session -ScriptBlock { Remove-Item "$($args[2])\$($args[0]).entropy.$($args[1])" -Force -ErrorAction SilentlyContinue } -ArgumentList $file, $tag, $dir
        }
    
        Write-LogMessage -type Verbose -MSG "CreateCredFile on $componentName $file successful"
        Write-LogMessage -type Verbose -MSG "Updating $componentName via RESTAPI"
        Set-UserPassword -username $userItem -Password $tempPassword
        Write-LogMessage -type Verbose -MSG "Update of $componentName user via RESTAPI Complete"
        Write-LogMessage -type Success -MSG "Update of user $useritem on $server completed successfully"
    }

    
}
function Reset-VaultFile {

    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $true)]
        $compInfo,
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$session,
        [Parameter(Mandatory = $false)]
        $vaultAddress,
        [Parameter(Mandatory = $false)]
        $apiAddress
        
    )
    $installLocation = $compInfo.path
    $component = $compInfo.name

    switch ($component) {
        "AIM" {
            $CompFiles += @(
                @{
                    type          = "AIM"
                    vaultdir      = "vault"
                    componentName = "AAM"
                }
            )
        }
        "CPM" {
            $CompFiles += @( 
                @{
                    type          = "CPM"
                    vaultdir      = "vault"
                    componentName = "CPM"

                }
            )
        }
        "PSM" {
            $CompFiles += @(
                @{
                    type          = "PSM"
                    vaultdir      = "vault"
                    componentName = "PSM"
                }    
            )
        }
        "PVWA" {
            $CompFiles += @(
                @{
                
                    type          = "PVWA"
                    vaultdir      = "VaultInfo"
                    componentName = "PVWA"
                }
            )
        }
    } 
    $failed = $false

    foreach ($comp in $CompFiles) {

        $component = $comp.type
        $file = $comp.CredFiles
        $vaultDir = "$installLocation\$($comp.vaultdir)"
        $vaultFile = "$vaultdir\vault.ini"

        Write-LogMessage -type Verbose -MSG "Updating $component vault.ini files"
        Invoke-Command -Session $session -ScriptBlock { Set-Location -Path "$($args[0])"; } -ArgumentList $vaultDir

        $tag = [DateTimeOffset]::Now.ToUnixTimeSeconds()
        Invoke-Command -Session $session -ScriptBlock { Copy-Item $($args[0]) -Destination "$($args[0]).$($args[1])" -Force } -ArgumentList $vaultFile, $tag
        Write-LogMessage -type Verbose -MSG "Backed up existing $component vault.ini file"

        try {
            $regex = '(^ADDRESS=.*)'
            Invoke-Command -Session $session -ScriptBlock { $file = $args[0]; $regex = $args[1] } -ArgumentList $vaultFile, $regex
            Invoke-Command -Session $session -ScriptBlock { (Get-Content $file) -replace $regex, "ADDRESS=$($args[0])" | Set-Content $file } -ArgumentList $vaultaddress
            Write-LogMessage -type Verbose -MSG "$component vault.ini updated successfully"
            Invoke-Command -Session $session -ScriptBlock { Remove-Item "$($args[0]).$($args[1])" -Force } -ArgumentList $vaultFile, $tag
        }
        catch {
            Invoke-Command -Session $session -ScriptBlock { Rename-Item "$($args[0]).$($args[1])" -NewName "$($args[0])" -Force } -ArgumentList $vaultFile, $tag
            Write-LogMessage -type Error -MSG "Error updating $component  vault.ini file on $server"
            $failed = $true
            Throw "Error updating $component vault.ini file"
        }
        Write-LogMessage -type Success -MSG "Update of vault address in vault.ini on $componentName completed successful"

        IF (![string]::IsNullOrEmpty($apiAddress)) {
            Invoke-Command -Session $session -ScriptBlock { Copy-Item $($args[0]) -Destination "$($args[0]).$($args[1])" -Force } -ArgumentList $vaultFile, $tag
            Write-LogMessage -type Verbose -MSG "Backed up existing $component vault.ini file"
            try {
                $regex = '(^Addresses=.*)'
                Invoke-Command -Session $session -ScriptBlock { $file = $args[0]; $regex = $args[1] } -ArgumentList $vaultFile, $regex
                Invoke-Command -Session $session -ScriptBlock { (Get-Content $file) -replace $regex, "Addresses=$($args[0])" | Set-Content $file } -ArgumentList $apiAddress
                Write-LogMessage -type Verbose -MSG "$component vault.ini updated successfully"
                Invoke-Command -Session $session -ScriptBlock { Remove-Item "$($args[0]).$($args[1])" -Force } -ArgumentList $vaultFile, $tag
            }
            catch {
                Invoke-Command -Session $session -ScriptBlock { Rename-Item "$($args[0]).$($args[1])" -NewName "$($args[0])" -Force } -ArgumentList $vaultFile, $tag
                Write-LogMessage -type Error -MSG "Error updating $component  vault.ini file on $server"
                $failed = $true
                Throw "Error updating $component vault.ini file"
            }
            Write-LogMessage -type Success -MSG "Update of vault API in vault.ini on $componentName completed successfully"
        }
       
    }
}
function Reset-WinComponent {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $true)]
        [string]$component,
        [Parameter(Mandatory = $true)]
        [string]$componentName,
        [Parameter(Mandatory = $true)]
        $services,
        [Parameter(Mandatory = $false)]
        [string]$vaultaddress,
        [Parameter(Mandatory = $false)]
        [string]$apiAddress

    )
    $complete = $failed = $false
    $attempts = 0
    Write-LogMessage -type Verbose -MSG "Entering Reset-WinComponent"
    While (!$complete -and !$failed) {
        try {
            $complete = $failed = $false
            $attempts = 0

            While (!$complete) {
                Try {
                    $session = New-PSLogon $server
                    Write-LogMessage -type Verbose -MSG "Got Session"
                    Write-LogMessage -type Verbose -MSG "Connected to host: $(Invoke-Command -Session $session -ScriptBlock{[System.Net.Dns]::GetHostName()})"
                    Write-LogMessage -type Verbose -MSG "Connected as user: $(Invoke-Command -Session $session -ScriptBlock{whoami.exe})"
                }
                Catch {
                    Write-LogMessage -type Verbose -MSG "Error Message is $($error)"     
                    Write-LogMessage -type Verbose -MSG "Error Message is $_" 
                    Write-LogMessage -type Error -MSG "Unable to connect to winRM on $server. Verify this is a Windows server and winRM has been enabled."             
                            
                    break
                }
                Write-LogMessage -type Verbose -MSG "Connected to $Server. Importing required modules"
                
                Import-ModuleRemotely -moduleName CyberArk-Common -session $Session
                Write-LogMessage -type Verbose -MSG "Modules imported. Getting information about the installed components"
                
                $compInfo = Get-ComponentInfo -Server $Server -ComponentType $component -Session $Session          
                
                $installLocation = $compInfo.path
                [version]$version = $compInfo.Version
                Write-LogMessage -type Verbose -MSG "Retrived Component Information"
                Write-LogMessage -type Verbose -MSG "Installation path : $installLocation"
                Write-LogMessage -type Verbose -MSG "Version: $version"

                Write-LogMessage -type Verbose -MSG "Attempting to stop $componentName Services" 
                Stop-ComponentService -services $services -session $session -server $server
                Write-LogMessage -type Verbose -MSG "Stopped $componentName Services"

                $credfailed = Reset-WinCredFile -Server $server -compInfo $compInfo -session $session

                IF (!($credfailed) -and (![string]::IsNullOrEmpty($vaultaddress))) {
                    $vaultfailed = Reset-VaultFile -Server $server -compInfo $compInfo -session $session -vaultAddres $vaultaddress -apiAddress $apiAddress
                }
                $complete = Start-ComponentService -services $services -session $session -server $server

                $attempts += 1
		
                if ($attempts -gt 5) {
                    $failed = $true;
                    Write-LogMessage -type Error -MSG "Failed on $server" 
                    Throw "Failed on $componentName credentials on $server"
                }

                Write-LogMessage -type Verbose -MSG "$componentName Started"

                if ($complete) {
                    Write-LogMessage -type Success -MSG "$componentName component on $server update completed successful" -Footer
                }
                else {
                    Write-LogMessage -type Warning -MSG "$componentName component on $server update failed, restarting" -Footer
                }
            }
        }
        catch {
            Write-LogMessage -type Error -MSG "Error during update of $componentName on $server" -Footer
            Throw $_
        }
        Finally {
            Write-LogMessage -type Verbose -MSG "Disconnecting from $server"  
            Remove-PSSession $session
            Write-LogMessage -type Verbose -MSG "Disconnected from $server"
        }
    }
}
function Get-ComponentInfo {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $false)]
        [string]$ComponentType,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )
    $newSession = $false
    try {
		
        if ($Session.State -ne "Opened") {
            $newSession = $true
            $Session = New-PSLogon $server
        }
        $ComponentsFound = Invoke-Command -Session $Session -ScriptBlock { Find-WinComponents $args[0] } -ArgumentList $ComponentType
        return $ComponentsFound

    }
    catch {
        Throw "error"
    }
    Finally {
        If ($newSession) {
            Remove-PSSession $Session
        }
    }

}
Function Get-ComponentStatus {

    try {
        $restResponse = $(Invoke-Rest -Uri $URL_HealthSummery -Header $g_LogonHeader -Command "Get")	
        $selection = $restResponse.Components | Where-Object { $_.ComponentTotalCount -gt 0 } | Select-Object @{Name = "Component Type"; Expression = { $_.'ComponentName' } }, @{Name = "Amount Connected"; Expression = { $_.'ConnectedComponentCount' } }, @{Name = "Total Amount"; Expression = { $_.'ComponentTotalCount' } } | Sort-Object -Property "Component Type" 
        Return $selection
    }
    catch {
        return $null
    }
}
Function Get-ComponentDetails {

    param (
        [Parameter(Mandatory = $true)]
        $component
    )

    switch ($component) {
        "PSM/PSMP" {
            $targetComp = "SessionManagement"; break 
        }
        "Secrets Manager Credential Providers" {
            $targetComp = "AIM"; break 
        }
        "AAM Credential Provider" {
            $targetComp = "AIM"; break 
        }
        Default {
            $targetComp = $component
        }
    } 
    $URLHealthDetails = $URL_HealthDetails -f $targetComp
    Try {
        $restResponse = $(Invoke-Rest -Uri $URLHealthDetails -Header $g_LogonHeader -Command "Get")

        $selection = $restResponse.ComponentsDetails | Select-Object @{Name = "Component Type"; Expression = { $component } }, @{Name = "Component Version"; Expression = { $_.ComponentVersion } }, @{Name = "IP Address"; Expression = { $_.'ComponentIP' } }, @{Name = "Component User"; Expression = { $_.'ComponentUserName' } }, @{Name = "Connected"; Expression = { $_.'IsLoggedOn' } }, @{Name = "Last Connection"; Expression = { Get-LogonTimeUnixTime $_.'LastLogonDate' } } | Sort-Object -Property "IP Address" 
		
        Return $selection
    }
    Catch {
        Return $null
    }
}
Function Test-TargetWinRM {
    param (
        [Parameter()]
        [string]$server
    )
    Write-LogMessage -type Verbose -MSG "Parameter in Test-TargetWinRM passed for `'server`' "$server
    Write-LogMessage -type Verbose -MSG "In Test-TargetWinRM"
    try {
        New-PSLogon -server $server
        Write-LogMessage -type Verbose -MSG "Test-TargetWinRM Success"
        Return $true
    }
    catch {
        Write-LogMessage -type Verbose -MSG "Test-TargetWinRM Failed"
        Return $false
    }
}
function New-PSLogon {
    param (
        [Parameter()]
        [string]$server
    )
    $psoptions = New-PSSessionOption -IncludePortInSPN

    Write-LogMessage -type Verbose -MSG "Parameter in New-PSLogon passed for `'server`' "$server
    Write-LogMessage -type Verbose -MSG "In New-PSLogon"
    Try {
        If ($null -ne $G_PSCredentials) {
            Write-LogMessage -type Verbose -MSG "Parameter passed for `'G_PSCredentials`' "$G_PSCredentials
            $psSession = New-PSSession $server -Credential $G_PSCredentials -Authentication Negotiate -SessionOption $psoptions
        }
        else {   
            Write-LogMessage -type Verbose -MSG "Parameter passed for `'G_PSCredentials`' is null"
            $psSession = New-PSSession $server -SessionOption $psoptions -Authentication Negotiate
        }
        Write-LogMessage -type Verbose -MSG "Retrived Session"
        IF (![string]::IsNullOrEmpty($g_prePSSession)) {
            Write-LogMessage -type Verbose -MSG "Inside g_prePSSession"
            Invoke-Command -Session $psSession -ScriptBlock $g_prePSSession -ErrorAction SilentlyContinue
            Write-LogMessage -type Verbose -MSG "Completed g_prePSSession"
        }
        return $psSession 
    }
    Catch {
        Write-LogMessage -type Error -MSG "Catch in New-PSLogon"
        Write-LogMessage -type Verbose -MSG "$_"
    }
}
