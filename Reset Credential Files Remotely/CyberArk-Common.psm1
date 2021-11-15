[CmdletBinding()]



# Global URLS
# -----------
#region Global Variables
$URL_PVWAAPI = $global:PVWAURL+"/api"
$URL_Authentication = $URL_PVWAAPI+"/auth"
$URL_Logon = $URL_Authentication+"/$global:AuthType/Logon"
$URL_Logoff = $URL_Authentication+"/Logoff"

$URL_UserSearch = $URL_PVWAAPI+"/Users?filter=componentUser&search={0}"
$URL_UserResetPassword = $URL_PVWAAPI+"/Users/{0}/ResetPassword"
$URL_Activate = $URL_PVWAAPI+"/Users/{0}/Activate"

$URL_HealthSummery = $URL_PVWAAPI+"/ComponentsMonitoringSummary"
$URL_HealthDetails = $URL_PVWAAPI+"/ComponentsMonitoringDetails/{0}"

$g_cpmservices = @("CyberArk Password Manager","CyberArk Central Policy Manager Scanner")
$g_pvwaservices = @("CyberArk Scheduled Tasks")
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
$g_aamuserCredv12 = ".\CreateCredFile.exe AppProviderUser.cred Password /Username {0} /AppType AppPrv /IpAddress /Hostname /EntropyFile /DPAPIMachineProtection /Password {1}"

$g_aamuserCred = ".\CreateCredFile.exe AppProviderUser.cred Password /Username {0} /AppType AppPrv /IpAddress /Hostname /Password {1}"

if($InVerbose){
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
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [AllowEmptyString()]
        [String]$MSG,
        [Parameter(Mandatory=$false)]
        [Switch]$Header,
        [Parameter(Mandatory=$false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory=$false)]
        [Switch]$Footer,
        [Parameter(Mandatory=$false)]
        [Bool]$WriteLog = $true,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Info","Warning","Error","Debug","Verbose", "Success", "LogOnly")]
        [String]$type = "Info",
        [Parameter(Mandatory=$false)]
        [String]$LogFile = $LOG_FILE_PATH
    )

    If (![string]::IsNullOrEmpty($PSSenderInfo)) {$WriteLog = $false}
    Try{
        If([string]::IsNullOrEmpty($LogFile) -and $WriteLog) {
            # User wanted to write logs, but did not provide a log file - Create a temporary file
            $LogFile = Join-Path -Path $ENV:Temp -ChildPath "$((Get-Date).ToShortDateString().Replace('/','_')).log"
            Write-Host "No log file path inputted, created a temporary file at: '$LogFile'"
        }
        If ($Header -and $WriteLog) {
            "=======================================" | Out-File -Append -FilePath $LogFile 
            Write-Host "=======================================" -ForegroundColor Magenta
        } ElseIf($SubHeader -and $WriteLog) { 
            "------------------------------------" | Out-File -Append -FilePath $LogFile 
            Write-Host "------------------------------------" -ForegroundColor Magenta
        }
		
        # Replace empty message with 'N/A'
        if([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
        $msgToWrite = ""
		
        # Mask Passwords
        if($Msg -match '((?:password|credentials|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()-_\=\+\\\/|;:\.,\[\]{}]+))') {
            $Msg = $Msg.Replace($Matches[2],"****")
        }
        # Check the message type
        switch ($type) {
            {($_ -eq "Info") -or ($_ -eq "LogOnly")} { 
                If($_ -eq "Info") {
                    Write-Host $MSG.ToString() -ForegroundColor $(If($Header -or $SubHeader) { "Magenta" } Else { "Gray" })
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
                if($InDebug -or $InVerbose) {
                    Write-Debug $MSG
                    $msgToWrite = "[Debug]`t$Msg"
                }
                break
            }
            "Verbose" { 
                if($InVerbose) {
                    Write-Verbose -Msg $MSG
                    $msgToWrite = "[VERBOSE]`t$Msg"
                }
                break
            }
        }

        If($WriteLog) { 
            If(![string]::IsNullOrEmpty($msgToWrite)) {				
                "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t$msgToWrite" | Out-File -Append -FilePath $LogFile
            }
        }
        If ($Footer -and $WriteLog) { 
            "=======================================" | Out-File -Append -FilePath $LogFile 
            Write-Host "=======================================" -ForegroundColor Magenta
        }
    } catch{
        Throw $(New-Object System.Exception ("Cannot write message"),$_.Exception)
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
    try {if(Get-Command $command){RETURN $true}}
    Catch {Write-Host "$command does not exist"; RETURN $false}
    Finally {$ErrorActionPreference=$oldPreference}
} #end function test-CommandExists

# @FUNCTION@ ======================================================================================================================
# Name...........: ConvertTo-URL
# Description....: HTTP Encode test in URL
# Parameters.....: Text to encode
# Return Values..: Encoded HTML URL text
# =================================================================================================================================
Function ConvertTo-URL($sText) {
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
	
    if($txt -match "^y$|^yes$") { $retBool = $true }
    elseif ($txt -match "^n$|^no$") { $retBool = $false }
    else { [bool]::TryParse($txt, [ref]$retBool) | Out-Null }
    
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
    if($null -ne $sText) {
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
        [Parameter(Mandatory=$true)]
        [ValidateSet("GET","POST","DELETE","PATCH")]
        [String]$Command, 
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()] 
        [String]$URI, 
        [Parameter(Mandatory=$false)]
        $Header, 
        [Parameter(Mandatory=$false)]
        [String]$Body, 
        [Parameter(Mandatory=$false)]
        [ValidateSet("Continue","Ignore","Inquire","SilentlyContinue","Stop","Suspend")]
        [String]$ErrAction="Continue"
    )
	
    If ((Test-CommandExists Invoke-RestMethod) -eq $false) {
        Throw "This script requires PowerShell version 3 or above"
    }
    $restResponse = ""
    try{
        if([string]::IsNullOrEmpty($Body)) {
            Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -TimeoutSec 2700"
            $restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -TimeoutSec 2700 -ErrorAction $ErrAction
        } else {
            Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body -TimeoutSec 2700"
            $restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body -TimeoutSec 2700 -ErrorAction $ErrAction
        }
    } catch [System.Net.WebException] {
        if($ErrAction -match ("\bContinue\b|\bInquire\b|\bStop\b|\bSuspend\b")){
            Write-LogMessage -Type Error -Msg "Error Message: $_"
            Write-LogMessage -Type Error -Msg "Exception Message: $($_.Exception.Message)"
            Write-LogMessage -Type Error -Msg "Status Code: $($_.Exception.Response.StatusCode.value__)"
            Write-LogMessage -Type Error -Msg "Status Description: $($_.Exception.Response.StatusDescription)"
        }
        $restResponse = $null
    } catch { 
        Throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'",$_.Exception))
    }
    Write-LogMessage -Type Verbose -Msg "Invoke-REST Response: $restResponse"
    return $restResponse
}

If ((Test-CommandExists Invoke-RestMethod) -eq $false) {
    Write-LogMessage -Type Error -MSG "This script requires PowerShell version 3 or above"
    return
}


Function Write-ProgressStatus{

    
}
Function Set-PSSessionCred{

    param(
        [Parameter(Mandatory=$false)]
        [PSCredential]$PSCredentials

    )
    if ($null -eq $PSCredentials) {$PSCredentials = $Host.UI.PromptForCredential($caption,$msg,"","")}
}

Function Invoke-Logon{

    param(
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credentials

    )

    # Get Credentials to Login
    # ------------------------
    $caption = "Reset Remote Cred File Utility"
    $msg = "Enter your $AuthType User name and Password"; 
    if ($null -eq $Credentials) {$Credentials = $Host.UI.PromptForCredential($caption,$msg,"","")}
    if ($null -ne $Credentials) {
        if($AuthType -eq "radius" -and ![string]::IsNullOrEmpty($OTP)) {
            Set-Variable -Scope Global -Force -Name g_LogonHeader -Value $(Get-LogonHeader -Credentials $Credentials -RadiusOTP $OTP)
        } else {
            Set-Variable -Scope Global -Force -Name g_LogonHeader -Value $(Get-LogonHeader -Credentials $Credentials)
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
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credentials,
        [Parameter(Mandatory=$false)]
        [string]$RadiusOTP
    )
    # Create the POST Body for the Logon
    # ----------------------------------
    $logonBody = @{ username=$Credentials.username.Replace('\','');password=$Credentials.GetNetworkCredential().password;concurrentSession="true" } | ConvertTo-Json -Compress
    If(![string]::IsNullOrEmpty($RadiusOTP)) {
        $logonBody.Password += ",$RadiusOTP"
    }
	
    try{
        # Logon
        $logonToken = Invoke-Rest -Command Post -Uri $URL_Logon -Body $logonBody
        # Clear logon body
        $logonBody = ""
    } catch {
        Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.Exception.Response.StatusDescription)",$_.Exception))
    }
    
    $logonHeader = $null
    If ([string]::IsNullOrEmpty($logonToken)) {
        Throw "Get-LogonHeader: Logon Token is Empty - Cannot login"
    }
	
    # Create a Logon Token Header (This will be used through out all the script)
    # ---------------------------
    $logonHeader = @{Authorization = $logonToken}
	
    return $logonHeader
}

Function Reset-ComponentUser {



	
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

    [Parameter(Mandatory=$true)]
    [Switch]$DisableSSLVerify

    If($DisableSSLVerify) {
        try{
            Write-Warning "It is not Recommended to disable SSL verification" -WarningAction Inquire
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
        try{
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
        try{
            If (($null -ne $filePath) -and (Test-Path $filePath)) {
                $path = Resolve-Path $filePath
                $retFileVersion = ($path | Get-Item | Select-Object VersionInfo).VersionInfo.ProductVersion
            } else {
                throw "File path is empty"
            }

            return $retFileVersion
        } catch{
            Throw $(New-Object System.Exception ("Cannot get File ($filePath) version",$_.Exception))
        } finally{

        }
    }
    End {

    }
}
function Import-ModuleRemotely([string] $moduleName,[System.Management.Automation.Runspaces.PSSession] $session) {
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

    $moduleString= @"
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


# @FUNCTION@ ======================================================================================================================
# Name...........: Get-ServiceInstallPath
# Description....: Get the installation path of a service
# Parameters.....: Service Name
# Return Values..: $true
#                  $false
# =================================================================================================================================
# Save the Services List
$m_ServiceList = $null
Function Get-ServiceInstallPath {
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
        try{
            if ($null -eq $m_ServiceList) {
                Set-Variable -Name m_ServiceList -Value $(Get-ChildItem "HKLM:\System\CurrentControlSet\Services" | ForEach-Object { Get-ItemProperty $_.pspath }) -Scope Script
                Write-LogMessage -Type "Verbose" -MSG "Service $ServiceName has a registry path of $m_ServiceList"
            }
            $regPath =  $m_ServiceList | Where-Object {$_.PSChildName -eq $ServiceName}
            If ($Null -ne $regPath) {
                $retInstallPath = $regPath.ImagePath.Substring($regPath.ImagePath.IndexOf('"'),$regPath.ImagePath.LastIndexOf('"')+1)
                Write-LogMessage -Type "Verbose" -MSG "Service $ServiceName has a installation location of $retInstallPath"
            }
        } catch{
            Throw $(New-Object System.Exception ("Cannot get Service Install path for $ServiceName",$_.Exception))
        }

        return $retInstallPath
    }
    End {

    }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Find-Components
# Description....: Detects all CyberArk Components installed on the local server
# Parameters.....: None
# Return Values..: Array of detected components on the local server
# =================================================================================================================================
Function Find-Components {
    <#
.SYNOPSIS
	Method to query a local server for CyberArk components
.DESCRIPTION
	Detects all CyberArk Components installed on the local server
#>
    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet("All","Vault","CPM","PVWA","PSM","AIM","EPM","SecureTunnel")]
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
        if(![string]::IsNullOrEmpty($Component)) {
            Switch ($Component) {
                "Vault" {
                    try{
                        # Check if Vault is installed
                        Write-LogMessage -Type "Debug" -MSG "Searching for Vault..."
                        if(($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_VAULTSERVICE_OLD))) -or ($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_VAULTSERVICE_NEW)))) {
                            Write-LogMessage -Type "Debug" -MSG "Found Vault installation"
                            $vaultPath = $componentPath.Replace("LogicContainer\BLServiceApp.exe","").Replace("Event Notification Engine\ENE.exe","").Replace('"',"").Trim()
                            $fileVersion = Get-FileVersion "$vaultPath\dbmain.exe"
                            return New-Object PSObject -Property @{Name="Vault";Path=$vaultPath;Version=$fileVersion}
                        }
                    } catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "CPM" {
                    try{
                        # Check if CPM is installed
                        Write-LogMessage -Type "Debug" -MSG "Searching for CPM..."
                        if(($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_CPMSERVICE_OLD))) -or ($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_CPMSERVICE_NEW)))) {
                            # Get the CPM Installation Path
                            Write-LogMessage -Type "Debug" -MSG "Found CPM installation"
                            $cpmPath = $componentPath.Replace("Scanner\CACPMScanner.exe","").Replace("PMEngine.exe","").Replace("/SERVICE","").Replace('"',"").Trim()
                            $fileVersion = Get-FileVersion "$cpmPath\PMEngine.exe"
                            return New-Object PSObject -Property @{Name="CPM";Path=$cpmPath;Version=$fileVersion}
                        }
                    } catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "PVWA" {
                    try{
                        # Check if PVWA is installed
                        Write-LogMessage -Type "Debug" -MSG "Searching for PVWA..."
                        if($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_PVWASERVICE))) {
                            Write-LogMessage -Type "Debug" -MSG "Found PVWA installation"
                            $pvwaPath = $componentPath.Replace("Services\CyberArkScheduledTasks.exe","").Replace('"',"").Trim()
                            $fileVersion = Get-FileVersion "$pvwaPath\Services\CyberArkScheduledTasks.exe"
                            return New-Object PSObject -Property @{Name="PVWA";Path=$pvwaPath;Version=$fileVersion}
                        }
                    } catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "PSM" {
                    try{
                        # Check if PSM is installed
                        Write-LogMessage -Type "Debug" -MSG "Searching for PSM..."
                        if($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_PSMSERVICE))) {
                            Write-LogMessage -Type "Debug" -MSG "Found PSM installation"
                            $PSMPath = $componentPath.Replace("CAPSM.exe","").Replace('"',"").Trim()
                            $fileVersion = Get-FileVersion "$PSMPath\CAPSM.exe"
                            return New-Object PSObject -Property @{Name="PSM";Path=$PSMPath;Version=$fileVersion}
                        }
                    } catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "AIM" {
                    try{
                        # Check if AIM is installed
                        Write-LogMessage -Type "Debug" -MSG "Searching for AIM..."
                        if($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_AIMSERVICE))) {
                            Write-LogMessage -Type "Debug" -MSG "Found AIM installation"
                            $AIMPath = $componentPath.Replace("/mode SERVICE","").Replace("AppProvider.exe","").Replace('"',"").Trim()
                            $fileVersion = Get-FileVersion "$AIMPath\AppProvider.exe"
                            return New-Object PSObject -Property @{Name="AIM";Path=$AIMPath;Version=$fileVersion}
                        }
                    } catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "EPM" {
                    try{
                        # Check if EPM Server is installed
                        Write-LogMessage -Type "Debug" -MSG "Searching for EPM Server..."
                        if($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_EPMSERVICE))) {
                            Write-LogMessage -Type "Debug" -MSG "Found EPM Server installation"
                            $EPMPath = $componentPath.Replace("VfBackgroundWorker.exe","").Replace('"',"").Trim()
                            $fileVersion = Get-FileVersion "$EPMPath\VfBackgroundWorker.exe"
                            return New-Object PSObject -Property @{Name="EPM";Path=$EPMPath;Version=$fileVersion}
                        }
                    } catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "SecureTunnel" {
                    try{
                        # Check if Privilege Cloud Secure tunnel is installed
                        Write-LogMessage -Type "Debug" -MSG "Searching for Privilege Cloud Secure tunnel..."
                        if($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_SECURETUNNELSERVICE))) {
                            Write-LogMessage -Type "Debug" -MSG "Found Privilege Cloud Secure tunnel installation"
                            $tunnelPath = $componentPath.Replace("PrivilegeCloudSecureTunnel.exe","").Replace('"',"").Trim()
                            $fileVersion = Get-FileVersion "$tunnelPath\PrivilegeCloudSecureTunnel.exe"
                            return New-Object PSObject -Property @{Name="SecureTunnel";Path=$tunnelPath;Version=$fileVersion}
                        }
                    } catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "All" {
                    try{
                        ForEach($comp in @("Vault","CPM","PVWA","PSM","AIM","EPM","SecureTunnel")) {
                            $retArrComponents += Find-Components -Component $comp
                        }
                        return $retArrComponents
                    } catch {
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
        [Parameter(Mandatory=$true)]
        [array]$services,

        [Parameter(Mandatory=$true)]
        [string]$Server,

        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$session,

        [Parameter(Mandatory=$false)]
        [int]$wait=1,

        [Parameter(Mandatory=$false)]
        [int]$attempts=1
    )

    ForEach ($service in $services){
        $running = $false
        $attemptCount= 0
        While (!$running){
            Write-LogMessage -Type "Debug" -MSG "Attempting to start `"$service`" on $server"
            Invoke-Command -Session $session -ScriptBlock {$targetService = Get-Service -Name $args[0];$targetService.start();$targetService.WaitForStatus('Running',(New-TimeSpan -Seconds 20))} -ArgumentList $service -ErrorAction SilentlyContinue -ErrorVariable startResult

            IF ($attemptCount -ge $attempts) {
                return $false
            } elseIf ("0" -ne $startResult.Count){
                $attemptCount += 1
                Write-LogMessage -Type "Debug" -MSG "Unable to start $service on $server, attempting force restart processes. Attempt $attemptCount"
                $null = Invoke-Command -Session $session -ScriptBlock {Stop-ServiceProcess -name $args[0]} -ArgumentList $service 
                Start-Sleep 1
                $startResult.clear()
            } else {
                $running = $true
                Write-LogMessage -Type "Debug" -MSG "`"$service`" on $server Started"
                Start-Sleep -Seconds $wait
            }
        }
    }
    return $true
}
function Stop-ComponentService {
    param (
        [Parameter(Mandatory=$true)]
        [array]$services,

        [Parameter(Mandatory=$true)]
        [string]$Server,

        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$session

    )

    ForEach ($service in $services){
        Write-LogMessage -Type "Debug" -MSG "Attempting to stop `"$service`" on $server"
        Invoke-Command -Session $session -ScriptBlock {$targetService = Get-Service -Name $args[0];$targetService.Stop();$targetService.WaitForStatus('Stopped',(New-TimeSpan -Seconds 15))} -ArgumentList $service -ErrorAction SilentlyContinue -ErrorVariable stopResult

        If ($stopResult.Count -gt 0){
            If ("InvalidOperationException" -ieq $stopResult[0].FullyQualifiedErrorId){$null}
            else {
                Write-LogMessage -Type "Debug" -MSG "Unable to stop `"$service`" on $server, force stopping processes"
                $null = Invoke-Command -Session $session -ScriptBlock {Stop-ServiceProcess -name $args[0]} -ArgumentList $service
            }
        }
        Write-LogMessage -Type "Debug" -MSG "`"$service`" on $server Started"
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
        [Parameter(Mandatory=$true)]
        [String]$Username,
        [Parameter(Mandatory=$true)]
        [SecureString]$Password
    )
    Process {
        Write-LogMessage -type Verbose -MSG "URL for PVWA: $PVWAURL"
        Write-LogMessage -type Verbose -MSG "URL for PVWA API: $URL_PVWAAPI"
        $urlSearch = $Script:URL_UserSearch -f $Username
        Write-LogMessage -type Verbose -MSG "URL for user search: $urlSearch"
        $searchResult = $(Invoke-Rest -Uri $urlSearch -Header $g_LogonHeader -Command "Get")
        if ($searchResult.Total -gt 0){
            $userFound = $false
            foreach ($account in $searchResult.users) {
                if ($account.username -ieq $Username -and $account.componentUser){
                    try {       
                        $userFound = $true
                        $accountID = $account.id
                        
                        $bodyActivate =@{id =$accountID} | ConvertTo-Json -Depth 3 -Compress
                        $urlActivate = $Script:URL_Activate -f $accountID
                        $null = Invoke-Rest -Uri $urlActivate -Header $g_LogonHeader -Command "Post" -Body $bodyActivate

                        $bodyReset = @{ id=$accountID;newPassword=$(Convert-SecureString($Password))} | ConvertTo-Json -Depth 3 -Compress
                        $urlReset = $Script:URL_UserResetPassword -f $accountID
                        $null = Invoke-Rest -Uri $urlReset -Header $g_LogonHeader -Command "Post" -Body $bodyReset
                    } catch {
                        Throw $_   
                    }
                }
            }
            If (!$userFound) {Write-LogMessage -type Verbose -MSG "Unable to locate component account for $Username"}
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
Function New-RandomPassword{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # Length, Type uint32, Length of the random string to create.
        [Parameter(Mandatory=$true, Position=0)]
        [ValidatePattern('[0-9]+')]
        [ValidateRange(1,100)]
        [uint32]$Length,

        # Lowercase, Type switch, Use lowercase characters.
        [Parameter(Mandatory=$false)]
        [switch]$Lowercase=$false,
        
        # Uppercase, Type switch, Use uppercase characters.
        [Parameter(Mandatory=$false)]
        [switch]$Uppercase=$false,

        # Numbers, Type switch, Use alphanumeric characters.
        [Parameter(Mandatory=$false)]
        [switch]$Numbers=$false,

        # Symbols, Type switch, Use symbol characters.
        [Parameter(Mandatory=$false)]
        [switch]$Symbols=$false
    )
    Begin {
        if (-not($Lowercase -or $Uppercase -or $Numbers -or $Symbols)) {
            throw "You must specify one of: -Lowercase -Uppercase -Numbers -Symbols"
        }

        # Specifies bitmap values for character sets selected.
        $CHARSET_LOWER=1
        $CHARSET_UPPER=2
        $CHARSET_NUMBER=4
        $CHARSET_SYMBOL=8

        # Creates character arrays for the different character classes, based on ASCII character values.
        $charsLower=97..122 | ForEach-Object{ [Char] $_ }
        $charsUpper=65..90 | ForEach-Object{ [Char] $_ }
        $charsNumber=48..57 | ForEach-Object{ [Char] $_ }
        $charsSymbol=33,35,37,42,43,44,45,46,95 | ForEach-Object{ [Char] $_ }

        Write-LogMessage -type Verbose -MSG "The following symbols may be selected $charSymbol"
        
    }
    Process {
        # Contains the array of characters to use.
        $charList=@()
        $charSets=0
        if ($Lowercase) {
            $charList+=$charsLower
            $charSets=$charSets -bor $CHARSET_LOWER
        }
        if ($Uppercase) {
            $charList+=$charsUpper
            $charSets=$charSets -bor $CHARSET_UPPER
        }
        if ($Numbers) {
            $charList+=$charsNumber
            $charSets=$charSets -bor $CHARSET_NUMBER
        }
        if ($Symbols) {
            $charList+=$charsSymbol
            $charSets=$charSets -bor $CHARSET_SYMBOL
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
            $flags=0
            $output=""
            # Create output string containing random characters.
            1..$Length | ForEach-Object { $output+=$charList[(Get-Random -Maximum $charList.Length)] }

            # Check if character classes match.
            if ($Lowercase) {
                if (Test-StringContents $output $charsLower) {
                    $flags=$flags -bor $CHARSET_LOWER
                }
            }
            if ($Uppercase) {
                if (Test-StringContents $output $charsUpper) {
                    $flags=$flags -bor $CHARSET_UPPER
                }
            }
            if ($Numbers) {
                if (Test-StringContents $output $charsNumber) {
                    $flags=$flags -bor $CHARSET_NUMBER
                }
            }
            if ($Symbols) {
                if (Test-StringContents $output $charsSymbol) {
                    $flags=$flags -bor $CHARSET_SYMBOL
                }
            }
        }
        until ($flags -eq $charSets)
    }
    End {   
        $output
    }
}

Function Convert-SecureString{

    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # Length, Type uint32, Length of the random string to create.    [Parameter(Mandatory=$true, Position=0)]
        [secureString]$secureString
    )

    Process{

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }
}

Function Stop-ServiceProcess{
    [CmdletBinding()]
    
    Param
    (
        [Parameter(Mandatory=$True,ValuefromPipeline=$True)]
        [string[]]$name
    )
    
    Process{
        $name
        $id = Get-WmiObject -Class Win32_Service -Filter "Name LIKE '$name'" | Select-Object -ExpandProperty ProcessId
        if (0 -ne $id){
            Stop-Process -Id $id -Force
        }
    }
}

function Reset-PVWACredentials{
    param (
        [Parameter(Mandatory=$true)]
        [string]$Server

    )
    $complete = $failed = $false
    $attempts = 0
    While (!$complete -and !$failed) {
        If ($PVWAURL -match $server) {
            Write-LogMessage -type Error -MSG "Unable to reset credentials of PVWA being used by script"
            break
        }
        try {
            Try {
                $session = New-PSLogon $server
            } Catch {
                Write-LogMessage -type Error -MSG "Unable to connect to winRM on $server. Verify this is a windows server and winRM has been enabled."             
                break
            }
            Write-LogMessage -type info -MSG "Connected to $Server and starting to reset PVWA Credentials"
            Write-LogMessage -type Verbose -MSG "Connected to $Server. Importing required modules"
            
            Import-ModuleRemotely -moduleName CyberArk-Common -session $Session
            Write-LogMessage -type Verbose -MSG "Modules imported. Getting information about the installed components"
            
            $compInfo = Get-ComponentInfo -Server $Server -ComponentType "PVWA" -Session $Session          
            $installLocation = $compInfo.path
            [version]$version = $compInfo.Version
            Write-LogMessage -type Verbose -MSG "Retrived Component Information"
            Write-LogMessage -type Verbose -MSG "Installation path : $installLocation"
            Write-LogMessage -type Verbose -MSG "Version: $version"

            Write-LogMessage -type Verbose -MSG "Attempting to stop PVWA Services" 
            Stop-ComponentService -services $Script:g_pvwaservices -session $session -server $server
            Invoke-Command -Session $session -ScriptBlock{iisreset /stop} -OutVariable iisresetStopResult | Out-Null

            if (!$iisresetStopResult[3] -contains "Internet Information Services successfully stopped") {
                $failed = $true
                Write-LogMessage -type Error -MSG "Error while trying to Internet Information Services"
                Throw "Error Stopping IIS"; 
                
            }
            Write-LogMessage -type Verbose -MSG "Stopped PVWA Services"
            Write-LogMessage -type Verbose -MSG "Updating PVWA credential files"

            Invoke-Command -Session $session -ScriptBlock {Set-Location -Path ($args[0]+"\Env");} -ArgumentList $installLocation
            $appuserItem = Invoke-Command -Session $session -ScriptBlock {((Select-String -Path ..\CredFiles\appuser.ini -Pattern "username=").Line).split("=")[1]}
            Write-LogMessage -type Verbose -MSG "AppUser Username: $appuserItem"
            
            $tempPassword = New-RandomPassword -Length 14 -Lowercase -Uppercase -Numbers -Symbols | ConvertTo-SecureString -AsPlainText -Force 
            $tag = [DateTimeOffset]::Now.ToUnixTimeSeconds()
            Invoke-Command -Session $session -ScriptBlock {Rename-Item "..\CredFiles\appuser.ini" -NewName "appuser.ini.$($args[0])" -Force} -ArgumentList $tag
            Invoke-Command -Session $session -ScriptBlock {Rename-Item "..\CredFiles\appuser.ini.entropy" -NewName "appuser.ini.entropy.$($args[0])" -Force} -ArgumentList $tag
            Write-LogMessage -type Verbose -MSG "Backed up APPUser credential files"
        
            if ($version -ge [version]'12.1'){
                $appcommand = $g_pvwaappuserCredv12 -f $appuserItem, $(Convert-SecureString($tempPassword))
            } else {
                $appcommand = $g_pvwaappuserCred -f $appuserItem, $(Convert-SecureString($tempPassword))
            }

            Invoke-Command -Session $session -ScriptBlock {Invoke-Expression $args[0];} -ArgumentList $appcommand -ErrorAction SilentlyContinue -ErrorVariable invokeResultApp
            Remove-Variable appcommand
            Write-LogMessage -type Verbose -MSG "Ran CreateCredFile on AppUser"
		
            If ($invokeResultApp[0].TargetObject -ne "Command ended successfully"){
                Invoke-Command -Session $session -ScriptBlock {Rename-Item "..\CredFiles\appuser.ini.$($args[0])" -NewName "appuser.ini" -Force} -ArgumentList $tag
                Invoke-Command -Session $session -ScriptBlock {Rename-Item "..\CredFiles\appuser.ini.entropy.$($args[0])" -NewName "appuser.ini.entropy" -Force -ErrorAction SilentlyContinue} -ArgumentList $tag
			
                $failed = $true
                Write-LogMessage -type Error -MSG "Error while resetting AppUser on  $server"
                Throw "Error resetting AppUser credential file on $server"
            } else {
                Invoke-Command -Session $session -ScriptBlock {Remove-Item "..\CredFiles\appuser.ini.$($args[0])" -Force} -ArgumentList $tag
                Invoke-Command -Session $session -ScriptBlock {Remove-Item "..\CredFiles\appuser.ini.entropy.$($args[0])" -Force -ErrorAction SilentlyContinue} -ArgumentList $tag
			
            }
            
            Write-LogMessage -type Verbose -MSG "CreateCredFile on AppUser successful"

            Write-LogMessage -type Verbose -MSG "Updating GWUser credential files"

            $gwuserItem = Invoke-Command -Session $session -ScriptBlock {((Select-String -Path ..\CredFiles\gwuser.ini -Pattern "username=").Line).split("=")[1]}
            Write-LogMessage -type Verbose -MSG "GWUser Username: $gwuserItem"

            Invoke-Command -Session $session -ScriptBlock {Rename-Item "..\CredFiles\gwuser.ini" -NewName "gwuser.ini.$($args[0])" -Force} -ArgumentList $tag
            Invoke-Command -Session $session -ScriptBlock {Rename-Item "..\CredFiles\gwuser.ini.entropy" -NewName "gwuser.ini.entropy.$($args[0])" -Force} -ArgumentList $tag
		
            Write-LogMessage -type Verbose -MSG "Backed up GWUser credential files"

            if ($version -ge [version]'12.1'){
                $gwcommand = $g_pvwagwuserCredv12 -f $gwuserItem, $(Convert-SecureString($tempPassword))
            } else {
                $gwcommand = $g_pvwagwuserCred -f $gwuserItem, $(Convert-SecureString($tempPassword))
            }

            Invoke-Command -Session $session -ScriptBlock {Invoke-Expression $args[0];} -ArgumentList $gwcommand -ErrorAction SilentlyContinue -ErrorVariable invokeResultGw
            Remove-Variable gwcommand
           
            If ($invokeResultGW[0].TargetObject -ne "Command ended successfully"){
                Invoke-Command -Session $session -ScriptBlock {Rename-Item "..\CredFiles\gwuser.ini.$($args[0])" -NewName "gwuser.ini" -Force} -ArgumentList $tag
                Invoke-Command -Session $session -ScriptBlock {Rename-Item "..\CredFiles\gwuser.ini.entropy.$($args[0])" -NewName "gwuser.ini.entropy" -Force} -ArgumentList $tag
                Write-LogMessage -type Error -MSG "Error while resetting GWUser"
                $failed = $true
                Throw "Error resetting Gateway credential file"
            } else {
                Invoke-Command -Session $session -ScriptBlock {Remove-Item "..\CredFiles\gwuser.ini.$($args[0])" -Force} -ArgumentList $tag
                Invoke-Command -Session $session -ScriptBlock {Remove-Item "..\CredFiles\gwuser.ini.entropy.$($args[0])" -Force -ErrorAction SilentlyContinue} -ArgumentList $tag
            }

            Write-LogMessage -type Verbose -MSG "CreateCredFile on GWUser successful"
            Write-LogMessage -type Verbose -MSG "Updating AppUser via RESTAPI"
            Set-UserPassword -username $appuserItem -Password $tempPassword
            Write-LogMessage -type Verbose -MSG "Update of AppUser via RESTAPI Complete"
            Write-LogMessage -type Verbose -MSG "Updating GWUser via RESTAPI"
            Set-UserPassword -username $gwuserItem -Password $tempPassword
            Write-LogMessage -type Verbose -MSG "Update of GWUser via RESTAPI Complete"

            Write-LogMessage -type Verbose -MSG "Attempting to start Internet Information Services"
            Invoke-Command -Session $session -ScriptBlock{iisreset /start} -OutVariable iisresetStartResult | Out-Null
                      
            if (!$iisresetStartResult[3] -contains "Internet Information Services successfully started") {
                $failed = $true
                Write-LogMessage -type Error -MSG "Error Starting Internet Information Services"
                Throw "Error Starting Internet Information Services" 
            }
            Write-LogMessage -type Verbose -MSG "Started Internet Information Services" 

            Write-LogMessage -type Verbose -MSG "Attempting to start PVWA Services"  
            $complete = Start-ComponentService -services $Script:g_pvwaservices -session $session -server $server
            Write-LogMessage -type Verbose -MSG "Started PVWA Services"  

            $attempts += 1
    
            if ($attempts -gt 5) {$failed = $true;Throw}

            if ($complete) {
                Write-LogMessage -type Info -MSG "PVWA on $server reset completed successful"
            } else {
                Write-LogMessage -type Info -MSG "PVWA on $server reset failed, restarting"
            }


        } catch {
            Write-LogMessage -type Error -MSG "Error during reset of PVWA on $server"
            Throw $_
        }

        Finally {
            Write-LogMessage -type Verbose -MSG "Disconnecting from $server"  
            Remove-PSSession $session
            Write-LogMessage -type Verbose -MSG "Disconnected from $server"
        }
    }
}

function Reset-PSMCredentials{
    param (
        [Parameter(Mandatory=$true)]
        [string]$Server

    )
    $complete = $failed = $false
    $attempts = 0
    While (!$complete -and !$failed) {

        try {

            <#

        $session = New-PSSession $server
        Add the ability to use alt credentials

        Do as function due to reuse in multiple places
        $User = "administrator"
        $PWord = ConvertTo-SecureString -String "Cyberark1!" -AsPlainText -Force
        $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord
        
#>

            Try {
                $session = New-PSLogon $server
            } Catch {
                Write-LogMessage -type Error -MSG "Unable to connect to winRM on $server. Verify this is a windows server and winRM has been enabled."             
                break
            }
            Write-LogMessage -type info -MSG "Connected to $Server and reseting PSM Credentials"
            Write-LogMessage -type Verbose -MSG "Connected to $Server. Importing required modules"            
            Import-ModuleRemotely -moduleName CyberArk-Common -session $Session

            Write-LogMessage -type Verbose -MSG "Modules imported. Getting information about the installed components"
            $compInfo = Get-ComponentInfo -Server $Server -ComponentType "PSM" -Session $Session

            $installLocation = $compInfo.path
            [version]$version = $compInfo.Version
            Write-LogMessage -type Verbose -MSG "Retrived Component Information"
            Write-LogMessage -type Verbose -MSG "Installation path : $installLocation"
            Write-LogMessage -type Verbose -MSG "Version: $version"

            Write-LogMessage -type Verbose -MSG "Attempting to stop PSM Services" 
            Stop-ComponentService -services $Script:g_psmservices -session $session -server $server
            Write-LogMessage -type Verbose -MSG "PSM Stopped. Updating credential files" 

            $tempPassword = New-RandomPassword -Length 14 -Lowercase -Uppercase -Numbers -Symbols | ConvertTo-SecureString -AsPlainText -Force 
            $tag = [DateTimeOffset]::Now.ToUnixTimeSeconds()

            Invoke-Command -Session $session -ScriptBlock {Set-Location -Path ($args[0]+"\vault");} -ArgumentList $installLocation
            $appuserItem = Invoke-Command -Session $session -ScriptBlock {((Select-String -Path .\psmapp.cred -Pattern "username=").Line).split("=")[1]}
            Write-LogMessage -type Verbose -MSG "APP Username: $appuserItem"

            Invoke-Command -Session $session -ScriptBlock {Rename-Item ".\psmapp.cred" -NewName "psmapp.cred.$($args[0])" -Force} -ArgumentList $tag
            Invoke-Command -Session $session -ScriptBlock {Rename-Item ".\psmapp.cred.entropy" -NewName "psmapp.cred.entropy.$($args[0])" -Force -ErrorAction SilentlyContinue} -ArgumentList $tag
            Write-LogMessage -type Verbose -MSG "Backed up APP User credential files"
            
            if ($version -ge [version]'12.1'){
                $appcommand = $g_psmappuserCredv12 -f $appuserItem, $(Convert-SecureString($tempPassword))
            } else {
                $appcommand = $g_psmappuserCred -f $appuserItem, $(Convert-SecureString($tempPassword))
            }
                    
            Invoke-Command -Session $session -ScriptBlock {Invoke-Expression $args[0];} -ArgumentList $appcommand -ErrorAction SilentlyContinue -ErrorVariable invokeResultApp
            Remove-Variable appcommand
		
            If ($invokeResultApp[0].TargetObject -ne "Command ended successfully"){
                Invoke-Command -Session $session -ScriptBlock {Rename-Item ".\psmapp.cred.$($args[0])" -NewName "psmapp.cred" -Force} -ArgumentList $tag
                Invoke-Command -Session $session -ScriptBlock {Rename-Item ".\psmapp.cred.entropy.$($args[0])" -NewName "psmapp.cred.entropy" -Force -ErrorAction SilentlyContinue} -ArgumentList $tag | Out-Null
                $failed = $true
                Write-LogMessage -type Error -MSG "Error while resetting AppUser on $server"
                Throw "Error while resetting AppUser on $server"
                
            } else {
                Invoke-Command -Session $session -ScriptBlock {Remove-Item ".\psmapp.cred.$($args[0])" -Force} -ArgumentList $tag
                Invoke-Command -Session $session -ScriptBlock {Remove-Item ".\psmapp.cred.entropy.$($args[0])" -Force -ErrorAction SilentlyContinue} -ArgumentList $tag
            }
            Write-LogMessage -type Verbose -MSG "APP CreateCredFile on PSM successful"
            Write-LogMessage -type Verbose -MSG "Updating PSM APP User via RESTAPI"
            Set-UserPassword -username $appuserItem -Password $tempPassword
            Write-LogMessage -type Verbose -MSG "Update of PSM APP User via RESTAPI Complete"


            $gwuserItem = Invoke-Command -Session $session -ScriptBlock {((Select-String -Path .\psmgw.cred -Pattern "username=").Line).split("=")[1]}
            Write-LogMessage -type Verbose -MSG "GW Username: $gwuserItem"

            Invoke-Command -Session $session -ScriptBlock {Rename-Item ".\psmgw.cred" -NewName "psmgw.cred.$($args[0])" -Force} -ArgumentList $tag
            Invoke-Command -Session $session -ScriptBlock {Rename-Item ".\psmgw.cred.entropy" -NewName "psmgw.cred.entropy.$($args[0])" -Force} -ArgumentList $tag
            Write-LogMessage -type Verbose -MSG "Backed up GW User credential files"

            if ($version -ge [version]'12.1'){
                $gwcommand = $g_psmgwuserCredv12 -f $gwuserItem, $(Convert-SecureString($tempPassword))
            } else {
                $gwcommand = $g_psmgwuserCred -f $gwuserItem, $(Convert-SecureString($tempPassword))
            }
            
            Invoke-Command -Session $session -ScriptBlock {Invoke-Expression $args[0];} -ArgumentList $gwcommand -ErrorAction SilentlyContinue -ErrorVariable invokeResultGW
            Remove-Variable gwcommand
            
            If ($invokeResultGW[0].TargetObject -ne "Command ended successfully"){
                Invoke-Command -Session $session -ScriptBlock {Rename-Item ".\psmgw.cred.$($args[0])" -NewName "psmgw.cred" -Force} -ArgumentList $tag
                Invoke-Command -Session $session -ScriptBlock {Rename-Item ".\psmgw.cred.entropy.$($args[0])" -NewName "psmgw.cred.entropy" -Force -ErrorAction SilentlyContinue} -ArgumentList $tag
                $failed = $true
                Write-LogMessage -type Error -MSG "Error while resetting GWUser on $server"
                Throw "Error while resetting GWUser on $server"
            } else {
                Invoke-Command -Session $session -ScriptBlock {Remove-Item ".\psmgw.cred.$($args[0])" -Force} -ArgumentList $tag
                Invoke-Command -Session $session -ScriptBlock {Remove-Item ".\psmgw.cred.entropy.$($args[0])" -Force -ErrorAction SilentlyContinue} -ArgumentList $tag
            }
            Write-LogMessage -type Verbose -MSG "GW CreateCredFile on PSM successful"
            Write-LogMessage -type Verbose -MSG "Updating PSM GW User via RESTAPI"
            Set-UserPassword -username $gwuserItem -Password $tempPassword
            Write-LogMessage -type Verbose -MSG "Update of PSM GW User via RESTAPI Complete"

            Write-LogMessage -type Verbose -MSG "Attempting to start PSM services"

            $complete = Start-ComponentService -services $Script:g_psmservices -session $session -server $server

            $attempts += 1
		
            if ($attempts -gt 5) {$failed = $true;Throw}


            if ($complete) {
                Write-LogMessage -type Info -MSG "PSM on $server reset completed successful"
            } else {
                Write-LogMessage -type Info -MSG "PSM on $server reset failed, restarting"
            }
        } catch {
            Write-LogMessage -type Error -MSG "Error during reset of PSM on $server"
            Throw $_
        } Finally {
            Write-LogMessage -type Verbose -MSG "Disconnecting from $server"  
            Remove-PSSession $session
            Write-LogMessage -type info -MSG "Disconnected from $server"
        }
    }
}
function Reset-Credentials{
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComponentType,

        [Parameter(Mandatory=$true)]
        [string]$Server,

        [Parameter(Mandatory=$true)]
        [string]$OS
    )
    IF ("Windows" -eq $os){
        switch ($ComponentType) {
            "CPM" {Reset-CPMCredentials $server; break}
            "PVWA" {Reset-PVWACredentials $server;break }
            "PSM" {Reset-PSMCredentials $server;break }
            "AAM Credential Provider" { Reset-AAMCredentialsWindows $server;break }
            "Secrets Manager Credential Providers" { Reset-AAMCredentialsWindows $server;break }
            default {Write-LogMessage -type Error -MSG "No Component Type passed for $server"}
        }
    } elseIf ("Linux" -eq $os) {
        Write-LogMessage -type Error -msg "Unable to reset PSMP credentials at this time. Manual reset required for $server"
    } else {
        Write-LogMessage -type Error -msg "Unable to determine OS type for $server"
    }
}
function Reset-CPMCredentials{
    param (
        [Parameter(Mandatory=$true)]
        [string]$Server

    )
    $complete = $failed = $false
    $attempts = 0
    While (!$complete -and !$failed) {
        try {
            Try {
                $session = New-PSLogon $server
            } Catch {
                Write-LogMessage -type Error -MSG "Unable to connect to winRM on $server. Verify this is a windows server and winRM has been enabled."             
                break
            }
            Write-LogMessage -type info -MSG "Connected to $Server and reseting CPM Credentials"
            Write-LogMessage -type Verbose -MSG "Connected to $Server. Importing required modules"

            Import-ModuleRemotely -moduleName CyberArk-Common -session $Session

            Write-LogMessage -type Verbose -MSG "Modules imported. Getting information about the installed components"
            $compInfo = Get-ComponentInfo -Server $Server -ComponentType "CPM" -Session $Session            
            $installLocation = $compInfo.path
            [version]$version = $compInfo.Version
            Write-LogMessage -type Verbose -MSG "Retrived Component Information"
            Write-LogMessage -type Verbose -MSG "Installation path : $installLocation"
            Write-LogMessage -type Verbose -MSG "Version: $version"

            Write-LogMessage -type Verbose -MSG "Attempting to stop CPM Services" 
            Stop-ComponentService -services $Script:g_cpmservices -session $session -server $server
            Write-LogMessage -type Verbose -MSG "CPM Stopped. Updating credential files" 

            Invoke-Command -Session $session -ScriptBlock {Set-Location -Path ($args[0]+"\vault");} -ArgumentList $installLocation
            $userItem = Invoke-Command -Session $session -ScriptBlock {((Select-String -Path .\user.ini -Pattern "username=").Line).split("=")[1]}
            Write-LogMessage -type Verbose -MSG "Username: $userItem"
            $tempPassword = New-RandomPassword -Length 14 -Lowercase -Uppercase -Numbers -Symbols | ConvertTo-SecureString -AsPlainText -Force 
            $tag = [DateTimeOffset]::Now.ToUnixTimeSeconds()
        
            Invoke-Command -Session $session -ScriptBlock {Rename-Item ".\user.ini" -NewName "user.ini.$($args[0])" -Force} -ArgumentList $tag
            Invoke-Command -Session $session -ScriptBlock {Rename-Item ".\user.ini.entropy" -NewName "user.ini.entropy.$($args[0])" -Force -ErrorAction SilentlyContinue } -ArgumentList $tag
            Write-LogMessage -type Verbose -MSG "Backed up credential files"

            if ($version -ge [version]'12.1'){
                $command = $g_cpmuserCredv12 -f $userItem, $(Convert-SecureString($tempPassword))
            } else {
                $command = $g_cpmuserCred -f $userItem, $(Convert-SecureString($tempPassword))
            }
            Invoke-Command -Session $session -ScriptBlock {Invoke-Expression $args[0];} -ArgumentList $command -ErrorAction SilentlyContinue -ErrorVariable invokeResult
            Remove-Variable command
            If ($invokeResult[0].TargetObject -ne "Command ended successfully"){
                Invoke-Command -Session $session -ScriptBlock {Rename-Item "user.ini.$($args[0])" -NewName "user.ini" -Force} -ArgumentList $tag
                Invoke-Command -Session $session -ScriptBlock {Rename-Item "user.ini.entropy.$($args[0])" -NewName "user.ini.entropy" -Force -ErrorAction SilentlyContinue} -ArgumentList $tag
                Write-LogMessage -type Error -MSG "Error resetting credential file on $server"
                $failed = $true
                Throw "Error resetting credential file on $server"
            } else {
                Invoke-Command -Session $session -ScriptBlock {Remove-Item ".\user.ini.$($args[0])" -Force} -ArgumentList $tag
                Invoke-Command -Session $session -ScriptBlock {Remove-Item ".\user.ini.entropy.$($args[0])" -Force -ErrorAction SilentlyContinue} -ArgumentList $tag
            }
            
            Write-LogMessage -type Verbose -MSG "CreateCredFile on CPM successful"
            Write-LogMessage -type Verbose -MSG "Updating CPM via RESTAPI"
            Set-UserPassword -username $userItem -Password $tempPassword
            Write-LogMessage -type Verbose -MSG "Update of CPM via RESTAPI Complete"
		
            Write-LogMessage -type Verbose -MSG "Attempting to start CPM services"
            $complete = Start-ComponentService -services $Script:g_cpmservices -session $session -server $server -wait 2

            $attempts += 1
    
            if ($attempts -gt 5) {
                $failed = $true;
                Write-LogMessage -type Error -MSG "Failed to reset CPM credentials on $server" 
                Throw "Failed to reset CPM credentials on $server"
            }
		
            if ($complete) {
                Write-LogMessage -type Info -MSG "CPM on $server reset completed successful"
            } else {
                Write-LogMessage -type Info -MSG "CPM on $server reset  failed, restarting"
            }


        } catch {
            Write-LogMessage -type Error -MSG "Error during reset of CPM on $server"
            Throw $_
        }

        Finally {
            Write-LogMessage -type Verbose -MSG "Disconnecting from $server"  
            Remove-PSSession $session
            Write-LogMessage -type info -MSG "Disconnected from $server"
        }
    }
}
function Reset-AAMCredentialsWindows{
    param (
        [Parameter(Mandatory=$true)]
        [string]$Server

    )
    $complete = $failed = $false
    $attempts = 0
    While (!$complete -and !$failed) {
        try {
            $complete = $failed = $false
            $attempts = 0
            While (!$complete){
                Try {
                    $session = New-PSLogon $server
                } Catch {
                    Write-LogMessage -type Error -MSG "Unable to connect to winRM on $server. Verify this is a windows server and winRM has been enabled."             
                    break
                }
                Write-LogMessage -type info -MSG "Connected to $Server and reseting Provider Credentials"
                Write-LogMessage -type Verbose -MSG "Connected to $Server. Importing required modules"
                
                Import-ModuleRemotely -moduleName CyberArk-Common -session $Session
                Write-LogMessage -type Verbose -MSG "Modules imported. Getting information about the installed components"
                
                $compInfo = Get-ComponentInfo -Server $Server -ComponentType "AIM" -Session $Session          
                
                $installLocation = $compInfo.path
                [version]$version = $compInfo.Version
                Write-LogMessage -type Verbose -MSG "Retrived Component Information"
                Write-LogMessage -type Verbose -MSG "Installation path : $installLocation"
                Write-LogMessage -type Verbose -MSG "Version: $version"

                Write-LogMessage -type Verbose -MSG "Attempting to stop AAM Services" 
                Stop-ComponentService -services $Script:g_aamservices -session $session -server $server
                Write-LogMessage -type Verbose -MSG "Stopped AAM Services"

                Write-LogMessage -type Verbose -MSG "Updating AppProviderUser credential files"
                Invoke-Command -Session $session -ScriptBlock {Set-Location -Path ($args[0]+"\vault");} -ArgumentList $installLocation
                $userItem = Invoke-Command -Session $session -ScriptBlock {((Select-String -Path .\AppProviderUser.cred -Pattern "username=").Line).split("=")[1]}
                $tempPassword = New-RandomPassword -Length 14 -Lowercase -Uppercase -Numbers -Symbols | ConvertTo-SecureString -AsPlainText -Force 
                Write-LogMessage -type Verbose -MSG "Username: $userItem"
  
                $tag = [DateTimeOffset]::Now.ToUnixTimeSeconds()
                Invoke-Command -Session $session -ScriptBlock {Rename-Item ".\AppProviderUser.cred" -NewName "AppProviderUser.cred.$($args[0])" -Force} -ArgumentList $tag
                Invoke-Command -Session $session -ScriptBlock {Rename-Item ".\AppProviderUser.cred.entropy" -NewName "AppProviderUser.cred.entropy.$($args[0])" -Force -ErrorAction SilentlyContinue} -ArgumentList $tag
                Write-LogMessage -type Verbose -MSG "Backed up AppProviderUser credential files"
                
                if ($version -ge [version]'12.0'){
                    $command = $g_aamuserCredv12 -f $userItem, $(Convert-SecureString($tempPassword))
                } else {
                    $command = $g_aamuserCred -f $userItem, $(Convert-SecureString($tempPassword))
                }

                Invoke-Command -Session $session -ScriptBlock {Invoke-Expression $args[0];} -ArgumentList $command -ErrorAction SilentlyContinue -ErrorVariable invokeResultApp
                Remove-Variable command
                If ($invokeResultApp[0].TargetObject -ne "Command ended successfully"){
                    Invoke-Command -Session $session -ScriptBlock {Rename-Item ".\AppProviderUser.cred.$($args[0])" -NewName "AppProviderUser.cred" -Force} -ArgumentList $tag | Out-Null
                    Invoke-Command -Session $session -ScriptBlock {Rename-Item ".\AppProviderUser.cred.entropy.$($args[0])" -NewName "AppProviderUser.cred.entropy" -Force -ErrorAction SilentlyContinue} -ArgumentList $tag | Out-Null
			
                    Write-LogMessage -type Error -MSG "Error resetting credential file on $server"
                    $failed = $true
                    Throw "Error resetting credential file"
                } else {
                    Invoke-Command -Session $session -ScriptBlock {Remove-Item ".\AppProviderUser.cred.$($args[0])" -Force} -ArgumentList $tag
                    Invoke-Command -Session $session -ScriptBlock {Remove-Item ".\AppProviderUser.cred.entropy.$($args[0])" -Force -ErrorAction SilentlyContinue} -ArgumentList $tag
                }
        
        
                Write-LogMessage -type Verbose -MSG "CreateCredFile on AppProviderUser successful"
                Write-LogMessage -type Verbose -MSG "Updating AppProviderUser via RESTAPI"
                Set-UserPassword -username $userItem -Password $tempPassword
                Write-LogMessage -type Verbose -MSG "Update of AppUser via RESTAPI Complete"

                Write-LogMessage -type Verbose -MSG "Attempting to start AAM services"
        
                $complete = Start-ComponentService -services $Script:g_aamservices -session $session -server $server

                $attempts += 1
		
                if ($attempts -gt 5) {
                    $failed = $true;
                    Write-LogMessage -type Error -MSG "Failed to reset AAM Provider credentials on $server" 
                    Throw "Failed to reset AAM Provider credentials on $server"
                }

                Write-LogMessage -type Verbose -MSG "AAM Provider Started"

                if ($complete) {
                    Write-LogMessage -type Info -MSG "AAM on $server reset completed successful"
                } else {
                    Write-LogMessage -type Info -MSG "AAM on $server reset failed, restarting"
                }
    
    
            }
        } catch {
            Write-LogMessage -type Error -MSG "Error during reset of AAM on $server"
            Throw $_
        }

        Finally {
            Write-LogMessage -type Verbose -MSG "Disconnecting from $server"  
            Remove-PSSession $session
            Write-LogMessage -type info -MSG "Disconnected from $server"
        }
    }
}

function Get-ComponentInfo{
    param (
        [Parameter(Mandatory=$true)]
        [string]$Server,
        [Parameter(Mandatory=$false)]
        [string]$ComponentType,
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.Runspaces.PSSession]$Session

    )
    $newSession = $false
    try {
		
        if($Session.State -ne "Opened"){
            $newSession = $true
            $Session = New-PSLogon $server
        }
        $ComponentsFound = Invoke-Command -Session $Session -ScriptBlock {Find-Components $args[0]} -ArgumentList $ComponentType
        return $ComponentsFound

    } catch {
        Throw "error"
    } Finally {
        If($newSession) {Remove-PSSession $Session}
    }

}

Function Get-ComponentStatus{

    try {
        $restResponse = $(Invoke-Rest -Uri $URL_HealthSummery -Header $g_LogonHeader -Command "Get")	
        $selection = $restResponse.Components | Where-Object {$_.ComponentTotalCount -gt 0} | Select-Object @{Name="Component Type"; Expression = {$_.'ComponentName'} },@{Name="Amount Connected"; Expression = {$_.'ConnectedComponentCount'} },@{Name="Total Amount"; Expression = {$_.'ComponentTotalCount'} } | Sort-Object -Property "Component Type" 
        Return $selection
    } catch {
        return $null
    }
}
Function Get-ComponentDetails{

    param (
        [Parameter(Mandatory=$true)]
        $component
    )

    switch ($component) {
        "PSM/PSMP" { $targetComp = "SessionManagement"; break }
        "Secrets Manager Credential Providers" { $targetComp = "AIM"; break }
        "AAM Credential Provider" { $targetComp = "AIM"; break }
        Default {$targetComp = $component}
    } 
    $URLHealthDetails= $URL_HealthDetails -f $targetComp
    Try{
        $restResponse = $(Invoke-Rest -Uri $URLHealthDetails -Header $g_LogonHeader -Command "Get")

        $selection = $restResponse.ComponentsDetails | Select-Object @{Name="Component Type"; Expression = {$component} },@{Name="Component Version"; Expression = {$_.ComponentVersion} },@{Name="IP Address"; Expression = {$_.'ComponentIP'} },@{Name="Component User"; Expression = {$_.'ComponentUserName'} },@{Name="Connected"; Expression = {$_.'IsLoggedOn'}},@{Name="Last Connection"; Expression = {Get-LogonTimeUnixTime $_.'LastLogonDate'}} | Sort-Object -Property "IP Address" 
		
        #$selection = $restResponse.ComponentsDetails | Select-Object @{Name="Component Type"; Expression = {$component} },@{Name="IP Address"; Expression = {$_.'ComponentIP'} },@{Name="Component User"; Expression = {$_.'ComponentUserName'} },@{Name="Connected"; Expression = {$_.'IsLoggedOn'}},@{Name="Last Connection"; Expression = {Get-LogonTimeUnixTime $_.'LastLogonDate'}} | Sort-Object -Property "IP Address" | Out-GridView -OutputMode Multiple -Title "Select Server(s)"
		
        Return $selection
    } Catch{
        Return $null
    }
}

Function Test-TargetWinRM {
    param (
        [Parameter()]
        [string]$server
    )
    try {
        If ($null -ne $G_PSCredentials) {
            Invoke-Command -ComputerName $server -ScriptBlock {$null} -ErrorAction Stop -ErrorVariable $null -Credential $G_PSCredentials | Out-Null
        } else {
            Invoke-Command -ComputerName $server -ScriptBlock {$null} -ErrorAction Stop -ErrorVariable $null | Out-Null
        }   
        Return $true
    } catch {
        Return $false
    }
}

function New-PSLogon {
    param (
        [Parameter()]
        [string]$server
    )
    If ($null -ne $G_PSCredentials) {
        Return New-PSSession $server -Credential $G_PSCredentials -Authentication Negotiate 
    } else {   
        return New-PSSession $server
    }
}