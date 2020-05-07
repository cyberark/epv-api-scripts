$global:g_LogonHeader = ""
# Global URLS
# -----------
$global:URL_Server = $URL_PVWAAPI+"/Server"

#region Custom REST Exceptions
# @FUNCTION@ ======================================================================================================================
# Name...........: Add-RESTException
# Description....: Loads a custom CyberArk REST Exception
# Parameters.....: None
# Return Values..: None
# =================================================================================================================================
Function Add-RESTException
{
<# 
.SYNOPSIS 
	Method to create a new CyberArk REST custom Exception

.DESCRIPTION
	Create a new CyberArk REST custom Exception
#>
	param()
	try{ [CYBRRESTException] -as [type] | out-null }
	catch {
		Add-Type @"
using System;
using System.IO;
using System.Net;

public class CYBRRESTException : System.Exception
{
    public string CyberArkErrorMessage { get; set; }
    public HttpStatusCode StatusCode { get; set; }
    public string StatusDescription { get; set; }
    public string ResponseBody { get; set; }

    public CYBRRESTException(string message, System.Net.WebException inner) : base(message, inner)
    {
        if (inner.Response != null)
        {
            this.StatusDescription = inner.Message;
            if (((HttpWebResponse)inner.Response).StatusDescription != null)
            {
                this.CyberArkErrorMessage = ((HttpWebResponse)inner.Response).StatusDescription;
            }
            this.StatusCode = ((HttpWebResponse)inner.Response).StatusCode;

            System.IO.Stream result = ((HttpWebResponse)inner.Response).GetResponseStream();
            System.IO.StreamReader reader = new System.IO.StreamReader(result);
            this.ResponseBody = reader.ReadToEnd();
        }
    }
}
"@
	}
}

#endregion

Add-RESTException

#region Writer Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Write-LogMessage
# Description....: Writes the message to log and screen
# Parameters.....: LogFile, MSG, (Switch)Header, (Switch)SubHeader, (Switch)Footer, Type
# Return Values..: None
# =================================================================================================================================
Function Write-LogMessage
{
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
		[ValidateSet("Info","Warning","Error","Debug","Verbose")]
		[String]$type = "Info",
		[Parameter(Mandatory=$false)]
		[String]$LogFile = $LOG_FILE_PATH
	)
	Try{
		If([string]::IsNullOrEmpty($LogFile))
		{
			# Create a temporary log file
			$LogFile = "$ScriptLocation\tmp.log"
		}
		
		If ($Header) {
			"=======================================" | Out-File -Append -FilePath $LogFile 
		}
		ElseIf($SubHeader) { 
			"------------------------------------" | Out-File -Append -FilePath $LogFile 
		}
		
		$msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
		# Replace empty message with 'N/A'
		if([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
		
		# Mask Passwords
		if($Msg -match '((?>password|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=(\w+))')
		{
			$Msg = $Msg.Replace($Matches[2],"****")
		}
		$writeToFile = $true
		# Check the message type
		switch ($type)
		{
			"Info" { 
				Write-Host $MSG.ToString()
				$msgToWrite += "[INFO]`t$Msg"
				break
			}
			"Warning" {
				Write-Host $MSG.ToString() -ForegroundColor DarkYellow
				$msgToWrite += "[WARNING]`t$Msg"
				break
			}
			"Error" {
				Write-Host $MSG.ToString() -ForegroundColor Red
				$msgToWrite += "[ERROR]`t$Msg"
				break
			}
			"Debug" { 
				if($InDebug -or $InVerbose)
				{
					Write-Debug $MSG
					$msgToWrite += "[DEBUG]`t$Msg"
					break
				}
				else { $writeToFile = $False }
			}
			"Verbose" { 
				if($InVerbose)
				{
					Write-Verbose $MSG
					$msgToWrite += "[VERBOSE]`t$Msg"
					break
				}
				else { $writeToFile = $False }
			}
		}
		If($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LogFile }
		If ($Footer) { 
			"=======================================" | Out-File -Append -FilePath $LogFile 
		}
	}
	catch{
		Throw $(New-Object System.Exception ("Cannot write message '$Msg' to file '$Logfile'",$_.Exception))
	}
}
Export-ModuleMember -Function Write-LogMessage

# @FUNCTION@ ======================================================================================================================
# Name...........: Join-ExceptionMessage
# Description....: Formats exception messages
# Parameters.....: Exception
# Return Values..: Formatted String of Exception messages
# =================================================================================================================================
Function Join-ExceptionMessage
{
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
Export-ModuleMember -Function Join-ExceptionMessage
#endregion

#region HTTP REST Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Encode-URL
# Description....: HTTP Encode test in URL
# Parameters.....: Text to encode
# Return Values..: Encoded HTML URL text
# =================================================================================================================================
Function Encode-URL($sText)
{
<# 
.SYNOPSIS 
	HTTP Encode test in URL
.DESCRIPTION
	HTTP Encode test in URL
.PARAMETER sText
	The text to encode
#>
	if ($sText.Trim() -ne "")
	{
		Write-LogMessage -Type Debug -Msg "Returning URL Encode of $sText"
		return [System.Web.HttpUtility]::UrlEncode($sText)
	}
	else
	{
		return $sText
	}
}
Export-ModuleMember -Function Encode-URL

# @FUNCTION@ ======================================================================================================================
# Name...........: Disable-SSLVerification
# Description....: Disables the SSL Verification (bypass self signed SSL certificates)
# Parameters.....: None
# Return Values..: None
# =================================================================================================================================
Function Disable-SSLVerification
{
<# 
.SYNOPSIS 
	Bypass SSL certificate validations
.DESCRIPTION
	Disables the SSL Verification (bypass self signed SSL certificates)
#>
	# Using Proxy Default credentials if the Server needs Proxy credentials
	[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
	# Using TLS 1.2 as security protocol verification
	[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
	# Disable SSL Verification
	if (-not("DisableCertValidationCallback" -as [type])) {
    add-type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class DisableCertValidationCallback {
    public static bool ReturnTrue(object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors) { return true; }

    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(DisableCertValidationCallback.ReturnTrue);
    }
}
"@ }

	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = [DisableCertValidationCallback]::GetDelegate()
}
Export-ModuleMember -Function Disable-SSLVerification

# @FUNCTION@ ======================================================================================================================
# Name...........: Invoke-Rest
# Description....: Invoke REST Method
# Parameters.....: Command method, URI, Header, Body
# Return Values..: REST response
# =================================================================================================================================
Function Invoke-Rest
{
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
	(Optional) The Error Action to perform in case of error. By deault "Continue"
#>
	param (
		[Parameter(Mandatory=$true)]
		[ValidateSet("GET","POST","DELETE","PATCH")]
		[String]$Command, 
		[Parameter(Mandatory=$true)]
		[String]$URI, 
		[Parameter(Mandatory=$false)]
		$Header, 
		[Parameter(Mandatory=$false)]
		[String]$Body, 
		[Parameter(Mandatory=$false)]
		[ValidateSet("Continue","Ignore","Inquire","SilentlyContinue","Stop","Suspend")]
		[String]$ErrAction="Continue"
	)
	
	If ((Test-CommandExists Invoke-RestMethod) -eq $false)
	{
	   Throw "This script requires PowerShell version 3 or above"
	}
	$restResponse = ""
	try{
		if($Command -match "GET")
		{
			Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -TimeoutSec 36000"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -TimeoutSec 36000
		} else {
			Write-LogMessage -Type Verbose -Msg "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body -TimeoutSec 36000"
			$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body -TimeoutSec 36000

		}
	} catch [System.Net.WebException] {
		Throw $(New-Object CYBRRESTException ("Invoke-Rest: Error in running $Command on '$URI'",$_.Exception))
		$restResponse = $null
	} catch { 
		Throw $(New-Object System.Exception ("Invoke-Rest: Unknown Error in running $Command on '$URI'",$_.Exception))
	}
	Write-LogMessage -Type Verbose -Msg "Invoke-REST Response: $restResponse"
	return $restResponse
}
Export-ModuleMember -Function Invoke-Rest

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-LogonHeader
# Description....: Invoke REST Method
# Parameters.....: Credentials
# Return Values..: Logon Header
# =================================================================================================================================
Function Get-LogonHeader
{
<# 
.SYNOPSIS 
	Get-LogonHeader
.DESCRIPTION
	Get-LogonHeader
.PARAMETER Credentials
	The REST API Credentials to authenticate
#>
	param(
		[Parameter(Mandatory=$false)]
		[PSCredential]$Credentials
	)

	if([string]::IsNullOrEmpty($g_LogonHeader))
	{
		if($null -eq $Credentials)
		{
			Throw "Get-LogonHeader: Credentials are needed to login"
		}
		# Create the POST Body for the Logon
		# ----------------------------------
		$logonBody = @{ username=$Credentials.username.Replace('\','');password=$Credentials.GetNetworkCredential().password } | ConvertTo-Json
		try{
			# Logon
			$logonToken = Invoke-Rest -Command Post -Uri $URL_Logon -Body $logonBody
			
			# Clear logon body
			$logonBody = ""
		} catch {
			Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.Exception.Response.StatusDescription)",$_.Exception))
		}

		$logonHeader = $null
		If ([string]::IsNullOrEmpty($logonToken))
		{
			Throw "Get-LogonHeader: Logon Token is Empty - Cannot login"
		}
		
		# Create a Logon Token Header (This will be used through out all the script)
		# ---------------------------
		$logonHeader =  New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
		$logonHeader.Add("Authorization", $logonToken)
		Set-Variable -Name g_LogonHeader -Value $logonHeader -Scope global		
	}
	
	return $g_LogonHeader
}
Export-ModuleMember -Function Get-LogonHeader

# @FUNCTION@ ======================================================================================================================
# Name...........: Invoke-Logon
# Description....: Logon PVWA
# Parameters.....: Credentials
# Return Values..: None
# =================================================================================================================================
Function Invoke-Logon
{
<# 
.SYNOPSIS 
	Invoke-Logon
.DESCRIPTION
	Logon to PVWA using credentials
.PARAMETER Credentials
	The REST API Credentials to authenticate
#>
	param(
		[Parameter(Mandatory=$false)]
		[PSCredential]$Credentials
	)
	try{
		# Logon to a session
		# ------------------
		Write-LogMessage -Type Info -Msg "Logging on to PVWA using entered credentials..."
		Get-LogonHeader -Credentials $Credentials
	} catch {
		Throw $(New-Object System.Exception ("Invoke-Logon: Failed to logon to a session",$_.Exception))
	}
}
Export-ModuleMember -Function Invoke-Logon

# @FUNCTION@ ======================================================================================================================
# Name...........: Invoke-Logoff
# Description....: Logoff PVWA
# Parameters.....: None
# Return Values..: None
# =================================================================================================================================
Function Invoke-Logoff
{
	try{
		# Logoff the session
		# ------------------
		Write-LogMessage -Type Info -Msg "Logoff Session..."
		Invoke-Rest -Command Post -Uri $URL_Logoff -Header $g_LogonHeader | out-null
		Set-Variable -Name g_LogonHeader -Value $null -Scope global
	} catch {
		Throw $(New-Object System.Exception ("Invoke-Logoff: Failed to logoff session",$_.Exception))
	}
}
Export-ModuleMember -Function Invoke-Logoff

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-RESTVersion
# Description....: Tests if the requested version exists in the PVWA REST API
# Parameters.....: version
# Return Values..: True / False
# =================================================================================================================================
Function Test-RESTVersion
{
<# 
.SYNOPSIS 
	Tests if the requested version exists in the PVWA REST API
.DESCRIPTION
	Tests if the requested version exists in the PVWA REST API
.PARAMETER Version
	A string of the requested PVWA REST version to test
#>

    param (
		[Parameter(Mandatory=$true)]
		[string]$version
	)
	
	try{
		$retVersionExists = $false
		If(Test-RESTResource $URL_Server)
		{
			Write-LogMessage -Type debug -Msg "Testing to see if the PVWA is at least in version $version"
			$serverResponse = Invoke-REST -Command GET -URI $URL_Server
			Write-LogMessage -Type debug -Msg "The current PVWA is in version $($serverResponse.ExternalVersion)"
			$majorVersionCompare = ( [int]($serverResponse.ExternalVersion.Split('.')[0]) -ge [int]($version.Split('.')[0]) )
			$minorVersionCompare = ( [int]($serverResponse.ExternalVersion.Split('.')[1]) -ge [int]($version.Split('.')[1]) )
			if($majorVersionCompare -and $minorVersionCompare)
			{
				$retVersionExists = $true
			}
		}
		
		return $retVersionExists
	} catch {
		# Check the error code returned from the REST call
		$innerExcp = $_.Exception.InnerException
		Write-LogMessage -Type Verbose -Msg "Status Code: $($innerExcp.StatusCode); Status Description: $($innerExcp.StatusDescription); REST Error: $($innerExcp.CyberArkErrorMessage)"
		if($innerExcp.StatusCode -eq "NotFound") {
			return $false
		}
		else{
			Throw $(New-Object System.Exception ("Test-RESTVersion: There was an error checking for REST version $version.",$_.Exception))
		}
	}
}
Export-ModuleMember -Function Test-RESTVersion
#endregion

#region Internal Helper Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Test-CommandExists
# Description....: Tests if a command exists
# Parameters.....: Command
# Return Values..: True / False
# =================================================================================================================================
Function Test-CommandExists
{
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
    try { if(Get-Command $command){ return $true } }
    Catch { return $false }
    Finally {$ErrorActionPreference=$oldPreference}
} 

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-RESTResource
# Description....: Tests if a REST resource exists
# Parameters.....: REST Resource URI
# Return Values..: True / False
# =================================================================================================================================
Function Test-RESTResource
{
<# 
.SYNOPSIS 
	Tests if a REST resource exists
.DESCRIPTION
	Tests if a REST resource exists
.PARAMETER URI
	The REST Resource URI to test
#>

    Param ($URI)
	$retResponse = $false
    try{
		Invoke-Rest -URI $URI -Command GET
		$retResponse = $true
	} catch [CYBRRESTException] {
		Switch ($_.StatusCode){
			{ "400", "404" } {
				# 400: Bad Request
				# 404: Not Found
				# The resource is not found
				$retResponse = $false
			}
			{ "401", "403" } {
				# 401: Unauthorized
				# 403: Forbidden
				# The resource is found, just no permissions to access
				$retResponse = $true
			}
			"500" {
				# Something went wrong, throw the error
				throw $_
			}
		}
	}
	
	return $retResponse
} 
#endregion

#region External Helper Function
Function OpenFile-Dialog
{
<# 
.SYNOPSIS 
	Opens a new "Open File" Dialog
.DESCRIPTION
	Opens a new "Open File" Dialog
.PARAMETER LocationPath
	The Location to open the dialog in
#>
	param (
		[string]$LocationPath
	)
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $LocationPath
    $OpenFileDialog.filter = "CSV (*.csv)| *.csv"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
}
Export-ModuleMember -Function OpenFile-Dialog

Function Convert-ToBool
{
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
	else { [bool]::TryParse($txt, [ref]$retBool) }
    
    return $retBool
}
Export-ModuleMember -Function Convert-ToBool
#endregion