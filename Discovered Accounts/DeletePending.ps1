[cmdletBinding()]
param
(
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com/passwordvault)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,

	[Parameter(Mandatory = $false, HelpMessage = "Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark", "ldap", "radius")]
	[String]$AuthType = "cyberark",
	
	[Parameter(Mandatory = $false, HelpMessage = "Enter the RADIUS OTP")]
	[ValidateScript({ $AuthType -eq "radius" })]
	[String]$OTP,

	[Parameter(Mandatory=$false)]
	[Switch]$DisableSSLVerify,

	[Parameter(Mandatory = $false)]
	[Switch]$concurrentSession,

	[Parameter(Mandatory = $false, HelpMessage = "Vault Stored Credentials")]
	[PSCredential]$PVWACredentials,

	# Use this parameter to pass a pre-existing authorization token. If passed the token is NOT logged off
	[Parameter(Mandatory = $false)]
	$logonToken

)

$URL_PVWAAPI = $PVWAURL + "/api"
$URL_Authentication = $URL_PVWAAPI + "/auth"
$URL_Logon = $URL_Authentication + "/$AuthType/Logon"
$URL_Logoff = $URL_Authentication + "/Logoff"

$global:g_LogonHeader = ""

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
		[bool]$concurrentSession,
		[Parameter(Mandatory = $false)]
		[string]$RadiusOTP
	)
	# Create the POST Body for the Logon
	# ----------------------------------
	If ($concurrentSession) {
		$logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password; concurrentSession = "true" } | ConvertTo-Json -Compress
	} else {
		$logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password } | ConvertTo-Json -Compress
	}
	If (![string]::IsNullOrEmpty($RadiusOTP)) {
		$logonBody.Password += ",$RadiusOTP"
	}
	
	try {
		# Logon
		$logonToken = Invoke-RestMethod -Uri $URL_Logon -Method POST -Body $logonBody -ContentType "application/json" -TimeoutSec 2700 -ErrorAction Continue
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

If($DisableSSLVerify) {
	try{
		[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
	} catch {
		Write-LogMessage -Type Error -MSG "Could not change SSL validation"
		Write-LogMessage -Type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
		return
	}
} Else {
	try{
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
	} catch {
		Write-LogMessage -Type Error -MSG "Could not change SSL settings to use TLS 1.2"
		Write-LogMessage -Type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
	}
}


#region [Logon]
# Get Credentials to Login
# ------------------------
$caption = "Clear Pending Accounts"
If (![string]::IsNullOrEmpty($logonToken)) {
	if ($logonToken.GetType().name -eq "String") {
		$logonHeader = @{Authorization = $logonToken }
		Set-Variable -Scope Global -Name g_LogonHeader -Value $logonHeader
	} else {
		Set-Variable -Scope Global -Name g_LogonHeader -Value $logonToken
 }
} else {
	If (![string]::IsNullOrEmpty($PVWACredentials)) {
		$creds = $PVWACredentials
	} else {
		$msg = "Enter your $AuthType User name and Password" 
		$creds = $Host.UI.PromptForCredential($caption, $msg, "", "")
	}
	if ($AuthType -eq "radius" -and ![string]::IsNullOrEmpty($OTP)) {
		Set-Variable -Scope Global -Name g_LogonHeader -Value $(Get-LogonHeader -Credentials $creds -concurrentSession $concurrentSession -RadiusOTP $OTP )
	} else {
		Set-Variable -Scope Global -Name g_LogonHeader -Value $(Get-LogonHeader -Credentials $creds -concurrentSession $concurrentSession)
	}
	# Verify that we successfully logged on
	If ($null -eq $g_LogonHeader) { 
		return # No logon header, end script 
	}
}
#endregion

try {
	Invoke-RestMethod "$PVWAURL/api/DiscoveredAccounts" -Method 'DELETE' -Headers $g_LogonHeader
	"Invoked Delete All Pending accounts successfully"
} catch {
	"Invoke Delete All Pending accounts failed"
} Finally {
	If (![string]::IsNullOrEmpty($logonToken)) {
		Write-Host "LogonToken passed, session NOT logged off"
	} else {
		Write-Host "Logoff Session..."
		Invoke-RestMethod -Uri $URL_Logoff -Method POST -Header $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700 -ErrorAction Continue
		$global:g_LogonHeader = $null
	}
}