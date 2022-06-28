[cmdletBinding()]
param
(
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com/passwordvault)")]
	#[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,

	[Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark","ldap")]
	[String]$AuthType="cyberark",

    [Parameter(Mandatory=$false)]
	[Switch]$DisableSSLVerify

)

If($DisableSSLVerify)
{
	try{

		[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $DisableSSLVerify }
	} catch {
		Write-LogMessage -Type Error -MSG "Could not change SSL validation"
		Write-LogMessage -Type Error -MSG (Join-ExceptionMessage $_.Exception) -ErrorAction "SilentlyContinue"
		return
	}
}
Else
{
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
    $caption = "Get accounts"
    $msg = "Enter your User name and Password"; 
    $creds = $Host.UI.PromptForCredential($caption,$msg,"","")
	if ($null -ne $creds)
	{
		$rstusername = $creds.username.Replace('\','');    
		$rstpassword = $creds.GetNetworkCredential().password
	}
	else { exit }
#endregion

$authBody = @{ username=$rstusername;password=$rstpassword;concurrentSession="true" } | ConvertTo-Json -Compress
$logonToken = Invoke-RestMethod -Uri "$PVWAURL/API/Auth/$AuthType/Logon" -Method 'POST' -ContentType "application/json" -Body $authBody
If ([string]::IsNullOrEmpty($logonToken)) {"No logon token found"; break}
$logonHeader = @{Authorization = $logonToken}
try {
    Invoke-RestMethod "$PVWAURL/api/DiscoveredAccounts" -Method 'DELETE' -Headers $logonHeader
    "Invoked Delete All Pending accounts successfully"
}
catch {
    "Invoke Delete All Pending accounts failed"
}
Finally
{
    $null = Invoke-RestMethod "$PVWAURL/API/Auth/Logoff" -Method 'POST' -Headers $logonHeader
}