###########################################################################
#
# NAME: Update Properties to an Account using REST API
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will update account properties on a specified Account
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v10.4 and above
#
# VERSION HISTORY:
# 1.0 10/02/2020 - Initial release
#
###########################################################################
[CmdletBinding(DefaultParameterSetName="")]
param
(
	[Parameter(Mandatory=$true,HelpMessage="Enter the PVWA URL")]
	[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,
	
	[Parameter(Mandatory=$true,HelpMessage="The required Account ID")]
	[Alias("id")]
	[string]$AccountID,
	
	[Parameter(Mandatory=$true,HelpMessage="Parameter name(s) to edit")]
	[Alias("paramName")]
	[string[]]$ParameterNames,
	
	[Parameter(Mandatory=$true,HelpMessage="Parameter value(s) to edit")]
	[Alias("paramValue")]
	[string[]]$ParameterValues
)

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path

# Global URLS
# -----------
$URL_PVWAAPI = $PVWAURL+"/api"
$URL_Authentication = $URL_PVWAAPI+"/auth"
$URL_CyberArkLogon = $URL_Authentication+"/cyberark/Logon"
$URL_CyberArkLogoff = $URL_Authentication+"/Logoff"

# URL Methods
# -----------
$URL_Accounts = $URL_PVWAAPI+"/Accounts"
$URL_AccountsDetails = $URL_PVWAAPI+"/Accounts/{0}"
$URL_Platforms = $URL_PVWAAPI+"/Platforms/{0}"

# Script Defaults
# ---------------

# Initialize Script Variables
# ---------------------------
$rstusername = $rstpassword = ""
$logonToken  = ""

#region Functions
Function Test-CommandExists
{
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {if(Get-Command $command){RETURN $true}}
    Catch {Write-Host "$command does not exist"; RETURN $false}
    Finally {$ErrorActionPreference=$oldPreference}
} #end function test-CommandExists

Function Convert-Date($epochdate)
{
	if (($epochdate).length -gt 10 ) {return (Get-Date -Date "01/01/1970").AddMilliseconds($epochdate)}
	else {return (Get-Date -Date "01/01/1970").AddSeconds($epochdate)}
}

#endregion

If (Test-CommandExists Invoke-RestMethod)
{

# Check that the PVWA URL is OK
    If ($PVWAURL -ne "")
    {
        If ($PVWAURL.Substring($PVWAURL.Length-1) -eq "/")
        {
            $PVWAURL = $PVWAURL.Substring(0,$PVWAURL.Length-1)
        }
    }
    else
    {
        Write-Host -ForegroundColor Red "PVWA URL can not be empty"
        return
    }

#region [Logon]
    # Get Credentials to Login
    # ------------------------
    $caption = "Update accounts"
    $msg = "Enter your User name and Password"; 
    $creds = $Host.UI.PromptForCredential($caption,$msg,"","")
	if ($creds -ne $null)
	{
		$rstusername = $creds.username.Replace('\','');    
		$rstpassword = $creds.GetNetworkCredential().password
	}
	else { return }

    # Create the POST Body for the Logon
    # ----------------------------------
    $logonBody = @{ username=$rstusername;password=$rstpassword }
    $logonBody = $logonBody | ConvertTo-Json
	try{
	    # Logon
	    $logonToken = Invoke-RestMethod -Method Post -Uri $URL_CyberArkLogon -Body $logonBody -ContentType "application/json"
	}
	catch
	{
		Write-Host -ForegroundColor Red $_.Exception.Response.StatusDescription
		$logonToken = ""
	}
    If ($logonToken -eq "")
    {
        Write-Host -ForegroundColor Red "Logon Token is Empty - Cannot login"
        return
    }
	
    # Create a Logon Token Header (This will be used through out all the script)
    # ---------------------------
    $logonHeader =  New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $logonHeader.Add("Authorization", $logonToken)
#endregion

	# List common properties
	$excludedProperties = @("name","username","address","safe","platformid","password","key","enableautomgmt","manualmgmtreason","groupname","groupplatformid","remotemachineaddresses","restrictmachineaccesstolist","sshkey")
	$response = ""
	if($AccountID -ne "")
	{
		$GetAccountDetailsResponse = Invoke-RestMethod -Method Get -Uri $($URL_AccountsDetails -f $AccountID) -Headers $logonHeader -ContentType "application/json" -TimeoutSec 3600000
		$response = $GetAccountDetailsResponse
	}
	If([string]::IsNullOrEmpty($response))
	{
		Write-Host "Account was not found!" -ForegroundColor Red
		return
	}
	else
	{
		Write-Host "Account Details (before change):" -ForegroundColor Cyan
		$response
	}
	# Prepare the parameters body
	$arrProperties = @()
	For($i=0; $i -lt $ParameterNames.Count; $i++)
	{
		$_bodyOp = "" | select "op", "path", "value"
		$_bodyOp.op = "replace"
		# Adding a specific case for "/secretManagement/automaticManagementEnabled"
		If($ParameterNames[$i] -in @("automaticManagementEnabled","manualManagementReason"))
		{
			If($ParameterNames[$i] -like "manualManagementReason")
			{
				$_bodyOp.op = "replace"
				$_bodyOp.path = "/secretManagement/manualManagementReason"
				$_bodyOp.value = $ParameterValues[$i]
				$arrProperties += $_bodyOp
			}
			else
			{
				If($ParameterValues[$i] -eq $true)
				{
					# Need to remove the manualManagementReason
					$_bodyOp.op = "remove"
					$_bodyOp.path = "/secretManagement/manualManagementReason"
					$_bodyOp.value = ""
					$arrProperties += $_bodyOp
				}
				else
				{
					# Need to add the manualManagementReason
					$_bodyOp.op = "add"
					$_bodyOp.path = "/secretManagement/manualManagementReason"
					if([string]::IsNullOrEmpty($ParameterValues[$i]))
					{
						$_bodyOp.value = "[No Reason]"
					}
					else
					{
						$_bodyOp.value = $ParameterValues[$i]
					}
					$arrProperties += $_bodyOp
				}
			}
		}
		# Handling all other properties
		If ($ParameterNames[$i].ToLower() -notin $excludedProperties)
		{
			$_bodyOp.path = "/platformAccountProperties/"+$ParameterNames[$i]
		}
		else
		{
			$_bodyOp.path = "/"+$ParameterNames[$i]
		}
		if($i -lt $ParameterValues.Count)
		{
			$_bodyOp.value = $ParameterValues[$i]
		}
		else
		{
			$_bodyOp.value = $ParameterValues[-1]
		}
		$arrProperties += $_bodyOp
	}
	
	
	#Format the body to send
	$body = $arrProperties | ConvertTo-Json -Depth 5
	If($body[0] -ne '[') 
	{
		$body = "[" + $body + "]"
	}
	
	Write-Host "Properties that will change in Account:" -ForegroundColor Cyan
	$arrProperties | Select-Object @{Name='Property'; Expression={"{0} = {1}" -f $_.path, $_.value}}
	
	#Format the body to send
	$body = $arrProperties | ConvertTo-Json -Depth 5
	If($body[0] -ne '[') 
	{
		$body = "[" + $body + "]"
	}
	
	try{
		$UpdateAccountDetailsResponse = Invoke-RestMethod -Method Patch -Uri $($URL_AccountsDetails -f $AccountID) -Headers $logonHeader -Body $body -ContentType "application/json" -TimeoutSec 3600000
		$response = $UpdateAccountDetailsResponse
	} catch {
		Write-Error $_.Exception.Response.StatusDescription
	}
	If([string]::IsNullOrEmpty($response))
	{
		Write-Host "Error occurred, Account was not updated!" -ForegroundColor Red
	}
	else
	{
		Write-Host "Account Details (after change):" -ForegroundColor Cyan
		$response
	}
    # Logoff the session
    # ------------------
    Write-Host "Logoff Session..."
    Invoke-RestMethod -Method Post -Uri $URL_CyberArkLogoff -Headers $logonHeader -ContentType "application/json" | Out-Null
}
else
{
    Write-Error "This script requires PowerShell version 3 or above"
}
