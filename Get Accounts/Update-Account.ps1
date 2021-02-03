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

	[Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
	[ValidateSet("cyberark","ldap","radius")]
	[String]$AuthType="cyberark",
	
	[Parameter(Mandatory=$true,HelpMessage="The required Account ID")]
	[ValidateScript({ $_ -match "\d{1,}_\d{1,}" })]
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
# Script Version
$ScriptVersion = "1.2"

# Global URLS
# -----------
$URL_PVWAAPI = $PVWAURL+"/api"
$URL_Authentication = $URL_PVWAAPI+"/auth"
$URL_Logon = $URL_Authentication+"/$AuthType/Logon"
$URL_Logoff = $URL_Authentication+"/Logoff"

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
	if ($null -ne $creds)
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
	    $logonToken = Invoke-RestMethod -Method Post -Uri $URL_Logon -Body $logonBody -ContentType "application/json"
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
	$excludedProperties = @("name","username","address","safe","platformid","password","key","automaticManagementEnabled","manualManagementReason","enableautomgmt","manualmgmtreason","groupname","groupplatformid","remotemachineaddresses","restrictmachineaccesstolist","remoteMachines","accessRestrictedToRemoteMachines","sshkey")
	$response = ""
	if($AccountID -ne "")
	{
		$GetAccountDetailsResponse = Invoke-RestMethod -Method Get -Uri $($URL_AccountsDetails -f $AccountID) -Headers $logonHeader -ContentType "application/json" -TimeoutSec 2700
		$response = $GetAccountDetailsResponse
		if ($([string]::IsNullOrEmpty($GetAccountDetailsResponse.platformAccountProperties)))
		{
			$PropsName = @()
		}
		else
		{
			$PropsName = Get-Member -InputObject $GetAccountDetailsResponse.platformAccountProperties -MemberType NoteProperty | ForEach-Object { $_.Name }
		}
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
	$arrProperties = @{}
	$arrPropertiesBody = @()
	# Prepare the parameters with their values
	For($i=0; $i -lt $ParameterNames.Count; $i++)
	{
		if($i -lt $ParameterValues.Count)
		{
			$arrProperties.Add($ParameterNames[$i],$ParameterValues[$i])
		}
		else
		{
			If($ParameterNames[$i] -like "manualManagementReason")
			{
				$arrProperties.Add($ParameterNames[$i],"[No Reason]")
			}
			Else
			{
				$arrProperties.Add($ParameterNames[$i],$ParameterValues[-1])
			}
		}
	}
	# Filter excluded Properties and go over regular properties
	ForEach($param in ($arrProperties.GetEnumerator() | Where-Object { $_.Name -notin $excludedProperties }))
	{
		$_bodyOp = "" | Select-Object "op", "path", "value"
		if ($PropsName.Contains($param.Name))
		{
			$_bodyOp.op = "replace"
		} else {
			$_bodyOp.op = "add"
		}
		$_bodyOp.path = "/platformAccountProperties/"+$param.Name
		$_bodyOp.value = $param.Value
		$arrPropertiesBody += $_bodyOp
	}
	# Go over only excluded Properties
	ForEach($param in ($arrProperties.GetEnumerator() | Where-Object { $_.Name -in $excludedProperties }))
	{
		$_bodyOp = "" | Select-Object "op", "path", "value"
		If($param.Name -in ("automaticManagementEnabled","manualManagementReason"))
		# Handle Secret Management section
		{
			# Check if Account already has them set
			If($response.secretManagement.automaticManagementEnabled -eq $true)
			{
				If($param.Name -like "automaticManagementEnabled" -and $param.Value -like "false")
				{
					# Change to Manual Management
					$_bodyOp.op = "replace"
					$_bodyOp.path = "/secretManagement/automaticManagementEnabled"
					$_bodyOp.value = $false
					$arrProperties += $_bodyOp
					# Need to add the manualManagementReason
					$_bodyOp.op = "add"
					$_bodyOp.path = "/secretManagement/manualManagementReason"
					$_bodyOp.value = "[No Reason]"
					$arrProperties += $_bodyOp
				}
				If($param.Name -like "manualManagementReason")
				{
					# Update Manual management reason
					$_bodyOp.op = "replace"
					$_bodyOp.path = "/secretManagement/manualManagementReason"
					$_bodyOp.value = $param.Value
					$arrProperties += $_bodyOp
				}
			}
			Else # Current Automatic Management is False
			{
				If($param.Name -like "automaticManagementEnabled" -and $param.Value -like "true")
				{
					# Change to Manual Management
					$_bodyOp.op = "replace"
					$_bodyOp.path = "/secretManagement/automaticManagementEnabled"
					$_bodyOp.value = $true
					$arrProperties += $_bodyOp
					# Need to add the manualManagementReason
					$_bodyOp.op = "remove"
					$_bodyOp.path = "/secretManagement/manualManagementReason"
					$_bodyOp.value = ""
					$arrProperties += $_bodyOp
				}
				If($param.Name -like "manualManagementReason")
				{
					# Update Manual management reason
					$_bodyOp.op = "replace"
					$_bodyOp.path = "/secretManagement/manualManagementReason"
					$_bodyOp.value = $param.Value
					$arrProperties += $_bodyOp
				}
			}
		}
		ElseIf($param.Name -in ("remotemachineaddresses","restrictmachineaccesstolist", "remoteMachines", "accessRestrictedToRemoteMachines"))
		# Handle Remote Machine section
		{
			$_bodyOp.op = "replace"
			if($param.Name -in("remotemachineaddresses", "remoteMachines"))
			{
				$_bodyOp.path = "/remoteMachinesAccess/remoteMachines"
				$_bodyOp.value = $param.value
			}
			if($param.Name -in("restrictmachineaccesstolist", "accessRestrictedToRemoteMachines"))
			{
				$_bodyOp.path = "/remoteMachinesAccess/accessRestrictedToRemoteMachines"
				$_bodyOp.value = $param.value
			}
			$arrPropertiesBody += $_bodyOp
		}
		Else
		# Handle Account basic properties
		{
			$_bodyOp.op = "replace"
			$_bodyOp.path = "/"+$param.Name
			$_bodyOp.value = $param.Value
		}
		$arrPropertiesBody += $_bodyOp
	}
	
	#Format the body to send
	$body = $arrPropertiesBody | ConvertTo-Json -Depth 5
	If($body[0] -ne '[') 
	{
		$body = "[" + $body + "]"
	}
	
	Write-Host "Properties that will change in Account:" -ForegroundColor Cyan
	$arrPropertiesBody | Select-Object @{Name='Property'; Expression={"{0} = {1}" -f $_.path, $_.value}}
	
	try{
		$UpdateAccountDetailsResponse = Invoke-RestMethod -Method Patch -Uri $($URL_AccountsDetails -f $AccountID) -Headers $logonHeader -Body $body -ContentType "application/json" -TimeoutSec 2700
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
    Invoke-RestMethod -Method Post -Uri $URL_Logoff -Headers $logonHeader -ContentType "application/json" | Out-Null
}
else
{
    Write-Error "This script requires PowerShell version 3 or above"
}
