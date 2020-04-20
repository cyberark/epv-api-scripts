###########################################################################
#
# NAME: Get List of Accounts using REST API
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will list all accounts according to filters (optional).
# Or get all account details for a specific account (by ID)
#
# Filter Criteria available:
# --------------------------
# Safe Name - Search for all accounts in a specific safe
# Keywords - Filter by keywords (by default with OR between them)
# Sort by - Sort by property or properties list (parameter needs to be defined in the accounts list)
# Limit - Limits the number of returned accounts
# Auto Next Page - In case the limit is small or the returned number of accounts is greater than the limit, this will return all accounts from all pages
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v10.4 and above
#
# VERSION HISTORY:
# 1.0 22/07/2018 - Initial release
#
###########################################################################
[CmdletBinding(DefaultParameterSetName="List")]
param
(
	[Parameter(Mandatory=$true,HelpMessage="Enter the PVWA URL")]
	[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,
		
	# Use this switch to list accounts
	[Parameter(ParameterSetName='List',Mandatory=$true)][switch]$List,
	# Use this switch to list accounts
	[Parameter(ParameterSetName='Details',Mandatory=$true)][switch]$Details,
	# Use this switch to see the account in a Report form
	[Parameter(ParameterSetName='List',Mandatory=$false)]
	[Parameter(ParameterSetName='Details')]
	[switch]$Report,

    # Authentication method
	[Parameter(ParameterSetName='List',Mandatory=$true)]
    [Parameter(ParameterSetName='Details',Mandatory=$true)]
    [String]$AuthMethod,
	
	# List accounts filters
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="Enter a Safe Name to search in")]
	[ValidateScript({$_.Length -le 28})]
	[Alias("Safe")]
	[String]$SafeName,
	
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="Enter filter Keywords. List of keywords are separated with space to search in accounts")]
	[String]$Keywords,
	
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="properties by which to sort returned accounts, followed by asc (default) or desc to control sort direction. Multiple sorts are comma-separated. To sort on members of object properties. Maximum number of properties is 3")]
	[String]$SortBy,
	
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="Maximum number of returned accounts. If not specified, the default value is 50. The maximum number that can be specified is 1000")]
	[int]$Limit = 50,
	
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="If used, the next page is automatically returned")]
	[switch]$AutoNextPage,
	
	[Parameter(ParameterSetName='Details',Mandatory=$true,HelpMessage="The required Account ID")]
	[Alias("id")]
	[string]$AccountID,
	
	[Parameter(ParameterSetName='List')]
	[Parameter(ParameterSetName='Details',Mandatory=$false,HelpMessage="Path to a CSV file to export data to")]
	[Alias("path")]
	[string]$CSVPath
)

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path

# Global URLS
# -----------
$URL_PVWAAPI = $PVWAURL+"/api"
$URL_Authentication = $URL_PVWAAPI+"/auth"
$URL_CyberArkLogon = $URL_Authentication+"/{0}/Logon"
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
$authList = @("cyberark","ldap")

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

Function EncodeForURL($sText)
{
	if ($sText.Trim() -ne "")
	{
		write-debug "Returning URL Encode of $sText"
		return [System.Web.HttpUtility]::UrlEncode($sText)
	}
	else
	{
		return ""
	}
}

Function Convert-Date($epochdate)
{
	if (($epochdate).length -gt 10 ) {return (Get-Date -Date "01/01/1970").AddMilliseconds($epochdate)}
	else {return (Get-Date -Date "01/01/1970").AddSeconds($epochdate)}
}

Function AddSearchCriteria
{
	param ([string]$sURL, [string]$sSearch, [string]$sSortParam, [string]$sSafeName, [int]$iLimitPage, [int]$iOffsetPage)
	[string]$retURL = $sURL
	$retURL += "?"
	
	if($sSearch.Trim() -ne "")
	{
		write-debug "Search: $sSearch"
		$retURL += "search=$(EncodeForURL $sSearch)&"
	}
	if($sSafeName.Trim() -ne "")
	{
		write-debug "Safe: $sSafeName"
		$retURL += "filter=safename eq $(EncodeForURL $sSafeName)&"
	}
	if($sSortParam.Trim() -ne "")
	{
		write-debug "Sort: $sSortParam"
		$retURL += "sort=$(EncodeForURL $sSortParam)&"
	}
	if($iLimitPage -gt 0)
	{
		write-debug "Limit: $iLimitPage"
		$retURL += "limit=$iLimitPage&"
	}
		
	if($retURL[-1] -eq '&') { $retURL = $retURL.substring(0,$retURL.length-1) }
	write-debug "URL: $retURL"
	
	return $retURL
}

Function Test-AvailableAuth
{
    param ([string]$authMethod)
    return ($authMethod -in $authList)
}

Function Display-AuthMethods
{
    param ([string[]]$authList)
    foreach($e in $authList)
    {
        Write-Host -ForegroundColor Red "*$e"
    } 
}

#endregion


# Check that the authentication method is allowed
$AuthMethod = $AuthMethod.ToLower()
If (-Not (Test-AvailableAuth $AuthMethod))
{
     Write-Host -ForegroundColor Red "Allowed methods are:"
     Display-AuthMethods $authList
     return
}

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
    $caption = "Get accounts"
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
	    $logonToken = Invoke-RestMethod -Method Post -Uri $($URL_CyberArkLogon-f $AuthMethod) -Body $logonBody -ContentType "application/json"
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

	$response = ""
	switch($PsCmdlet.ParameterSetName)
	{
		"List"
		{
			# List all Accounts by filters
			Write-Host "Retrieving accounts..."
			
			try {
				$AccountsURLWithFilters = ""
				$AccountsURLWithFilters = $(AddSearchCriteria -sURL $URL_Accounts -sSearch $Keywords -sSortParam $SortBy -sSafeName $SafeName -iLimitPage $Limit)
				Write-Debug $AccountsURLWithFilters
			} catch {
				Write-Error $_.Exception
			}
			try{
				$GetAccountsResponse = Invoke-RestMethod -Method Get -Uri $AccountsURLWithFilters -Headers $logonHeader -ContentType "application/json" -TimeoutSec 3600000
			} catch {
				Write-Error $_.Exception.Response.StatusDescription
			}
						
			If ($AutoNextPage)
			{
				$GetAccountsList = @()
				$GetAccountsList += $GetAccountsResponse.value
				Write-Debug $GetAccountsList.count
				$nextLink =  $GetAccountsResponse.nextLink
                If ($nextLink -ne $null)
                {
                    Write-Debug $nextLink
                }
				
				While ($nextLink -ne "" -and $nextLink -ne $null)
				{
					$GetAccountsResponse = Invoke-RestMethod -Method Get -Uri $("$PVWAURL/$nextLink") -Headers $logonHeader -ContentType "application/json" -TimeoutSec 3600000	
					$nextLink = $GetAccountsResponse.nextLink
					Write-Debug $nextLink
					$GetAccountsList += $GetAccountsResponse.value
					Write-Debug $GetAccountsList.count
				}
				Write-Host "Showing $($GetAccountsList.count) accounts"
				$response = $GetAccountsList
			}
			else 
			{
				Write-Host "Showing up to $Limit accounts" 
				$response = $GetAccountsResponse.value
			}
		}
		"Details"
		{
			if($AccountID -ne "")
			{
				$GetAccountDetailsResponse = Invoke-RestMethod -Method Get -Uri $($URL_AccountsDetails -f $AccountID) -Headers $logonHeader -ContentType "application/json" -TimeoutSec 3600000
				$response = $GetAccountDetailsResponse
			}
		}
	}
	
	If($Report)
	{
		$output = @()
		Foreach ($item in $response)
		{
			# Get the Platform Name
			$platformName = Invoke-RestMethod -Method Get -Uri $($URL_Platforms -f $item.platformId) -Headers $logonHeader -ContentType "application/json" -TimeoutSec 3600000
			$output += $item | Select-Object id,@{Name = 'UserName'; Expression = { $_.userName}}, @{Name = 'Address'; Expression = { $_.address}}, @{Name = 'SafeName'; Expression = { $_.safeName}}, @{Name = 'Platform'; Expression = { $platformName.Details.PolicyName}}, @{Name = 'CreateDate'; Expression = { Convert-Date $_.createdTime}}
		}
		If([string]::IsNullOrEmpty($CSVPath))
		{
			$output | FT -Autosize
		}
		else
		{
			$output | Export-Csv -NoTypeInformation -UseCulture -Path $CSVPath -force
		}
	}
	else
	{
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
