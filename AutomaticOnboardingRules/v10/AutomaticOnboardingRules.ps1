###########################################################################
#
# NAME: Manage Automatic Onboarding Rules using REST API
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will get/create/edit/delete an Automatic Onboarding rule for Discovered Privileged Local Accounts.
# The script will apply to the filters defined in the script parameters 
# Available parameters: System Type, Machine Type, Platform, Account Category, Safe, User name filter, Address filter
# In Addition, a user can query a specific rule bu Rule ID
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v10.2 and above (for Get, Create, Delete), PVWA 10.4 and above (for Edit)
#
# VERSION HISTORY:
# 1.0 25/10/2018 - Initial release
#
###########################################################################
[CmdletBinding(DefaultParametersetName="Get")] 
param
(
	[Parameter(Mandatory=$true,HelpMessage="Enter the PVWA URL")]
	[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,
	
	# Use this switch to get rules details only
	[Parameter(ParameterSetName='Get',Mandatory=$false)][switch]$Get,
	
	# Use this switch to create new rules
	[Parameter(ParameterSetName='Create',Mandatory=$false)][switch]$Create,
	
	# Use this switch to edit existing rules
	[Parameter(ParameterSetName='Edit',Mandatory=$false)][switch]$Edit,
	
	# Use this switch to delete a rule
	[Parameter(ParameterSetName='Delete',Mandatory=$false)][switch]$Delete,
	
	[Parameter(ParameterSetName='Create',Mandatory=$false)]
	[Parameter(ParameterSetName='Edit')]
	[ValidateSet("Windows","Unix")]
    [String]$SystemType, 
	
	[Parameter(ParameterSetName='Create',Mandatory=$false)]
	[Parameter(ParameterSetName='Edit')]
	[ValidateSet("Any","Server","Workstation")]
    [String]$MachineType, 
	
	[Parameter(ParameterSetName='Create',Mandatory=$false)]
	[Parameter(ParameterSetName='Edit')]
    [String]$PlatformID,
	
	[Parameter(ParameterSetName='Create',Mandatory=$false)]
	[Parameter(ParameterSetName='Edit')]
	[ValidateSet("Any","Privileged","NonPrivileged")]
    [String]
	$AccountCategory,
	
	[Parameter(ParameterSetName='Create',Mandatory=$false)]
	[Parameter(ParameterSetName='Edit')]
	[ValidateScript({
		if($_ -eq $true -and $AccountCategory -ne "NonPrivileged") { return $true }
		elseif ($_ -eq $false) { return $true }
		else {Throw [System.Management.Automation.ValidationMetadataException] "You cannot Filter Administrative users with a Non Privileged Account category"}
		})]
    [Bool]
	$FilterAdminOnly = $false,
	
	[Parameter(ParameterSetName='Create',Mandatory=$false,HelpMessage="Enter a filter User name")]
	[Parameter(ParameterSetName='Edit')]
	[String]$UserName,
	
	[Parameter(ParameterSetName='Create',Mandatory=$false,HelpMessage="Enter a filter User name")]
	[Parameter(ParameterSetName='Edit')]
	[ValidateSet("Begins", "Ends", "Exact")]
	[String]$UserNameMethod = "Begins",
	
	[Parameter(ParameterSetName='Create',Mandatory=$false,HelpMessage="Enter a filter Address")]
	[Parameter(ParameterSetName='Edit')]
	[String]$Address,
	
	[Parameter(ParameterSetName='Create',Mandatory=$false,HelpMessage="Enter a filter Address")]
	[Parameter(ParameterSetName='Edit')]
	[ValidateSet("Begins", "Ends", "Exact")]
	[String]$AddressMethod = "Begins",
	
	[Parameter(ParameterSetName='Create',Mandatory=$false,HelpMessage="Enter the destination Safe name")]
	[Parameter(ParameterSetName='Edit')]
	[String]$SafeName,
	
	[int]$RuleID	
)

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path

# Global URLS
# -----------
$URL_PVWAWebServices = $PVWAURL+"/WebServices"
$URL_PVWAAPI = $PVWAURL+"/api"
$URL_CyberArkAuthentication = $URL_PVWAAPI+"/auth"
$URL_CyberArkLogon = $URL_CyberArkAuthentication+"/cyberark/Logon"
$URL_CyberArkLogoff = $URL_CyberArkAuthentication+"/Logoff"

# URL Methods
# -----------
$URL_OnboardRules = $URL_PVWAAPI+"/AutomaticOnboardingRules"


# Initialize Script Variables
# ---------------------------
$rstusername = $rstpassword = ""
$logonToken  = ""
$Platform = ""
$isUID = $False

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

Function Convert-ToEnum
{
	param ($sObjToEnum)
	
	switch($sObjToEnum)
	{
		"Exact" {return 0}
		"Privileged" { return 0}
		"Begins" {return 1}
		"NonPrivileged" {return 1}
		"Any" {return 2}
		"Ends" {return 2}
	}
}

Function Get-PlatformByParams
{
	param ($iSystemType, $iMachineType)
	$retPlatform = $null
	
	if($SystemType -match "Win")
	{
		if(($iMachineType -match "Server") -or ($iMachineType -match "srv"))
		{
			$retPlatform = "WinServerLocal"
		}
		elseif($MachineType -match "Workstation")
		{
			$retPlatform = "WinDesktopLocal"
		}
		else{
			$retPlatform = "WinServerLocal" 
		}
	}
	elseif($SystemType -match "nix")
	{
		$retPlatform = "UnixSSH"
	}
	
	return $retPlatform
}

Function Get-AutomaticRules
{
	try {
		$getResponse = Invoke-RestMethod -Method Get -Uri $URL_OnboardRules -Headers $logonHeader -ContentType "application/json" -TimeoutSec 3600000
	} catch {
		Write-Error $_.Exception.Response.StatusDescription
	}
	if($getResponse.Total -eq 0)
	{
		Write-Host "Currently No rules defined"
		return $null
	}
	else
	{
		return $getResponse
	}
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
        break
    }

#region [Logon]
    # Get Credentials to Login
    # ------------------------
    $caption = "Create Automatic Onboarding Rule"
    $msg = "Enter your User name and Password"; 
    $creds = $Host.UI.PromptForCredential($caption,$msg,"","")
	if ($creds -eq $null)
	{break;}
	
    $rstusername = $creds.username.Replace('\','');    
    $rstpassword = $creds.GetNetworkCredential().password

    # Create the POST Body for the Logon
    # ----------------------------------
    $logonBody = @{ username=$rstusername;password=$rstpassword }
    $logonBody = $logonBody | ConvertTo-Json
	try{
	    # Logon
	    $logonResult = Invoke-RestMethod -Method Post -Uri $URL_CyberArkLogon -Body $logonBody -ContentType "application/json"
	    # Save the Logon Result - The Logon Token
	    $logonToken = $logonResult
	}
	catch
	{
		Write-Host -ForegroundColor Red $_.Exception.Response.StatusDescription
		$logonToken = ""
	}
    If ($logonToken -eq "")
    {
        Write-Host -ForegroundColor Red "Logon Token is Empty - Cannot login"
        exit
    }

    # Create a Logon Token Header (This will be used through out all the script)
    # ---------------------------
    $logonHeader =  New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $logonHeader.Add("Authorization", $logonToken)
#endregion

	# Validate input
	switch($PsCmdlet.ParameterSetName)
	{
		"Get"
		{
			# Get all available Automatic Rules defined
			Write-Host "Retrieving rules..."
			$GetRuleResponse = Get-AutomaticRules
			if ($GetRuleResponse -ne $null)
			{
				If ($RuleID -gt 0)
				{
					# Return selected rule
					$GetRuleResponse.AutomaticOnboardingRules | Where RuleId -eq $RuleID | Select * | Format-List
				}
				else
				{
					# Return all rules
					Write-Host "$($GetRuleResponse.Total) Currently available rules (by precedence):"
					$arrRules = @()
					foreach($rule in ($GetRuleResponse.AutomaticOnboardingRules | Sort-Object RulePrecedence)){
						# More properties
						# RuleId, RuleName, RuleDescription, RulePrecedence, TargetPlatformId, TargetDeviceType, TargetSafeName, IsAdminIDFilter, MachineTypeFilter, SystemTypeFilter,
						# CreationTime, UserNameFilter, UserNameMethod, AddressFilter, AddressMethod, AccountTypeFilter, AccountCategoryFilter, ReconcileAccountId, LastOnboardedTime
						$arrRules += $($rule | Select RuleId, RuleName, TargetDeviceType, TargetPlatformId, TargetSafeName, UserNameFilter)
					}
					$arrRules | Format-Table -AutoSize
				}
			}
		}
		
		"Create"
		{
			if($PlatformID -eq $null) 
			{ $PlatformID = Get-PlatformByParams -iSystemType $SystemType -iMachineType $MachineType }
			
			if($UserName.Trim().length -eq 0)
			{ $UserName = $null }	
			
			if($Address.Trim().length -eq 0)
			{ $Address = $null }	
			
			# Convert User methods from string to enum values
			$UserNameMethodEnum = Convert-ToEnum $UserNameMethod
			
			# Convert Address methods from string to enum values
			$AddressMethodEnum = Convert-ToEnum $AddressMethod
			
			# Convert Account category filter from string to enum values
			$AccountCategoryEnum = Convert-ToEnum $AccountCategory
			
			Write-Host "Creating rule..." 
			# All parameters: "TargetPlatformId", "TargetSafeName", "IsAdminIDFilter", "MachineTypeFilter", "SystemTypeFilter", "UserNameFilter", "RuleName", "RuleDescription", "UserNameMethod","AddressFilter","AddressMethod","AccountCategoryFilter"
			$bodyRule = @{TargetPlatformId=$PlatformID;TargetSafeName=$SafeName;IsAdminIDFilter=$FilterAdminOnly;MachineTypeFilter=$MachineType;SystemTypeFilter=$SystemType;UserNameFilter=$UserName;UserNameMethod=$UserNameMethodEnum;AddressFilter=$Address;AddressMethod=$AddressMethodEnum;AccountCategoryFilter=$AccountCategoryEnum }
			$restRuleCreate = $bodyRule | ConvertTo-Json -depth 3	
			Write-Debug "[DEBUG] $restRuleCreate"
			try {
				# Create the Rule
				$CreateRuleResponse = Invoke-RestMethod -Method Post -Uri $URL_OnboardRules -Headers $logonHeader -Body $restRuleCreate -ContentType "application/json" -TimeoutSec 3600000
			} catch {
				Write-Error $_.Exception.Response.StatusDescription
			}
			
			$CreateRuleResponse | Select * | FL
		}
		
		"Edit"
		{
			# Verify that we have a Rule ID
			if ($RuleID -le 0) { break }
			
			# Get the current Rule details
			$GetRuleResponse = Get-AutomaticRules
			if ($GetRuleResponse -ne $null)
			{
				$currentRule = $GetRuleResponse.AutomaticOnboardingRules | Where RuleId -eq $RuleID
				
				# Change only according to the given parameters
				ForEach ($parameter in $MyInvocation.BoundParameters.Keys)
				{
					switch($parameter)
					{
						"MachineType" { $currentRule.MachineTypeFilter = $MachineType }
						"PlatformID" { $currentRule.TargetPlatformId = $PlatformID }
						"AccountCategory" { $currentRule.AccountCategoryFilter = Convert-ToEnum $AccountCategory }
						"FilterAdminOnly" { $currentRule.IsAdminIDFilter = $FilterAdminOnly }
						"UserName" { $currentRule.UserNameFilter = $UserName }
						"UserNameMethod" { $currentRule.UserNameMethod = Convert-ToEnum $UserNameMethod }
						"Address" { $currentRule.AddressFilter = $Address}
						"AddressMethod" { $currentRule.AddressMethod = Convert-ToEnum $AddressMethod }
						"SafeName" { $currentRule.TargetSafeName = $SafeName}
					}
				}
				
				# Prepare the Update rule body
				Write-Host "Updating rule..." 
				$restRuleUpdate = $currentRule | ConvertTo-Json -depth 3	
				Write-Debug "[DEBUG] $restRuleUpdate"
				try {
					# Update the Rule
					$UpdateRuleResponse = Invoke-RestMethod -Method Put -Uri "$URL_OnboardRules/$RuleID" -Headers $logonHeader -Body $restRuleUpdate -ContentType "application/json" -TimeoutSec 3600000
				} catch {
					Write-Error $_.Exception.Response.StatusDescription
				}
				
				$UpdateRuleResponse | Select * | FL
			}
			
		}
		
		"Delete"
		{
			# Delete a specific Automatic Rule by ID
			Write-Host "Deleting rule ID $RuleID..."
			
			try {
				$DeleteRuleResponse = Invoke-RestMethod -Method Delete -Uri "$URL_OnboardRules/$RuleID" -Headers $logonHeader -ContentType "application/json" -TimeoutSec 3600000
			} catch {
				Write-Error $_.Exception.Response.StatusDescription
			}
			
			If($DeleteRuleResponse -eq "")
			{ Write-Host "Rule deleted successfully"}
		}
	}


	
    # Logoff the session
    # ------------------
    Write-Host "Logoff Session..."
    Invoke-RestMethod -Method Post -Uri $URL_CyberArkLogoff -Headers $logonHeader -ContentType "application/json" | Out-Null
}
else
{
    Write-Error "This script requires Powershell version 3 or above"
}
