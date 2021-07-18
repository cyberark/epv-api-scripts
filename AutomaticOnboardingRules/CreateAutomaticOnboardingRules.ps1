###########################################################################
#
# NAME: Create Automatic Onboarding Rules using REST API
#
# AUTHOR:  Assaf Miron
#
# COMMENT: 
# This script will create an Automatic Onboarding rule for Discovered Privileged Local Accounts.
# The script will apply to the filters defined in the script parameters (Machine Type, Target Safe)
#
# VERSION HISTORY:
# 1.0 08/01/2017 - Initial release
# 1.1 10/01/2017 - Bug fixes and updates
# 1.2 16/01/2017 - Added parameter validations and better rules parsing
# 1.3 25/01/2017 - Added Get, Create and Delete use cases
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
	[Parameter(ParameterSetName='Create',Mandatory=$false)]
	[ValidateSet("Windows","Unix")]
    [String]$SystemType, 
	
	[Parameter(ParameterSetName='Create',Mandatory=$false)]
	[ValidateSet("Server","Workstation")]
    [String]$MachineType, 
	
	[Parameter(ParameterSetName='Create',Mandatory=$false,HelpMessage="Enter a filter User name")]
	[String]$UserName,
	
	[Parameter(ParameterSetName='Create',Mandatory=$false,HelpMessage="Enter the destination Safe name")]
	[String]$SafeName,
	
	# User this switch to delete a rule
	[Parameter(ParameterSetName='Delete',Mandatory=$false)][switch]$Delete,
	[Parameter(ParameterSetName='Delete',Mandatory=$false,HelpMessage="Enter the Rule ID for deletion")]
	[int]$RuleID	
)

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path

# Global URLS
# -----------
$URL_PVWAWebServices = $PVWAURL+"/WebServices"
$URL_PVWAAPI = $PVWAURL+"/api"
$URL_CyberArkAuthentication = $URL_PVWAWebServices+"/auth/Cyberark/CyberArkAuthenticationService.svc"
#$URL_CyberArkAuthentication = $URL_PVWAAPI+"/auth/cyberark"
$URL_CyberArkLogon = $URL_CyberArkAuthentication+"/Logon"
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
        exit
    }

#region [Logon]
    # Get Credentials to Login
    # ------------------------
    $caption = "Create Automatic Onboarding Rule"
    $msg = "Enter your User name and Password"; 
    $creds = $Host.UI.PromptForCredential($caption,$msg,"","")
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
	    $logonToken = $logonResult.CyberArkLogonResult
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
			Write-Host "Retriving rules..."
			try {
				$GetRuleResponse = Invoke-RestMethod -Method Get -Uri $URL_OnboardRules -Headers $logonHeader -ContentType "application/json" -TimeoutSec 2700
			} catch {
				Write-Error $_.Exception.Response.StatusDescription
			}
			if($GetRuleResponse.AutomaticOnboardingRules.Length -eq 0)
			{
				Write-Host "Currently No rules defined"
			}
			else
			{
				Write-Host "Currently available rules:"
				$arrRules = @()
				foreach($rule in $GetRuleResponse.AutomaticOnboardingRules){
					$arrRules += $($rule | Select RuleId, RuleName, DecisionPlatformId, DecisionSafeName, UserNameFilter)
				}
				$arrRules | Format-Table -AutoSize
			}
		}
		
		"Create"
		{
			if ($SystemType -eq "") { $SystemType = "Windows" }
			if($SystemType -match "Win")
			{
				if(($MachineType -match "Server") -or ($MachineType -match "srv"))
				{
					$SystemType = "Windows"
					$MachineType = "Server"
					$Platform = "WinServerLocal"
				}
				elseif($MachineType -match "Workstation")
				{
					$SystemType = "Windows"
					$MachineType = "Workstation"
					$Platform = "WinDesktopLocal"
				}
				else{
					$SystemType = "Windows"
					$MachineType = "Server"
					$Platform = "WinServerLocal" 
				}
			}
			elseif($SystemType -match "nix")
			{
				$SystemType = "Unix"
				$MachineType = "Server"
				$Platform = "UnixSSH"
				$isUID=$True
			}
			
			if($UserName.Trim().length -eq 0)
			{ $UserName = $null }	
			
			Write-Host "Creating rule..."
			$bodyRule = @{DecisionPlatformId=$Platform;DecisionSafeName=$SafeName;IsAdminUIDFilter=$isUID;MachineTypeFilter=$MachineType;SystemTypeFilter=$SystemType;UserNameFilter=$UserName }
			$restRuleCreate = $bodyRule | ConvertTo-Json	
			Write-Debug "[DEBUG] $restRuleCreate"
			try {
				# Create the Rule
				$CreateRuleResponse = Invoke-RestMethod -Method Post -Uri $URL_OnboardRules -Headers $logonHeader -Body $restRuleCreate -ContentType "application/json" -TimeoutSec 2700
			} catch {
				Write-Error $_.Exception.Response.StatusDescription
			}
			
			$CreateRuleResponse | Select RuleId, RuleName, DecisionPlatformId, DecisionSafeName, UserNameFilter | Format-Table -AutoSize
		}
		
		"Delete"
		{
			# Delete a specific Automatic Rule by ID
			Write-Host "Deleting rule ID $RuleID..."
			
			try {
				$DeleteRuleResponse = Invoke-RestMethod -Method Delete -Uri "$URL_OnboardRules/$RuleID" -Headers $logonHeader -ContentType "application/json" -TimeoutSec 2700
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
