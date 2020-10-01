###########################################################################
#
# NAME: Manage Safes using REST API
#
# AUTHOR:  Jake DeSantis, Carl Anderson
#
# COMMENT: 
# This script will help in Safe Management tasks
#
# SUPPORTED VERSIONS:
# CyberArk PVWA v9.8 and above
#
# VERSION HISTORY:
# 1.0 16/12/2018 - Initial release
# 1.1 06/02/2019 - Bug fix
#
###########################################################################
[CmdletBinding(DefaultParameterSetName="List")]
param
(
	[Parameter(Mandatory=$true,HelpMessage="Please enter your PVWA address (For example: https://pvwa.mydomain.com/passwordvault)")]
	[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
	[Alias("url")]
	[String]$PVWAURL,
		
	# Use this switch to list Safes
	[Parameter(ParameterSetName='List',Mandatory=$true)][switch]$List,
	# Use this switch to Add Safes
	[Parameter(ParameterSetName='Add',Mandatory=$true)][switch]$Add,
	# Use this switch to Update Safes
	[Parameter(ParameterSetName='Update',Mandatory=$true)][switch]$Update,
	# Use this switch to Update Safe Members
	[Parameter(ParameterSetName='UpdateMembers',Mandatory=$true)][switch]$UpdateMembers,
	# Use this switch to Delete Safe Members
	[Parameter(ParameterSetName='DeleteMembers',Mandatory=$true)][switch]$DeleteMembers,
	# Use this switch to Delete Safes
	[Parameter(ParameterSetName='Delete',Mandatory=$true)][switch]$Delete,
	# Use this switch to Add Safe Members
	[Parameter(ParameterSetName='Members',Mandatory=$true)][switch]$Members,
		
	# Safe Name
	[Parameter(ParameterSetName='List',Mandatory=$false,HelpMessage="Enter a Safe Name to filter by")]
	[Parameter(ParameterSetName='Add',Mandatory=$false,HelpMessage="Enter a Safe Name to create")]
	[Parameter(ParameterSetName='Update',Mandatory=$false,HelpMessage="Enter a Safe Name to update")]
	[Parameter(ParameterSetName='Delete',Mandatory=$true,HelpMessage="Enter a Safe Name to delete")]
	[Parameter(ParameterSetName='Members',Mandatory=$true,HelpMessage="Enter a Safe Name to add members to")]
	[ValidateScript({$_.Length -le 28})]
	[Alias("Safe")]
	[String]$SafeName,
	
	# Safe Description
	[Parameter(ParameterSetName='Add',Mandatory=$false,HelpMessage="Enter a Safe Description")]
	[Parameter(ParameterSetName='Update',Mandatory=$false,HelpMessage="Enter an updated Safe Description")]
	[Alias("Description")]
	[String]$SafeDescription,
	
	# Import File support
	[Parameter(ParameterSetName='Add',Mandatory=$false,HelpMessage="Enter a file path for bulk safe creation")]
	[Parameter(ParameterSetName='Update',Mandatory=$false,HelpMessage="Enter a file path for bulk safe update")]
	[Parameter(ParameterSetName='UpdateMembers',Mandatory=$false,HelpMessage="Enter a file path for bulk safe membership update")]
	[Parameter(ParameterSetName='DeleteMembers',Mandatory=$false,HelpMessage="Enter a file path for bulk safe membership deletion")]
	[Parameter(ParameterSetName='Delete',Mandatory=$false,HelpMessage="Enter a file path for bulk safe deletion")]
	[ValidateScript( { Test-Path -Path $_ -PathType Leaf -IsValid})]
	[ValidatePattern( '\.csv$' )]
	[Alias("File")]
	[String]$FilePath,
	
	# Add / Update Safe options
	[Parameter(ParameterSetName='Add',Mandatory=$false,HelpMessage="Enter the managing CPM name")]
	[Parameter(ParameterSetName='Update',Mandatory=$false,HelpMessage="Enter the updated managing CPM name")]
	[string]$ManagingCPM,
	
	[Parameter(ParameterSetName='Add',Mandatory=$false,HelpMessage="Enter the number of versions retention")]
	[Parameter(ParameterSetName='Update',Mandatory=$false,HelpMessage="Enter the updated number of versions retention")]
	[int]$NumVersionRetention,
	
	# Member Roles 
	[Parameter(ParameterSetName='Members',Mandatory=$false,HelpMessage="Enter a role for the member to add (Default: EndUser)")]
	[ValidateSet("Admin", "Auditor", "EndUser", "Owner")]
	[Alias("Role")]
	[String]$MemberRole = "EndUser",
	
	# User / Member name 
	[Parameter(ParameterSetName='Members',Mandatory=$false,HelpMessage="Enter the user name to add as member to the safe")]
	[ValidateScript({$_.Length -le 128})]
	[Alias("User")]
	[String]$UserName,
	
	# User / Member Vault Location
	[Parameter(ParameterSetName='Members',Mandatory=$false,HelpMessage="Enter the vault-integrated LDAP directory name the vault should search for the account. Must match one of the directory names defined in the LDAP Integration page of the PVWA. (Default: Search in Vault)")]
	[Alias("Location")]
	[String]$UserLocation = "Vault",
	
	# Support for Threading (Logon Connection Number)
	[Parameter(Mandatory=$false,HelpMessage="Enter a thread connection number between 0-100. (Default: 0)")]
	[Alias("Thread")]
	[ValidateScript({ ($_ -ge 0) -and ($_ -lt 100) })]
	[int]$ThreadNumber = 0,
	
	# Use this switch to Disable SSL verification (NOT RECOMMENDED)
	[Parameter(Mandatory=$false)]
	[Switch]$DisableSSLVerify
)

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
# Get Debug / Verbose parameters for Script
$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent

# Script Version
$ScriptVersion = "1.6"

# ------ SET global parameters ------
# Set Log file path
$global:LOG_DATE = $(get-date -format yyyyMMdd) + "-" + $(get-date -format HHmmss)
$global:LOG_FILE_PATH = "$ScriptLocation\SafeManagement_$LOG_DATE.log"
# Set a global Header Token parameter
$global:g_LogonHeader = ""
# Set a global safes list to improve performance
$global:g_SafesList = $null
# Set a global list of all Default sues to ignore
$global:g_DefaultUsers = @("Master","Batch","Backup Users","Auditors","Operators","DR Users","Notification Engines","PVWAGWAccounts","PVWAGWUser","PVWAAppUser","PasswordManager")

# Global URLS
# -----------
$URL_PVWAWebServices = $PVWAURL+"/WebServices"
$URL_PVWABaseAPI = $URL_PVWAWebServices+"/PIMServices.svc"
$URL_CyberArkAuthentication = $URL_PVWAWebServices+"/auth/cyberark/CyberArkAuthenticationService.svc"
$URL_Logon = $URL_CyberArkAuthentication+"/Logon"
$URL_Logoff = $URL_CyberArkAuthentication+"/Logoff"

# URL Methods
# -----------
$URL_Safes = $URL_PVWABaseAPI+"/Safes"
$URL_SpecificSafe = $URL_Safes+"/{0}"
$URL_SafeMembers = $URL_SpecificSafe+"/Members"
$URL_SafeSpecificMember = $URL_SpecificSafe+"/Members/{1}"

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

Function Encode-URL($sText)
{
	if ($sText.Trim() -ne "")
	{
		Write-LogMessage -Type Verbose -Msg "Returning URL Encode of $sText"
		return [URI]::EscapeDataString($sText)
	}
	else
	{
		return ""
	}
}

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
		[Parameter(Mandatory=$true)]
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
	try{
		If ($Header) {
			"=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
			Write-Host "======================================="
		}
		ElseIf($SubHeader) { 
			"------------------------------------" | Out-File -Append -FilePath $LOG_FILE_PATH 
			Write-Host "------------------------------------"
		}
	
		$msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
		$writeToFile = $true
		# Replace empty message with 'N/A'
		if([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
		# Mask Passwords
		if($Msg -match '((?:"password"|"secret"|"NewCredentials")\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w!@#$%^&*()-\\\/]+))')
		{
			$Msg = $Msg.Replace($Matches[2],"****")
		}
		# Check the message type
		switch ($type)
		{
			"Info" { 
				Write-Host $MSG.ToString()
				$msgToWrite += "[INFO]`t$Msg"
			}
			"Warning" {
				Write-Host $MSG.ToString() -ForegroundColor DarkYellow
				$msgToWrite += "[WARNING]`t$Msg"
			}
			"Error" {
				Write-Host $MSG.ToString() -ForegroundColor Red
				$msgToWrite += "[ERROR]`t$Msg"
			}
			"Debug" { 
				if($InDebug)
				{
					Write-Debug $MSG
					$msgToWrite += "[DEBUG]`t$Msg"
				}
				else { $writeToFile = $False }
			}
			"Verbose" { 
				if($InVerbose)
				{
					Write-Verbose $MSG
					$msgToWrite += "[VERBOSE]`t$Msg"
				}
				else { $writeToFile = $False }
			}
		}
		
		If($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH }
		If ($Footer) { 
			"=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
			Write-Host "======================================="
		}
	} catch { Write-Error "Error in writing log: $($_.Exception.Message)" }
}

Function Collect-ExceptionMessage
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
		[Parameter(Mandatory=$true)]
		[System.Management.Automation.CredentialAttribute()]$Credentials,
		[Parameter(Mandatory=$false)]
		[ValidateScript({ ($_ -ge 0) -and ($_ -lt 100) })]
		[int]$ConnectionNumber = 0
	)
	
	if([string]::IsNullOrEmpty($g_LogonHeader))
	{
		# Disable SSL Verification to contact PVWA
		If($DisableSSLVerify)
		{
			Disable-SSLVerification
		}
		
		# Create the POST Body for the Logon
		# ----------------------------------
		If($ConnectionNumber -eq 0)
		{
			$logonBody = @{ username=$Credentials.username.Replace('\',''); password=$Credentials.GetNetworkCredential().password } | ConvertTo-Json
		}
		elseif($ConnectionNumber -gt 0)
		{
			$logonBody = @{ username=$Credentials.username.Replace('\',''); password=$Credentials.GetNetworkCredential().password; connectionNumber=$ConnectionNumber } | ConvertTo-Json
		}
		try{
			# Logon
			$logonToken = Invoke-RestMethod -Method Post -Uri $URL_Logon -Body $logonBody -ContentType "application/json" -TimeoutSec 3600000
			
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
		
		try{
			# Create a Logon Token Header (This will be used through out all the script)
			# ---------------------------
			$logonHeader = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
			$logonHeader.Add("Authorization", $logonToken.CyberArkLogonResult)			

			Set-Variable -Name g_LogonHeader -Value $logonHeader -Scope global		
		} catch {
			Throw $(New-Object System.Exception ("Get-LogonHeader: Could not create Logon Headers Dictionary",$_.Exception))
		}
	}
}

Function Run-Logoff
{
<# 
.SYNOPSIS 
	Run-Logoff
.DESCRIPTION
	Logoff a PVWA session
#>
	try{
		# Logoff the session
		# ------------------
		If($null -ne $g_LogonHeader)
		{
			Write-LogMessage -Type Info -Msg "Logoff Session..."
			Invoke-RestMethod -Method Post -Uri $URL_Logoff -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 3600000 | out-null
			Set-Variable -Name g_LogonHeader -Value $null -Scope global
		}
	} catch {
		Throw $(New-Object System.Exception ("Run-Logoff: Failed to logoff session",$_.Exception))
	}
}

Function Disable-SSLVerification
{
<# 
.SYNOPSIS 
	Bypass SSL certificate validations
.DESCRIPTION
	Disables the SSL Verification (bypass self signed SSL certificates)
#>
	# Check if to disable SSL verification
	If($DisableSSLVerify)
	{
		try{
			Write-Warning "It is not Recommended to disable SSL verification" -WarningAction Inquire
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
		} catch {
			Write-LogMessage -Type Error -Msg "Could not change SSL validation. Error: $(Collect-ExceptionMessage $_.Exception)"
		}
	}
	Else
	{
		try{
			Write-LogMessage -Type Info -Msg "Setting script to use TLS 1.2"
			[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
		} catch {
			Write-LogMessage -Type Error -Msg "Could not change SSL setting to use TLS 1.2. Error: $(Collect-ExceptionMessage $_.Exception)"
		}
	}
}

Function Get-Safes 
{
<#
.SYNOPSIS
Lists the cyberark safes that the APIUser has access to

.DESCRIPTION
Lists the cyberark safes that the APIUser has access to

.EXAMPLE
Get-Safes

#>

    [CmdletBinding()]
    [OutputType([String])]
    Param
    (
    )

try {
		If($g_SafesList -eq $null)
		{
			Write-LogMessage -Type Debug -Msg "Retrieving safes from the vault..."
			$safes = (Invoke-RestMethod -Uri $URL_Safes -Method GET -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 3600000).GetSafesResult
			Set-Variable -Name g_SafesList -Value $safes -Scope Global
		}
		
        return $g_SafesList
    }catch{
		Throw $(New-Object System.Exception ("Get-Safes: There was an error retrieving the safes from the Vault.",$_.Exception))
    }

}

Function Get-Safe
{
<#
.SYNOPSIS
Get all Safe details on a specific safe

.DESCRIPTION
Get all Safe details on a specific safe

.EXAMPLE
Get-Safe -safeName "x0-Win-S-Admins"

#>
	param (
		[ValidateScript({$_.Length -le 28})]
		[String]$safeName
	)
	$_safe = $null
	try{
		$accSafeURL = $URL_SpecificSafe -f $(Encode-URL $safeName)
		$_safe = $(Invoke-RestMethod -Uri $accSafeURL -Method "Get" -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 3600000 -ErrorAction "SilentlyContinue").GetSafeResult
	}
	catch
	{
		Throw $(New-Object System.Exception ("Get-Safe: Error retrieving safe '$safename' details.",$_.Exception))
	}
	
	return $_safe
}

Function Create-Safe
{
<#
.SYNOPSIS
Allows a user to create a new cyberArk safe

.DESCRIPTION
Creates a new cyberark safe

.EXAMPLE
Create-Safe -safename "x0-Win-S-Admins" -safeDescription "Safe description goes here"

#>
    [CmdletBinding()]
    [OutputType()]
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$safename,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string]$safedescription,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string]$managingCPM="PasswordManager",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [int]$numVersionRetention=7,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [int]$numDaysRetention=-1,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [bool]$EnableOLAC=$false
    )

$createSafeBody=@{
            safe=@{
            "SafeName"="$safename"; 
            "Description"="$safeDescription"; 
            "OLACEnabled"=$enableOLAC; 
            "ManagingCPM"="$managingCPM";
            "NumberOfVersionsRetention"=$numVersionRetention;
            }
}

If($numDaysRetention -gt -1)
{
	$createSafeBody.Safe.Add("NumberOfDaysRetention",$numDaysRetention)
	$createSafeBody.Safe.Remove("NumberOfVersionsRetention")
}

	try {
        Write-LogMessage -Type Debug -Msg "Adding the safe $safename to the Vault..."
        $safeadd = Invoke-RestMethod -Uri $URL_Safes -Body ($createSafeBody | ConvertTo-Json) -Method POST -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 3600000
		# Reset cached Safes list
		Set-Variable -Name g_SafesList -Value $null -Scope Global
		# Update Safes list to include new safe
		Get-Safes | out-null
    }catch{
		Throw $(New-Object System.Exception ("Create-Safe: Error adding $safename to the Vault.",$_.Exception))
    }
}

Function Update-Safe
{
<#
.SYNOPSIS
Allows a user to update an existing cyberArk safe

.DESCRIPTION
Updates a new cyberark safe

.EXAMPLE
Update-Safe -safename "x0-Win-S-Admins" -safeDescription "Updated Safe description goes here" -managingCPM "PassManagerDMZ"

#>
    [CmdletBinding()]
    [OutputType()]
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$safeName,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string]$safedescription,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string]$managingCPM,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [int]$numVersionRetention=-1,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [int]$numDaysRetention=-1,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [bool]$EnableOLAC
    )
	try {
		# Get the current safe details and update when necessary
		$getSafe = Get-Safe -safeName $safeName
	} catch {
		Throw $(New-Object System.Exception ("Update-Safe: Error getting current details on safe '$safeName'",$_.Exception))
	}
	$updateDescription = $getSafe.Description
	$updateOLAC = $getSafe.OLACEnabled
	$updateManageCPM = $getSafe.ManagingCPM
	$updateRetVersions = $getSafe.NumberOfVersionsRetention
	$updateRetDays = $getSafe.NumberOfDaysRetention
	
	If(![string]::IsNullOrEmpty($safedescription) -and $getSafe.Description -ne $safeDescription)
	{
		$updateDescription = $safeDescription
	}
	If($getSafe.OLACEnabled -ne $EnableOLAC)
	{
		$updateOLAC = $EnableOLAC
	}
	If(![string]::IsNullOrEmpty($managingCPM) -and $getSafe.ManagingCPM -ne $managingCPM)
	{
		$updateManageCPM = $managingCPM
	}
	If($numVersionRetention -ne $null -and $numVersionRetention -gt 0 -and $getSafe.NumberOfVersionsRetention -ne $numVersionRetention)
	{
		$updateRetVersions = $numVersionRetention
	}
	If($numDaysRetention -ne $null -and $numDaysRetention -gt 0 -and $getSafe.NumberOfDaysRtention -ne $numDaysRetention)
	{
		$updateRetDays = $numDaysRetention
	}
	
$updateSafeBody=@{
            safe=@{
            "SafeName"="$safeName"; 
            "Description"="$updateDescription"; 
            "OLACEnabled"=$updateOLAC; 
            "ManagingCPM"="$updateManageCPM";
            "NumberOfVersionsRetention"=$updateRetVersions;
            "NumberOfDaysRetention"=$updateRetDays;
            }
} | ConvertTo-Json

	try {
        Write-LogMessage -Type Debug -Msg "Updating safe $safename..."
        Write-LogMessage -Type Debug -Msg "Update Safe Body: $updateSafeBody" 
        $safeupdate = Invoke-RestMethod -Uri ($URL_SpecificSafe -f $safeName) -Body $updateSafeBody -Method PUT -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 3600000
    }catch{
		Throw $(New-Object System.Exception ("Update-Safe: Error updating $safeName.",$_.Exception))
    }
}

Function Delete-Safe
{
<#
.SYNOPSIS
Allows a user to delete a cyberArk safe

.DESCRIPTION
Deletes a cyberark safe

.EXAMPLE
Delete-Safe -safename "x0-Win-S-Admins"

#>
    [CmdletBinding()]
    [OutputType()]
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$safename
    )

	try {
        Write-LogMessage -Type Debug -Msg "Deleting the safe $safename from the Vault..."
        $safedelete = Invoke-RestMethod -Uri ($URL_SpecificSafe -f $safeName) -Method DELETE -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 3600000
    }catch{
		Throw $(New-Object System.Exception ("Delete-Safe: Error deleting $safename from the Vault.",$_.Exception))
    }
}

Function Set-SafeMember 
{
<#
.SYNOPSIS
Gives granular permissions to a member on a cyberark safe

.DESCRIPTION
Gives granular permission to a cyberArk safe to the particular member based on parameters sent to the command.

.EXAMPLE
Set-SafeMember -safename "Win-Local-Admins" -safemember "Win-Local-Admins" -memberSearchInLocation "LDAP Directory Name"

.EXAMPLE
Set-SafeMember -safename "Win-Local-Admins" -safemember "Administrator" -memberSearchInLocation vault

#>
    [CmdletBinding()]
    [OutputType()]
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({((Get-Safes).safename) -contains $_})]
        $safename,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        $safeMember,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [switch]$updateMember,
		[Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [switch]$deleteMember,
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Which vault-integrated LDAP directory name the vault should search for the account. Must match one of the directory names defined in the LDAP Integration page of the PVWA.",
                   Position=0)]
		$memberSearchInLocation = "Vault",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permUseAccounts = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permRetrieveAccounts = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permListAccounts = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permAddAccounts = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permUpdateAccountContent = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permUpdateAccountProperties = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permInitiateCPMManagement = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permSpecifyNextAccountContent = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permRenameAccounts = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permDeleteAccounts = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permUnlockAccounts = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permManageSafe = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permManageSafeMembers = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permBackupSafe = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permViewAuditLog = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permViewSafeMembers = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [int]$permRequestsAuthorizationLevel = 0,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permAccessWithoutConfirmation = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permCreateFolders = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permDeleteFolders = $false,
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [bool]$permMoveAccountsAndFolders = $false
    )

	If($safemember -notin $g_DefaultUsers)
	{
		$SafeMembersBody = @{
			member = @{
				MemberName = "$safeMember"
				SearchIn = "$memberSearchInLocation"
				MembershipExpirationDate = "$null"
				Permissions = @(
					@{Key="UseAccounts";Value=$permUseAccounts}
					@{Key="RetrieveAccounts";Value=$permRetrieveAccounts}
					@{Key="ListAccounts";Value=$permListAccounts}
					@{Key="AddAccounts";Value=$permAddAccounts}
					@{Key="UpdateAccountContent";Value=$permUpdateAccountContent}
					@{Key="UpdateAccountProperties";Value=$permUpdateAccountProperties}
					@{Key="InitiateCPMAccountManagementOperations";Value=$permInitiateCPMManagement}
					@{Key="SpecifyNextAccountContent";Value=$permSpecifyNextAccountContent}
					@{Key="RenameAccounts";Value=$permRenameAccounts}
					@{Key="DeleteAccounts";Value=$permDeleteAccounts}
					@{Key="UnlockAccounts";Value=$permUnlockAccounts}
					@{Key="ManageSafe";Value=$permManageSafe}
					@{Key="ManageSafeMembers";Value=$permManageSafeMembers}
					@{Key="BackupSafe";Value=$permBackupSafe}
					@{Key="ViewAuditLog";Value=$permViewAuditLog}
					@{Key="ViewSafeMembers";Value=$permViewSafeMembers}
					@{Key="RequestsAuthorizationLevel";Value=$permRequestsAuthorizationLevel}
					@{Key="AccessWithoutConfirmation";Value=$permAccessWithoutConfirmation}
					@{Key="CreateFolders";Value=$permCreateFolders}
					@{Key="DeleteFolders";Value=$permDeleteFolders}
					@{Key="MoveAccountsAndFolders";Value=$permMoveAccountsAndFolders}
				)
			}  
		}

		try {
			If($updateMember)
			{
				Write-LogMessage -Type Debug -Msg "Updating safe membership for $safeMember on $safeName in the vault..."
				$urlSafeMembers = ($URL_SafeSpecificMember -f $(Encode-URL $safeName),$safemember)
				$restMethod = "PUT"
			}
			elseif($deleteMember)
			{
				Write-LogMessage -Type Debug -Msg "Deleting $safeMember from $safeName in the vault..."
				$urlSafeMembers = ($URL_SafeSpecificMember -f $(Encode-URL $safeName),$safemember)
				$restMethod = "DELETE"
			}
			else
			{
				# Adding a member
				Write-LogMessage -Type Debug -Msg "Adding $safeMember located in $memberSearchInLocation to $safeName in the vault..."
				$urlSafeMembers = ($URL_SafeMembers -f $(Encode-URL $safeName))
				$restMethod = "POST"
			}
			$setSafeMembers = Invoke-RestMethod -Uri $urlSafeMembers -Body ($safeMembersBody | ConvertTo-Json -Depth 5) -Method $restMethod -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 3600000 -ErrorVariable rMethodErr
		}catch{
			if ($rmethodErr.message -like "*User or Group is already a member*"){
				Write-LogMessage -Type Warning -Msg "The user $safeMember is already a member. Use the update member method instead"
			}else{
				Write-LogMessage -Type Error -Msg "There was an error setting the membership for $safeMember on $safeName in the Vault. The error was:"
				Write-LogMessage -Type Error -Msg ("{0} ({1})" -f $rMethodErr.message, $_.Exception.Response.StatusDescription)
			}
		}
	}
	else
	{
		Write-LogMessage -Type Info -Msg "Skipping default user $safeMember..."
	}
}

Function Get-SafeMembers
{
<#
.SYNOPSIS
Returns the permissions of a member on a cyberark safe

.DESCRIPTION
Returns the permissions of a cyberArk safe of all members based on parameters sent to the command.

.EXAMPLE
Get-SafeMember -safename "Win-Local-Admins" 

#> 
	param (
		[Parameter(Mandatory=$true)]
		[String]$safeName
		)
	$_safeMembers = $null
	$_safeOwners = $null
	try{
		$accSafeMembersURL = $URL_SafeMembers -f $(Encode-URL $safeName)
		$_safeMembers = $(Invoke-RestMethod -Uri $accSafeMembersURL -Method GET -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 3600000 -ErrorAction "SilentlyContinue")
		# Remove default users and change UserName to MemberName
		$_safeOwners = $_safeMembers.members | Where {$_.UserName -notin $g_DefaultUsers} | Select-Object -Property @{Name = 'MemberName'; Expression = { $_.UserName }}, Permissions
	}
	catch
	{
		Throw $(New-Object System.Exception ("Get-SafeMembers: There was an error getting the safe $safeName Members.",$_.Exception))
	}
	
	return $_safeOwners
}

Function Convert-ToBool
{
	param (
		[string]$txt
	)
	$retBool = $false
	
if ([bool]::TryParse($txt, [ref]$retBool)) {
    # parsed to a boolean
    return [System.Convert]::ToBoolean($txt)
	} else {
		Write-LogMessage -Type Error -Msg "The input ""$txt"" is not in the correct format (true/false), defaulting to False"
		return $false
	}
}
#endregion

Write-LogMessage -Type Info -MSG "Starting script (v$ScriptVersion)" -Header -LogFile $LOG_FILE_PATH
if($InDebug) { Write-LogMessage -Type Info -MSG "Running in Debug Mode" -LogFile $LOG_FILE_PATH }
if($InVerbose) { Write-LogMessage -Type Info -MSG "Running in Verbose Mode" -LogFile $LOG_FILE_PATH }
Write-LogMessage -Type Debug -MSG "Running PowerShell version $($PSVersionTable.PSVersion.Major) compatible of versions $($PSVersionTable.PSCompatibleVersions -join ", ")" -LogFile $LOG_FILE_PATH

# Check if Powershell is running in Constrained Language Mode
If($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage")
{
	Write-LogMessage -Type Error -MSG "Powershell is currently running in $($ExecutionContext.SessionState.LanguageMode) mode which limits the use of some API methods used in this script.`
	PowerShell Constrained Language mode was designed to work with system-wide application control solutions such as CyberArk EPM or Device Guard User Mode Code Integrity (UMCI).`
	For more information: https://blogs.msdn.microsoft.com/powershell/2017/11/02/powershell-constrained-language-mode/"
	Write-LogMessage -Type Info -MSG "Script ended" -Footer -LogFile $LOG_FILE_PATH
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
        Write-LogMessage -Type Error -Msg "PVWA URL can not be empty"
        return
    }

#region [Logon]
	try{
		# Get Credentials to Login
		# ------------------------
		$caption = "Safe Management"
		$msg = "Enter your User name and Password"; 
		$creds = $Host.UI.PromptForCredential($caption,$msg,"","")
		if ($creds -ne $null)
		{
			Get-LogonHeader -Credentials $creds -ConnectionNumber $ThreadNumber
		}
		else { 
			Write-LogMessage -Type Error -Msg "No Credentials were entered"
			return
		}
	} catch {
		Write-LogMessage -Type Error -Msg "Error Logging on. Error: $(Collect-ExceptionMessage $_.Exception)"
		return
	}
#endregion

	$response = ""
	switch($PsCmdlet.ParameterSetName)
	{
		"List"
		{
			# List all Safes
			Write-LogMessage -Type Info -Msg "Retrieving Safes..."
			
			try{
				If (![string]::IsNullOrEmpty($SafeName))
				{
					Get-Safe -SafeName $SafeName
				}
				else
				{
					Get-Safes
				}
			} catch {
				Write-LogMessage -Type Error -Msg "Error retrieving safes. Error: $(Collect-ExceptionMessage $_.Exception)"
			}
		}
		{($_ -eq "Add") -or ($_ -eq "Update") -or ($_ -eq "UpdateMembers") -or ($_ -eq "Delete") -or ($_ -eq "DeleteMembers")} 
		{
			try{
				if(![string]::IsNullOrEmpty($FilePath))
				{
					# Bulk Import of Safes
					$csv = Import-Csv $FilePath
					# Sort List by Safes
					$sortedList = $csv | Sort-Object -Property safename
					# For each line in the csv, import the safe
					ForEach ($line in $sortedList)
					{
						Write-LogMessage -Type Info -Msg "Importing safe $($line.safename) with safe member $($line.member)..."
						$parameters = @{ 
							safeName=$line.safename; 
							safeDescription=$line.description;
							managingCPM=$line.ManagingCPM;
							numVersionRetention==$line.numVersionRetention;
							numDaysRetention=$line.numDaysRetention;
							EnableOLAC=$line.EnableOLAC;
						}
						if([string]::IsNullOrEmpty($parameters.safeDescription)) { $parameters.Remove('safeDescription') }
						if([string]::IsNullOrEmpty($parameters.ManagingCPM)) { $parameters.Remove('managingCPM') }
						if([string]::IsNullOrEmpty($parameters.numVersionRetention)) { $parameters.Remove('numVersionRetention') }
						if([string]::IsNullOrEmpty($parameters.numDaysRetention)) { $parameters.Remove('numDaysRetention') }
						if([string]::IsNullOrEmpty($parameters.EnableOLAC)) 
						{ 
							$parameters.Remove('EnableOLAC') 
						}
						Else
						{
							$parameters.EnableOLAC = Convert-ToBool $parameters.EnableOLAC
						}
						If($Add)
						{
							#If safe doesn't exist, create the new safe
							if (((Get-Safes).safename) -notcontains $line.safename) 
							{
								Write-LogMessage -Type Info -Msg "Adding the safe $($line.safename)..."
								Create-Safe @parameters
							}
							else
							{
								# Safe exists, would create an error creating it again
								Write-LogMessage -Type Error -Msg "Safe $($line.safename) already exists, to update it use the Update switch"
							}
						}
						ElseIf($Update)
						{
							Write-LogMessage -Type Info -Msg "Updating the safe $($line.safename)..."
							Update-Safe @parameters
						}
						ElseIf($Delete)
						{
							Write-LogMessage -Type Info -Msg "Deleting safe $($line.safename)..."
							Delete-Safe @parameters
						}
						
						If($Delete -eq $False)
						{
							If(![string]::IsNullOrEmpty($line.member))
							{
								# Add permissions to the safe
								Set-SafeMember -safename $line.safename -safeMember $line.member -updateMember:$UpdateMembers -deleteMember:$DeleteMembers -memberSearchInLocation $line.MemberLocation `
									-permUseAccounts $(Convert-ToBool $line.UseAccounts) -permRetrieveAccounts $(Convert-ToBool $line.RetrieveAccounts) -permListAccounts $(Convert-ToBool $line.ListAccounts) `
									-permAddAccounts $(Convert-ToBool $line.AddAccounts) -permUpdateAccountContent $(Convert-ToBool $line.UpdateAccountContent) -permUpdateAccountProperties $(Convert-ToBool $line.UpdateAccountProperties) `
									-permInitiateCPMManagement $(Convert-ToBool $line.InitiateCPMAccountManagementOperations) -permSpecifyNextAccountContent $(Convert-ToBool $line.SpecifyNextAccountContent) `
									-permRenameAccounts $(Convert-ToBool $line.RenameAccounts) -permDeleteAccounts $(Convert-ToBool $line.DeleteAccounts) -permUnlockAccounts $(Convert-ToBool $line.UnlockAccounts) `
									-permManageSafe $(Convert-ToBool $line.ManageSafe) -permManageSafeMembers $(Convert-ToBool $line.ManageSafeMembers) -permBackupSafe $(Convert-ToBool $line.BackupSafe) `
									-permViewAuditLog $(Convert-ToBool $line.ViewAuditLog) -permViewSafeMembers $(Convert-ToBool $line.ViewSafeMembers) `
									-permRequestsAuthorizationLevel $line.RequestsAuthorizationLevel -permAccessWithoutConfirmation $(Convert-ToBool $line.AccessWithoutConfirmation) `
									-permCreateFolders $(Convert-ToBool $line.CreateFolders) -permDeleteFolders $(Convert-ToBool $line.DeleteFolders) -permMoveAccountsAndFolders $(Convert-ToBool $line.MoveAccountsAndFolders)
							}
						}
					}
				}
				else
				{
					$parameters = @{ 
						safeName=$SafeName; 
						safeDescription=$SafeDescription;
						managingCPM=$ManagingCPM;
						numVersionRetention=$NumVersionRetention
					}
					# Keep only relevant properties (and keeping defaults when needed)
					if([string]::IsNullOrEmpty($SafeDescription))
					{
						$parameters.Remove('safeDescription')
					}
					if([string]::IsNullOrEmpty($ManagingCPM))
					{
						$parameters.Remove('managingCPM')
					}
					if([string]::IsNullOrEmpty($NumVersionRetention))
					{
						$parameters.Remove('numVersionRetention')
					}
					If($Add)
					{
						# Create one Safe
						Write-LogMessage -Type Info -Msg "Adding the safe $SafeName..."
						Create-Safe @parameters
					}
					ElseIf($Update)
					{
						# Update the Safe
						Write-LogMessage -Type Info -Msg "Updating the safe $SafeName..."
						Update-Safe @parameters
					}
					ElseIf($Delete)
					{
						# Deleting one Safe
						Write-LogMessage -Type Info -Msg "Deleting the safe $SafeName..."
						Delete-Safe @parameters
					}
				}			
			}catch{
				Write-LogMessage -Type Error -Msg "Error configuring safe '$($line.SafeName)'. Error: $(Collect-ExceptionMessage $_.Exception)"
			}
		}
		"Members"
		{
			try{
				if([string]::IsNullOrEmpty($UserName))
				{
					# List all members of a safe
					Get-SafeMembers -SafeName $SafeName
				}
				else
				{
					# Add a member to a safe
					$permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = `
					$permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafe = $permManageSafeMembers = $permBackupSafe = $permViewAuditLog = `
					$permViewSafeMembers = $permAccessWithoutConfirmation = $permCreateFolders = $permDeleteFolders = $permMoveAccountsAndFolders = $false
					[int]$permRequestsAuthorizationLevel = 0
					Write-LogMessage -Type Verbose -Msg "Adding member '$UserName' to safe $SafeName with Role '$MemberRole'..."
					switch($MemberRole)
					{
						"Admin"
						{
							$permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = `
							$permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafe = $permManageSafeMembers = $permBackupSafe = `
							$permViewAuditLog = $permViewSafeMembers = $permAccessWithoutConfirmation = $permCreateFolders = $permDeleteFolders = $permMoveAccountsAndFolders = $true
							$permRequestsAuthorizationLevel = 1
						}
						"Auditor"
						{
							$permListAccounts = $permViewAuditLog = $permViewSafeMembers = $true
						}
						"EndUser"
						{
							$permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permViewAuditLog = $permViewSafeMembers = $true
						}
						"Approver"
						{
							$permListAccounts = $permViewAuditLog = $permViewSafeMembers = $true
							$permRequestsAuthorizationLevel = 1
						}
						"Owner"
						{
							$permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = $permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafeMembers = $permViewAuditLog = $permViewSafeMembers = $permMoveAccountsAndFolders = $true
							$permRequestsAuthorizationLevel = 1
						}
					}
					Set-SafeMember -safename $SafeName -safeMember $UserName -memberSearchInLocation $UserLocation `
								-permUseAccounts $permUseAccounts -permRetrieveAccounts $permRetrieveAccounts -permListAccounts $permListAccounts `
								-permAddAccounts $permAddAccounts -permUpdateAccountContent $permUpdateAccountContent -permUpdateAccountProperties $permUpdateAccountProperties `
								-permInitiateCPMManagement $permInitiateCPMManagement -permSpecifyNextAccountContent $permSpecifyNextAccountContent `
								-permRenameAccounts $permRenameAccounts -permDeleteAccounts $permDeleteAccounts -permUnlockAccounts $permUnlockAccounts `
								-permManageSafe $permManageSafe -permManageSafeMembers $permManageSafeMembers -permBackupSafe $permBackupSafe `
								-permViewAuditLog $permViewAuditLog -permViewSafeMembers $permViewSafeMembers `
								-permRequestsAuthorizationLevel $permRequestsAuthorizationLevel -permAccessWithoutConfirmation $permAccessWithoutConfirmation `
								-permCreateFolders $permCreateFolders -permDeleteFolders $permDeleteFolders -permMoveAccountsAndFolders $permMoveAccountsAndFolders
				}
			} catch {
				Write-LogMessage -Type Error -Msg "Error updating Members for safe '$SafeName'. Error: $(Collect-ExceptionMessage $_.Exception)"
			}
		}
	}
	
    # Logoff the session
    # ------------------
	Run-Logoff
}
else
{
    Write-LogMessage -Type Error -Msg "This script requires PowerShell version 3 or above"
}

Write-LogMessage -Type Info -MSG "Script ended" -Footer -LogFile $LOG_FILE_PATH
return
