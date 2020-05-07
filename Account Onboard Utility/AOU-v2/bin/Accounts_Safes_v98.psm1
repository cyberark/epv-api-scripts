# CyberArk REST API for versions 9.8 and above

#region URL definition
# Global URLS
# -----------
$URL_Authentication = $URL_PVWAWebServices+"/auth/$AuthType/CyberArkAuthenticationService.svc"
$global:URL_Logon = $URL_Authentication+"/Logon"
$global:URL_Logoff = $URL_Authentication+"/Logoff"
#endregion

#region REST Commands
#region Safes
# URL Methods
# -----------
$global:URL_Safes = $URL_PVWABaseAPI+"/Safes"
$global:URL_SafeDetails = $URL_PVWABaseAPI+"/Safes/{0}"
$global:URL_SafeMembers = $URL_PVWABaseAPI+"/Safes/{0}/Members"

Function Get-Safe
{
<#
.SYNOPSIS
Returns safe details on a specific safe

.DESCRIPTION
Returns safe details on a specific safe

.EXAMPLE
Get-Safe -safename "Win-Local-Admins" 

#> 
	param ($safeName)
	$_safe = $null
	try{
		Write-LogMessage -Type Debug -Msg "Getting Safe details for $safename"
		$accSafeURL = $URL_SafeDetails -f $safeName
		$_safe = $(Invoke-Rest -Uri $accSafeURL -Header (Get-LogonHeader) -Command "Get" -ErrorAction "SilentlyContinue")
	}
	catch
	{
		Throw $(New-Object System.Exception ("Get-Safe: There was an error retriving safe details for $safeName.",$_.Exception))
	}
	
	return $_safe.GetSafeResult
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
	try {
		Write-LogMessage -Type Debug -Msg "Getting owners for safe $safename"
		$_defaultUsers = @("Master","Batch","Backup Users","Auditors","Operators","DR Users","Notification Engines","PVWAGWAccounts","PasswordManager")
		$accSafeMembersURL = $URL_SafeMembers -f $safeName
		$_safeMembers = $(Invoke-Rest -Uri $accSafeMembersURL -Header (Get-LogonHeader) -Command "Get" -ErrorAction "SilentlyContinue")
		# Remove default users and change UserName to MemberName
		$_safeOwners = $_safeMembers.members | Where {$_.UserName -notin $_defaultUsers} | Select-Object -Property @{Name = 'MemberName'; Expression = { $_.UserName }}, Permissions
		Write-LogMessage -Type Debug -Msg "Returning $($_safeOwners.count) members"
	}
	catch
	{
		Throw $(New-Object System.Exception ("Get-SafeMembers: There was an error getting the owners for safe $safeName.",$_.Exception))
	}
	
	return $_safeOwners		
}

Function Test-Safe
{
<#
.SYNOPSIS
Checks if a safe exists or not

.DESCRIPTION
Checks if a safe exists or not

.EXAMPLE
Test-Safe -safename "Win-Local-Admins" 

#> 
	param (
		[Parameter(Mandatory=$true)]
		[String]$safeName
		)
		
	try{
		If ($null -eq $(Get-Safe -safeName $safeName))
		{
			# Safe does not exist
			Write-LogMessage -Type Warning -MSG "Safe $safeName does not exist"
			return $false
		}
		else
		{
			# Safe exists
			Write-LogMessage -Type Info -MSG "Safe $safeName exists"
			return $true
		}
	}
	catch
	{
		# Check the error code returned from the REST call
		$innerExcp = $_.Exception.InnerException
		Write-LogMessage -Type Verbose -Msg "Status Code: $($innerExcp.StatusCode); Status Description: $($innerExcp.StatusDescription); REST Error: $($innerExcp.CyberArkErrorMessage)"
		if($innerExcp.StatusCode -eq "NotFound") {
			return $false
		}
		else{
			Throw $(New-Object System.Exception ("Test-Safe: There was an error testing existance of safe $safeName.",$_.Exception))
		}
	}
}
Export-ModuleMember -Function Test-Safe

$global:TemplateSafeDetails = $null
$global:TemplateSafeMembers = $null
Function New-TemplateSafe
{
<#
.SYNOPSIS
Creates a new Safe based on a template safe

.DESCRIPTION
Creates a new Safe based on a template safe. 
The new safe is created with all the template safe members as well

.EXAMPLE
New-TemplateSafe -safename "Win-Local-Admins" -templateSafeName "TemplateSafe" 

#> 
	param (
		[Parameter(Mandatory=$true)]
        [string]$safename,
		[Parameter(Mandatory=$true)]
		[string]$templateSafeName
	)
	
	try {
		if ($null -eq $TemplateSafeDetails -and $null -eq $TemplateSafeMembers)
		{
			If ((Test-Safe -safeName $templateSafeName))
			{
				# Safe Exists
				Set-Variable -scope Global -Name TemplateSafeDetails -Value (Get-Safe -safeName $templateSafeName)
				$TemplateSafeDetails.Description = "Template Safe Created using Accounts Onboard Utility"
				# Get the Template safe members
				Set-Variable -scope Global -Name TemplateSafeMembers -Value (Get-SafeMembers -safeName $templateSafeName)
			}
			else
			{
				Throw "Safe $templateSafeName does not exist"
			}
		}
	
		# Update the safe name and description in the Safe Template Object
		$TemplateSafeDetails.SafeName = $safeName
		
		# Create the new Safe
		$restBody = @{ safe=$templateSafeObject } | ConvertTo-Json -Depth 3
		$createSafeResult = $(Invoke-Rest -Uri $URL_Safes -Header (Get-LogonHeader) -Command "Post" -Body $restBody)
		if ($createSafeResult)
		{
			$urlOwnerAdd = $URL_SafeMembers -f $safeName
			# Add the template safe owners to the newly created safe
			ForEach($bodyMember in $TemplateSafeMembers)
			{
				$restBody = @{ member=$bodyMember } | ConvertTo-Json -Depth 3
				# Add the Safe Owner
				try {
					# Add the Safe Owner
					$restResponse = Invoke-Rest -Uri $urlOwnerAdd -Header (Get-LogonHeader) -Command "Post" -Body $restBody
				} catch {
					Write-LogMessage -Type Error -MSG "Failed to add Owner to safe $safeName with error: $($_.Exception.Response.StatusDescription)"
				}
			}
			
			return $true
		}
		else
		{
			Throw "Template Safe Creation failed"
		}
	} catch {
		Throw $(New-Object System.Exception ("New-TemplateSafe: Failed to create safe $safeName.",$_.Exception))
	}
}

Function New-Safe
{
<#
.SYNOPSIS
Creaets a new Safe

.DESCRIPTION
Creaets a new Safe

.EXAMPLE
New-Safe -safename "Win-Local-Admins" -safedescription "This is a safe for all Windows Local Admin Accounts"

#> 
	param (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$safename,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string]$safedescription,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [string]$managingCPM="PasswordManager",
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [int]$numVersionRetention=7,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [int]$numDaysRetention=5,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)]
        [bool]$EnableOLAC=$false,
		[Parameter(Mandatory=$false)]
		[string]$templateSafeName
		)
	
	# Check if Template Safe is in used
	If(![string]::IsNullOrEmpty($templateSafeName))
	{
		# Using Template Safe
		Write-LogMessage -Type Info -MSG "Creating Safe $safeName according to Template"
		New-TemplateSafe -safename $safeName -templateSafeName $templateSafeName
	}
	else
	{
		# Create the Target Safe
		Write-LogMessage -Type Info -MSG "Creating Safe $safeName"
		$bodySafe = @{ SafeName=$safeName;Description="$safeName - Created using Accounts Onboard Utility";OLACEnabled=$EnableOLAC;ManagingCPM=$managingCPM;NumberOfDaysRetention=$numDaysRetention }
		$restBody = @{ safe=$bodySafe } | ConvertTo-Json -Depth 3
		try{
			$createSafeResult = $(Invoke-Rest -Uri $URL_Safes -Header (Get-LogonHeader) -Command "Post" -Body $restBody)
			if ($createSafeResult)
			{
				Write-LogMessage -Type Debug -MSG "Safe $safename created"
				return $true
			}
			else { 
				# Safe creation failed
				Write-LogMessage -Type Error -MSG "Safe Creation failed - Should Skip Account Creation"
				return $false 
			}
		} catch {
			Throw $(New-Object System.Exception ("New-Safe: Failed to create safe $safeName.",$_.Exception))
		}
	}
}
Export-ModuleMember -Function New-Safe

Function Add-SafeOwner
{
<#
.SYNOPSIS
Adds a new Owner to an existing safe

.DESCRIPTION
Adds a new Owner to an existing safe

.EXAMPLE
Add-SafeOwner -safename "Win-Local-Admins" -member "User1" -memberRole "EndUser"

#> 
	param (
		[Parameter(Mandatory=$true)]
		[String]$safeName, 
		[Parameter(Mandatory=$true)]
		[String]$member,
		[Parameter(Mandatory=$true)]
		[ValidateSet("Admin", "Auditor", "EndUser", "Owner")]
		[String]$memberRole,
		[Parameter(Mandatory=$false,HelpMessage="Which vault-integrated LDAP directory name the vault should search for the account. Must match one of the directory names defined in the LDAP Integration page of the PVWA.")]
        $memberSearchInLocation = "Vault"
	)
	
	try{
		$rolePermissions = Get-RolePermissions -Role $memberRole
		$addSafeOwnerBody = @{member=@{MemberName=$member; SearchIn=$memberSearchInLocation;MembershipExpirationDate=$null;Permissions=$rolePermissions}} | ConvertTo-Json -Depth 5
		Write-LogMessage -Type Debug -Msg "Setting safe membership for $member located in $memberSearchInLocation on $safeName..."
		$addSafeOwnerResponse = Invoke-Rest -Command POST -URI $($URL_SafeMembers -f $(Encode-URL $safeName)) -Body $addSafeOwnerBody -Headers $(Get-LogonHeader)
	} catch {
		Throw $(New-Object System.Exception ("Add-SafeOwner: There was an error setting the membership for $safeMember on $safeName in the Vault.",$_.Exception))
	}
}
Export-ModuleMember -Function Add-SafeOwner

Function Get-RolePermissions
{
<#
.SYNOPSIS
Returns a detailed permissions dictionary for a safe owner based on Role

.DESCRIPTION
Returns a detailed permissions dictionary for a safe owner based on Role

.EXAMPLE
Get-RolePermissions -Role "EndUser"

#>
	param (
		[Parameter(Mandatory=$true)]
		[ValidateSet("Admin", "Auditor", "EndUser", "Owner")]
		[String]$Role
	)
	
	# Add a member to a safe
	[bool]$permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = `
		$permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafe = $permManageSafeMembers = $permBackupSafe = $permViewAuditLog = `
		$permViewSafeMembers = $permAccessWithoutConfirmation = $permCreateFolders = $permDeleteFolders = $permMoveAccountsAndFolders = $false
	[int]$permRequestsAuthorizationLevel = 0
	switch($Role)
	{
		"Admin"
		{
			$permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = `
				$permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafe = $permManageSafeMembers = $permBackupSafe = `
				$permViewAuditLog = $permViewSafeMembers = $permAccessWithoutConfirmation = $permCreateFolders = $permDeleteFolders = $permMoveAccountsAndFolders = $true
			$permRequestsAuthorizationLevel = 1
			break
		}
		"Auditor"
		{
			$permListAccounts = $permViewAuditLog = $permViewSafeMembers = $true
			break
		}
		"EndUser"
		{
			$permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permViewAuditLog = $permViewSafeMembers = $true
			break
		}
		"Approver"
		{
			$permListAccounts = $permViewAuditLog = $permViewSafeMembers = $true
			$permRequestsAuthorizationLevel = 1
			break
		}
		"Owner"
		{
			$permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = $permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafeMembers = $permViewAuditLog = $permViewSafeMembers = $permMoveAccountsAndFolders = $true
			$permRequestsAuthorizationLevel = 1
			break
		}
	}
	
	$permissionDictionary = New-Object "System.Collections.Generic.Dictionary[[String],[Object]]"
	$permissionDictionary.Add("UseAccounts", $permUseAccounts)
    $permissionDictionary.Add("RetrieveAccounts", $permRetrieveAccounts)
    $permissionDictionary.Add("ListAccounts", $permListAccounts)
    $permissionDictionary.Add("AddAccounts", $permAddAccounts)
    $permissionDictionary.Add("UpdateAccountContent", $permUpdateAccountContent)
    $permissionDictionary.Add("UpdateAccountProperties", $permUpdateAccountProperties)
    $permissionDictionary.Add("InitiateCPMAccountManagementOperations", $permInitiateCPMManagement)
    $permissionDictionary.Add("SpecifyNextAccountContent", $permSpecifyNextAccountContent)
    $permissionDictionary.Add("RenameAccounts", $permRenameAccounts)
    $permissionDictionary.Add("DeleteAccounts", $permDeleteAccounts)
    $permissionDictionary.Add("UnlockAccounts", $permUnlockAccounts)
    $permissionDictionary.Add("ManageSafe", $permManageSafe)
    $permissionDictionary.Add("ManageSafeMembers", $permManageSafeMembers)
    $permissionDictionary.Add("BackupSafe", $permBackupSafe)
    $permissionDictionary.Add("ViewAuditLog", $permViewAuditLog)
    $permissionDictionary.Add("ViewSafeMembers", $permViewSafeMembers)
    $permissionDictionary.Add("RequestsAuthorizationLevel", $permRequestsAuthorizationLevel)
    $permissionDictionary.Add("AccessWithoutConfirmation", $permAccessWithoutConfirmation)
    $permissionDictionary.Add("CreateFolders", $permCreateFolders)
    $permissionDictionary.Add("DeleteFolders", $permDeleteFolders)
    $permissionDictionary.Add("MoveAccountsAndFolders", $permMoveAccountsAndFolders)
	
	return $permissionDictionary
}

#endregion

#region Accounts
# URL Methods
# -----------
$global:URL_Account = $URL_PVWABaseAPI+"/Account"
$global:URL_Accounts = $URL_PVWABaseAPI+"/Accounts"
$global:URL_AccountsDetails = $URL_Accounts+"/{0}"

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-Account
# Description....: Returns a list of accounts based on a filter
# Parameters.....: Account name, Account address, Account Safe Name
# Return Values..: List of accounts
# =================================================================================================================================
Function Get-Account
{
<# 
.SYNOPSIS 
	Returns accoutns based on filters
.DESCRIPTION
	Creates a new Account Object
.PARAMETER AccountName
	Account user name
.PARAMETER AccountAddress
	Account address
.PARAMETER SafeName
	The Account Safe Name to search in
#>
	param (
		[Parameter(Mandatory=$true)]
		[String]$accountName, 
		[Parameter(Mandatory=$true)]
		[String]$accountAddress, 
		[Parameter(Mandatory=$true)]
		[String]$safeName
	)
	$_retaccount = $null
	$_accounts = $null
	try{
		# Search for created account
		$urlSearchAccount = $URL_Accounts+"?Safe="+$(Encode-URL $safeName)+"&Keywords="+$(Encode-URL "$accountName $accountAddress")
		$_account = $(Invoke-Rest -Uri $urlSearchAccount -Header (Get-LogonHeader) -Command "Get")
		if($null -ne $_account)
		{
			$_retaccount = $_account.accounts
		}
	} catch {
		Throw $(New-Object System.Exception ("Get-Account: There was an error retreiving the account object.",$_.Exception))
	}
	
	return $_retaccount
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-Account
# Description....: Checks if an account exists
# Parameters.....: Account name, Account address, Account Safe Name
# Return Values..: True / False
# =================================================================================================================================
Function Test-Account
{
<# 
.SYNOPSIS 
	Test if an accoutn exists (Search based on filters)
.DESCRIPTION
	Test if an accoutn exists (Search based on filters)
.PARAMETER AccountName
	Account user name
.PARAMETER AccountAddress
	Account address
.PARAMETER SafeName
	The Account Safe Name to search in
#>
	param (
		[Parameter(Mandatory=$true)]
		[String]$accountName, 
		[Parameter(Mandatory=$true)]
		[String]$accountAddress, 
		[Parameter(Mandatory=$true)]
		[String]$safeName
	)
	try {
		$accResult = $(Get-Account -accountName $accountName -accountAddress $accountAddress -safeName $safeName)
		If (($null -eq $accResult) -or ($accResult.count -eq 0))
		{
			# No accounts found
			Write-LogMessage -Type Debug -MSG "Account $accountName does not exist"
			return $false
		}
		else
		{
			# Account Exists
			Write-LogMessage -Type Info -MSG "Account $accountName exist"
			return $true
		}
	} catch {
		# Check the error code returned from the REST call
		$innerExcp = $_.Exception.InnerException
		Write-LogMessage -Type Verbose -Msg "Status Code: $($innerExcp.StatusCode); Status Description: $($innerExcp.StatusDescription); REST Error: $($innerExcp.CyberArkErrorMessage)"
		if($innerExcp.StatusCode -eq "NotFound") {
			return $false
		}
		else{
			Throw $(New-Object System.Exception ("Test-Account: There was an error finding the account object.",$_.Exception))
		}
	}
}
Export-ModuleMember -Function Test-Account

# @FUNCTION@ ======================================================================================================================
# Name...........: New-AccountObject
# Description....: Creates a new Account object
# Parameters.....: Account line read from CSV
# Return Values..: Account Object foro onboarding
# =================================================================================================================================
Function New-AccountObject
{
<# 
.SYNOPSIS 
	Creates a new Account Object
.DESCRIPTION
	Creates a new Account Object
.PARAMETER AccountLine
	(Optional) Account Object Name
#>
	param (
		[Parameter(Mandatory=$true)]
		[PSObject]$AccountLine
	)
	try{
		# Convert Account from CSV to Account Object (properties mapping)
		$objAccount = "" | select Safe,Folder,PlatformID,Address,UserName,Password,DeviceType,AccountName,Properties,disableAutoMgmt,disableAutoMgmtReason
		$ObjAccount | Add-Member -MemberType AliasProperty -Name safeName -Value safe | out-null
		$objAccount.Properties = @()
		$objAccount.accountName = $AccountLine.name
		$objAccount.address = $AccountLine.address
		$objAccount.userName = $AccountLine.userName
		$objAccount.Password = $AccountLine.Password
		$objAccount.platformId = $AccountLine.platformID
		$objAccount.safe = $AccountLine.safe
		# Convert DisableAutoMgmt from yes / true to $true
		$objAccount.disableAutoMgmt = Convert-ToBool $AccountLine.enableAutoMgmt
		if ($objAccount.disableAutoMgmt -eq $false)
		{ $objAccount.disableAutoMgmtReason = $AccountLine.manualManagementReason }
		
		# Check if there are custom properties
		$customProps = $($AccountLine.PSObject.Properties | Where { $_.Name -notin "username","address","safe","platformID","password","disableAutoMgmt","disableAutoMgmtReason","groupName","groupPlatformID" })
		if($customProps -ne $null)
		{
			# Convert any non-default property in the CSV as a new account property
			ForEach ($prop in $customProps)
			{
				If(![string]::IsNullOrEmpty($prop.Value))
				{ $objAccount.properties += @{"Key"=$prop.Name; "Value"=$prop.Value} }
				$objAccount.PSObject.Properties.Remove($prop.Name)
			}
		}
		
		return $objAccount
	} catch {
		Throw $(New-Object System.Exception ("New-AccountObject: There was an error creating a new account object.",$_.Exception))
	}
}
Export-ModuleMember -Function New-AccountObject

# @FUNCTION@ ======================================================================================================================
# Name...........: New-Account
# Description....: Adds an Account to the PVWA
# Parameters.....: Account object created from New-AccountObject
# Return Values..: True / False
# =================================================================================================================================
Function New-Account
{
<# 
.SYNOPSIS 
	Adds an Account to the PVWA
.DESCRIPTION
	Adds an Account to the PVWA
.PARAMETER AccountObject
	Account Object (created from New-AccountObject function)
#>
	param(
		[Parameter(Mandatory=$true)]
		[PSObject]$AccountObject
	)
	try{			
		$retAddAccount = $false
		# Create the Account
		$restBody = @{ account=$AccountObject } | ConvertTo-Json -Depth 5
		$addAccountResult = $(Invoke-Rest -Uri $URL_Account -Header $(Get-LogonHeader) -Body $restBody -Command "Post")		
		if($addAccountResult -ne $null)
		{
			Write-LogMessage -Type Debug -MSG "Account $("{0}@{1}" -f $($AccountObject.userName), $AccountObject.address) Onboarded Successfully"
			$retAddAccount = $true
		}
		return $retAddAccount
	}
	catch{
		Throw $(New-Object System.Exception ("New-Account: Could not Create Account $("{0}@{1}" -f $($AccountObject.userName), $AccountObject.address)",$_.Exception))
	}
}
Export-ModuleMember -Function New-Account

# @FUNCTION@ ======================================================================================================================
# Name...........: Update-Account
# Description....: Update an existing Account in the PVWA
# Parameters.....: Account object created from New-AccountObject
# Return Values..: True / False
# =================================================================================================================================
Function Update-Account
{
<# 
.SYNOPSIS 
	Update an existing Account in the PVWA
.DESCRIPTION
	Update an existing Account in the PVWA
.PARAMETER AccountObject
	Account Object (created from New-AccountObject function)
#>
	param(
		[Parameter(Mandatory=$true)]
		[PSObject]$AccountObject
	)
	try{			
		$retUpdateAccount = $false
		# Get Existing Account Details
		$s_Account = $(Get-Account -safeName $AccountObject.Safe -accountName $AccountObject.username -accountAddress $AccountObject.address)
		
		# Create the Account to update with current properties
		$updateAccount = "" | select Safe,Folder,PlatformID,Address,UserName,DeviceType,AccountName,Properties
		$updateAccount.Properties = @()
		$updateAccount.Properties += $AccountObject.properties
		ForEach($sProp in $s_Account.Properties)
		{
			switch($sProp.Key)
			{
				"Safe" { 
					$updateAccount.Safe = $sProp.Value
					If(![string]::IsNullOrEmpty($AccountObject.Safe) -and $AccountObject.Safe -ne $updateAccount.Safe)
					{
						$updateAccount.Safe = $AccountObject.Safe	
					}
					break
				}	
				"Folder" { 
					$updateAccount.Folder = $sProp.Value 
					If(![string]::IsNullOrEmpty($AccountObject.Folder) -and $AccountObject.Folder -ne $updateAccount.Folder)
					{
						$updateAccount.Folder = $AccountObject.Folder	
					}
					break
				}
				"PolicyID" { 
					$updateAccount.PlatformID = $sProp.Value
					If(![string]::IsNullOrEmpty($AccountObject.PlatformID) -and $AccountObject.PlatformID -ne $updateAccount.PlatformID)
					{
						$updateAccount.PlatformID = $AccountObject.PlatformID	
					}
					break
				}
				"DeviceType" { 
					$updateAccount.DeviceType = $sProp.Value
					#If(![string]::IsNullOrEmpty($AccountObject.DeviceType) -and $AccountObject.DeviceType -ne $updateAccount.DeviceType)
					#{
					#	$updateAccount.DeviceType = $AccountObject.DeviceType	
					#}
					break
				}
				"Address" { 
					$updateAccount.Address = $sProp.Value
					If(![string]::IsNullOrEmpty($AccountObject.Address) -and $AccountObject.Address -ne $updateAccount.Address)
					{
						$updateAccount.Address = $AccountObject.Address	
					}
					break
				}
				"Name" { 
					$updateAccount.AccountName = $sProp.Value
					If(![string]::IsNullOrEmpty($AccountObject.AccountName) -and $AccountObject.AccountName -ne $updateAccount.AccountName)
					{
						$updateAccount.AccountName = $AccountObject.AccountName	
					}
					break
				}
				"UserName" { 
					$updateAccount.UserName = $sProp.Value
					If(![string]::IsNullOrEmpty($AccountObject.UserName) -and $AccountObject.UserName -ne $updateAccount.UserName)
					{
						$updateAccount.UserName = $AccountObject.UserName	
					}
					break
				}
				default {
					# Check other properties on the account to update
					ForEach($uProp in $updateAccount.Properties)
					{
						if($uProp.ContainsValue($sProp.Name))
						{
							$uProp.Value = $sProp.Value
						}
					}
					break
				}
			}
		}
		
		# Check if we need to add more properties to the updated account
		If ($AccountObject.disableAutoMgmt)
		{
			$updateAccount.Properties += @{"Key"="CPMDisabled"; "Value"="yes"}
		}

		# Update the existing account
		$restBody = @{ Accounts=$updateAccount } | ConvertTo-Json -depth 5
		$urlUpdateAccount = $URL_AccountDetails -f $s_Account.AccountID
		$UpdateAccountResult = $(Invoke-Rest -Uri $urlUpdateAccount -Header (Get-LogonHeader) -Body $restBody -Command "PUT")

		if($updateAccountResult -ne $null)
		{
			Write-LogMessage -Type Debug -MSG "Account $("{0}@{1}" -f $($AccountObject.userName), $AccountObject.address) was updated Successfully"
			$retUpdateAccount = $true
		}
		return $retUpdateAccount
	}
	catch{
		Throw $(New-Object System.Exception ("Update-Account: Could not Update Account $("{0}@{1}" -f $($AccountObject.userName), $AccountObject.address)",$_.Exception))
	}
}
Export-ModuleMember -Function Update-Account
#endregion
#endregion