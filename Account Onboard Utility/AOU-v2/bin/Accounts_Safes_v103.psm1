# CyberArk REST API for versions 10.3 and above

#region URL definition
# Global URLS
# -----------
$URL_Authentication = $URL_PVWAAPI+"/auth"
$global:URL_Logon = $URL_Authentication+"/$AuthType/Logon"
$global:URL_Logoff = $URL_Authentication+"/Logoff"
#endregion

#region REST Commands
#region Accounts
# URL Methods
# -----------
$global:URL_Accounts = $URL_PVWAAPI+"/Accounts"
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
		$urlSearchAccount = $URL_Accounts+"?filter=safename eq "+$(Encode-URL $safeName)+"&search="+$(Encode-URL "$accountName $accountAddress")
		# Search for created account
		$_accounts = $(Invoke-Rest -Uri $urlSearchAccount -Header $(Get-LogonHeader) -Command "Get")
		if($null -ne $_accounts)
		{
			foreach ($item in $_accounts.value)
			{
				if(($item -ne $null) -and ($item.username -eq $accountName) -and ($item.address -eq $accountAddress))
				{
					$_retaccount = $item
					break;
				}
			}
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
		$objAccount = "" | Select "name", "address", "userName", "platformId", "safeName", "secretType", "secret", "platformAccountProperties", "secretManagement", "remoteMachinesAccess"
		$objAccount.platformAccountProperties = $null
		$objAccount.secretManagement = "" | Select "automaticManagementEnabled", "manualManagementReason"
		$objAccount.name = $AccountLine.name
		$objAccount.address = $AccountLine.address
		$objAccount.userName = $AccountLine.userName
		$objAccount.platformId = $AccountLine.platformID
		$objAccount.safeName = $AccountLine.safe
		if ((![string]::IsNullOrEmpty($AccountLine.password)) -and ([string]::IsNullOrEmpty($AccountLine.SSHKey)))
		{ 
			$objAccount.secretType = "password"
			$objAccount.secret = $AccountLine.password
		} elseif(![string]::IsNullOrEmpty($AccountLine.SSHKey)) { 
			$objAccount.secretType = "key" 
			$objAccount.secret = $AccountLine.SSHKey
		}
		else
		{
			# Empty password
			$objAccount.secretType = "password"
			$objAccount.secret = $AccountLine.password
		}
		if(![string]::IsNullOrEmpty($customProps))
		{
			$customProps.count
			# Convert any non-default property in the CSV as a new platform account property
			if($objAccount.platformAccountProperties -eq $null) { $objAccount.platformAccountProperties =  New-Object PSObject }
			For ($i = 0; $i -lt $customProps.count; $i++){
				$prop = $customProps[$i]
				If(![string]::IsNullOrEmpty($prop.Value))
				{
					$objAccount.platformAccountProperties | Add-Member -MemberType NoteProperty -Name $prop.Name -Value $prop.Value 
				}
			}
		}
		$objAccount.secretManagement.automaticManagementEnabled = Convert-ToBool $AccountLine.enableAutoMgmt
		if ($objAccount.secretManagement.automaticManagementEnabled -eq $false)
		{ $objAccount.secretManagement.manualManagementReason = $AccountLine.manualManagementReason }
		$objAccount.remoteMachinesAccess = "" | select "remoteMachines", "accessRestrictedToRemoteMachines"
		$objAccount.remoteMachinesAccess.remoteMachines = $AccountLine.remoteMachineAddresses
		# Convert Restrict Machine Access To List from yes / true to $true
		if ($AccountLine.restrictMachineAccessToList -eq "yes" -or $AccountLine.restrictMachineAccessToList -eq "true") 
		{
			$objAccount.remoteMachinesAccess.accessRestrictedToRemoteMachines =  $true
		} else {
			$objAccount.remoteMachinesAccess.accessRestrictedToRemoteMachines = $false
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
		$restBody = $AccountObject | ConvertTo-Json -Depth 5
		$addAccountResult = $(Invoke-Rest -Uri $URL_Accounts -Header $(Get-LogonHeader) -Body $restBody -Command "Post")
		if($addAccountResult -ne $null)
		{
			Write-LogMessage -Type Debug -MSG "Account $("{0}@{1}" -f $($AccountObject.userName), $AccountObject.address) Onboarded Successfully"
			$retAddAccount = $true
		}
		return $retAddAccount
	}
	catch{
		Throw $(New-Object System.Exception ("Add-Account: Could not Create Account $("{0}@{1}" -f $($AccountObject.userName), $AccountObject.address)",$_.Exception))
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
		$s_Account = $(Get-Account -safeName $AccountObject.safeName -accountName $AccountObject.userName -accountAddress $AccountObject.Address)
		$s_AccountBody = @()
		Foreach($sProp in $s_Account.Properties)
		{
			If($AccountObject.$($sProp.Key) -ne $sProp.Value)
			{
				$_bodyOp = "" | select "op", "path", "value"
				$_bodyOp.op = "replace"
				$_bodyOp.path = "/"+$sProp.Key
				$_bodyOp.value = $AccountObject.$($sProp.Key)
				$s_AccountBody += $_bodyOp
			}
		}
		
		# Update the existing account
		$restBody = ConvertTo-Json @($s_AccountBody) -depth 5
		$urlUpdateAccount = $URL_AccountsDetails -f $s_Account.id
		$UpdateAccountResult = $(Invoke-Rest -Uri $urlUpdateAccount -Header $(Get-LogonHeader) -Body $restBody -Command "PATCH")
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