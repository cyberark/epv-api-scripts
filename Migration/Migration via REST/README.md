
# Main capabilities
-----------------
Module to migrate accounts and safes from one environment into another

## Process flow
### Commands used
- Import-Module '\Migrate.psm1' -force
- New-SourceSession
- Export-Accounts
- Import-Accounts
- New-DestinationSession
- Sync-Safes
- Sync-Accounts

"Import-Module '\Migrate.psm1' -force" will load the module
"New-SourceSession" will establish a connection to the environment that currently has the safes and accounts
"Export-Accounts" will export all accounts the user that used "New-SourceSession" has access too
	After the accounts have been exported you will want to review the CSV file to determin if accounts need to be removed from the list
"Import-Accounts" will import a new list of accounts that will be targeted for migration
	Only needed if the exported account list required changes
"New-DestinationSession" will establish a connection to the environment that will be receiving the safes and accounts
"Sync-Safes" can be used to create safes, including the safe memberships, in the new destination environment. If the safe already exists it the destination environment, and update safe member is passed,  you can optionally update the destination safe memberships
	If safe memberships are selected for updates, it is possible for owners to have existing access removed. Use with caution
"Sync-Accounts" can be used to create accounts in the destination environment. It can also be used to synchronize the remote machines that the account has access too.
	At this time, it will NOT update any properties on existing accounts. Only the secret and remote machines will be updated on existing accounts

## Current limitations

1. Safe memberships during updates are copied directly over which can result in access being removed
   1. Plan in future version is to allow for the selection of add permissions only
2. Safe properties are not updated, only set on creation
3. The ability to select CPM in destination environment is limited
   1. Only have the ability to replace the name of one CPM with a new name at this time
      1. Future version will allow for multiple CPM names to be replaced
   2. If multiple CPMs exist in the destintation environment use the export-accounts and import-accounts to work on subsets of accounts/safes and use the CPM name override to set the CPM name accordinly
4. Account properties are not updated during synchronization, only secrets and remote machine access
   1. Due to the REST API not allowing for full account updates we need to first pull that account, run a compare to identity the differences, and then send only updates. Work in progress
5. SSH keys are not able to be synchronized
   1. This limitation is due to REST not supporting updates of SSH key, only creations
6. All required files must be in the same location
   1. Migrate.psm1
   2. Invoke-Process.ps1
   3. Cyberark-Migration.pms1
# Commands
More detailed info about paramters are available via Get-Help

## New-SourceSession
### SYNOPSIS
Established a new session to the source environment
### SYNTAX
```powershell
New-SourceSession [-srcPVWAURL] <String> [[-srcAuthType] <String>] [[-srcOTP] <String>] [[-srcPVWACredentials] <PSCredential>] [[-srcLogonToken] <Object>] [-DisableSSLVerify] [<CommonParameters>]
```
### DESCRIPTION
Established a new session to the source environment.
This can be either on-premie or Privileged Cloud environment

## Export-Accounts
### SYNOPSIS
Exports accounts from the source environment
### SYNTAX

```
Export-Accounts [[-exportCSV] <Object>] [<CommonParameters>]
```
### DESCRIPTION
Exports accounts from the source environment and stores them in a variable called AccountList to be used by Sync-Safe and Sync-Accounts.
Generates a feed file called ExportOfAccounts.csv

## Import-Accounts
### SYNOPSIS
Import a list of accounts to be used by Sync-Safe and Sync-Accounts
### SYNTAX
```powershell
Import-Accounts [[-importCSV] <String>] [<CommonParameters>]
```
### DESCRIPTION
Import accounts from a CSV and stores them in a variable called AccountList to be used by Sync-Safe and Sync-Accounts.
Default name of feed file called ExportOfAccounts.csv

## New-DestinationSession
### SYNOPSIS
Established a new session to the destination environment.
### SYNTAX
```powershell
New-DestinationSession [-dstPVWAURL] <String> [[-dstAuthType] <String>] [[-dstOTP] <String>]
 [[-dstPVWACredentials] <PSCredential>] [[-dstLogonToken] <Object>] [-DisableSSLVerify] [<CommonParameters>]
```
### DESCRIPTION
Established a new session to the destination environment.
This can be either on-premie or Privileged Cloud environment

## Sync-Safes
### SYNOPSIS
Synchronizes the safes between the two environments
### SYNTAX
```powershell
Sync-Safes [-CreateSafes] [-UpdateSafeMembers] [[-CPMOld] <String>] [[-CPMNew] <String>] [[-CPMOverride] <String>] [[-CPMList] <String[]>] [[-newDir] <String>] [[-dstDomainSuffix] <String>] [-srcRemoveDomain] [[-maxJobCount] <String>] [-ProgressDetails] [-SuppressProgress] [<CommonParameters>]
```
### DESCRIPTION
Using the variable AccountList to target specific safes connects to the two environments does the following process
- Determines if the safe already exists in the destination environment
	- If the safe does not exist, create the safe if CreateSafes switch is passed
- Updates safe ownerships on newly created safes based on the ownership in the source environment
- If the safe does exist and UpdateSafeMembers switch is passed updates safe ownerships on safes based on the ownership in the source environment

Prior to running ensure the following items in both environments are set
- The user that is running the command has direct access to all in scope safes in both environments
	- In the source environment the minimum ownerships are the following
		- List Accounts, Retrieve Accounts, View Safe members, Access Safe without confirmation (If dual control active)
	- In the destination environment the minimum ownerships are the following
		- Full Permission required
			- This is due to the requirement that you must have the permissions to be able to grant the permissions
	- Group membership in "Vault Admins" or "Auditors" will cause all accounts to be exported, including system level accounts which should not be migrated

Prior to running it is recommended that the following items in both environments are set.
- A dedicated "Export" and "Import" users are created

After running the following items are recommended
- After beginning use of the destination environment and verifications have been completed, delete the user account used to import safes
- The import user will retain full permissions to any safe it created, the easiest and most secure method to ensure that access is removed is to delete the user.

To get further information about the paramaters use "Get-Help Sync-Safes -full"
## Sync-Accounts

### SYNOPSIS
Synchronizes the accounts between the two environments

### SYNTAX

```powershell
Sync-Accounts [-SkipCheckSecret] [-getRemoteMachines] [-noCreate] [-allowEmpty] [-VerifyPlatform] [[-maxJobCount] <String>] [-ProgressDetails] [-SuppressProgress] [<CommonParameters>]
```

### DESCRIPTION
Using the variable AccountList to target specific accounts connects to two environments does the following process
- If VerifyPlatform is passed get a list of all platforms on destination environment
    - For each future create verify that the platform from the source environment exist in the destination environment, if it doesn't fail the create
    - For each future create update the platformID casing to match the casing in the destination environment
- Determines if the account already exists in the destination environment and the source account has a secret set
    - If the account does not exist create the account unless NoCreate is passed
    - If the account does not have a secret set, do not create the account unless allowEmpty is passed
- Unless SkipCheckSecret is passed, for each existing account found, verify that the secret matches between the source and destination
    - Whenever possible ensures that secrets for both the source and destination are stored in variables as SecureStrings and only retained for as long as needed and then removed.
- If getRemoteMachines is passed, update the destination account with the values from the source account

Prior to running ensure the following items in both environments are set
- CPMs stopped in both environments
  - This is to prevent password from being locked due to CPM initiated changes and password unexpectedly changing
- "Enforce check-in/check-out exclusive access" is inactive
  - Due to the command reading the secret in both environments if Exclusive use is enabled all accounts will become locked to the user running the command
- "Enforce one-time password access" is inactive
  - If enabled all secrets will change based on the platform MinValidityPeriod and exclusive access settings
- "Require dual control password access approval" is inactive or the user running the commands has "Access Safe without Confirmation" for all in scope safes
  - If "DisableDualControlForPSMConnections" is set to "Yes" on the platform either "dual controls" must be set to inactive or the platform updated to have "DisableDualControlForPSMConnections" set to "No".
    - This is due to a limitation in the REST interface
- Ensure all in scope accounts are unlocked
  - This can easiest be done by using PrivateArk Client.
    - After logging in "CTRL + F", select "Advanced" tab, check only "Locked", and clicking "Find".
    - All locked accounts will be displayed in the results pane, click in this pane and then select "Edit", "Select All".
      - With everything highlighted, right click and then select "Unlock File"
      - All locked files will now be unlocked.
        - Unlocking this way will NOT trigger the CPM to change the password when restarted.

Prior to running it is recommended that the following items in both environments are set.
- A dedicated "Export" and "Import" users are created
- "NFNotifyOnPasswordUsed" is set to "No" to ensure a large amount of emails are not generated
  - If "Yes", ensure that "Event Notification Engine" is stopped and you delete "\PrivateArk\Safes\ENE\ENELastEventID.dat" prior to restarting.
    - In Privilege Cloud environments clients do not have access to the ENE.
- "EnforcePasswordPolicyOnManualChange" is set to "No"
  - This will allow for the currently in use secrets, and prior secrets, to be used to ensure they are synchronized between environments
- "AutoChangeOnAdd" are set to "No"
  - The will prevent the secrets from automatically changing when the CPM in the destination is turned on
- "AutoVerifyOnAdd" are set to "No"
  - This will prevent the CPM from having a large workload on initial startup after work

After running the following items are recommended
- Any "Master Policy" or "Platform" settings adjusted to allow for export and import are reset back to standard values
- Only the environment that is currently being actively used has a running CPM.
- IF CPMs are required to be running in both environments, ensure each safe has a CPM assigned in only one environment at a time.
- Prior to beginning use of the destination environment, verify no password have changed in the source environment that have not been synchronized.
  - You can see the data of last secret change of the source account by running "Export-Accounts" and reviewing the column titled "PasswordLastChangeUTC".
    - The time zone used to display the date and time of last password change is UTC (+0)
  - If secretes have changed remove all other entries in the CSV, leaving on the accounts with secret changes, and use "Import-Account" to target those accounts specifically
- After beginning use of the destination environment and verifications have been completed, delete the user account used to import safes
  - The import user will retain full permissions to any safe it created, the easiest and most secure method to ensure that access is removed is to delete the user.

To get further information about the paramaters use "Get-Help Sync-Accounts -full"