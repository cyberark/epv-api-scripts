
# Migration

## Main capabilities

Migrate accounts and safes from one environment into another using this module.

## Process flow
### Commands used
1. `Import-Module '.\Migrate.psm1' -force`
2. `New-SourceSession`
3. `Export-Accounts`
4. `Import-Accounts`
5. `New-DestinationSession`
6. `Sync-Safes`
7. `Sync-Accounts`

### Explanation 

1. `Import-Module '\Migrate.psm1' -force` will load the module.
2. `New-SourceSession` will establish a connection to the environment that currently has the Safes and Accounts
3. `Export-Accounts` will export all accounts accessible by the user (who used `New-SourceSession`). 
	  - After the accounts have been exported, review the .csv file to check if some Accounts need to be removed.
4. `Import-Accounts` will import a new list of accounts that will be targeted for migration
    - Only needed if the exported account list required changes.
5. `New-DestinationSession` will establish a connection to the environment that will be receiving the Safes and Accounts.
6. `Sync-Safes` can be used to create Safes, including the Safe memberships, in the new destination environment.
    - If the Safe does not exist and `-CreateSafes` is passed: creates the Safe.
    - If the Safe exists and `-UpdateSafeMembers` is passed: updates Safe ownerships on the ownership in the source environment.
    - Updates Safe ownerships on newly created Safes based on the ownership in the source environment. It is possible for owners to have existing access removed. Use with caution.
7. `Sync-Accounts` can be used to create Accounts in the destination environment. It can also be used to synchronize the remote machines that the account has access too.
    - At this time, it will NOT update any properties on existing accounts. Only the secret and remote machines will be updated on existing accounts.

## Current limitations

1. During updates, Safe memberships are copied directly over which can result in access being removed
   1. Plan for future version: to allow for the selection of add permissions only
2. Safe properties are not updated, only set on creation
3. The ability to select CPM in destination environment is limited
   1. Only possible to replace the name of one CPM with a new name at this time
      - Future version will allow for multiple CPM names to be replaced
   2. If multiple CPMs exist in the destination environment: use `Export-Accounts` and `Import-Accounts` to work on subsets of Accounts/Safes and use the CPM name override to set the CPM name accordingly.
4. Account properties are not updated during synchronization, only secrets and remote machine access
   1. Due to the REST API not allowing for full account updates we need to first pull that account, run a compare to identify the differences, and then send only updates. Work in progress.
5. SSH keys are not able to be synchronized
   1. This limitation is due to REST not supporting updates of SSH key, only creations
6. All required files must be in the same location
   1. Migrate.psm1
   2. Invoke-Process.ps1
   3. Cyberark-Migration.pms1

## Commands
More detailed info about parameters are available via `Get-Help`.

### New-SourceSession
#### SYNOPSIS
Establish a new session to the source environment.

#### SYNTAX
```PowerShell
New-SourceSession [-srcPVWAURL] <String> [[-srcAuthType] <String>] [[-srcOTP] <String>] [[-srcPVWACredentials] <PSCredential>] [[-srcLogonToken] <Object>] [-DisableSSLVerify] [<CommonParameters>]
```
#### DESCRIPTION
Established a new session to the source environment.
This can be either on-premie or Privileged Cloud environment

### Export-Accounts
#### SYNOPSIS
Exports accounts from the source environment.

#### SYNTAX
```PowerShell
Export-Accounts [[-exportCSV] <Object>] [<CommonParameters>]
```
#### DESCRIPTION
Exports accounts from the source environment and stores them in a variable called 'AccountList' to be used by `Sync-Safe` and `Sync-Accounts`. Generates a feed file called 'ExportOfAccounts.csv'.

### Import-Accounts
#### SYNOPSIS
Import a list of accounts to be used by `Sync-Safe` and `Sync-Accounts`.

#### SYNTAX
```powershell
Import-Accounts [[-importCSV] <String>] [<CommonParameters>]
```

#### DESCRIPTION
Import accounts from a .csv file and stores them in a variable called 'AccountList' to be used by `Sync-Safe` and `Sync-Accounts`.
Default name of feed file called 'ExportOfAccounts.csv'.


### New-DestinationSession
#### SYNOPSIS
Establish a new session to the destination environment.

#### SYNTAX
```powershell
New-DestinationSession [-dstPVWAURL] <String> [[-dstAuthType] <String>] [[-dstOTP] <String>]
 [[-dstPVWACredentials] <PSCredential>] [[-dstLogonToken] <Object>] [-DisableSSLVerify] [<CommonParameters>]
```

#### DESCRIPTION
Establish a new session to the destination environment.
This can be either on-premises or in a Privileged Cloud environment.


### Sync-Safes
#### SYNOPSIS
Synchronizes the Safes between the two environments.

#### SYNTAX
```powershell
Sync-Safes [-CreateSafes] [-UpdateSafeMembers] [[-CPMOld] <String>] [[-CPMNew] <String>] [[-CPMOverride] <String>] [[-CPMList] <String[]>] [[-OwnersToExclude] <String[]>]  [[-newDir] <String>] [[-dstDomainSuffix] <String>] [-srcRemoveDomain] [[-maxJobCount] <String>] [-ProgressDetails] [-SuppressProgress] [<CommonParameters>]
```

#### DESCRIPTION
Uses the variable 'AccountList' to target specific Safes, and connects to the two environments to perform the following process:
- Determines if the Safe already exists in the destination environment
	- If the Safe does not exist and `-CreateSafes` switch is passed: create the Safe.
  - If the Safe exists and `-UpdateSafeMembers` is passed: updates Safe ownerships on the ownership in the source environment.
- Updates Safe ownerships on newly created Safes based on the ownership in the source environment.

Prior to running, ensure the following items are set in both environments:
- The current user (ie: the one running the command) must have direct access to all Safes in scope in both environments.
	- **In the source environment** the minimum permissions are the following:
      - List Accounts, 
      - Retrieve Accounts, 
      - View Safe members, 
      - Access Safe without confirmation (If dual control active)
	- **In the destination environment** the minimum ownerships are the following:
      - Full Permission required
      - This is due to the requirement that you must have the permissions to be able to grant the permissions.
- **Caution**: Group membership in "Vault Admins" or "Auditors" will cause all Accounts to be exported, including system level accounts which should not be migrated.

Prior to running, it is recommended that the following items are done in both environments:
- Creation of dedicated "Export" and "Import" users.

After running the command, the following items are recommended:
- Delete the user account used to import the Safes after you have done the verifications in the destination environment. This user will retain full permissions to every created Safes, this is the most secure method to ensure all permissions are removed.

For further information about the parameters, use `Get-Help Sync-Safes -full`.



### Sync-Accounts
#### SYNOPSIS
Synchronize the accounts between two environments.

#### SYNTAX
```powershell
Sync-Accounts [-SkipCheckSecret] [-getRemoteMachines] [-noCreate] [-allowEmpty] [-VerifyPlatform] [[-maxJobCount] <String>] [-ProgressDetails] [-SuppressProgress] [<CommonParameters>]
```

#### DESCRIPTION
Uses the variable 'AccountList' to target specific accounts, and connects to two environments to perform the following process:
- If `-VerifyPlatform` is passed: get a list of all Platforms on destination environment
    - Verify that the Platform from the the source environment exists in the destination environment, for each future Account creation.
    - Update the 'platformID' casing to match the casing in the destination environment, for each Account.
- Check if the accounts exist in the destination environment, and if the source account has a secret set.
    - If the account does not exist: creates the account unless `-NoCreate` is passed.
    - If the account does not have a secret set: does not create the account unless `-allowEmpty` is passed.
- Unless `-SkipCheckSecret` is passed: verifies that the secret matches between the source and destination, for each existing account found.
    - Whenever possible, ensure that secrets for both the source and destination are stored in variables as *SecureStrings* and only retained for as long as needed and then removed.
- If `-getRemoteMachines` is passed: updates the destination account with the values from the source account.

Prior to running, it is recommended to do the following in both environment:
- CPMs is stopped in both environments. This is to prevent password from being locked due to CPM initiating changes and password unexpectedly changing.
- "Enforce check-in/check-out exclusive access" is inactive.
  - Due to the command reading the secret in both environments if 'Exclusive use' is enabled all accounts will become locked to the user running the command.
- "Enforce one-time password access" is inactive.
  - If enabled all secrets will change based on the Platform 'MinValidityPeriod' and exclusive access settings.
- "Require dual control password access approval" is inactive or the user running the commands has "Access Safe without Confirmation" for all Safes in scope.
  - If "DisableDualControlForPSMConnections" is set to "Yes" on the Platform either "dual controls" must be set to inactive or the Platform updated to have "DisableDualControlForPSMConnections" set to "No".
    - This is due to a limitation in the REST interface.
- Ensure all in-scope accounts are unlocked.
  - This can easily be done by using PrivateArk Client.
    - After logging, enter "CTRL + F", select "Advanced" tab, check only "Locked", and click "Find".
    - All locked accounts will be displayed in the results pane, click in this pane and then select "Edit", "Select All".
    - With everything highlighted, right click and then select "Unlock File"
    - All locked files will now be unlocked.
    - Unlocking this way will **not** trigger the CPM to change the password when restarted.

Prior to running, it is recommended to do the following in both environment:
- Create dedicated "Export" and "Import" users.
- "NFNotifyOnPasswordUsed" is set to "No" to ensure a large amount of emails are not generated
  - If "Yes", ensure that the Event Notification Engine (ENE) is stopped and you delete "\PrivateArk\Safes\ENE\ENELastEventID.dat" prior to restarting.
  - In Privilege Cloud environments, clients do not have access to the ENE.
- "EnforcePasswordPolicyOnManualChange" is set to "No".
  - This ensures synchronization of secrets between environments.
- "AutoChangeOnAdd" is set to "No".
  - The will prevent the secrets from automatically changing when the CPM in the destination is turned on.
- "AutoVerifyOnAdd" is set to "No".
  - This will prevent the CPM from having a large workload on initial startup after work.

After execution, the following is recommended:
- Any "Master Policy" or "Platform" settings adjusted to allow for export and import are reset back to standard values.
- Only the environment that is currently being actively used has a running CPM.
- If CPMs are required to be running in both environments, ensure each Safe has a CPM assigned in only one environment at a time.
- Before using the destination environment: verify no password has changed in the source environment, without being synchronized.
  - You can find the information of the last secret change of the source account by running `Export-Accounts` and reviewing the column titled "PasswordLastChangeUTC".
    - The time zone used to display the date and time of last password change is UTC (+0).
  - If secrets have changed: remove all other entries in the .csv file but leaving in the accounts with secret changes. Use `Import-Accounts` to target these accounts specifically.
- Once you started using the destination environment and verifications are complete: delete the user Account used to import Safes. The import user will retain full permissions to any safe it created, the easiest and most secure method to ensure that access is removed is to delete the user.

To get further information about the parameters, use `Get-Help Sync-Accounts -full`.
