# Auto Onboard LCD using EPM Data


## Main capabilities
-----------------
Automatically adds accounts to PAS using  


## Parameters:
```powershell
.\Get-SafeMemberReport.ps1 [-ReportPath ".\SafeMemberReport.csv"] [-userTypes @("EPVUser", "BasicUser")] [-ExcludeUsers] [-IncludePredefinedUsers] [-IncludeGroups] [-IncludeApps] [-HidePerms] [-PermList @("useAccounts", "retrieveAccounts","listAccounts")] [-logonToken $logonToken] [-IdentityUserName "brian.bors@cyberark.cloud.xxxx"] [-IdentityURL aalxxxx.my.idaptive.app] [-PCloudSubDomain "TestingLab"] [-PVWAAddress "https://onprem.lab.local/passwordVault"] [-PVWACredentials $PSCredential] [-PVWAAuthType "CyberArk"]
```
### Report paramaters
All required variables have default values
- ReportPath [String]
	- Location to where the report will be outputted to.
    - Default Value: .\SafeMemberReport.csv
- userTypes [Array]
	- Vault user types to include in report passed as a array
    - Default Value: @("EPVUser", "BasicUser")
- ExcludeUsers [Switch]
    - Used to exclude the default values from the output
    - If used with -UserTypes the exclusion will override UserTypes
- IncludePredefinedUsers [Switch]
    - Used to include PredefinedUsers
- IncludeGroups [Switch]
    - Used to include groups in report output
    - Can be used with -ExcludeUsers to only output Groups
- IncludeApps [Switch]
    - Used to include Applications and Credential Providers
- HidePerms [Switch]
    - Used to only output users and the safes they have access to in the report
- PermList [Array]
    - Used to specify a specific set of permissions to include in the output
### Logon Parameters
Prior to attempting to logon a check is preformed to determine if a PSPas session already exists and is still valid. If no valid session is found a attempt will be made to if one of the following groupings is also passed

Used for pre-established LogonTokens
- LogonToken
    - Used to pass a pre-established logon token

Used to establish a session with PCloud ISPSS
- IdentityUserName
    - Username to use when logging into PCloud ISPSS
- IdentityURL
    - URL for the Identity Portal
    - This should not be confused with the PCloud portal which contains "cyberark.cloud/privilegecloud/"
- PCloudSubDomain
    - The assigned PCloud Sub Domain
    - This is the first part of the URL which includes cyberark.cloud/privilegecloud
    - Example: 
        - URL = https://FakeTestingLAb.cyberark.cloud/privilegecloud/
        - Subdomain =  FakeTestingLAb

Used to establish a session to a on-prem or PCloud Standalone environment
- PVWAAddress
    - URL to the PVWA
    - Used with On-Premise or PCloud Standalone systems
- PVWAAuthType
    - Type of authentication used with PVWA
    - Default Value: CyberArk
    - Acceptable Values: CyberArk or LDAP 