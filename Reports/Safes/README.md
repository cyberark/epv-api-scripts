# Safe Member Permissions Report


## Main capabilities
Create reports for all accessible Safes.


## Parameters:
```powershell
.\Get-SafeMemberReport.ps1 [-ReportPath ".\SafeMemberReport.csv"] [-userTypes @("EPVUser", "BasicUser")] [-ExcludeUsers] [-IncludePredefinedUsers] [-IncludeGroups] [-IncludeApps] [-HidePerms] [-PermList @("useAccounts", "retrieveAccounts","listAccounts")] [-logonToken $logonToken] [-IdentityUserName "brian.bors@cyberark.cloud.xxxx"] [-IdentityURL aalxxxx.my.idaptive.app] [-PCloudSubDomain "TestingLab"] [-PVWAAddress "https://onprem.lab.local/passwordVault"] [-PVWACredentials $PSCredential] [-PVWAAuthType "CyberArk"]
```

### Login Parameters
>Before logging in, the script will check if a psPAS session exists and is still valid. If no valid session is found, an attempt to log in is made *if* one of the following groups is passed.

For pre-established **LogonTokens**:
- LogonToken
    - Used to pass a pre-established logon token

For establishing a session with **PCloud ISPSS**:
- IdentityUserName
    - Username to log into PCloud ISPSS
- IdentityURL
    - URL of the Identity Portal
    - This should not be confused with the PCloud portal which contains "cyberark.cloud/privilegecloud/"
- PCloudSubDomain
    - The assigned PCloud Sub Domain
    - This is the first part of the URL which includes cyberark.cloud/privilegecloud
    - Example: 
        - URL = 'https://FakeTestingLAb.cyberark.cloud/privilegecloud/'
        - Subdomain =  'FakeTestingLAb'

For establishing a session to a **on-prem or PCloud Standalone environment**:
- PVWAAddress
    - URL to the PVWA
    - Used with On-Premise or PCloud Standalone systems
- PVWAAuthType
    - Type of authentication used with PVWA
    - Default Value: CyberArk
    - Acceptable Values: CyberArk or LDAP 


### Report parameters
>All required variables have default values.
- ReportPath [String]
	- Location of the ouput report.
    - Default: '.\SafeMemberReport.csv'
- userTypes [Array]
    - User types to include in the report.
    - Default Value: @("EPVUser", "BasicUser")
- ExcludeUsers [Switch]
    - Exclude the default values from the output.
    - If used with `-UserTypes`, the exclusion will override it.
- IncludePredefinedUsers [Switch]
    - Include PredefinedUsers in the report.
- IncludeGroups [Switch]
    - Include groups in report.
    - If used with `-ExcludeUsers`: only outputs Groups.
- IncludeApps [Switch]
    - Include Applications and Credential Providers in the report.
- HidePerms [Switch]
    - Only output Users, and the Safes they have access to, in the report.
- PermList [Array]
    - Specify a specific set of permissions to include in the report.
