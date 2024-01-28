# Account Based Reports

## Main capabilities

Create reports for all accessible accounts including properties like Platform IDs, username etc.

The following properties are **default** outputs and can't be removed from the report:
- "UserName", 
- "Address", 
- "Safename", 
- "PlatformID", 
- "SecretType".

## Parameters:
```powershell
.\Get-AccountReport.ps1 [-ReportPath ".\AccountReport.csv"] [-allProps] [-ExcludeExtendedProps] [-MachineRestrictedProps] [-PolicyProps] [-ChangeProps] [-VerifyProps] [-ReconcileProps] [-ObjectNameProps] [-ImportedProps] [-PropList @("Property1","Property2")] [-logonToken $logonToken] [-IdentityUserName "brian.bors@cyberark.cloud.xxxx"] [-IdentityURL aalxxxx.my.idaptive.app] [-PCloudSubDomain "TestingLab"] [-PVWAAddress "https://onprem.lab.local/passwordVault"] [-PVWACredentials $PSCredential] [-PVWAAuthType "CyberArk"]
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
    - Default: '.\AccountReport.csv'
- allProps [Switch]
    - Outputs all possible properties.
    - Overrides all other switches.
- ExcludeExtendedProps [Switch]
    - Exclude Extended properties from report. 
    - Properties Removed: "SecretStatus", "AccountManaged", "manualManagementReason", "ManagingCPM", "PlatformName".
- MachineRestrictedProps [Switch]
    - Display restriction-on-usage properties.
    - Properties: "RestrictedToSpecificMachines", "RemoteMachines".
- PolicyProps [Switch]
    - Display policy properties.
    - Properties: "DualControl", "ExclusiveUse", "OneTime", "RequireReason".
- ChangeProps [Switch]
    - Display password changes information.
    - Properties: "ChangeManual", "ChangeOnAdd", "ChangeAuto", "ChangeLast", "ChangeNext", "ChangeDays", "ChangeInReset".
- VerifyProps [Switch]
    - Display password verification properties.
    - Properties: "VerifyManual", "VerifyOnAdd", "VerifyAuto", "VerifyLast", "VerifyNext", "VerifyDays".
- ReconcileProps [Switch]
    - Display password reconcile properties.
    - Properties: "ReconcileManual", "ReconcileUnSync".
- ImportedProps [Switch]
    - Display all properties found under "platformAccountProperties".
- ObjectNameProps [Switch]
    - Display the object name property.
    - Property: "ObjectName"
- PropList [Array]
    - Allows for a customized list of properties to be retrieved and displayed in report.


