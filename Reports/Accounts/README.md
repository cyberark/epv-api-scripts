# Account Based Reports
Reports that are focused on Accounts

# Parameters Common to all reports
## Logon Parameters
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


# Account Report
## Main capabilities
-----------------
Report of all accounts the the platform settings with each accounts

The following properties are Default outputs and are not able to be removed from the report
- Default Properties
    - "UserName", "Address", "Safename", "PlatformID", "SecretType"


## Parameters:
```powershell
.\Get-AccountReport.ps1 [-ReportPath ".\AccountReport.csv"] [-allProps] [-ExcludeExtendedProps] [-MachineRestrictedProps] [-PolicyProps] [-ChangeProps] [-VerifyProps] [-ReconcileProps] [-ObjectNameProps] [-ImportedProps] [-PropList @("Property1","Property2")] [-logonToken $logonToken] [-IdentityUserName "brian.bors@cyberark.cloud.xxxx"] [-IdentityURL aalxxxx.my.idaptive.app] [-PCloudSubDomain "TestingLab"] [-PVWAAddress "https://onprem.lab.local/passwordVault"] [-PVWACredentials $PSCredential] [-PVWAAuthType "CyberArk"]
```
### Report paramaters
All required variables have default values
- ReportPath [String]
	- Location to where the report will be outputted to.
    - Default Value: .\AccountReport.csv
- allProps [Switch]
    - Whether to output all possible properties
    - Overrides all other switches
- ExcludeExtendedProps [Switch]
    - Exclude Extended properties from report. 
    - Properties Removed: "SecretStatus", "AccountManaged", "manualManagementReason", "ManagingCPM", "PlatformName"
- MachineRestrictedProps [Switch]
    - Switch to display properties to show if account has restrictions on usage
    - Properties: "RestrictedToSpecificMachines", "RemoteMachines"
- PolicyProps [Switch]
    - Switch to display properties to show policy properties
    - Properties: "DualControl", "ExclusiveUse", "OneTime", "RequireReason"
- ChangeProps [Switch]
    - Switch to display properties to show information around password changes
    - Properties: "ChangeManual", "ChangeOnAdd", "ChangeAuto", "ChangeLast", "ChangeNext", "ChangeDays", "ChangeInReset"
- VerifyProps [Switch]
    - Switch to display properties to show information around password verification
    - Properties: "VerifyManual", "VerifyOnAdd", "VerifyAuto", "VerifyLast", "VerifyNext", "VerifyDays"
- ReconcileProps [Switch]
    - Switch to display properties to show information around password reconcile
    - Properties: "ReconcileManual", "ReconcileUnSync"
- ImportedProps [Switch]
    - Switch to display all properties found under "platformAccountProperties"
    - Properties: Generated Listed
- ObjectNameProps [Switch]
    - Switch to display object name
    - Properties: "ObjectName"
- PropList [Array]
    - Allows for customized list of properties to be retrieved and displayed in report


