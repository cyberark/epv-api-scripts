# Auto Onboard LCD using EPM Data


## Main capabilities
-----------------
Automatically adds accounts to PAS using EPM as it's source


## Parameters:
```powershell
.\Invoke-OnboardEPMintoPAS.ps1 [-EPMCredentials <PSCredential>] [-EPMSetID <String>] [-EPMSetID <String>] [-LCDSafeName <String>] [-LCDPUsername <String>] [-LCDDomain] [-LCDAdd] [-logonToken $logonToken] [-IdentityUserName "brian.bors@cyberark.cloud.xxxx"] [-IdentityURL aalxxxx.my.idaptive.app] [-PCloudSubDomain "TestingLab"] [-PVWAAddress "https://onprem.lab.local/passwordVault"] [-PVWACredentials $PSCredential] [-PVWAAuthType "CyberArk"]
```

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

### Onboarding paramaters
- EPMCredentials [PSCredential]
	- Credentials that would be used to connect to EPM
    - There are limits on the allow connections on the amount of calls per min. See link for more information.
        - https://docs.cyberark.com/EPM/Latest/en/Content/WebServices/WebServicesIntro.htm#LimitationsfornewAPIs
- EPMSetID [String]
  - The EPM Management Set ID (Not Name) to retrieve systems from
- LCDPlatform [String]
  - Platform to assign new accounts to
- LCDSafeName [String]
  - Safe to create accounts in
- LCDPUsername [String]
  - Username of the account to create
- LCDDomain [String]
  - Domain of the account to create
- LCDFolder
  - Folder to output JSON output to
    - Default Value: ".\"
- LCDAdd [Switch]
    - Switch to add accounts automatically to PAS
    - If not set the accounts will only be outputted to .\ToAdd-$EPMSetID.json.
      - JSon can later be imported using command outputted
