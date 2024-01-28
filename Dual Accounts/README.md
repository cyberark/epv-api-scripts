# Dual Accounts

> **General**
> - Uses REST API and can support v10.6 of PVWA and up.
> - Allow easy management for Dual Account.

## Convert Platform DualAccount
Convert an existing Platform to support Dual Account use cases.
This will add all the needed properties to the relevant Platform and allow account creation for Dual Account use cases.

> This script can be supported from PVWA version 10.4 and above

### Usage
```powershell
Convert-Platform-DualAccount.ps1 -PVWAURL <string> -PlatformID <string> [-AuthType <string>] [-DisableSSLVerify] [<CommonParameters>]
```

## Create Dual Account
Create accounts for Dual Account and adds them to a Rotational Group.
This allows an application to work with two user accounts while one is active and the other passive.
More information [here](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/CP%20and%20ASCP/cv_Managing-Dual-Accounts.htm?tocpath=Integrations%7CCyberArk%20Vault%20Synchronizer%7CAccounts%20and%20Safes%7CManage%20Dual%20Accounts%7C_____0#ManageDualAccounts##)

**Note:** Before running this script, make sure you have a Rotational Group Platform imported to your PVWA.
You can download a Rotational Group sample platform from the [CyberArk Marketplace](https://cyberark-customers.force.com/mplace/s/#a352J000000pm6xQAA-a392J000001h4XZQAY) 

> This script can be supported from PVWA version 10.6 and above

This script supports two modes: [*Interactive*](#interactive) and [*NonInteractive*](#noninteractive).

### Usage
```powershell
Create-DualAccount.ps1 -PVWAURL <string> -Interactive [-AuthType <string>] [-DisableSSLVerify] [<CommonParameters>]
Create-DualAccount.ps1 -PVWAURL <string> -NonInteractive -CSVPath <string> -AccountPlatformID <string> -GroupPlatformID <string> -AccountSafeName <string> [-AuthType <string>] [-DisableSSLVerify] [<CommonParameters>]
```

#### Interactive
```powershell
Create-DualAccount.ps1 -PVWAURL <PVWA URL> -PlatformID <Platform ID>
```

#### NonInteractive
```powershell
Create-DualAccount.ps1 -NonInteractive -PVWAURL <PVWA URL> -CSVPath <CSV containing account details> -AccountPlatformID <Dual Account Platform ID> -GroupPlatformID <Rotational Group Platform ID> -AccountSafeName <Safe Name>
```

### Known issues
Creation of Account Groups with a Rotational Group Platform Type is not yet supported.
Change the Rotational Group Platform type to Group (instead of RotationalGroup) before running this script.
After execution, change the platform type back to RotationGroup so Dual Account use case will work as expected.
