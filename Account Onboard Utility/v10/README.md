The content of the sample_accounts.csv is for example only and does not represent real accounts

Main capabilities
-----------------
- The tool Uses REST API and can support v10.4 of PVWA and up
- The tool supports basic Account and Safe Creation, much like the Password Upload Utility
- The tool supports Template Safe (currently one for all Accounts)
- The tool can take a simple CSV file with only the relevant Account information
- The tool can support comma delimited CSV files (default) or tab delimited CSV files
- In this example script you will find examples of iterating Accounts, Patching account information (for update), Creating accounts, Creating safes, Adding Owners to safe

In order to run the tool you need to run some simple commands in Powershell.
The Tool supports two modes: <Create> and <Update>


Create Command:
---------------
```powershell
Accounts_Onboard_Utility.ps1 -PVWAURL <string> [-TemplateSafe <string>] [-CsvPath <string>] [-CsvDelimiter <Comma / Tab>] [-DisableSSLVerify] [-Create] [-NoSafeCreation] [<CommonParameters>]
```

If you just want to Create Accounts (including creating the Safes if they don’t exist):
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault"  -CsvPath .\accounts.csv -Create
```

If you want to Create Accounts and Safes according to a Safe Template:
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault"  -CsvPath .\accounts.csv -Create -TemplateSafe “MyTemplateSafe”
```

If you want to Create Accounts but not create the safes (if they don’t exist):
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault"  -CsvPath .\accounts.csv -Create -NoSafeCreation
```

Update Command:
---------------
```powershell
Accounts_Onboard_Utility.ps1 -PVWAURL <string> [-TemplateSafe <string>] [-CsvPath <string>] [-CsvDelimiter <Comma / Tab>] [-DisableSSLVerify] [-Update] [-NoSafeCreation] [<CommonParameters>]
```

If you want to Create and Update Accounts (and safes):
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault"  -CsvPath .\accounts.csv -Update
```

If you want to Create and Update Accounts (without Safe creation):
```powershell
& .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://myPVWA.myDomain.com/PasswordVault" -CsvPath .\accounts.csv -Update -NoSafeCreation
```

