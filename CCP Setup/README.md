# Configure CCP Tool


## Main capabilities
-----------------
- The tool automates the configuration of CCP

## Parameters:
```powershell
Configure CCP.ps1 -PVWAURL <string> [-AuthType] [-OTP] [-DisableSSLVerify] 
```


# CCP via REST.ps1
## Main capabilities
-----------------
- The tool for testing CCP using REST calls

## Parameters:
Update lines 2 thru 8 with correct information

```powershell
CCP via REST.ps1
```

# CCP via REST with client cert.ps1
## Main capabilities
-----------------
- The tool for testing CCP using REST calls using client certificate authenticaiton
- Requires that the client ceritifcate is imported in the localmachine personal store
  - The command "Get-ChildItem -path cert:\LocalMachine\My" can be use to list certificates and the thumbprints

## Parameters:
Update lines 2 thru 10 with correct information
Line 10 needs to have all spaces removed

```powershell
CCP via REST with client cert.ps1
```
