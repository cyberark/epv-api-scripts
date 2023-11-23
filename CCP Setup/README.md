# Configure CCP.ps1


## Main capabilities
-----------------
- Automates the configuration of CCP.

## Parameters:
```powershell
Configure CCP.ps1 -PVWAURL <string> [-AuthType] [-OTP] [-DisableSSLVerify] 
```


# CCP via REST.ps1
## Main capabilities
-----------------
- This tool is for testing CCP using REST calls.

## Parameters:
Update lines 2 through 8 with correct information.

```powershell
CCP via REST.ps1
```

# CCP via REST with client cert.ps1
## Main capabilities
-----------------
- This tool is for testing CCP using REST calls using client certificate authentication.
- Requires that the client certificate is imported in the localmachine personal store.
- The command ``Get-ChildItem -path cert:\LocalMachine\My`` can be used to list certificates and thumbprints.

## Parameters:
Update lines 2 through 10 with correct information.
Line 10 needs to have all spaces removed.

```powershell
CCP via REST with client cert.ps1
```
