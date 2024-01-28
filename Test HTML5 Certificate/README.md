# Test HTML5 Certificates

## Main capabilities
- Checks the selected certificate for compatibility with RDS and the HTML5 Gateway / Remote Access.
- Optionally, sets the certificate for use in RDS, if the `-SetCertificate` flag is used.

## Limitations
- Certificate must be installed in the Local Machine - Personal store. The script doesn't search any other certificate stores at present.

## Parameters
```powershell
Test-HTML5Certificate.ps1 [-SetCertificate]
```
