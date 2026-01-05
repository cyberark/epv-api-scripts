# Legacy CyberArk Application Management Scripts

This directory contains legacy versions of CyberArk application management scripts maintained for backward compatibility.

## Export-Import-Applications.ps1 (Legacy)

Original script by Assaf Miron for exporting and importing AAM applications using REST API.

### Version Information
- **Script Version:** 1.0
- **Supported Versions:** CyberArk PVWA v9.10 and above
- **Status:** Legacy - Maintained for compatibility

### Why Legacy?

This script has been superseded by newer, more maintainable scripts:
- [Export-CyberArkApplications.ps1](../Export-CyberArkApplications.ps1) - Modern export functionality
- [Import-CyberArkApplications.ps1](../Import-CyberArkApplications.ps1) - Modern import functionality

The newer scripts provide:
- Better error handling and logging
- Consistent parameter naming with other scripts
- Session token reuse support
- Individual export/import for better control
- PSScriptAnalyzer compliance
- PowerShell 5.1+ compatibility

### When to Use This Script

Use this legacy script only if:
- You have existing workflows dependent on its specific behavior
- You need compatibility with older PVWA versions (v9.10-v10.3)
- You require the combined export/import in a single script file

For new implementations, use the modern Export/Import scripts.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| PVWAURL | String | Yes | PVWA base URL (e.g., https://pvwa.company.com/PasswordVault) |
| AuthType | String | No | Authentication type: cyberark, ldap, radius (default: cyberark) |
| Export | Switch | Yes* | Export mode switch |
| Import | Switch | Yes* | Import mode switch |
| CSVPath | String | Yes | Path to CSV file |
| AppID | String | No | (Export only) Filter by specific application |
| PVWACredentials | PSCredential | No | Credentials for authentication |
| concurrentSession | Switch | No | Allow concurrent sessions |
| logonToken | String/Object | No | Pre-existing session token |
| DisableSSLVerify | Switch | No | Disable SSL verification (not recommended) |

*Either -Export or -Import is required

### Export Examples

```powershell
# Export all applications (simple form)
.\Export-Import-Applications.ps1 -Export -PVWAURL "https://pvwa.company.com/PasswordVault" -CSVPath ".\applications.csv"

# Export all applications (using splatting for readability)
$params = @{
    Export = $true
    PVWAURL = "https://pvwa.company.com/PasswordVault"
    CSVPath = ".\applications.csv"
}
.\Export-Import-Applications.ps1 @params

# Export specific application
$params = @{
    Export = $true
    PVWAURL = "https://pvwa.company.com/PasswordVault"
    AppID = "MyApp"
    CSVPath = ".\myapp.csv"
}
.\Export-Import-Applications.ps1 @params

# Export using LDAP authentication
$params = @{
    Export = $true
    PVWAURL = "https://pvwa.company.com/PasswordVault"
    AuthType = "ldap"
    CSVPath = ".\applications.csv"
}
.\Export-Import-Applications.ps1 @params

# Export with pre-existing credentials
$cred = Get-Credential
$params = @{
    Export = $true
    PVWAURL = "https://pvwa.company.com/PasswordVault"
    PVWACredentials = $cred
    CSVPath = ".\applications.csv"
}
.\Export-Import-Applications.ps1 @params
```

### Import Examples

```powershell
# Import applications from CSV
$params = @{
    Import = $true
    PVWAURL = "https://pvwa.company.com/PasswordVault"
    CSVPath = ".\applications.csv"
}
.\Export-Import-Applications.ps1 @params

# Import using LDAP authentication
$params = @{
    Import = $true
    PVWAURL = "https://pvwa.company.com/PasswordVault"
    AuthType = "ldap"
    CSVPath = ".\applications.csv"
}
.\Export-Import-Applications.ps1 @params

# Import with session token
$params = @{
    Import = $true
    PVWAURL = "https://pvwa.company.com/PasswordVault"
    CSVPath = ".\applications.csv"
    logonToken = $token
}
.\Export-Import-Applications.ps1 @params
```

### CSV Format

The script uses a specific CSV format with the following columns:
- AppID - Application identifier
- Description - Application description
- Location - Vault location
- AccessPermittedFrom - Access start hour (0-24)
- AccessPermittedTo - Access end hour (0-24)
- ExpirationDate - Application expiration date
- Disabled - Boolean: Is application disabled
- BusinessOwnerFName - Business owner first name
- BusinessOwnerLName - Business owner last name
- BusinessOwnerEmail - Business owner email
- BusinessOwnerPhone - Business owner phone
- Authentications - Semicolon-separated authentication methods in format: {property=value,property=value};{property=value,property=value}

### Authentication Methods Format

Authentication methods are stored as objects in the format:
```
{AuthType=path,AuthValue=C:\app.exe,IsFolder=false};{AuthType=osUser,AuthValue=DOMAIN\User}
```

### Logging

The script creates a log file: Applications.log in the script directory.

### Error Handling

The script includes comprehensive error handling with:
- Try/catch blocks for all API operations
- Detailed error messages in logs
- Continuation on individual application failures
- Automatic logoff on script completion

### Known Limitations

1. **Authentication Format:** Uses object format {key=value} instead of modern semicolon-delimited format
2. **Combined Operation:** Export and Import in single script (less flexible)
3. **Logging:** Uses custom logging instead of standard PowerShell streams
4. **Error Messages:** Uses Write-LogMessage instead of Write-Output/Write-Error
5. **No Pipeline Support:** Does not support PowerShell pipeline patterns

### Migration Path

To migrate from this legacy script to modern scripts:

**Export Migration:**
```powershell
# Old way
$params = @{
    Export = $true
    PVWAURL = "https://pvwa.company.com/PasswordVault"
    CSVPath = "app.csv"
}
.\Export-Import-Applications.ps1 @params

# New way
$params = @{
    PVWAUrl = "https://pvwa.company.com"
    CSVPath = "app.csv"
}
..\Export-CyberArkApplications.ps1 @params
```

**Import Migration:**
```powershell
# Old way
$params = @{
    Import = $true
    PVWAURL = "https://pvwa.company.com/PasswordVault"
    CSVPath = "app.csv"
}
.\Export-Import-Applications.ps1 @params

# New way (requires CSV conversion)
$params = @{
    PVWAUrl = "https://pvwa.company.com"
    CSVPath = "app.csv"
}
..\Import-CyberArkApplications.ps1 @params
```

**Note:** CSV formats are different. The new scripts use semicolon-delimited format for authentication methods instead of object notation.

### CSV Conversion

To convert legacy CSV to modern format, authentication methods need reformatting from:
```
{AuthType=path,AuthValue=C:\app.exe,IsFolder=false}
```

To:
```
AuthType=path;AuthValue=C:\app.exe;IsFolder=false
```

### Support

This is a legacy script maintained for compatibility only. For new features or enhancements, use the modern Export/Import scripts.

For issues specific to this legacy version:
- Check the Applications.log file in the script directory
- Verify PVWA version compatibility (v9.10+)
- Ensure proper permissions for application management

### References

- [Modern Export Script](../Export-CyberArkApplications.ps1)
- [Modern Import Script](../Import-CyberArkApplications.ps1)
- [Main AAM Applications README](../README.md)
- [CyberArk REST API Documentation](https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/api-ref-intro.htm)

---

**Recommendation:** For all new implementations, use the modern Export-CyberArkApplications.ps1 and Import-CyberArkApplications.ps1 scripts located in the parent directory.
