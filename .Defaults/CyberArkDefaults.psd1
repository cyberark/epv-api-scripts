@{
    RootModule = 'CyberArkDefaults.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author = 'CyberArk Community'
    CompanyName = 'CyberArk'
    Copyright = '(c) 2026 CyberArk. All rights reserved.'
    Description = 'Module for managing CyberArk default parameter values across PowerShell scripts. Enables session token reuse and simplified script execution.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Set-CyberArkDefaults', 'Show-CyberArkDefaults', 'Clear-CyberArkDefaults', 'Invoke-CyberArkLogoff', 'Install-CyberArkDefaults', 'Uninstall-CyberArkDefaults')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('CyberArk', 'PAM', 'PrivilegeCloud', 'Security', 'REST-API')
            LicenseUri = ''
            ProjectUri = 'https://github.com/cyberark/epv-api-scripts'
            ReleaseNotes = 'Initial release of CyberArkDefaults module'
        }
    }
}
