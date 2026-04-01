@{
    ModuleVersion = '2.0.0'
    GUID = 'b9c8d7e6-f5a4-5b3c-ad9e-8f7a6b5c4d3e'
    Author = 'CyberArk'
    CompanyName = 'CyberArk'
    Copyright = '(c) 2026 CyberArk. All rights reserved.'
    Description = 'Authentication module for CyberArk Identity Security Platform Shared Services (ISPSS) - PowerShell 7+'
    PowerShellVersion = '7.0'

    RootModule = 'IdentityAuth7.psm1'

    FunctionsToExport = @(
        'Get-IdentityHeader',
        'Get-IdentityURL',
        'Test-IdentityToken',
        'Clear-IdentitySession',
        'Get-IdentitySession'
    )

    VariablesToExport = @()
    AliasesToExport = @()
    CmdletsToExport = @()

    PrivateData = @{
        PSData = @{
            Tags = @('CyberArk', 'Identity', 'Authentication', 'PrivilegeCloud', 'PAM', 'ISPSS', 'PowerShell7')
            LicenseUri = 'https://github.com/cyberark/epv-api-scripts/blob/main/LICENSE'
            ProjectUri = 'https://github.com/cyberark/epv-api-scripts'
            ReleaseNotes = 'v2.0.0: Complete rewrite with classes/enums, OOBAUTHPIN support, OAuth modernization'
        }
    }
}
