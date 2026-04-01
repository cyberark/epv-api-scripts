@{
    ModuleVersion = '2.0.0'
    GUID = 'a8b7c6d5-e4f3-4a2b-9c8d-7e6f5a4b3c2d'
    Author = 'CyberArk'
    CompanyName = 'CyberArk'
    Copyright = '(c) 2026 CyberArk. All rights reserved.'
    Description = 'Authentication module for CyberArk Identity Security Platform Shared Services (ISPSS)'
    PowerShellVersion = '5.1'

    RootModule = 'IdentityAuth.psm1'

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
            Tags = @('CyberArk', 'Identity', 'Authentication', 'PrivilegeCloud', 'PAM', 'ISPSS')
            LicenseUri = 'https://github.com/cyberark/epv-api-scripts/blob/main/LICENSE'
            ProjectUri = 'https://github.com/cyberark/epv-api-scripts'
            ReleaseNotes = 'v2.0.0: Complete rewrite with OOBAUTHPIN support, OAuth modernization, session management'
        }
    }
}
