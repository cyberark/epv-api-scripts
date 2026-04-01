# Developer Guide: IdentityAuth Module v2

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Development Setup](#development-setup)
- [Module Functions](#module-functions)
- [Adding New Authentication Methods](#adding-new-authentication-methods)
- [Testing Guidelines](#testing-guidelines)
- [Build Process](#build-process)
- [Coding Standards](#coding-standards)
- [Troubleshooting](#troubleshooting)

## Architecture Overview

### Module Distribution

**PowerShell 5.1+ (IdentityAuth.psm1):**
- Single module file with all functions combined
- Uses hashtables for session management
- Compatible with Windows PowerShell 5.1+

**PowerShell 7+ (IdentityAuth7.psm1):**
- Single module file with classes and enums
- Enhanced type safety with class-based sessions
- Cross-platform support (Windows/Linux/macOS)

**Both versions include:**
- Module manifest (.psd1)
- Identical functionality and API
- Same return values and parameters

### Design Principles

1. **Dual Version Support:** Maintain compatibility with PS5.1 while leveraging PS7 features
2. **Separation of Concerns:** Private helpers vs public API
3. **Parameter Sets:** Different auth methods via parameter sets
4. **Token Caching:** Automatic OAuth token management
5. **Structured Logging:** Consistent logging infrastructure
6. **Error Handling:** Detailed errors with troubleshooting hints

## Development Setup

### Prerequisites

```powershell
# Required
PowerShell 5.1 or 7+

# Optional but recommended
Install-Module -Name Pester -MinimumVersion 5.0.0 -Scope CurrentUser
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser
```

### Clone and Setup

```powershell
# Clone the repository
git clone https://github.com/cyberark/epv-api-scripts.git
cd epv-api-scripts/"Identity Authentication"/v2-Modernized

# For end users: Download compiled modules from releases
# For contributors: See full source structure in repository
```

### Load for Development

```powershell
# Import the module
Import-Module .\IdentityAuth.psd1 -Force      # PS5.1
# OR
Import-Module .\IdentityAuth7.psd1 -Force     # PS7

# Reload after making changes to source
Remove-Module IdentityAuth* -Force -ErrorAction SilentlyContinue
Import-Module .\IdentityAuth7.psd1 -Force
```

## Module Functions

### Public Functions (Exported)

**Main Authentication:**
- `Get-IdentityHeader` - Main authentication entry point
  - Parameter Sets: OAuth, UPCreds, IdentityUserName
  - Supports: OAuth, UP, MFA (OTP/Push/SMS/Email), OOBAUTHPIN
  - Returns: Hashtable with Authorization headers

**Helper Functions:**
- `Get-IdentityURL` - Auto-discover Identity URL from PCloud URL
- `Get-IdentitySession` - Get current cached session details
- `Clear-IdentitySession` - Clear cached session (with optional logout)
- `Test-IdentityToken` - Validate JWT token and check expiry

### Internal Functions (Not Exported)

The module contains private helper functions for:
- REST API calls with error handling
- Authentication challenge processing
- OOBAUTHPIN flow handling
- Session management and token formatting

### PowerShell 7 Enhancements

**IdentityAuth7.psm1 includes:**
- Class-based session management (IdentitySession)
- Type-safe enums (AuthenticationMechanism, ChallengeType, etc.)
- Enhanced error handling with custom exceptions
- Modern PowerShell syntax (ternary operators, null coalescing)

## Adding New Authentication Methods

**Note:** To contribute new authentication methods, you'll need to work with the source code in the GitHub repository. The distributed .psm1 files are compiled from individual source files.

### Step 1: Create Private Helper Function

In the source repository, create a new private helper function:

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Brief description

.DESCRIPTION
    Detailed description
#>

function Invoke-NewAuthMethod {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SessionId,

        [Parameter(Mandatory)]
        [string]$MechanismId,

        [Parameter(Mandatory)]
        [string]$IdentityTenantURL
    )

    Write-IdentityLog -Message "Starting new auth method" -Level Verbose -Component 'NewAuth'

    try {
        # Implementation
        $response = Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType 'application/json'

        # Validate response
        $null = Test-AuthenticationResponse -Response $response -AuthMethod 'NewAuth'

        if ($response.Result.Auth) {
            Write-IdentityLog -Message "New auth successful" -Level Verbose -Component 'NewAuth'
            return $response.Result.Auth
        }
    } catch {
        $safeMessage = Get-SafeErrorMessage -ErrorRecord $_
        Write-IdentityLog -Message "New auth failed: $safeMessage" -Level Error -Component 'NewAuth'
        throw
    }
}
```

### Step 2: Update Get-IdentityHeader

Add parameter set:

```powershell
[Parameter(Mandatory, ParameterSetName = 'NewAuth')]
[string]$NewAuthParameter,
```

Add process block logic:

```powershell
if ($PSCmdlet.ParameterSetName -eq 'NewAuth') {
    Write-Verbose "Authenticating with NewAuth"

    $authSession = Start-OOBAUTHPINAuthentication -Username $Username -IdentityTenantURL $IdentityURL
    $mechanism = Get-AuthenticationMechanism -Challenges $authSession.Challenges -AnswerType 'NewType'
    $authToken = Invoke-NewAuthMethod -SessionId $authSession.SessionId -MechanismId $mechanism.MechanismId -IdentityTenantURL $IdentityURL

    $headers = Format-IdentityHeaders -AccessToken $authToken
    return $headers
}
```

### Step 3: Update Both Versions

```powershell
# In the source repository:
# 1. Update PS5.1 version (traditional PowerShell)
# 2. Update PS7 version (with classes/enums as needed)
# 3. Rebuild modules to create new .psm1 files
```

### Step 4: Add Tests

Create test in `Tests/Pester/Get-IdentityHeader.Tests.ps1`:

```powershell
Context 'NewAuth Authentication' {
    BeforeAll {
        Mock Invoke-RestMethod { @{ Result = @{ Auth = 'test_token' } } } -ModuleName IdentityAuth
    }

    It 'Should authenticate with NewAuth' {
        $result = Get-IdentityHeader -NewAuthParameter "value" -PCloudURL $url
        $result | Should -Not -BeNullOrEmpty
    }
}
```

### Step 5: Build and Test

```powershell
.\Build\Build-PS51Module.ps1
Invoke-Pester -Path .\Tests\Pester\
```

## Testing Guidelines

### Unit Tests

Focus on mocking external API calls:

```powershell
Describe 'Function' {
    BeforeAll {
        Mock Invoke-RestMethod { @{ success = $true } } -ModuleName IdentityAuth
    }

    It 'Should work' {
        $result = Test-Function
        $result | Should -Not -BeNullOrEmpty
    }
}
```

### Integration Tests

Use environment variables for credentials:

```powershell
BeforeAll {
    $env:TEST_OAUTH_CLIENTID = "client_id"
    $env:TEST_OAUTH_SECRET = "secret"
    $env:TEST_PCLOUD_URL = "https://subdomain.privilegecloud.cyberark.cloud/PasswordVault"
}
```

### Running Tests

```powershell
# All tests
Invoke-Pester

# Unit tests only
Invoke-Pester -Tag 'Unit'

# Integration tests only
Invoke-Pester -Tag 'Integration'

# Specific file
Invoke-Pester -Path .\Tests\Pester\Get-IdentityHeader.Tests.ps1
```

## Build Process

**For Contributors:**

The module is built from source files in the GitHub repository. Each version (PS5.1 and PS7) has:
- Private helper functions
- Public exported functions
- PS7 also includes classes and enums

Build scripts combine all source files into single .psm1 files for distribution.

**For End Users:**

No build required - download the pre-built .psm1 and .psd1 files and import directly.

## Coding Standards

### PSScriptAnalyzer Compliance

```powershell
# Check compliance
Invoke-ScriptAnalyzer -Path .\PS5.1 -Settings .\PSScriptAnalyzerSettings.psd1 -Recurse

# Zero violations required!
```

### Naming Conventions

- Functions: `Verb-Noun` (approved verbs only)
- Parameters: `PascalCase`
- Variables: `$camelCase` (private), `$PascalCase` (public)
- No aliases in code

### Comment-Based Help

Every public function must have:

```powershell
<#
.SYNOPSIS
    Brief description

.DESCRIPTION
    Detailed description

.PARAMETER ParameterName
    Description

.EXAMPLE
    Example usage

.NOTES
    Version, author, etc.
#>
```

### Error Handling

```powershell
try {
    # Operation
} catch {
    $safeMessage = Get-SafeErrorMessage -ErrorRecord $_
    Write-IdentityLog -Message $safeMessage -Level Error -Component 'ComponentName'
    throw
}
```

### Logging

```powershell
Write-IdentityLog -Message "Operation started" -Level Verbose -Component 'ComponentName'
Write-IdentityLog -Message "Operation failed" -Level Error -Component 'ComponentName' -AdditionalData @{Detail="value"}
```

## Troubleshooting

### Module Not Loading

```powershell
# Check syntax
Test-ModuleManifest .\PS5.1\IdentityAuth.psd1

# Check for errors
Import-Module .\PS5.1\IdentityAuth.psd1 -Force -Verbose
```

### Function Not Found

```powershell
# Verify function is exported
(Get-Module IdentityAuth).ExportedFunctions.Keys

# Check manifest
$manifest = Import-PowerShellDataFile .\PS5.1\IdentityAuth.psd1
$manifest.FunctionsToExport
```

### PSScriptAnalyzer Failures

```powershell
# Get detailed output
Invoke-ScriptAnalyzer -Path .\PS5.1\Private\Function.ps1 -Settings .\PSScriptAnalyzerSettings.psd1

# Fix common issues:
# - Use Write-Verbose instead of Write-Host
# - Place $null on left: $null -ne $var
# - No positional parameters
# - Full cmdlet names (no aliases)
```

### Test Failures

```powershell
# Run with verbose output
Invoke-Pester -Output Detailed

# Debug specific test
$config = New-PesterConfiguration
$config.Run.Path = '.\Tests\Pester\Get-IdentityHeader.Tests.ps1'
$config.Output.Verbosity = 'Detailed'
$config.Debug.WriteDebugMessages = $true
Invoke-Pester -Configuration $config
```

## Contributing

1. Create feature branch from `main`
2. Make changes following coding standards
3. Add tests for new functionality
4. Run PSScriptAnalyzer (zero violations)
5. Run all tests
6. Build both PS5.1 and PS7 versions
7. Update documentation
8. Submit pull request

---

**Questions?** See [README-MODULE.md](README-MODULE.md) or open an issue.
