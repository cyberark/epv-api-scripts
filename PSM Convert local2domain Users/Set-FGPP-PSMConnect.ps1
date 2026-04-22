[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Enter samAccountName Name")]
    [String]$user,
    [Parameter(Mandatory = $False, HelpMessage = "Enter Fine Grade Password Policy Name")]
    [String]$PolicyName = "PSMServiceAccounts",
    [Parameter(Mandatory = $False, HelpMessage = "Enter Fine Grade Password Policy -Precedence")]
    [int32]$Precedence = 100
)
$ErrorActionPreference = "silentlycontinue"
if ([string]::IsNullOrEmpty($(Get-ADFineGrainedPasswordPolicy $PolicyName))) {
    New-ADFineGrainedPasswordPolicy -Name $PolicyName -Precedence $Precedence -Description "Fine Grade Password Policy for CyberArk PSM accounts" -LockoutThreshold 0 -MaxPasswordAge 0 -MinPasswordAge 0 -MinPasswordLength 48 -PasswordHistoryCount 0 -ReversibleEncryptionEnabled $False
}
elseif ($Precedence -eq -1) {
    Get-ADFineGrainedPasswordPolicy $PolicyName | Set-ADFineGrainedPasswordPolicy -Precedence 100
}
elseif ($Precedence -ne 100) {
    Get-ADFineGrainedPasswordPolicy $PolicyName | Where-Object -Property Precedence -NE $Precedence | Set-ADFineGrainedPasswordPolicy -Precedence $Precedence
}
Add-ADFineGrainedPasswordPolicySubject $PolicyName -Subjects $user
Get-ADFineGrainedPasswordPolicy $PolicyName
