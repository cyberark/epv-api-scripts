<# 
###########################################################################

NAME: 
    Migration.PS1 

AUTHOR:  
    Brian Bors  <brian.bors@cyberark.com>
    Assaf Miron <assaf.miron@cyberark.com>

COMMENT: 
    Script used migrate data between two environments

Version: 
    0.1

Change Log:
    2020-09-13 
        Initial Version    

########################################################################### 
#>


[CmdletBinding()]
param(

    [Parameter(Mandatory=$false,HelpMessage="Export Items")]
    [switch]$export,

    [Parameter(Mandatory=$false,HelpMessage="Process File")]
    [switch]$processFile,


    [Parameter(Mandatory=$false,HelpMessage="Enter the Authentication type (Default:CyberArk)")]
    [ValidateSet("cyberark","ldap","radius")]
    [String]$AuthType="cyberark",
	
    [Parameter(Mandatory=$false,HelpMessage="Enter the RADIUS OTP")]
    [ValidateScript({$AuthType -eq "radius"})]
    [String]$OTP,

    [Parameter(Mandatory=$true,HelpMessage="Please enter your source PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
    #[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
    [Alias("srcurl")]
    [String]$SRCPVWAURL,

    [Parameter(Mandatory=$true,HelpMessage="Please enter your destination PVWA address (For example: https://pvwa.mydomain.com/PasswordVault)")]
    #[ValidateScript({Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $_ -Method 'Head' -ErrorAction 'stop' -TimeoutSec 30})]
    [Alias("dsturl")]
    [String]$DSTPVWAURL,
	
    [Parameter(Mandatory=$true,HelpMessage="Source Vault Stored Credentials")]
    [PSCredential]$SRCPVWACredentials,

    [Parameter(Mandatory=$true,HelpMessage="Destination Vault Stored Credentials")]
    [PSCredential]$DSTPVWACredentials,

    [Parameter(Mandatory=$false,
        HelpMessage="Path and file name of the objects.csv file created by the export",
        ValueFromPipelineByPropertyName=$true)]
    [ValidateScript({Test-Path -Path $_ -PathType Leaf -IsValid})]
    [ValidatePattern('\.csv$')]
    $exportCSV="$($env:TEMP)\ExportOfAccounts.csv",

    [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
    [ValidatePattern( '\.csv$' )]
    $importCSV="$($env:TEMP)\ExportOfAccounts.csv",

    # Use this switch to Disable SSL verification (NOT RECOMMENDED)
    [Parameter(Mandatory=$false)]
    [Switch]$DisableSSLVerify,

    # Use this switch to Disable SSL verification (NOT RECOMMENDED)
    [Parameter(Mandatory=$false)]
    [Switch]$SkipCheckSecret,

    # Use this switch to Disable SSL verification (NOT RECOMMENDED)
    [Parameter(Mandatory=$false)]
    [Switch]$createSafes,

    # Use this switch to Disable SSL verification (NOT RECOMMENDED)
    [Parameter(Mandatory=$false)]
    [Switch]$UpdateSafeMembers
)
#Rest Error Codes to ignore
$global:SkipErrorCode = @("SFWS0007","ITATS127E")

#region Writer Functions
$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent
$oldverbose = $VerbosePreference
if($InVerbose){
    $VerbosePreference = "continue"
}
# Get Script Location 
$ScriptFullPath = $MyInvocation.MyCommand.Path
$ScriptLocation = Split-Path -Parent $ScriptFullPath
$ScriptParameters = @()
$PSBoundParameters.GetEnumerator() | ForEach-Object { $ScriptParameters += ("-{0} '{1}'" -f $_.Key, $_.Value) }
$Script:g_ScriptCommand = "{0} {1}" -f $ScriptFullPath, $($ScriptParameters -join ' ')

# Script Version
$ScriptVersion = "0.10"

# Set Log file path
New-Variable -Name LOG_FILE_PATH -Value "$ScriptLocation\$(($MyInvocation.MyCommand.Name).Replace("ps1","log"))" -Scope Global -Force

New-Variable -Name AuthType -Value $AuthType -Scope Global -Force

$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent

Import-Module -Name ".\CyberArk-Migration.psm1" -Force

Set-SSLVerify($DisableSSLVerify)

# Check that the PVWA URL is OK
Test-PVWA -PVWAURL $SRCPVWAURL
Test-PVWA -PVWAURL $DSTPVWAURL

Write-LogMessage -Type Info -MSG "Getting Logon Tokens"

$srcToken = Get-Logon -url $SRCPVWAURL -Credentials $SRCPVWACredentials 
$dstToken = Get-Logon -url $DSTPVWAURL -Credentials $DSTPVWACredentials 


$srcAccounts = Get-Accounts -url $SRCPVWAURL -logonHeader $srcToken
#$dstAccounts = Get-Accounts -url $DSTPVWAURL -logonHeader $dstToken
if ($export) {

    $objectSafesToRemove="System","VaultInternal","Notification Engine","SharedAuth_Internal","PVWAUserPrefs",
    "PVWAConfig","PVWAReports","PVWATaskDefinitions","PVWAPrivateUserPrefs","PVWAPublicData","PVWATicketingSystem","PasswordManager",
    "PasswordManagerTemp","PasswordManager_Pending","PasswordManager_workspace","PasswordManager_ADInternal",
    "PasswordManager_Info","PasswordManagerShared","AccountsFeed","PSM","xRay","PIMSuRecordings","xRay_Config",
    "AccountsFeedADAccounts","AccountsFeedDiscoveryLogs","PSMSessions","PSMLiveSessions","PSMUniversalConnectors",
    "PSMNotifications","PSMUnmanagedSessionAccounts","PSMRecordings","PSMPADBridgeConf","PSMPADBUserProfile","PSMPADBridgeCustom",
    "AppProviderConf"

    $srcAccounts | `
        Where-Object {$_.safename -notIn $objectSafesToRemove} | `
        Select-Object -Property "name","address","userName","platformId","safeName","id" | `
        Export-Csv -Path $exportCSV -NoTypeInformation
}

if ($processFile){

    $counter = 0

    $objects = Import-Csv $importCSV
    foreach ($object in $objects){
        $counter++
        $found = $false
        Write-Progress -Activity "Processing objects" -CurrentOperation "$counter of $($objects.count)" -PercentComplete (($counter / $objects.count)*100)
        $srcAccount = Get-AccountDetail -url $SRCPVWAURL -logonHeader $srcToken -AccountID $object.id
        $dstAccountArray = Get-Accounts -url $DSTPVWAURL -logonHeader $dstToken -safename $($srcAccount.safeName) -keywords "$($srcAccount.userName) $($srcAccount.address)" -startswith $true
        if(![string]::IsNullOrEmpty($dstAccountArray)){
            foreach($account in $dstAccountArray){
        
                IF($($account.userName) -eq $($srcAccount.userName) -and $($account.address) -eq $($srcAccount.address) -and $($account.safeName) -eq $($srcAccount.safeName)  ){
                    $found = $true
                    $dstAccount = $account
                }
            }
        }

        $dstsafe = Get-Safe -url $DSTPVWAURL -logonHeader $dstToken -safe $($srcAccount.safename)

        if ([string]::IsNullOrEmpty($dstsafe)) {
            if($createSafes){
                $srcSafe = Get-Safe -url $SRCPVWAURL -logonHeader $srcToken -safe $($srcAccount.safename)
                $dstSafe = New-Safe -url $DSTPVWAURL -logonHeader $dstToken -safe $srcSafe

            } else {
                Write-LogMessage -Type Warning -Msg "Target safe `"$($srcAccount.safename)`" does not exist in destination and creating of safes disabled, skipping `"$($srcAccount.name)`""
                continue 
            }
            If($UpdateSafeMembers){
                Get-SafeMembers -url $DSTPVWAURL -logonHeader $dstToken -safe $($srcAccount.safename)
            }
        }

        if ($found) {
            if (!$SkipCheckSecret){
                [SecureString]$srcSecret = Get-Secret -url $SRCPVWAURL -logonHeader $srcToken -id $srcAccount.id 
                [SecureString]$dstSecret = Get-Secret -url $DSTPVWAURL -logonHeader $dstToken -id $dstAccount.id 
            
                if ($null -eq $dstSecret -and $null -ne $srcSecret){
                    Write-LogMessage -Type Debug -Msg "No secret found on destination account $($dstAccount.Name)"
                    Set-Secret -url $DSTPVWAURL -logonHeader $dstToken -id $dstAccount.id -secret $srcSecret
                }
                elseif ($null -eq $srcSecret){
                    Write-LogMessage -Type warning -Msg "No secret found on source account $($srcSecret.Name)"
                }
                elseif(!(Compare-SecureString -pwd1 $srcSecret -pwd2 $dstSecret)) {
                    Write-LogMessage -Type Debug -Msg "No Match: $($srcAccount.Name) and $($dstAccount.Name) do not match."
                    Set-Secret -url $DSTPVWAURL -logonHeader $dstToken -id $dstAccount.id -secret $srcSecret
                } else {
                    Write-LogMessage -Type Debug -Msg "Match: $($srcAccount.Name) and $($dstAccount.Name) do match."
                    #Set-Secret -url $DSTPVWAURL -logonHeader $dstToken -id $dstAccount.id-secret $srcSecret
                }
            }
        } else {

            $newDstAccount = New-Account -url $DSTPVWAURL -logonHeader $dstToken -account $srcAccount -secret $srcSecret 
        }

    }
}


#region [Logoff]
# Logoff the session
# ------------------
Write-Host "Logoff Session..."

Invoke-Logoff -url $SRCPVWAURL -logonHeader $srcToken
Invoke-Logoff -url $DSTPVWAURL -logonHeader $dstToken

Remove-Variable -Name LOG_FILE_PATH -Scope Global -Force
Remove-Variable -Name AuthType -Scope Global -Force

#endregion

$VerbosePreference = $oldverbose