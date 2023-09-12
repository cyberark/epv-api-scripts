
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Pass EPM Credentials")]
    [PSCredential]$EPMCredentials,
    [Parameter(Mandatory = $false, HelpMessage = "Enter EPM Set to use")]
    [String]$EPMSetID,    
    [Parameter(Mandatory = $true, HelpMessage = "Enter Platform to use")]
    [String]$LCDPlatform,
    [Parameter(Mandatory = $true, HelpMessage = "Enter Safe to use")]
    [String]$LCDSafeName,
    [Parameter(Mandatory = $true, HelpMessage = "Enter Username to onboard")]
    [String]$LCDPUsername,
    [Parameter(Mandatory = $true, HelpMessage = "Enter domain to be appended to address")]
    [String]$LCDDomain,
    [Parameter(Mandatory = $false, HelpMessage = "Load Accounts?")]
    [Switch]$LCDAdd,    

    [Parameter(Mandatory = $false, HelpMessage = "Enter Identity Name")]
    [String]$IdentityUserName,
    [Parameter(Mandatory = $false, HelpMessage = "Enter Identity URL")]
    [String]$IdentityURL,
    [Parameter(Mandatory = $false, HelpMessage = "Enter Privilege Cloud Subdomain")]
    [String]$SubDomain,

    [Parameter(Mandatory = $false, HelpMessage = "Pass PVWA Credentials")]
    [PSCredential]$PVWACredentials,
    [Parameter(Mandatory = $false, HelpMessage = "Enter PVWA URL")]
    [String]$PVWAAddress
)

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
# Get Debug / Verbose parameters for Script
$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent

# Script Version
$ScriptVersion = "0.1"

# ------ SET global parameters ------
# Set Log file path
$global:LOG_DATE = $(Get-Date -Format yyyyMMdd) + "-" + $(Get-Date -Format HHmmss)
$global:LOG_FILE_PATH = "$ScriptLocation\SafeManagement_$LOG_DATE.log"


Function Write-LogMessage {
    <#
.SYNOPSIS
	Method to log a message on screen and in a log file

.DESCRIPTION
	Logging The input Message to the Screen and the Log File.
	The Message Type is presented in colours on the screen based on the type

.PARAMETER LogFile
	The Log File to write to. By default using the LOG_FILE_PATH
.PARAMETER MSG
	The message to log
.PARAMETER Header
	Adding a header line before the message
.PARAMETER SubHeader
	Adding a Sub header line before the message
.PARAMETER Footer
	Adding a footer line after the message
.PARAMETER Type
	The type of the message to log (Info, Warning, Error, Debug)
#>
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [Switch]$Header,
        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory = $false)]
        [Switch]$Footer,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Debug", "Verbose")]
        [String]$type = "Info",
        [Parameter(Mandatory = $false)]
        [String]$LogFile = $LOG_FILE_PATH
    )
    try {
        If ($Header) {
            "=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
            Write-Host "======================================="
        } ElseIf ($SubHeader) { 
            "------------------------------------" | Out-File -Append -FilePath $LOG_FILE_PATH 
            Write-Host "------------------------------------"
        }
	
        $msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
        $writeToFile = $true
        # Replace empty message with 'N/A'
        if ([string]::IsNullOrEmpty($Msg)) {
            $Msg = "N/A" 
        }
        # Mask Passwords
        if ($Msg -match '((?:"password"|"secret"|"NewCredentials")\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w!@#$%^&*()-\\\/]+))') {
            $Msg = $Msg.Replace($Matches[2], "****")
        }
        # Check the message type
        switch ($type) {
            "Info" { 
                Write-Host $MSG.ToString()
                $msgToWrite += "[INFO]`t$Msg"
            }
            "Warning" {
                Write-Host $MSG.ToString() -ForegroundColor DarkYellow
                $msgToWrite += "[WARNING]`t$Msg"
            }
            "Error" {
                Write-Host $MSG.ToString() -ForegroundColor Red
                $msgToWrite += "[ERROR]`t$Msg"
            }
            "Debug" { 
                if ($InDebug -or $InVerbose) {
                    Write-Debug $MSG
                    $msgToWrite += "[DEBUG]`t$Msg"
                } else {
                    $writeToFile = $False 
                }
            }
            "Verbose" { 
                if ($InVerbose) {
                    Write-Verbose $MSG
                    $msgToWrite += "[VERBOSE]`t$Msg"
                } else {
                    $writeToFile = $False 
                }
            }
        }
		
        If ($writeToFile) {
            $msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH 
        }
        If ($Footer) { 
            "=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
            Write-Host "======================================="
        }
    } catch {
        Write-Error "Error in writing log: $($_.Exception.Message)" 
    }
}

#Region EPM Connections
$EPMBody = @{ 
    username      = $EPMCredentials.username.Replace('\', '')
    password      = $EPMCredentials.GetNetworkCredential().password
    ApplicationID = "CheckForLCD"
} | ConvertTo-Json

Write-LogMessage -Type Debug -Msg "EPM - EPMBody: $EPMBody"

$logonResult = Invoke-RestMethod 'https://login.epm.cyberark.com/EPM/API/Auth/EPM/Logon' -Method 'POST' -Body $EPMBody
Write-LogMessage -Type Debug -Msg "EPM - LogonResult: $logonResult"
$ManagerURL = $logonResult.ManagerURL

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization","basic $($logonResult.EPMAuthenticationResult)")

if ([string]::IsNullOrEmpty($EPMSetID)){
    $Sets = Invoke-RestMethod "$ManagerURL/EPM/API/Sets" -Method 'GET' -Headers $headers
    Write-LogMessage -Type Debug -Msg "EPM - Sets: $Sets"
    $EPMSetID = ($sets.sets | Select-Object -Property Name,@{Name="Type";Expression={if($_.SetType -eq 4){
                    "LCD"
                } else{
                    "Full"
                }}
        },id | Out-GridView -OutputMode Single -Title "Select Set to search").id
        Write-LogMessage -Type Info -Msg "Selected EPM SetID: `"$EPMSetID`""
    
}

##### Need to update logging from here down

try {
    $setComputersTotal = (Invoke-RestMethod "$ManagerURL/EPM/API/Sets/$EPMSetID/Computers?limit=1&offset=0" -Method 'GET' -Headers $headers).TotalCount
    $offset = 0
    $limit = 5000

    [Array]$epmComputers =@()
    Do {
        try {
            $setOffsetResult = Invoke-RestMethod "$ManagerURL/EPM/API/Sets/$EPMSetID/Computers?limit=$limit&offset=$offset" -Method 'GET' -Headers $headers
            Write-LogMessage -Type Info -Msg "Retrived $($setOffsetResult.Count)"
            $epmComputers += $setOffsetResult.Computers
            $offset += $limit
        } catch {
            "Error while tooping thru computers"
            $_
            break
        }
    } until ($offset -ge $setComputersTotal)
} catch {
    "Error while getting computers"
    $_
    break
}
#endregion
"Retrived $($setOffsetResult.Count) computers"
#region PAS Connection
if (!(Get-Module -ListAvailable -Name PSPAS)) {
    Install-Module PSPAS -Scope CurrentUser
} 

Get-PASComponentSummary -ErrorAction SilentlyContinue -ErrorVariable TestConnect | Out-Null
if ($TestConnect.count -ne 0) {
    Close-PASSession -ErrorAction SilentlyContinue
}
If ($null -eq (Get-PASSession).User){
    If (![string]::IsNullOrEmpty($IdentityUserName)) {
        "Identity username provided"  
        IF (!(Test-Path .\IdentityAuth.psm1)){
            Invoke-WebRequest -Uri https://raw.githubusercontent.com/cyberark/epv-api-scripts/main/Identity%20Authentication/IdentityAuth.psm1 -OutFile IdentityAuth.psm1
        }
        Import-Module .\IdentityAuth.psm1
        $header = Get-IdentityHeader -psPASFormat -IdentityTenantURL $IdentityURL -IdentityUserName $IdentityUserName -PCloudTenantAPIURL "https://$SubDomain.privilegecloud.cyberark.cloud/passwordvault/"
        if ($null -eq $header) {
            exit
        }
        Use-PASSession $header
        "Successfully Connected"
    } elseif (![string]::IsNullOrEmpty($PVWAAddress)){
        if ([string]::IsNullOrEmpty($PVWACredentials)) {
            $PVWACredentials = Get-Credential
        }
        New-PASSession -Credential $PVWACredentials -concurrentSession $true -BaseURI $PVWAAddress
    } else {
        "You must enter either a PVWAAddress or IdentityURL and SubDomain"
        break
    }
}

$accounts = Get-PASAccount -search $LCDPUsername
$pasComputers = @()
ForEach ($account in $accounts){

    try {
        if (![string]::IsNullOrEmpty($account.Address)){
            $pasComputers += $account.Address.split(".")[0].ToLower()
        } else {
            "Invalid Address on $account"
        }
    } catch {
        $account
        $_
    }
   
}
$pasComputers = $pasComputers | Select-Object -Unique
#endregion

#region Compare and add
[Array]$listToAdd = $epmComputers | Where-Object {$_.ComputerName -notin $pasComputers} | Select-Object -Property ComputerName,ComputerType,Platform,Status,LastSeen
"`n$($listToAdd.count) computers exist in EPM but not in PAS"
$toAdd = @()
ForEach ($add in $listToAdd){
    $Object = @{
        "address"    = "$($add.ComputerName).$LCDdomain"
        "platformID" = "$LCDPlatform"
        "userName"   = "$LCDPUsername"
        "SafeName"   = "$LCDSafeName"       
    }
    $toAdd += $Object
}
$toAdd | ConvertTo-Json | Out-File -Force .\ToAdd-$EPMSetID.json

If ($LCDAdd){
    "Starting to onboard $($listToAdd.count) accounts"
    $count = 0
    forEach ($add in $toAdd) {
        $accountinfo = Add-PASAccount `
            -address $($add.address) `
            -platformID $($add.platformID) `
            -userName $($add.Username) `
            -SafeName $($add.SafeNAme) 
    
        $accountinfo | Invoke-PASCPMOperation -ChangeTask -ImmediateChangeByCPM Yes -ErrorAction SilentlyContinue
        $count += 1
    }
    "`nOnboarded $count accounts`n"
} else {
    $Output = @'

To load use the following commands

$toAdd = Get-Content .\ToAdd-$EPMSetID.json | ConvertFrom-Json

forEach ($add in $toAdd) {
    $accountinfo = Add-PASAccount `
        -address $($add.address) `
        -platformID $($add.platformID) `
        -userName $($add.Username) `
        -SafeName $($add.SafeNAme) 

     $accountinfo | Invoke-PASCPMOperation -ChangeTask -ImmediateChangeByCPM Yes -ErrorAction SilentlyContinue
}
'@
    $Output
}
#endregion