<#
Author: Jake DeSantis <jake.desantis@cyberark.com>
Date: 10/21/2021

#>

function Add-CyberArkAccount {
    <#
    .SYNOPSIS
    Adds an account to a safe
    
    .DESCRIPTION
    Adds a privileged account to the specified Safe
    
    .EXAMPLE
    Add-CyberArkAccount -safeName "safe name here" -platformID "name of the platform" -address ip.name.or.domain.name.fqdn -accountPassword "afsdujpaoief89w7823" -logonDomain "DomainName" -accountUsername "AccountUserName" -accountName "Specific Account Name" -noAutoMgmt $true
    
    #>
        [CmdletBinding()]
        [OutputType()]
        Param(
            [Parameter(Mandatory=$true,
                HelpMessage="Name of the CyberArk web server not including http[s]:// or passwordvault. e.g. CyberArk.lab.local",
                Position=0)]
            [ValidateScript({
                $webCheck = (Invoke-WebRequest -UseBasicParsing -Uri "https://$_/PasswordVault" -TimeoutSec 3600000).statuscode
                if ($webCheck -eq 200){$true}else{throw "There was an error connecting to $_"}
                })]
            $caEnv,
            [Parameter(Mandatory=$true,
                ValueFromPipelineByPropertyName=$true,
                HelpMessage="Auth token received from the Get-CyberArkSessionToken function",
                Position=1)]
            $authToken,
            [Parameter(Mandatory=$true,
                HelpMessage="Name of the safe where the account will be stored",
                ValueFromPipelineByPropertyName=$true,
                Position=0)]
            [ValidateScript({((Get-CyberArkSafes -caEnv $caEnv -authToken $authToken).safename) -contains "$_"})]
            $safeName,
            [Parameter(Mandatory=$true,
                 HelpMessage="The case-sensitive platform ID which the account will be associated.")]
            [ValidateScript({
                $verifyPlatform = Get-CyberArkPlatformDetails -authToken $authToken -caEnv $caEnv -PlatformName $_
                if ($verifyPlatform){$true}else{throw "The platform, $_, does not exist"}
                })]
            $platformID,
            [Parameter(Mandatory=$true,
                HelpMessage="The address the account will use to logon to the target")]
            $address,
            [Parameter(Mandatory=$false,
                HelpMessage="The address the account will use to logon to the target")]
            $port,
            [Parameter(Mandatory=$false,
                HelpMessage="The name of the CyberArk account group.")]
            [ValidateSet("Password","Key")]
            $secretType="Password",
            [Parameter(Mandatory=$true,
                HelpMessage="The password that should be set for the privileged account.")]
            [Alias("Secret")]
            $accountPassword,
            [Parameter(Mandatory=$false,
                HelpMessage="The logon domain that should be used")]
            $logonDomain,
            [Parameter(Mandatory=$true,
                HelpMessage="The actual username of the account.")]
            $accountUsername,
            [Parameter(Mandatory=$true,
                HelpMessage="The CyberArk reference name / ID of the account.")]
            $accountName,
            [Parameter(Mandatory=$false,
                HelpMessage="Weather or not the account will be managed by the CPM")]
            [ValidateSet("true","false")]
            $AutoMgmt,
            [Parameter(Mandatory=$false,
                HelpMessage="Reason for not auto-managing the account")]
            $noAutoMgmtReason,
            [Parameter(Mandatory=$false,
                HelpMessage="Weather or not access should be restricted to specific machines")]
            [ValidateSet("true","false")]
            $restrictAccess="false",
            [Parameter(Mandatory=$false,
                HelpMessage="list of machines that access should be restricted to")]
            $remoteMachines
        )
    
        BEGIN{
    
            $URI = "https://$caEnv/PasswordVault/api/Accounts"
            $header = @{Authorization = $AuthToken}
            $contentType = "application/json"
        }
        PROCESS{
            
            #Build body as a hash table
            $body = @{
                name="$accountName"
                address="$address"
                userName="$accountUsername"
                platformId="$platformID"
                safeName="$safeName"
                secretType="$secretType"
                secret="$accountPassword"
                platformAccountProperties=@{}
                secretManagement=@{
                    automaticManagementEnabled="$autoMgmt"
                    manualManagementREason="$noAutoMgmtReason"
                }
                remoteMachineAccess=@{
                    remoteMachines="$remoteMachines"
                    restrictAccess="$restrictAccess"
                }
            } 
    
            #Add additional platform-defined properties here like port. Make sure to add them as parameters as well in the params section.
            if($port){$body.platformaccountproperties.add("port","$port")}
    
            $body = $body | ConvertTo-Json
    
            try {
                Write-Verbose "Adding $accountUsername to the $safeName safe and associating it with the $platformID, platform in the $caEnv vault..." #VERBOSE
                Invoke-RestMethod -Uri $URI -ContentType $contentType -Body $Body -Method POST -Headers $header -ErrorVariable rMethodErr
            }catch{
                Write-Error "There was an error adding $accountUsername to the $safeName safe and associating it with the $platformID platform in the $caEnv vault." -Reason $rMethodErr.message #Error
            }
        }
        END{
    
        }
    
     
     
    }
    
    function Get-CyberArkPlatformDetails {
    <#
    .SYNOPSIS
    Gets the details of a cyberark platform
    
    .DESCRIPTION
    Gets the details of a particular cyberark Platform specified by the platofrm name
    
    .EXAMPLE
    Get-CyberArkPlatformDetails -platformname "WinDomain"
    
    #>
    
        [CmdletBinding()]
        [OutputType([String], ParameterSetName="Platform")]
        Param(
            [Parameter(Mandatory=$true,
                HelpMessage="Name of the CyberArk web server not including http[s]:// or passwordvault. e.g. CyberArk.lab.local",
                Position=0)]
            [ValidateScript({
                $webCheck = (Invoke-WebRequest -UseBasicParsing -Uri "https://$_/PasswordVault" -TimeoutSec 3600000).statuscode
                if ($webCheck -eq 200){$true}else{throw "There was an error connecting to $_"}
                })]
            $caEnv,
            [Parameter(Mandatory=$true,
                ValueFromPipelineByPropertyName=$true,
                HelpMessage="Auth token received from the Get-CyberArkSessionToken function",
                Position=1)]
            $authToken,
            [Parameter(Mandatory=$true,
                HelpMessage="The name of the platform")]
            $platformName           
        )
    
        #BEGIN - Execute only once while calling the function when passing in an array
        BEGIN{
            #Decare static variables used by the call to the REST API
            $header = @{Authorization = $authToken}
            $contentType = "application/json"
        }
    
        #PROCESS -Always execute upon every call to the function when passing in an array trhough the pipeline
        PROCESS{
    
            #Define URI
            $URI = "https://$caEnv/PasswordVault/API/Platforms/$platformName"
    
            try {
                Write-Host "Getting the details of the platform, $platformName, from the $caEnv vault..." -ForegroundColor Yellow #DEBUG
                $platform = (Invoke-RestMethod -Uri $URI -ContentType $contentType -Method GET -Headers $header -ErrorVariable rMethodErr).details
                return $platform
            }catch{
                Write-Host "There was an error getting the details of the platform, $platformName, from the $caEnv vault. The error was:" -ForegroundColor Red #ERROR
                Write-Host $rMethodErr.message -ForegroundColor Red #Error
            }
        }
    
        #END - Execute only when all members of the array have been processed
        END{
    
        }
        
    }
    
    function Get-CyberArkSafes {
    <#
    .SYNOPSIS
    Lists all safes
    
    .DESCRIPTION
    Allows a user to list all of the cyberark safes and the details that the user has access to.
    
    .EXAMPLE
    Get-CyberArkSafes -authToken $authToken -caenv $caenv
    
    #>
    
        [CmdletBinding()]
        [OutputType()]
        Param(
            [Parameter(Mandatory=$true,
                HelpMessage="Name of the CyberArk web server not including http[s]:// or passwordvault. e.g. CyberArk.lab.local",
                Position=0)]
            [ValidateScript({
                $webCheck = (Invoke-WebRequest -UseBasicParsing -Uri "https://$_/PasswordVault" -TimeoutSec 3600000).statuscode
                if ($webCheck -eq 200){$true}else{throw "There was an error connecting to $_"}
                })]
            $caEnv,
            [Parameter(Mandatory=$true,
                ValueFromPipelineByPropertyName=$true,
                HelpMessage="Auth token received from the Get-CyberArkSessionToken function",
                Position=1)]
            $authToken
         )
    
        #BEGIN - Execute only once while calling the function when passing in an array
        BEGIN{
            
            #Declare static variables used by the call to the REST API
            $URI = "https://$caEnv/PasswordVault/WebServices/PIMServices.svc/Safes"
            $header = @{Authorization = $authToken}
            $contentType = "application/json"
        }
    
        #PROCESS -Always execute upon every call to the function when passing in an array trhough the pipeline
        PROCESS{
            try {
                #Attempt to list the safes
                Write-Host "Retrieving safes from the $caEnv vault..." -ForegroundColor Yellow #DEBUG
                (Invoke-RestMethod -Uri $URI -ContentType $contentType -Method GET -Headers $header -ErrorVariable rMethodErr).GetSafesResult
            }catch{
                Write-Host "There was an error retrieving the safes frome the $caEnv CyberArk Vault. The error was:" -ForegroundColor Red #ERROR
                Write-Host $rMethodErr.message -ForegroundColor Red #Error
            }
        }
    
        #END - Execute only when all members of the array have been processed
        END{
    
        }
    
    }
    
    function Import-CyberArkGroupObjects{
    <#
    .SYNOPSIS
    Onboards group objects based on CSV created by Convert-VEMObjectsFile
    
    .DESCRIPTION
    Onboards csv of group objects
    
    .EXAMPLE
    Import-CyberArkGroupObjects -groupedAccountsCSV C:\Scratch\vem\csvs\objects51520_GroupObjects-Test.csv
    
    #>
    
        [CmdletBinding()]
        [OutputType()]
        Param(
            [Parameter(Mandatory=$true,
                HelpMessage="Name of the CyberArk web server not including http[s]:// or passwordvault. e.g. CyberArk.lab.local",
                Position=0)]
            [ValidateScript({
                $webCheck = (Invoke-WebRequest -UseBasicParsing -Uri "https://$_/PasswordVault" -TimeoutSec 3600000).statuscode
                if ($webCheck -eq 200){$true}else{throw "There was an error connecting to $_"}
                })]
            $caEnv,
            [Parameter(Mandatory=$false,
                HelpMessage="Username of the user",
                Position=1)]
            [string]$logonUser = "Administrator",
            [Parameter(Mandatory=$false,
                ValueFromPipelineByPropertyName=$false,
                HelpMessage="CyberArk, LDAP, Windows or RADIUS",
                Position=2)]
            [ValidateSet("CyberArk","LDAP","Windows","RADIUS")]
            $authSystem="CyberArk",
            [Parameter(Mandatory=$false,
                HelpMessage="The gruoped objects CSV created by Convert-VemObjects cmdlet",
                Position=2)]
            [ValidateScript({Test-Path -Path $_ -PathType Leaf -IsValid})]
            $groupedObjectsCSV
        )
    
        #BEGIN - Execute only once while calling the function when passing in an array
        BEGIN{
    
            #import the group objects csv
            $groupedAccountsCSV = Import-Csv $groupedObjectsCSV
    
            #identify group objects
            $groups = $groupedAccountsCSV | Where-Object folder -eq "Root\Groups"
    
            #identify group accounts
            $groupAccounts = $groupedAccountsCSV | Where-Object folder -NE "Root\Groups"
    
            #add the GroupID property to the groupedAccuntsCSV
            $groupedAccountsCSV | Add-Member -MemberType NoteProperty -Name GroupID -Value $null
    
            $authtoken = Get-CyberArkSessionToken -caEnv $caEnv -user $logonUser -authSystem $authSystem -concurrentSessions $true -verbose
        }
    
        #PROCESS -Always execute upon every call to the function when passing in an array trhough the pipeline
        PROCESS{
            #for every group in groups...
            foreach ($group in $groups){
                Write-Verbose "Adding group $($group.name) to the vault"
                try {
                    #create the new group
                    $group = New-CyberArkAccountGroup -caEnv $caEnv -authToken $authtoken -groupName $group.Name -groupPlatformID $group.PlatformID -SafeName $group.Safe -ErrorVariable _Err
                    write-log -message "Successfully added $($group.groupname) to the vault" 
    
                    #assign the groupID to the member in the object
                    ($groupedAccountsCSV | Where-Object name -eq $group.GroupName).groupid = $group.GroupID
                }catch{
                    write-log -message "There was a problem adding the group to the vault. 
                                The error was $($_Err.message)"
                }
    
            }
    
            #for every grouped account in grouped accounts...
            foreach ($groupAccount in $groupAccounts){
                Write-Verbose "Adding $($groupAccount.UserName) to the vault..."
                try {
                    #Add the account to cyberark
                    $account = Add-CyberArkAccount -caEnv $caEnv -authToken $authtoken -safeName $groupAccount.Safe -platformID $groupAccount.PlatformID -address $groupAccount.address -port $groupAccount.port -secretType password -accountPassword $groupAccount.password -accountUsername $groupAccount.username -accountName $groupAccount.Name -AutoMgmt false -noAutoMgmtReason "Testing" -ErrorVariable _Err
    
                    #determine what the group object is for that account
                    $group = $groupedAccountsCSV | Where-Object name -eq $groupAccount.groupName
                    write-log -message "Successfully added $($groupAccount.UserName) to the vault..." 
                }catch{
                    write-log -message "There was a problem adding the $($account.username) to the vault. 
                                The error was $($_Err.message)"
                }
    
                Write-Verbose "Adding $($account.username) to the $($group.GroupName) group..."
                try{
                    #add the newly created account to the group using the account ID and group ID
                    Add-CyberArkAccountToGroup -caEnv $caEnv -authToken $authtoken -groupID $group.groupID -accountID $account.ID -ErrorVariable _Err
                    write-log -message "Successfully added $($account.username) to the $($group.GroupName) group" 
                }catch{
                    write-log -message "There was a problem adding the $($account.username) account to the $($group.GroupName) group. 
                                The error was $($_Err.message)"
                }
            }
        }
    
        #END - Execute only when all members of the array have been processed
        END{
    
        }
    }
    
    function New-CyberArkAccountGroup {
    <#
    .SYNOPSIS
    
    .DESCRIPTION
    
    .EXAMPLE
    
    .EXAMPLE 
    
    
    #>
        [CmdletBinding()]
        [OutputType()]
        Param
        (
    
            [Parameter(Mandatory=$true,
                HelpMessage="Name of the CyberArk web server not including http[s]:// or passwordvault. e.g. CyberArk.lab.local",
                Position=0)]
            [ValidateScript({
                $webCheck = (Invoke-WebRequest -UseBasicParsing -Uri "https://$_/PasswordVault" -TimeoutSec 3600000).statuscode
                if ($webCheck -eq 200){$true}else{throw "There was an error connecting to $_"}
                })]
            $caEnv,
            [Parameter(Mandatory=$true,
                ValueFromPipelineByPropertyName=$true,
                HelpMessage="Auth token received from the Get-CyberArkSessionToken function",
                Position=1)]
            $authToken,
            [Parameter(Mandatory=$true,
                HelpMessage="Group Name",
                Position=2)]
            $groupName,
            [Parameter(Mandatory=$true,
                HelpMessage="Group Platform ID",
                Position=3)]
            $groupPlatformID,
            [Parameter(Mandatory=$true,
                HelpMessage="Group Safe Name",
                Position=4)]
            $SafeName
    
        )
    
        #BEGIN - Execute only once while calling the function when passing in an array
        BEGIN{
            
            #Decare variables used by the call to the REST API
            $header = @{Authorization = $authToken}
            $contentType = "application/json"
        }
    
        #PROCESS -Always execute upon every call to the function when passing in an array trhough the pipeline
        PROCESS{
            
            $URI = "https://$caEnv/PasswordVault/api/AccountGroups/"
    
            #Declare variables use by the call to the REST API
            $body = @{
                "GroupName"="$groupName";
                "GroupPlatformID"="$groupPlatformID";
                "Safe"="$safeName";
            } | ConvertTo-Json
    
            
            try {
                #Attempt to find the account(s)
                Write-Host "Adding the $groupName group..." -ForegroundColor Yellow #DEBUG
                Invoke-RestMethod -Uri $URI -ContentType $contentType -Method POST -Headers $header -Body $body -ErrorVariable rMethodErr
            }catch{
                Write-Host "There was a problem adding the $groupName to the $caEnv Vault. The error was:" -ForegroundColor Red #ERROR
                Write-Host $rMethodErr.message -ForegroundColor Red #Error
                }
        }
    
        #END - Execute only when all members of the array have been processed
        END{
    
        }
    }
    
    function Add-CyberArkAccountToGroup {
    <#
    .SYNOPSIS
    
    .DESCRIPTION
    
    .EXAMPLE
    
    .EXAMPLE 
    
    
    #>
        [CmdletBinding()]
        [OutputType()]
        Param
        (
    
            [Parameter(Mandatory=$true,
                HelpMessage="Name of the CyberArk web server not including http[s]:// or passwordvault. e.g. CyberArk.lab.local",
                Position=0)]
            [ValidateScript({
                $webCheck = (Invoke-WebRequest -UseBasicParsing -Uri "https://$_/PasswordVault" -TimeoutSec 3600000).statuscode
                if ($webCheck -eq 200){$true}else{throw "There was an error connecting to $_"}
                })]
            $caEnv,
            [Parameter(Mandatory=$true,
                ValueFromPipelineByPropertyName=$true,
                HelpMessage="Auth token received from the Get-CyberArkSessionToken function",
                Position=1)]
            $authToken,
            [Parameter(Mandatory=$true,
                HelpMessage="Group Name",
                Position=2)]
            $groupID,
            [Parameter(Mandatory=$true,
                HelpMessage="Group Platform ID",
                Position=3)]
            $accountID
    
        )
    
        #BEGIN - Execute only once while calling the function when passing in an array
        BEGIN{
            
            #Decare variables used by the call to the REST API
            $header = @{Authorization = $authToken}
            $contentType = "application/json"
        }
    
        #PROCESS -Always execute upon every call to the function when passing in an array trhough the pipeline
        PROCESS{
            
            #Declare variables use by the call to the REST API
            $body = @{
                "AccountID"="$accountID";
            } | ConvertTo-Json
    
            $URI = "https://$caEnv/PasswordVault/api/AccountGroups/$groupID/Members"
            
            try {
                #Attempt to find the account(s)
                Write-Host "Adding $accountID account to $groupID group..." -ForegroundColor Yellow #DEBUG
                return (Invoke-RestMethod -Uri $URI -ContentType $contentType -Method POST -Headers $header -Body $body -ErrorVariable rMethodErr).value
            }catch{
                Write-Host "There was a problem adding the $groupName to the $caEnv Vault. The error was:" -ForegroundColor Red #ERROR
                Write-Host $rMethodErr.message -ForegroundColor Red #Error
                }
        }
    
        #END - Execute only when all members of the array have been processed
        END{
    
        }
    }
    
    function Get-CyberArkSessionToken {
    <#
    .SYNOPSIS
    Allows a user to get an authtoken via 
    
    .DESCRIPTION
    Allows a user to login to CyberArk via the API. This generates a token that can be used with the other cyberark functions that interact with the API.
    
    .EXAMPLE
    
    Get-CyberArkSessionToken -caenv "cyberark.lab.local"
    
    .EXAMPLE
    Get-CyberArkSessionToken -user APIUser -caenv "cyberark.lab.local"
    
    .EXAMPLE
    Get-CyberArkSessionToken -user aduser -caenv "Cyberark.lab.local" -authsystem "LDAP"
    #>
        [CmdletBinding()]
        [OutputType([string])]
        Param
        (
            [Parameter(Mandatory=$true,
                HelpMessage="Name of the CyberArk web server not including http[s]:// or passwordvault. e.g. CyberArk.lab.local",
                Position=0)]
            #validate the connection to the web server address provided
            [ValidateScript({
                $webCheck = (Invoke-WebRequest -UseBasicParsing -Uri "https://$_/PasswordVault" -TimeoutSec 3600000).statuscode
                if ($webCheck -eq 200){$true}else{throw "There was an error connecting to $_"}
                })]
            [string]$caEnv,
            [Parameter(Mandatory=$false,
                HelpMessage="Username of the user",
                Position=1)]
            [string]$user = "Administrator",
            [Parameter(Mandatory=$false,
                ValueFromPipelineByPropertyName=$false,
                HelpMessage="CyberArk, LDAP, Windows or RADIUS",
                Position=2)]
            [ValidateSet("CyberArk","LDAP","Windows","RADIUS")]
            $authSystem="CyberArk",
            [Parameter(Mandatory=$false)]
            [Security.SecureString]$password,
            [Parameter(Mandatory=$false,
                HelpMessage="Weather or not to use concurrent sessions",
                Position=1)]
            [boolean]$concurrentSessions = $false
            )
        
        #BEGIN - Execute only once when calling the function when passing in an array
        BEGIN{
    
            #Decare variables used by the call to the REST API
            $contentType = "application/json"
            $uri = "https://$caEnv/PasswordVault/API/auth/$authSystem/Logon"
    
            #prompt the user for the password securely
            if (!$password){
            $password = Read-Host -Prompt "Enter the $authSystem password for $user " -AsSecureString
            }
    
            #Define the body parameter as a hash table 
            $body = @{
            "username"="$user";
            "password"="$([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)))"
            "concurrentSessions"="$concurrentSessions"
            } | ConvertTo-Json  
        }
    
        #PROCESS -Always execute upon every call to the function when passing in an array trhough the pipeline
        PROCESS{  
            
            #attempt to login with the username and password provided
            try {
                Write-Host "Attempting login as $user at $caEnv..." -ForegroundColor Yellow #DEBUG
                Invoke-RestMethod -Uri $uri -ContentType $contentType -Body $body -Method POST -ErrorVariable rMethodErr
                Write-Host "Login for $caEnv user, $user, Succeeded" -ForegroundColor Green #DEBUG
            }catch{
                Write-Host "There was a problem logging in as $user to the $caEnv vault using $authSystem authentication. The error was:" -ForegroundColor Red #ERROR
                Write-Host $rMethodErr.message -ForegroundColor Red #Error
            }
        }
    
        END{
    
        }
        
    }
    
    Function Write-Log {
    <#
    .SYNOPSIS
    Writes a session log to the user's temp directory.
    
    .DESCRIPTION
    Writes a log file to the user's temp directory with the name PoShLog-YYYY-MM-DD-HHmmss.log. 
    The log file is session based (as long as the global logfile variable exists).
    
    Using -verbose will output to the console.
    
    .EXAMPLE
    Write-Log -message "This is an error" -logLevel ERR -Verbose
    
    .EXAMPLE
    Write-Log -message "This is a warning" -logLevel WARN
    
    .EXAMPLE
    Write-Log -message "This is informational"
    
    #>
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$false)]
            [string]$message,
            [Parameter(Mandatory=$false)]
            [ValidateSet("ERR","WARN","INFO")]
            [string]$logLevel="INFO"
        )
    
        BEGIN{
            if (!$logfile){
                $global:logfile = "$env:temp\PoShLog-$((get-date).tostring("yyyy-mm-dd-HHmmss")).log"
                Write-Verbose -Message "Writing log to $logfile"
                New-Item -Path $logfile -ItemType File | Out-Null
                }
        }
    
        PROCESS{
            $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
            $Line = "$Stamp [$logLevel] $message"
                Add-Content -Path $logFile -Value $Line -Force
                Write-Verbose $Line
        }
        END{
    
        }
    }