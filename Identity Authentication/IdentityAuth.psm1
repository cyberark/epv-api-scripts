Function Get-IdentityHeader {
    <# 
    .SYNOPSIS 
        Function to get Identity Header to enable running scripts using the token parameter. This will allow running the rest of the scripts in the directory for Identity Shared Services - Shared Services customers (ISPSS) (Privilege Cloud). 
        Token created using Identity documentation https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/WebServices/ISP-Auth-APIs.htm
    
    .DESCRIPTION
        This function starts by requesting authentication into identity APIs. Once the process starts there can be multiple challenges that need to be responded with multiple options. 
        Each option is then being decided by the user. Once authentication is complete we get a token for the user to use for APIs within the ISPSS platform. 
    .PARAMETER PlatformDomainName
        The Subdomain of the customer platform. For example: servicesum.cyberark.cloud we will need to give servicesum as the option here.
    .PARAMETER IdentityTenantURL
        The URL of the tenant. you can find it if you go to Identity Admin Portal > constimization > Tenant URL. This is without the https:// at the start.
    
    #>
        [CmdletBinding()]
        Param (
            [Parameter(
                Mandatory = $true,
                HelpMessage = "Identity Tenant URL")]
            [string]$IdentityTenantURL,
            [Parameter(
                Mandatory = $true,
                HelpMessage = "User to authenticate into the platform")]
            [string]$IdentityUserName,
            [Parameter(
                Mandatory = $false,
                HelpMessage = "Identity Tenant ID")]
            [string]$IdentityTenantId
        )
        #Platform Identity API
    
        if($IdentityTenantURL -match "https://"){
            $IdaptiveBasePlatformURL = $IdentityTenantURL
        }
        Else{
            $IdaptiveBasePlatformURL = "https://$IdentityTenantURL"
        }
    
        #Creating URLs
    
        $IdaptiveBasePlatformSecURL = "$IdaptiveBasePlatformURL/Security"
        $startPlatformAPIAuth = "$IdaptiveBasePlatformSecURL/StartAuthentication"
        $startPlatformAPIAdvancedAuth = "$IdaptiveBasePlatformSecURL/AdvanceAuthentication"
        $LogoffPlatform = "$IdaptiveBasePlatformSecURL/logout"
    
        #Creating the username/password variables
    
        $startPlatformAPIBody = @{TenantId = $IdentityTenantId; User = $IdentityUserName ; Version = "1.0"} | ConvertTo-Json -Compress
        $IdaptiveResponse = Invoke-RestMethod -Uri $startPlatformAPIAuth -Method Post -ContentType "application/json" -Body $startPlatformAPIBody -TimeoutSec 30
        # We can use the following to give info to the customer $IdaptiveResponse.Result.Challenges.mechanisms
        $j = 1
        $SessionId = $($IdaptiveResponse.Result.SessionId)
        ForEach ($challenge in $IdaptiveResponse.Result.Challenges) {
            #reseting variables
            $Mechanism = $null
            $MechanismId = $null
            $Action = $null
            $startPlatformAPIAdvancedAuthBody = $null
            $ChallengeCount = 0
            $ChallengeCount = $challenge.mechanisms.count
    
            Write-LogMessage -type "Info" -MSG "Challenge $($j):"
            #Multi mechanisms option response
            If ($ChallengeCount -gt 1) {
                Write-LogMessage -type "Info" -MSG "There are $ChallengeCount options to choose from."
                $mechanisms = $challenge.mechanisms
                #Displaying the two options for MFA at this challenge part
                $i = 1
                ForEach ($mechanismsOption in $mechanisms) {
                    $mechanismsName = $mechanismsOption.Name
                    $MechanismsMechChosen = $mechanismsOption.PromptMechChosen
                    Write-LogMessage -type "Info" -MSG "$i - is $mechanismsName - $MechanismsMechChosen"
                    $i=$i+1
                }
                #Requesting to know which option the user wants to use
                $Option = $Null
                While ($Option -gt $ChallengeCount -or $Option -lt 1 -or $Option -eq $Null) {
                    $Option = Read-Host "Please enter the option number you want to use. from 1-$ChallengeCount" 
                    Try {
                        $Option = [Int]$Option
                    }
                    Catch {
                        Write-LogMessage -Type Error -MSG $_.ErrorDetails.Message
                    }
                }
                #Getting the mechanism
                $Mechanism = $challenge.mechanisms[$Option-1] #This is an array so number-1 means the actual position
                #Completing step of authentication
                $AnswerToResponse = Run-AdvancedAuthBody -SessionId $SessionId -Mechanism $Mechanism -IdentityTenantId $IdentityTenantId
            } 
            #One mechanism
            Else {
                $Mechanism = $challenge.mechanisms
                $MechanismName = $Mechanism.Name
                $MechanismPrmpt = $Mechanism.PromptMechChosen
                Write-LogMessage -type "Info" -MSG  "$MechanismName - $MechanismPrmpt"
                $AnswerToResponse = Run-AdvancedAuthBody -SessionId $SessionId -Mechanism $Mechanism -IdentityTenantId $IdentityTenantId
            }
            #Need Better logic here to make sure that we are done with all the challenges correctly and got next challenge.  
            $j=$j+1 #incrementing the challenge number
        }
    
        #Creating Header
        $IdentityHeaders = @{Authorization  = "Bearer $($AnswerToResponse.Result.Token)"}
        $IdentityHeaders.Add("X-IDAP-NATIVE-CLIENT","true")
    
        return $identityHeaders
    }
    
    
    #Runs an advanceAuth API. It will wait in the loop if needed
    Function Run-AdvancedAuthBody {
        [CmdletBinding()]
        Param (
            [Parameter(
                Mandatory = $true,
                HelpMessage = "Session ID of the mechanism")]
            [string]$SessionId,
            [Parameter(
                Mandatory = $true,
                HelpMessage = "Mechanism of Authentication")]
            $Mechanism,
            [Parameter(
                Mandatory = $false,
                HelpMessage = "Tenant ID")]
            [String]$IdentityTenantId
        )
        $MechanismId = $Mechanism.MechanismId
        #need to do this if/elseif as a function so we do not double code here.
        If ($Mechanism.AnswerType -eq "StartTextOob") {
            #We got two options here 1 text and one Push notification. We will need to do the while statement in this option.
            $Action = "StartOOB"
            $startPlatformAPIAdvancedAuthBody = @{TenantID = $IdentityTenantId; SessionId = $SessionId; MechanismId = $MechanismId; Action = $Action; } | ConvertTo-Json -Compress
            Write-LogMessage -type "Info" -MSG "Waiting for Push to be pressed"
        }
        ElseIf ($Mechanism.AnswerType -eq "Text") {
            $Action = "Answer"
            $Answer = Read-Host "Please enter the answer from the challenge type" -AsSecureString
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Answer)
            $startPlatformAPIAdvancedAuthBody = @{TenantID = $IdentityTenantId; SessionId = $SessionId; MechanismId = $MechanismId; Action = $Action; Answer = ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR))} | ConvertTo-Json -Compress
        }
        #Rest API
        Try {
            $AnswerToResponse = Invoke-RestMethod -Uri $startPlatformAPIAdvancedAuth -Method Post -ContentType "application/json" -Body $startPlatformAPIAdvancedAuthBody -TimeoutSec 30
        }
        Catch {
            Write-LogMessage -Type Error -MSG $_.ErrorDetails.Message  
        }
        while ($AnswerToResponse.Result.Summary -eq "OobPending") {
            Start-Sleep -Seconds 2
            $pollBody = @{TenantID = $IdentityTenantId; SessionId = $SessionId; MechanismId = $MechanismId; Action = "Poll"; } | ConvertTo-Json -Compress
            $AnswerToResponse = Invoke-RestMethod -Uri $startPlatformAPIAdvancedAuth -Method Post -ContentType "application/json" -Body $pollBody -TimeoutSec 30
            Write-LogMessage -type "Info" -MSG "$($AnswerToResponse.Result.Summary)"
        }
        $AnswerToResponse
    }
    
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
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            [AllowEmptyString()]
            [String]$MSG,
            [Parameter(Mandatory = $false)]
            [Switch]$Header,
            [Parameter(Mandatory = $false)]
            [Switch]$Early,
            [Parameter(Mandatory = $false)]
            [Switch]$SubHeader,
            [Parameter(Mandatory = $false)]
            [Switch]$Footer,
            [Parameter(Mandatory = $false)]
            [ValidateSet("Info", "Warning", "Error", "Debug", "Verbose", "Success", "LogOnly")]
            [String]$type = "Info",
            [Parameter(Mandatory = $false)]
            [String]$LogFile = $LOG_FILE_PATH
        )
        Try {
            If ($Header) {
                "=======================================" | Out-File -Append -FilePath $LogFile 
                Write-Host "=======================================" -ForegroundColor Magenta
            }
            ElseIf ($SubHeader) { 
                "------------------------------------" | Out-File -Append -FilePath $LogFile 
                Write-Host "------------------------------------" -ForegroundColor Magenta
            }
            
            $msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
            $writeToFile = $false
            # Replace empty message with 'N/A'
            if ([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
            
            # Mask Passwords
            if ($Msg -match '((?:password|credentials|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()-_\=\+\\\/|;:\.,\[\]{}]+))') {
                $Msg = $Msg.Replace($Matches[2], "****")
            }
            # Check the message type
            switch ($type) {
                { ($_ -eq "Info") -or ($_ -eq "LogOnly") } { 
                    If ($_ -eq "Info") {
                        Write-Host $MSG.ToString() -ForegroundColor $(If ($Header -or $SubHeader) { "magenta" } Elseif ($Early) { "DarkGray" } Else { "White" })
                    }
                    $msgToWrite += "[INFO]`t$Msg"
                }
                "Success" { 
                    Write-Host $MSG.ToString() -ForegroundColor Green
                    $msgToWrite += "[SUCCESS]`t$Msg"
                }
                "Warning" {
                    Write-Host $MSG.ToString() -ForegroundColor Yellow
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
                    }
                    else { $writeToFile = $False }
                }
                "Verbose" { 
                    if ($InVerbose) {
                        Write-Verbose -Msg $MSG
                        $msgToWrite += "[VERBOSE]`t$Msg"
                    }
                    else { $writeToFile = $False }
                }
            }
    
            If ($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LogFile }
            If ($Footer) { 
                "=======================================" | Out-File -Append -FilePath $LogFile 
                Write-Host "=======================================" -ForegroundColor Magenta
            }
        }
        catch {
            Throw $(New-Object System.Exception ("Cannot write message"), $_.Exception)
        }
    }