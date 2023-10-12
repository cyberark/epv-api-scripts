Function Get-IdentityHeader {
    <#
    .SYNOPSIS
        Function to get Identity Header to enable running scripts using the token parameter. This will allow running the rest of the scripts in the directory for Identity Shared Services - Shared Services customers (ISPSS) (Privilege Cloud).
        Token created using Identity documentation https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/WebServices/ISP-Auth-APIs.htm

    .DESCRIPTION
        This function starts by requesting authentication into identity APIs. Once the process starts there can be multiple challenges that need to be responded with multiple options.
        Each option is then being decided by the user. Once authentication is complete we get a token for the user to use for APIs within the ISPSS platform.

    .PARAMETER IdentityTenantURL
        The URL of the tenant. you can find it if you go to Identity Admin Portal > Settings > Customization > Tenant URL.

    .Parameter IdentityUserName
        The Username that will log into the system. It just needs the username, we will ask for PW, Push etc when doing the authentication.

    .Parameter PCloudSubdomain
        The Subdomain assigned to the privileged cloud environment.

    .Parameter psPASFormat
        Use this switch to output the token in a format that PSPas can consume directly.

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
        [string]$IdentityTenantId,
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Output header in a format for use with psPAS")]
        [switch]$psPASFormat,
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Subdomain of the privileged cloud environment")]
        [string]$PCloudSubdomain

    )
    $ScriptFullPath = Get-Location
    $LOG_FILE_PATH = "$ScriptFullPath\IdentityAuth.log"

    $InDebug = $PSBoundParameters.Debug.IsPresent
    $InVerbose = $PSBoundParameters.Verbose.IsPresent

    #Platform Identity API

    if ($IdentityTenantURL -match "https://") {
        $IdaptiveBasePlatformURL = $IdentityTenantURL
    } Else {
        $IdaptiveBasePlatformURL = "https://$IdentityTenantURL"
    }

    $PCloudTenantAPIURL = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/"

    Write-LogMessage -type "Verbose" -MSG "URL used : $($IdaptiveBasePlatformURL|ConvertTo-Json -Depth 9)"

    #Creating URLs

    $IdaptiveBasePlatformSecURL = "$IdaptiveBasePlatformURL/Security"
    $startPlatformAPIAuth = "$IdaptiveBasePlatformSecURL/StartAuthentication"
    $startPlatformAPIAdvancedAuth = "$IdaptiveBasePlatformSecURL/AdvanceAuthentication"
    $LogoffPlatform = "$IdaptiveBasePlatformSecURL/logout"

    #Creating the username/password variables

    $startPlatformAPIBody = @{TenantId = $IdentityTenantId; User = $IdentityUserName ; Version = "1.0"} | ConvertTo-Json -Compress -Depth 9
    Write-LogMessage -type "Verbose" -MSG "URL body : $($startPlatformAPIBody|ConvertTo-Json -Depth 9)"
    $IdaptiveResponse = Invoke-RestMethod -SessionVariable session -Uri $startPlatformAPIAuth -Method Post -ContentType "application/json" -Body $startPlatformAPIBody -TimeoutSec 30
    Write-LogMessage -type "Verbose" -MSG "IdaptiveResponse : $($IdaptiveResponse|ConvertTo-Json -Depth 9)"

    # We can use the following to give info to the customer $IdaptiveResponse.Result.Challenges.mechanisms

    $SessionId = $($IdaptiveResponse.Result.SessionId)
    Write-LogMessage -type "Verbose" -MSG "SessionId : $($SessionId |ConvertTo-Json -Depth 9)"

    IF (![string]::IsNullOrEmpty($IdaptiveResponse.Result.IdpRedirectUrl)) {
        IF ([string]::IsNullOrEmpty($PCloudSubdomain)) {
            $PCloudSubdomain = Read-Host -Prompt "The Privilege Cloud Subdomain is required when using SAML. Please enter it"
        }
        $OriginalProgressPreference = $Global:ProgressPreference
        $Global:ProgressPreference = 'SilentlyContinue'
        IF (Test-NetConnection -InformationLevel Quiet -Port 443 "$PCloudSubdomain.privilegecloud.cyberark.cloud") {
            $PCloudTenantAPIURL = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/"
            $Global:ProgressPreference = $OriginalProgressPreference
        } else {
            $Global:ProgressPreference = $OriginalProgressPreference
            Write-LogMessage -type Error -MSG "Error during subdomain validation: Unable to contact https://$PCloudSubdomain.privilegecloud.cyberark.cloud"
            exit
        }
        $AnswerToResponse = Invoke-SAMLLogon $IdaptiveResponse
    } else {
        $AnswerToResponse = Invoke-Challenge $IdaptiveResponse
    }

    If ($AnswerToResponse.success) {
        #Creating Header
        If (!$psPASFormat) {
            $IdentityHeaders = @{Authorization = "Bearer $($AnswerToResponse.Result.Token)"}
            $IdentityHeaders.Add("X-IDAP-NATIVE-CLIENT", "true")
        } else {
            $ExternalVersion = Get-PCloudExternalVersion -PCloudTenantAPIURL $PCloudTenantAPIURL -Token $AnswerToResponse.Result.Token
            $header = New-Object System.Collections.Generic.Dictionary"[String,string]"
            $header.add("Authorization", "Bearer $($AnswerToResponse.Result.Token)")
            $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            $session.Headers = $header
            $IdentityHeaders = [PSCustomObject]@{
                User            = $IdentityUserName
                BaseURI         = $PCloudTenantAPIURL
                ExternalVersion = $ExternalVersion
                WebSession      = $session
            }
            $IdentityHeaders.PSObject.TypeNames.Insert(0, 'psPAS.CyberArk.Vault.Session')
        }
        Write-LogMessage -type "Verbose" -MSG "IdentityHeaders - $($IdentityHeaders |ConvertTo-Json)"
        Write-LogMessage -type "Info" -MSG "Identity Token Set Successfully"
        return $identityHeaders
    } else {
        Write-LogMessage -type "Verbose" -MSG "identityHeaders: $($AnswerToResponse|ConvertTo-Json)"
        Write-LogMessage -type Error -MSG "Error during logon : $($AnswerToResponse.Message)"
    }
}

Function Invoke-Challenge {
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $true)]
        [array]$IdaptiveResponse
    )

    $j = 1
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
                $i = $i + 1
            }
            #Requesting to know which option the user wants to use
            $Option = $Null
            While ($Option -gt $ChallengeCount -or $Option -lt 1 -or $Option -eq $Null) {
                $Option = Read-Host "Please enter the option number you want to use. from 1-$ChallengeCount"
                Try {
                    $Option = [Int]$Option
                } Catch {
                    Write-LogMessage -Type Error -MSG $_.ErrorDetails.Message
                }
            }
            #Getting the mechanism
            $Mechanism = $challenge.mechanisms[$Option - 1] #This is an array so number-1 means the actual position
            #Completing step of authentication
            $AnswerToResponse = Invoke-AdvancedAuthBody -SessionId $SessionId -Mechanism $Mechanism -IdentityTenantId $IdentityTenantId
            Write-LogMessage -type "Verbose" -MSG "AnswerToResponce - $($AnswerToResponse |ConvertTo-Json)"
        }
        #One mechanism
        Else {
            $Mechanism = $challenge.mechanisms
            $MechanismName = $Mechanism.Name
            $MechanismPrmpt = $Mechanism.PromptMechChosen
            Write-LogMessage -type "Info" -MSG "$MechanismName - $MechanismPrmpt"
            $AnswerToResponse = Invoke-AdvancedAuthBody -SessionId $SessionId -Mechanism $Mechanism -IdentityTenantId $IdentityTenantId
            Write-LogMessage -type "Verbose" -MSG "AnswerToResponce - $($AnswerToResponse |ConvertTo-Json)"
        }
        #Need Better logic here to make sure that we are done with all the challenges correctly and got next challenge.
        $j = + 1 #incrementing the challenge number
    }

    Return $AnswerToResponse



}

#Runs an advanceAuth API. It will wait in the loop if needed
Function Invoke-AdvancedAuthBody {
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
    $MaskList = @("UP")
    $MechanismId = $Mechanism.MechanismId
    #need to do this if/elseif as a function so we do not double code here.
    If ($Mechanism.AnswerType -eq "StartTextOob") {
        #We got two options here 1 text and one Push notification. We will need to do the while statement in this option.
        $Action = "StartOOB"
        $startPlatformAPIAdvancedAuthBody = @{TenantID = $IdentityTenantId; SessionId = $SessionId; MechanismId = $MechanismId; Action = $Action; } | ConvertTo-Json -Compress
        Write-LogMessage -type "Verbose" -MSG "startPlatformAPIAdvancedAuthBody: $($startPlatformAPIAdvancedAuthBody|ConvertTo-Json -Depth 9)"
        Write-LogMessage -type "Info" -MSG "Waiting for Push to be pressed"
    } ElseIf ($Mechanism.AnswerType -eq "Text") {
        $Action = "Answer"
        $Answer = Read-Host "Please enter the answer from the challenge type" -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Answer)
        $startPlatformAPIAdvancedAuthBody = @{TenantID = $IdentityTenantId; SessionId = $SessionId; MechanismId = $MechanismId; Action = $Action; Answer = ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR))} | ConvertTo-Json -Compress
        If ($Mechanism.Name -in $MaskList) {
            Write-LogMessage -type "Verbose" -MSG "startPlatformAPIAdvancedAuthBody: $($startPlatformAPIAdvancedAuthBody|ConvertTo-Json -Depth 9))" -maskAnswer
        } Else {
            Write-LogMessage -type "Verbose" -MSG "startPlatformAPIAdvancedAuthBody: $($startPlatformAPIAdvancedAuthBody|ConvertTo-Json -Depth 9))"
        }
    }
    #Rest API
    Try {
        $AnswerToResponse = Invoke-RestMethod -Uri $startPlatformAPIAdvancedAuth -Method Post -ContentType "application/json" -Body $startPlatformAPIAdvancedAuthBody -TimeoutSec 30
        Write-LogMessage -type "Verbose" -MSG "AnswerToResponse: $($AnswerToResponse|ConvertTo-Json)"
    } Catch {
        Write-LogMessage -Type Error -MSG $_.ErrorDetails.Message
    }
    while ($AnswerToResponse.Result.Summary -eq "OobPending") {
        Start-Sleep -Seconds 2
        $pollBody = @{TenantID = $IdentityTenantId; SessionId = $SessionId; MechanismId = $MechanismId; Action = "Poll"; } | ConvertTo-Json -Compress
        Write-LogMessage -type "Verbose" -MSG "pollBody: $($pollBody|ConvertTo-Json)"
        $AnswerToResponse = Invoke-RestMethod -Uri $startPlatformAPIAdvancedAuth -Method Post -ContentType "application/json" -Body $pollBody -TimeoutSec 30
        Write-LogMessage -type "Verbose" -MSG "AnswerToResponse: $($AnswerToResponse|ConvertTo-Json)"
        Write-LogMessage -type "Info" -MSG "$($AnswerToResponse.Result.Summary)"
    }
    $AnswerToResponse
}

function Get-PCloudExternalVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PCloudTenantApiUrl,
        [Parameter(Mandatory = $true)]
        $Token
    )

    $ExternalVersion = "12.6.0"
    try {
        $Headers = @{
            Authorization = "Bearer $Token"
        }
        $Response = Invoke-RestMethod -Method GET -Uri "$PCloudTenantApiUrl/WebServices/PIMServices.svc/Server" -Headers $Headers -ContentType 'application/json'
        $ExternalVersion = $Response.ExternalVersion
    } catch {
        Write-LogMessage -Type Error -MSG $_.ErrorDetails.Message
    }

    $ExternalVersion
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
        [String]$LogFile = $LOG_FILE_PATH,
        [Parameter(Mandatory = $false)]
        [Switch]$maskAnswer
    )
    Try {
        If ($Header) {
            "=======================================" | Out-File -Append -FilePath $LogFile
            Write-Host "=======================================" -ForegroundColor Magenta
        } ElseIf ($SubHeader) {
            "------------------------------------" | Out-File -Append -FilePath $LogFile
            Write-Host "------------------------------------" -ForegroundColor Magenta
        }

        $msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
        if ($InDebug -or $InVerbose) {
            $writeToFile = $true
        } Else {
            $writeToFile = $false
        }
        # Replace empty message with 'N/A'
        if ([string]::IsNullOrEmpty($Msg)) {
            $Msg = "N/A"
        }
        If ($maskAnswer) {
            $Msg -match '(?:\\"Answer\\":\\")(?<Mask>.*?)(?:\\")' | Out-Null
            $Msg = $Msg.Replace($Matches.Mask, "<Value Masked>")
        }
        # Check the message type
        switch ($type) {
            { ($_ -eq "Info") -or ($_ -eq "LogOnly") } {
                If ($_ -eq "Info") {
                    Write-Host $MSG.ToString() -ForegroundColor $(If ($Header -or $SubHeader) {
                            "magenta"
                        } Elseif ($Early) {
                            "DarkGray"
                        } Else {
                            "White"
                        })
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
                    $writeToFile = $true
                    Write-Debug $MSG
                    $msgToWrite += "[DEBUG]`t$Msg"
                } else {
                    $writeToFile = $False
                }
            }
            "Verbose" {
                if ($InVerbose) {
                    $writeToFile = $true
                    Write-Verbose -Msg $MSG
                    $msgToWrite += "[VERBOSE]`t$Msg"
                } else {
                    $writeToFile = $False
                }
            }
        }

        If ($writeToFile) {
            $msgToWrite | Out-File -Append -FilePath $LogFile
        }
        If ($Footer) {
            "=======================================" | Out-File -Append -FilePath $LogFile
            Write-Host "=======================================" -ForegroundColor Magenta
        }
    } catch {
        Throw $(New-Object System.Exception ("Cannot write message"), $_.Exception)
    }
}

function Invoke-SAMLLogon {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Array] $IdaptiveResponse
    )

    Begin {

        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Web

        #Special thanks to Shay Tevet for his assistance on this section
        $source = @"
using System;
using System.Runtime.InteropServices;
using System.Text;
namespace Cookies
{
    public static class getter
    {
       [DllImport("wininet.dll", CharSet=CharSet.None, ExactSpelling=false, SetLastError=true)]
        public static extern bool InternetGetCookieEx(string url, string cookieName, StringBuilder cookieData, ref int size, int dwFlags, IntPtr lpReserved);

	public static string GetUriCookieContainer(String uri)
        {
            string str;
            try
            {
                int num = 131072;
                StringBuilder stringBuilder = new StringBuilder(num);
                if (!InternetGetCookieEx(uri, null, stringBuilder, ref num, 8192, IntPtr.Zero))
                {
                        str = null;
                        return str;
                }
                str = (!stringBuilder.ToString().Contains("idToken-") ? "Error" : stringBuilder.ToString().Split(new string[] { "idToken-" }, StringSplitOptions.None)[1].Split(new char[] { ';' })[0].Split(new char[] { '=' })[1]);
            }
            catch
            {
                str = "Error";
            }
            return str;
        }
    }
}
"@

        $compilerParameters = New-Object System.CodeDom.Compiler.CompilerParameters
        $compilerParameters.CompilerOptions = "/unsafe"

        Add-Type -TypeDefinition $source -Language CSharp -CompilerParameters $compilerParameters

        $PCloudURL = "https://$PCloudSubdomain.cyberark.cloud"
        $PCloudPortalURL = "$PCloudURL/privilegecloud/"
        $logonURL = "$IdaptiveBasePlatformURL/login?redirectUrl=https%3A%2F%2F$PCloudSubdomain.cyberark.cloud%2Fprivilegecloud&username=$IdentityUserName&iwa=false&iwaSsl=false"

    }

    Process {
        $DocComp = {

            if ($web.Url.AbsoluteUri -like "*/privilegecloud" -and $web.document.Cookie -like "*loggedIn-*") {
                $Global:Auth = [cookies.getter]::GetUriCookieContainer("$PCloudURL").ToString()
                $form.Close()
            }
        }


        # create window for embedded browser
        $form = New-Object Windows.Forms.Form
        $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
        $form.Width = 640
        $form.Height = 700
        $form.showIcon = $false
        $form.TopMost = $false
        $form.Text = "SAML Based Authentication"

        $web = New-Object Windows.Forms.WebBrowser
        $web.Size = $form.ClientSize
        $web.Anchor = "Left,Top,Right,Bottom"
        $web.ScriptErrorsSuppressed = $false
        $web.AllowWebBrowserDrop = $false
        $web.IsWebBrowserContextMenuEnabled = $true
        $web.Add_DocumentCompleted($DocComp)
        $form.Controls.Add($web)

        $web.Navigate(("$logonURL"))

        # show browser window, waits for window to close
        if ([system.windows.forms.application]::run($form) -ne "OK") {

            if ($null -ne $auth) {
                [PSCustomObject]$Return = @{
                    Success = $true
                    Result  = @{
                        Token = $auth
                    }
                }
                return $Return
                $form.Close()
            } Else {
                throw "Unable to get auth token"
            }
        }

        End {
            $form.Dispose()
        }
    }
}