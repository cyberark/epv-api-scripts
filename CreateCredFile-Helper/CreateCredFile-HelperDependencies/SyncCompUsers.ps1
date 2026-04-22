param
(

    [Parameter(ParameterSetName='Common')]
	[Parameter(Mandatory=$false,HelpMessage="Parameters files path.")]
	[String]$InputFile = "SyncCompUsersInput.json",
    
    [Parameter(ParameterSetName='Common')]
	[Parameter(Mandatory=$false,HelpMessage="Vault user password.")]
	[securestring]$VaultSecurePassword,

    [Parameter(ParameterSetName='Common')]
	[Parameter(Mandatory=$false,HelpMessage="Run silently.")]
	[switch]$Silent = $false
)

# @FUNCTION@ ======================================================================================================================
# Name...........: RunProcess
# Description....: Run deployment process 
# Parameters.....: 
# Return Values..: if operation succeeded 
# =================================================================================================================================
function RunProcess{
	Param(
		[Parameter(Mandatory=$true)] 
		[string]$ProcessFullPath,
		[Parameter(Mandatory=$false)] 
		[string[]]$Args,
        [Parameter(Mandatory=$false)] 
		[string]$PasswordEnvVarKey,
        [Parameter(Mandatory=$false)] 
		[Security.SecureString]$SecurePassword
	)
    Begin{
		$processName = Split-Path -Leaf $ProcessFullPath
        $processPath = Split-Path -Parent $ProcessFullPath
	}
	Process{
        $processArgs = ""
        foreach($item in $Args)
        {
            $processArgs += "`"$item`" "
        }
		Write-host "Running process [$processName] from path [$processPath] with arguments [$processArgs]."
        if ($SecurePassword -and $PasswordEnvVarKey)
        { 
           $password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword))
            [System.Environment]::SetEnvironmentVariable($PasswordEnvVarKey,$password)    
        }
        $process = (Start-Process $ProcessName "$processArgs" -WorkingDirectory $processPath -Wait -WindowStyle Hidden -PassThru)
		$processExitCode = $process.ExitCode.ToString()
		[bool]$isSuccess = $false
        if ($process.ExitCode -eq 0)
        {
            Write-host "Process $ProcessName finished successfully"
            $isSuccess = $true
        }
        else
        {
            Write-host "Process $ProcessName failed with exit code $processExitCode" "Error"
            $isSuccess = $false
        }
		return $isSuccess
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-SecurePassword
# Description....: this method gets password as securePassword or plain text
#						 and returns the password as securePassword
# Parameters.....: $spassword - password as securePassword
# password AsPlainText
# Return Values..: execution summary
# =================================================================================================================================
function Get-SecurePassword
{
	[CmdletBinding()]
	param(
   [Security.SecureString]$spassword
	)
	Process {
		
		if(!$spassword)
		{
			if ([string]::IsNullOrEmpty($password)) 
			{
				#read secure password from intercative user
				Write-host "Vault user password is missing, reading password from interactive user" "Info"
				$spassword = Read-Host "Enter Vault User Password" -AsSecureString;
			}
		}
		
		return $spassword;
	 }
	 End {
	 }
}

try
{
   
    if(-not $silent)
    {
        $answer = Read-Host -prompt "Component user\s password and cred file will be reset. Please confirm by entering yes"
        if ($answer -ne "yes")
        {
            write-host "Process terminated"
            exit
        }
    }

    $pass = Get-SecurePassword -spassword $VaultSecurePassword

    $args = @($InputFile, "yes")
    $ExecutableFullPath = Resolve-Path .\SyncCompUsers.exe
    
    RunProcess -ProcessFullPath $ExecutableFullPath -Args $args -SecurePassword $pass -PasswordEnvVarKey "VAULT_PASSWORD" 
}
catch
{
    write-host "Failed to sync component users."
    write-host $_.Exception
}