#Requires -Version 5.1

###########################################################################
#
# NAME: Reset Cred File Helper
#
# AUTHOR:  Mike Brook<mike.brook@cyberark.com>
#
# COMMENT:
# Script will attempt to regenerate the local Applicative Cred File and Sync it in the Vault.
#
#
###########################################################################
[CmdletBinding()]
param(
    [Parameter(Mandatory=$False)]
    [ValidateSet("cyberark","ldap")]
    [string]$AuthType = "cyberark",

    [Parameter(Mandatory=$false)]
    [Switch]$SkipVersionCheck,

    [Parameter(Mandatory=$false)]
    [Switch]$skipTLS,

    [Parameter(Mandatory = $false, HelpMessage = "Specify a User that has Privilege Cloud Administrative permissions.")]
    [PSCredential]$Credentials,

    [Parameter(Mandatory=$false)]
    [Switch]$SkipCertVerification
)

# Load CyberArk module
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
$ModulePath = Join-Path $ScriptLocation '..\PS-Modules\CyberArkPCloud.psd1'

if (-not (Test-Path $ModulePath)) {
    Write-Error "CyberArk module not found at: $ModulePath"
    Write-Error "Ensure the PS-Modules folder contains CyberArkPCloud.psd1"
    Pause
    Exit 1
}

try {
    Import-Module $ModulePath -Force -ErrorAction Stop
}
catch {
    Write-Error "Failed to load CyberArk module: $_"
    Pause
    Exit 1
}


$Host.UI.RawUI.WindowTitle = "Privilege Cloud CreateCredFile-Helper"
$Script:LOG_FILE_PATH = "$PSScriptRoot\_CreateCredFile-Helper.log"
$global:CPMnewSyncToolFolder = "$PSScriptRoot\CreateCredFile-HelperDependencies"

# Script Version
$ScriptVersion = "4.0"

#region Writer Functions

# Error handling functions (Write-LogMessage, Collect-ExceptionMessage, Join-ExceptionMessage)
# are now available from the ErrorHandling module

#endregion


#region Check latest version
# Taken from https://github.com/AssafMiron/CheckLatestVersion

$Script:GitHubAPIURL = "https://api.github.com/repos"

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-ScriptLatestVersion
# Description....: Compare the current version and the online (GitHub) version
# Parameters.....: The online file URL, current Version, a pattern to look for the script version number in the online file
# Return Values..: True if the online version is the latest, False otherwise
# =================================================================================================================================
Function Test-ScriptLatestVersion
{
<#
.SYNOPSIS
	Compare the current version and the online (GitHub) version
.DESCRIPTION
	Compare the current version and the online (GitHub) version.
    Can compare version number based on Major, Major-Minor and Major-Minor-Patch version numbers
    Returns True if the online version is the latest, False otherwise
.PARAMETER fileURL
    The online file URL (in GitHub) to download and inspect
.PARAMETER currentVersion
    The current version number to compare to
.PARAMETER versionPattern
    A pattern of the script version number to search for in the online file
#>
    param(
        [Parameter(Mandatory=$true)]
        [string]$fileURL,
        [Parameter(Mandatory=$true)]
        [string]$currentVersion,
        [Parameter(Mandatory=$false)]
        [string]$versionPattern = "ScriptVersion",
        [Parameter(Mandatory=$false)]
        [ref]$outGitHubVersion
    )
    $getScriptContent = ""
    $isLatestVersion = $false
    try{
        $getScriptContent = (Invoke-WebRequest -UseBasicParsing -Uri $scriptURL).Content
        If($($getScriptContent -match "$versionPattern\s{0,1}=\s{0,1}\""([\d\.]{1,10})\"""))
	    {
            $gitHubScriptVersion = $Matches[1]
            if($null -ne $outGitHubVersion)
            {
                $outGitHubVersion.Value = $gitHubScriptVersion
            }
            Write-LogMessage -type verbose -msg "Current Version: $currentVersion; GitHub Version: $gitHubScriptVersion"
            # Get a Major-Minor number format
            $gitHubMajorMinor = [double]($gitHubScriptVersion.Split(".")[0..1] -join '.')
            $currentMajorMinor = [double]($currentVersion.Split(".")[0..1] -join '.')
            # Check if we have a Major-Minor-Patch version number or only Major-Minor
            If(($gitHubScriptVersion.Split(".").count -gt 2) -or ($currentVersion.Split(".").count -gt 2))
            {
                $gitHubPatch = [int]($gitHubScriptVersion.Split(".")[2])
                $currentPatch = [int]($currentVersion.Split(".")[2])
            }
            # Check the Major-Minor version
            If($gitHubMajorMinor -ge $currentMajorMinor)
            {
                If($gitHubMajorMinor -eq $currentMajorMinor)
                {
                    # Check the patch version
                    $isLatestVersion = $($gitHubPatch -gt $currentPatch)
                }
                else {
                    $isLatestVersion = $true
                }
            }
        }
        {
            Write-LogMessage -type Info -MSG "Test-ScriptLatestVersion: Couldn't match Script Version pattern ($versionPattern)"
        }
    }
    catch
    {
        Write-LogMessage -type Info -MSG ("Test-ScriptLatestVersion: Couldn't download and check for latest version", $_.Exception)
    }
    return $isLatestVersion
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Copy-GitHubContent
# Description....: Copies all file and folder structure from a specified GitHub repository folder
# Parameters.....: The output folder path, the GitHub item URL to download from
# Return Values..: NONE
# =================================================================================================================================
Function Copy-GitHubContent
{
    <#
.SYNOPSIS
	Copies all file and folder structure from a specified GitHub repository folder
.DESCRIPTION
	Copies all file and folder structure from a specified GitHub repository folder
    Will create the content from a GitHub URL in the output folder
    Can handle files and folders recursively
.PARAMETER outputFolderPath
    The folder path to create the files and folders in
.PARAMETER gitHubItemURL
    The GitHub item URL to download from
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$outputFolderPath,
        [Parameter(Mandatory=$true)]
        [string]$gitHubItemURL
    )
    try{
        $gitHubFolderObject = (Invoke-RestMethod -Method Get -Uri $gitHubItemURL)
        foreach ($item in $gitHubFolderObject) {
            if($item.type -eq "dir")
            {
                # Create the relevant folder
                $itemDir = Join-Path -Path $outputFolderPath -ChildPath $item.name
                if(! (Test-Path -path $itemDir))
                {
                    New-Item -ItemType Directory -Path $itemDir | Out-Null
                }
                # Get all relevant files from the folder
                Copy-GitHubContent -outputFolderPath $itemDir -gitHubItemURL $item.url
            }
            elseif ($item.type -eq "file") {
                Invoke-WebRequest -UseBasicParsing -Uri ($item.download_url) -OutFile $(Join-Path -Path $outputFolderPath -ChildPath $item.name)
            }
        }
    }
    catch{
        Throw $(New-Object System.Exception ("Copy-GitHubContent: Couldn't download files and folders from GitHub URL ($gitHubItemURL)",$_.Exception))
    }
}

Function Replace-Item
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path $_})]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path $_})]
        [string]$Destination,
        [Parameter(Mandatory=$false)]
        [switch]$Recurse
    )

    try{
        foreach($item in $(Get-ChildItem -Recurse:$Recurse -Path $Path))
        {
            $destPath = split-path -path $item.fullName.Replace($Path, $Destination) -Parent
            $oldName = "$($item.name).OLD"
            if(Test-Path -Path $(Join-Path -path $destPath -ChildPath $item.name))
            {
                Rename-Item -Path $(Join-Path -path $destPath -ChildPath $item.name) -NewName $oldName
                Copy-Item -path $item.FullName -Destination $(Join-Path -path $destPath -ChildPath $item.name)
                Remove-Item -path $(Join-Path -path $destPath -ChildPath $oldName)
            }
            Else
			{
				Write-Error "Can't find file $($item.name) in destination location '$destPath' to replace, copying"
                Copy-Item -path $item.FullName -Destination $destPath
			}
        }
    }
    catch{
        Throw $(New-Object System.Exception ("Replace-Item: Couldn't Replace files",$_.Exception))
    }

}

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-GitHubLatestVersion
# Description....: Tests if the script is running the latest version from GitHub
# Parameters.....: NONE
# Return Values..: True / False
# =================================================================================================================================
Function Test-GitHubLatestVersion
{
<#
.SYNOPSIS
	Tests if the script is running the latest version from GitHub
.DESCRIPTION
	Tests if the script is running the latest version from GitHub
    Can support a mode of test only and Test and download new version
    Can support searching the entire repository or a specific folder or a specific branch (default main)
    If not exclusively selected to test only, the function will update the script if a new version is found
.PARAMETER repositoryName
    The repository name
.PARAMETER scriptVersionFileName
    The file name to search the script version in
.PARAMETER currentVersion
    The current version of the script
.PARAMETER sourceFolderPath
    The source folder of the script
    Used to download and replace the new updated script to
.PARAMETER repositoryFolderPath
    The repository Folder path
.PARAMETER branch
    The branch to search for
    Default main
.PARAMETER versionPattern
    The pattern to check in the script
    Default: ScriptVersion
.PARAMETER TestOnly
    Switch parameter to perform only test
    If not exclusively selected, the function will update the script if a new version is found
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$repositoryName,
    [Parameter(Mandatory=$true)]
    [string]$scriptVersionFileName,
    [Parameter(Mandatory=$true)]
    [string]$currentVersion,
    [Parameter(Mandatory=$true)]
    [string]$sourceFolderPath,
    [Parameter(Mandatory=$false)]
    [string]$repositoryFolderPath,
    [Parameter(Mandatory=$false)]
    [string]$branch = "main",
    [Parameter(Mandatory=$false)]
    [string]$versionPattern = "ScriptVersion",
    [Parameter(Mandatory=$false)]
    [switch]$TestOnly
)
    if([string]::IsNullOrEmpty($repositoryFolderPath))
    {
        $apiURL = "$GitHubAPIURL/$repositoryName/contents"
    }
    else {
        $apiURL = "$GitHubAPIURL/$repositoryName/contents/$repositoryFolderPath`?ref=$branch"
    }

	$retLatestVersion = $true
	try{
		$folderContents = $(Invoke-RestMethod -Method Get -Uri $apiURL)
		$scriptURL = $($folderContents | Where-Object { $_.Type -eq "file" -and $_.Name -eq $scriptVersionFileName }).download_url
        $gitHubVersion = 0
        $shouldDownloadLatestVersion = Test-ScriptLatestVersion -fileURL $scriptURL -currentVersion $currentVersion -outGitHubVersion ([ref]$gitHubVersion)
	}
	catch
	{
		Write-LogMessage -type Info -MSG ("Test-GitHubLatestVersion: Couldn't check for latest version $($_.Exception.Message)")
	}

    try{
        # Check if we need to download the gitHub version
        If($shouldDownloadLatestVersion -eq $true)
        {
            # GitHub has a more updated version
            $retLatestVersion = $false
            If(! $TestOnly) # Not Test only, update script
            {
                Write-LogMessage -type Info -Msg "Found new version (version $gitHubVersion), Updating..."
                # Create a new tmp folder to download all files to
                $tmpFolder = Join-Path -path $sourceFolderPath -ChildPath "tmp"
                if(! (Test-Path -path $tmpFolder))
                {
                    New-Item -ItemType Directory -Path $tmpFolder | Out-Null
                }
                try{
                    # Download the entire folder (files and directories) to the tmp folder
                    Copy-GitHubContent -outputFolderPath $tmpFolder -gitHubItemURL $apiURL
                    # Replace the current folder content
                    Replace-Item -Recurse -Path $tmpFolder -Destination $sourceFolderPath
                    # Remove tmp folder
                    Remove-Item -Recurse -Path $tmpFolder -Force
                }
                catch
                {
                    # Revert to current version in case of error
                    $retLatestVersion = $true
                    Write-Error -Message "There was an error downloading GitHub content." -Exception $_.Exception
                }
            }
            else {
                Write-LogMessage -type Info -Msg "Found a new version in GitHub (version $gitHubVersion), skipping update"
            }
        }
        Else
        {
            Write-LogMessage -type Info -Msg "Current version ($currentVersion) is the latest!"
        }
    }
    catch
	{
		Throw $(New-Object System.Exception ("Test-GitHubLatestVersion: Couldn't download latest version",$_.Exception))
	}

	return $retLatestVersion
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-Choice
# Description....: Prompts user for Selection choice
# Parameters.....: None
# Return Values..:
# =================================================================================================================================
Function Get-Choice {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        $Title,

        [Parameter(Mandatory = $true, Position = 1)]
        [String[]]
        $Options,

        [Parameter(Position = 2)]
        $DefaultChoice = -1
    )

    # Check if running on macOS
    if ($IsMacOS -or ($PSVersionTable.OS -match "Unix" -and !(Test-Path Env:OS -Value "Windows_NT"))) {
        if ($DefaultChoice -ne -1 -and ($DefaultChoice -gt $Options.Count -or $DefaultChoice -lt 0)) {
            Write-Warning "DefaultChoice needs to be a value between 0 and $($Options.Count - 1) or -1 (for none)"
            return
        }

        Write-Host "$Title`n"

        for ($i = 0; $i -lt $Options.Length; $i++) {
            Write-Host "$($i+1): $($Options[$i])"
        }

        $choice = $DefaultChoice
        if ($DefaultChoice -eq -1) {
            do {
                $input = Read-Host "Please select an option (1-$($Options.Length))"
                if ($input -match '^\d+$') {
                    $choice = [int]$input - 1
                }
            }
            while ($choice -lt 0 -or $choice -ge $Options.Length)
        }

        return $Options[$choice]
    } else {
        # Original GUI-based logic for Windows
        if ($DefaultChoice -ne -1 -and ($DefaultChoice -gt $Options.Count -or $DefaultChoice -lt 1)) {
            Write-Warning "DefaultChoice needs to be a value between 1 and $($Options.Count) or -1 (for none)"
            exit
        }
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        [System.Windows.Forms.Application]::EnableVisualStyles()
        $script:result = ""
        $form = New-Object System.Windows.Forms.Form
        $form.FormBorderStyle = [Windows.Forms.FormBorderStyle]::FixedDialog
        $form.BackColor = [Drawing.Color]::White
        $form.TopMost = $True
        $form.Text = $Title
        $form.ControlBox = $False
        $form.StartPosition = [Windows.Forms.FormStartPosition]::CenterScreen
        # Calculate width required based on longest option text and form title
        $minFormWidth = 300
        $formHeight = 44
        $minButtonWidth = 150
        $buttonHeight = 23
        $buttonY = 12
        $spacing = 10
        $buttonWidth = [Windows.Forms.TextRenderer]::MeasureText((($Options | Sort-Object Length)[-1]), $form.Font).Width + 1
        $buttonWidth = [Math]::Max($minButtonWidth, $buttonWidth)
        $formWidth = [Windows.Forms.TextRenderer]::MeasureText($Title, $form.Font).Width
        $spaceWidth = ($options.Count + 1) * $spacing
        $formWidth = ($formWidth, $minFormWidth, ($buttonWidth * $Options.Count + $spaceWidth) | Measure-Object -Maximum).Maximum
        $form.ClientSize = New-Object System.Drawing.Size($formWidth, $formHeight)
        $index = 0
        # Create the buttons dynamically based on the options
        foreach ($option in $Options) {
            Set-Variable "button$index" -Value (New-Object System.Windows.Forms.Button)
            $temp = Get-Variable "button$index" -ValueOnly
            $temp.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
            $temp.UseVisualStyleBackColor = $True
            $temp.Text = $option
            $buttonX = ($index + 1) * $spacing + $index * $buttonWidth
            $temp.Add_Click({
                    $script:result = $this.Text;
                    $form.Close()
                })
            $temp.Location = New-Object System.Drawing.Point($buttonX, $buttonY)
            $form.Controls.Add($temp)
            $index++
        }
        $shownString = '$this.Activate();'
        if ($DefaultChoice -ne -1) {
            $shownString += '(Get-Variable "button$($DefaultChoice-1)" -ValueOnly).Focus()'
        }
        $shownSB = [ScriptBlock]::Create($shownString)
        $form.Add_Shown($shownSB)
        [void]$form.ShowDialog()
        return $result
    }
}
#endregion

#region Components Detection
# @FUNCTION@ ======================================================================================================================
# Name...........: Get-ServiceInstallPath
# Description....: Get the installation path of a service
# Parameters.....: Service Name
# Return Values..: $true
#                  $false
# =================================================================================================================================
# Save the Services List
$m_ServiceList = $null
function Get-ServiceInstallPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    try {
        # Construct the registry path for the service.
        $regKeyPath = "HKLM:\System\CurrentControlSet\Services\$ServiceName"

        # Retrieve the service registry key properties.
        $serviceProps = Get-ItemProperty -Path $regKeyPath -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace($serviceProps.ImagePath)) {
            Write-LogMessage -type Verbose -MSG "Service '$ServiceName' does not have an ImagePath defined."
            return $null
        }

        $imagePath = $serviceProps.ImagePath.Trim()

        # If the ImagePath starts with quotes, extract the content inside quotes.
        if ($imagePath.StartsWith('"')) {
            if ($imagePath -match '^"([^"]+)"') {
                return $matches[1]
            } else {
                Write-LogMessage -type Verbose -MSG "Unable to extract the executable path from quoted ImagePath: $imagePath"
                return $imagePath
            }
        } else {
            # If the path isn�t quoted, assume the executable path is the first token.
            return $imagePath.Split(" ")[0]
        }
    }
    catch {
        Write-LogMessage -type Verbose -MSG "Error retrieving install path for service '$ServiceName': $_"
        return $null
    }
}


# @FUNCTION@ ======================================================================================================================
# Name...........: Get-FileVersion
# Description....: Method to return a file version
# Parameters.....: File Path
# Return Values..: File version
# =================================================================================================================================
Function Get-FileVersion
{
<#
.SYNOPSIS
	Method to return a file version

.DESCRIPTION
	Returns the File version and Build number
	Returns Null if not found

.PARAMETER FilePath
	The path to the file to query
#>
	param ($filePath)
	Begin {

	}
	Process {
		$retFileVersion = $Null
		try{
			If (($null -ne $filePath) -and (Test-Path $filePath))
			{
				$path = Resolve-Path $filePath
				$retFileVersion = ($path | Get-Item | Select-Object VersionInfo).VersionInfo.ProductVersion
			}
			else
			{
				throw "File path is empty"
			}

			return $retFileVersion
		}
		catch{
			Throw $(New-Object System.Exception ("Cannot get File ($filePath) version",$_.Exception))
		}
		finally{

		}
	}
	End {

	}
}


# @FUNCTION@ ======================================================================================================================
# Name...........: Find-Components
# Description....: Detects all CyberArk Components installed on the local server
# Parameters.....: None
# Return Values..: Array of detected components on the local server
# =================================================================================================================================
Function Find-Components
{
<#
.SYNOPSIS
	Method to query a local server for CyberArk components
.DESCRIPTION
	Detects all CyberArk Components installed on the local server
#>
	param(
		[Parameter(Mandatory=$false)]
		[ValidateSet("All","CPM","PVWA","PSM","AIM")]
		[String]$Component = "All"
	)

	Begin {
		$retArrComponents = @()
		# COMPONENTS SERVICE NAMES
		$REGKEY_CPMSERVICE = "CyberArk Password Manager"
        $REGKEY_CPMScannerSERVICE = "CyberArk Central Policy Manager Scanner"
		$REGKEY_PVWASERVICE = "CyberArk Scheduled Tasks"
		$REGKEY_PSMSERVICEold = "Cyber-Ark Privileged Session Manager" #12.7-
        $REGKEY_PSMSERVICEnew = "CyberArk Privileged Session Manager" #13.0+
		$REGKEY_AIMSERVICE = "CyberArk Application Password Provider"
	}
	Process {
		if(![string]::IsNullOrEmpty($Component))
		{
			Switch ($Component) {
				"CPM"
				{
					try{
						# Check if CPM is installed
						Write-LogMessage -Type "Debug" -MSG "Searching for CPM..."
						if($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_CPMSERVICE)))
						{
							# Get the CPM Installation Path
							Write-LogMessage -Type "Info" -MSG "Found CPM installation"
							$cpmPath = $componentPath.Replace("Scanner\CACPMScanner.exe","").Replace("PMEngine.exe","").Replace("/SERVICE","").Replace('"',"").Trim()
                            $ConfigPath = (Join-Path -Path $cpmPath -ChildPath "Vault\Vault.ini")
							$fileVersion = [version](Get-FileVersion "$cpmPath\PMEngine.exe")
                            $serviceLogsOldTrace = @(Join-Path -Path $cpmPath -ChildPath "Logs\old\PMTrace.log.*" | Get-ChildItem -Recurse | Select-Object -Last 10)
                            $serviceLogsOldConsole = @(Join-Path -Path $cpmPath -ChildPath "Logs\old\PMConsole.log.*" | Get-ChildItem -Recurse | Select-Object -Last 10)
                            $ServiceLogsMain = @((Join-Path -Path $cpmPath -ChildPath "Logs\PMTrace.log"),(Join-Path -Path $cpmPath -ChildPath "Logs\CACPMScanner.log"))
                            $serviceLogs = $ServiceLogsMain + $serviceLogsOldTrace + $serviceLogsOldConsole
                            $userType = "CPM"
                            #Create New Fresh Cred File, it will not overwrite an existing one, this is just incase there was no cred to begin with.
                            New-Item (Join-Path -Path $cpmPath -ChildPath "Vault\user.ini") -ErrorAction SilentlyContinue | Get-Acl | Set-Acl (Join-Path -Path $cpmPath -ChildPath "Vault\Vault.ini")
                            $appFilePath = (Join-Path -Path $cpmPath -ChildPath "Vault\user.ini")
                            if (Test-Path $appFilePath){
                                $ComponentUser = @($appFilePath)
                            }
							$myObject = New-Object PSObject -Property @{Name="CPM";DisplayName="CyberArk Password Manager (CPM)";
                                                                        ServiceName=@($REGKEY_CPMSERVICE,$REGKEY_CPMScannerSERVICE);Path=$cpmPath;Version=$fileVersion;
                                                                        ComponentUser=$ComponentUser;ConfigPath=$ConfigPath;ServiceLogs=$ServiceLogs;UserType=$userType}
                            $myObject | Add-Member -MemberType ScriptMethod -Name InitPVWAURL -Value { Set-PVWAURL -ComponentID $this.Name -ConfigPath $this.ConfigPath -AuthType $AuthType } | Out-Null
                            return $myObject
						}
					} catch {
						Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
					}
					break
				}
				"PVWA"
				{
					try{
						# Check if PVWA is installed
						Write-LogMessage -Type "Debug" -MSG "Searching for PVWA..."
						if($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_PVWASERVICE)))
						{
							Write-LogMessage -Type "Info" -MSG "Found PVWA installation"
							$pvwaPath = $componentPath.Replace("Services\CyberArkScheduledTasks.exe","").Replace('"',"").Trim()
							$fileVersion = [version](Get-FileVersion "$pvwaPath\Services\CyberArkScheduledTasks.exe")
                            $ServiceLogs = @()
                            $ComponentUser = @()
                            $ConfigPath = ""
                            $myObject = New-Object PSObject -Property @{Name="PVWA";DisplayName="CyberArk Password Vault Web Application (PVWA)";
                                                                        ServiceName=$REGKEY_PVWASERVICE;Path=$pvwaPath;Version=$fileVersion;
                                                                        ComponentUser=$ComponentUser;ConfigPath=$ConfigPath;ServiceLogs=$ServiceLogs}
                            $myObject | Add-Member -MemberType ScriptMethod -Name InitPVWAURL -Value { Set-PVWAURL -ComponentID $this.Name -ConfigPath $this.ConfigPath -AuthType $AuthType} | Out-Null
                            return $myObject
						}
					} catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
					}
					break
				}
				"PSM"
				{
                            try{
                            # handle old and new psm
                            $psmCandidates = @($REGKEY_PSMSERVICEold, $REGKEY_PSMSERVICEnew)
                            $componentPath = $null
                            foreach ($candidate in $psmCandidates) {
                                $foundPath = Get-ServiceInstallPath $candidate
                                if ($foundPath) {
                                    $componentPath = $foundPath
                                    $REGKEY_PSMSERVICE = $candidate
                                break
                                }
                            }
                            # If no valid install found, exit switch
                            if (-not $componentPath) {
                                Write-LogMessage -Type "Debug" -MSG "PSM service not found. Skipping PSM detection."
                                break
                            }
                            Write-LogMessage -Type "Info" -MSG "Found PSM installation"
							$PSMPath = $componentPath.Replace("CAPSM.exe","").Replace('"',"").Trim()
                            $ConfigPath = (Join-Path -Path $PSMPath -ChildPath "temp\PVConfiguration.xml")
							$fileVersion = [version](Get-FileVersion "$PSMPath\CAPSM.exe")
                            $serviceLogsOldTrace = @(Join-Path -Path $PSMPath -ChildPath "Logs\old\PSMTrace.log.*" | Get-ChildItem -Recurse | Select-Object -Last 10)
                            $serviceLogsOldConsole = @(Join-Path -Path $PSMPath -ChildPath "Logs\old\PSMConsole.log.*" | Get-ChildItem -Recurse | Select-Object -Last 10)
                            $ServiceLogsMain = @(Join-Path -Path $PSMPath -ChildPath "Logs\PSMTrace.log")
                            $ServiceLogs = $ServiceLogsMain + $serviceLogsOldTrace + $serviceLogsOldConsole
                            $ComponentUser = @()
                            $UserType = "PSM"
                            #Create New Fresh Cred File, it will not overwrite an existing one, this is just incase there was no cred to begin with.
                            foreach($cleanCredFile in @("psmapp.cred","psmgw.cred"))
                            {
                            New-Item (Join-Path -Path $PSMPath -ChildPath "Vault\$cleanCredFile") -ErrorAction SilentlyContinue | Get-Acl | Set-Acl (Join-Path -Path $PSMPath -ChildPath "Vault\Vault.ini")
                            }
                            foreach($fileName in @("psmapp.cred","psmgw.cred"))
                            {
                                $appFilePath = (Join-Path -Path $PSMPath -ChildPath "Vault\$fileName")
                                if (Test-Path $appFilePath){
                                    $ComponentUser += $appFilePath
                                }
                            }
                            $myObject = New-Object PSObject -Property @{Name="PSM";DisplayName="CyberArk Privileged Session Manager (PSM)";
                                                                        ServiceName=$REGKEY_PSMSERVICE;Path=$PSMPath;Version=$fileVersion;
                                                                        ComponentUser=$ComponentUser;ConfigPath=$ConfigPath;ServiceLogs=$ServiceLogs;UserType=$UserType}
                            $myObject | Add-Member -MemberType ScriptMethod -Name InitPVWAURL -Value { Set-PVWAURL -ComponentID $this.Name -ConfigPath $this.ConfigPath -AuthType $AuthType} | Out-Null
                            return $myObject

					} catch {
						Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
					}
					break
				}
				"AIM"
				{
					try{
						# Check if AIM is installed
						Write-LogMessage -Type "Debug" -MSG "Searching for AIM..."
						if($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_AIMSERVICE)))
						{
							Write-LogMessage -Type "Info" -MSG "Found AIM installation"
							$AIMPath = $componentPath.Replace("/mode SERVICE","").Replace("AppProvider.exe","").Replace('"',"").Trim()
                            $ConfigPath = (Join-Path -Path $AIMPath -ChildPath "Vault\Vault.ini")
							$fileVersion = [version](Get-FileVersion "$AIMPath\AppProvider.exe")
                            $serviceLogsOldTrace = @(Join-Path -Path $AIMPath -ChildPath "Logs\old\APPTrace.log.*" | Get-ChildItem -Recurse | Select-Object -Last 10)
                            $serviceLogsOldConsole = @(Join-Path -Path $AIMPath -ChildPath "Logs\old\APPConsole.log.*" | Get-ChildItem -Recurse | Select-Object -Last 10)
                            $ServiceLogsMain = @(Join-Path -Path $AIMPath -ChildPath "Logs\APPTrace.log")
                            $ServiceLogs = $ServiceLogsMain + $serviceLogsOldTrace + $serviceLogsOldConsole
                            $UserType = "AppProvider"
                            #Create New Fresh Cred File, it will not overwrite an existing one, this is just incase there was no cred to begin with.
                            New-Item (Join-Path -Path $AIMPath -ChildPath "Vault\AppProviderUser.cred") -ErrorAction SilentlyContinue | Get-Acl | Set-Acl (Join-Path -Path $AIMPath -ChildPath "Vault\Vault.ini")
                            $appFilePath = (Join-Path -Path $AIMPath -ChildPath "Vault\AppProviderUser.cred")
                            if (Test-Path $appFilePath){
                                $ComponentUser = @($appFilePath)
                            }
                            $myObject = New-Object PSObject -Property @{Name="AIM";DisplayName="CyberArk Application Password Provider (AIM)";
                                                                        ServiceName=$REGKEY_AIMSERVICE;Path=$AIMPath;Version=$fileVersion;
                                                                        ComponentUser=$ComponentUser;ConfigPath=$ConfigPath;ServiceLogs=$ServiceLogs;UserType=$UserType}
                            $myObject | Add-Member -MemberType ScriptMethod -Name InitPVWAURL -Value { Set-PVWAURL -ComponentID $this.Name -ConfigPath $this.ConfigPath -AuthType $AuthType } | Out-Null
                            return $myObject
						}
					} catch {
						Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
					}
					break
				}
				"All"
				{
					try{
						ForEach($comp in @("CPM","PVWA","PSM","AIM"))
						{
							$retArrComponents += Find-Components -Component $comp
						}
						return $retArrComponents
					} catch {
						Write-LogMessage -Type "Error" -Msg "Error detecting components. Error: $(Join-ExceptionMessage $_.Exception)"
					}
					break
				}
			}
		}
	}
	End {
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Set-PVWAURL
# Description....: Sets the PVWA URLs to be used in the script based on the Component found
# Parameters.....: Component ID (PVWA, CPM, PSM), ConfigPath
# Return Values..: NONE (All PVWA URLs are set on a script level)
# =================================================================================================================================
Function Set-PVWAURL{
<#
.SYNOPSIS
	Sets the PVWA URLs to be used in the script based on the Component found
.DESCRIPTION
	Sets the PVWA URLs to be used in the script based on the Component found
.PARAMETER ComponentID
    The component ID that is used
    Accepts only: PVWA, CPM, PSM
.PARAMETER ConfigPath
    For CPM and PSM, this is the configuration path to extract the PVWA URL from
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("PVWA","CPM","PSM","AIM")]
        [string]$ComponentID,
        [Parameter(Mandatory=$False)]
        [string]$ConfigPath,
        [Parameter(Mandatory=$False)]
        [ValidateSet("cyberark","ldap")]
        [string]$AuthType = "cyberark"
    )
    Try{
        $foundConfig = $false
        Write-LogMessage -type debug -Msg "Get PVWA URL from component '$ComponentID' and from config file '$ConfigPath'"
        if($ComponentID -eq "PVWA")
        {
            $PVWAurl = "https://$($env:COMPUTERNAME)"
            $foundConfig = $true
        }
        if (Test-Path $ConfigPath)
        {
            if ($ComponentID -eq "PSM"){
                [xml]$GetPVWAStringURL = Get-Content $ConfigPath
                if(![string]::IsNullOrEmpty($GetPVWAStringURL) -and $GetPVWAStringURL.PasswordVaultConfiguration.General.ApplicationRoot){
                    # In case there is more than one address, get the first one
                    $PVWAurl = ($GetPVWAStringURL.PasswordVaultConfiguration.General.ApplicationRoot).Split(",")[0]
                    # Check that the PVWAUrl contains a URL and not IP
                    # if false, URL contains IP and we need to prompt for user input.
                    $foundConfig = ($PVWAurl -NotMatch "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
                }
                else {
                    Write-LogMessage -type Warning -Msg "Error reading the configuration file $($ConfigPath)"
                }
            }
            if ($ComponentID -eq "CPM"){
                try{
                    # In case there is more than one address, get the first one
                    $GetPVWAStringURL = ((Get-Content $ConfigPath | Where-Object {$_ -match "Addresses" }).Split("=")[1]).Split(",")[0]
                } catch {
                    Write-LogMessage -type Error -MSG "There was an error finding PVWA Address from vault.ini configuration file"
                    $GetPVWAStringURL = $null
                }
                If(![string]::IsNullOrEmpty($GetPVWAStringURL)){
                    $PVWAurl = $GetPVWAStringURL
                    $foundConfig = $true
                }
            }
            if ($ComponentID -eq "AIM"){
                try{
                    # In case there is more than one address, get the first one
                    $GetPVWAStringURL = ((Get-Content $ConfigPath | Where-Object {$_ -match "Address" }).Split("=")[1]).Split(",")[0]
                    # if false, URL contains IP and we need to prompt for user input.
                    $foundConfig = ($GetPVWAStringURL -NotMatch "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
                    # In case of AIM there is no PVWA record anywhere, but we can determine if vault address is DNS type and has pcloud pattern and convert it to PVWA from it.
                    if (($foundConfig -eq $true) -and (-not([string]::IsNullOrEmpty($GetPVWAStringURL)))){
                        # URL exists and is DNS type, let's check if its pcloud pattern
                        if (($GetPVWAStringURL -like "vault-*.cyberark.com") -or ($GetPVWAStringURL -like "*vault-*.cyberark.cloud")){
                            # grab first subdomain and trim vault- from it.
                            $portalSubDomainURL = $GetPVWAStringURL.split(".")[0].TrimStart("vault-")
                        }
                        Else{
                            # set $foundConfig to false in case this is non pcloud tenant so it prompts user to enter PVWA again
                            $foundConfig = $False
                         }
                        # Check if standard or shared services implementation.
                        if($GetPVWAStringURL -like "*.cyberark.com"){
                            # standard
                            $script:PVWAurl = "https://$portalSubDomainURL.privilegecloud.cyberark.com"
                        }
                        Elseif($GetPVWAStringURL -like "*.cyberark.cloud"){
                            # ISPSS
                            $script:PVWAurl = "https://$portalSubDomainURL.privilegecloud.cyberark.cloud"
                        }
                    }
                } catch {
                    Write-LogMessage -type Error -MSG "There was an error finding PVWA Address from vault.ini configuration file"
                    $GetPVWAStringURL = $null
                }
            }
        }
        # We Couldn't find PVWA URL so we prompt the user
        if(($foundConfig -eq $False) -or ([string]::IsNullOrEmpty($PVWAurl)))
        {
            Write-LogMessage -type Info -MSG "Couldn't retrieve portal URL from configuration file, let's type it manually:"
            $PVWAurl = (Read-Host "Enter your Portal URL (eg; 'https://mikeb.privilegecloud.cyberark.com' or https://mikeb.privilegecloud.cyberark.cloud)")
            # Check pcloud format
            if($PVWAurl -notmatch "\.privilegecloud\.cyberark."){
                Write-LogMessage -type Warning -MSG "Warning: URL entered doesn't seem to have Privilege Cloud Format (Missing `"privilegecloud`" in the string)"
                $PVWAurl = $PVWAurl -replace "(\.cyberark\.)", ".privilegecloud.cyberark."
                Write-LogMessage -type Info -MSG "Let's rebuild the URL: $PVWAurl"
            }
        }

		# Let user confirm this is the correct URL, otherwise, enter manually
        $confirmPVWAUrl = Get-Choice -Title "Is this your Portal URL: $PVWAurl" -Options "Yes", "No, let me type." -DefaultChoice 1
        if($confirmPVWAUrl -eq "No, let me type."){
            $PVWAurl = (Read-Host "Enter your Portal URL (eg; 'https://mikeb.privilegecloud.cyberark.com' or https://mikeb.privilegecloud.cyberark.cloud)")
        }

        Write-LogMessage -type debug -Msg "The PVWA URL to be used is: '$PVWAurl'"
    } Catch{
        Write-LogMessage -type Error -MSG "There was an error reading the $ComponentID configuration file '$ConfigPath': $($_.Exception.Message)"
        Write-LogMessage -type Info -MSG "Couldn't retrieve portal URL from configuration file, let's type it manually:"
        $PVWAurl = (Read-Host "Enter your Portal URL (eg; 'https://mikeb.privilegecloud.cyberark.com' or https://mikeb.privilegecloud.cyberark.cloud)")
    }

    # Set the PVWA URLS
    $URL_PVWA = "https://"+([System.Uri]$PVWAurl).Host
    $URL_PVWAPasswordVault = $URL_PVWA+"/passwordVault"
    $global:URL_PVWAAPI = $URL_PVWAPasswordVault+"/api"
    $URL_PVWAAuthentication = $URL_PVWAAPI+"/auth"
    $script:URL_PVWALogon = $URL_PVWAAuthentication+"/$AuthType/Logon"
    $script:URL_PVWALogoff = $URL_PVWAAuthentication+"/Logoff"
    Write-LogMessage -type debug -Msg "Logon URL will be: '$URL_PVWALogon'"
    # URL Methods
    # -----------
    $script:URL_Users = $URL_PVWAAPI+"/Users"
    $script:URL_UserResetPassword = $URL_Users+"/{0}/ResetPassword"
    $script:URL_UserActivate = $URL_Users+"/{0}/Activate"
    $script:URL_SystemHealthComponent =  $URL_PVWAAPI+"/ComponentsMonitoringDetails/"
    Write-LogMessage -type debug -Msg "Users URL will be: '$URL_Users'"
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-SystemHealth
# Description....: Detects all CyberArk Components installed on the local server
# Parameters.....: None
# Return Values..: Array of detected components on the local server
# =================================================================================================================================
Function Get-SystemHealth
{
    param(
        # Component ID to return System Health on
        [Parameter(Mandatory=$true)]
        [string]$ComponentID,
        [Parameter(Mandatory=$False)]
        [string]$componentUserDetails,
        [Parameter(Mandatory=$false)]
        [switch]$OfflineOnly
    )

    $WhereFilterText = ""
    # Check the component user

    If([string]::IsNullOrEmpty($componentUserDetails) -or $OfflineOnly)
    {
        # Set the filter to offline components from Component ID type
        $WhereFilterText = '$_.IsLoggedOn -eq $false'
        Write-LogMessage -type Info -Msg "Checking SystemHealth Status for all $ComponentID offline users"
    }
    else {
        # Set the filter to the specific component user name
        $WhereFilterText = '$_.ComponentUserName -eq $componentUserDetails'
        Write-LogMessage -type Info -Msg "Checking SystemHealth Status for User $componentUserDetails"
    }
    # Handle specific use case of PSM ID
    if($ComponentID -eq "PSM") { $URI = $URL_SystemHealthComponent+"SessionManagement" }
    else { $URI = $URL_SystemHealthComponent+$ComponentID }
    $WhereFilter = [scriptblock]::Create($WhereFilterText)
    Try{
        $GetSystemHealthResponse = Invoke-RestMethod -Method Get -Uri $URI -Headers $pvwaLogonHeader -ContentType "application/json" -TimeoutSec 4500
        $offlineComponents = @()
        if($null -ne $GetSystemHealthResponse){
            foreach ($Component in ($GetSystemHealthResponse.ComponentsDetails | Where-Object $WhereFilter)){
                if($OfflineOnly){
                    $offlineComponents += $Component
                }
                elseif ($Component.ComponentUserName -eq $componentUserDetails){
                    if ($Component.IsLoggedOn -eq $true){
                        Write-LogMessage -Type "Success" -Msg "$ComponentID = $componentUserDetails Is : Online!"
                    } Else {
                        Write-LogMessage -Type "Warning" -Msg "$ComponentID = $componentUserDetails Is : Offline! <---"
                    }
                }
            }
        }

        if($OfflineOnly){
            # Return all the offline components for further investigation
            return $offlineComponents
        }
    } Catch{
        Throw $(New-Object System.Exception ("Cannot get '$componentUserDetails' status. Error: $($_.Exception.Response.StatusDescription)",$_.Exception))
    }
}

#endregion

#region PVWA REST Functions
Function Get-LogonHeader{
    <#
    .SYNOPSIS
        Get-LogonHeader
    .DESCRIPTION
        Get-LogonHeader
    .PARAMETER Credentials
        The REST API Credentials to authenticate
    #>
        param(
            [Parameter(Mandatory=$true)]
            [PSCredential]$Credentials
        )

        # Create the POST Body for the Logon
        # ----------------------------------
        $logonBody = @{ username=$Credentials.username.Replace('\','');password=$Credentials.GetNetworkCredential().password } | ConvertTo-Json -Compress

        try{
            # Logon
            $logonToken = Invoke-RestMethod -Method Post -Uri $URL_PVWALogon -Body $logonBody -ContentType "application/json" -TimeoutSec 2700

            # Clear logon body
            $logonBody = ""
        } catch {
            Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.ErrorDetails.Message)"))
        }

        $logonHeader = $null
        If ([string]::IsNullOrEmpty($logonToken))
        {
            Throw "Get-LogonHeader: Logon Token is Empty - Cannot login"
        }

        # Create a Logon Token Header (This will be used through out all the script)
        # ---------------------------
        If($logonToken.PSObject.Properties.Name -contains "CyberArkLogonResult")
        {
            $logonHeader = @{Authorization = $($logonToken.CyberArkLogonResult)}
        } else {
            $logonHeader = @{Authorization = $logonToken}
        }
        return $logonHeader
}

Function Invoke-Logon{
    # Get Credentials to Login
    # ------------------------
    $caption = "Enter Credentials"
    $msg = "Enter your Privilege Cloud Admin Account";
    if(-not($Credentials)){
        [PSCredential]$script:Credentials = $Host.UI.PromptForCredential($caption,$msg,"","")
    }
    try{
        # Login to PVWA
        $global:pvwaLogonHeader = Get-LogonHeader -Credentials $Credentials
    } catch {
        Throw $(New-Object System.Exception ("Error logging on to PVWA",$_.Exception))
    }
}

Function Invoke-Logoff{
    try{
        Write-LogMessage -type Info -Msg "Logoff Session..."
        Invoke-RestMethod -Method Post -Uri $URL_PVWALogoff -Headers $pvwaLogonHeader -ContentType "application/json" | Out-Null
    } catch {
        Throw $(New-Object System.Exception ("Error logging off from PVWA",$_.Exception))
    }
}

#endregion

#region Helper functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Test-CurrentUserLocalAdmin
# Description....: Check if the current user is a Local Admin
# Parameters.....: None
# Return Values..: True/False
# =================================================================================================================================
Function Test-CurrentUserLocalAdmin
{
<#
.SYNOPSIS
	Method to check a service login options and verify that the running user has 'Login as service' rights
.DESCRIPTION
	Check if a service is running with a local user and check if the user has the required user rights to run as service
.PARAMETER ServiceName
	The Service Name to Check Login info for
.PARAMETER UserName
	The User Name to Check 'Login as a Service' for
#>
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    return (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.SecurityIdentifier] "S-1-5-32-544")  # Local Administrators group SID
}

# @FUNCTION@ ======================================================================================================================
# Name...........: New-RandomPassword
# Description....: Creates a new random password
# Parameters.....: Length, (Switch)Lowercase, (Switch)Uppercase, (Switch)Numbers, (Switch)Symbols
# Return Values..: A random password based on the requirements
# =================================================================================================================================
Function New-RandomPassword{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # Length, Type uint32, Length of the random string to create.
        [Parameter(Mandatory=$true, Position=0)]
        [ValidatePattern('[0-9]+')]
        [ValidateRange(1,100)]
        [uint32]$Length,

        # Lowercase, Type switch, Use lowercase characters.
        [Parameter(Mandatory=$false)]
        [switch]$Lowercase=$false,

        # Uppercase, Type switch, Use uppercase characters.
        [Parameter(Mandatory=$false)]
        [switch]$Uppercase=$false,

        # Numbers, Type switch, Use alphanumeric characters.
        [Parameter(Mandatory=$false)]
        [switch]$Numbers=$false,

        # Symbols, Type switch, Use symbol characters.
        [Parameter(Mandatory=$false)]
        [switch]$Symbols=$false
    )
    Begin
    {
        if (-not($Lowercase -or $Uppercase -or $Numbers -or $Symbols))
        {
            throw "You must specify one of: -Lowercase -Uppercase -Numbers -Symbols"
        }

        # Specifies bitmap values for character sets selected.
        $CHARSET_LOWER=1
        $CHARSET_UPPER=2
        $CHARSET_NUMBER=4
        $CHARSET_SYMBOL=8

        # Creates character arrays for the different character classes, based on ASCII character values.
        $charsLower=97..122 | ForEach-Object{ [Char] $_ }
        $charsUpper=65..90 | ForEach-Object{ [Char] $_ }
        $charsNumber=48..57 | ForEach-Object{ [Char] $_ }
        $charsSymbol=35,36,40,41,42,44,45,46,58,59,63,64,95 | ForEach-Object{ [Char] $_ }
    }
    Process
    {
        # Contains the array of characters to use.
        $charList=@()
        # Contains bitmap of the character sets selected.
        $charSets=0
        if ($Lowercase)
        {
            $charList+=$charsLower
            $charSets=$charSets -bor $CHARSET_LOWER
        }
        if ($Uppercase)
        {
            $charList+=$charsUpper
            $charSets=$charSets -bor $CHARSET_UPPER
        }
        if ($Numbers)
        {
            $charList+=$charsNumber
            $charSets=$charSets -bor $CHARSET_NUMBER
        }
        if ($Symbols)
        {
            $charList+=$charsSymbol
            $charSets=$charSets -bor $CHARSET_SYMBOL
        }

        <#
        .SYNOPSIS
            Test string for existence specified character.
        .DESCRIPTION
            examine each character of a string to determine if it contains a specified characters
        .EXAMPLE
            Test-StringContents in string
        #>
        function Test-StringContents([String] $test, [Char[]] $chars)
        {
            foreach ($char in $test.ToCharArray())
            {
                if ($chars -ccontains $char)
                {
                    return $true
                }
            }
            return $false
        }

        do
        {
            # No character classes matched yet.
            $flags=0
            $output=""
            # Create output string containing random characters.
            1..$Length | ForEach-Object { $output+=$charList[(get-random -maximum $charList.Length)] }

            # Check if character classes match.
            if ($Lowercase)
            {
                if (Test-StringContents $output $charsLower)
                {
                    $flags=$flags -bor $CHARSET_LOWER
                }
            }
            if ($Uppercase)
            {
                if (Test-StringContents $output $charsUpper)
                {
                    $flags=$flags -bor $CHARSET_UPPER
                }
            }
            if ($Numbers)
            {
                if (Test-StringContents $output $charsNumber)
                {
                    $flags=$flags -bor $CHARSET_NUMBER
                }
            }
            if ($Symbols)
            {
                if (Test-StringContents $output $charsSymbol)
                {
                    $flags=$flags -bor $CHARSET_SYMBOL
                }
            }
        }
        until ($flags -eq $charSets)
    }
    End
    {
    	$output
    }
}

Function Stop-CYBRService
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $ServiceName
    )
    try{
        #Check If need to Stop CPM or PSM
        $CAStopped = "Stopped"
        $CAStopping = "StopPending"
        $CAStop = "Stop"
        Write-LogMessage -type Info -Msg "Stopping '$ServiceName' Service..."
        #get process ID
        $Service = (Get-WmiObject win32_service | where {$_.name -eq $ServiceName} -ErrorAction SilentlyContinue).ProcessID
        if($Service -eq 0){
            Write-LogMessage -type Info -MSG "Service is already stopped, skipping..."
        }
        Else{
            #kill the process
            Stop-Process $Service -Force | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
            #stop service, this makes sure the next status command receives a proper status as kill command is very abrupt.
            Get-Service $ServiceName | Stop-Service -Force -ErrorAction SilentlyContinue
            $ServiceStatus = Get-Service -Name $ServiceName | Select-Object -ExpandProperty status
            if($ServiceStatus -eq $CAStopped){
                Write-LogMessage -type success -Msg "Successfully $CAStopped Service: $($ServiceName)."
            }
            Else{
                Write-LogMessage -type Warning -Msg "Couldn't $CAStop Service: $($ServiceName) Do it Manually."
            }
        }
    } catch {
        Throw $(New-Object System.Exception ("Error stopping the service '$ServiceName'.",$_.Exception))
    }
}
Function Start-CYBRService
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $ServiceName
    )
    try{
        Write-LogMessage -type Info -MSG "Starting service '$ServiceName'..."
        #Check If need to Stop CPM or PSM
        $CAStarted = "Started"
        $CAStart = "Start"
        $CARunning = "Running"
        $Service = Get-Service $ServiceName
        $service.Start()
        $Service.WaitForStatus($CARunning,'00:01:59')
        $service.refresh()
        $ServiceStatus = Get-Service -Name $Service.Name | Select-Object -ExpandProperty status
        if($ServiceStatus -eq $CARunning){
            Write-LogMessage -type success -Msg "Successfully $CAStarted Service: $($service.name)."
        }
        Else{
            Write-LogMessage -type Warning -Msg "Couldn't $CAStart Service: $($service.name) Do it Manually."
        }
    } catch {
        Throw $(New-Object System.Exception ("Error starting the service '$ServiceName'. Check Service Status and start it Manually (Also check local Console or Trace logs)."))
    }
}

Function enforceTLS {
    # Check the current SecurityProtocol setting
    $securityProtocol = [Net.ServicePointManager]::SecurityProtocol
	if ($securityProtocol -ne 'SystemDefault' -and $securityProtocol -notmatch 'Tls12') {
        Write-LogMessage -type Info -MSG "Detected SecurityProtocol not highest settings ('$($securityProtocol)'), enforcing TLS 1.2."
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	}
        # Registry checks for .NET Framework strong cryptography settings
        $GetTLSReg86 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
        $GetTLSReg64 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue

        # Registry checks for TLS 1.2 being explicitly disabled in Client and Server
        $Gettls12ClientValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -ErrorAction SilentlyContinue
        $Gettls12ServerValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -ErrorAction SilentlyContinue

        $gettls12ClientDefaultDisabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault" -ErrorAction SilentlyContinue
        $gettls12ServerDefaultDisabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -ErrorAction SilentlyContinue

        $TLSReg86 = $GetTLSReg86 -ne $null -and $GetTLSReg86.SchUseStrongCrypto -eq 0
        $TLSReg64 = $GetTLSReg64 -ne $null -and $GetTLSReg64.SchUseStrongCrypto -eq 0
        $tls12ClientValue = $Gettls12ClientValue -ne $null -and $Gettls12ClientValue.Enabled -eq 0
        $tls12ServerValue = $Gettls12ServerValue -ne $null -and $Gettls12ServerValue.Enabled -eq 0
        $tls12ClientDefaultDisabled = $gettls12ClientDefaultDisabled -ne $null -and $gettls12ClientDefaultDisabled.DisabledByDefault -eq 1
        $tls12ServerDefaultDisabled = $gettls12ServerDefaultDisabled -ne $null -and $gettls12ServerDefaultDisabled.DisabledByDefault -eq 1

        if ($TLSReg86 -or $TLSReg64 -or $tls12ClientValue -or $tls12ServerValue -or $tls12ClientDefaultDisabled -or $tls12ServerDefaultDisabled) {
            Write-LogMessage -Type Info -MSG "Adjusting settings to ensure TLS 1.2 is not explicitly disabled and strong cryptography is enforced."
            if ($TLSReg86) {
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord -Force -Verbose
            }
            if ($TLSReg64) {
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord -Force -Verbose
            }
            if ($tls12ClientValue) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Value 1 -Type DWord -Force -Verbose
            }
            if ($tls12ServerValue) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value 1 -Type DWord -Force -Verbose
            }
            if ($tls12ClientDefaultDisabled) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault" -Value 0 -Type DWord -Force -Verbose
            }
            if ($tls12ServerDefaultDisabled) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -Value 0 -Type DWord -Force -Verbose
            }

            Write-LogMessage -Type Warning -MSG "Settings adjusted. Please RESTART the system for the changes to take effect."
            Write-LogMessage -Type Warning -MSG "If this check keeps looping, you can skip it with -skipTLS flag when running the script."
			Pause
			Exit
        } else {
            Write-LogMessage -Type Info -MSG "TLS 1.2 is properly configured."
        }
}

Function IgnoreCert {
    param(
        [bool]$SkipCertVerification = $false # Add a parameter to control certificate verification skipping
    )

    # Your existing logic to check and enforce TLS 1.2 settings

    if ($SkipCertVerification) {
        # The portion of the script that ignores certificate errors
        Write-LogMessage -Type Info -MSG "Skipping certificate verification as per script parameter."
        if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
            $certCallback = @"
                using System;
                using System.Net;
                using System.Net.Security;
                using System.Security.Cryptography.X509Certificates;
                public class ServerCertificateValidationCallback
                {
                    public static void Ignore()
                    {
                        if (ServicePointManager.ServerCertificateValidationCallback == null)
                        {
                            ServicePointManager.ServerCertificateValidationCallback +=
                                delegate
                                (
                                    Object obj,
                                    X509Certificate certificate,
                                    X509Chain chain,
                                    SslPolicyErrors errors
                                )
                                {
                                    return true;
                                };
                        }
                    }
                }
"@
            Add-Type $certCallback
        }
        [ServerCertificateValidationCallback]::Ignore()
    }

    # This line ensures TLS 1.2 is used for future requests. Consider the context and necessity as per earlier discussion.
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}

Function Show-Menu
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$Items
    )
    # Write the menu
    #Clear-Host
    Write-Host "================ ResetCredFile Guide ================"
    Write-Host ""
    Write-Host "Displaying Only Detected CyberArk Services:"
    Write-Host "Please select an option:"
    Write-Host ""
    $i = 1
    $keys = @("Q")
    Write-LogMessage -type debug -Msg "Going over $($Items.Count) items..."
    foreach($item in $Items)
    {
        Write-Host "$($i). $item"
        $keys += $i
        $i++
    }

    Write-Host "Q. Press Q to Quit"

    # Read the answer
    $answer = Read-Host "`nSelect"
    if ($answer -notin $keys)
    {
        Throw "Invalid Option...Exiting..."
    }
    return $answer.ToString()
}

Function Get-CredFileUser
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path $_})]
        [string]$File
    )
    try{
        $fileUserName = ((Get-Content $File | Select-Object -Index 2).split("=")[1]).Trim()
        return $fileUserName
    } catch {
        Write-LogMessage -type Error -MSG "Could not find CredFile user name from file '$file'"
        return $null
    }
}

Function Test-SystemLogs
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComponentID,
        [Parameter(Mandatory=$true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$LogPath
    )
    $retResult = $true
    # Need to wait a few seconds because CPM logs are cleared twice after restart
    Start-Sleep -Seconds 7
    # Check the log is not empty
    if (![string]::IsNullOrEmpty($(Get-Content -Path $LogPath)) -and (Select-String -Path $LogPath -Pattern "error" -Quiet))
    {
        Write-LogMessage -type Error -Msg "$ComponentID Log '$LogPath' has some errors, please check it."
        $retResult = $False
    }
    Else
    {
        $retResult = $True
    }

    return $retResult
}

Function Find-UserInSystemLogs
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$User,
        [Parameter(Mandatory=$true)]
        [string[]]$LogPaths
    )
    $retUser = $null
    ForEach($log in $LogPaths)
    {
        If(Test-Path -Path $log)
        {
            If(Get-Content -Path $log | where {$_ -Match $User}){
                $retUser = $Matches[0]
                break
            }
        }
        Else
        {
            Write-LogMessage -type Warning -MSG "Could not find log file: '$log' - skipping"
        }
    }

    return $retUser
}

Function Format-URL($sText) {
	if ($sText.Trim() -ne "") {
		return [System.Web.HttpUtility]::UrlEncode($sText.Trim())
	}
	else {
		return ""
	}
}

Function New-SearchCriteria {
	param ([string]$sURL, [string]$sSearch, [string]$sSortParam, [string]$sSafeName, [int]$iLimitPage, [int]$iOffsetPage = 0)
	[string]$retURL = $sURL
	$retURL += "?"

	if (![string]::IsNullOrEmpty($sSearch)) {
		$retURL += "search=$(Format-URL $sSearch)&"
	}
	if (![string]::IsNullOrEmpty($sSafeName)) {
		$retURL += "filter=safename eq $(Format-URL $sSafeName)&"
	}
	if (![string]::IsNullOrEmpty($sSortParam)) {
		$retURL += "sort=$(Format-URL $sSortParam)&"
	}
	if ($iLimitPage -gt 0) {
		$retURL += "limit=$iLimitPage&"
	}

	if ($retURL[-1] -eq '&') {
		$retURL = $retURL.substring(0, $retURL.length - 1)
 }
	return $retURL
}

Function Get-Account{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$AccountName,

        [Parameter(Mandatory=$true)]
        [string]$URLAPI,

        [Parameter(Mandatory=$true)]
        $logonheader,

        [Parameter(Mandatory=$true)]
        [string]$SafeName,

        [Parameter(Mandatory=$true)]
        [int]$limitPage
    )

    $limitPage = 0
    $URL_Accounts = $URLAPI + "/Accounts"

    $AccountsURLWithFilters = ""
    $AccountsURLWithFilters = $(New-SearchCriteria -sURL $URL_Accounts -sSearch $AccountName -sSafeName $SafeName -iLimitPage $limitPage)

    Try
    {
        #Write-LogMessage -Type Info -Msg "Calling: $($AccountsURLWithFilters)"
        Write-LogMessage -type Info -MSG "Looking for account $AccountName in vault under safe: '$SafeName'"
        $GetAccountsResponse = Invoke-RestMethod -Method Get -Uri $AccountsURLWithFilters -Headers $logonheader -ContentType "application/json" -TimeoutSec 2700 -ErrorVariable pvwaERR
        return $GetAccountsResponse
    }
    Catch
    {
        Write-LogMessage -Type Error -Msg "Error: $(Collect-ExceptionMessage $_.exception.message $($_.ErrorDetails.Message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri) $pvwaERR)"
    }
}


Function Get-AccountPassword{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$AccountID,

        [Parameter(Mandatory=$true)]
        [string]$URLAPI,

        [Parameter(Mandatory=$true)]
        $logonheader
    )

    $URL_Accounts = $URLAPI + "/Accounts"
    $URL_AccountPW = "$URL_Accounts/$AccountID/Password/Retrieve"

    Try
    {
        #Write-LogMessage -Type Info -Msg "Calling: $($URL_AccountPW)"

        $bodyReason = @{ reason = "User ran pcloudtools API script" } | ConvertTo-Json
        Write-LogMessage -type Info -MSG "Retrieving account password"
        $GetAccountPassword = Invoke-RestMethod -Method POST -Uri $URL_AccountPW -Headers $logonheader -ContentType "application/json" -TimeoutSec 2700 -ErrorVariable pvwaERR -Body $bodyReason
        return $GetAccountPassword
    }
    Catch{
        Write-LogMessage -Type Error -Msg "Error: $(Collect-ExceptionMessage $_.exception.message $($_.ErrorDetails.Message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri) $pvwaERR)"
    }
}

function Reset-LocalUserPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    # Check for admin rights
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-LogMessage -type Error -MSG "This script requires administrative privileges. Please run PowerShell as an administrator."
        pause
        exit
    }

    try {
        $Username = $Credential.UserName
        # Check if the user exists
        $userExists = Get-LocalUser | Where-Object { $_.Name -eq $Username }
        if (-not $userExists) {
            Write-LogMessage -type Error -MSG "User '$Username' does not exist."
            return
        }

        $securePassword = $Credential.Password
        Set-LocalUser -Name $Username -Password $securePassword
        Write-LogMessage -type Success -MSG "Password for user '$Username' has been reset successfully."
    }
    catch {
        Write-LogMessage -type Error -MSG "Failed to reset password for user '$Username'. Error: $_"
    }
}

function Test-Credential {
	param(
		[parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[System.Management.Automation.PSCredential]$credential,
		[parameter()][validateset('Domain','Machine')]
		[string]$context = 'Domain'
	)
	begin {
		Add-Type -AssemblyName System.DirectoryServices.AccountManagement
		$DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::$context)
	}
	process {
		$DS.ValidateCredentials($credential.GetNetworkCredential().UserName, $credential.GetNetworkCredential().password)
	}
}
#endregion

#region Functions

Function Invoke-GenerateCredFile
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComponentID,
        [Parameter(Mandatory=$true)]
        [string]$ComponentVersion,
        [Parameter(Mandatory=$true)]
        [string]$ComponentPath,
        [Parameter(Mandatory=$true)]
        [string]$FileName,
        [Parameter(Mandatory=$true)]
        [string]$ComponentUser,
        [Parameter(Mandatory=$true)]
        [securestring]$NewPassword
    )
    try{
        #Generate a new password with Complexity and we use it later for the Vault part
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPassword) #Convert Password to BSTR
        $GetComponentUserDetailsNewPW = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR) #Convert Password to Plaintext
        Write-LogMessage -type Info -MSG "Generating CredFile: '$FileName'"
        #Generate Cred, Check if component is version 12 or lower and select the relevant cred file command
        If($ComponentVersion -gt 12)
        {
            # Set the AppType and ExePath parameters based on the Component ID
            If($ComponentID -eq "CPM")
            {
                # Run the CreateCredFile command
                & "$ComponentPath\Vault\CreateCredFile.exe" "$FileName" Password /username $ComponentUser /Password $GetComponentUserDetailsNewPW /AppType "CPM" /DPAPIMachineProtection /EntropyFile /Hostname /IpAddress
            }
            ElseIf($ComponentID -eq "PSM")
            {
                # Run the CreateCredFile command
                & "$ComponentPath\Vault\CreateCredFile.exe" "$FileName" Password /username $ComponentUser /Password $GetComponentUserDetailsNewPW /AppType "PSMApp" /DPAPIMachineProtection /EntropyFile /ExePath $(Join-Path -Path $ComponentPath -ChildPath "CAPSM.exe") /Hostname /IpAddress
            }
            elseif ($ComponentID -eq "AIM") {
                & "$ComponentPath\Vault\CreateCredFile.exe" "$FileName" Password /username $ComponentUser /Password $GetComponentUserDetailsNewPW /DPAPIMachineProtection /EntropyFile /Hostname /IpAddress
            }
        } Else {
            $appType = $ComponentID
            If($ComponentID -eq "PSM") { $appType = "PSMApp" }
            If ($ComponentID -eq "AIM") { $appType = "AIMProvider" }
            & "$ComponentPath\Vault\CreateCredFile.exe" "$FileName" Password /username $ComponentUser /Password $GetComponentUserDetailsNewPW /AppType $appType
        }
    } catch {
        Throw $(New-Object System.Exception ("Error generating CredFile for file '$FileName'.",$_.Exception))
    }
}



Function ResetCPMUserandAPIkeyNewMethdod(){ # Should only use from CPM 14.2+ since
param(
    [PSCredential]$Credentials,
    [string]$cpmPAth,
    [string]$apiUser
)


    $ComponentConfig = @{
        VaultIniPath = "$($cpmPAth)Vault\Vault.ini"
        Component = "cpm"
        ComponentUsers = @(
            @{
                GenerateCredFile = $true
                CredFilePath = "$($cpmPAth)Vault\user.ini"
                APIGWFilePath = "$($cpmPAth)Vault\apikey.ini"
                DisplayName = "CPM app user"
                CompDefaultUsername = "$apiUser"
            }
        )
        vaultAdminUsername = "$($Credentials.Username)"
    }

    # Generate the JSON input file
    $InputFile = "$CPMnewSyncToolFolder\SyncCompUsersInput.json"
    $jsonContent = $ComponentConfig | ConvertTo-Json -Depth 3

    # Ensure the folder exists and overwrite the file if it exists
    $InputFolder = [System.IO.Path]::GetDirectoryName($InputFile)
    if (-not (Test-Path $InputFolder)) {
        New-Item -Path $InputFolder -ItemType Directory | Out-Null
    }
    Set-Content -Path $InputFile -Value $jsonContent

    Write-LogMessage -type Info -MSG "Input JSON file created/updated at $InputFile"


    function RunProcess {
        param (
            [Parameter(Mandatory=$true)]
            [string]$ProcessFullPath,

            [Parameter(Mandatory=$false)]
            [string[]]$Args

        )
        begin {
            $processName = Split-Path -Leaf $ProcessFullPath
            $processPath = Split-Path -Parent $ProcessFullPath
        }
        process {
            $processArgs = ""
            foreach ($item in $Args) {
                $processArgs += "`"$item`" "
            }

            [System.Environment]::SetEnvironmentVariable("VAULT_PASSWORD", $Credentials.GetNetworkCredential().Password)


            $process = (Start-Process $ProcessName "$processArgs" -WorkingDirectory $processPath -Wait -WindowStyle Hidden -PassThru)
            $processExitCode = $process.ExitCode.ToString()
            [bool]$isSuccess = $false
            if ($process.ExitCode -eq 0) {
                Write-LogMessage -type Success -MSG "Process $processName finished successfully"
            }
            else {
                Write-LogMessage -type Error -MSG "Process $processName failed with exit code $processExitCode"
                Write-LogMessage -type Error -MSG "More info here: $CPMnewSyncToolFolder\Log\SyncCompUsers.log"
            }
        }
    }


    try {

        $args = @($InputFile, "yes")
        $ExecutableFullPath = Resolve-Path $CPMnewSyncToolFolder\SyncCompUsers.exe

        RunProcess -ProcessFullPath $ExecutableFullPath -Args $args
    }
    catch {
        Write-LogMessage -type Error -MSG "Failed to sync component users."
        Write-LogMessage -type Error -MSG "$($_.Exception)"
    }
}

Function Invoke-ResetCredFile
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [PSObject]
        $Component
    )
    try{
        $generatedPassword = New-RandomPassword -Length 39 -Lowercase -Uppercase -Numbers -Symbols | ConvertTo-SecureString -AsPlainText -Force
        $Component.InitPVWAURL()
        # Prompt User and get Token
        Invoke-Logon
        # For cases where there is more than one service to stop
        Foreach($svc in $Component.ServiceName)
        {
            Stop-CYBRService -ServiceName $svc
        }

        # Set all parameters for the Generate Cred File function
        $generateCredFileParameters = @{
            ComponentID = $Component.Name;
            ComponentVersion = $Component.Version;
            ComponentPath = $Component.Path;
            NewPassword = $generatedPassword
        }
        #Run through each existing cred File (For CPM: User.ini, for PSM: psmapp.cred, psmgw.cred) and generate cred using $ComponentUser
        Foreach($credFile in $Component.ComponentUser)
        {
            #Pull the User from the cred file
            $ComponentUser = $(Get-CredFileUser -File $credFile)
            if([string]::IsNullOrEmpty($ComponentUser))
            {
                # In case we did not find the Component User from the credFile - Look in other places
                Write-LogMessage -Type Info -MSG "Could not find Component User from CredFile, trying to look for all offline components"
                # Look for all offline components
                $offlineComponents = $(Get-SystemHealth -ComponentID $Component.Name -OfflineOnly)
                # Compare offline components to the specific component logs
                Foreach($user in $offlineComponents)
                {
                    $foundUser = $(Find-UserInSystemLogs -User $User.ComponentUserName -LogPaths $Component.ServiceLogs)
                    If(! [string]::IsNullOrEmpty($foundUser)){
                        Write-LogMessage -Type Info -MSG "Found a match between an offline component user '$foundUser' and local logs, will use it to generate CredFile."
                        $ComponentUser = $foundUser
                        #If the $CredFile is psmgw.cred then we split the SystemHealth PSM App user into 2 strings and replace "PSMApp_blabla" with "PSMgw_blabla" so we also reset the gw cred.
                            If ($credFile -like "*psmgw.cred*"){
								$ComponentUser = "PSMGw_"+$foundUser.split("_")[1]
                            }
                        Break
                    }
                }
                If($offlineComponents.Count -eq 0 -or $ComponentUser -eq $null)
                {
                    # We couldn't find any component User - ask the user to input the user name
                    Write-LogMessage -Type Info -MSG "Couldn't match offline component user in SystemHealth in local Logs, will have to input manually."
                    $ComponentUser = $(Read-Host "Enter the relevant user name for CredFile: '$credFile'")
                }
            }
            Invoke-GenerateCredFile @generateCredFileParameters -FileName $credFile -ComponentUser $ComponentUser
            # Reset User pw in the vault and activate it
            Get-UserAndResetPassword -ComponentUser $ComponentUser -UserType $Component.UserType -NewPassword $generatedPassword
            #expose variable for apikey reset function.
			if(-not($ComponentUser -like "PSMGw_*"))
			{ # if PSM user is GW skip it from being exposed for apikey use.
				$global:apiKeyUsername = $ComponentUser
				$global:apiKeyPath = $Component.Path
			}

        }
        # For cases where there is more than one service to start
        Foreach($svc in $Component.ServiceName)
        {
            if (-not($svc -eq "CyberArk Central Policy Manager Scanner")){
                Start-CYBRService -ServiceName $svc
            }
        }

        Get-SystemHealth -componentUserDetails $(Get-CredFileUser -File $Component.ComponentUser[0]) -ComponentID $Component.Name
        #Test-SystemLogs -ComponentID $Component.Name -LogPath $Component.serviceLogs[0] | Out-Null
        #Invoke-Logoff
    } catch {
        Throw $(New-Object System.Exception ("Error in the flow of Resetting component $($Component.Name) credentials file.",$_.Exception))
    }
}

Function Get-UserAndResetPassword{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComponentUser,
        [Parameter(Mandatory=$true)]
        [SecureString]$NewPassword,
        [Parameter(Mandatory=$true)]
        [string]$UserType
    )
    try{
        $SearchComponentUserURL = $URL_Users+"?filter=componentUser&search=$ComponentUser&UserType=$UserType"
        $GetUsersResponse = Invoke-RestMethod -Method Get -Uri $SearchComponentUserURL -Headers $pvwaLogonHeader -ContentType "application/json" -TimeoutSec 2700 | Select-Object -ExpandProperty Users | where {$_.username -eq $ComponentUser}
        If($null -ne $GetUsersResponse){
            #Try to reset Password
            Try{
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPassword) #Convert Password to BSTR
                $GetComponentUserDetailsNewPW = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR) #Convert Password to Plaintext
                $BodyResetPW = @{ id = ""+$GetUsersResponse.Users.id+"" ; newPassword = $GetComponentUserDetailsNewPW } | ConvertTo-Json -Compress #Prep Body for API call
                Write-LogMessage -Type Info -Msg "Resetting Password for User: $ComponentUser"
                $SetNewPassword = Invoke-RestMethod -Method POST -Uri ($URL_UserResetPassword -f $GetUsersResponse.id) -Headers $pvwaLogonHeader -ContentType "application/json" -Body $BodyResetPW -TimeoutSec 2700 #Reset Pass
                Write-LogMessage -Type Info -Msg "Activating User: $ComponentUser"
                $ActivateUser = Invoke-RestMethod -Method POST -Uri ($URL_UserActivate -f $GetUsersResponse.id) -Headers $pvwaLogonHeader -ContentType "application/json" -TimeoutSec 2700 #activate user
                Write-LogMessage -Type Success -Msg "Successfully reset Password in the Vault for User: $ComponentUser"
            }
            Catch
            {
                Write-LogMessage -Type Error -Msg "There was an error Restting or Activating user '$ComponentUser'. The error was: $($_.ErrorDetails.Message)"
            }
        }
    } catch {
        Write-LogMessage -Type Error -Msg "There was an error finding user '$ComponentUser'. The error was: $($_.Exception.Response.StatusDescription)"
        Throw $(New-Object System.Exception ("There was an error finding user '$ComponentUser'.",$_.Exception))
    }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Add-CALocalUser
# Description....: Creates a new local user using the username, password and description submitted
# Parameters.....: $userName - The username of user to create
#                  $userPassword - The user password
#                  $userDescription - The user description of user to create
# Return Values..: $true or $false
# =================================================================================================================================
function Add-CALocalUser{
	[CmdletBinding()]
   param(
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]$userName,
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()][System.Security.SecureString]$userPassword,
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]$userDescription
   )
     	Process {
		Try{
            $result = $false
			   Write-LogMessage -Type Info -MSG "Attempting to create new local user $userName"

            $localComputer = [ADSI]"WinNT://$env:COMPUTERNAME"
            $existingUser = $localComputer.Children | where {$_.SchemaClassName -eq 'user' -and $_.Name -eq $userName }

            if ($existingUser -eq $null) {

				$user = $localComputer.Create("User", $userName)

				$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($userPassword)
	            $user.SetPassword([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR))
	            $user.SetInfo()
				[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

	            $user.Put("Description", $userDescription)
	            $user.SetInfo()
               Write-LogMessage -Type Info -MSG "The local user $userName has been successfully created"
            }
            else {
                Write-LogMessage -Type Info -MSG "Local user $userName is already exists."
            }

		}Catch{
            Write-LogMessage -Type "Error" -Msg "Error: $(Join-ExceptionMessage $_.Exception)"
		}
	}
	End{
   }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: New-CANewAccessControlObject
# Description....: Get the relevant access control object for this path.
# Parameters.....: $path - The location path we want to set permissions.
#				   $identity - The identity we want to set the relevant permissions.
#				   $rights - The rights we want to set to the identity on this path.
#							 Please Notice this needs to be string indicate enum name from System.Security.AccessControl.RegistryRights or System.Security.AccessControl.FileSystemRights enums.
# Return Values..: $NUll is couldn't create object, otherwise it return the relevant object.
# =================================================================================================================================
function New-CANewAccessControlObject{
   [CmdletBinding()]
   param(
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]$path,
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]$identity,
   [ValidateNotNullOrEmpty()]$rights
   )
	Process {
		$returnVal = $NULL
		try {
			$item = Get-Item -Path $path

			If ($item -is [System.IO.DirectoryInfo]) {
				$returnVal = New-Object System.Security.AccessControl.FileSystemAccessRule ($identity,$rights,"ContainerInherit,ObjectInherit","None","Allow")
			} ElseIf ($item -is [Microsoft.Win32.RegistryKey]) {
				$returnVal = New-Object System.Security.AccessControl.RegistryAccessRule ($identity,$rights,"ContainerInherit,ObjectInherit","None","Allow")
			} ElseIf ($item -is [System.IO.FileInfo]){
				$returnVal = New-Object System.Security.AccessControl.FileSystemAccessRule ($identity,$rights,"Allow")
			}
		} Catch {
			Write-LogMessage -Type "Error" -Msg "Error: $(Join-ExceptionMessage $_.Exception)"
		}
		return $returnVal
	}
	End{
   }
}


function Set-CAPermissions{
   [CmdletBinding()]
   param(
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]$path,
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]$identity,
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]$rights,
   [ValidateNotNullOrEmpty()]
   [bool]$removePreviousPermisions = $false

   )
	Process {
		$returnVal = $false
		try {
			$acl =( Get-Item $path).GetAccessControl('Access')

			$aclPermision = New-CANewAccessControlObject -path $path -identity $identity -rights $rights
			$acl.AddAccessRule($aclPermision)

			$acl = Set-Acl -Path $path -AclObject $acl -Passthru
		} Catch {
			Write-LogMessage -Type "Error" -Msg "Failed to set new permissions: '$rights' on path: '$path' to user\group: '$identity' Error: $(Join-ExceptionMessage $_.Exception)"
		}
	}
	End{
   }
}

function SetAclPermissions($username, $path, $permissions, $allowOrDeny){

	$aclFromPath = Get-Acl $path

	$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($username,$permissions,"ContainerInherit, ObjectInherit","None",$allowOrDeny)

	 $aclFromPath.SetAccessRule($AccessRule)

	 Set-Acl -Path $path -AclObject $aclFromPath
}


function Add-CAUserRight {
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $userName,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $userRight
    )
    Process {
        try {
            $ntprincipal = new-object System.Security.Principal.NTAccount "$userName"
            $userSid = $ntprincipal.Translate([System.Security.Principal.SecurityIdentifier])
            $userSidstr = $userSid.Value.ToString()

            if ([string]::IsNullOrEmpty($userSidstr)) {
                Write-LogMessage -Type "Error" -Msg "User $userName not found!"
            }

            $tempPath = [System.IO.Path]::GetTempPath()
            $exportPath = Join-Path -Path $tempPath -ChildPath "export.inf"
            secedit.exe /export /cfg "$exportPath" >$null 2>&1

            $currentRightKeyValue = (Select-String $exportPath -Pattern "$userRight").Line
            $splitedKeyValue = $currentRightKeyValue.split("=", [System.StringSplitOptions]::RemoveEmptyEntries)
            $currentSidsValue = $splitedKeyValue[1].Trim()

            if ($currentSidsValue -notlike "*$userSidstr*") {
                $newSidsValue = if ([string]::IsNullOrEmpty($currentSidsValue)) { "*$userSidstr" } else { "*$userSidstr,$currentSidsValue" }

                $importPath = Join-Path -Path $tempPath -ChildPath "import.inf"
                $importFileContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
$userRight = $newSidsValue
"@
                Set-Content -Path $importPath -Value $importFileContent -Encoding Unicode -Force
                secedit.exe /configure /db secedit.sdb /cfg "$importPath" /areas USER_RIGHTS >$null 2>&1
            }

            Remove-Item -Path $importPath -Force
            Remove-Item -Path $exportPath -Force
        } catch {
            Write-LogMessage -Type "Error" -Msg "Failed to add $userRight user right for user $userName. Error: $_"
        }
    }
}

Function CheckIfNewDiscoveryEnabled(){
    Try{
        Write-LogMessage "Retrieving tenant details"
        $GetTenantSettingsInvoke = Invoke-RestMethod -Uri "$URL_PVWAAPI/settings/features" -Method Get -ContentType "application/json" -TimeoutSec 10 -Headers $pvwaLogonHeader -ErrorVariable pvwaERR
    }Catch{
        Write-LogMessage -Type Error -Msg "Error: $(Collect-ExceptionMessage $_.exception.message $($_.ErrorDetails.Message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri) $pvwaERR)"
    }
    Return $GetTenantSettingsInvoke.DisabledClassicDiscovery
}

Function Invoke-ResetAPIKey
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$pathApikey,
        [Parameter(Mandatory=$true)]
        [string]$apiUser,
        [Parameter(Mandatory=$true)]
        [string]$AdminUser,
		[Parameter(Mandatory = $False)]
		[ValidateSet("CPM","PSM")]
		[string]$ComponentType
    )

if($ComponentType -eq "CPM"){
	$apikeyFileName = "apikey.ini"
}Else{
	$apikeyFileName = "apigw.cred"
}

Add-Type -AssemblyName System.Windows.Forms
$wshell = New-Object -ComObject wscript.shell
$ApiLogs = "$pathApiKey`Vault\Logs\ApiKeyManager.log"

#Purge logs before execution
Remove-Item $ApiLogs -Force -ErrorAction SilentlyContinue

Write-LogMessage -type Info -MSG "Resetting ApiKey, this can take a few secs..."
Write-LogMessage -type Info -MSG "Testing if SendWait function will work..."
$dummyString = "Test"
$teststring = $null
$specialchars = '!@#$%^&*()'',./\`~[]":?<>+|'.ToCharArray()
[string]$simplePw = ($Credentials.GetNetworkCredential().password)

#Escape curly brackets from SendWait command
if($simplePw -match "{"){$simplePw = $simplePw.Replace("{","_LEFT_")}
if($simplePw -match "}"){$simplePw = $simplePw.Replace("}","_RIGHT_")}
$simplePw = $simplePw.Replace('_LEFT_',"{{}").Replace('_RIGHT_',"{}}")

#Escape special chars that have other meaning in SendKeys class.
foreach($char in $specialchars){
    if($simplePw -match "\$char")
    {
        $simplepw = $simplePw.Replace("$char","{$char}")
    }
}

#we need to test this command since some endpoint agents are blocking it, if its blocked, user will have to enter admin pw manually.
[System.Windows.Forms.SendKeys]::SendWait($dummyString);
[System.Windows.Forms.SendKeys]::SendWait('{ENTER}');
$wshell.AppActivate('Privilege Cloud CreateCredFile-Helper') | Out-Null
$teststring = Read-Host -Prompt "Testing SendWait command: "
#if test string contains value, SendWait works
if($teststring){
    $wshell.AppActivate('Privilege Cloud CreateCredFile-Helper') | Out-Null
    [System.Windows.Forms.SendKeys]::SendWait($simplePw)
    [System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
    & "$pathApikey\Vault\ApiKeyManager.exe" revoke -t $apiUser -u $AdminUser -a "$URL_PVWAAPI/"
    Start-Sleep 1
    $wshell.AppActivate('Privilege Cloud CreateCredFile-Helper') | Out-Null
    [System.Windows.Forms.SendKeys]::SendWait($simplePw)
    [System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
    & "$pathApikey\Vault\ApiKeyManager.exe" add -f "$pathApikey`Vault\$apikeyFileName" -t $apiUser -u $AdminUser -a "$URL_PVWAAPI/"
}
Else{
Write-LogMessage -type Warning -Msg "Error Powershell's SendWait command doesn't work, probably because you have Endpoint agent blocking this action."
Write-LogMessage -type Warning -Msg "You will have to input your administrative account manually (the same account pw you input at the start of the script)."
& "$pathApikey\Vault\ApiKeyManager.exe" revoke -t $apiUser -u $AdminUser -a "$URL_PVWAAPI/"
& "$pathApikey\Vault\ApiKeyManager.exe" add -f "$pathApikey`Vault\$apikeyFileName" -t $apiUser -u $AdminUser -a "$URL_PVWAAPI/"
}

if(gc $ApiLogs | Select-String "ERROR"){
Write-LogMessage -type Warning -MSG "Couldn't reset API key, check for errors in logfile: $ApiLogs"
}

$simplePw = $null
}

# -----------------------------------
# Script Begins Here
Write-LogMessage -type Info -MSG "Starting Create CredFile helper script" -Header
# Check latest version
$gitHubLatestVersionParameters = @{
    currentVersion = $ScriptVersion;
    repositoryName = "pCloudServices/CreateCredHelper";
    scriptVersionFileName = "CreateCredFile-Helper.ps1";
    sourceFolderPath = $PSScriptRoot;

    # More parameters that can be used
    # repositoryFolderPath = "FolderName";
    # branch = "main";
    # versionPattern = "ScriptVersion";
}

If(! $SkipVersionCheck)
{
	try{
        Write-LogMessage -type Info -Msg "Current script version $ScriptVersion"
        $isLatestVersion = $(Test-GitHubLatestVersion @gitHubLatestVersionParameters)
		If($isLatestVersion -eq $false)
		{
            # Skip the version check so we don't get into a loop
			$scriptPathAndArgs = "`& `"$PSScriptRoot\CreateCredFile-Helper.ps1`" -SkipVersionCheck"
			Write-LogMessage -type Info -Msg "Finished Updating, relaunching the script"
			# Run the updated script
			Invoke-Expression $scriptPathAndArgs
			# Exit the current script
			return
		}
	} catch {
		Write-LogMessage -type Error -Msg "Error checking for latest version. Error: $(Join-ExceptionMessage $_.Exception)"
	}
}

If ($(Test-CurrentUserLocalAdmin) -eq $False)
{
	Write-LogMessage -Type Error -Msg "You must be logged on as a local administrator in order to run this script"
    pause
	return
}

try{

    # skip TLS checks
    if(-not($skipTLS)){enforceTLS}
    # ignore cert issues
    if(-not($SkipCertVerification)){IgnoreCert}

    #Create A Dynamic Menu based on the services found
    $detectedComponents = $(Find-Components)
    If(($null -ne $detectedComponents) -and ($detectedComponents.Name.Count -gt 0))
    {
        # Show the menu
        $answer = Show-Menu -Items $detectedComponents.DisplayName
        # Check the user chosen answer
        If ($answer -eq "Q")
        {
            Write-Host "Exiting..." -ForegroundColor Gray
            break
        }
                Else
        {
            $answer = [int]$answer #if answer is not a letter (Q) convert to int so we can use the below command
            $typeChosen = $detectedComponents[$answer-1]
            Invoke-ResetCredFile -Component $typeChosen
            switch ($typeChosen.Name)
            {
                "CPM"
                {
                    $PluginManagerUser = "PluginManagerUser"
                    $cpmPath = $typeChosen.Path
                    Write-LogMessage -type Info -MSG "Syncing $PluginManagerUser"
                    if ($typeChosen.Version -ge [version]"13.1")
                    {
                        # Sync PluginManagerUser
                        # Get account details
                        $GetAccountResponse = Get-Account -AccountName "$PluginManagerUser" -URLAPI $URL_PVWAAPI -logonheader $pvwaLogonHeader -SafeName "$($apiKeyUsername)_Accounts" -limitPage 0
                        if($GetAccountResponse)
                        {
                            # Get account password using acc details
                            $GetAccPassword = Get-AccountPassword -AccountID $($GetAccountResponse.value.id) -URLAPI $URL_PVWAAPI -logonheader $pvwaLogonHeader
                            # If we get pw, perform an action to verify the windows user pw is correct
                            if($GetAccPassword){
                                $securePassword = ConvertTo-SecureString $GetAccPassword -AsPlainText -Force
                                Write-LogMessage -type Info -MSG "Successfully retrieved password, proceeding syncing locally."
                                # if local user doesn't exist, let's create it so we can reset pw.
                                if(-not(Get-LocalUser $PluginManagerUser -ErrorAction SilentlyContinue)){
                                    Write-LogMessage -type Warning -MSG "User '$PluginManagerUser does not exist, let's try to create it."

                                    Add-CALocalUser -userName $PluginManagerUser -userPassword $securePassword -userDescription "CyberArk Plugin Manager User used by CyberArk Password Manager service"
                                    # Retrieve PasswordManagerUser SID
                                    $ntprincipal = new-object System.Security.Principal.NTAccount "$PluginManagerUser"
                                    $userSid = $ntprincipal.Translate([System.Security.Principal.SecurityIdentifier])
                                    $userSidstr = $userSid.Value.ToString()
                                    # Retrieve PasswordManagerUser registry path
                                    [string]$DnsHost = $env:COMPUTERNAME.Trim()
                                    $userREGPaths = @("registry::HKEY_USERS\$userSidstr\Software","registry::HKEY_USERS\$userSidstr")
                                    # Grant regsitry permissions
                                    Write-LogMessage -type Info -MSG "Granting registry permissions."
                                    foreach ($userREGPath in $userREGPaths){
                                        Set-CAPermissions $userREGPath "$DnsHost\$PluginManagerUser" "FullControl"
                                    }
                                    Write-LogMessage -type Info -MSG "Granting folder permissions."
                                    SetAclPermissions $PluginManagerUser ($env:USERPROFILE + "\..\" + "$PluginManagerUser") "FullControl" "Allow"
                                    SetAclPermissions $PluginManagerUser ($cpmPath) "ReadAndExecute" "Allow"
                                    SetAclPermissions $PluginManagerUser ($cpmPath + "\" + "Scanner") "ReadAndExecute" "Deny"
                                    SetAclPermissions $PluginManagerUser ($cpmPath + "\" + "Logs") "Modify" "Allow"
                                    SetAclPermissions $PluginManagerUser ($cpmPath + "\" + "tmp") "FullControl" "Allow"
                                    SetAclPermissions $PluginManagerUser ($cpmPath + "\" + "bin") "ReadAndExecute" "Allow"
                                    Write-LogMessage -type Info -MSG "Adding User to 'Allow log on locally' policy."
                                    Add-CAUserRight $PluginManagerUser "SeInteractiveLogonRight"
                                }


                                # Check password is in sync by running generic powershell command
                                $success = $false
                                $LocalUserCreds = New-Object System.Management.Automation.PSCredential ($PluginManagerUser, $securePassword)
                                Write-LogMessage -type Info -MSG "Running test command using password from the vault with windows user '$PluginManagerUser'"
                                # Run generic command in AD
                                $validationResult = Test-Credential -credential $LocalUserCreds -context 'Machine'
                                if ($validationResult){
                                    Write-LogMessage -type Success -MSG "Account: $PluginManagerUser is synced!"
                                }Else{
                                    Write-LogMessage -type Warning -MSG "Account: $PluginManagerUser is out of sync!"
                                    $SyncAccountDecission = Get-Choice -Title "Would you like the script to attempt to sync the accounts?" -Options "Yes (Recommended)", "No" -DefaultChoice 1
                                    if ($SyncAccountDecission -eq "No") {
                                        Write-LogMessage -Type info -MSG "Selected not to sync user $PluginManagerUser ."
                                    }Else{
                                        # Sync local user with password from vault
                                        Reset-LocalUserPassword -Credential $LocalUserCreds
                                    }
                                }
                            }
                            Else
                            {
                                Write-LogMessage -type Error -MSG "Was unable to retrieve account password: '$($PluginManagerUser)' You will have to do this manually."
                            }
                        }
                        Else
                        {
                            Write-LogMessage -type Error -MSG "Was unable to retrieve account: '$($PluginManagerUser)' You will have to do this manually."
                        }
                    }Else{
                        Write-LogMessage -type Warning -MSG "Old CPM version detected, can't perform $PluginManagerUser Sync action, do it manually by contacting CyberArk Support if the user is out of sync."
                    }
                        # Skip CPM Scanner service if new discovery is enabled, False means we need to use old scanner and reset apikey.
                        $discoverySetting = CheckIfNewDiscoveryEnabled
                        if ($discoverySetting -eq $false -or $discoverySetting -eq $null){
                            # Reset APIKey
                            $decisionAPIKey = Get-Choice -Title "(Optional) Would you like to also reset CPM Scanner APIKey?" -Options "Yes", "No" -DefaultChoice 1
                            if ($decisionAPIKey -eq "No") {
                                Write-LogMessage -Type info -MSG "Selected not to run CPM Scanner APIKey reset."
                                # Scanner service
                                Start-CYBRService -ServiceName $typeChosen.ServiceName[1]
                            } else {
                                # in 14.2 CPM deprecated apikeymanger tool and we need to use the new tool
                                if($typeChosen.Version -ge [version]"14.2"){
                                    #check app exists
                                    if(Test-Path $CPMnewSyncToolFolder){
                                        ResetCPMUserandAPIkeyNewMethdod -cpmPath $cpmPath -credential $Credentials -apiUser $apiKeyUsername
                                    }Else{
                                        Write-LogMessage -type Error -MSG "Couldn't find folder $syncCompAPpPath make sure you download the latest zip from marketplace."
                                        Write-LogMessage -type Error -MSG "Skipping API Key reset..."
                                    }
                                }
                                Else
                                {
                                    Invoke-ResetAPIKey -pathApikey $apiKeyPath -apiUser $apiKeyUsername -AdminUser $Credentials.UserName -ComponentType CPM
                                }
                                # finally Scanner service
                                Start-CYBRService -ServiceName $typeChosen.ServiceName[1]
                                $Credentials = $null
                            }
                        }Else{
                            Write-LogMessage -type Success -MSG "Skipping $($typeChosen.ServiceName[1]) since New Discovery service is enabled on tenant."
                        }
                }
				"PSM"
				{
						$decisionAPIKey = Get-Choice -Title "(Optional )Would you like to also reset PSM APIKey?" -Options "Yes", "No" -DefaultChoice 2
                        if ($decisionAPIKey -eq "No") {
                            Write-LogMessage -Type info -MSG "Selected not to run PSM Scanner APIKey reset."
                        } else {
							Stop-CYBRService -ServiceName $typeChosen.ServiceName
                            Invoke-ResetAPIKey -pathApikey $apiKeyPath -apiUser $apiKeyUsername -AdminUser $Credentials.UserName -ComponentType PSM
                            Start-CYBRService -ServiceName $typeChosen.ServiceName
                            $Credentials = $null
                        }
				}
            }
			# TODO maybe add logs check here instead?
			Test-SystemLogs -ComponentID $typeChosen.Name -LogPath $typeChosen.serviceLogs[0] | Out-Null
        }
    }
    else {
        Write-LogMessage -Type Warning -MSG "There were no CyberArk components found on this machine"
    }
} catch {
    Write-LogMessage -type Error -Msg "There was an error running the script. Error $(Join-ExceptionMessage $_.Exception)"
}
Finally{
    Try{Invoke-Logoff}Catch{}
    $Credentials = $null
}
# Script ended
Write-LogMessage -type Info -MSG "Create CredFile helper script ended" -Footer
return
###########
