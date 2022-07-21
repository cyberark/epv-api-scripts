> **General**
> - The goal for this scripts is to allow easy installation of the PSM Health Check Service
> - To use download the latest version of the PSM Health Check from the CyberArk Market place
> - Extract the zip file and place the script in that folder and run using the commands below
## Parameters:
```powershell
Install-PSMHealthCheck.ps1  [-Location <string>] [-download] [-stage] [-hostingFile <string>] [-DisableSSLVerify] [<CommonParameters>]

```
- Location <string>
	- The path to where the PSM is installed
    - Default: "C:\Program Files (x86)\CyberArk\PSM"
- Download
    - If this switch is passed the required file(s) are downloaded from the internet otherwise local version will be used
- Stage
    - If this switch is passed the required file(s) are downloaded from the internet, but does not run the installation
    - Used in cases when the PSM does not have internet access and you wish to copy the files to the PSM. Normally this would run from a workstation
- CreateSelfSignedCert
    - If this switch is passed a self signed certificate will be created
- hostingFile <String>
    - File name for the "Microsoft .NET Core Windows Server Hosting" executable. This will be the named used to save the file to with -download or -stage
    - Uses the "Hosting Bundle" direct download link from "https://dotnet.microsoft.com/en-us/download/dotnet/3.1"
- DisableSSLVerify
	**(NOT RECOMMENDED)**
	- In case you experience issues making SSL connections during download(s)