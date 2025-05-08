# PSM Health Check Service Installation

## General
- The goal is to allow easy installation of the PSM Health Check Service.
- To use this script, download the latest version of the PSM Health Check from the CyberArk Marketplace
	- https://cyberark-customers.force.com/mplace/s/#a352J000000ai0MQAQ-a392J000002QBA6QAO
- Extract the .zip file and put the script in that folder and run using the commands shown below.

## Parameters:
```powershell
Install-PSMHealthCheck.ps1  [-Location <String>] [-download] [-stage] [-CreateSelfSignedCert] [-hostingFile <String>] [-DisableSSLVerify] [-AllowHTTP] [<CommonParameters>]

```
- Location <``String``>
	- The path to where the PSM is installed
    - Default: "C:\Program Files (x86)\CyberArk\PSM"
- Download
    - The required files are downloaded and installed from the internet.
    - Default: the script will use the local version of the files.
- Stage
    - The required files are downloaded from the internet, but not installed.
    - Used in cases when the PSM does not have internet access and you wish to copy the files to the PSM.
    - Normally this would run from a workstation.
- CreateSelfSignedCert
    - Create a self signed certificate.
- hostingFile <``String``>
    - If using the `-download` or `-stage` switches: provides the name used to save the downloaded "ASP.NET Core Runtime Windows Server Hosting" executable file.
    - Uses the "Hosting Bundle" direct download link from "https://dotnet.microsoft.com/download/dotnet/8.0"
- DisableSSLVerify
	**(NOT RECOMMENDED)**
	- In case you experience issues making SSL connections during download(s).
- AllowHTTP
	**(NOT RECOMMENDED)**
	- Uncheck "Require SSL" on "Default Web Site/PSM" to allow for connecting with non-SSL connections.

## Example:
Download "ASP.NET Core Runtime Windows Server Hosting" for use later. Must be done from a computer with internet access
```powershell
Install-PSMHealthCheck.ps1  -stage [<CommonParameters>]
```

Install PSM Health Check using defaults
```powershell
Install-PSMHealthCheck.ps1  [<CommonParameters>]
```
Install PSM Health Check using alternate location
```powershell
Install-PSMHealthCheck.ps1  -Location "D:\Program Files (x86)\CyberArk\PSM" [<CommonParameters>]
```
Download ASP.NET Core and then install PSM Health Check
```powershell
Install-PSMHealthCheck.ps1  -Download [<CommonParameters>]
```
Install ASP.NET Core by specifying installer and then install PSM Health Check
```powershell
Install-PSMHealthCheck.ps1 -hostingFile "C:\CAInstalls\dotnet-hosting-8.0.15-win.exe" [<CommonParameters>]
```
