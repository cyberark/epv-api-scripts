<# 
###########################################################################

NAME: 
    Add-CCPSites.ps1 

AUTHOR:  
    Brian Bors  <brian.bors@cyberark.com>

COMMENT: 
    Script used to create additional independent authentication types for CCP Use

Version: 
    0.1

Change Log:
    2021-06-01
        Initial Version    

########################################################################### 
#>

[CmdletBinding()]
param(

    [Parameter(Mandatory=$false,HelpMessage="Folder path to AIMWebService")]
    [String]$location="C:\inetpub\wwwroot\AIMWebService"
)

#Create new URL using REST for Remote Machine Authentication
#https://<your machine>/Rest/api/Accounts?AppID=<AppID>&Object=<Object Name>
New-WebApplication -force -Name "Rest" -Site "Default Web Site" -PhysicalPath $location -ApplicationPool "DefaultAppPool"

#Create new URL using REST with Certificate Authentication
#https://<your machine>/RestCert/api/Accounts?AppID=<AppID>&Object=<Object Name>
New-WebApplication -force -Name "RestCert" -Site "Default Web Site" -PhysicalPath $location -ApplicationPool "DefaultAppPool"
Set-WebConfiguration -force -Location "Default Web Site/RestCert" -Filter 'system.webserver/security/access' -Value "Ssl,SslRequireCert"

#Create new URL using REST with Windows OS Authentication
#https://<your machine>/RestWin/api/Accounts?AppID=<AppID>&Object=<Object Name>
New-WebApplication -force -Name "RestWin" -Site "Default Web Site" -PhysicalPath $location -ApplicationPool "DefaultAppPool"
Set-WebConfigurationProperty -force -PSPath "IIS:\" -Location "Default Web Site/RestWin" -filter "/system.webServer/security/authentication/anonymousAuthentication" -name enabled -value false
Set-WebConfigurationProperty -force -PSPath "IIS:\" -Location "Default Web Site/RestWin" -filter "/system.webServer/security/authentication/windowsAuthentication" -name enabled -value true

#Create new URL using REST with Certificate Authentication and Windows OS Authentication
#https://<your machine>/RestCertWin/api/Accounts?AppID=<AppID>&Object=<Object Name>
New-WebApplication -force -Name "RestCertWin" -Site "Default Web Site" -PhysicalPath $location -ApplicationPool "DefaultAppPool"
Set-WebConfiguration -force -Location "Default Web Site/RestCertWin" -Filter 'system.webserver/security/access' -Value "Ssl,SslRequireCert"
Set-WebConfigurationProperty -force -PSPath "IIS:\" -Location "Default Web Site/RestCertWin" -filter "/system.webServer/security/authentication/anonymousAuthentication" -name enabled -value false
Set-WebConfigurationProperty -force -PSPath "IIS:\" -Location "Default Web Site/RestCertWin" -filter "/system.webServer/security/authentication/windowsAuthentication" -name enabled -value true
