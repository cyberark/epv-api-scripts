######################################################################
#                                                                    #
#                                                                    #
#   CyberArk Privilege Cloud CreateCredFile-Helper		     #
#                                                                    #
#   This tool is designed to help customers       		     #
#   reset their component credfiles.                		     #
#                                                                    #
#                                                   		     #
######################################################################

This script will reset component cred file both locally and sync it in the Vault via API.

1. Before running the script, prepare your Privilege Cloud Admin account (typically <subdomain>_admin or "InstallationUser@..cyberark.cloud" if you are on ISPSS platform).
2. Copy the script to the machine of the component (CPM/PSM/CP).
3. Run the script in PowerShell Administrator mode.
4. You can use extra flags if you want to skip version or auth with an LDAP account ( -SkipVersionCheck -skipTLS), example:
./CreateCredFile-Helper.ps1 -SkipVersionCheck

For troubleshooting:
--------------------
Use the below commands to manually generate the cred files in case the script fails (from CMD or ps window):

CPM:
CreateCredFile.exe "<PathToCredFile>" Password /username <ComponentUserName> /Password <NewPassword> /AppType "CPM" /DPAPIMachineProtection /EntropyFile /Hostname /IpAddress

PSM:
CreateCredFile.exe "<PathToCredFile>" Password /username <ComponentUserName> /Password <Password> /AppType "PSMApp" /DPAPIMachineProtection /EntropyFile /ExePath "<PathTo"CAPSM.exe"File>" /Hostname /IpAddress

AIM/CP:
CreateCredFile.exe "<PathToCredFile>" Password /username <ComponentUserName> /Password <NewPassword> /DPAPIMachineProtection /EntropyFile /Hostname /IpAddress

Example:
CreateCredFile.exe "C:\Program Files (x86)\CyberArk\PSM\Vault\psmapp.cred" Password /username PSMApp_351d715 /Password MyNewTempPassword123 /AppType "PSMApp" /DPAPIMachineProtection /EntropyFile /ExePath "C:\Program Files (x86)\CyberArk\PSM\CAPSM.exe" /Hostname /IpAddress

(Afterwards you will need to reach out to CyberArk so we can set the same password on our end).
