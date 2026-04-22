######################################################################
#                                                                    #
#                                                                    #
#   CyberArk Privilege Cloud CreateCredFile-Helper		     #
#   Author:     mike.brook@cyberark.com                              #
#   This tool is designed to help customers       		     #
#   reset their component credfiles.                		     #
#                                                                    #
#                                                   		     #
######################################################################

This script will reset component cred file both locally and sync it in the Vault via API.

Works for:
PSMP
AIM/CP

1. Before running the script, prepare your Privilege Cloud Admin account (typically <subdomain>_admin or "InstallationUser@..cyberark.cloud" if you are on ISPSS platform).
2. Copy the script to the machine of the component (PSMP/AIM/CP).
3. give permissions to the script -> chmod 755 createCredFile-Helper.sh
4. You can use extra flags if you want to skip version check:
5. Run the script:

Example Run commands:
# This will skip version check from github
./createCredFile-Helper.sh -skip

# This will execute script normally
./createCredFile-Helper.sh

For troubleshooting:
--------------------
Use the below commands to manually generate the cred files in case the script fails:

First find the users you want to reset within:
/etc/opt/CARKpsmp/vault

PSMP - psmpappuser.cred, psmpgwuser.cred (must reset both)
CP - appprovideruser.cred

Then proceed running the reset command
PSMP/CP:
./CreateCredFile appprovideruser.cred Password -Username <username> -Password <userPassword> -Hostname -EntropyFile

Since you set this manually instead of using the script, you will need to reach out to CyberArk support so we can set the same password on our end.