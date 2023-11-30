# Accounts Risk Reports

## Main capabilities
This tool:
- Allows easy reporting of Account Risk gathered from the PTA Security Events.
- Needs PTA installed and a user credential that has access to the Security Events module.
- Outputs the report on screen or to a .csv file.
- Uses REST API and can support v10.4 of PVWA and up.

## Usage
```powershell
Get-AccoutnsRiskReport.ps1 [-PVWAURL] <string> [[-AuthType] <string>] [[-EventsDaysFilter] <int>] [[-CSVPath] <string>] [-DisableSSLVerify] [<CommonParameters>]
```

## Output Examples

### Report to the screen
```powershell
.\Get-AccoutnsRiskReport.ps1 -PVWAURL "https://mypvwaserver.mydomain.com/PasswordVault"
```

|UserName      | Address               | SafeName          | Risk | NumEvents | Create                | Change
|--------      | -------               | --------          | ---- | --------- | ------                | ------
|admin-hila    | rhel7-2.pta.com       | MySafe          | 80.0         | 1 | 4/28/2018 11:49:14 PM |
|dcadmin       | il.enigma.com         | DifferentSafe           | 90.0         | 3 | 5/24/2018 4:02:24 AM |
|john2_shadow  | server1.pta.com       | remidiateSafe         | 80.0         | 1 | 7/1/2019 12:00:43 AM |
|admin3_shadow | server1.pta.com       | remidiateSafe         | 80.0         | 1 | 6/30/2019 10:58:40 PM |
|admin2_shadow | server1.pta.com       | remidiateSafe         | 80.0         | 1 | 6/30/2019 10:42:08 PM |
|rec_acct      | pta.com               | remidiateSafe         | 80.0         | 1 | 6/30/2019 12:48:59 PM |
|john_admin    | pta.com               | remidiateSafe         | 80.0         | 1 | 7/5/2019 4:39:15 AM | 7/05/2019 13:12:44 PM
|john_backdoor | server1.pta.com       | remidiateSafe         | 80.0         | 1 | 6/30/2019 12:32:34 PM | 7/05/2019 1:12:44 AM
|admin-tom     | rhel7-2.pta.com       | remidiateSafe       | 90.0        | 30 | 6/25/2019 4:41:23 PM |
|caadmin1      | win10-client3.pta.com | Client Accounts  | 70.0         | 2 | 1/11/2017 8:05:57 AM |
|bind_pta      |                      | AWS              | 85.0         | 5 | 3/18/2019 4:38:21 AM |  
|administrator | 172.31.24.236         | Client Accounts  | 89.0         | 9 | 11/5/2017 5:52:36 AM |

### Report to a .csv file
```powershell
.\Get-AccoutnsRiskReport.ps1 -PVWAURL "https://mypvwaserver.mydomain.com/PasswordVault" -path .\output.csv
```

|UserName|Address|SafeName|Platform|Risk|NumberOfEvents|AccountCreateDate|LastAccountChangeDate
|--------|-------|--------|--------|----|--------------|-----------------|---------------------
|admin-hila|rhel7-2.pta.com|MySafe|Unix via SSH|80.0|1|4/28/2018 11:49:14 PM|
|dcadmin|il.enigma.com|DifferentSafe|Windows Domain Account|90.0|3|5/24/2018 4:02:24 AM|
|john2_shadow|server1.pta.com|remidiateSafe|Windows Desktop Local Accounts|80.0|1|7/1/2019 12:00:43 AM|
|admin3_shadow|server1.pta.com|remidiateSafe|Windows Desktop Local Accounts|80.0|1|6/30/2019 10:58:40 PM|
|admin2_shadow|server1.pta.com|remidiateSafe|Windows Desktop Local Accounts|80.0|1|6/30/2019 10:42:08 PM|
|rec_acct|pta.com|remidiateSafe|WinDomain_Reconcile|80.0|1|6/30/2019 12:48:59 PM|
|john_admin|pta.com|remidiateSafe|WinDomain_Reconcile|80.0|1|7/5/2019 4:39:15 AM|7/05/2019 13:12:44 PM|
|john_backdoor|server1.pta.com|remidiateSafe|Windows Desktop Local Accounts|80.0|1|6/30/2019 12:32:34 PM| |7/05/2019 1:12:44 AM
|admin-tom|rhel7-2.pta.com|remidiateSafe|Unix via SSH|90.0|30|6/25/2019 4:41:23 PM|
|caadmin1|win10-client3.pta.com|Client Accounts|Windows Desktop Local Accounts|70.0|2|1/11/2017 8:05:57 AM|
|bind_pta|,|AWS|Amazon Web Services - AWS - Access Keys|85.0|5|3/18/2019 4:38:21 AM|
|administrator|172.31.24.236|Client Accounts|Windows Desktop Local Accounts|89.0|9|11/5/2017 5:52:36 AM|
