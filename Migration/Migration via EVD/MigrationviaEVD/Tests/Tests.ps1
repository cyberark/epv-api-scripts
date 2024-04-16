$ThisOutputVerbose = $true
$ThisOutputDebug = $true
[pasobject]::AddOnUpdate = $true
[pasobject]::UpdateOnAdd = $true

(New-Object -TypeName PASMigrate).ConfigurePAS("https://pvwa.lab.local/passwordvault")
(New-Object -TypeName PASMigrate).Logon([pscredential]::new('administrator', ('Cyberark1!' | ConvertTo-SecureString -AsPlainText -Force)), "CyberARk")
"CyberArk Auth Header: $((New-Object -TypeName PASMigrate).AuthHeader|ConvertTo-Json)"


(New-Object -TypeName PASObject).ConfigureOAuth2( "https://aal4797.my.idaptive.app", "https://servicesum.privilegecloud.cyberark.cloud/passwordvault")
(New-Object -TypeName PASObject).Logon([pscredential]::new('bborsoauth@cyberark.cloud.1024', ('Cyberark1!Cyberark1!' | ConvertTo-SecureString -AsPlainText -Force)), "OAuth2")
"CyberArk OAuth2 Header: $((New-Object -TypeName PASObject).AuthHeader|ConvertTo-Json)"
""
Write-Host -ForegroundColor Cyan "Safe-Get" 
""
"CyberArk Auth Header: $((New-Object -TypeName PASMigrate).AuthHeader|ConvertTo-Json)"
$PASObject = (New-Object -TypeName PASObject)
$PASMigrate = (New-Object -TypeName PASMigrate)
[TranslateMember]::AddLDAPMap("lab.local", "lab.localSuf", "")
[TranslateMember]::LDAPDirectoryMap 


$SafeGet = New-Object Safe
$SafeGet.Get("babtest") | Out-Null

$safeGet.ToJson() 
$SafeGet.ToJson($true)
$SafeGet.GetMembers() | Out-Null
$SafeGet.members[0]
$SafeGet.GetMember("henry.cheung@cyberark.cloud.1024")
$SAfeGet.members[4].permissions.accessWithoutConfirmation = $true | Out-Null
$SAfeGet.members[4].Update() | Out-Null
$testNewMemberImport = Import-Csv -Path C:\temp\combind.csv 
$testNewMemberMember = New-Object SafeMember
$testNewMemberMember.Load($testNewMemberImport) | Out-Null
$testNewMemberMember.permissions 
$testNewMemberMember.SetFull() | Out-Null
$testNewMemberMember.Update() | Out-Null
$testNewMemberMember.Delete()  | Out-Null
$testNewMemberMember.Update() | Out-Null
$testNewMemberMember.SetUse() | Out-Null
$testNewMemberMember.Delete() | Out-Null
$testNewMemberMember.Add() | Out-Null
$testNewMemberMember.Add() | Out-Null 


$safeTest = $safeGet
$safeTest.SafeName = "BABTestRest"
$safeTest.safeUrlId = "BABTestRest"
$safeTest.Add() | Out-Null
$safeTest.Add() | Out-Null
$safeTest.description = "Test safe for bbors 2"
$safeTest.Update() | Out-Null
$safeTest.Get() | Out-Null
$safeTest.description = "Test safe for bbors 1"
$safeTest.Update() | Out-Null
$safeTest.Get() | Out-Null
$safeTest.Delete() | Out-Null
$safeTest.Update() | Out-Null
$safeTest.Delete() | Out-Null

"ToJson"
$safeTest.ToJson()
"ConvertTo-Json"
$safeTest | ConvertTo-Json
""
""
Write-Host -ForegroundColor Cyan "SafeList"
$SafeListTest = New-Object SafeList
$SafeListTest.Find("BABTest")
$SafeListTest.Safes.SafeName
"OffSet"
$SafeListOffsetTest = New-Object SafeList
$SafeListOffsetTest.Find("BABTest", 1)
$SafeListOffsetTest.Safes.SafeName
"Offset and Limit"
$SafeListOffsetLimitTest = New-Object SafeList
$SafeListOffsetLimitTest.Find("BABTest", 0, 1)
$SafeListOffsetLimitTest.Safes.SafeName

"safeListObjectTest"
$safeListObjectTest = New-Object SafeList
$SafeListSearchParms = New-Object SafeListSearchParms
$SafeListSearchParms.Search = "BABTest"
$SafeListSearchParms.includeAccounts = $true
$SafeListSearchParms.extendedDetails = $true
$safeListObjectTest.Find($SafeListSearchParms)
$safeListObjectTest.Safes

"safeListObjectAccountsTest"
$safeListObjectAccountsTest = New-Object SafeList
$safeListObjectAccountsParms = New-Object SafeListSearchParms
$safeListObjectAccountsParms.Search = "BABTest"
$safeListObjectAccountsParms.includeAccounts = $true
$safeListObjectAccountsTest.Find($safeListObjectAccountsParms)
$safeListObjectAccountsTest.Safes

"safeListObjectTest"
$safeListObjectExtendedTest = New-Object SafeList
$safeListObjectExtendedParms = New-Object SafeListSearchParms
$safeListObjectExtendedParms.Search = "BABTest"
$safeListObjectExtendedParms.extendedDetails = $true
$safeListObjectExtendedTest.Find($safeListObjectExtendedParms)
$safeListObjectExtendedTest.Safes

"safeListObjectAllTest"
$safeListObjectAllTest = New-Object SafeList
$safeListObjectAllParms = New-Object SafeListSearchParms
$safeListObjectAllParms.Search = "BABTest"
$safeListObjectAllParms.extendedDetails = $true
$safeListObjectAllParms.includeAccounts = $true
$safeListObjectAllTest.Find($safeListObjectAllParms)
$safeListObjectAllTest.GetMembers()
$safeListObjectAllTest.Safes | ForEach-Object { $PSitem.GetMembers() }




exit 0
$safeListTest = New-Object SafeList
$safeListTest.Get("BABTest")
[safe]::Get("babtest")
Write-Host -ForegroundColor Cyan "Safe-Find" 
[safe]::Find("babtest", "", "")

Write-Host -ForegroundColor Cyan "Safemember-get"
[SafeMember]::get("babtest")
Write-Host -ForegroundColor Cyan "Safemember-get With Member"
[SafeMember]::get("babtest", "PasswordManager")
Write-Host -ForegroundColor Cyan "Safemember-find"
[SafeMember]::find("babtest", "memberType eq user", "PasswordManager", "0", "")

Write-Host "Done" -BackgroundColor Red
exit 0

build-Module "C:\GIT\Migrate Usages\Source\" -OutputDirectory "C:\GIT\Migrate Usages\Output\Migrate Usages\" -Verbose

"Loaded"

. ([scriptblock]::Create('Using Module C:\GIT\EPV-API\Source\Classes\Logging.psm1
Using module C:\GIT\EPV-API\Source\Classes\RestCall.psm1
Using module C:\GIT\EPV-API\Source\Classes\PASObject.psm1
Using Module C:\GIT\EPV-API\Source\Classes\Safe.psm1
Using Module C:\GIT\EPV-API\Source\Classes\Safemember.psm1
Using Module C:\GIT\EPV-API\Source\Classes\PSMRecording.psm1
Using Module C:\GIT\EPV-API\Source\Classes\PSMRecordingList.psm1
Write-Host "Loaded"'))

