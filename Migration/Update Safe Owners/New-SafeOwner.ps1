[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Vault IP address")]
    [String]$vaultIP,

    [Parameter(ParameterSetName = 'add', Mandatory = $true, HelpMessage = "Owner to add")]
    [Parameter(ParameterSetName = 'delete', Mandatory = $true, HelpMessage = "Owner to add")]
    [Parameter(ParameterSetName = 'export', Mandatory = $false, HelpMessage = "Owner to add")]
    [String]$owner,

    [Parameter(Mandatory = $false, HelpMessage = "Location of safe list")]
    [String]$safecsv=".\safelist.csv",
		
    [Parameter(Mandatory = $false, HelpMessage = "Export Safe list")]
    [switch]$export,

    [Parameter(ParameterSetName = 'add', Mandatory = $false, HelpMessage = "Add Owner to safes on list")]
    [switch]$add,

    [Parameter(Mandatory = $false, HelpMessage = "Do NOT update safes where owner already exists")]
    [switch]$NoUpdate,

    [Parameter(ParameterSetName = 'delete', Mandatory = $false, HelpMessage = "Delete Owner from safes on list")]
    [switch]$delete
)

$FullAccess = "RETRIEVE=YES STORE=YES DELETE=YES ADMINISTER=YES SUPERVISE=YES BACKUP=YES MANAGEOWNERS=YES ACCESSNOCONFIRMATION=YES VALIDATESAFECONTENT=YES LIST=YES USEPASSWORD=YES UPDATEOBJECTPROPERTIES=YES INITIATECPMCHANGE=YES INITIATECPMCHANGEWITHMANUALPASSWORD=YES CREATEFOLDER=YES DELETEFOLDER=YES MOVEFROM=YES MOVEINTO=YES VIEWAUDIT=YES VIEWPERMISSIONS=YES EVENTSLIST=YES ADDEVENTS=YES CREATEOBJECT=YES UNLOCKOBJECT=YES RENAMEOBJECT=YES"

$Limited = "RETRIEVE=YES ACCESSNOCONFIRMATION=YES LIST=YES VIEWPERMISSIONS=YES BACKUP=YES"

$Access = $Limited


while(($Credentials.password.Length -eq 0) -or [string]::IsNullOrEmpty($Credentials.username)) {
    $Credentials = Get-Credential -Message "Please enter password" -UserName Master
    If ($null -eq $Credentials) {return}
}


Invoke-Expression ".\Pacli.exe init"
Invoke-Expression ".\Pacli.exe define vault=thing address=$vaultIP"
Invoke-Expression ".\Pacli.exe default vault=thing user=$($Credentials.username)"
[string]$resultLogon = Invoke-Expression ".\Pacli.exe logon password=$($Credentials.GetNetworkCredential().password) 2>&1"
if (![string]::IsNullOrEmpty($resultLogon)){
    $resultLogon
    Invoke-Expression ".\Pacli.exe logoff"
    Invoke-Expression ".\Pacli.exe term"
    continue
}

if ($export){
    "Safename" | Out-File $safecsv
    Invoke-Command -ScriptBlock{.\Pacli.exe safeslist output`(name`)} | Out-File $safecsv -Append
    "Exported safe names"
    Invoke-Expression ".\Pacli.exe logoff"
    Invoke-Expression ".\Pacli.exe term"
    return
}

$safelist=Import-Csv $safecsv
foreach ($safe in $safelist.Safename){
    IF ($safe -like "* *"){
        Write-Host -ForegroundColor Red "Safe `"$safe`" contains a space. Unable to modify" 
        continue
    }
    [string]$resultSafe = Invoke-Expression ".\Pacli.exe opensafe safe=`"$($safe.trim())`" 2>&1"
    if (![string]::IsNullOrEmpty($resultSAfe)){
        $resultSafe
        continue
    }
    try {
        if($delete){
            [string]$resultDelete = Invoke-Expression ".\Pacli.exe DELETEOWNER owner=$owner safe=`"$($safe.trim())`" 2>&1"
            if("$resultDelete" -like "*ITATS034E*"){ 
                "Did not find owner `"$owner`" on safe `"$safe`""
            } elseif("$resultDelete" -like "*ITATS034E*"){ 
                "Did not find owner `"$owner`" on safe `"$safe`""
            } elseif (![string]::IsNullOrEmpty($resultDelete)){
                Write-Host -ForegroundColor Red $resultDelete
                continue
            } else {
                "Deleted owner `"$owner`" on safe `"$safe`""
            }
        } elseif ($add) {
            [string]$resultAdd = Invoke-Expression ".\Pacli.exe addowner owner=$owner safe=`"$($safe.trim())`" $($Access) 2>&1"       
            if ("$resultAdd" -like "*parse error*") {
                Write-Host -ForegroundColor Red "Error Adding owner `"$owner`" on safe `"$safe`""
                Out-File 
            } elseif("$resultAdd" -like "*ITATS028E*"){ 
                Write-Host -ForegroundColor Red "You are not authorized to update owner `"$owner`" on safe `"$safe`""
            } elseif("$resultAdd" -like "*ITATS031E*"){ 
                IF(!$NoUpdate){
                    [string]$resultUpdate = Invoke-Expression ".\Pacli.exe updateowner owner=$owner safe=`"$($safe.trim())`" $($Access) 2>&1"
                    if("$resultUpdate" -like "*ITATS028E*"){ 
                    Write-Host -ForegroundColor Red  "You are not authorized to update owner `"$owner`" on safe `"$safe`""
                    } elseIf([string]::IsNullOrEmpty($resultUpdate)){
                        "Updated owner `"$owner`" on safe `"$safe`""
                    }
                } else {"Found owner `"$owner`" on safe `"$safe`" but updates disabled" }
            } else {
                "Added owner `"$owner`" to safe `"$safe`""
            }
        }
    } finally {
        Invoke-Expression ".\Pacli.exe closesafe safe=`"$safe`""
    
    }
}

Invoke-Command -ScriptBlock{.\Pacli.exe logoff}
Invoke-Command -ScriptBlock{.\Pacli.exe term}
