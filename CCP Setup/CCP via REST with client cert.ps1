$responseViaObject = $responseViaAddressAndUsername =  $null
$CCPAddress = "http://ccp.lab.local"
$application = "app"
$safe = "Safe"
$object = ""
$address = ""
$username = ""

$certThumbprint = ""
$cert = Get-ChildItem Cert:\LocalMachine\My\$certThumbprint

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")

if (![string]::IsNullOrEmpty($object)) {
    $responseViaObject = Invoke-RestMethod "$CCPAddress/AIMWebService/api/Accounts?AppID=$application&Safe=$safe&Object=$object" -Method 'GET' -Headers $headers  -Certificate $cert 

    Write-Host "Pulled using Object Name"
    write-host "Username: " $($responseViaObject.Username)
    Write-Host "Password: " $($responseViaObject.content)
    ""
    $responseViaObject | ConvertTo-Json
}

if (![string]::IsNullOrEmpty($address) -and ![string]::IsNullOrEmpty($username)) {
    $responseViaAddressAndUsername = Invoke-RestMethod "$CCPAddress/AIMWebService/api/Accounts?AppID=$application&Safe=$safe&address=$address&username=$username" -Method 'GET' -Headers $headers  -Certificate $cert 
    $responseViaAddressAndUsername | ConvertTo-Json

    Write-Host "Pulled using Address and Username"
    write-host "Username: " $($responseViaAddressAndUsername.Username)
    Write-Host "Password: " $($responseViaAddressAndUsername.content)
    ""
    $responseViaAddressAndUsername | ConvertTo-Json
}
