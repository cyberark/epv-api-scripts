$responseViaObject = $responseViaAddressAndUsername =  $null
$CCPAddress = "http://ccp.lab.local"
$location = "AIMWebService"
$application = "app"
$safe = "Safe"
$object = ""
$address = ""
$username = ""

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")

if (![string]::IsNullOrEmpty($object)) {
    $responseViaObject = Invoke-RestMethod "$CCPAddress/$location/api/Accounts?AppID=$application&Safe=$safe&Object=$object" -Method 'GET' -Headers $headers

    Write-Host "Pulled using Object Name"
    write-host "Username: " $($responseViaObject.Username)
    Write-Host "Password: " $($responseViaObject.content)
    ""
    $responseViaObject | ConvertTo-Json
}

if (![string]::IsNullOrEmpty($address) -and ![string]::IsNullOrEmpty($username)) {
    $responseViaAddressAndUsername = Invoke-RestMethod "$CCPAddress/$location/api/Accounts?AppID=$application&Safe=$safe&address=$address&username=$username" -Method 'GET' -Headers $headers
    $responseViaAddressAndUsername | ConvertTo-Json

    Write-Host "Pulled using Address and Username"
    write-host "Username: " $($responseViaAddressAndUsername.Username)
    Write-Host "Password: " $($responseViaAddressAndUsername.content)
    ""
    $responseViaAddressAndUsername | ConvertTo-Json
}
