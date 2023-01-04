$response = $null
$CCPAddress="http://ccp.lab.local"
$application = "app"
$safe = "Safe"
$object ="object"
$certThumbprint = ""

$cert = Get-ChildItem Cert:\LocalMachine\My\$certThumbprint

$response = $null

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")

$response = Invoke-RestMethod "$CCPAddress/AIMWebService/api/Accounts?AppID=$application&Safe=$safe&Object=$object" -Method 'GET' -Headers $headers -Certificate $cert 
$response | ConvertTo-Json

write-host "Username: " $($response.Username)
Write-Host "Password: " $($response.content)