function Get-DirectoryUUID {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $logonToken,
        [Parameter(Mandatory = $true)]
        [Alias("Purl")]
        [String]
        [String]$IdentityTenantURL,
        $DirectoryName
    )
    
    begin {

        $RedrockUrl = "$IdentityTenantURL/Redrock/Query"
    }
    
    process {
        
        $Userbody = [PSCustomObject]@{Script = "Select ServiceInstanceLocalized, DirectoryServiceUuid from DSUsers" } | ConvertTo-Json
        $usersQuery = $(Invoke-RestMethod $RedrockUrl -Method 'POST' -Headers $logonToken -Body $userbody).Result.Results.row
        $DirectoryUUIDS = $usersQuery | Select-Object -Unique -Property ServiceInstanceLocalized, DirectoryServiceUuid
        IF ([string]::IsNullOrEmpty($DirectoryName)){
            $DirectoryUUIDS
        } else {
            $DirectoryUUIDS |Where-Object {$PSItem.ServiceInstanceLocalized -like "*$DirectoryName*"} 
        }
        
        
    }
    end {
        
    }
}