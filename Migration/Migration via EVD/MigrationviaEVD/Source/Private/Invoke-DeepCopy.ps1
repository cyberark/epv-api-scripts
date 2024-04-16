function Invoke-DeepCopy {
    [CmdletBinding()]
    param (
        $data
    )
    $serialData = [System.Management.Automation.PSSerializer]::Serialize($data)
    return [System.Management.Automation.PSSerializer]::Deserialize($serialData)
}