IF (!("RestCall" -as [type]).IsPublic) {
    Add-Type -AssemblyName Microsoft.PowerShell.Commands.Utility
    $load = $null
    $(Get-ChildItem -Path $PSScriptRoot -Filter *.psm1 | Sort-Object ).FullName | ForEach-Object {
        $load += "Using Module `"$PSItem`"`n"
    }

    . ([scriptblock]::Create($Load))
}