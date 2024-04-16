using Module .\Logging.psm1
using Module .\PASBase.psm1
using Module .\PASObject.psm1
using Module .\Safe.psm1

[NoRunspaceAffinity()]
Class SafeListSearchParms {
    [string]$Search
    [Int32]$OffSet = 0
    [Int32]$Limit = 1000
    [string]$Sort = "SafeName"
    [bool]$includeAccounts
    [bool]$extendedDetails
    hidden [bool]$getNextLink = $true
}

[NoRunspaceAffinity()]
Class SafeList :PASObject {

    hidden [Int32]$AmountOfJobs = 25
    hidden [string]$nextLink
    # property to hold the list of Safe
    [System.Collections.Generic.List[Safe]]$Safes
    # method to initialize the list of Safe. Called in the other
    # methods to avoid needing to explicit initialize the value.
    [void] Initialize() {
        $this.Initialize($false) 
    }
    [bool] Initialize([bool]$force) {
        if ($this.Safes.Count -gt 0 -and -not $force) {
            return $false
        }
    
        $this.Safes = [System.Collections.Generic.List[Safe]]::new()
    
        return $true
    }
    # Ensure a Safe is valid for the list.
    [void] Validate([Safe]$Safe) {
        $Prefix = @(
            'Safe validation failed: Safe must be defined with SafeName'
            ' properties, but'
        ) -join ' '
        if ($null -eq $Safe) {
            throw "$Prefix was null" 
        }
        if ([string]::IsNullOrEmpty($Safe.SafeName)) {
            throw "$Prefix SafeName wasn't defined"
        }
    }
    # methods to manage the list of Safe.
    # Add a Safe if it's not already in the list.
    [void] Add([Safe]$Safe) {
        $this.Initialize()
        $this.Validate($Safe)
        if ($this.Safes.Contains($Safe)) {
            $This.WriteDebug("Safe '$($Safe.SafeName)' already in list")
            return
        }
        $FindPredicate = {
            param([Safe]$b)
            $b.SafeName -eq $Safe.SafeName 
        }.GetNewClosure()
        if ($this.Safes.Find($FindPredicate)) {
            $This.WriteDebug("Safe '$($Safe.SafeName)'already in list")
            return
        }
        $This.WriteVerbose("Adding Safe to SafeList: SafeName:`"$($Safe.safeName)`"")
        $this.Safes.Add($Safe)
        $This.WriteVerbose("Succesfully Added Safe to SafeList: safeName:`"$($Safe.safeName)`"")
    }
    # Clear the list of Safe.
    [void] Clear() {
        $this.Initialize()
        $this.Safes.Clear()
    }
    # Find a specific Safe using a filtering scriptblock.
    [Safe] Find([scriptblock]$Predicate) {
        $this.Initialize()
        return $this.Safes.Find($Predicate)
    }
    # Find every Safe matching the filtering scriptblock.
    [Safe[]] FindAll([scriptblock]$Predicate) {
        $this.Initialize()
        return $this.Safes.FindAll($Predicate)
    }
    [Safe[]] IndexOf([scriptblock]$Predicate) {
        $this.Initialize()
        return $this.Safes.IndexOf($Predicate)
    }
    [Safe[]] IndexOf([Safe]$Safe) {
        $FindPredicate = {
            param([Safe]$b)
        }.GetNewClosure()
        return $this.Safes.IndexOf($FindPredicate)
    }
    [string] FindBy([string]$Property, [string]$Value) {
        $this.Initialize()
        $Index = $this.Safes.FindIndex({
                param($b)
                $b.$Property -eq $Value
            }.GetNewClosure())
        if ($Index -ge 0) {
            return $Index
        }
        return $null
    }
    # Remove a specific Safe.
    [void] Remove([Safe]$Safe) {
        $this.Initialize()
        $this.Safes.Remove($Safe)
    }
    # Remove a Safe by property value.
    [void] RemoveBy([string]$Property, [string]$Value) {
        $this.Initialize()
        $Index = $this.Safes.FindIndex({
                param($b)
                $b.$Property -eq $Value
            }.GetNewClosure())
        if ($Index -ge 0) {
            $this.Safes.RemoveAt($Index)
        }
    }
    [void] Gather([SafeListSearchParms]$URLSearchParms) {
        $startTime = $(Get-Date)
        $This.WriteInfo("Started gathering Safes at $startTime")
        $restResult = ($this.InvokeGet($this.GenURLSearchString("/API/Safes", $URLSearchParms)))
        IF ([bool]($restResult.PSobject.Properties.name -match "NextLink")) {
            $this.nextLink = $restResult.nextLink
        }
        $This.WriteLogOnly("Toatl Safes gathered so far: $($restResult.count)")
        While (![string]::IsNullOrEmpty($This.nextLink) -and $this.getNextLink) {
            $addSafes = ($this.InvokeGet($This.nextLink))
            If ($addSafes.value.count -gt 0) {
                $restResult.value += $addSafes.value
                $This.WriteLogOnly("Toatl Safes gathered so far: $($restResult.value.count)")
                IF ([bool]($addSafes.PSobject.Properties.name -match "NextLink")) {
                    $this.nextLink = $addSafes.nextLink
                }
                else {
                    $this.nextLink = $null
                    Break
                }
            }
            else {
                $this.nextLink = $null
                Break
            }
        }
        $This.WriteLogOnly("Completed gathering Safes. Total gathered: $($restResult.value.count)")
        $restResult.value | ForEach-Object { 
            $this.add($([Safe]::New([PSCustomObject]$PSItem))) }
        $This.WriteLogOnly("Found $($this.Safes.count) Safess")
        $endtime = $(Get-Date)
        $diff = $endtime - $startTime
        $This.WriteInfo("Completed gathering of Safes at $endtime")
        $This.WriteLogOnly("Elapsed time $diff")
    }


    Find([SafeListSearchParms]$SearchObject){
        $this.Gather($SearchObject)
    }   
    Find([String]$Search){
        $SearchObject = New-Object SafeListSearchParms
        $SearchObject.Search = $search
        $this.Gather($SearchObject)
    }    
    Find([String]$Search,[int32]$OffSet){
        $SearchObject = New-Object SafeListSearchParms
        $SearchObject.Search = $search
        $SearchObject.OffSet = $OffSet
        $this.Gather($SearchObject)
    }
    Find([String]$Search,[int32]$OffSet,[int32]$Limit){
        $SearchObject = New-Object SafeListSearchParms
        $SearchObject.Search = $search
        $SearchObject.OffSet = $OffSet
        $SearchObject.Limit = $Limit
        $SearchObject.getNextLink = $false
        $this.Gather($SearchObject)
    }

    GetMembers() {
        $load = $null
        $(Get-ChildItem -Path $PSScriptRoot -Filter *.psm1).FullName | ForEach-Object {
            $load += "Using Module `"$PSItem`"`n"
        }
        $this.Safes |  ForEach-Object -Parallel {
            . ([scriptblock]::Create($using:Load))
            
            $PSItem.GetMembers()
        } -ThrottleLimit $($this.AmountOfJobs) -AsJob  | Receive-Job -Wait
    }

}