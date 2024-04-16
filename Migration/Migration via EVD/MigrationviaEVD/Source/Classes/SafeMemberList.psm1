using Module .\Logging.psm1
using Module .\PASObject.psm1
using Module .\SafeMember.psm1

Class SafeMemberListSearchParms {
    [string]$filter
    [string]$Search
    [Int32]$OffSet = 0
    [Int32]$Limit = 1000
    [string]$Sort = "memberName"
}

[NoRunspaceAffinity()]
Class SafeMemberList :PASObject {

    [Int32]$AmountOfJobs = 50
    hidden [string]$nextLink
    # property to hold the list of Safe
    [System.Collections.Generic.List[SafeMember]]$SafeMembers
    # method to initialize the list of Safe. Called in the other
    # methods to avoid needing to explicit initialize the value.
    [void] Initialize() {
        $this.Initialize($false) 
    }
    [bool] Initialize([bool]$force) {
        if ($this.SafeMembers.Count -gt 0 -and -not $force) {
            return $false
        }
    
        $this.SafeMembers = [System.Collections.Generic.List[SafeMember]]::new()
    
        return $true
    }
    # Ensure a Safe is valid for the list.
    [void] Validate([SafeMember]$SafeMember) {
        $Prefix = @(
            'Safe Member validation failed: Safe Member must be defined with memberName'
            ' properties, but'
        ) -join ' '
        if ($null -eq $SafeMember) {
            throw "$Prefix was null" 
        }
        if ([string]::IsNullOrEmpty($SafeMember.memberName)) {
            throw "$Prefix SafeName wasn't defined"
        }
    }
    # methods to manage the list of Safe.
    # Add a Safe if it's not already in the list.
    [void] Add([SafeMember]$SafeMember) {
        $this.Initialize()
        $this.Validate($SafeMember)
        if ($this.SafeMembers.Contains($SafeMember)) {
            $This.WriteDebug("Safe Member '$($SafeMember.memberName)' already in list")
            return
        }
        $FindPredicate = {
            param([SafeMember]$b)
            $b.SafeName -eq $SafeMember.memberName 
        }.GetNewClosure()
        if ($this.SafeMembers.Find($FindPredicate)) {
            $This.WriteDebug("Safe Member '$($SafeMember.memberName)'already in list")
            return
        }
        $This.WriteVerbose("Adding Safe Member to SafeMemberList: memberName:`"$($SafeMember.memberName)`"")
        $this.SafeMembers.Add($SafeMember)
        $This.WriteVerbose("Succesfully Added Safe to SafeMemberList: memberName:`"$($SafeMember.memberName)`"")
    }
    # Clear the list of Safe.
    [void] Clear() {
        $this.Initialize()
        $this.SafeMembers.Clear()
    }
    # Find a specific Safe using a filtering scriptblock.
    [SafeMember] Find([scriptblock]$Predicate) {
        $this.Initialize()
        return $this.SafeMembers.Find($Predicate)
    }
    # Find every Safe matching the filtering scriptblock.
    [SafeMember[]] FindAll([scriptblock]$Predicate) {
        $this.Initialize()
        return $this.SafeMembers.FindAll($Predicate)
    }
    [SafeMember[]] IndexOf([scriptblock]$Predicate) {
        $this.Initialize()
        return $this.SafeMembers.IndexOf($Predicate)
    }
    [SafeMember[]] IndexOf([SafeMember]$SafeMember) {
        $FindPredicate = {
            param([SafeMember]$b)
        }.GetNewClosure()
        return $this.SafeMembers.IndexOf($FindPredicate)
    }
    [string] FindBy([string]$Property, [string]$Value) {
        $this.Initialize()
        $Index = $this.SafeMembers.FindIndex({
                param($b)
                $b.$Property -eq $Value
            }.GetNewClosure())
        if ($Index -ge 0) {
            return $Index
        }
        return $null
    }
    # Remove a specific Safe.
    [void] Remove([SafeMember]$SafeMember) {
        $this.Initialize()
        $this.SafeMembers.Remove($SafeMember)
    }
    # Remove a Safe by property value.
    [void] RemoveBy([string]$Property, [string]$Value) {
        $this.Initialize()
        $Index = $this.SafeMembers.FindIndex({
                param($b)
                $b.$Property -eq $Value
            }.GetNewClosure())
        if ($Index -ge 0) {
            $this.SafeMembers.RemoveAt($Index)
        }
    }
    [void] Get([SafeMemberListSearchParms]$URLSearchParms, [string]$safe) {
        $startTime = $(Get-Date)
        $This.WriteInfo("Started gathering Safe Members at $startTime for safe `"$safe`"")
        $restResult = ($this.InvokeGet($this.GenURLSearchString("/API/Safes/$safe/Members/", $URLSearchParms)))
        
        $This.WriteLogOnly("Completed gathering Safe Members. Total gathered: $($restResult.count)")
        $restResult.value | ForEach-Object { 
            $this.add($([SafeMember]::New([PSCustomObject]$PSItem))) }
        $This.WriteLogOnly("Found $($this.SafeMembers.count) Safes Members for `"$safe`"")
        $endtime = $(Get-Date)
        $diff = $endtime - $startTime
        $This.WriteInfo("Completed gathering of Safe Members at $endtime")
        $This.WriteLogOnly("Elapsed time $diff")
    }
    [void] Get([string]$safe, [string]$memberName) {
        $restResult = ($this.InvokeGet("$([pasobject]::URL_Base)/API/Safes/$safe/Members/$memberName/"))
        $restResult | ForEach-Object { 
            $this.add($([SafeMember]::New([PSCustomObject]$PSItem))) 
        }
    }
}