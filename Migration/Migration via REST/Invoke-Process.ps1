function Invoke-DeepCopy {
    [CmdletBinding()]
    param (
        $data
    )
    $serialData = [System.Management.Automation.PSSerializer]::Serialize($data)
    return [System.Management.Automation.PSSerializer]::Deserialize($serialData)
}
function Update-Username {
    [CmdletBinding()]
    param (
        $srcMember
    )
    process {
        if ($srcRemoveDomain -or (![string]::IsNullOrEmpty($dstDomainSuffix))) {
            Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Removing domain from source username `"$($srcMember.membername)`""
            IF ($srcMember.membername -match '@') {
                $srcMember.membername = $($($srcMember.membername).Split("@"))[0]
                Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Updated username to `"$($srcMember.membername)`""
            }
            else {
                Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Username is not in UPN format, no change made"
            }
        }
        If (!$([string]::IsNullOrEmpty($dstDomainSuffix))) {
            Write-LogMessage -type Debug "[$($safememberCount)] New domain suffix of $dstDomainSuffix provided"
            $srcMember.memberName = "$($srcMember.memberName)@$dstDomainSuffix"
            Write-LogMessage -type Debug "[$($safememberCount)] Updated username to `"$($srcMember.membername)`""
        }
        return $srcMember  
    }

}

function Get-UPNFromAD {
    [CmdletBinding()]
    param (
        $srcMember
    )
    process {
        $adUser = Get-ADUser -Identity $srcMember
        If ([string]::IsNullOrEmpty($adUser.UserPrincipalName)) {
            Throw "Unable to locate UPN using samAccountName `"$srcMember`""
        }
        return $adUser.UserPrincipalName    
    }
}

Function Search-Members {
    [CmdletBinding()]
    param (
        $srcMember,
        $dstSafeMembers
    )
    [PSCustomObject]$result = @{
        Found       = $false
        srcUsername = $null
        dstUsername = $null
    }
    if ($srcMember.memberName -in $dstSafeMembers.memberName ) { 
        Write-LogMessage -type Debug "[$($safememberCount)] Matched source $($srcMember.memberType.ToLower()) `"$($srcMember.memberName)`" directly to destination  $($srcMember.memberType.ToLower()) `"$($srcMember.memberName)`""
        $result.Found = $true
        $result.srcUsername = $srcMember.memberName
        $result.dstUSername = $srcMember.memberName
        Return $result
    } 
    If (![string]::IsNullOrEmpty($dstDomainSuffix)) {
        if ($("$($srcMember.memberName)@$dstDomainSuffix") -in $dstSafeMembers.memberName) {
            Write-LogMessage -type Debug "[$($safememberCount)] Adding provided destination domain suffix matched source $($srcMember.memberType.ToLower()) `"$srcMember`" directly to destination $($srcMember.memberType.ToLower()) `"$($srcMember.memberName)@$dstDomainSuffix`""
            $result.Found = $true
            $result.srcUsername = $srcMember.memberName
            $result.dstUSername = $("$($srcMember.memberName)@$dstDomainSuffix")
            Return $result
        }
    }
    If ($dstMatchWitoutDomain) {
        ForEach ($username in $dstSafeMembers.membername) {
            IF ($($username.Split("@")[0]) -in $srcMember.memberName) {
                Write-LogMessage -type Debug "[$($safememberCount)] Removing source domain suffix matched source $($srcMember.memberType.ToLower()) `"$($srcMember.memberName)`" directly to destination $($srcMember.memberType.ToLower()) `"$username`""
                $result.Found = $true
                $result.srcUsername = $srcMember.memberName
                $result.dstUSername = $username
                return $result
            }
        }
    }
    Write-LogMessage -type Debug "[$($safememberCount)] Source $($srcMember.memberType.ToLower()) `"$($srcMember.memberName)`" not found as a member of destination safe"
    Return $result
}                    
Function Invoke-UpdateMember {
    [CmdletBinding()]
    param (
        $srcMember,
        $dstSafeMembers
    )
    $MemberFound = Search-Members -srcMember $srcMember -dstSafeMembers $dstSafeMembers
    IF ($MemberFound.Found) {
        If ($RetainExistingPerms) {
            Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Owner `"$($srcMember.memberName)`" has existing permission to safe `"$($srcMember.safename)`". Retain existing permissions selected. No updates made."
            return $true
        }
        Update-SafeMember -url $dstPVWAURL -logonHeader $dstToken -safe $($srcMember.safename) -safemember $srcMember -newSafeMember $($MemberFound.dstUSername ) | Out-Null
        Return $true
    }
    Else {
        if ([string]::IsNullOrEmpty($ReplaceMap)) {
            return $false
        }
        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Processing Username Replacement Map for `"$($srcMember.memberName)`""
        if ($ReplaceMap.ContainsKey($srcMember.memberName)) {
            $srcMember.memberName = $ReplaceMap[$($srcMember.memberName)]
        }
        else {
            Write-LogMessage -Type Debug -Msg "[$($safememberCount)] No match found in Replacement Map for `"$($srcMember.memberName)`""
            Return $false
        }
        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Found in Replacement Map. New username is `"$($srcMember.memberName)`""
        $MemberFound = Search-Members -srcMember $srcMember -dstSafeMembers $dstSafeMembers        
        IF ($MemberFound.Found) {
            If ($RetainExistingPerms) {
                Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Owner `"$($srcMember.memberName)`" has existing permission to safe `"$($srcMember.safename)`". Retain existing permissions selected. No updates made."
                return $true
            }
            Update-SafeMember -url $dstPVWAURL -logonHeader $dstToken -safe $($srcMember.safename) -safemember $srcMember -newSafeMember $($MemberFound.dstUSername ) | Out-Null
            Return $true
        }
    }
}
Function Invoke-ProcessUser {
    [CmdletBinding()]
    param (
        $srcMember,
        $dstSafeMembers
    )
    if (![string]::IsNullOrEmpty($ReplaceMap)) {
        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Processing Username Replacement Map for `"$($srcMember.membername)`""
        if ($ReplaceMap.ContainsKey($srcMember.memberName)) {
            $srcMember.memberName = $ReplaceMap[$($srcMember.memberName)]
        }
        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Final Username is `"$($srcMember.membername)`""
    }
    if ($GetUPNFromAD) {
        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Getting UPN from AD for `"$($srcMember.membername)`""
        Try {
            $srcMember.memberName = Get-UPNFromAD -samAccountName $($srcMember.membername)
            Write-LogMessage -Type Debug -Msg "[$($safememberCount)] UPN from AD for `"$($srcMember.membername)`""
        }
        Catch {
            Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Unable to get UPN from AD for  `"$($srcMember.membername)`""
        }
    }
    if ($srcMember.memberId -match "[A-Z]") {
        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is from PCloud ISPSS"
        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Attempting to add $($srcMember.MemberType) `"$($srcMember.membername)`" to safe `"$($dstsafe.safename)`""
        $null = New-SafeMember -url $dstPVWAURL -logonHeader $dstToken -safe $safename -safemember $srcMember
        Write-LogMessage -Type Info -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType) `"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`" succesfully"
    }
    elseif ($srcMember.memberType -eq "User") {
        IF (![string]::IsNullOrEmpty($newDir)) {
            Write-LogMessage -type Debug -MSG "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is a user and new directory provided, updating `"seachIn`" to `"$newDir`""
            $srcMember | Add-Member NoteProperty searchIn $newDir
            Write-LogMessage -type Debug -MSG "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" attribute`"seachIn`" succesfully set"
        }
        Else {
            Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is a user, attempting to find source"
            Try {
                $userSource = Get-UserSource -url $srcPVWAURL -logonHeader $srcToken -safemember $srcMember
                Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" source is `"$userSource`""
            }
            Catch {
                Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Unable to retrieve user source"
                Throw $PSItem
            }
            Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" source found. Setting `"SearchIn`""
            $srcMember = Get-SearchIn -srcMember $srcMember -source $userSource
            Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" `"SearchIn`" set to `"$($srcMember.SearchIn)`""
            Write-LogMessage -Type Info -Msg "[$($safememberCount)] Attempting to add user `"$($srcMember.membername)`" to safe `"$($dstsafe.safename)`""
            $null = New-SafeMember -url $dstPVWAURL -logonHeader $dstToken -safe $safename -safemember $srcMember
            Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member User`"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`""
        }
    }
}

Function Get-SearchIn {
    param (
        $srcMember,
        $source
    )
    If ("vault" -eq $source -and [string]::IsNullOrEmpty($VaultDir)) {
        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Source is `"vault`" but no directory for vault provided"
        Throw
    }
    elseif ("vault" -eq $source ) {
        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Source is `"$usersource`", updating `"seachIn`" to provided VaultDir of `"$VaultDir`""
        $srcMember | Add-Member NoteProperty searchIn $VaultDir                
        Write-LogMessage -type Debug -MSG "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" attribute `"seachIn`" succesfully set"
        return $srcMember    
    }
    elseif ($DirMap.ContainsKey($source)) {
        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Processing Directory Replacement Map for `"$($srcMember.memberName)`" with source of `"$userSource`""
        $newSearchin = $DirMap[$source]
    }
    elseif (!$DirMap.ContainsKey($source)) {
        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Source is not `"vault`" and not able to match to a domain"
        Throw 
    }
    Write-LogMessage -type Debug -MSG "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is a user and source matches to a domain, updating `"seachIn`" to `"$newSearchin`""               
    $srcMember | Add-Member NoteProperty searchIn $newSearchin
    Write-LogMessage -type Debug -MSG "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" attribute`"seachIn`" succesfully set"
    return $srcMember 
}

Function Invoke-ProcessGroup {
    [CmdletBinding()]
    param (
        $srcMember,
        $dstSafeMembers
    )
    if ($srcMember.memberId -match "[A-Z]") {
        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is from PCloud ISPSS"
    } 
    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is a group, attempting to find source"
    $groupSource = Get-GroupSource -url $srcPVWAURL -logonHeader $srcToken -safemember $srcMember
    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" source found. Setting `"SearchIn`""
    $srcMember = Get-SearchIn -srcMember $srcMember -source $groupSource
    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" `"SearchIn`" set to `"$($srcMember.SearchIn)`""

    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Attempting to add group `"$($srcMember.membername)`" to safe `"$($dstsafe.safename)`""
    try {
        $null = New-SafeMember -url $dstPVWAURL -logonHeader $dstToken -safe $safename -safemember $srcMember
        Write-LogMessage -Type Info -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType) `"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`" succesfully"
        Return
    }
    catch {
        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType) `"$($srcMember.membername)`" faild to added to safe `"$($dstsafe.safename)`""
    }
    
    IF ($srcMember.membername -match '@') {
        Try {
            Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Removing domain from source username `"$($srcMember.membername)`" and trying again"
            $srcMember.membername = $($($srcMember.membername).Split("@"))[0]
            Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Updated username to `"$($srcMember.membername)`""
            $null = New-SafeMember -url $dstPVWAURL -logonHeader $dstToken -safe $safename -safemember $srcMember
            Write-LogMessage -Type Info -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType) `"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`" succesfully"
            Return
        }
        Catch {
            Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType) `"$($srcMember.membername)`" faild to added to safe `"$($dstsafe.safename)`""
        }
    }
    If ($dstToken.Authorization.Contains("Bearer")) {
        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Destination is from PCloud ISPSS"
        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Updating MemberType to Role on `"$($srcMember.membername)`""
        $srcMember.memberType = "Role"
        Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Attempting to add group `"$($srcMember.membername)`" to safe `"$($dstsafe.safename)`" with MemberType of `"Role`""
        $null = New-SafeMember -url $dstPVWAURL -logonHeader $dstToken -safe $safename -safemember $srcMember
    }
    Throw "Safe Member Update Failed"
}

Function Invoke-ProcessRole {
    [CmdletBinding()]
    param (
        $srcMember,
        $dstSafeMembers
    )
    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is a Role."
    IF ($dstToken.Authorization.Contains("Bearer")) {
        try {
            Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Attempting to add Role `"$($srcMember.membername)`" to safe `"$($dstsafe.safename)`""
            $null = New-SafeMember -url $dstPVWAURL -logonHeader $dstToken -safe $safename -safemember $srcMember
            Write-LogMessage -Type Info -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType) `"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`" succesfully"
            return
        }
        catch {
            Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType) `"$($srcMember.membername)`" faild to added to safe `"$($dstsafe.safename)`""
        }
    }
    else {
        Write-LogMessage -Type Info -Msg "[$($safememberCount)] Destination is not PCLoud ISPSS. Not possible to add as a role. Updating memberType to `"Group`""
    }
    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Updating memberType to `"Group`""
    $srcMember.MemberType = "Group"
    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Attempting to add Role `"$($srcMember.membername)`" to safe `"$($dstsafe.safename)`" as a group"
    $null = New-SafeMember -url $dstPVWAURL -logonHeader $dstToken -safe $safename -safemember $srcMember
    Write-LogMessage -Type Info -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType) `"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`" succesfully"
}


Function Invoke-ProcessSafe {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $SafeName,
        [Parameter(Mandatory = $false)]
        [hashtable]
        $SafeStatus
    )

    IF ([string]::IsNullOrEmpty($SafeStatus)) {
        $SafeStatus = @{
            id                = "Not running as PS Job"
            safeName          = $SafeObject.Safename
            success           = $false
            createSkip        = $false
            UpdateMembersFail = $false
            GetUPNFromAD      = $false
            safeData          = $SafeObject
            Log               = @()
            Error             = @()
        }
        
        Function Write-LogMessage {
            param(
                [String]$MSG,
                [Switch]$NoWrite,
                [String]$type
            )
            $MSG = "`[$safename`] $msg"
            if (!$NoWrite) {
                CyberArk-Migration\Write-LogMessage -MSG $MSG -type $type -LogFile $LOG_FILE_PATH @Args
            }
        }
    }
    Try {
        Write-LogMessage -Type Info -Msg "Working with Safe `"$safename`""
        If ($safename -in $objectSafesToRemove) {
            Write-LogMessage -Type Info -Msg "Safe `"$($safename)`" is in the excluded safes list and will be skipped"
            $SafeStatus.success = $true
            write-LogMessage -Type Verbose -Msg "Final `$SafeStatus $($SafeStatus | ConvertTo-Json -Compress)"
            continue
        }
        Write-LogMessage -Type Debug -Msg "Getting source safe `"$safename`""
        $srcSafe = Get-Safe -url $srcPVWAURL -logonHeader $srcToken -safe $($safename)
        if ([string]::IsNullOrEmpty($srcSafe)) {
            Write-LogMessage -Type error -Msg "Source safe `"$safename`" not Found. Skipping"
            write-LogMessage -Type Verbose -Msg "Final `$SafeStatus $($SafeStatus |ConvertTo-Json -Compress)"
            Continue
        }
        else {
            Write-LogMessage -Type Debug -Msg "Source safe `"$safename`" located"
        }

        Write-LogMessage -Type Debug -Msg "Getting destination safe `"$safename`""
        Try {
            $dstsafe = Get-Safe -url $dstPVWAURL -logonHeader $dstToken -safe $($safename) -ErrorAction SilentlyContinue
        }
        catch {
            $dstsafe = $null
        }

        if ([string]::IsNullOrEmpty($dstsafe)) {
            Write-LogMessage -Type Debug -Msg "Destination safe `"$safename`" not Found"
            if ($CreateSafes) {
                Try {
                    Write-LogMessage -Type Debug -Msg "CreateSafe passed, attempting to create safe `"$safename`" in destination"
                    if (![string]::IsNullOrEmpty($CPMOverride)) {
                        $dstSafe = New-Safe -url $dstPVWAURL -logonHeader $dstToken -safe $srcSafe -cpnNameNew $CPMOverride
                    }
                    elseif ((![string]::IsNullOrEmpty($CPMOld)) -and (![string]::IsNullOrEmpty($CPMnew))) {
                        $dstSafe = New-Safe -url $dstPVWAURL -logonHeader $dstToken -safe $srcSafe -cpnNameOld $CPMOld -cpnNameNew $CPMnew
                    }
                    else {
                        $dstSafe = New-Safe -url $dstPVWAURL -logonHeader $dstToken -safe $srcSafe
                    }
                    Write-LogMessage -Type Debug -Msg "Created safe `"$safename`""
                    $createdDstSafe = $true
                }
                catch {
                    Write-LogMessage -Type error -Msg "`tError creating safe `"$safename`""
                    Write-LogMessage -Type Debug -Msg "Error: $_"
                    $SafeStatus.error = $_
                    $process.Completed = $true
                    continue
                }
            }
            else {
                Write-LogMessage -Type Warning -Msg "`tTarget safe `"$($safename)`" does not exist in destination and creating of safes disabled, skipping `"$($safename)`""
                $SafeStatus.createSkip = $true
                $SafeStatus.success = $true
                continue
            }
        }
        else {
            Write-LogMessage -Type Debug -Msg "Destination safe `"$($dstsafe.safename)`" located"
        }
        If (($UpdateSafeMembers -or $createdDstSafe)) {
            $srcSafeMembers = (Get-SafeMembers -url $srcPVWAURL -logonHeader $srcToken -safe $safename).value
            Write-LogMessage -Type Info -Msg "From source safe `"$($srcSafe.safename)`" retrived $($srcSafeMembers.Count) Safe Members"
            $dstSafeMembers = (Get-SafeMembers -url $dstPVWAURL -logonHeader $dstToken -safe $safename).value
            Write-LogMessage -Type Info -Msg "From destination safe `"$($dstsafe.safename)`" retrived $($dstSafeMembers.Count) Safe Members"
            $safememberCount = 0
            ForEach ($srcMember in $srcSafeMembers) {
                $safememberCount += 1
                Try {
                    Write-LogMessage -Type Info -Msg "[$($safememberCount)] Working with Safe Member `"$($srcMember.membername)`" in Safe `"$($safename)`""
                    IF ($srcMember.membername -in $ownersToRemove) {
                        Write-LogMessage -Type Info -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is in the excluded owners list"
                        continue
                    }
                    if ($srcMember.memberId -match "[_]" -and $srcMember.memberType -eq "Group") {
                        Write-LogMessage -Type Info -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is a Role, updating memberType to `"Role`""
                        $srcMember.memberType = "Role"
                    }
                    $srcMember = Update-Username -srcMember $srcMember
                    $MemberUpdated = $(Invoke-UpdateMember -srcMember $srcMember -dstSafeMembers $dstSafeMembers)
                    if (!$($MemberUpdated)) {
                        Switch ($($srcMember.memberType)) {
                            "User" {
                                Invoke-ProcessUser -srcMember $srcMember -dstSafeMembers $dstSafeMembers
                            }
                            "Group" {
                                Invoke-ProcessGroup -srcMember $srcMember -dstSafeMembers $dstSafeMembers
                            }
                            "Role" {
                                Invoke-ProcessRole -srcMember $srcMember -dstSafeMembers $dstSafeMembers
                            }
                        } 
                    }
                }
                Catch {
                    Write-LogMessage -Type Error -Msg "[$($safememberCount)] Failed to add or update Safe Member `"$($srcMember.membername)`" in safe `"$($dstsafe.safename)`""
                    $SafeStatus.UpdateMembersFail = $true
                    $SafeStatus.error = "[$($safememberCount)] $($PSItem.ErrorDetails)"
                    continue
                }
            }
            $SafeStatus.success = $true
        }
        else {
            Write-LogMessage -Type Info -Msg "Creating and/or Updating of Safe Members is disabled. Memberships of `"$($dstsafe.safename)`" not changed"
            $SafeStatus.success = $true
        }
    }
    Catch {
        $PSItem
        $SafeStatus.error = $PSItem
    }
    Finally {
        IF ($SafeStatus.UpdateMembersFail) {
            $SafeStatus.success = $false
        }
    }
}