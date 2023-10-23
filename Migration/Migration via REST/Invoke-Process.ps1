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
        } else {
            Write-LogMessage -Type Debug -Msg "Source safe `"$safename`" located"
        }

        Write-LogMessage -Type Debug -Msg "Getting destination safe `"$safename`""
        Try {
            $dstsafe = Get-Safe -url $dstPVWAURL -logonHeader $dstToken -safe $($safename) -ErrorAction SilentlyContinue
        } catch {
            $dstsafe = $null
        }

        if ([string]::IsNullOrEmpty($dstsafe)) {
            Write-LogMessage -Type Debug -Msg "Destination safe `"$safename`" not Found"
            if ($CreateSafes) {
                Try {
                    Write-LogMessage -Type Debug -Msg "CreateSafe passed, attempting to create safe `"$safename`" in destination"
                    if (![string]::IsNullOrEmpty($CPMOverride)) {
                        $dstSafe = New-Safe -url $dstPVWAURL -logonHeader $dstToken -safe $srcSafe -cpnNameNew $CPMOverride
                    } elseIf ((![string]::IsNullOrEmpty($CPMOld)) -and (![string]::IsNullOrEmpty($CPMnew))) {
                        $dstSafe = New-Safe -url $dstPVWAURL -logonHeader $dstToken -safe $srcSafe -cpnNameOld $CPMOld -cpnNameNew $CPMnew
                    } else {
                        $dstSafe = New-Safe -url $dstPVWAURL -logonHeader $dstToken -safe $srcSafe
                    }
                    Write-LogMessage -Type Debug -Msg "Created safe `"$safename`""
                    $createdDstSafe = $true
                } catch {
                    Write-LogMessage -Type error -Msg "`tError creating safe `"$safename`""
                    Write-LogMessage -Type Debug -Msg "Error: $_"
                    $SafeStatus.error = $_
                    $process.Completed = $true
                    continue
                }
            } else {
                Write-LogMessage -Type Warning -Msg "`tTarget safe `"$($safename)`" does not exist in destination and creating of safes disabled, skipping `"$($safename)`""
                $SafeStatus.createSkip = $true
                $SafeStatus.success = $true
                continue
            }
        } else {
            Write-LogMessage -Type Debug -Msg "Destination safe  `"$($dstsafe.safename)`" located"
        }
        If (($UpdateSafeMembers -or $createdDstSafe)) {
            $srcSafeMembers = (Get-SafeMembers -url $srcPVWAURL -logonHeader $srcToken -safe $safename).value
            Write-LogMessage -Type Info -Msg "From source safe retrived $($srcSafeMembers.Count) Safe Members"
            $dstSafeMembers = (Get-SafeMembers -url $dstPVWAURL -logonHeader $dstToken -safe $safename).value.membername
            Write-LogMessage -Type Info -Msg "From destination safe retrived $($dstSafeMembers.Count) Safe Members"
            $safememberCount = 0
            ForEach ($srcMember in $srcSafeMembers) {
                $safememberCount += 1
                Try {
                    Write-LogMessage -Type Info -Msg "[$($safememberCount)] Working with Safe Member `"$($srcMember.membername)`" in Safe `"$($safename)`""
                    IF ($srcMember.membername -in $ownersToRemove) {
                        Write-LogMessage -Type Info -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is in the excluded owners list"
                    } Else {
                        if ($srcRemoveDomain) {
                            Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Removing domain from source username `"$($srcMember.membername)`""
                            IF ($srcMember.membername -match '@') {
                                $srcMember.membername = $($($srcMember.membername).Split("@"))[0]
                                Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Updated username to `"$($srcMember.membername)`""
                            } else {
                                Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Username is not in UPN format, no change made"
                            }
                            If (!$([string]::IsNullOrEmpty($dstDomainSuffix))) {
                                Write-LogMessage -type Debug "[$($safememberCount)] New domain suffix of $dstDomainSuffix provided"
                                $srcMember.memberName = "$($srcMember.memberName)@$dstDomainSuffix"
                                Write-LogMessage -type Debug "[$($safememberCount)] Updated username to `"$($srcMember.membername)`""
                            }
                        }
                        if ($srcMember.membername -in $dstSafeMembers -or $("$($srcMember.memberName)@$dstDomainSuffix") -in $dstSafeMembers) {
                            Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is a member of safe `"$($dstsafe.safename)`" attempting to update permissions"
                            Update-SafeMember -url $dstPVWAURL -logonHeader $dstToken -safe $safename -safemember $srcMember | Out-Null
                            Write-LogMessage -Type Info -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" updated on safe `"$($dstsafe.safename)`" succesfully"
                        } else {
                            if ($srcMember.memberId -match "[A-Z]") {
                                Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is from PCloud ISPSS"
                                Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Attempting to add $($srcMember.MemberType) `"$($srcMember.membername)`" to safe `"$($dstsafe.safename)`""
                                try {
                                    $null = New-SafeMember -url $dstPVWAURL -logonHeader $dstToken -safe $safename -safemember $srcMember
                                    
                                    Write-LogMessage -Type Info -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType)  `"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`" succesfully"
                                } catch {
                                    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType)  `"$($srcMember.membername)`" faild to added to safe `"$($dstsafe.safename)`" changing memberType to Role and trying again"
                                    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Removing domain from source username `"$($srcMember.membername)`""
                                    $srcMember.membername = $($($srcMember.membername).Split("@"))[0]
                                    $srcMember.memberType = "Role"
                                    $null = New-SafeMember -url $dstPVWAURL -logonHeader $dstToken -safe $safename -safemember $srcMember
                                    
                                    Write-LogMessage -Type Info -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType)  `"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`" succesfully"
                                }
                            } elseif ($srcMember.memberType -eq "User") {
                                Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is a user, attempting to find source"
                                Try {
                                    $userSource = Get-UserSource -url $srcPVWAURL -logonHeader $srcToken -safemember $srcMember
                                    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" source is `"$userSource`""
                                } Catch {
                                    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Unable to retrieve user source"
                                }
                                IF ([string]::IsNullOrEmpty($newDir)) {
                                    $srcMember | Add-Member NoteProperty searchIn $userSource
                                } else {
                                    Write-LogMessage -type Debug -MSG "New direcory provided, updating `"seachIn`" to `"$newDir`""
                                    $srcMember | Add-Member NoteProperty searchIn $newDir
                                }
                                Write-LogMessage -Type Info -Msg "[$($safememberCount)] Attempting to add user `"$($srcMember.membername)`" to safe `"$($dstsafe.safename)`""
                                $null = New-SafeMember -url $dstPVWAURL -logonHeader $dstToken -safe $safename -safemember $srcMember
                                
                                Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member User`"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`""
                            } elseif ($srcMember.memberType -eq "Group") {
                                Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is a group, attempting to find source"
                                $groupSource = Get-GroupSource -url $srcPVWAURL -logonHeader $srcToken -safemember $srcMember
                                if ($groupSource -eq "Vault") {
                                    $srcMember | Add-Member NoteProperty searchIn "$groupSource"
                                } elseif (![string]::IsNullOrEmpty($newDir)) {
                                    Write-LogMessage -type Debug -MSG "New direcory provided, updating `"seachIn`" to `"$newDir`""
                                    $srcMember | Add-Member NoteProperty searchIn "$newDir"
                                } else {
                                    $srcMember | Add-Member NoteProperty searchIn "$groupSource"
                                }
                                Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" source is `"$groupSource`""
                                Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Attempting to add group `"$($srcMember.membername)`" to safe `"$($dstsafe.safename)`""
                                try {
                                    $null = New-SafeMember -url $dstPVWAURL -logonHeader $dstToken -safe $safename -safemember $srcMember
                                    Write-LogMessage -Type Info -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType)  `"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`" succesfully"
                                } catch {
                                    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType)  `"$($srcMember.membername)`" faild to added to safe `"$($dstsafe.safename)`""
                                    Write-LogMessage -Type Debug -Msg "[$($safememberCount)] Removing domain from source username `"$($srcMember.membername)`" and trying again"
                                    $srcMember.membername = $($($srcMember.membername).Split("@"))[0]
                                    $null = New-SafeMember -url $dstPVWAURL -logonHeader $dstToken -safe $safename -safemember $srcMember
                                    Write-LogMessage -Type Info -Msg "[$($safememberCount)] Safe Member $($srcMember.MemberType)  `"$($srcMember.membername)`" added  to safe `"$($dstsafe.safename)`" succesfully"
                                }
                            } else {
                                Write-LogMessage -Type Error -Msg "[$($safememberCount)] Safe Member `"$($srcMember.membername)`" is a unknown and is being skipped"
                                $SafeStatus.UpdateMembersFail = $true
                            }
                        }
                    }
                } Catch {
                    Write-LogMessage -Type Error -Msg "`t[$($safememberCount)] Failed to add or update Safe Member `"$($srcMember.membername)`" in safe `"$($dstsafe.safename)`""
                    $SafeStatus.UpdateMembersFail = $true
                    $SafeStatus.error = "[$($safememberCount)] $($PSItem.ErrorDetails)"
                    continue
                }
            }
            $SafeStatus.success = $true
        } else {
            Write-LogMessage -Type Info -Msg "Creating and/or Updating of Safe Members is disabled. Memberships of `"$($dstsafe.safename)`" not changed"
            $SafeStatus.success = $true
        }
    } Catch {
        $PSItem
        $SafeStatus.error = $PSItem
    } Finally {
        IF ($SafeStatus.UpdateMembersFail) {
            $SafeStatus.success = $false
        }
    }
}