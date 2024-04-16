using Module .\Logging.psm1


Class TranslateMember : Logging {
    static [hashtable]$MemberIDMap = @{}
    static [hashtable]$LDAPDirectoryMap = @{}

    [void]AddMememberIDMap ($memberID, $memberName, $LDAPFullDN, $LDAPDirectory) {
        IF ([TranslateMember]::memberIDMap.Contains($memberID)) {
            [TranslateMember]::WriteInfo("Member ID `"$memberID`" already exists in memberIDMap hashtable. To update directory entry remove it first")
        }
        else {
            [TranslateMember]::memberIDMap.Add($memberID, [PSCustomObject]@{
                    MemberName    = $MemberName
                    LDAPFullDN    = $LDAPFullDN
                    LDAPDirectory = $LDAPDirectory
                })
        }
    }
    [void]RemoveMememberIDMap ($memberID) {
        IF ([TranslateMember]::memberIDMap.Contains($memberID)) {
            [TranslateMember]::WriteInfo("Member ID `"$memberID`" exists in memberIDMap hashtable")
            [TranslateMember]::memberIDMap.Remove($memberID)
            [TranslateMember]::WriteInfo("Member ID `"$memberID`" remoeved from memberIDMap hashtable")
        }
        else {
            [TranslateMember]::WriteInfo("Member ID `"$memberID`" does not exist in memberIDMap hashtable")
        }
    }

    static [PSCustomObject]TranslateMemberID($memberID) {
        IF ([TranslateMember]::MemberIDMap.Contains($memberID)) {
            return [TranslateMember]::MemberIDMap[$memberID]
        }
        else {
            Throw "Unable to locate MemberID"
        }
    }

    static [void]AddLDAPMap ($ldapDirectory, $MemberSuffix, $searchIn) {
        IF ([TranslateMember]::LDAPDirectoryMap.Contains($ldapDirectory)) {
            [TranslateMember]::WriteInfo("LDAP Directory `"$ldapDirectory`" already exists in LDAPDirectoryMap hashtable. To update directory entry remove it first")
        }
        else {
            [TranslateMember]::LDAPDirectoryMap.Add($ldapDirectory, [PSCustomObject]@{
                    MemberSuffix = $MemberSuffix
                    searchIn     = $searchIn
                })
        }
    }
    static [void]RemoveeLDAPMap ($ldapDirectory, $MemberSuffix, $searchIn) {
        IF ([TranslateMember]::LDAPDirectoryMap.Contains($ldapDirectory)) {
            [TranslateMember]::WriteInfo("LDAP Directory `"$ldapDirectory`" exists in LDAPDirectoryMap hashtable")
            [TranslateMember]::LDAPDirectoryMap.Remove($ldapDirectory)
            [TranslateMember]::WriteInfo("LDAP Directory `"$ldapDirectory`" remoeved from LDAPDirectoryMap hashtable")
        }
        else {
            [TranslateMember]::WriteInfo("LDAP Directory `"$ldapDirectory`" does not exist in LDAPDirectoryMap hashtable")
        }
    }
    static [PSCustomObject]TranslateLDAPDirectory($memberObject) {
        return [TranslateMember]::TranslateLDAPDirectory($memberObject.memberName, $memberObject.LDAPFullDN, $memberObject.LDAPDirectory)
    }

    static [PSCustomObject]TranslateLDAPDirectory($memberName, $LDAPFullDN, $LDAPDirectory) {
        [string]$searchIn = ""
        IF ($memberName -match '@') {
            [TranslateMember]::WriteVerbose("MemberName `"$membername`" contains `"@`", removing suffix")
            $memberName = $($($memberName).Split("@"))[0]
            [TranslateMember]::WriteVerbose("New MemberName is `"$memberName`"")
        }
        IF ([TranslateMember]::LDAPDirectoryMap.Contains($ldapDirectory)) {
            [TranslateMember]::WriteVerbose("Found matching LDAP Directory with name of `"$LDAPDirectory`" in LDAP Directory Map")
            $memberName = "$memberName@$([TranslateMember]::LDAPDirectoryMap[$LDAPDirectory].MemberSuffix)"
            $searchIn = $([TranslateMember]::LDAPDirectoryMap[$LDAPDirectory].SearchIn)
        }
        return [PSCustomObject]@{
            memberName = $memberName
            searchIn   = $searchIn
        }
    }
    static [PSCustomObject]TranslateBothMapping($memberID){ 
        return  [TranslateMember]::TranslateLDAPDirectory([TranslateMember]::TranslateMemberID($memberID))
    }

}