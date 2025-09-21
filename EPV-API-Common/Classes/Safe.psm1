# Class Safe
# Properties:
# - [string]$SafeName: The name of the safe.
# - [string]$safeUrlId: The URL identifier for the safe.
# - [string]$autoPurgeEnabled: Indicates if auto purge is enabled.
# - [string]$creationTime: The creation time of the safe.
# - [pscustomobject]$creator: The creator of the safe.
# - [string]$description: The description of the safe.
# - [string]$isExpiredMember: Indicates if the safe has expired members.
# - [string]$lastModificationTime: The last modification time of the safe.
# - [string]$location: The location of the safe.
# - [string]$managingCPM: The managing CPM of the safe.
# - [string]$numberOfDaysRetention: The number of days for retention.
# - [string]$numberOfVersionsRetention: The number of versions for retention.
# - [string]$olacEnabled: Indicates if OLAC is enabled.
# - [string]$safeNumber: The number of the safe.
# - [pscustomobject]$accounts: The accounts associated with the safe.
# Methods:
# - [void] Report(): Exports the current instance of the Safe class to a CSV file.
# - Safe(): Default constructor.
# - Safe([pscustomobject]$PSCustom): Constructor that initializes the Safe instance with a PSCustomObject.
# - hidden [void] SetValues([pscustomobject]$PSCustom): Sets the values of the Safe instance properties from a PSCustomObject.
# - hidden [void] ClearValues(): Clears the values of the Safe instance properties.
Using Module .\Base.psm1

Class Safe : Base {
    [string]$SafeName
    [string]$safeUrlId
    [bool]$autoPurgeEnabled
    [string]$creationTime
    [pscustomobject]$creator
    [string]$description
    [bool]$isExpiredMember
    [string]$lastModificationTime
    [string]$location
    [string]$managingCPM
    [string]$numberOfDaysRetention
    [string]$numberOfVersionsRetention
    [bool]$olacEnabled
    [string]$safeNumber
    [pscustomobject]$accounts

    Safe() {}

    Safe([pscustomobject]$PSCustom) : Base([pscustomobject]$PSCustom) {
    }
}
