# Input bindings are passed in via param block.
param($Timer)

<#

# Description
    This script helps to dynamically add/remove users and their devices to a corresponding device group, administrative unit and tag the devices in defender based on user groups.
    This can be used to automate scope tags, delegated permissions and more.

# Make sure to update the following variables before running:
    Name = RunLevel
    Value = "Debug" or "Prod" - Debug wont make any changes to the groups. Prod will make changes.

    Name = RunAdminUnits
    Value = $true or $false - $true will run the administrative units feature, $false will not.

    Name = RunDefender
    Value = $true or $false - $true will run the defender feature, $false will not.

    Name = UserGroupNames
    Value = "DUDE Users" - Example

    Name = DeviceGroupNames
    Value = "DUDE Devices" - Example

    Name = AdminUnitNames
    Value = "DUDE" - Example

# Groups and Admin Units naming requirements:
    It's critical that the user and device group names and the administrative unit names are consistent and have a matching ending.
    If you enter the following variables:
        Name = UserGroupNames
        Value = DUDE Users

        Name = DeviceGroupNames
        Value = DUDE Devices

        Name = AdminUnitNames
        Value = DUDE

    All your user group names should start with "DUDE Users", all your device group names should start with "DUDE Devices" and all your administrative units should start with "DUDE".
    Whatever you choose to put after this in the group names have to match between the three.

.Example
    User Group Names:
        DUDE Users Rock
        DUDE Users Metal

    Device Group Names:
        DUDE Devices Rock
        DUDE Devices Metal

    Admin Unit Names:
        DUDE Rock
        DUDE Metal

# Release Notes
    1.0 - 2021-10-16 - Initial version
    2.0 - 2021-11-16 - Matching users devices based on registeredOwner from Azure AD devices and fallback to userPrincipalName from Intune managedDevices
    3.0 - 2021-11-17 - Added DeviceFilter to be able to choose between including all Intune and Azure AD devices or all Intune and only Managed Azure AD devices.
    4.0 - 2022-06-27 - Updated devices to add and devices to remove filter.
    5.0 - 2022-06-28 - Updated devices to add and devices to remove filter.
    6.0 - 2023-03-20 - PrimaryUser will only be gathered from Intune.
    7.0 - 2023-05-08 - Added support for administrative units.
    8.0 - 2023-05-11 - Added support for machine tags in defender and variables RunAdminUnits and RunDefender to select if these features are supposed to run or not.

#>

#region Variables
$RunLevel = "Debug"
$RunAdminUnits = $true
$RunDefender = $true
$UserGroupNames = "DUDE Users"
$DeviceGroupNames = "DUDE Devices"
$AdminUnitNames = "DUDE"
#endregion

#region Functions
function Get-GraphAccessToken {
    try {
        $ResourceURI = "https://graph.microsoft.com/"
        $TokenAuthURI = $env:IDENTITY_ENDPOINT + "?resource=$ResourceURI&api-version=2019-08-01"
        $TokenResponse = Invoke-RestMethod -Method Get -Headers @{"X-IDENTITY-HEADER" = "$env:IDENTITY_HEADER" } -Uri $TokenAuthURI -ErrorAction Stop
        $GraphAccessToken = @{ "Authorization" = "Bearer $($TokenResponse.access_token)" }
        return $GraphAccessToken
    }
    catch {
        Write-Error $_.Exception
    }
}

function Get-DefenderAccessToken {
    try {
        $ResourceURI = "https://api.securitycenter.windows.com/"
        $TokenAuthURI = $env:IDENTITY_ENDPOINT + "?resource=$ResourceURI&api-version=2019-08-01"
        $TokenResponse = Invoke-RestMethod -Method Get -Headers @{"X-IDENTITY-HEADER" = "$env:IDENTITY_HEADER" } -Uri $TokenAuthURI -ErrorAction Stop
        $DefenderAccessToken = @{ "Authorization" = "Bearer $($TokenResponse.access_token)" }
        return $DefenderAccessToken
    }
    catch {
        Write-Error $_.Exception
    }
}

function Invoke-GraphCall {
    [cmdletbinding()]
    param (
        [parameter(Mandatory = $false)]
        [ValidateSet('Get', 'Post', 'Delete')]
        [string]$Method = 'Get',

        [parameter(Mandatory = $false)]
        [hashtable]$GraphAccessToken = $script:GraphAccessToken,

        [parameter(Mandatory = $true)]
        [string]$Uri,

        [parameter(Mandatory = $false)]
        [string]$ContentType = 'Application/Json',

        [parameter(Mandatory = $false)]
        [hashtable]$Body
    )
    try {
        $params = @{
            Method      = $Method
            Headers     = $GraphAccessToken
            Uri         = $Uri
            ContentType = $ContentType
        }
        if ($Body) {
            $params.Body = $Body | ConvertTo-Json -Depth 20
        }
        if ($Method -eq "Get") {
            $request = Invoke-RestMethod @params
            $pages = $request.'@odata.nextLink'
            while ($null -ne $pages) {
                $addtional = Invoke-RestMethod -Method Get -Uri $pages -Headers $GraphAccessToken
                if ($pages) {
                    $pages = $addtional."@odata.nextLink"
                }
                $request.value += $addtional.value
            }
            return $request
        }
        else {
            $request = Invoke-RestMethod @params
            return $request
        }
    }
    catch {
        Write-Warning $_.Exception.Message
    }
}

function Invoke-DefenderCall {
    [cmdletbinding()]
    param (
        [parameter(Mandatory = $false)]
        [ValidateSet('Get', 'Post', 'Delete')]
        [string]$Method = 'Get',

        [parameter(Mandatory = $false)]
        [hashtable]$DefenderAccessToken = $script:DefenderAccessToken,

        [parameter(Mandatory = $true)]
        [string]$Uri,

        [parameter(Mandatory = $false)]
        [string]$ContentType = 'Application/Json',

        [parameter(Mandatory = $false)]
        [hashtable]$Body
    )
    try {
        $params = @{
            Method      = $Method
            Headers     = $DefenderAccessToken
            Uri         = $Uri
            ContentType = $ContentType
        }
        if ($Body) {
            $params.Body = $Body | ConvertTo-Json -Depth 20
        }
        if ($Method -eq "Get") {
            $request = Invoke-RestMethod @params
            $pages = $request.'@odata.nextLink'
            while ($null -ne $pages) {
                $addtional = Invoke-RestMethod -Method Get -Uri $pages -Headers $DefenderAccessToken
                if ($pages) {
                    $pages = $addtional."@odata.nextLink"
                }
                $request.value += $addtional.value
            }
            return $request
        }
        else {
            $request = Invoke-RestMethod @params
            return $request
        }
    }
    catch {
        Write-Warning $_.Exception.Message
    }
}
#endregion

#region Get GraphAccessToken
$script:GraphAccessToken = Get-GraphAccessToken
#endregion

#region Get DefenderAccessToken
if ($RunDefender) {
    $script:DefenderAccessToken = Get-DefenderAccessToken
}
#endregion

#region get AllUserGroups
$AllUserGroups = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/groups?`$filter=startswith(displayName,'$($UserGroupNames)')&`$select=id,displayName").value
if ($AllUserGroups.id.Count -eq "0") {
    Write-Error "Could not get AllUserGroups" -ErrorAction Stop
}
Write-Output "AllUserGroups = $($AllUserGroups.id.Count)"
#endregion

#region get AllDeviceGroups
$AllDeviceGroups = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/groups?`$filter=startswith(displayName,'$($DeviceGroupNames)')&`$select=id,displayName").value
if ($AllDeviceGroups.id.Count -eq "0") {
    Write-Error "Could not get AllDeviceGroups" -ErrorAction Stop
}
Write-Output "AllDeviceGroups = $($AllDeviceGroups.id.Count)"
#endregion

#region get AllManagedDevicesWithAADObjectTable
$AllManagedDevices = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$select=id,deviceName,userPrincipalName,azureADDeviceId").value
if ($AllManagedDevices.id.Count -eq "0") {
    Write-Error "Could not get AllManagedDevices" -ErrorAction Stop
}
Write-Output "AllManagedDevices = $($AllManagedDevices.id.Count)"
$AllManagedDevicesWithAADObject = $AllManagedDevices | Where-Object { $_.azureADDeviceId -ne "00000000-0000-0000-0000-000000000000" }
if ($AllManagedDevicesWithAADObject.id.Count -eq "0") {
    Write-Error "Could not get AllManagedDevicesWithAADObject" -ErrorAction Stop
}
Write-Output "AllManagedDevicesWithAADObject = $($AllManagedDevicesWithAADObject.id.Count)"
$AllManagedDevicesWithAADObjectTable = foreach ($Device in $AllManagedDevicesWithAADObject) {
    [PSCustomObject][Ordered]@{
        MdmDeviceId = $Device.id
        AadDeviceId = $Device.azureADDeviceId
        DeviceName  = $Device.deviceName
        EnrolledBy  = $Device.userPrincipalName
        PrimaryUser = $null
    }
}
if ($AllManagedDevicesWithAADObjectTable.MdmDeviceId.Count -eq "0") {
    Write-Error "Could get AllManagedDevicesWithAADObjectTable" -ErrorAction Stop
}
Remove-Variable AllManagedDevices, AllManagedDevicesWithAADObject
Write-Output "AllManagedDevicesWithAADObjectTable = $($AllManagedDevicesWithAADObjectTable.MdmDeviceId.Count)"
#endregion

#region get AllPrimaryUsers
$AllPrimaryUsers = @()
$Count = 0
do {
    $Results = @()
    $Batch = [System.Collections.ArrayList]@()
    $AllManagedDevicesWithAADObjectTable | Select-Object -First 20 -Skip $Count | Foreach-Object {
        $Object = [ordered]@{
            "id"     = $_.MdmDeviceId
            "method" = "GET"
            "url"    = "/deviceManagement/managedDevices/$($_.MdmDeviceId)/Users?`$select=userPrincipalName"
        }
        $Batch.Add($Object) | Out-Null
        $Count++
    }
    $Body = @{
        "requests" = $Batch
    }
    $Results = (Invoke-GraphCall -Method "POST" -Uri "https://graph.microsoft.com/beta/`$batch" -Body $Body).responses
    $AllPrimaryUsers += $Results | Where-Object { $_.body.error -eq $null }
    $FailedRequests = $Results | Where-Object { (($_.body.error -ne $null) -and ($_.body.error.code -ne "ResourceNotFound")) }
    if ($FailedRequests.id.Count -ge 1) {
        Write-Error "AllPrimaryUsers batching failed" -ErrorAction Stop
    }
} until ($Count -eq $AllManagedDevicesWithAADObjectTable.MdmDeviceId.Count)
$AllPrimaryUsers = $AllPrimaryUsers | Where-Object { $_.body.value.userPrincipalName -ne $null }
if ($AllPrimaryUsers.body.value.userPrincipalName.Count -eq "0") {
    Write-Error "Could not get AllPrimaryUsers" -ErrorAction Stop
}
Write-Output "AllPrimaryUsers = $($AllPrimaryUsers.PrimaryUser.Count)"
#endregion

#region create AllPrimaryUsersHash
$AllPrimaryUsersHash = @{}
foreach ($User in $AllPrimaryUsers) {
    $AllPrimaryUsersHash.Add($User.id, $User.body.value)
}
if ($AllPrimaryUsersHash.Count -eq "0") {
    Write-Error "Could not create AllPrimaryUsersHash" -ErrorAction Stop
}
Remove-Variable AllPrimaryUsers
Write-Output "AllPrimaryUsersHash = $($AllPrimaryUsersHash.Count)"
#region

#region get AllManagedDevicesWithAADObjectAndPrimaryUser
$AllManagedDevicesWithAADObjectAndPrimaryUser = foreach ($Device in $AllManagedDevicesWithAADObjectTable) {
    if ($AllPrimaryUsersHash.ContainsKey($Device.MdmDeviceId)) {
        $Device.PrimaryUser = $AllPrimaryUsersHash[$Device.MdmDeviceId].userPrincipalName
        $Device
    }
}
if ($AllManagedDevicesWithAADObjectAndPrimaryUser.MdmDeviceId.Count -eq "0") {
    Write-Error "Could not get AllManagedDevicesWithAADObjectAndPrimaryUser" -ErrorAction Stop
}
Remove-Variable AllPrimaryUsersHash, AllManagedDevicesWithAADObjectTable
Write-Output "AllManagedDevicesWithAADObjectAndPrimaryUser = $($AllManagedDevicesWithAADObjectAndPrimaryUser.MdmDeviceId.Count)"
#endregion

#region get AllAdminUnits
if ($RunAdminUnits) {
    $AllAdminUnits = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/administrativeUnits?`$filter=startswith(displayName,'$($AdminUnitNames)')&`$select=id,displayName").value
    if ($AllAdminUnits.id.Count -eq "0") {
        Write-Error "Could not get AllAdminUnits" -ErrorAction Stop
    }
    Write-Output "AllAdminUnits = $($AllAdminUnits.id.Count)"
}
#endregion

#region get AllUniqueDefenderOnboardedDevicesWithAADObjectTable
if ($RunDefender) {
    $AllDefenderOnboardedDevices = (Invoke-DefenderCall -Uri "https://api-eu.securitycenter.windows.com/api/machines?`$filter=onboardingStatus eq 'Onboarded'&`$Select=id,computerDnsName,aadDeviceId,machineTags,lastSeen").Value
    if ($AllDefenderOnboardedDevices.id.Count -eq "0") {
        Write-Error "Could not get AllDefenderOnboardedDevices" -ErrorAction Stop
    }
    Write-Output "AllDefenderOnboardedDevices = $($AllDefenderOnboardedDevices.id.Count)"
    $AllDefenderOnboardedDevicesWithAADObject = $AllDefenderOnboardedDevices | Where-Object { $_.aadDeviceId -ne $null }
    if ($AllDefenderOnboardedDevicesWithAADObject.id.Count -eq "0") {
        Write-Error "Could not get AllDefenderOnboardedDevicesWithAADObject" -ErrorAction Stop
    }
    Write-Output "AllDefenderOnboardedDevicesWithAADObject = $($AllDefenderOnboardedDevicesWithAADObject.id.Count)"
    $AllUniqueDefenderOnboardedDevicesWithAADObjectTable = @()
    foreach ($Device in $AllDefenderOnboardedDevicesWithAADObject) {
        if ($AllUniqueDefenderOnboardedDevicesWithAADObjectTable.AadDeviceId -notcontains $Device.AadDeviceId) {
            $AllUniqueDefenderOnboardedDevicesWithAADObjectTable += [PSCustomObject][Ordered]@{
                Id          = $Device.id
                AadDeviceId = $Device.aadDeviceId
                DeviceName  = $Device.computerDnsName
                LastSeen    = $Device.lastSeen
                Tag         = $Device.machineTags
            }
        }
    }
    if ($AllUniqueDefenderOnboardedDevicesWithAADObjectTable.Id.Count -eq "0") {
        Write-Error "Could get AllDefenderOnboardedDevicesWithAADObjectTable" -ErrorAction Stop
    }
    Remove-Variable AllDefenderOnboardedDevices, AllDefenderOnboardedDevicesWithAADObject
    Write-Output "AllUniqueDefenderOnboardedDevicesWithAADObjectTable = $($AllUniqueDefenderOnboardedDevicesWithAADObjectTable.MdmDeviceId.Count)"
}
#endregion

#region Manage groups
$GroupCount = 0
foreach ($UserGroup in $AllUserGroups) {
    $GroupCount++
    Write-Output "Running Group $($GroupCount) of $($AllUserGroups.id.count) = `"$($UserGroup.displayName)`""

    # Get usergroup members
    $UserGroupMembers = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/groups/$($UserGroup.id)/members?`$select=id,userPrincipalName").value
    if ($UserGroupMembers.id.Count -eq "0") {
        Write-Output "Could not find any UserGroupMembers in `"$($UserGroup.displayName)`""
    }
    else {
        # Get usergroup members managed devices
        $UserGroupMembersManagedDevices = $AllManagedDevicesWithAADObjectAndPrimaryUser | Where-Object { $UserGroupMembers.UserPrincipalName -contains $_.PrimaryUser }
        if ($UserGroupMembersManagedDevices.id.Count -eq "0") {
            Write-Output "Could not find any UserGroupMembersManagedDevices"
        }
        else {
            # Get matching device group
            $DeviceGroup = $AllDeviceGroups | Where-Object { $_.DisplayName -eq ($UserGroup.displayName -replace $UserGroupNames, $DeviceGroupNames) }
            if ($DeviceGroup.id.count -eq "0") {
                Write-Error "Could not find any matching device group" -ErrorAction Continue
            }
            else {
                # Get devicegroup members
                $DeviceGroupMembers = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/groups/$($DeviceGroup.id)/members?`$select=id,deviceId").value

                # Remove nested groups
                $DeviceGroupMembers = $DeviceGroupMembers | Where-Object { $_.'@odata.type' -ne "#microsoft.graph.group" }

                # Get devices to add to device group
                $DevicesToAddToDeviceGroup = $UserGroupMembersManagedDevices | Where-Object { $DeviceGroupMembers.deviceId -notcontains $_.AadDeviceId }

                # Get devices to remove from device group
                $DevicesToRemoveFromDeviceGroup = $DeviceGroupMembers | Where-Object { ($UserGroupMembersManagedDevices.AadDeviceId -notcontains $_.deviceId) -and ($DevicesToAddToDeviceGroup.AadDeviceId -notcontains $_.deviceId) }

                # Add devices to device group
                $DeviceCount = 0
                foreach ($Device in $DevicesToAddToDeviceGroup) {
                    $DeviceCount++
                    try {
                        $DeviceToAddInfo = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/devices?`$filter=DeviceID eq '$($Device.AadDeviceId)'&`$select=id,displayName").value
                        if ($DeviceToAddInfo.id.count -eq "1") {
                            if ($RunLevel -eq "Prod") {
                                $Body = @{"@odata.id" = "https://graph.microsoft.com/beta/devices/$($DeviceToAddInfo.id)" }
                                Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/groups/$($DeviceGroup.id)/members/`$ref" -Method POST -Body $Body | Out-Null
                                Write-Output "Device Group (Device $($DeviceCount) of $($DevicesToAddToDeviceGroup.AadDeviceId.count)) Added `"$($DeviceToAddInfo.displayName)`" to `"$($DeviceGroup.displayName)`""
                            }
                            elseif ($RunLevel -eq "Debug") {
                                Write-Output "Device Group (Device $($DeviceCount) of $($DevicesToAddToDeviceGroup.AadDeviceId.count)) Would add `"$($DeviceToAddInfo.displayName)`" to `"$($DeviceGroup.displayName)`""
                            }
                            else {
                                Write-Error "Please specify RunLevel and try again" -ErrorAction Stop
                            }
                        }
                        else {
                            Write-Warning "Device Group (Device $($DeviceCount) of $($DevicesToAddToDeviceGroup.AadDeviceId.count)) Could not find `"$($Device.DeviceName)`" with AadDeviceId `"$($Device.AadDeviceId)`" in Azure AD"
                        }
                    }
                    catch {
                        Write-Error "Device Group (Device $($DeviceCount) of $($DevicesToAddToDeviceGroup.AadDeviceId.count)) Could not add `"$($Device.DeviceName)`" to `"$($DeviceGroup.displayName)`"" -ErrorAction Continue
                    }
                }

                # Remove devices from device group
                $DeviceCount = 0
                foreach ($Device in $DevicesToRemoveFromDeviceGroup) {
                    $DeviceCount++
                    try {
                        $DeviceToRemoveInfo = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/devices?`$filter=id eq '$($Device.id)'&`$select=id,displayName").value
                        if ($RunLevel -eq "Prod") {
                            Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/groups/$($DeviceGroup.id)/members/$($DeviceToRemoveInfo.id)/`$ref" -Method Delete | Out-Null
                            Write-Output "Device Group (Device $($DeviceCount) of $($DevicesToRemoveFromDeviceGroup.id.count)) Removed `"$($DeviceRemoveInfo.displayName)`" from `"$($DeviceGroup.displayName)`""
                        }
                        elseif ($RunLevel -eq "Debug") {
                            Write-Output "Device Group (Device $($DeviceCount) of $($DevicesToRemoveFromDeviceGroup.id.count)) Would remove `"$($DeviceToRemoveInfo.displayName)`" from `"$($DeviceGroup.displayName)`""
                        }
                        else {
                            Write-Error "Please specify RunLevel and try again" -ErrorAction Stop
                        }
                    }
                    catch {
                        Write-Error "Device Group (Device $($DeviceCount) of $($DevicesToRemoveFromDeviceGroup.id.count)) Could not remove `"$($DeviceToRemoveInfo.displayName)`" from `"$($DeviceGroup.displayName)`"" -ErrorAction Continue
                    }
                }

                if ($RunAdminUnits) {
                    # Get matching admin unit
                    $AdminUnit = $AllAdminUnits | Where-Object { $_.DisplayName -eq ($UserGroup.displayName -replace $UserGroupNames, $AdminUnitNames) }
                    if ($AdminUnit.id.count -eq "0") {
                        Write-Error "Could not find any matching admin unit" -ErrorAction Continue
                    }
                    else {
                        # Get admin unit members
                        $AdminUnitMembers = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/administrativeUnits/$($AdminUnit.id)/members?`$select=id,userPrincipalName,deviceId,displayName").value
                        $AdminUnitUserMembers = $AdminUnitMembers | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.user" }
                        $AdminUnitDeviceMembers = $AdminUnitMembers | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.device" }
                        Remove-Variable AdminUnitMembers

                        # Get users to add to admin unit
                        $UsersToAddToAdminUnit = $UserGroupMembers | Where-Object { $AdminUnitUserMembers.userPrincipalName -notcontains $_.userPrincipalName }

                        # Get users to remove from admin unit
                        $UsersToRemoveFromAdminUnit = $AdminUnitUserMembers | Where-Object { ($UserGroupMembers.userPrincipalName -notcontains $_.userPrincipalName) -and ($UsersToAddToAdminUnit.userPrincipalName -notcontains $_.userPrincipalName) }

                        # Add users to admin unit
                        $AdminUnitUserCount = 0
                        foreach ($User in $UsersToAddToAdminUnit) {
                            $AdminUnitUserCount++
                            try {
                                if ($RunLevel -eq "Prod") {
                                    $Body = @{"@odata.id" = "https://graph.microsoft.com/beta/users/$($User.id)" }
                                    Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/administrativeUnits/$($AdminUnit.id)/members/`$ref" -Method POST -Body $Body | Out-Null
                                    Write-Output "Admin Unit (User $($AdminUnitUserCount) of $($UsersToAddToAdminUnit.id.count)) Added `"$($User.userPrincipalName)`" to `"$($AdminUnit.displayName)`""
                                }
                                elseif ($RunLevel -eq "Debug") {
                                    Write-Output "Admin Unit (User $($AdminUnitUserCount) of $($UsersToAddToAdminUnit.id.count)) Would add `"$($User.userPrincipalName)`" to `"$($AdminUnit.displayName)`""
                                }
                                else {
                                    Write-Error "Please specify RunLevel and try again" -ErrorAction Stop
                                }
                            }
                            catch {
                                Write-Error "Admin Unit (User $($AdminUnitUserCount) of $($UsersToAddToAdminUnit.id.count)) Could not add `"$($User.userPrincipalName)`" to `"$($AdminUnit.displayName)`"" -ErrorAction Continue
                            }
                        }

                        # Remove users from admin unit
                        $AdminUnitUserCount = 0
                        foreach ($User in $UsersToRemoveFromAdminUnit) {
                            $AdminUnitUserCount++
                            try {
                                if ($RunLevel -eq "Prod") {
                                    Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/administrativeUnits/$($AdminUnit.id)/members/$($User.id)/`$ref" -Method Delete | Out-Null
                                    Write-Output "Admin Unit (User $($AdminUnitUserCount) of $($UsersToRemoveFromAdminUnit.id.count)) Removed `"$($User.userPrincipalName)`" from `"$($AdminUnit.displayName)`""
                                }
                                elseif ($RunLevel -eq "Debug") {
                                    Write-Output "Admin Unit (User $($AdminUnitUserCount) of $($UsersToRemoveFromAdminUnit.id.count)) Would remove `"$($User.userPrincipalName)`" from `"$($AdminUnit.displayName)`""
                                }
                                else {
                                    Write-Error "Please specify RunLevel and try again" -ErrorAction Stop
                                }
                            }
                            catch {
                                Write-Error "Admin Unit (User $($AdminUnitUserCount) of $($UsersToRemoveFromAdminUnit.id.count)) Could not remove `"$($User.userPrincipalName)`" from `"$($AdminUnit.displayName)`"" -ErrorAction Continue
                            }
                        }

                        # Get devices to add to admin unit
                        $DevicesToAddToAdminUnit = $UserGroupMembersManagedDevices | Where-Object { $AdminUnitDeviceMembers.deviceId -notcontains $_.AadDeviceId }

                        # Get devices to remove from admin unit
                        $DevicesToRemoveFromAdminUnit = $AdminUnitDeviceMembers | Where-Object { ($UserGroupMembersManagedDevices.AadDeviceId -notcontains $_.deviceId) -and ($DevicesToAddToAdminUnit.AadDeviceId -notcontains $_.deviceId) }

                        # Add devices to admin unit
                        $DeviceCount = 0
                        foreach ($Device in $DevicesToAddToAdminUnit) {
                            $DeviceCount++
                            try {
                                $DeviceToAddInfo = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/devices?`$filter=DeviceID eq '$($Device.AadDeviceId)'&`$select=id,displayName").value
                                if ($DeviceToAddInfo.id.count -eq "1") {
                                    if ($RunLevel -eq "Prod") {
                                        $Body = @{"@odata.id" = "https://graph.microsoft.com/beta/devices/$($DeviceToAddInfo.id)" }
                                        Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/administrativeUnits/$($AdminUnit.id)/members/`$ref" -Method POST -Body $Body | Out-Null
                                        Write-Output "Admin Unit (Device $($DeviceCount) of $($DevicesToAddToAdminUnit.AadDeviceId.count)) Added `"$($DeviceToAddInfo.displayName)`" to `"$($AdminUnit.displayName)`""
                                    }
                                    elseif ($RunLevel -eq "Debug") {
                                        Write-Output "Admin Unit (Device $($DeviceCount) of $($DevicesToAddToAdminUnit.AadDeviceId.count)) Would add `"$($DeviceToAddInfo.displayName)`" to `"$($AdminUnit.displayName)`""
                                    }
                                    else {
                                        Write-Error "Please specify RunLevel and try again" -ErrorAction Stop
                                    }
                                }
                                else {
                                    Write-Warning "Admin Unit (Device $($DeviceCount) of $($DevicesToAddToAdminUnit.AadDeviceId.count)) Could not find `"$($Device.DeviceName)`" with AadDeviceId `"$($Device.AadDeviceId)`" in Azure AD"
                                }
                            }
                            catch {
                                Write-Error "Admin Unit (Device $($DeviceCount) of $($DevicesToAddToAdminUnit.AadDeviceId.count)) Could not add `"$($Device.DeviceName)`" to `"$($AdminUnit.displayName)`"" -ErrorAction Continue
                            }
                        }

                        # Remove devices from admin unit
                        $DeviceCount = 0
                        foreach ($Device in $DevicesToRemoveFromAdminUnit) {
                            $DeviceCount++
                            try {
                                $DeviceToRemoveInfo = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/devices?`$filter=id eq '$($Device.id)'&`$select=id,displayName").value
                                if ($RunLevel -eq "Prod") {
                                    Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/administrativeUnits/$($AdminUnit.id)/members/$($DeviceToRemoveInfo.id)/`$ref" -Method Delete | Out-Null
                                    Write-Output "Admin Unit (Device $($DeviceCount) of $($DevicesToRemoveFromAdminUnit.id.count)) Removed `"$($DeviceRemoveInfo.displayName)`" from `"$($AdminUnit.displayName)`""
                                }
                                elseif ($RunLevel -eq "Debug") {
                                    Write-Output "Admin Unit (Device $($DeviceCount) of $($DevicesToRemoveFromAdminUnit.id.count)) Would remove `"$($DeviceRemoveInfo.displayName)`" from `"$($AdminUnit.displayName)`""
                                }
                                else {
                                    Write-Error "Please specify RunLevel and try again" -ErrorAction Stop
                                }
                            }
                            catch {
                                Write-Error "Admin Unit (Device $($DeviceCount) of $($DevicesToRemoveFromAdminUnit.id.count)) Could not remove `"$($DeviceRemoveInfo.displayName)`" from `"$($AdminUnit.displayName)`"" -ErrorAction Continue
                            }
                        }
                    }
                }
                if ($RunDefender) {
                    # Get Defender Tag
                    $DefenderTag = ($DeviceGroup.displayName -replace $DeviceGroupNames).TrimStart(" ")

                    # Get devices to tag in defender
                    $DevicesToAddTagToInDefender = $AllUniqueDefenderOnboardedDevicesWithAADObjectTable | Where-Object { (($UserGroupMembersManagedDevices.AadDeviceId -contains $_.AadDeviceId) -and ($_.Tag -notcontains $DefenderTag)) }

                    # Get devices to remove tag from in defender
                    $DevicesToRemoveTagFromInDefender = $AllUniqueDefenderOnboardedDevicesWithAADObjectTable | Where-Object { (($UserGroupMembersManagedDevices.AadDeviceId -notcontains $_.AadDeviceId) -and ($_.Tag -contains $DefenderTag)) }

                    # Tag devices in defender
                    $DeviceCount = 0
                    foreach ($Device in $DevicesToAddTagToInDefender) {
                        $DeviceCount++
                        try {
                            if ($RunLevel -eq "Prod") {
                                $Body = @{
                                    "Value"  = $DefenderTag;
                                    "Action" = "Add";
                                }
                                Invoke-DefenderCall -Uri "https://api.securitycenter.windows.com/api/machines/$($Device.Id)/tags" -Method POST -Body $Body | Out-Null
                                Write-Output "Defender (Device $($DeviceCount) of $($DevicesToAddTagToInDefender.Id.count)) Added `"$($DefenderTag)`" to `"$($Device.DeviceName)`""
                            }
                            elseif ($RunLevel -eq "Debug") {
                                Write-Output "Defender (Device $($DeviceCount) of $($DevicesToAddTagToInDefender.Id.count)) Would add `"$($DefenderTag)`" to `"$($Device.DeviceName)`""
                            }
                            else {
                                Write-Error "Please specify RunLevel and try again" -ErrorAction Stop
                            }
                        }
                        catch {
                            Write-Error "Defender (Device $($DeviceCount) of $($DevicesToAddTagToInDefender.Id.count)) Could not add `"$($DefenderTag)`" to `"$($Device.DeviceName)`"" -ErrorAction Continue
                        }
                    }

                    # Remove tag from devices in defender
                    $DeviceCount = 0
                    foreach ($Device in $DevicesToRemoveTagFromInDefender) {
                        $DeviceCount++
                        try {
                            if ($RunLevel -eq "Prod") {
                                $Body = @{
                                    "Value"  = $DefenderTag;
                                    "Action" = "Remove";
                                }
                                Invoke-DefenderCall -Uri "https://api.securitycenter.windows.com/api/machines/$($Device.Id)/tags" -Method POST -Body $Body | Out-Null
                                Write-Output "Defender (Device $($DeviceCount) of $($DevicesToRemoveTagFromInDefender.Id.count)) Removed `"$($DefenderTag)`" from `"$($Device.DeviceName)`""
                            }
                            elseif ($RunLevel -eq "Debug") {
                                Write-Output "Defender (Device $($DeviceCount) of $($DevicesToRemoveTagFromInDefender.Id.count)) Would remove `"$($DefenderTag)`" from `"$($Device.DeviceName)`""
                            }
                            else {
                                Write-Error "Please specify RunLevel and try again" -ErrorAction Stop
                            }
                        }
                        catch {
                            Write-Error "Defender (Device $($DeviceCount) of $($DevicesToRemoveTagFromInDefender.Id.count)) Could not remove `"$($DefenderTag)`" from `"$($Device.DeviceName)`"" -ErrorAction Continue
                        }
                    }
                }
            }
        }
    }
}
#endregion