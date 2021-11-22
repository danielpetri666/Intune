<#

# Description
    This script helps to dynamically add/remove users devices to a corresponding device group based on user groups.
    This can be used to automate scope tags among other things.

# Make sure to update the following custom variables before running:
    $UserGroupNames = ""
    $DeviceGroupNames = ""

# User and device group names
    It's critical that the user and device group names are consistent and have a matching ending.
    If you enter the following Custom Variables:
        $UserGroupNames = "Endpoint-DUDE Users"
        $DeviceGroupNames = "Endpoint-DUDE Devices"
    
    All your user group names should start with "Endpoint-DUDE Users" and all your device group names should start with "Endpoint-DUDE Devices".
    Whatever you choose to put after this in the group names have to match between the two.

.Example
    User Group Names:
        Endpoint-DUDE Users HR
        Endpoint-DUDE Users IT
        Endpoint-DUDE Users Sweden
        Endpoint-DUDE Users North Europe

    Device Group Names:
        Endpoint-DUDE Devices HR
        Endpoint-DUDE Devices IT
        Endpoint-DUDE Devices Sweden
        Endpoint-DUDE Devices North Europe

# Release Notes
    2.0 - 2021-10-10 - Changed from client secret to managed identity
    1.0 - 2021-10-09 - Initial version

#>

# Custom Variables
Write-Output "Loading Custom Variables..."
$UserGroupNames = ""
$DeviceGroupNames = ""
Write-Output "Custom Variables loaded"

# Global Variables
Write-Output "Loading Global Variables..."
$GraphVersion = "beta"
$GraphHost = "https://graph.microsoft.com"
Write-Output "Global Variables loaded"

# Get AccessToken for Microsoft Graph via the managed identity
Write-Output "Retrieving AccessToken..."
try {
    $response = [System.Text.Encoding]::Default.GetString((Invoke-WebRequest -UseBasicParsing -Uri "$($env:IDENTITY_ENDPOINT)?resource=$GraphHost" -Method 'GET' -Headers @{'X-IDENTITY-HEADER' = "$env:IDENTITY_HEADER"; 'Metadata' = 'True' }).RawContentStream.ToArray()) | ConvertFrom-Json 
    $AccessToken = $response.access_token 
    Write-Output "AccessToken retrieved"
}
catch {
    Write-Error "Could not retrieve AccessToken" -ErrorAction Stop
}

# Get AllManagedDevices
Write-Output "Loading AllManagedDevices..."
$AllManagedDevices = Invoke-RestMethod -Method Get -uri "$GraphHost/$GraphVersion/deviceManagement/managedDevices" -Headers @{Authorization = "Bearer $AccessToken" }
$Total = @()
$Pages = @()
$Addtional = @()
$Total = $AllManagedDevices.value
$Pages = $AllManagedDevices.'@odata.nextLink'
while ($null -ne $Pages) {
    $Addtional = Invoke-RestMethod -Method Get -Uri $Pages -Headers @{Authorization = "Bearer $AccessToken" }
    if ($Pages) {
        $Pages = $Addtional."@odata.nextLink"
    }
    $Total += $Addtional.value
}
$AllManagedDevices = $Total | Select-Object id, deviceName, userPrincipalName, azureADDeviceId
Write-Output "Found $($AllManagedDevices.id.count) AllManagedDevices"
if ($AllManagedDevices.id.count -eq "0") {
    Write-Error "Could not load AllManagedDevices" -ErrorAction Stop
}

# Get AllUserGroups
Write-Output "Loading AllUserGroups..."
$AllUserGroups = Invoke-RestMethod -Method Get -uri "$GraphHost/$GraphVersion/groups?`$filter=startswith(displayName,'$($UserGroupNames)')" -Headers @{Authorization = "Bearer $AccessToken" }
$Total = @()
$Pages = @()
$Addtional = @()
$Total = $AllUserGroups.value
$Pages = $AllUserGroups.'@odata.nextLink'
while ($null -ne $Pages) {
    $Addtional = Invoke-RestMethod -Method Get -Uri $Pages -Headers @{Authorization = "Bearer $AccessToken" }
    if ($Pages) {
        $Pages = $Addtional."@odata.nextLink"
    }
    $Total += $Addtional.value
}
$AllUserGroups = $Total | Select-Object id, displayName
Write-Output "Found $($AllUserGroups.id.count) AllUserGroups"
if ($AllUserGroups.id.count -eq "0") {
    Write-Error "Could not load AllUserGroups" -ErrorAction Stop
}

# Get AllDeviceGroups
Write-Output "Loading AllDeviceGroups..."
$AllDeviceGroups = Invoke-RestMethod -Method Get -uri "$GraphHost/$GraphVersion/groups?`$filter=startswith(displayName,'$($DeviceGroupNames)')" -Headers @{Authorization = "Bearer $AccessToken" }
$Total = @()
$Pages = @()
$Addtional = @()
$Total = $AllDeviceGroups.value
$Pages = $AllDeviceGroups.'@odata.nextLink'
while ($null -ne $Pages) {
    $Addtional = Invoke-RestMethod -Method Get -Uri $Pages -Headers @{Authorization = "Bearer $AccessToken" }
    if ($Pages) {
        $Pages = $Addtional."@odata.nextLink"
    }
    $Total += $Addtional.value
}
$AllDeviceGroups = $Total | Select-Object id, displayName
Write-Output "Found $($AllDeviceGroups.id.count) AllDeviceGroups"
if ($AllDeviceGroups.id.count -eq "0") {
    Write-Error "Could not load AllDeviceGroups" -ErrorAction Stop
}

# Manage Groups
$GroupCount = 0
foreach ($Group in $AllUserGroups) {
    $GroupCount++
    Write-Output "Running group $($Group.displayName) (Group $($GroupCount) of $($AllUserGroups.id.count))..."
    
    # Get usergroup members
    Write-Output "Loading UserGroupMembers..."
    $UserGroupMembers = Invoke-RestMethod -Method Get -uri "$GraphHost/$GraphVersion/groups/$($Group.id)/members" -Headers @{Authorization = "Bearer $AccessToken" }
    $Total = @()
    $Pages = @()
    $Addtional = @()
    $Total = $UserGroupMembers.value
    $Pages = $UserGroupMembers.'@odata.nextLink'
    while ($null -ne $Pages) {
        $Addtional = Invoke-RestMethod -Method Get -Uri $Pages -Headers @{Authorization = "Bearer $AccessToken" }
        if ($Pages) {
            $Pages = $Addtional."@odata.nextLink"
        }
        $Total += $Addtional.value
    }
    $UserGroupMembers = $Total | Select-Object id, userPrincipalName
    if ($UserGroupMembers.id.count -eq "0") {
        Write-Output "Could not find any UserGroupMembers in $($Group.displayName)"
    }
    else {
        Write-Output "Found $($UserGroupMembers.id.count) UserGroupMembers"

        # Get usergroup members devices
        Write-Output "Loading UserGroupMembersDevices..."
        $UserGroupMembersDevices = $AllManagedDevices | Where-Object { $UserGroupMembers.UserPrincipalName -contains $_.UserPrincipalName }
        if ($UserGroupMembersDevices.id.count -eq "0") {
            Write-Output "Could not find any UserGroupMembersDevices"
        }
        else {
            Write-Output "Found $($UserGroupMembersDevices.id.count) UserGroupMembersDevices"

            # Get matching device group
            Write-Output "Loading matching DeviceGroup..."
            $MatchName = $Group.displayName -replace $UserGroupNames
            $DeviceGroupName = $DeviceGroupNames + $MatchName
            $DeviceGroup = $AllDeviceGroups | Where-Object { $_.DisplayName -eq $DeviceGroupName }
            if ($DeviceGroup.count -eq "0") {
                Write-Error "Could not find any matching device group" -ErrorAction Continue
            }
            else {
                Write-Output "Matching device group is $($DeviceGroup.displayName)"

                # Get devicegroup members
                Write-Output "Loading DeviceGroupMembers..."
                $DeviceGroupMembers = Invoke-RestMethod -Method Get -uri "$GraphHost/$GraphVersion/groups/$($DeviceGroup.id)/members" -Headers @{Authorization = "Bearer $AccessToken" }
                $Total = @()
                $Pages = @()
                $Addtional = @()
                $Total += $DeviceGroupMembers.value
                $Pages = $DeviceGroupMembers.'@odata.nextLink'
                while ($null -ne $Pages) {
                    $Addtional = Invoke-RestMethod -Method Get -Uri $Pages -Headers @{Authorization = "Bearer $AccessToken" }
                    if ($Pages) {
                        $Pages = $Addtional."@odata.nextLink"
                    }
                    $Total += $Addtional.value
                }
                $DeviceGroupMembers = $Total | Select-Object id, DeviceId, userPrincipalName
                Write-Output "Found $($DeviceGroupMembers.id.count) DeviceGroupMembers"

                # Get devices to add
                Write-Output "Loading DevicesToAdd..."
                $DevicesToAdd = $UserGroupMembersDevices | Where-Object { $DeviceGroupMembers.DeviceId -notcontains $_.azureADDeviceId }
                Write-Output "Found $($DevicesToAdd.id.count) DevicesToAdd"
 
                # Get devices to remove
                Write-Output "Loading DevicesToRemove..."
                $DevicesToRemove = $DeviceGroupMembers | Where-Object { ($UserGroupMembersDevices.azureADDeviceId -notcontains $_.DeviceId) -and ($DevicesToAdd.azureADDeviceId -notcontains $_.DeviceId) }
                Write-Output "Found $($DevicesToRemove.id.count) DevicesToRemove"

                # Add devices
                $DeviceCount = 0
                foreach ($Device in $DevicesToAdd) {
                    $DeviceCount++
                    Write-Output "Running device $($Device.deviceName) (Device $($DeviceCount) of $($DevicesToAdd.id.count) to add)..."
                    try {
                        Write-Output "Trying to add the device..."
                        $DeviceAddFilter = "DeviceID eq '$($Device.azureADDeviceId)'"
                        $DeviceAddInfo = Invoke-RestMethod -Method Get -uri "$GraphHost/$GraphVersion/devices?`$filter=$($DeviceAddFilter)" -Headers @{Authorization = "Bearer $AccessToken" } | Select-Object -ExpandProperty Value | Select-Object id, displayName
                        $BodyContent = @{
                            "@odata.id" = "$GraphHost/$GraphVersion/devices/$($DeviceAddInfo.id)"
                        } | ConvertTo-Json
                        Invoke-RestMethod -Method POST -uri "$GraphHost/$GraphVersion/groups/$($DeviceGroup.id)/members/`$ref" -Headers @{Authorization = "Bearer $AccessToken"; 'Content-Type' = 'application/json' } -Body $BodyContent
                        Write-Output "Device added successfully"
                    }
                    catch {
                        Write-Error "Could not add $($Device.deviceName) to $($DeviceGroup.DisplayName)" -ErrorAction Continue
                    }
                }

                # Remove devices
                $DeviceCount = 0
                foreach ($Device in $DevicesToRemove) {
                    $DeviceCount++
                    Write-Output "Running device $($Device.id) (Device $($DeviceCount) of $($DevicesToRemove.id.count) to remove)..."
                    try {
                        Write-Output "Trying to remove the device..."
                        Invoke-RestMethod -Method Delete -uri "$GraphHost/$GraphVersion/groups/$($DeviceGroup.id)/members/$($Device.id)/`$ref" -Headers @{Authorization = "Bearer $AccessToken" }
                        Write-Output "Device removed successfully"
                    }
                    catch {
                        Write-Error "Could not remove $($Device.id) from $($DeviceGroup.DisplayName)" -ErrorAction Continue
                    }
                }
            }
        }        
    }
}