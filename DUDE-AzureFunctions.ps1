# Input bindings are passed in via param block.
param($Timer)

<#

# Description
    This script helps to dynamically add/remove users devices to a corresponding device group based on user groups.
    This can be used to automate scope tags among other things.

# Make sure to set the following application settings before running:
    Name = UserGroupNames
    Value = ""

    Name = DeviceGroupNames
    Value = ""

    Name = DeviceFilter
    Value = "All" or "Managed" (All will include all Intune and Azure AD devices. Managed will include all Intune and only managed Azure AD devices.)

    Name = RunLevel
    Value = "Prod" or "Debug" (Use Prod to make changes. Debug for logging only.)

# User and device group names
    It's critical that the user and device group names are consistent and have a matching ending.
    If you enter the following application settings:
        Name = UserGroupNames
        Value = Endpoint-DUDE Users

        Name = DeviceGroupNames
        Value = Endpoint-DUDE Devices
    
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
    5.0 - 2022-06-28 - Updated devices to add and devices to remove filter.
    4.0 - 2022-06-27 - Updated devices to add and devices to remove filter.
    3.0 - 2021-11-17 - Added DeviceFilter to be able to choose between including all Intune and Azure AD devices or all Intune and only Managed Azure AD devices.
    2.0 - 2021-11-16 - Matching users devices based on registeredOwner from Azure AD devices and fallback to userPrincipalName from Intune managedDevices
    1.0 - 2021-10-16 - Initial version

#>

#region functions
function Get-AccessToken {
    try {
        $ResourceURI = "https://graph.microsoft.com/"
        $TokenAuthURI = $env:IDENTITY_ENDPOINT + "?resource=$ResourceURI&api-version=2019-08-01"
        $TokenResponse = Invoke-RestMethod -Method Get -Headers @{"X-IDENTITY-HEADER" = "$env:IDENTITY_HEADER" } -Uri $TokenAuthURI -ErrorAction Stop
        $AccessToken = @{ "Authorization" = "Bearer $($TokenResponse.access_token)" }
        return $AccessToken
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
        [hashtable]$AccessToken = $script:AccessToken,

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
            Headers     = $AccessToken
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
                $addtional = Invoke-RestMethod -Method Get -Uri $pages -Headers $AccessToken
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

#region get AccessToken
$script:AccessToken = Get-AccessToken
#endregion

#region get AllManagedDevices
$AllManagedDevices = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$select=id,deviceName,userPrincipalName,azureADDeviceId").value
if ($AllManagedDevices.id.Count -eq "0") {
    Write-Error "Could not load AllManagedDevices" -ErrorAction Stop
}
#endregion

#region get AllAzureADDevices
if ($env:DeviceFilter -eq "All") {
    $AllAzureADDevices = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/devices?`$expand=registeredOwners(`$select=id,userPrincipalName)&`$select=id,deviceId,displayName").value | Where-Object { $_.registeredOwners -ne $null }
    if ($AllAzureADDevices.id.Count -eq "0") {
        Write-Error "Could not load AllAzureADDevices" -ErrorAction Stop
    }
}
elseif ($env:DeviceFilter -eq "Managed") {
    $AllAzureADDevices = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/devices?`$expand=registeredOwners(`$select=id,userPrincipalName)&`$select=id,deviceId,displayName,managementType").value | Where-Object { ($_.registeredOwners -ne $null) -and ($_.managementType -ne $null) }
    if ($AllAzureADDevices.id.Count -eq "0") {
        Write-Error "Could not load AllAzureADDevices" -ErrorAction Stop
    }
}
else {
    Write-Error "Please specify DeviceFilter and try again" -ErrorAction Stop
}
#endregion

#region get AllDevices
$AllDevices = $AllManagedDevices | Where-Object { $AllAzureADDevices.deviceId -notcontains $_.azureADDeviceId }
$AllDevices += $AllAzureADDevices
Remove-Variable -Name AllManagedDevices, AllAzureADDevices
#endregion

#region get AllUserGroups
$AllUserGroups = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/groups?`$filter=startswith(displayName,'$($env:UserGroupNames)')&`$select=id,displayName").value
if ($AllUserGroups.id.Count -eq "0") {
    Write-Error "Could not load AllUserGroups" -ErrorAction Stop
}
#endregion

#region get AllDeviceGroups
$AllDeviceGroups = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/groups?`$filter=startswith(displayName,'$($env:DeviceGroupNames)')&`$select=id,displayName").value
if ($AllDeviceGroups.id.Count -eq "0") {
    Write-Error "Could not load AllDeviceGroups" -ErrorAction Stop
}
#endregion

#region manage groups
$GroupCount = 0
foreach ($Group in $AllUserGroups) {
    $GroupCount++
    Write-Output "Group $($GroupCount) of $($AllUserGroups.id.count): $($Group.displayName)"
    
    # Get usergroup members
    $UserGroupMembers = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/groups/$($Group.id)/members?`$select=id,userPrincipalName").value
    if ($UserGroupMembers.id.Count -eq "0") {
        Write-Output "Could not find any UserGroupMembers in $($Group.displayName)"
    }
    else {
        # Get usergroup members devices
        $UserGroupMembersDevices = $AllDevices | Where-Object { ($UserGroupMembers.UserPrincipalName -contains $_.UserPrincipalName) -or ($UserGroupMembers.UserPrincipalName -contains $_.registeredOwners.UserPrincipalName) }   
        if ($UserGroupMembersDevices.id.Count -eq "0") {
            Write-Output "Could not find any UserGroupMembersDevices"
        }
        else {
            # Get matching device group
            $DeviceGroup = $AllDeviceGroups | Where-Object { $_.DisplayName -eq ($Group.displayName -replace $env:UserGroupNames, $env:DeviceGroupNames) }
            if ($DeviceGroup.count -eq "0") {
                Write-Error "Could not find any matching device group" -ErrorAction Continue
            }
            else {
                # Get devicegroup members
                $DeviceGroupMembers = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/groups/$($DeviceGroup.id)/members?`$select=id,deviceId").value

                # Get devices to add
                if ($DeviceGroupMembers.id.count -eq "0") {
                    $DevicesToAdd = $UserGroupMembersDevices
                }
                else {
                    $DevicesToAdd = $UserGroupMembersDevices | Where-Object { $DeviceGroupMembers.deviceId -notcontains $_.azureADDeviceId -or $DeviceGroupMembers.deviceId -notcontains $_.deviceId }
                }
 
                # Get devices to remove
                $DevicesToRemove = $DeviceGroupMembers | Where-Object { $UserGroupMembersDevices.azureADDeviceId -notcontains $_.deviceId -and $UserGroupMembersDevices.deviceId -notcontains $_.deviceId -and $DevicesToAdd.azureADDeviceId -notcontains $_.deviceId -and $DevicesToAdd.deviceId -notcontains $_.deviceId }

                # Add devices
                $DeviceCount = 0
                foreach ($Device in $DevicesToAdd) {
                    $DeviceCount++
                    try {
                        if ($null -ne $Device.azureADDeviceId) {
                            $DeviceAddInfo = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/devices?`$filter=DeviceID eq '$($Device.azureADDeviceId)'&`$select=id,displayName").value
                            if ($env:RunLevel -eq "Prod") {
                                $Body = @{"@odata.id" = "https://graph.microsoft.com/beta/devices/$($DeviceAddInfo.id)" }
                                Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/groups/$($DeviceGroup.id)/members/`$ref" -Method POST -Body $Body | Out-Null
                                Write-Output "Device $($DeviceCount) of $($DevicesToAdd.id.count): Added $($DeviceAddInfo.displayName) to $($DeviceGroup.displayName)"
                            }
                            elseif ($env:RunLevel -eq "Debug") {
                                Write-Output "Device $($DeviceCount) of $($DevicesToAdd.id.count): Would add $($DeviceAddInfo.displayName) to $($DeviceGroup.displayName)"
                            }
                            else {
                                Write-Error "Please specify RunLevel and try again" -ErrorAction Stop
                            }
                        }
                        else {
                            if ($env:RunLevel -eq "Prod") {
                                $Body = @{"@odata.id" = "https://graph.microsoft.com/beta/devices/$($Device.id)" }
                                Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/groups/$($DeviceGroup.id)/members/`$ref" -Method POST -Body $Body | Out-Null
                                Write-Output "Device $($DeviceCount) of $($DevicesToAdd.id.count): Added $($Device.displayName) to $($DeviceGroup.displayName)"
                            }
                            elseif ($env:RunLevel -eq "Debug") {
                                Write-Output "Device $($DeviceCount) of $($DevicesToAdd.id.count): Would add $($Device.displayName) to $($DeviceGroup.displayName)"
                            }
                            else {
                                Write-Error "Please specify RunLevel and try again" -ErrorAction Stop
                            }
                        }

                    }
                    catch {
                        Write-Error "Device $($DeviceCount) of $($DevicesToAdd.id.count): Could not add $($Device.displayName)$($Device.deviceName) to $($DeviceGroup.displayName)" -ErrorAction Continue
                    }
                }

                # Remove devices
                $DeviceCount = 0
                foreach ($Device in $DevicesToRemove) {
                    $DeviceCount++
                    try {
                        $DeviceRemoveInfo = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/devices?`$filter=id eq '$($Device.id)'&`$select=id,displayName").value
                        if ($env:RunLevel -eq "Prod") {
                            Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/groups/$($DeviceGroup.id)/members/$($DeviceRemoveInfo.id)/`$ref" -Method Delete | Out-Null
                            Write-Output "Device $($DeviceCount) of $($DevicesToRemove.id.count): Removed $($DeviceRemoveInfo.displayName) from $($DeviceGroup.displayName)"
                        }
                        elseif ($env:RunLevel -eq "Debug") {
                            Write-Output "Device $($DeviceCount) of $($DevicesToRemove.id.count): Would remove $($DeviceRemoveInfo.displayName) from $($DeviceGroup.displayName)"
                        }
                        else {
                            Write-Error "Please specify RunLevel and try again" -ErrorAction Stop
                        }
                    }
                    catch {
                        Write-Error "Device $($DeviceCount) of $($DevicesToRemove.id.count): Could not remove $($Device.displayName)$($Device.deviceName) from $($DeviceGroup.displayName)" -ErrorAction Continue
                    }
                }
            }
        }        
    }
}
#endregion