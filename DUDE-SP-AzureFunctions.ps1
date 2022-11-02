# Input bindings are passed in via param block.
param($Timer)

<#

# Description
    This script helps to dynamically add/remove users devices to a corresponding device group based on user groups stored in a SharePoint list.
    This can be used to automate scope tags among other things.

# Variables
    RunLevel = "Debug" or "Prod" - Debug wont make any changes to the groups.
    MasterSPSiteID = ID of the SharePoint site where the list is stored.
    MasterlistID = ID of the list itself.

# Release Notes
    2.0 - 2022-11-02 - Logging for Intune devices that could not be found in Azure AD
    1.0 - 2022-10-26 - Initial version

#>

#region Variables
$RunLevel = "Prod"
$MasterSPSiteID = ""
$MasterlistID = ""
#endregion

#region Functions
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

#region Get AccessToken
$script:AccessToken = Get-AccessToken
#endregion

#region Get
$Masterlist = (Invoke-GraphCall -Uri "https://graph.microsoft.com/v1.0/sites/$($MasterSPSiteID)/lists/$($MasterlistID)/items?`$select=id&`$expand=fields(`$select=UserGroup,DeviceGroup)").Value.fields | select UserGroup,DeviceGroup
if ($Masterlist.UserGroup.Count -eq "0") {
    Write-Error "Could not load Masterlist" -ErrorAction Stop
}
Write-Output "Found $($Masterlist.UserGroup.Count) UserGroups in Masterlist"
#endregion

#region Get AllManagedDevices
$AllManagedDevicesGraph = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$select=id,deviceName,userPrincipalName,azureADDeviceId").value
$AllManagedDevicesGraph = $AllManagedDevicesGraph | Where-Object {$_.azureADDeviceId -ne "00000000-0000-0000-0000-000000000000"}
if ($AllManagedDevicesGraph.id.Count -eq "0") {
    Write-Error "Could not load AllManagedDevicesGraph" -ErrorAction Stop
}
$AllManagedDevices = foreach ($Device in $AllManagedDevicesGraph) {
    [PSCustomObject][Ordered]@{
        MdmDeviceId = $Device.id
        AadDeviceId = $Device.azureADDeviceId
        DeviceName  = $Device.deviceName
        UserUPN     = $Device.userPrincipalName
    }
}
if ($AllManagedDevices.MdmObjectID.Count -eq "0") {
    Write-Error "Could not load AllManagedDevices" -ErrorAction Stop
}
Remove-Variable AllManagedDevicesGraph
Write-Output "Found $($AllManagedDevices.MdmObjectID.Count) AllManagedDevices"
#endregion

#region Get AllAzureADDevices
$AllAzureADDevicesGraph = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/devices?`$expand=registeredOwners(`$select=userPrincipalName)&`$select=id,deviceId,displayName,managementType").value | Where-Object { ($_.registeredOwners -ne $null) -and ($_.managementType -ne $null) }
if ($AllAzureADDevicesGraph.id.Count -eq "0") {
    Write-Error "Could not load AllAzureADDevicesGraph" -ErrorAction Stop
}
$AllAzureADDevices = foreach ($Device in $AllAzureADDevicesGraph) {
    [PSCustomObject][Ordered]@{
        MdmDeviceId = ""
        AadDeviceId = $Device.deviceId
        DeviceName  = $Device.displayName
        UserUPN     = $Device.registeredOwners.userPrincipalName
    }
}
if ($AllAzureADDevices.deviceId.Count -eq "0") {
    Write-Error "Could not load AllAzureADDevices" -ErrorAction Stop
}
Remove-Variable AllAzureADDevicesGraph
Write-Output "Found $($AllAzureADDevices.deviceId.Count) AllAzureADDevices"
#endregion

#region Create AllAzureADDevicesHash
$AllAzureADDevicesHash = @{}
foreach ($Device in $AllAzureADDevices) {
    $AllAzureADDevicesHash.Add($Device.AadDeviceId, $Device)
}
#region

#region Get AllDevices
$AllDevices = foreach ($Device in $AllManagedDevices) {
    if ($AllAzureADDevicesHash.ContainsKey($Device.AadDeviceId)) {
        $Device.UserUPN = $AllAzureADDevicesHash[$Device.AadDeviceId].UserUpn
    }
    $Device
}
Remove-Variable AllManagedDevices, AllAzureADDevices, AllAzureADDevicesHash
Write-Output "Found $($AllDevices.DeviceName.Count) AllDevices"
#endregion

#region Manage groups
$GroupCount = 0
foreach ($Group in $Masterlist) {
    $GroupCount++
    Write-Output "Group $($GroupCount) of $($Masterlist.count): $($Group.UserGroup)"

    # Get user group info
    $UserGroup = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/groups?`$filter=displayName eq '$($Group.UserGroup)'&`$select=id,displayName").value
    if ($UserGroup.id.Count -ne "1") {
        Write-Error "Could not find UserGroup" -ErrorAction Continue
    }
    else {
        # Get device group info
        $DeviceGroup = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/groups?`$filter=displayName eq '$($Group.DeviceGroup)'&`$select=id,displayName").value
        if ($DeviceGroup.id.Count -ne "1") {
            Write-Error "Could not find DeviceGroup" -ErrorAction Continue
        }
        else {
            # Get usergroup members
            $UserGroupMembers = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/groups/$($UserGroup.id)/members?`$select=id,userPrincipalName").value
            if ($UserGroupMembers.id.Count -eq "0") {
                Write-Output "Could not find any UserGroupMembers in $($UserGroup.displayName)"
            }
            else {
                # Get usergroup members devices
                $UserGroupMembersDevices = $AllDevices | Where-Object { $UserGroupMembers.UserPrincipalName -contains $_.UserUPN }
                if ($UserGroupMembersDevices.id.Count -eq "0") {
                    Write-Output "Could not find any UserGroupMembersDevices"
                }
                else {
                    # Get devicegroup members
                    $DeviceGroupMembers = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/groups/$($DeviceGroup.id)/members?`$select=id,deviceId").value

                    # Remove nested groups
                    $DeviceGroupMembers = $DeviceGroupMembers | Where-Object { $_.'@odata.type' -ne "#microsoft.graph.group" }

                    # Get devices to add
                    if ($DeviceGroupMembers.id.count -eq "0") {
                        $DevicesToAdd = $UserGroupMembersDevices
                    }
                    else {
                        $DevicesToAdd = $UserGroupMembersDevices | Where-Object { $DeviceGroupMembers.deviceId -notcontains $_.AadDeviceId }
                    }

                    # Get devices to remove
                    $DevicesToRemove = $DeviceGroupMembers | Where-Object { ($UserGroupMembersDevices.AadDeviceId -notcontains $_.deviceId) -and ($DevicesToAdd.AadDeviceId -notcontains $_.deviceId) }

                    # Add devices
                    $DeviceCount = 0
                    foreach ($Device in $DevicesToAdd) {
                        $DeviceCount++
                        try {
                            $DeviceAddInfo = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/devices?`$filter=DeviceID eq '$($Device.AadDeviceId)'&`$select=id,displayName").value
                            if ($DeviceAddInfo.id.count -eq "1") {
                                if ($RunLevel -eq "Prod") {
                                    $Body = @{"@odata.id" = "https://graph.microsoft.com/beta/devices/$($DeviceAddInfo.id)" }
                                    Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/groups/$($DeviceGroup.id)/members/`$ref" -Method POST -Body $Body | Out-Null
                                    Write-Output "Device $($DeviceCount) of $($DevicesToAdd.AadDeviceId.count): Added $($DeviceAddInfo.displayName) to $($DeviceGroup.displayName)"
                                }
                                elseif ($RunLevel -eq "Debug") {
                                    Write-Output "Device $($DeviceCount) of $($DevicesToAdd.AadDeviceId.count): Would add $($DeviceAddInfo.displayName) to $($DeviceGroup.displayName)"
                                }
                                else {
                                    Write-Error "Please specify RunLevel and try again" -ErrorAction Stop
                                }
                            }
                            else {
                                Write-Warning "Device $($DeviceCount) of $($DevicesToAdd.AadDeviceId.count): Could not find $($Device.DeviceName) with AadDeviceId $($Device.AadDeviceId) in Azure AD"
                            }
                        }
                        catch {
                            Write-Error "Device $($DeviceCount) of $($DevicesToAdd.AadDeviceId.count): Could not add $($Device.DeviceName) to $($DeviceGroup.displayName)" -ErrorAction Continue
                        }
                    }

                    # Remove devices
                    $DeviceCount = 0
                    foreach ($Device in $DevicesToRemove) {
                        $DeviceCount++
                        try {
                            $DeviceRemoveInfo = (Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/devices?`$filter=id eq '$($Device.id)'&`$select=id,displayName").value
                            if ($RunLevel -eq "Prod") {
                                Invoke-GraphCall -Uri "https://graph.microsoft.com/beta/groups/$($DeviceGroup.id)/members/$($DeviceRemoveInfo.id)/`$ref" -Method Delete | Out-Null
                                Write-Output "Device $($DeviceCount) of $($DevicesToRemove.id.count): Removed $($DeviceRemoveInfo.displayName) from $($DeviceGroup.displayName)"
                            }
                            elseif ($RunLevel -eq "Debug") {
                                Write-Output "Device $($DeviceCount) of $($DevicesToRemove.id.count): Would remove $($DeviceRemoveInfo.displayName) from $($DeviceGroup.displayName)"
                            }
                            else {
                                Write-Error "Please specify RunLevel and try again" -ErrorAction Stop
                            }
                        }
                        catch {
                            Write-Error "Device $($DeviceCount) of $($DevicesToRemove.id.count): Could not remove $($DeviceRemoveInfo.displayName) from $($DeviceGroup.displayName)" -ErrorAction Continue
                        }
                    }
                }
            }
        }
    }
}
#endregion