<#

# Description
    This script creates the following to prepare your environment for DUDE:
        Creates dynamic usergroups
        Creates assigned devicegroups
        Creates scope tags
        Assigns scope tags to the devicegroups
        Creates admin units.

# Permissions needed for the MSAL app registration in Azure:
    Group.ReadWrite.All
    DeviceManagementRBAC.ReadWrite.All
    AdministrativeUnit.ReadWrite.All

# Make sure to update the variables before running:
    Name = ClientId
    Value = "Application (client) ID of the MSAL app registration in Azure"

    Name = TenantId
    Value = ".onmicrosoft.com"

    Name = CreateScopeTags
    Value = $True or $False - $true will create and assign scope tags. $false will not create or assign scope tags.

    Name = CreateAdminUnits
    Value = $True or $False - $true will create admin units. $false will not create admin units.

# Release Notes
    1.0 - 2021-10-27 - Initial version
    2.0 - 2023-03-31 - CSV source and additional checks
    3.0 - 2023-05-05 - Added step to create admin units
    4.0 - 2023-07-10 - Removed CSV source and added the options to skip scope tags and admin units creation

#>

#region Variables
$ClientId = ""
$TenantId = ""
$CreateScopeTags = $True
$CreateAdminUnits = $True
$Groups = @(
    [PSCustomObject]@{
        UserGroupName           = "DUDE Users Rock"
        UserGroupDescription    = "Rock Users"
        UserGroupMembershipRule = "(user.department -eq `"Rock`")"
        DeviceGroupName         = "DUDE Devices Rock"
        DeviceGroupDescription  = "Rock Users Devices"
        ScopeTagName            = "Rock" # Only needed if $CreateScopeTags = $True
        ScopeTagDescription     = "Rock" # Only needed if $CreateScopeTags = $True
        AdminUnitName           = "DUDE Rock" # Only needed if $CreateAdminUnits = $True
        AdminUnitDescription    = "Rock" # Only needed if $CreateAdminUnits = $True
    }
    [PSCustomObject]@{
        UserGroupName           = "DUDE Users Metal"
        UserGroupDescription    = "Metal Users"
        UserGroupMembershipRule = "(user.department -eq `"Metal`")"
        DeviceGroupName         = "DUDE Devices Metal"
        DeviceGroupDescription  = "Metal Users Devices"
        ScopeTagName            = "Metal" # Only needed if $CreateScopeTags = $True
        ScopeTagDescription     = "Metal" # Only needed if $CreateScopeTags = $True
        AdminUnitName           = "DUDE Metal" # Only needed if $CreateAdminUnits = $True
        AdminUnitDescription    = "Metal" # Only needed if $CreateAdminUnits = $True
    }
)
#endregion

#region Get auth token and build auth header
$auth = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -Interactive
$authHeader = @{Authorization = $auth.CreateAuthorizationHeader() }
#endregion

$Count = 0
foreach ($Group in $Groups) {
    $Count++
    Write-Host "Group $($Count) of $($Groups.UserGroupName.count): $($Group.ScopeTagName)"

    # Create dynamic usergroup
    $UserGroup = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/groups?`$filter=displayName eq '$($Group.UserGroupName)'&`$select=id,displayName" -Headers $authHeader -ContentType 'Application/Json').value
    if ($UserGroup.id.count -eq "0") {
        $Body = @{
            "displayName"                   = $Group.UserGroupName;
            "description"                   = $Group.UserGroupDescription
            "membershipRule"                = $Group.UserGroupMembershipRule;
            "groupTypes"                    = @("DynamicMembership");
            "mailEnabled"                   = $False;
            "mailNickname"                  = ([guid]::NewGuid().ToString());
            "membershipRuleProcessingState" = "On";
            "securityEnabled"               = $True
        } | ConvertTo-Json
        try {
            Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/beta/groups" -Body $Body -Headers $authHeader -ContentType 'Application/Json' | Out-Null
            Write-Host "Usergroup `"$($Group.UserGroupName)`" was successfully created" -ForegroundColor Green
        }
        catch {
            Write-Host "Usergroup `"$($Group.UserGroupName)`" could not be created" -ForegroundColor Red
            break
        }
    }
    else {
        Write-Host "UserGroup `"$($Group.UserGroupName)`" already exists" -ForegroundColor Green
    }

    # Create device group
    $DeviceGroup = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/groups?`$filter=displayName eq '$($Group.DeviceGroupName)'&`$select=id,displayName" -Headers $authHeader -ContentType 'Application/Json').value
    if ($DeviceGroup.id.count -eq "0") {
        $Body = @{
            "displayName"     = $Group.DeviceGroupName;
            "description"     = $Group.DeviceGroupDescription
            "mailEnabled"     = $False;
            "mailNickname"    = ([guid]::NewGuid().ToString());
            "securityEnabled" = $True
        } | ConvertTo-Json
        try {
            $GroupResponse = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/beta/groups" -Body $Body -Headers $authHeader -ContentType 'Application/Json'
            $DeviceGroupId = $GroupResponse.id
            Write-Host "Devicegroup `"$($Group.DeviceGroupName)`" was successfully created" -ForegroundColor Green
        }
        catch {
            Write-Host "Devicegroup `"$($Group.DeviceGroupName)`" could not be created" -ForegroundColor Red
            break
        }
    }
    else {
        $DeviceGroupId = $DeviceGroup.id
        Write-Host "Devicegroup `"$($Group.DeviceGroupName)`" already exists" -ForegroundColor Green
    }

    # Create scope tag
    if ($CreateScopeTags) {
        $ScopeTag = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags?`$filter=displayName eq '$($Group.ScopeTagName)'&`$select=id,displayName" -Headers $authHeader -ContentType 'Application/Json').value
        if ($ScopeTag.id.count -eq "0") {
            $Body = @{
                "displayName" = $Group.ScopeTagName
                "description" = $Group.ScopeTagDescription
            } | ConvertTo-Json
            try {
                $TagResponse = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags" -Body $Body -Headers $authHeader -ContentType 'Application/Json'
                $ScopeTagId = $TagResponse.id
                Write-Host "Scopetag `"$($Group.ScopeTagName)`" was successfully created" -ForegroundColor Green
            }
            catch {
                Write-Host "Scopetag `"$($Group.ScopeTagName)`" could not be created" -ForegroundColor Red
            }
        }
        else {
            $ScopeTagId = $ScopeTag.id
            Write-Host "Scopetag `"$($Group.ScopeTagName)`" already exists" -ForegroundColor Green
        }

        # Assign scope tag
        $ScopeTagAssignments = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags/$($ScopeTagId)/assignments" -Headers $authHeader -ContentType 'Application/Json').value
        if (($ScopeTagAssignments.id.count -eq "0") -and ($ScopeTagAssignments.id -notmatch "$DeviceGroupId")) {
            $Body = '
    {
        "assignments": [
        {"target":
        {"@odata.type":
        "#microsoft.graph.groupAssignmentTarget",
        "groupId":"' + $DeviceGroupId + '"}}]
    }'
            try {
                Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags/$($ScopeTagId)/assign" -Body $Body -Headers $authHeader -ContentType 'Application/Json' | Out-Null
                Write-Host "Scopetag `"$($Group.ScopeTagName)`" was successfully assigned" -ForegroundColor Green
            }
            catch {
                Write-Host "Scopetag `"$($Group.ScopeTagName)`" could not be assigned" -ForegroundColor Red
            }
        }
        else {
            Write-Host "Scopetag `"$($Group.ScopeTagName)`" already assigned" -ForegroundColor Green
        }
    }

    # Create admin unit
    if ($CreateAdminUnits) {
        $AdminUnit = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/administrativeUnits?`$filter=displayName eq '$($Group.AdminUnitName)'&`$select=id,displayName" -Headers $authHeader -ContentType 'Application/Json').value
        if ($AdminUnit.id.count -eq "0") {
            $Body = @{
                "displayName" = $Group.AdminUnitName
                "description" = $Group.AdminUnitDescription
            } | ConvertTo-Json
            try {
                Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/beta/administrativeUnits" -Body $Body -Headers $authHeader -ContentType 'Application/Json' | Out-Null
                Write-Host "AdminUnit `"$($Group.AdminUnitName)`" was successfully created" -ForegroundColor Green
            }
            catch {
                Write-Host "AdminUnit `"$($Group.AdminUnitName)`" could not be created" -ForegroundColor Red
                break
            }
        }
        else {
            Write-Host "AdminUnit `"$($Group.AdminUnitName)`" already exists" -ForegroundColor Green
        }
    }
}