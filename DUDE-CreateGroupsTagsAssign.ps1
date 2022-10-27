<#

# Description
    This script creates dynamic usergroups, assigned devicegroups, creates and assigns scope tags to devicegroups.
    Update the variables before running.

# Release Notes
    1.0 - 2021-10-27 - Initial version

#>

#region Variables
$ClientId = ""
$TenantId = ""
$Groups = @(
    [PSCustomObject]@{
        UserGroupName           = "Endpoint-DUDE Users IT"
        UserGroupDescription    = "IT Users"
        UserGroupMembershipRule = "(user.department -eq `"IT`")"
        DeviceGroupName         = "Endpoint-DUDE Devices IT"
        DeviceGroupDescription  = "IT Users Devices"
        ScopeTagName            = "IT"
        ScopeTagDescription     = "IT"
    }
    [PSCustomObject]@{
        UserGroupName           = "Endpoint-DUDE Users HR"
        UserGroupDescription    = "HR Users"
        UserGroupMembershipRule = "(user.department -eq `"HR`")"
        DeviceGroupName         = "Endpoint-DUDE Devices HR"
        DeviceGroupDescription  = "HR Users Devices"
        ScopeTagName            = "HR"
        ScopeTagDescription     = "HR"
    }
)
#endregion

#region Get auth token and build auth header
$auth = Get-MsalToken -ClientId $clientId -TenantId $tenantId -Interactive
$authHeader = @{Authorization = $auth.CreateAuthorizationHeader() }
#endregion

foreach ($Group in $Groups) {
    # Create dynamic usergroup
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
        Write-Output "Usergroup `"$($Group.UserGroupName)`" was successfully created"
    }
    catch {
        Write-Error "Usergroup `"$($Group.UserGroupName)`" could not be created"
    }

    # Create device group
    $Body = @{
        "displayName"     = $Group.DeviceGroupName;
        "description"     = $Group.DeviceGroupDescription
        "mailEnabled"     = $False;
        "mailNickname"    = ([guid]::NewGuid().ToString());
        "securityEnabled" = $True
    } | ConvertTo-Json
    try {
        $GroupResponse = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/beta/groups" -Body $Body -Headers $authHeader -ContentType 'Application/Json'
        Write-Output "Devicegroup `"$($Group.DeviceGroupName)`" was successfully created"
    }
    catch {
        Write-Error "Devicegroup `"$($Group.DeviceGroupName)`" could not be created"
    }

    # Create scope tag
    $Body = @{
        "displayName" = $Group.ScopeTagName
        "description" = $Group.ScopeTagDescription
    } | ConvertTo-Json
    try {
        $TagResponse = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags" -Body $Body -Headers $authHeader -ContentType 'Application/Json'
        Write-Output "Scopetag `"$($Group.ScopeTagName)`" was successfully created"
    }
    catch {
        Write-Error "Scopetag `"$($Group.ScopeTagName)`" could not be created"
    }

    # Assign scope tag
    $Body = '
    {
        "assignments": [
        {"target":
        {"@odata.type":
        "#microsoft.graph.groupAssignmentTarget",
        "groupId":"' + $GroupResponse.id + '"}}]
    }'
    try {
        Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags/$($TagResponse.id)/assign" -Body $Body -Headers $authHeader -ContentType 'Application/Json' | Out-Null
        Write-Output "Scopetag `"$($Group.ScopeTagName)`" was successfully assigned"
    }
    catch {
        Write-Error "Scopetag `"$($Group.ScopeTagName)`" could not be assigned"
    }
}