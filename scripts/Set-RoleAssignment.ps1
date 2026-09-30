#Requires -Modules Az.Resources

<#
.SYNOPSIS
  Idempotently ensures a service principal has a given RBAC role at a
  given scope. Skips silently if the assignment already exists.
#>
param(
    [Parameter(Mandatory)][string]$ServicePrincipalObjectId,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$RoleName,
    [string]$ResourceGroup   # optional - omit for subscription-wide scope
)

Import-Module "$PSScriptRoot/common/Common.psm1" -Force

$scope = if ($ResourceGroup) {
    "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
} else {
    "/subscriptions/$SubscriptionId"
}

$existing = Get-AzRoleAssignment -ObjectId $ServicePrincipalObjectId -Scope $scope -RoleDefinitionName $RoleName -ErrorAction SilentlyContinue

if ($existing) {
    Write-Log "Role '$RoleName' already assigned at $scope - skipping."
} else {
    Write-Log "Assigning role '$RoleName' at $scope."
    Invoke-WithRetry -Activity "Assigning role '$RoleName' at $scope" -ScriptBlock {
        New-AzRoleAssignment -ObjectId $ServicePrincipalObjectId -RoleDefinitionName $RoleName -Scope $scope -ErrorAction Stop
    } | Out-Null
}
