#Requires -Modules Microsoft.Graph.Applications

<#
.SYNOPSIS
  Idempotently ensures an Entra ID app registration + service principal
  exist for a given subscription request. Safe to re-run: looks the app
  up by its deterministic display name before creating anything.
#>
param(
    [Parameter(Mandatory)][PSCustomObject]$Request,   # from Get-SubscriptionRequest
    [Parameter(Mandatory)][string]$DisplayName          # from Get-DeterministicName
)

Import-Module "$PSScriptRoot/common/Common.psm1" -Force

# Plain filter, not an advanced (-ConsistencyLevel eventual) query: the
# advanced-query index lags behind writes, so a re-run shortly after a
# failed one could miss the app and create a duplicate.
$existingApp = @(Get-MgApplication -Filter "displayName eq '$DisplayName'")

if ($existingApp.Count -gt 1) {
    throw "Found $($existingApp.Count) app registrations named '$DisplayName' - remove the duplicates before re-running."
}

if ($existingApp) {
    Write-Log "App registration '$DisplayName' already exists (appId=$($existingApp.AppId)) - reusing."
    $app = $existingApp[0]
} else {
    Write-Log "Creating app registration '$DisplayName'."
    $app = New-MgApplication -DisplayName $DisplayName `
        -Tags @(
            "ManagedBy:platform-automation",
            "ConfigFile:$($Request.ConfigPath)",
            "RequestedBy:$($Request.RequestedBy)"
        )
}

$existingSp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'"

if ($existingSp) {
    Write-Log "Service principal for '$DisplayName' already exists (objectId=$($existingSp.Id)) - reusing."
    $sp = $existingSp
} else {
    Write-Log "Creating service principal for '$DisplayName'."
    $sp = Invoke-WithRetry -Activity "Creating service principal for '$DisplayName'" -ScriptBlock {
        New-MgServicePrincipal -AppId $app.AppId -ErrorAction Stop
    }
}

# Handed off to the next step in this same pipeline run - not persisted
# anywhere, since it's always re-discoverable by DisplayName later.
[PSCustomObject]@{
    AppId              = $app.AppId
    AppObjectId        = $app.Id
    ServicePrincipalId = $sp.Id
    DisplayName        = $DisplayName
}
