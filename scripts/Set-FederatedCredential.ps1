#Requires -Modules Microsoft.Graph.Applications

<#
.SYNOPSIS
  Idempotently ensures the app registration has a federated identity
  credential trusting one Azure DevOps service connection. Used for
  workload identity federation (WIF) service connections, which hold no
  secret or certificate at all.

.NOTES
  Issuer and subject come from the service connection that Azure DevOps
  created (authorization.parameters.workloadIdentityFederationIssuer /
  workloadIdentityFederationSubject), rather than being built here, so
  they always match what Azure DevOps will present at token exchange.
#>
param(
    [Parameter(Mandatory)][string]$AppObjectId,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Issuer,
    [Parameter(Mandatory)][string]$Subject,
    [Parameter(Mandatory)][string]$Audience
)

Import-Module "$PSScriptRoot/common/Common.psm1" -Force

$existing = Get-MgApplicationFederatedIdentityCredential -ApplicationId $AppObjectId -All |
    Where-Object Name -eq $Name

if ($existing -and $existing.Issuer -eq $Issuer -and $existing.Subject -eq $Subject -and $existing.Audiences -contains $Audience) {
    Write-Log "Federated credential '$Name' already matches - skipping."
} elseif ($existing) {
    Write-Log "Federated credential '$Name' exists with a different issuer/subject - updating."
    Invoke-WithRetry -Activity "Updating federated credential '$Name'" -ScriptBlock {
        Update-MgApplicationFederatedIdentityCredential -ApplicationId $AppObjectId `
            -FederatedIdentityCredentialId $existing.Id `
            -BodyParameter @{ issuer = $Issuer; subject = $Subject; audiences = @($Audience) } `
            -ErrorAction Stop
    } | Out-Null
} else {
    Write-Log "Creating federated credential '$Name' (subject $Subject)."
    Invoke-WithRetry -Activity "Creating federated credential '$Name'" -ScriptBlock {
        New-MgApplicationFederatedIdentityCredential -ApplicationId $AppObjectId `
            -BodyParameter @{ name = $Name; issuer = $Issuer; subject = $Subject; audiences = @($Audience) } `
            -ErrorAction Stop
    } | Out-Null
}
