<#
.SYNOPSIS
  Orchestrates provisioning for a single subscription request. This is
  what the CD pipeline calls after a config file is merged to main.
  Every step it calls is independently idempotent, so re-running this
  after a partial failure is always safe.
#>
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$KeyVaultName,
    [Parameter(Mandatory)][string]$CollectionUrl,
    [Parameter(Mandatory)][string]$ProjectName,
    [Parameter(Mandatory)][string]$PersonalAccessToken,
    [Parameter(Mandatory)][string]$TenantId,
    [ValidateSet('AzureUSGovernment','AzureCloud')][string]$AzureCloud = 'AzureUSGovernment'
)

$root = $PSScriptRoot
Import-Module "$root/common/Common.psm1" -Force

$request = Get-SubscriptionRequest -Path $ConfigPath
Test-AllowedRoles -RequestedRoles $request.Roles

$name = Get-DeterministicName -ConnectionName $request.ConnectionName

Write-Log "=== Provisioning '$name' for subscription $($request.SubscriptionId) ==="

$principal = & "$root/New-ServicePrincipal.ps1" -Request $request -DisplayName $name

$connectionArgs = @{
    CollectionUrl         = $CollectionUrl
    ProjectName           = $ProjectName
    ConnectionName        = $request.ConnectionName
    PersonalAccessToken   = $PersonalAccessToken
    TenantId              = $TenantId
    ServicePrincipalAppId = $principal.AppId
    SubscriptionId        = $request.SubscriptionId
    SubscriptionName      = $request.SubscriptionName
    AzureCloud            = $AzureCloud
    AuthType              = $request.AuthType
}

Write-Log "Auth type: $($request.AuthType)"

if ($request.AuthType -eq 'clientSecret') {
    $secret = & "$root/New-ClientSecret.ps1" `
        -KeyVaultName $KeyVaultName `
        -AppObjectId $principal.AppObjectId `
        -SecretName $name

    & "$root/New-ServiceConnection.ps1" @connectionArgs -ClientSecret $secret.SecretValue | Out-Null
    $credentialSummary = "client secret valid until $($secret.Expires)"
}
elseif ($request.AuthType -eq 'certificate') {
    # Separate Key Vault name from the client secret's: a Key Vault
    # certificate also creates a secret with its own name.
    $cert = & "$root/New-ClientCertificate.ps1" `
        -KeyVaultName $KeyVaultName `
        -AppObjectId $principal.AppObjectId `
        -CertificateName (Get-CertificateName -DeterministicName $name)

    & "$root/New-ServiceConnection.ps1" @connectionArgs -CertificatePem $cert.CertificatePem | Out-Null
    $credentialSummary = "certificate $($cert.Thumbprint) valid until $($cert.Expires)"
}
elseif ($request.AuthType -eq 'wif') {
    # Create the connection first - Azure DevOps assigns the issuer and
    # subject the federated credential has to trust.
    $endpoint = & "$root/New-ServiceConnection.ps1" @connectionArgs

    & "$root/Set-FederatedCredential.ps1" `
        -AppObjectId $principal.AppObjectId `
        -Name (Get-FederatedCredentialName -ConnectionName $request.ConnectionName) `
        -Issuer $endpoint.authorization.parameters.workloadIdentityFederationIssuer `
        -Subject $endpoint.authorization.parameters.workloadIdentityFederationSubject `
        -Audience (Get-AzureCloudSettings -AzureCloud $AzureCloud).FederatedAudience
    $credentialSummary = "workload identity federation (no stored credential)"
}

foreach ($role in $request.Roles) {
    & "$root/Set-RoleAssignment.ps1" `
        -ServicePrincipalObjectId $principal.ServicePrincipalId `
        -SubscriptionId $request.SubscriptionId `
        -RoleName $role `
        -ResourceGroup $request.Scope
}

Write-Log "=== Completed '$name' - $credentialSummary ==="
