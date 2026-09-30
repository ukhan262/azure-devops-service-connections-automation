<#
.SYNOPSIS
  Idempotently creates or updates an Azure Resource Manager service
  connection. -AuthType picks how it authenticates:
    clientSecret - service principal + client secret (spnKey)
    certificate  - service principal + certificate (spnCertificate)
    wif          - workload identity federation; no stored credential.
                   The caller must then add a federated credential to the
                   app using the issuer/subject in the returned endpoint.
  Targets Azure Government or commercial Azure depending on -AzureCloud.
  Returns the service endpoint object Azure DevOps sends back.

.NOTES
  Azure DevOps Server's REST API is close to, but not guaranteed
  identical to, Azure DevOps Services. Validate the exact request/response
  shape against your Server version before relying on this in production:
  create one connection manually through the UI first, then GET it back
  and compare against the body built below. Adjust -ApiVersion if your
  Server version doesn't support 7.1.
#>
param(
    [Parameter(Mandatory)][string]$CollectionUrl,      # e.g. https://ado-server.contoso.gov/DefaultCollection
    [Parameter(Mandatory)][string]$ProjectName,
    [Parameter(Mandatory)][string]$ConnectionName,
    [Parameter(Mandatory)][string]$PersonalAccessToken,
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ServicePrincipalAppId,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$SubscriptionName,
    [ValidateSet('clientSecret','certificate','wif')][string]$AuthType = 'clientSecret',
    [securestring]$ClientSecret,     # required for clientSecret
    [securestring]$CertificatePem,   # required for certificate: PEM with private key + certificate
    [ValidateSet('AzureUSGovernment','AzureCloud')][string]$AzureCloud = 'AzureUSGovernment',
    [string]$ApiVersion = '7.1'
)

Import-Module "$PSScriptRoot/common/Common.psm1" -Force

$cloud = Get-AzureCloudSettings -AzureCloud $AzureCloud

if ($AuthType -eq 'clientSecret' -and -not $ClientSecret) { throw "-ClientSecret is required when -AuthType is clientSecret." }
if ($AuthType -eq 'certificate' -and -not $CertificatePem) { throw "-CertificatePem is required when -AuthType is certificate." }

$authHeader = @{
    Authorization  = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$PersonalAccessToken"))
    'Content-Type' = 'application/json'
}

$projectPath = [uri]::EscapeDataString($ProjectName)

# Create/update are organization-level calls in api-version 5.1+; the
# project the connection belongs to goes in serviceEndpointProjectReferences,
# which needs the project's ID. (Reading projects needs the PAT's
# "Project and Team: Read" scope.)
$project = Invoke-RestMethod -Method Get -Headers $authHeader `
    -Uri "$CollectionUrl/_apis/projects/$projectPath`?api-version=$ApiVersion"

$endpointsUri = "$CollectionUrl/_apis/serviceendpoint/endpoints"

# --- Look up existing connection by name (idempotency check) ---
# Listing by name is still project-scoped.
$listUri = "$CollectionUrl/$projectPath/_apis/serviceendpoint/endpoints" +
    "?endpointNames=$([uri]::EscapeDataString($ConnectionName))&api-version=$ApiVersion"
$existing = Invoke-RestMethod -Uri $listUri -Headers $authHeader -Method Get

$authorization = switch ($AuthType) {
    'clientSecret' {
        @{
            scheme     = 'ServicePrincipal'
            parameters = @{
                tenantid            = $TenantId
                serviceprincipalid  = $ServicePrincipalAppId
                authenticationType  = 'spnKey'
                serviceprincipalkey = ConvertFrom-SecureStringToPlainText $ClientSecret
            }
        }
    }
    'certificate' {
        @{
            scheme     = 'ServicePrincipal'
            parameters = @{
                tenantid                    = $TenantId
                serviceprincipalid          = $ServicePrincipalAppId
                authenticationType          = 'spnCertificate'
                servicePrincipalCertificate = ConvertFrom-SecureStringToPlainText $CertificatePem
            }
        }
    }
    'wif' {
        # Azure DevOps fills in workloadIdentityFederationIssuer/Subject.
        @{
            scheme     = 'WorkloadIdentityFederation'
            parameters = @{
                tenantid           = $TenantId
                serviceprincipalid = $ServicePrincipalAppId
            }
        }
    }
}

$body = [ordered]@{
    name = $ConnectionName
    type = 'azurerm'
    url  = $cloud.ResourceManagerUrl
    data = @{
        subscriptionId   = $SubscriptionId
        subscriptionName = $SubscriptionName
        environment      = $cloud.DevOpsEnvironment
        scopeLevel       = 'Subscription'
        creationMode     = 'Manual'
    }
    authorization = $authorization
    isShared = $false
    isReady  = $true
    serviceEndpointProjectReferences = @(
        @{
            projectReference = @{ id = $project.id; name = $project.name }
            name             = $ConnectionName
        }
    )
}

if ($existing.count -gt 0) {
    $endpointId = $existing.value[0].id
    $currentScheme = $existing.value[0].authorization.scheme
    Write-Log "Service connection '$ConnectionName' already exists (id=$endpointId, scheme=$currentScheme) - updating to $AuthType."
    $body.id = $endpointId
    $endpoint = Invoke-RestMethod -Method Put -Headers $authHeader `
        -Uri "$endpointsUri/$endpointId`?api-version=$ApiVersion" `
        -Body ($body | ConvertTo-Json -Depth 10)
} else {
    Write-Log "Creating $AuthType service connection '$ConnectionName'."
    $endpoint = Invoke-RestMethod -Method Post -Headers $authHeader `
        -Uri "$endpointsUri`?api-version=$ApiVersion" `
        -Body ($body | ConvertTo-Json -Depth 10)
}

$authorization = $null
$body = $null

if ($AuthType -eq 'wif' -and (
        -not $endpoint.authorization.parameters.workloadIdentityFederationIssuer -or
        -not $endpoint.authorization.parameters.workloadIdentityFederationSubject)) {
    throw "Azure DevOps did not return a workload identity federation issuer/subject for '$ConnectionName'."
}

$endpoint
