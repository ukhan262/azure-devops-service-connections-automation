#Requires -Modules Az.Accounts, Az.KeyVault, Az.Resources, Microsoft.Graph.Authentication, Microsoft.Graph.Applications, powershell-yaml

# Common.psm1
# Shared helpers for the service-connection automation scripts.
# None of these assume a prior run's state is remembered anywhere except
# in Azure / Entra ID itself - every "does this exist" question is
# answered live, on every run.

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )
    $timestamp = (Get-Date).ToString('u')
    $line = "[$timestamp] [$Level] $Message"
    switch ($Level) {
        'ERROR' { Write-Host "##vso[task.logissue type=error]$Message"; Write-Error $line }
        'WARN'  { Write-Host "##vso[task.logissue type=warning]$Message"; Write-Warning $line }
        default { Write-Host $line }
    }
}

function Get-AzureCloudSettings {
    <#
      Single place that knows the per-cloud endpoint/environment names, so
      every other script only has to carry the one -AzureCloud flag.
      AzureUSGovernment = Azure Government, AzureCloud = commercial/public.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('AzureUSGovernment','AzureCloud')][string]$AzureCloud
    )

    switch ($AzureCloud) {
        'AzureUSGovernment' {
            [PSCustomObject]@{
                AzEnvironment      = 'AzureUSGovernment'   # Connect-AzAccount -Environment
                GraphEnvironment   = 'USGov'               # Connect-MgGraph -Environment
                DevOpsEnvironment  = 'AzureUSGovernment'   # service connection data.environment
                ResourceManagerUrl = 'https://management.usgovcloudapi.net/'
                FederatedAudience  = 'api://AzureADTokenExchangeUSGov'   # WIF federated credential audience
            }
        }
        'AzureCloud' {
            [PSCustomObject]@{
                AzEnvironment      = 'AzureCloud'
                GraphEnvironment   = 'Global'
                DevOpsEnvironment  = 'AzureCloud'
                ResourceManagerUrl = 'https://management.azure.com/'
                FederatedAudience  = 'api://AzureADTokenExchange'
            }
        }
    }
}

function Connect-AutomationContext {
    <#
      Connects Az and Microsoft Graph as the pipeline's bootstrap identity,
      using a client secret that only the CD pipeline's agent can read.
      This is the one identity in the whole system that isn't provisioned
      by this automation - it's created once, manually, by security, and
      everything downstream of it is what gets automated away.
    #>
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ApplicationId,
        [Parameter(Mandatory)][securestring]$ClientSecret,
        [ValidateSet('AzureUSGovernment','AzureCloud')][string]$AzureCloud = 'AzureUSGovernment'
    )

    $cloud = Get-AzureCloudSettings -AzureCloud $AzureCloud
    $credential = [PSCredential]::new($ApplicationId, $ClientSecret)

    Write-Log "Connecting to $($cloud.AzEnvironment) as $ApplicationId"
    Connect-AzAccount -ServicePrincipal `
        -TenantId $TenantId `
        -Credential $credential `
        -Environment $cloud.AzEnvironment | Out-Null

    Connect-MgGraph -TenantId $TenantId `
        -ClientSecretCredential $credential `
        -Environment $cloud.GraphEnvironment `
        -NoWelcome
}

function Get-SubscriptionRequest {
    <#
      Reads and validates one config/*.yaml request file. This file is the
      only declared desired state in the whole system - everything else is
      looked up live from Azure/Entra on every run.
    #>
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) {
        throw "Config file not found: $Path"
    }

    $raw = Get-Content -Path $Path -Raw | ConvertFrom-Yaml

    foreach ($field in @('subscriptionId','subscriptionName','environment','connectionName','roles')) {
        if (-not $raw.ContainsKey($field)) {
            throw "Config file '$Path' is missing required field '$field'"
        }
    }

    # How the service connection authenticates. Optional so request files
    # written before this field existed keep their original behaviour.
    $validAuthTypes = @('clientSecret', 'certificate', 'wif')
    $authType = if ($raw.ContainsKey('authType') -and $raw.authType) { [string]$raw.authType } else { 'clientSecret' }
    $canonicalAuthType = $validAuthTypes | Where-Object { $_ -eq $authType }   # case-insensitive match
    if (-not $canonicalAuthType) {
        throw "Config file '$Path' has authType '$authType' - must be one of: $($validAuthTypes -join ', ')"
    }

    return [PSCustomObject]@{
        SubscriptionId   = $raw.subscriptionId
        SubscriptionName = $raw.subscriptionName
        Environment      = $raw.environment
        ConnectionName   = $raw.connectionName
        Roles            = @($raw.roles)
        Scope            = $raw.scope   # optional resource group; omit for subscription-wide
        RequestedBy      = $raw.requestedBy
        AuthType         = $canonicalAuthType
        ConfigPath       = $Path
    }
}

function Get-AllowedRolePolicy {
    <#
      Loads policy/allowed-roles.yaml so the allow/deny list lives in one
      reviewable file instead of being hardcoded across scripts. Falls
      back to a conservative default if the file isn't found (e.g. when a
      script is run outside the repo layout).
    #>
    param(
        [string]$Path = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'policy/allowed-roles.yaml')
    )

    if (Test-Path $Path) {
        $policy = Get-Content -Path $Path -Raw | ConvertFrom-Yaml
        return [PSCustomObject]@{
            Allowed = @($policy.allowedRoles)
            Denied  = @($policy.deniedRoles)
        }
    }

    Write-Log "policy/allowed-roles.yaml not found at $Path - using built-in defaults." -Level WARN
    return [PSCustomObject]@{
        Allowed = @('Reader','Contributor','Storage Blob Data Contributor')
        Denied  = @('Owner','User Access Administrator')
    }
}

function Test-AllowedRoles {
    <#
      Policy-as-code gate. This is what actually reduces security's review
      burden - a request can never reach the point of creating a role
      assignment for anything on the deny list, PR approval or not.
    #>
    param(
        [Parameter(Mandatory)][string[]]$RequestedRoles,
        [string[]]$AllowedRoles,
        [string[]]$DeniedRoles
    )

    if (-not $AllowedRoles -or -not $DeniedRoles) {
        $policy = Get-AllowedRolePolicy
        if (-not $AllowedRoles) { $AllowedRoles = $policy.Allowed }
        if (-not $DeniedRoles)  { $DeniedRoles  = $policy.Denied }
    }

    foreach ($role in $RequestedRoles) {
        if ($DeniedRoles -contains $role) {
            throw "Role '$role' is explicitly denied by policy and can never be auto-approved."
        }
        if ($AllowedRoles -notcontains $role) {
            throw "Role '$role' is not on the allowed list. Add it to policy/allowed-roles.yaml if this is a genuine need."
        }
    }
}

function Get-DeterministicName {
    <#
      Every resource this automation creates is named from the config file
      alone, so any script can re-find it on a later run without a state
      file to remember the ID. Derived from connectionName (unique across
      config/, enforced in validate.yml) so every service connection gets
      its own app registration / service principal, even when several
      requests target the same subscription. Key Vault names only allow
      letters, digits and '-'.
    #>
    param(
        [Parameter(Mandatory)][string]$ConnectionName
    )
    return ($ConnectionName -replace '[^a-zA-Z0-9-]', '-').ToLower()
}

function Get-CertificateName {
    <# Key Vault certificate name for a request - distinct from the client secret's name. #>
    param([Parameter(Mandatory)][string]$DeterministicName)
    return "$DeterministicName-cert"
}

function Get-FederatedCredentialName {
    <# Federated credential names allow letters, digits, '-' and '_' (max 120). #>
    param([Parameter(Mandatory)][string]$ConnectionName)
    $safe = $ConnectionName -replace '[^a-zA-Z0-9_-]', '-'
    return ("ado-$safe").Substring(0, [Math]::Min(120, "ado-$safe".Length))
}

function Invoke-WithRetry {
    <#
      Entra ID is eventually consistent: an object created a moment ago
      can be missing from the replica serving the next call (e.g. "appId
      ... does not reference a valid application object", or a role
      assignment reporting PrincipalNotFound for a brand-new service
      principal). Retries the script block with exponential backoff.
      The script block must throw on failure (use -ErrorAction Stop).
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory)][string]$Activity,
        [int]$MaxAttempts = 6,
        [int]$InitialDelaySeconds = 5,
        [int]$MaxDelaySeconds = 30
    )

    $delay = $InitialDelaySeconds
    for ($attempt = 1; ; $attempt++) {
        try {
            return & $ScriptBlock
        } catch {
            if ($attempt -ge $MaxAttempts) {
                throw
            }
            Write-Log "$Activity failed (attempt $attempt of $MaxAttempts): $($_.Exception.Message) - retrying in $delay s." -Level WARN
            Start-Sleep -Seconds $delay
            $delay = [Math]::Min($delay * 2, $MaxDelaySeconds)
        }
    }
}

function ConvertTo-Thumbprint {
    <# Graph keyCredential customKeyIdentifier (SHA-1 thumbprint bytes) -> hex string. #>
    param([byte[]]$Bytes)
    if (-not $Bytes) { return $null }
    return ([BitConverter]::ToString($Bytes) -replace '-', '')
}

function ConvertFrom-SecureStringToPlainText {
    <#
      Cross-platform SecureString -> string. Marshal.PtrToStringAuto on a
      BSTR returns only the first character on Linux agents, so avoid it.
    #>
    param([Parameter(Mandatory)][securestring]$SecureString)
    return [Net.NetworkCredential]::new('', $SecureString).Password
}

function Set-AppKeyCredentials {
    <#
      Adds and/or removes certificate credentials on an app registration.
      Graph's addKey/removeKey calls need proof of possession from an
      existing certificate, which a first certificate can't provide, so
      this rewrites the whole keyCredentials list instead. Existing entries
      are sent back with key = $null, which tells Graph to keep them as-is.
    #>
    param(
        [Parameter(Mandatory)][string]$AppObjectId,
        [byte[]]$AddCertificate,              # DER-encoded public certificate
        [string]$AddDisplayName,
        [string[]]$RemoveThumbprints = @()
    )

    $app = Get-MgApplication -ApplicationId $AppObjectId -Property keyCredentials

    $credentials = @(foreach ($k in $app.KeyCredentials) {
        if ($RemoveThumbprints -contains (ConvertTo-Thumbprint $k.CustomKeyIdentifier)) { continue }
        @{
            keyId               = $k.KeyId
            type                = $k.Type
            usage               = $k.Usage
            customKeyIdentifier = $k.CustomKeyIdentifier
            displayName         = $k.DisplayName
            startDateTime       = $k.StartDateTime
            endDateTime         = $k.EndDateTime
            key                 = $null
        }
    })

    if ($AddCertificate) {
        $credentials += @{
            type        = 'AsymmetricX509Cert'
            usage       = 'Verify'
            key         = $AddCertificate
            displayName = $AddDisplayName
        }
    }

    Invoke-WithRetry -Activity "Updating certificate credentials on app $AppObjectId" -ScriptBlock {
        Update-MgApplication -ApplicationId $AppObjectId -KeyCredentials $credentials -ErrorAction Stop
    } | Out-Null
}

Export-ModuleMember -Function *
