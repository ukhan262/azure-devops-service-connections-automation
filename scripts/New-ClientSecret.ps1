#Requires -Modules Az.KeyVault, Microsoft.Graph.Applications

<#
.SYNOPSIS
  Idempotently ensures a usable client secret exists for the app
  registration, stored in Key Vault. Reuses the stored secret if it isn't
  close to expiry; otherwise adds a new password credential to the app
  and stores its value.

.NOTES
  The plaintext secret is only ever returned once, at creation time, from
  Microsoft Graph - it can never be read back from Graph afterwards. That
  means Key Vault, not Graph, is the source of truth for whether a usable
  secret currently exists: if Key Vault doesn't have a live copy, the
  script has to mint a new credential even if the app registration
  already has an unexpired one attached.

  Client secrets are a plaintext bearer credential, weaker than
  certificate-based auth - keep validity short (this defaults to 12
  months), rotate on a schedule, and treat the value as sensitive
  wherever it's held in memory.
#>
param(
    [Parameter(Mandatory)][string]$KeyVaultName,
    [Parameter(Mandatory)][string]$AppObjectId,
    [Parameter(Mandatory)][string]$SecretName,       # Key Vault secret name = deterministic name
    [int]$ValidityMonths = 12,
    [int]$RenewIfExpiringWithinDays = 30
)

Import-Module "$PSScriptRoot/common/Common.psm1" -Force

$existingSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName -ErrorAction SilentlyContinue

$needsNewSecret = $true
if ($existingSecret -and $existingSecret.Expires) {
    $daysToExpiry = ($existingSecret.Expires - (Get-Date)).Days
    if ($daysToExpiry -gt $RenewIfExpiringWithinDays) {
        Write-Log "Existing secret '$SecretName' is valid for $daysToExpiry more days - reusing."
        $needsNewSecret = $false
    } else {
        Write-Log "Existing secret '$SecretName' expires in $daysToExpiry days - issuing a replacement."
    }
} else {
    Write-Log "No usable secret named '$SecretName' found in $KeyVaultName - issuing a new one."
}

if ($needsNewSecret) {
    $endDateTime = (Get-Date).AddMonths($ValidityMonths)

    $credential = Invoke-WithRetry -Activity "Adding client secret '$SecretName'" -ScriptBlock {
        Add-MgApplicationPassword -ApplicationId $AppObjectId -PasswordCredential @{
            displayName = $SecretName
            endDateTime = $endDateTime
        } -ErrorAction Stop
    }

    $secureValue = ConvertTo-SecureString -String $credential.SecretText -AsPlainText -Force

    # Tag with the Graph key ID so the rotation script can remove exactly
    # this credential later, without guessing which one is "the old one".
    Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName `
        -SecretValue $secureValue `
        -Expires $endDateTime `
        -Tag @{ GraphKeyId = $credential.KeyId } | Out-Null

    $existingSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName
}

[PSCustomObject]@{
    SecretValue = $existingSecret.SecretValue   # SecureString
    Expires     = $existingSecret.Expires
    GraphKeyId  = $existingSecret.Tags['GraphKeyId']
}
