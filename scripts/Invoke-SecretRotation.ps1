<#
.SYNOPSIS
  Scheduled job: walks every subscription request in config/, and for any
  whose credential is close to expiry, issues a replacement and pushes it
  to both the app registration and the Azure DevOps service connection.
  Handles client secrets and certificates; workload identity federation
  connections have no stored credential and are skipped. Run this on a
  schedule (weekly is reasonable against a 30-day renewal window) rather
  than per-request.

.NOTES
  In both cases the new credential is added alongside the old one, the
  service connection is switched to the new one, and only then is the old
  one removed from the app registration - a grace window instead of a
  hard cutover.
#>
param(
    [Parameter(Mandatory)][string]$ConfigFolder,
    [Parameter(Mandatory)][string]$KeyVaultName,
    [Parameter(Mandatory)][string]$CollectionUrl,
    [Parameter(Mandatory)][string]$ProjectName,
    [Parameter(Mandatory)][string]$PersonalAccessToken,
    [Parameter(Mandatory)][string]$TenantId,
    [ValidateSet('AzureUSGovernment','AzureCloud')][string]$AzureCloud = 'AzureUSGovernment',
    [int]$RenewIfExpiringWithinDays = 30
)

$root = $PSScriptRoot
Import-Module "$root/common/Common.psm1" -Force

$configFiles = Get-ChildItem -Path $ConfigFolder -Filter '*.yaml'
$rotated = @()

foreach ($file in $configFiles) {
    try {
        $request = Get-SubscriptionRequest -Path $file.FullName
        $name = Get-DeterministicName -ConnectionName $request.ConnectionName

        if ($request.AuthType -eq 'wif') {
            Write-Log "'$name' uses workload identity federation - nothing to rotate."
            continue
        }

        $connectionArgs = @{
            CollectionUrl       = $CollectionUrl
            ProjectName         = $ProjectName
            ConnectionName      = $request.ConnectionName
            PersonalAccessToken = $PersonalAccessToken
            TenantId            = $TenantId
            SubscriptionId      = $request.SubscriptionId
            SubscriptionName    = $request.SubscriptionName
            AzureCloud          = $AzureCloud
            AuthType            = $request.AuthType
        }

        if ($request.AuthType -eq 'clientSecret') {
            $existingSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $name -ErrorAction SilentlyContinue
            if (-not $existingSecret) {
                Write-Log "No secret found for '$name' - skipping (has it been provisioned yet?)" -Level WARN
                continue
            }

            $daysToExpiry = ($existingSecret.Expires - (Get-Date)).Days
            if ($daysToExpiry -gt $RenewIfExpiringWithinDays) {
                continue   # nothing to do this run
            }

            Write-Log "Rotating client secret for '$name' (expires in $daysToExpiry days)."

            $app = Get-MgApplication -Filter "displayName eq '$name'"
            $oldKeyId = $existingSecret.Tags['GraphKeyId']

            $newSecret = & "$root/New-ClientSecret.ps1" -KeyVaultName $KeyVaultName -AppObjectId $app.Id -SecretName $name `
                -RenewIfExpiringWithinDays $RenewIfExpiringWithinDays

            & "$root/New-ServiceConnection.ps1" @connectionArgs -ServicePrincipalAppId $app.AppId `
                -ClientSecret $newSecret.SecretValue | Out-Null

            # Only remove the old Graph password credential now that the
            # service connection is confirmed to be using the new one.
            if ($oldKeyId) {
                Remove-MgApplicationPassword -ApplicationId $app.Id -KeyId $oldKeyId
            }
        }
        elseif ($request.AuthType -eq 'certificate') {
            $certName = Get-CertificateName -DeterministicName $name
            $existingCert = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $certName -ErrorAction SilentlyContinue
            if (-not $existingCert) {
                Write-Log "No certificate found for '$name' - skipping (has it been provisioned yet?)" -Level WARN
                continue
            }

            $daysToExpiry = ($existingCert.Expires - (Get-Date)).Days
            if ($daysToExpiry -gt $RenewIfExpiringWithinDays) {
                continue
            }

            Write-Log "Rotating certificate for '$name' (expires in $daysToExpiry days)."

            $app = Get-MgApplication -Filter "displayName eq '$name'"

            $newCert = & "$root/New-ClientCertificate.ps1" -KeyVaultName $KeyVaultName -AppObjectId $app.Id `
                -CertificateName $certName -RenewIfExpiringWithinDays $RenewIfExpiringWithinDays

            & "$root/New-ServiceConnection.ps1" @connectionArgs -ServicePrincipalAppId $app.AppId `
                -CertificatePem $newCert.CertificatePem | Out-Null

            # Now that the service connection uses the new certificate,
            # stop trusting the old one.
            if ($existingCert.Thumbprint -ne $newCert.Thumbprint) {
                Set-AppKeyCredentials -AppObjectId $app.Id -RemoveThumbprints $existingCert.Thumbprint
            }
        }

        $rotated += "$name ($($request.AuthType))"
    } catch {
        Write-Log "Failed to rotate credential for $($file.Name): $_" -Level ERROR
    }
}

if ($rotated.Count -gt 0) {
    Write-Log "Rotated credentials for: $($rotated -join ', ')"
    # Hook your Teams/Slack webhook call here.
} else {
    Write-Log "No credentials needed rotation this run."
}
