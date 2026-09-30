#Requires -Modules Az.KeyVault, Microsoft.Graph.Applications

<#
.SYNOPSIS
  Idempotently ensures a usable certificate exists for the app
  registration. Key Vault generates and holds the certificate; only the
  public part is uploaded to the app registration. Reuses the current
  Key Vault certificate unless it is close to expiry, in which case a new
  version is issued.

.NOTES
  The certificate is issued with a PEM secret content type, so the secret
  Key Vault stores alongside it is exactly what an Azure DevOps
  spnCertificate service connection expects: private key + certificate in
  one PEM. The key must therefore be exportable - Key Vault is still the
  only place it's stored outside the service connection itself.

  This does not remove older certificates from the app registration; the
  rotation script does that once the service connection has been switched
  to the new one.
#>
param(
    [Parameter(Mandatory)][string]$KeyVaultName,
    [Parameter(Mandatory)][string]$AppObjectId,
    [Parameter(Mandatory)][string]$CertificateName,   # Key Vault certificate name
    [int]$ValidityMonths = 12,
    [int]$RenewIfExpiringWithinDays = 30,
    [int]$IssuanceTimeoutSeconds = 300
)

Import-Module "$PSScriptRoot/common/Common.psm1" -Force

$cert = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $CertificateName -ErrorAction SilentlyContinue

$needsNewCert = $true
if ($cert -and $cert.Expires) {
    $daysToExpiry = ($cert.Expires - (Get-Date)).Days
    if ($daysToExpiry -gt $RenewIfExpiringWithinDays) {
        Write-Log "Existing certificate '$CertificateName' is valid for $daysToExpiry more days - reusing."
        $needsNewCert = $false
    } else {
        Write-Log "Existing certificate '$CertificateName' expires in $daysToExpiry days - issuing a new version."
    }
} else {
    Write-Log "No certificate named '$CertificateName' found in $KeyVaultName - issuing a new one."
}

if ($needsNewCert) {
    $policy = New-AzKeyVaultCertificatePolicy `
        -SecretContentType 'application/x-pem-file' `
        -SubjectName "CN=$CertificateName" `
        -IssuerName 'Self' `
        -ValidityInMonths $ValidityMonths `
        -KeyType RSA -KeySize 2048

    Add-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $CertificateName -CertificatePolicy $policy | Out-Null

    # Issuance is asynchronous, even for self-signed certificates.
    $deadline = (Get-Date).AddSeconds($IssuanceTimeoutSeconds)
    do {
        Start-Sleep -Seconds 5
        $operation = Get-AzKeyVaultCertificateOperation -VaultName $KeyVaultName -Name $CertificateName
    } while ($operation.Status -eq 'inProgress' -and (Get-Date) -lt $deadline)

    if ($operation.Status -ne 'completed') {
        throw "Key Vault did not issue certificate '$CertificateName' (status: $($operation.Status); $($operation.ErrorMessage))."
    }

    $cert = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $CertificateName
}

# --- Make sure the app registration trusts this certificate ---
$app = Get-MgApplication -ApplicationId $AppObjectId -Property keyCredentials
$alreadyOnApp = $app.KeyCredentials |
    Where-Object { (ConvertTo-Thumbprint $_.CustomKeyIdentifier) -eq $cert.Thumbprint }

if ($alreadyOnApp) {
    Write-Log "Certificate $($cert.Thumbprint) is already on the app registration - skipping upload."
} else {
    Write-Log "Uploading certificate $($cert.Thumbprint) to the app registration."
    Set-AppKeyCredentials -AppObjectId $AppObjectId `
        -AddCertificate $cert.Certificate.RawData `
        -AddDisplayName "CN=$CertificateName"
}

# PEM (private key + certificate) for this exact certificate version.
$pem = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $CertificateName -Version $cert.Version

[PSCustomObject]@{
    CertificatePem = $pem.SecretValue   # SecureString
    Thumbprint     = $cert.Thumbprint
    Expires        = $cert.Expires
}
