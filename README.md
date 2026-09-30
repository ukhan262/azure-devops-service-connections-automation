# Azure service connection automation

Self-service replacement for ticket-per-subscription service connection
requests. An app team adds a config file describing what they need; CI
validates it against policy; security approves the pull request; merging
to main triggers PowerShell automation that idempotently creates the app
registration, its credential (client secret, certificate, or workload
identity federation), the Azure DevOps service connection, and the RBAC
role assignments. No Terraform state - every step checks Azure
directly before acting, so re-running after a failure is always safe.

## Layout

- `config/` - one YAML file per subscription/environment request. The only
  declared desired state in the whole system.
- `policy/allowed-roles.yaml` - roles that can and can't be auto-approved.
- `scripts/` - idempotent PowerShell automation, called by the pipelines.
- `pipelines/` - Azure Pipelines YAML: PR validation, apply-on-merge, and
  scheduled credential rotation.

## Authentication types

Each request file picks how its service connection authenticates with
`authType`. Omitting it means `clientSecret`.

| `authType`     | What gets created | Stored where | Rotation |
| -------------- | ----------------- | ------------ | -------- |
| `clientSecret` | Client secret on the app registration; `spnKey` service connection | Key Vault secret `<name>` | New secret within 30 days of expiry |
| `certificate`  | Self-signed Key Vault certificate; public part on the app registration; `spnCertificate` service connection | Key Vault certificate `<name>-cert` | New certificate version within 30 days of expiry |
| `wif`          | Workload identity federation service connection, plus a federated credential on the app registration trusting it | Nothing - no stored credential | None needed |

`<name>` is the request's `connectionName`, lowercased, with anything other than letters, digits and `-` replaced by `-`. Each request therefore gets its own app registration and service principal, even when several requests target the same subscription.

- **Certificate:** the private key has to be exportable, because the
  service connection needs the PEM (private key + certificate). Key Vault
  is the only other place it's kept.
- **WIF:** Azure DevOps creates the connection first and returns the
  issuer and subject; the federated credential (`ado-<connectionName>`)
  is then created with those values and the cloud's audience
  (`api://AzureADTokenExchange`, or `api://AzureADTokenExchangeUSGov` for
  Azure Government).
- **Changing `authType`** on an already-provisioned request updates the
  existing service connection in place. The previous credential (secret,
  certificate or federated credential) is left on the app registration;
  remove it by hand once the connection works.

## Azure Government vs commercial Azure

`pipelines/apply.yml` and `pipelines/rotate-secrets.yml` take an
`azureCloud` runtime parameter:

| `azureCloud`                  | Target                 | Variable group                                  |
| ----------------------------- | ---------------------- | ----------------------------------------------- |
| `AzureUSGovernment` (default) | Azure Government       | `azure-service-connections-secrets`             |
| `AzureCloud`                  | Commercial/public Azure | `azure-service-connections-secrets-commercial` |

The flag controls the Az and Microsoft Graph login environments, plus the
`environment` and management URL written into each service connection
(`Get-AzureCloudSettings` in `scripts/common/Common.psm1`). The scripts
take the same value as `-AzureCloud` when you run them directly.

Each cloud has its own Entra tenant, so each needs its own bootstrap
service principal, Key Vault, and variable group. Both variable groups
use the same variable names. A single run targets one cloud.

Scheduled and CI-triggered runs always use the parameter default
(`AzureUSGovernment`). To automate commercial Azure too, create a second
pipeline definition from a copy of the YAML with `default: AzureCloud`.

## Agent pools

All three pipelines take a `poolType` runtime parameter:

- `selfHosted` (default): runs on `selfHostedPoolName` (default
  `OnPremAgents`). The agents need the PowerShell modules listed in setup
  step 3 installed beforehand.
- `microsoftHosted`: runs on an Azure Pipelines hosted agent using
  `vmImage` (default `ubuntu-latest`).
  `pipelines/templates/install-modules.yml` installs the required modules
  at the start of each run. Microsoft-hosted agents exist only on Azure
  DevOps Services, not on Azure DevOps Server. They also need network
  access to `CollectionUrl`, Key Vault, Entra ID and ARM for the chosen
  cloud.

Like `azureCloud`, scheduled, CI and PR-triggered runs use the parameter
defaults. To have triggered runs use hosted agents, change `default:` in
the YAML.

## One-time setup (by security)

1. Create the pipeline's bootstrap service principal manually
   (`Application Administrator` + `User Access Administrator` at the
   management group scope), issue it a client secret, and store the
   secret where only the CD pipeline's agent can read it.
   The bootstrap identity also needs to create, read and update secrets
   and certificates in the Key Vault (`Key Vault Secrets Officer` +
   `Key Vault Certificates Officer` with Azure RBAC, or the equivalent
   access policies).
2. Create a variable group named `azure-service-connections-secrets`
   holding: `TenantId`, `BootstrapAppId`, `BootstrapClientSecret`,
   `KeyVaultName`, `CollectionUrl`, `ProjectName`, `PersonalAccessToken`.
   Mark the client secret and PAT as secret variables. The PAT needs
   **Service Connections (Read, query & manage)** and **Project and
   Team (Read)**. For commercial
   Azure, repeat steps 1-2 in the commercial tenant and name the group
   `azure-service-connections-secrets-commercial`.
3. Install `Az`, `Microsoft.Graph.Authentication`,
   `Microsoft.Graph.Applications`, and `powershell-yaml` on your
   self-hosted agent pool. Skip this if you only use Microsoft-hosted
   agents (see "Agent pools").
4. Add `pipelines/validate.yml` as a PR build validation policy on `main`
   for the `config/**` path, and require security as reviewers on that
   path (`CODEOWNERS` or an equivalent branch policy).
5. Point `pipelines/apply.yml` at merges to `main`, and schedule
   `pipelines/rotate-secrets.yml` (weekly is reasonable).
6. Optionally attach an approval check to the `production-azure-access`
   environment referenced in `apply.yml` for an extra gate beyond PR
   review.

Prefer `wif` for new requests: there is no secret or key to leak or
rotate. `certificate` is next best. `clientSecret` is a plaintext bearer
credential; keep it for cases where the other two don't work. Whatever
the request types, make sure the variable group holding
`BootstrapClientSecret` is locked down to the pipeline itself.

## Requesting a subscription

Copy an existing file in `config/` (e.g.
`config/tc-development-subscription.yaml`), fill in the fields including
`authType`, and open a pull request. That's the entire request process - no ticket.

## Before you trust it in production

The Azure DevOps REST payloads in `scripts/New-ServiceConnection.ps1`
(one per `authType`) follow the api-version 7.1 contract but have not all
been exercised against a live organization. For each auth type, create
one connection manually through the UI, `GET` it back, and diff the JSON
shape against what the script sends.
