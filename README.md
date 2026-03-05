# CIS Microsoft Azure Foundations Benchmark v5.0.0 — Audit Tool

**Version:** 1.0.0
**Benchmark:** CIS Microsoft Azure Foundations Benchmark v5.0.0 (September 2025)
**Coverage:** 93 of 95 automated controls · 2 manual controls noted in output

---

## Overview

A Python tool that audits an Azure tenant against the CIS Microsoft Azure Foundations Benchmark v5.0.0.
It requires no pip installs — only Python 3.10+ and the Azure CLI.

Results are saved as checkpoints after each subscription completes, so a failed or interrupted run
can be resumed without re-running completed work. Output is a self-contained HTML report with
filtering, compliance scoring, and per-finding remediation guidance.

---

## Requirements

### Runtime

| Requirement | Details |
| --- | --- |
| Python | 3.10 or higher |
| Azure CLI | Any recent version — <https://aka.ms/install-azure-cli> |
| resource-graph extension | Installed automatically on first run |
| Azure login | `az login` completed before running |

### Azure permissions

| Scope | Role |
| --- | --- |
| Each subscription | Reader |
| Each subscription | Security Reader |
| Microsoft Entra ID (tenant) | Global Reader (for identity checks 5.x; not programmatically verified) |

### Development prerequisites

If you're planning to modify or lint the code, install the development dependencies:

```bash
pip install -r requirements-dev.txt
```

This brings in `flake8`, `mypy`, and optionally `rich` for richer console output.

---

## Permission Preflight

Before auditing subscriptions the tool verifies the signed-in account has the required roles:

- **Reader** and **Security Reader** on each target subscription
- **Global Reader** at the tenant level (for identity-related checks; not validated by the tool)

If any roles are missing the script will abort early with a concise list of shortfalls.
This prevents long runs that then fail due to insufficient permissions.

---

## Quick Start

```powershell
# 1. Login to Azure
az login

# 2. Run the audit
python cis_azure_audit.py
```

The script will automatically install the `resource-graph` extension if missing, enumerate all
enabled subscriptions, run all checks, and save `cis_azure_audit_report.html` in the current
directory.

---

## Usage

```text
python cis_azure_audit.py [options]
```

| Option | Description |
| --- | --- |
| `-s`, `--subscription` | Audit a single subscription by name or ID |
| `-o`, `--output` | Output HTML filename (default: `cis_azure_audit_report.html`) |
| `-p`, `--parallel` | Concurrent subscription workers (default: 2) |
| `--executor` | Worker backend: `process` (default) or `thread` |
| `--no-adaptive-concurrency` | Disable dynamic worker tuning when throttling is detected |
| `-l`, `--level` | Filter output to Level 1 or Level 2 controls only |
| `--fresh` | Clear all checkpoints and start from scratch |
| `--report-only` | Regenerate HTML from existing checkpoints, no API calls |
| `--log-level` | Base log level: `TRACE`, `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `-v`, `--verbose` | Enable verbose logging (sets `DEBUG`) |
| `--debug` | Enable trace logging (sets `TRACE`) |
| `--log-file` | Write structured logs to a file (in addition to console) |
| `--skip-preflight` | Skip permission preflight checks |

### Logging flags

Logging level precedence is:

1. `--debug` (most verbose, `TRACE`)
2. `--verbose` (`DEBUG`)
3. `--log-level` (default `INFO`)

Use `--log-file` to keep a persistent log while still printing concise output to the console.

### Concurrency tuning

The audit adapts worker count automatically when Azure API throttling (HTTP 429 / rate limit
retries) is detected:

- Starts at `--parallel` workers (minimum 1).
- Reduces workers when transient throttling retries spike.
- Gradually increases workers again after stable batches without throttling.

Default execution uses `--executor process --parallel 2`, based on benchmark results in this
environment. Users can still override both defaults at runtime.

Use `--no-adaptive-concurrency` to keep worker count fixed.

#### Benchmark your own defaults

Use a representative subscription and compare elapsed time across candidate settings, then pick
the fastest *stable* option (few/no throttling retries).

```powershell
$py = "python"
$sub = "<YOUR-LARGEST-SUBSCRIPTION-NAME>"
$runs = @(
  @{executor="process"; parallel=2},
  @{executor="process"; parallel=4},
  @{executor="thread";  parallel=2}
)

foreach ($r in $runs) {
  $label = "$($r.executor)-p$($r.parallel)"
  $log = "bench_$label.log"
  $elapsed = Measure-Command {
    & $py cis_azure_audit.py --subscription "$sub" --executor $r.executor --parallel $r.parallel `
      --level 1 --fresh --skip-preflight --output "bench_$label.html" --log-file $log *> $null
  }
  $transient = (Select-String -Path $log -Pattern "transient error detected" -SimpleMatch | Measure-Object).Count
  Write-Output "$label : $([Math]::Round($elapsed.TotalSeconds,2))s ; transient_retries=$transient"
}
```

Tip: run each candidate 2–3 times and compare median runtime, not a single run.

### Examples

```powershell
# Audit all subscriptions
python cis_azure_audit.py

# Audit one subscription
python cis_azure_audit.py -s "Production"

# Run faster with more parallel workers
python cis_azure_audit.py --parallel 5

# Use thread workers instead of the process default
python cis_azure_audit.py --executor thread --parallel 4

# Keep a fixed worker count (disable adaptive throttling response)
python cis_azure_audit.py --parallel 6 --no-adaptive-concurrency

# Script was interrupted? Just re-run — it resumes automatically
python cis_azure_audit.py

# Start completely fresh, ignoring previous checkpoints
python cis_azure_audit.py --fresh

# Regenerate the HTML report without re-running any checks
python cis_azure_audit.py --report-only

# Level 1 controls only
python cis_azure_audit.py --level 1

# Verbose per-check diagnostics
python cis_azure_audit.py --verbose

# Trace-level diagnostics and write logs to file
python cis_azure_audit.py --debug --log-file cis_audit.log
```

---

## How It Works

### Data collection — three methods

#### 1. Azure Resource Graph (bulk prefetch — runs once per audit)

Before any per-subscription work begins, a set of Kusto queries fetches all relevant resources
across the entire tenant in one round trip. Resources fetched via Resource Graph:

- Network Security Groups and all security rules
- Storage accounts and their security properties
- Key Vaults — access configuration and network settings
- Virtual Networks, subnets, and NSG associations
- Application Gateways and WAF settings
- Databricks workspaces
- Bastion Hosts
- Network Watchers and resource locations
- Role assignments (Owner and User Access Administrator)
- WAF policies

#### 2. Azure CLI calls per subscription

For data Resource Graph cannot return — live service configurations, diagnostic settings, activity
log alerts, and storage service properties:

- `az security pricing show` — all Defender plan statuses (8.1.x)
- `az security contact list` — notification settings (8.1.12–8.1.15)
- `az monitor diagnostic-settings list` — Key Vault and App Service logging
- `az monitor activity-log alert list` — all 11 alert checks (6.1.2.x)
- `az keyvault key/secret list` — expiry dates per key and secret
- `az keyvault key rotation-policy show` — auto rotation configuration
- `az keyvault certificate show` — certificate validity periods
- `az storage account blob-service-properties show` — soft delete, versioning
- `az storage account file-service-properties show` — file soft delete, SMB settings
- `az network watcher flow-log list` — flow log retention (7.5, 7.8)
- `az role definition list` — custom admin roles (5.23)

#### 3. Azure REST API via `az rest`

For tenant-level identity checks where only the Graph or ARM REST API applies:

- `graph.microsoft.com/v1.0/policies/authorizationPolicy` — covers 5.4, 5.14, 5.15, 5.16
- ARM REST for WDATP integration settings (8.1.3.3) and attack path notifications (8.1.15)

### Checkpoints and resume

After each subscription completes, results are written to `cis_checkpoints/<subscription-id>.json`.
If the script is stopped or crashes mid-run, re-running it will automatically skip completed
subscriptions and continue from where it left off. Use `--fresh` to discard all checkpoints.

### Parallel execution

Subscriptions run concurrently via Python's `concurrent.futures` executor. The default is 2
parallel workers. Increase with `--parallel` for large tenants. The Resource Graph prefetch always
runs once before the parallel loop begins.

---

## HTML Report

The generated report is a self-contained HTML file with no external dependencies.

- **Summary cards** — compliance score (PASS / total, excluding INFO and MANUAL), plus individual counts for each status.
- **Compliance chart** — a pie chart shows PASS/FAIL/ERROR proportions at a glance.
- **Filterable table** — filter simultaneously by free-text search, status, and level (L1/L2). Section headers collapse automatically when all their results are filtered out.
- **Per-resource results** — each NSG, storage account, Key Vault, subnet, and Databricks workspace is reported individually, not aggregated to a single pass/fail per control.
- **Remediation hints** — every FAIL result includes the Azure portal navigation path to fix the issue.
- **Export JSON/CSV** — download the currently filtered results for automation or sharing.
- **Back to top** — fixed button in the bottom-right corner for long reports.

### Status types

| Status | Meaning |
| --- | --- |
| PASS | Control is compliant |
| FAIL | Control is non-compliant — remediation hint provided |
| ERROR | Check could not complete (permissions issue, timeout, or API error) |
| INFO | Not applicable — no resources of this type exist, or control does not apply |
| MANUAL | Cannot be automated — requires manual verification per the CIS PDF |

---

## Controls Covered

### Section 2 — Azure Databricks (5 of 6 automated)

| Control | Title | Level |
| --- | --- | --- |
| 2.1.2 | NSGs configured for Databricks subnets | L1 |
| 2.1.7 | Diagnostic logging configured | L1 |
| 2.1.9 | No Public IP enabled | L1 |
| 2.1.10 | Public network access disabled | L1 |
| 2.1.11 | Private endpoints used to access workspaces | L2 |

> **2.1.1** (Databricks in customer-managed VNet) — pending implementation.

### Section 5 — Identity Services (9 automated)

| Control | Title | Level |
| --- | --- | --- |
| 5.1.1 | Security defaults enabled | L1 |
| 5.1.2 | MFA enabled for all users | L1 |
| 5.3.3 | User Access Administrator role restricted | L1 |
| 5.4 | Restrict non-admin users from creating tenants | L1 |
| 5.14 | Users cannot register applications | L1 |
| 5.15 | Guest access restricted to own directory objects | L1 |
| 5.16 | Guest invite restrictions set to admins or no one | L2 |
| 5.23 | No custom subscription administrator roles | L1 |
| 5.27 | Between 2 and 3 subscription owners | L1 |

> **5.1.1** — returns INFO for E3/E5 tenants using Conditional Access (security defaults are mutually exclusive with CA).
> **5.1.2** — returns MANUAL. The only audit method in the CIS PDF is `Get-MgUser` via Graph PowerShell; there is no `az` CLI equivalent.

### Section 6 — Management and Governance (16 automated)

| Control | Title | Level |
| --- | --- | --- |
| 6.1.1.1 | Diagnostic Setting exists for Subscription Activity Logs | L1 |
| 6.1.1.2 | Diagnostic Setting captures required categories | L1 |
| 6.1.1.4 | Key Vault diagnostic logging enabled | L1 |
| 6.1.1.6 | Azure AppService HTTP logs enabled | L2 |
| 6.1.2.1 | Activity Log Alert: Create Policy Assignment | L1 |
| 6.1.2.2 | Activity Log Alert: Delete Policy Assignment | L1 |
| 6.1.2.3 | Activity Log Alert: Create or Update NSG | L1 |
| 6.1.2.4 | Activity Log Alert: Delete NSG | L1 |
| 6.1.2.5 | Activity Log Alert: Create or Update Security Solution | L1 |
| 6.1.2.6 | Activity Log Alert: Delete Security Solution | L1 |
| 6.1.2.7 | Activity Log Alert: Create or Update SQL Firewall Rule | L1 |
| 6.1.2.8 | Activity Log Alert: Delete SQL Firewall Rule | L1 |
| 6.1.2.9 | Activity Log Alert: Create or Update Public IP | L1 |
| 6.1.2.10 | Activity Log Alert: Delete Public IP | L1 |
| 6.1.2.11 | Activity Log Alert: Service Health | L1 |
| 6.1.3.1 | Application Insights configured | L2 |

### Section 7 — Networking Services (13 automated)

| Control | Title | Level |
| --- | --- | --- |
| 7.1 | RDP (3389) not open to internet | L1 |
| 7.2 | SSH (22) not open to internet | L1 |
| 7.3 | UDP access from internet restricted | L1 |
| 7.4 | HTTP/HTTPS (80/443) from internet evaluated and restricted | L1 |
| 7.5 | NSG flow log retention >= 90 days | L2 |
| 7.6 | Network Watcher enabled for all regions in use | L2 |
| 7.8 | VNet flow log retention >= 90 days | L2 |
| 7.10 | WAF enabled on Azure Application Gateway | L2 |
| 7.11 | Subnets associated with NSGs | L1 |
| 7.12 | App Gateway SSL policy min TLS 1.2+ | L1 |
| 7.13 | HTTP2 enabled on Application Gateway | L1 |
| 7.14 | WAF request body inspection enabled | L2 |
| 7.15 | WAF bot protection enabled | L2 |

### Section 8 — Security Services (29 automated)

| Control | Title | Level |
| --- | --- | --- |
| 8.1.1.1 | Microsoft Defender CSPM | L2 |
| 8.1.2.1 | Microsoft Defender for APIs | L2 |
| 8.1.3.1 | Microsoft Defender for Servers | L2 |
| 8.1.3.3 | Endpoint protection (WDATP) component | L2 |
| 8.1.4.1 | Microsoft Defender for Containers | L2 |
| 8.1.5.1 | Microsoft Defender for Storage | L2 |
| 8.1.6.1 | Microsoft Defender for App Services | L2 |
| 8.1.7.1 | Microsoft Defender for Azure Cosmos DB | L2 |
| 8.1.7.2 | Microsoft Defender for Open-Source Relational DBs | L2 |
| 8.1.7.3 | Microsoft Defender for SQL (Managed Instance) | L2 |
| 8.1.7.4 | Microsoft Defender for SQL Servers on Machines | L2 |
| 8.1.8.1 | Microsoft Defender for Key Vault | L2 |
| 8.1.9.1 | Microsoft Defender for Resource Manager | L2 |
| 8.1.10 | Defender configured to check VM OS updates | L1 |
| 8.1.12 | Security alerts notify subscription Owners | L1 |
| 8.1.13 | Additional email addresses for security contact | L1 |
| 8.1.14 | Alert severity notifications configured | L1 |
| 8.1.15 | Attack path notifications configured | L1 |
| 8.3.1 | Key expiration set — RBAC Key Vaults | L1 |
| 8.3.2 | Key expiration set — non-RBAC Key Vaults | L1 |
| 8.3.3 | Secret expiration set — RBAC Key Vaults | L1 |
| 8.3.4 | Secret expiration set — non-RBAC Key Vaults | L1 |
| 8.3.5 | Key Vault purge protection enabled | L1 |
| 8.3.6 | Key Vault RBAC authorization enabled | L2 |
| 8.3.7 | Key Vault public network access disabled | L1 |
| 8.3.8 | Private endpoints used to access Key Vault | L2 |
| 8.3.9 | Automatic key rotation enabled | L2 |
| 8.3.11 | Certificate validity period <= 12 months | L1 |
| 8.4.1 | Azure Bastion Host exists | L2 |
| 8.5 | DDoS Network Protection enabled on VNets | L2 |

### Section 9 — Storage Services (19 automated)

| Control | Title | Level |
| --- | --- | --- |
| 9.1.1 | Azure Files soft delete enabled | L1 |
| 9.1.2 | SMB protocol version >= 3.1.1 | L1 |
| 9.1.3 | SMB channel encryption AES-256-GCM or higher | L1 |
| 9.2.1 | Blob soft delete enabled | L1 |
| 9.2.2 | Container soft delete enabled | L1 |
| 9.2.3 | Blob versioning enabled | L2 |
| 9.3.1.1 | Key rotation reminders enabled | L1 |
| 9.3.1.2 | Access keys regenerated within 90 days | L1 |
| 9.3.1.3 | Storage account key access disabled | L1 |
| 9.3.2.1 | Private endpoints used to access storage accounts | L2 |
| 9.3.2.2 | Public network access disabled | L1 |
| 9.3.2.3 | Default network access rule is Deny | L1 |
| 9.3.3.1 | Default to Microsoft Entra authorization in Azure portal | L1 |
| 9.3.4 | Secure transfer (HTTPS) required | L1 |
| 9.3.5 | Allow Azure trusted services to access storage | L2 |
| 9.3.6 | Minimum TLS version 1.2 | L1 |
| 9.3.7 | Cross-tenant replication disabled | L1 |
| 9.3.8 | Blob anonymous access disabled | L1 |
| 9.3.9 | Storage account has CanNotDelete resource lock | L1 |
| 9.3.10 | Storage account has ReadOnly resource lock | L2 |
| 9.3.11 | Redundancy set to geo-redundant (GRS) | L2 |

---

## Testing

The test suite uses Python's built-in `unittest` — no extra packages required.
All tests mock Azure CLI calls so no real Azure connection is needed.

### Run everything

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

### Run one test file

```powershell
python -m unittest tests.test_permissions -v
python -m unittest tests.test_retry -v
```

### Run one test class

```powershell
python -m unittest tests.test_permissions.TestPermissionHelpers -v
python -m unittest tests.test_permissions.TestPreflight -v
```

### Continuous Integration

A GitHub Actions pipeline runs on every push and pull request:

- `python -m unittest` (Python 3.10, 3.11, 3.12, 3.13)
- `black --check` formatting
- `flake8` linting
- `mypy` static type checks

The workflow file lives at `.github/workflows/ci.yml`.

---

## Checkpoint Files

```text
cis_checkpoints/
  |- xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.json   <- completed
  |- yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy.json   <- completed
  `- zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz.json  <- failed (retried on next run)
```

Each file contains the full result set for that subscription, a UTC timestamp, and a completion
status. Delete the `cis_checkpoints/` folder or use `--fresh` to discard all checkpoints.

---

## Known Limitations

**Read-only** — the script audits only. It makes no changes to your environment.

**Point-in-time** — results reflect the state at the moment the script ran.

**Key Vault data plane access** — listing keys and secrets requires data plane permissions in
addition to subscription Reader. Assign Key Vault Reader (RBAC vaults) or add the runner to the
vault's access policy (non-RBAC vaults).

**Graph API for identity checks** — controls 5.4, 5.14, 5.15, and 5.16 use `az rest` to call
the Graph API. If your tenant has not consented to the required Graph permissions for the Azure
CLI app, these will return ERROR. Test with:

```powershell
az rest --method get --url "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
```

**Conditional Access policies (5.2.x)** — these controls are marked Manual in the benchmark and
are not checked by this script. They require review in the Entra ID portal.

**Large tenants** — Resource Graph handles bulk data efficiently. The main bottleneck at scale is
per-subscription CLI calls. Use `--parallel 5` or higher for tenants with many subscriptions.

---

## Troubleshooting

**`az` not found on Windows**
The script automatically uses `az.cmd` on Windows. Ensure the Azure CLI is installed and on your
PATH, then restart your terminal.

**Identity checks return ERROR (AccessDenied)**
Your account needs Global Reader in Entra ID. Test the Graph call directly:

```powershell
az rest --method get --url "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
```

If this fails, ask your Entra ID admin to grant Global Reader or consent to the required Graph
API permissions for the Azure CLI app (app ID: 04b07795-8ddb-461a-bbee-02f9e1bf7b46).

**A check consistently times out**
All `az` CLI calls have a 25-second timeout (15 seconds for storage service property calls).
Timed-out checks are recorded as ERROR and the script continues.

---

## Attribution

This tool is an independent implementation referencing the publicly available CIS Microsoft Azure
Foundations Benchmark v5.0.0. CIS Benchmarks are the property of the Center for Internet Security
(<https://www.cisecurity.org>). This tool is not affiliated with or endorsed by CIS.
