# CIS Azure Benchmark Audit Tools — Review Action Items

Cross-repo review of both **Python** (`CIS-Azure-Benchmark-Audit-Tool`) and **PowerShell** (`CISAzureBenchmark-PS`) tools.

---

## Completed

- [x] **Both: Add Section 3 — check 3.1.1 (manual)**
  CIS Benchmark Sections 3 (Compute) and 4 (Database) are reference sections — most controls relocated to separate CIS benchmarks. Only 3.1.1 (MFA for privileged VM access) remains as an auditable control in the Foundations Benchmark. Cannot be fully automated (requires correlating role assignments with per-user MFA status and Conditional Access policy evaluation). Added as a manual check to both tools with `Section3.ps1` / `s3.py`, registered in tenant-level check loops, and documented in both READMEs.

- [x] **PS README: Fix `-Subscriptions` parameter description**
  Changed "subscription IDs" to "subscription names or IDs".

- [x] **PS README: Add 2.1.1 pending note**
  Added note after Section 2 table matching the Python README.

- [x] **PS README: Fix troubleshooting "GUIDs only" text**
  Replaced "Subscription IDs must be exact GUIDs" with accurate guidance that names or IDs work.

- [x] **Python `_friendly_error()`: Fix Key Vault default message bug**
  Now checks for "key vault" / "keyvault" in the error before using the KV-specific message. Generic RBAC errors get a resource-agnostic message instead.

- [x] **Python README: Fix Section 6 title**
  Changed "Management and Governance" to "Logging and Monitoring".

- [x] **PS: Implement suppressions system**
  Implemented full suppression system in `Suppressions.ps1`: `Get-Suppressions` (JSON loading, expiry validation, 365-day max), `Invoke-Suppressions` (apply SUPPRESSED status), `Find-SuppressionMatch` (exact/wildcard matching), `Show-Suppressions` (pretty-print). Integrated in main script with `-SuppressionsFile` param. Documented in README.

- [x] **PS: Add `-ExitCode` switch**
  Added `-ExitCode` switch param. When set, script exits with code 2 if any FAIL or ERROR results are found after suppression. Documented in README with CI/CD examples.

- [x] **PS: Add JSON/CSV file export**
  Added JSON (`ConvertTo-Json`) and CSV export to `Report.ps1`, written alongside the HTML report. Documented in README "Output files" section.

- [x] **PS: Enforce `$TimeoutSec` in `Invoke-AzCli`**
  Replaced `& az.cmd` with `System.Diagnostics.Process` + `WaitForExit($TimeoutSec * 1000)`. Timed-out processes are killed and retried. Async stdout/stderr capture avoids deadlocks.

- [x] **Both READMEs: Add SP / CI-CD pipeline usage section**
  Python README already had this section. Added "Using this tool in your own CI/CD pipeline" to PS README with GitHub Actions and Azure DevOps examples, `-ExitCode` integration, and exit code summary table.

---

## Must Fix

*(all items completed)*

---

## Should Fix

*(all items completed)*

---

## Nice to Have

- [x] **PS: Add config file support**
  Python has `cis_audit.toml` for persistent configuration (subscriptions, output dir, exit code). PS has no equivalent — all options must be passed on every run. Consider adding a config file.
  *Done: `cis_audit.json` with Read-ConfigFile in Config.ps1. Supports CIS_AUDIT_CONFIG env var. CLI args always override. PR #10.*

- [x] **PS: Implement checkpoint reclassification**
  Python checkpoints store raw FAIL results and reclassify at report time based on current suppressions. PS checkpoints don't support this. Align behavior.
  *Already correct: PS checkpoints store raw FAIL, suppressions applied at report time. No changes needed.*

- [x] **PS: Add adaptive concurrency**
  Python dynamically adjusts thread pool size based on throttling responses. PS uses a fixed `ThrottleLimit 8`. Consider adaptive throttling.
  *Done: Batch-based parallel execution with shared ConcurrentBag throttle counter. Reduces workers on throttling, increases after 2 clean batches. PR #10.*

- [x] **PS: Add Ctrl+C subprocess cleanup**
  Python registers signal handlers to kill child `az` processes on Ctrl+C. PS has no equivalent — interrupted runs may leave orphan processes.
  *Done: Shared ConcurrentDictionary process registry. PowerShell.Exiting event handler kills all tracked processes. PR #10.*

- [x] **PS: Remove "JSON is invalid" from firewall error tokens**
  `Test-FirewallError` in `AzureClient.ps1` includes `"JSON is invalid"` as a firewall detection token. This is a generic JSON parse error, not a firewall indicator. Remove it to avoid misclassification.
  *Done: Removed from Test-FirewallError token list. PR #10.*

---

## Error Message Alignment

These aren't bugs, but the inconsistent messaging between tools may confuse users running both.

| Category | Python | PowerShell |
|----------|--------|------------|
| Firewall | "Firewall blocked — resource not reachable from this runner" | "Network access blocked — resource has firewall rules..." |
| KV Auth | "account lacks Key Vault data-plane permissions" | "Insufficient permissions — ..." |
| Graph Auth | "Graph API access denied — the signed-in account lacks..." | "Microsoft Graph API permission denied..." |
| 5.1.1 Error | MSAL-specific or "Requires Policy.Read.All..." | `New-GraphPermissionMessage` with "create an app registration..." |

Consider aligning the wording once the above fixes are done.

---

## Auth Model Summary

| Aspect | Python | PowerShell |
|--------|--------|------------|
| CLI calls | `az` via subprocess | `az` via `Invoke-AzCli` |
| Graph (5.1.1) | Dedicated MSAL flow (browser popup + PKCE + token cache) | `az rest --resource graph` (no MSAL) |
| SP detection | `az account show` → `user.type == "servicePrincipal"` | Same |
| Token cache | `~/.cis_audit/msal_token_cache.json` | N/A |
| Trade-off | MSAL gives fine-grained consent but requires app registration setup | `az rest --resource graph` works if user already has `Policy.Read.All` consented — simpler but less explicit |
