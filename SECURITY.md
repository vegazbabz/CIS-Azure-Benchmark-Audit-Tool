# Security Policy

## No Warranty — Community Tool

This is a **community-maintained tool** provided **as-is, with no warranty of any kind**.

The maintainers and contributors:

- Offer **no SLA** and make no commitment to respond to, fix, or disclose any reported issue within any timeframe.
- Accept **no legal responsibility or liability** for the use of this tool, its output, or any decisions made based on its results.
- Cannot be held accountable for inaccurate audit findings, missed controls, false positives, false negatives, data loss, or any other harm arising from the use of this software.

Use of this tool is entirely at your own risk. See the [LICENSE](LICENSE) for the full MIT disclaimer.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities in the tool itself.**

If you discover a potential security issue in the tool's code (e.g. credential exfiltration, code execution), you may report it using GitHub's
[private vulnerability reporting](https://github.com/vegazbabz/CIS-Azure-Benchmark-Audit-Tool/security/advisories/new).

Reports are reviewed on a **best-effort, volunteer basis**. There is no guaranteed response time or commitment to fix.

### What to include

- A description of the issue and its potential impact
- Steps to reproduce or a proof-of-concept
- Any suggested mitigations

## Scope

This tool is **read-only** — it makes no changes to your Azure environment.

In-scope for vulnerability reports:

- Code that could exfiltrate credentials or execute arbitrary commands
- Logic errors causing materially incorrect audit results (e.g. a critical FAIL always reported as PASS)

Out of scope:

- Issues in the Azure CLI, Python runtime, or GitHub Actions infrastructure
- Audit results that differ from your environment (report these as regular bugs)
- Feature requests or benchmark interpretation disagreements
