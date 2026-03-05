"""
cis_models.py — Data model for the CIS Azure Audit Tool.

Contains the R (Result) dataclass that represents a single audit finding.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class R:
    """
    A single audit finding. One R instance is created per resource per control.

    For example: if a subscription has 20 storage accounts and there are 10
    storage checks, up to 200 R instances are produced for that subscription.

    Named R (short) rather than Result because it appears hundreds of times
    in check functions — brevity makes the check code readable.

    Fields
    ──────
    control_id        CIS control number, e.g. "7.11" or "9.3.1.2"
    title             Human-readable control title (from CIS benchmark PDF)
    level             CIS Profile Applicability: 1 (basic) or 2 (advanced)
    section           Section name used for grouping in the report
    status            One of the five constants: PASS / FAIL / ERROR / INFO / MANUAL
    details           Explanation shown in the report — what was found
    remediation       Azure portal path to fix the issue (empty string for PASS/INFO)
    subscription_id   Azure subscription GUID (empty for tenant-level checks)
    subscription_name Display name of the subscription
    resource          Specific resource name (NSG, vault, storage account, etc.)
                      Empty string means the finding applies to the subscription overall.
    """

    control_id: str
    title: str
    level: int
    section: str
    status: str
    details: str = ""
    remediation: str = ""
    subscription_id: str = ""
    subscription_name: str = ""
    resource: str = ""
