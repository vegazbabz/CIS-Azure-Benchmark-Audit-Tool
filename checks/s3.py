"""Section 3 — Compute Services checks."""

from cis.config import MANUAL
from cis.models import R


def check_3_1_1() -> R:
    """
    3.1.1 — Only MFA-enabled identities can access privileged VMs (Manual, Level 2)

    Verify that identities assigned the Virtual Machine Administrator Login
    (or Virtual Machine User Login) role have MFA enabled — either via
    per-user MFA or a Conditional Access policy.  Revoke admin-level
    permissions that violate least-privilege.

    Full automation requires correlating per-subscription role assignments
    with per-user MFA registration status and Conditional Access policy
    evaluation (UserAuthenticationMethod.Read.All + Policy.Read.All).
    Partial checks would be misleading, so this remains manual.
    """
    return R(
        "3.1.1",
        "Only MFA-enabled identities can access privileged Virtual Machines",
        2,
        "3 - Compute Services",
        MANUAL,
        "Manual verification required — check that all identities with "
        "'Virtual Machine Administrator Login' or 'Virtual Machine User Login' "
        "roles have MFA enabled (per-user MFA or Conditional Access).",
        "Subscription > Access control (IAM) > Role assignments > filter on "
        "'Virtual Machine Administrator Login'. For each identity, verify MFA "
        "via Entra ID > Users > Per-user MFA, or confirm coverage by a "
        "Conditional Access policy requiring MFA.",
    )
