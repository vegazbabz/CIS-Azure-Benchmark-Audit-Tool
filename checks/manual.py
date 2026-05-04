"""Manual CIS Azure Benchmark controls that are intentionally not automated."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cis.check_helpers import _idx, _info
from cis.config import CONTROL_CATALOG, MANUAL
from cis.models import R

_CATALOG_BY_ID = {
    control_id: (title, level, section) for control_id, level, section, title, _audit_method in CONTROL_CATALOG
}


@dataclass(frozen=True)
class ManualControl:
    control_id: str
    title: str
    level: int
    section: str
    details: str
    remediation: str


def _manual(control: ManualControl, sid: str = "", sname: str = "", resource: str = "") -> R:
    title, level, section = _catalog_metadata(control)
    return R(
        control.control_id,
        title,
        level,
        section,
        MANUAL,
        control.details,
        control.remediation,
        sid,
        sname,
        resource,
    )


def _catalog_metadata(control: ManualControl) -> tuple[str, int, str]:
    return _CATALOG_BY_ID.get(control.control_id, (control.title, control.level, control.section))


_DATABRICKS_MANUAL: tuple[ManualControl, ...] = (
    ManualControl(
        "2.1.3",
        "Traffic is encrypted between Databricks cluster worker nodes",
        2,
        "2 - Databricks",
        "Manual verification required per CIS 5.0.0: confirm secure cluster connectivity / "
        "encrypted worker-node traffic for each Databricks workspace.",
        "Azure Databricks workspace > Compute / Workspace settings > enable secure cluster connectivity.",
    ),
    ManualControl(
        "2.1.4",
        "Users and groups are synced from Microsoft Entra ID to Azure Databricks",
        2,
        "2 - Databricks",
        "Manual verification required per CIS 5.0.0: review identity federation / SCIM provisioning "
        "for the Databricks workspace.",
        "Configure Microsoft Entra ID SCIM provisioning for Databricks users and groups.",
    ),
    ManualControl(
        "2.1.5",
        "Unity Catalog is configured for Azure Databricks",
        2,
        "2 - Databricks",
        "Manual verification required per CIS 5.0.0: confirm Unity Catalog is enabled and used "
        "for governance in the workspace.",
        "Databricks account console > Data > Unity Catalog > create/assign metastore.",
    ),
    ManualControl(
        "2.1.6",
        "Databricks personal access token usage is restricted and expiry is enforced",
        1,
        "2 - Databricks",
        "Manual verification required per CIS 5.0.0: review workspace personal access token "
        "permissions and maximum token lifetime.",
        "Databricks workspace admin settings > Personal access tokens > restrict users and enforce expiry.",
    ),
)


_TENANT_IDENTITY_MANUAL: tuple[ManualControl, ...] = (
    ManualControl(
        "5.2.1",
        "Trusted locations are defined",
        2,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review Conditional Access named locations.",
        "Entra ID > Protection > Conditional Access > Named locations.",
    ),
    ManualControl(
        "5.2.3",
        "Exclusionary device code flow policy is considered",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review Conditional Access policies for device code flow.",
        "Entra ID > Protection > Conditional Access > create or review a device code flow policy.",
    ),
    ManualControl(
        "5.2.4",
        "Multifactor authentication policy exists for all users",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: confirm Conditional Access or equivalent MFA "
        "policy covers all users with documented exclusions only.",
        "Entra ID > Protection > Conditional Access > require multifactor authentication for all users.",
    ),
    ManualControl(
        "5.2.5",
        "Multifactor authentication is required for risky sign-ins",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review risk-based Conditional Access policies.",
        "Entra ID > Protection > Conditional Access > require MFA for sign-in risk.",
    ),
    ManualControl(
        "5.2.6",
        "Multifactor authentication is required for Windows Azure Service Management API",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: confirm MFA is required for Windows Azure "
        "Service Management API access.",
        "Entra ID > Protection > Conditional Access > Target resources > Windows Azure Service Management API.",
    ),
    ManualControl(
        "5.2.7",
        "Multifactor authentication is required to access Microsoft Admin Portals",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: confirm admin portal access requires MFA.",
        "Entra ID > Protection > Conditional Access > Target resources > Microsoft Admin Portals.",
    ),
    ManualControl(
        "5.2.8",
        "Token Protection Conditional Access policy is considered",
        2,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review whether token protection policies "
        "are configured for supported clients.",
        "Entra ID > Protection > Conditional Access > Session > Token protection.",
    ),
    ManualControl(
        "5.3.1",
        "Azure admin accounts are not used for daily operations",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review privileged account usage practices.",
        "Use separate standard accounts for daily work and privileged accounts only for administration.",
    ),
    ManualControl(
        "5.3.4",
        "Privileged role assignments are periodically reviewed",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: confirm privileged role reviews occur periodically.",
        "Entra ID > Identity Governance > Access Reviews > review privileged role assignments.",
    ),
    ManualControl(
        "5.3.5",
        "Disabled user accounts do not have read, write, or owner permissions",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review disabled users and remove Azure RBAC access.",
        "Entra ID > Users and Azure RBAC role assignments > remove access from disabled accounts.",
    ),
    ManualControl(
        "5.3.6",
        "Tenant Creator role assignments are periodically reviewed",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review Tenant Creator role assignments.",
        "Entra ID > Roles and administrators > Tenant Creator > review assignments.",
    ),
    ManualControl(
        "5.3.7",
        "Non-privileged role assignments are periodically reviewed",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: confirm non-privileged role assignments "
        "are periodically reviewed.",
        "Entra ID / Azure IAM > Access reviews > review non-privileged assignments.",
    ),
    ManualControl(
        "5.5",
        "Number of methods required to reset is set to 2",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review SSPR authentication method requirements.",
        "Entra ID > Password reset > Authentication methods > Number of methods required to reset: 2.",
    ),
    ManualControl(
        "5.7",
        "Account lockout duration in seconds is greater than or equal to 60",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review password protection lockout duration.",
        "Entra ID > Protection > Authentication methods > Password protection > Lockout duration: 60 or higher.",
    ),
    ManualControl(
        "5.8",
        "Custom banned password list is set to Enforce",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review custom banned password protection.",
        "Entra ID > Protection > Authentication methods > Password protection > Custom banned password list.",
    ),
    ManualControl(
        "5.9",
        "Days before users re-confirm authentication information is not set to 0",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review SSPR registration reconfirmation interval.",
        "Entra ID > Password reset > Registration > reconfirm authentication information interval.",
    ),
    ManualControl(
        "5.10",
        "Notify users on password resets is set to Yes",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review password reset notifications.",
        "Entra ID > Password reset > Notifications > Notify users on password resets: Yes.",
    ),
    ManualControl(
        "5.11",
        "Notify all admins when other admins reset their password is set to Yes",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review admin password reset notifications.",
        "Entra ID > Password reset > Notifications > Notify all admins: Yes.",
    ),
    ManualControl(
        "5.12",
        "User consent for applications is set to do not allow user consent",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review user consent settings.",
        "Entra ID > Enterprise applications > Consent and permissions > User consent settings.",
    ),
    ManualControl(
        "5.13",
        "User consent is limited to verified publishers for selected permissions",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review selected permission consent policy.",
        "Entra ID > Enterprise applications > Consent and permissions > User consent settings.",
    ),
    ManualControl(
        "5.17",
        "Restrict access to Microsoft Entra admin center is set to Yes",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review Entra admin center access restriction.",
        "Entra ID > User settings > Restrict access to Microsoft Entra admin center: Yes.",
    ),
    ManualControl(
        "5.18",
        "Restrict user ability to access groups features in My Groups is set to Yes",
        2,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review My Groups access restrictions.",
        "Entra ID > Groups > General > restrict My Groups features.",
    ),
    ManualControl(
        "5.19",
        "Users can create security groups is set to No",
        2,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review security group creation settings.",
        "Entra ID > Groups > General > Users can create security groups: No.",
    ),
    ManualControl(
        "5.20",
        "Owners can manage group membership requests in My Groups is set to No",
        2,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review group owner membership request settings.",
        "Entra ID > Groups > General > Owners can manage group membership requests: No.",
    ),
    ManualControl(
        "5.21",
        "Users can create Microsoft 365 groups is set to No",
        2,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review Microsoft 365 group creation settings.",
        "Entra ID > Groups > General > Users can create Microsoft 365 groups: No.",
    ),
    ManualControl(
        "5.22",
        "Require MFA to register or join devices with Microsoft Entra is set to Yes",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review device registration MFA requirement.",
        "Entra ID > Devices > Device settings > Require MFA to register or join devices: Yes.",
    ),
    ManualControl(
        "5.24",
        "Custom role is assigned permissions for administering resource locks",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review custom roles used for resource lock administration.",
        "Create/assign a least-privilege custom role for resource lock administration.",
    ),
    ManualControl(
        "5.25",
        "Subscription tenant transfer settings are set to Permit no one",
        2,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review subscription entering/leaving tenant settings.",
        "Entra ID > Properties / subscription policies > permit no one for tenant transfers.",
    ),
    ManualControl(
        "5.26",
        "Fewer than 5 users have Global Administrator assignment",
        1,
        "5 - Identity Services",
        "Manual verification required per CIS 5.0.0: review Global Administrator assignments.",
        "Entra ID > Roles and administrators > Global Administrator > keep fewer than five assigned users.",
    ),
)


_TENANT_LOGGING_MANUAL: tuple[ManualControl, ...] = (
    ManualControl(
        "6.1.1.8",
        "Microsoft Entra diagnostic setting sends Microsoft Graph activity logs to an appropriate destination",
        2,
        "6 - Management & Governance",
        "Manual verification required per CIS 5.0.0: review Microsoft Graph activity log diagnostic settings.",
        "Entra ID > Monitoring > Diagnostic settings > send Microsoft Graph activity logs to an approved destination.",
    ),
    ManualControl(
        "6.1.1.9",
        "Microsoft Entra diagnostic setting sends Microsoft Entra activity logs to an appropriate destination",
        2,
        "6 - Management & Governance",
        "Manual verification required per CIS 5.0.0: review Microsoft Entra activity log diagnostic settings.",
        "Entra ID > Monitoring > Diagnostic settings > send Entra activity logs to an approved destination.",
    ),
    ManualControl(
        "6.1.1.10",
        "Intune logs are captured and sent to Log Analytics",
        2,
        "6 - Management & Governance",
        "Manual verification required per CIS 5.0.0: review Intune diagnostic settings.",
        "Intune admin center > Tenant administration > Diagnostic settings > send logs to Log Analytics.",
    ),
)


_SECURITY_MANUAL: tuple[ManualControl, ...] = (
    ManualControl(
        "8.1.3.2",
        "Vulnerability assessment for machines component status is set to On",
        2,
        "8 - Security Services",
        "Manual verification required per CIS 5.0.0: review Defender for Servers vulnerability assessment component.",
        "Defender for Cloud > Environment settings > Defender plans > Servers > Vulnerability assessment.",
    ),
    ManualControl(
        "8.1.3.4",
        "Agentless scanning for machines component status is set to On",
        2,
        "8 - Security Services",
        "Manual verification required per CIS 5.0.0: review Defender agentless scanning for machines.",
        "Defender for Cloud > Environment settings > Defender plans > Servers > Agentless scanning.",
    ),
    ManualControl(
        "8.1.3.5",
        "File Integrity Monitoring component status is set to On",
        2,
        "8 - Security Services",
        "Manual verification required per CIS 5.0.0: review File Integrity Monitoring configuration.",
        "Defender for Cloud > Environment settings > Defender plans > Servers > File Integrity Monitoring.",
    ),
    ManualControl(
        "8.1.5.2",
        "Advanced Threat Protection alerts for Storage Accounts are monitored",
        2,
        "8 - Security Services",
        "Manual verification required per CIS 5.0.0: review Defender for Storage alerts and response process.",
        "Defender for Cloud > Security alerts > review and monitor storage account alerts.",
    ),
    ManualControl(
        "8.1.11",
        "Microsoft Cloud Security Benchmark policies are not set to Disabled",
        1,
        "8 - Security Services",
        "Manual verification required per CIS 5.0.0: review Defender for Cloud regulatory compliance policies.",
        "Defender for Cloud > Environment settings > Security policy > keep MCSB policies enabled.",
    ),
    ManualControl(
        "8.1.16",
        "Microsoft Defender External Attack Surface Monitoring is enabled",
        2,
        "8 - Security Services",
        "Manual verification required per CIS 5.0.0: review Defender EASM enablement.",
        "Defender EASM > create inventory and monitor external attack surface.",
    ),
    ManualControl(
        "8.2.1",
        "Microsoft Defender for IoT Hub is set to On",
        2,
        "8 - Security Services",
        "Manual verification required per CIS 5.0.0: review Defender for IoT Hub configuration.",
        "IoT Hub > Defender for IoT > enable Microsoft Defender for IoT.",
    ),
)


def check_databricks_manual_controls(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    workspaces = _idx(td, "databricks", sid)
    if not workspaces:
        info_results: list[R] = []
        for control in _DATABRICKS_MANUAL:
            title, level, section = _catalog_metadata(control)
            info_results.append(
                _info(control.control_id, title, level, section, "No Databricks workspaces found.", sid, sname)
            )
        return info_results

    results: list[R] = []
    for workspace in workspaces:
        resource = workspace.get("name", "")
        results.extend(_manual(c, sid, sname, resource) for c in _DATABRICKS_MANUAL)
    return results


def check_tenant_identity_manual_controls() -> list[R]:
    return [_manual(c) for c in _TENANT_IDENTITY_MANUAL]


def check_tenant_logging_manual_controls() -> list[R]:
    return [_manual(c) for c in _TENANT_LOGGING_MANUAL]


def check_vnet_flow_log_manual_control(sid: str, sname: str, td: dict[str, Any]) -> list[R]:
    control = ManualControl(
        "6.1.1.7",
        "Virtual network flow logs are captured and sent to Log Analytics",
        2,
        "6 - Management & Governance",
        "Manual verification required per CIS 5.0.0: review VNet flow logs and confirm they send to Log Analytics.",
        "Network Watcher > Flow logs > create VNet flow logs with Log Analytics destination.",
    )
    vnets = _idx(td, "vnets", sid)
    if not vnets:
        title, level, section = _catalog_metadata(control)
        return [_info(control.control_id, title, level, section, "No VNets found.", sid, sname)]
    return [_manual(control, sid, sname, vnet.get("name", "")) for vnet in vnets]


def check_security_manual_controls(sid: str, sname: str) -> list[R]:
    return [_manual(c, sid, sname) for c in _SECURITY_MANUAL]
