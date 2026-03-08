"""azure_helpers.py — backwards-compatible re-export shim.

All symbols have moved to focused sub-modules:
  az_client.py   — subprocess/CLI layer (az, az_rest, graph_query, retry, errors)
  az_identity.py — identity lookup and permission preflight

Import from those modules directly in new code.
"""

from azure.client import (  # noqa: F401
    AZ,
    _friendly_error,
    az,
    az_rest,
    az_rest_paged,
    get_and_reset_rate_limit_retry_count,
    graph_query,
    is_authz_error,
    is_firewall_error,
    is_notapplicable_error,
    kill_running_procs,
)
from azure.identity import (  # noqa: F401
    _upn_to_objectid,
    check_user_permissions,
    get_signed_in_user_id,
    list_role_names_for_user,
)
