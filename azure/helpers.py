"""azure_helpers.py — backwards-compatible re-export shim.

All symbols have moved to focused sub-modules:
  az_client.py   — subprocess/CLI layer (az, az_rest, graph_query, retry, errors)
  az_identity.py — identity lookup and permission preflight

Import from those modules directly in new code.
"""

from azure.client import (  # noqa: F401
    AZ,
    _AUTHZ_TOKENS,
    _FIREWALL_TOKENS,
    _first_error_line,
    _friendly_error,
    _run_cmd_with_retries,
    az,
    az_rest,
    get_and_reset_rate_limit_retry_count,
    graph_query,
    is_firewall_error,
    logger,
)
from azure.identity import (  # noqa: F401
    _upn_to_objectid,
    check_user_permissions,
    get_signed_in_user_id,
    list_role_names_for_user,
)
