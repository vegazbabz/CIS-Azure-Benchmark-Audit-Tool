#!/usr/bin/env python
"""Ad-hoc utility to inspect permission preflight output.

This script is intentionally lightweight and prints the key fields from
``check_user_permissions`` so maintainers can quickly validate behavior
outside the full audit flow.
"""

from azure_helpers import check_user_permissions


def main() -> None:
    """Run preflight against current CLI context and print a readable summary."""
    preflight = check_user_permissions([])
    print(f'User: {preflight.get("user_id")}')

    roles = preflight.get("roles", [])
    print(f"Roles ({len(roles)}):", flush=True)
    for role_name in roles:
        print(f"  - {role_name}")

    print(f'All clear: {preflight.get("all_clear")}')

    warnings = preflight.get("warnings", [])
    print(f"Warnings: {len(warnings)}")
    for warning in warnings:
        print(f"  - {warning}")


if __name__ == "__main__":
    main()
