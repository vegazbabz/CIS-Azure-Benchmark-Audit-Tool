#!/usr/bin/env python
"""Quick test of the preflight check."""

from azure_helpers import check_user_permissions

preflight = check_user_permissions([])
print(f'User: {preflight.get("user_id")}')
print(f'Roles ({len(preflight.get("roles", []))}):', flush=True)
for r in preflight.get("roles", []):
    print(f"  - {r}")
print(f'All clear: {preflight.get("all_clear")}')
print(f'Warnings: {len(preflight.get("warnings", []))}')
for w in preflight.get("warnings", []):
    print(f"  - {w}")
