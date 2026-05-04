"""Tests for explicit tenant scoping in the CLI orchestration layer."""

from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import patch

import cis_azure_audit as audit


class TestGetSubscriptionsTenantScope(unittest.TestCase):
    def _subs(self) -> list[dict[str, str]]:
        return [
            {"id": "sub-a", "name": "Alpha", "tenantId": "tenant-1"},
            {"id": "sub-b", "name": "Beta", "tenantId": "tenant-2"},
            {"id": "sub-c", "name": "Gamma", "tenantId": "tenant-1"},
        ]

    @patch("cis_azure_audit.az")
    def test_filters_subscriptions_to_selected_tenant(self, mock_az: Any) -> None:
        mock_az.return_value = (0, self._subs())

        result = audit.get_subscriptions(tenant_id="tenant-1")

        self.assertEqual([s["id"] for s in result], ["sub-a", "sub-c"])

    @patch("cis_azure_audit.az")
    def test_subscription_filter_is_applied_inside_selected_tenant(self, mock_az: Any) -> None:
        mock_az.return_value = (0, self._subs())

        result = audit.get_subscriptions(["Gamma"], tenant_id="tenant-1")

        self.assertEqual([s["id"] for s in result], ["sub-c"])

    @patch("cis_azure_audit.az")
    def test_subscription_outside_selected_tenant_is_rejected(self, mock_az: Any) -> None:
        mock_az.return_value = (0, self._subs())

        with self.assertRaises(SystemExit) as cm:
            audit.get_subscriptions(["Beta"], tenant_id="tenant-1")

        self.assertEqual(cm.exception.code, 1)

    @patch("cis_azure_audit.az")
    def test_unknown_tenant_is_rejected(self, mock_az: Any) -> None:
        mock_az.return_value = (0, self._subs())

        with self.assertRaises(SystemExit) as cm:
            audit.get_subscriptions(tenant_id="tenant-missing")

        self.assertEqual(cm.exception.code, 1)
