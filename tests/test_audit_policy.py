from __future__ import annotations

import unittest

from twn_toolkit import create_app
from twn_toolkit.audit_policy import (
    AUDIT_EXCLUDED_ENDPOINTS,
    MUTATING_HTTP_METHODS,
    mutation_audit_policies,
)


class AuditPolicyContractTests(unittest.TestCase):
    def test_every_mutating_route_has_one_explicit_audit_policy(self) -> None:
        app = create_app()
        route_endpoints = {
            rule.endpoint
            for rule in app.url_map.iter_rules()
            if MUTATING_HTTP_METHODS.intersection(rule.methods)
        }
        policies = mutation_audit_policies()

        self.assertEqual(
            sorted(route_endpoints - set(policies)),
            [],
            "Classify every new mutating endpoint before merging it.",
        )
        self.assertEqual(
            sorted(set(policies) - route_endpoints),
            [],
            "Remove stale audit-policy entries when routes are removed.",
        )

    def test_every_audit_exclusion_has_a_reason(self) -> None:
        self.assertTrue(AUDIT_EXCLUDED_ENDPOINTS)
        for endpoint, reason in AUDIT_EXCLUDED_ENDPOINTS.items():
            with self.subTest(endpoint=endpoint):
                self.assertTrue(reason.strip())


if __name__ == "__main__":
    unittest.main()
