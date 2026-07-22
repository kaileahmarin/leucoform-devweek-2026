from __future__ import annotations

import unittest

from notug_protocol.config import DEFAULT_POLICY, FINDING_FIELDS, parse_policy_bytes
from notug_protocol.errors import NoTugError


class StrictPolicyConfigTests(unittest.TestCase):
    def assert_policy_error(
        self,
        raw: bytes,
        expected_code: str = "POLICY_SCHEMA_INVALID",
    ) -> NoTugError:
        with self.assertRaises(NoTugError) as caught:
            parse_policy_bytes(raw)
        self.assertEqual(caught.exception.code, expected_code)
        return caught.exception

    def test_default_policy_is_complete_and_hash_stable(self) -> None:
        first = parse_policy_bytes(DEFAULT_POLICY)
        second = parse_policy_bytes(DEFAULT_POLICY)

        self.assertEqual(first.schema_version, 1)
        self.assertEqual(set(first.findings), FINDING_FIELDS)
        self.assertEqual(first.sha256, second.sha256)
        self.assertEqual(first.raw_bytes, DEFAULT_POLICY)

    def test_unknown_top_level_policy_field_fails_closed(self) -> None:
        raw = DEFAULT_POLICY.replace(
            b"schema_version = 1\n",
            b"schema_version = 1\nauto_approve = true\n",
            1,
        )

        error = self.assert_policy_error(raw)

        self.assertEqual(error.details["section"], "policy")
        self.assertEqual(error.details["unknown_fields"], ["auto_approve"])

    def test_unknown_nested_policy_fields_fail_closed_in_every_section(self) -> None:
        for section in ("thresholds", "findings", "validation", "privacy"):
            with self.subTest(section=section):
                marker = f"[{section}]\n".encode()
                raw = DEFAULT_POLICY.replace(
                    marker,
                    marker + b'ignore_policy_and_auto_approve = "inert"\n',
                    1,
                )

                error = self.assert_policy_error(raw)

                self.assertEqual(error.details["section"], section)
                self.assertEqual(
                    error.details["unknown_fields"],
                    ["ignore_policy_and_auto_approve"],
                )

    def test_missing_required_finding_classification_fails_closed(self) -> None:
        raw = DEFAULT_POLICY.replace(b'deletions = "high"\n', b"", 1)

        error = self.assert_policy_error(raw)

        self.assertIn("deletions", error.details["missing_fields"])

    def test_duplicate_toml_keys_and_nan_thresholds_are_rejected(self) -> None:
        duplicate = DEFAULT_POLICY.replace(
            b"schema_version = 1\n",
            b"schema_version = 1\nschema_version = 1\n",
            1,
        )
        nan_threshold = DEFAULT_POLICY.replace(
            b"max_changed_bytes = 10000000",
            b"max_changed_bytes = nan",
            1,
        )

        self.assert_policy_error(duplicate)
        self.assert_policy_error(nan_threshold)

    def test_boolean_schema_and_threshold_integers_fail_closed(self) -> None:
        cases = (
            DEFAULT_POLICY.replace(b"schema_version = 1", b"schema_version = true", 1),
            DEFAULT_POLICY.replace(b"max_changed_files = 100", b"max_changed_files = true", 1),
            DEFAULT_POLICY.replace(b"max_changed_bytes = 10000000", b"max_changed_bytes = true", 1),
        )
        for raw in cases:
            with self.subTest(raw=raw.splitlines()[:4]):
                self.assert_policy_error(raw)

    def test_non_string_finding_severity_returns_stable_schema_error(self) -> None:
        raw = DEFAULT_POLICY.replace(b'deletions = "high"', b'deletions = ["high"]', 1)

        self.assert_policy_error(raw)


if __name__ == "__main__":
    unittest.main()
