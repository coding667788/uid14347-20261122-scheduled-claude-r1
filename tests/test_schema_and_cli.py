"""Structural validation: every error must be machine-locatable.

A structural rejection reports ``E_SCHEMA_*`` (or a parse code) plus the exact
JSON path that failed, and nothing is committed.
"""

from __future__ import annotations

import json
import unittest

from tests import builder as B
from tests.support import LedgerTestCase


class SchemaErrorTests(LedgerTestCase):
    def test_missing_events(self) -> None:
        error = self.apply_expect_error({"schema": "challenge-ledger/v1"})
        self.assertEqual(error.code, "E_SCHEMA_MISSING")
        self.assertEqual(error.path, "case.events")

    def test_events_must_be_an_array(self) -> None:
        error = self.apply_expect_error({"events": {"not": "a list"}})
        self.assertEqual(error.code, "E_SCHEMA_TYPE")
        self.assertEqual(error.path, "case.events")

    def test_unknown_top_level_field(self) -> None:
        error = self.apply_expect_error({"events": [B.register()], "surprise": 1})
        self.assertEqual(error.code, "E_SCHEMA_UNKNOWN")
        self.assertEqual(error.path, "case.surprise")

    def test_event_must_be_an_object(self) -> None:
        error = self.apply_expect_error({"events": ["nope"]})
        self.assertEqual(error.code, "E_SCHEMA_TYPE")
        self.assertEqual(error.path, "events[0]")

    def test_missing_event_id(self) -> None:
        event = B.register()
        del event["event_id"]
        error = self.apply_expect_error({"events": [event]})
        self.assertEqual(error.code, "E_SCHEMA_MISSING")
        self.assertEqual(error.path, "events[0].event_id")

    def test_unknown_event_type(self) -> None:
        error = self.apply_expect_error({"events": [{"event_id": "e1", "type": "teleport"}]})
        self.assertEqual(error.code, "E_SCHEMA_ENUM")
        self.assertEqual(error.path, "events[0].type")

    def test_risk_enumeration(self) -> None:
        error = self.apply_expect_error(B.case(B.register(risk="medium")))
        self.assertEqual(error.code, "E_SCHEMA_ENUM")
        self.assertEqual(error.path, "events[0].risk")

    def test_op_version_must_be_positive(self) -> None:
        error = self.apply_expect_error(B.case(B.register(op_version=0)))
        self.assertEqual(error.code, "E_SCHEMA_RANGE")
        self.assertEqual(error.path, "events[0].op_version")

    def test_integer_fields_reject_booleans(self) -> None:
        error = self.apply_expect_error(B.case(B.register(op_version=True)))
        self.assertEqual(error.code, "E_SCHEMA_TYPE")

    def test_policy_error_is_located(self) -> None:
        bad = {"version": 1, "recipes": [{"id": "r", "stage": 9, "factors": ["device"]}]}
        error = self.apply_expect_error(
            {"schema": "challenge-ledger/v1", "policies": [bad], "events": [B.register()]}
        )
        self.assertEqual(error.code, "E_SCHEMA_ENUM")
        self.assertEqual(error.path, "case.policies[0].recipes[0].stage")

    def test_recipe_with_both_requirements_and_factors(self) -> None:
        bad = {
            "version": 1,
            "recipes": [
                {
                    "id": "r",
                    "stage": 1,
                    "factors": ["device"],
                    "requirements": [{"kind": "device", "count": 1}],
                }
            ],
        }
        error = self.apply_expect_error(
            {"schema": "challenge-ledger/v1", "policies": [bad], "events": [B.register()]}
        )
        self.assertEqual(error.code, "E_SCHEMA_CONFLICT")
        self.assertEqual(error.path, "case.policies[0].recipes[0].requirements")

    def test_duplicate_recipe_id(self) -> None:
        bad = {
            "version": 1,
            "recipes": [
                {"id": "r", "stage": 1, "factors": ["device"]},
                {"id": "r", "stage": 2, "factors": ["human"]},
            ],
        }
        error = self.apply_expect_error(
            {"schema": "challenge-ledger/v1", "policies": [bad], "events": [B.register()]}
        )
        self.assertEqual(error.code, "E_POLICY_CONFLICT")
        self.assertEqual(error.path, "case.policies[0].recipes[1]")

    def test_redefining_a_policy_version_with_new_content_conflicts(self) -> None:
        db = self.db_path()
        self.apply(B.case(B.register(), batch_id="first"), db=db)
        other = {
            "version": 1,
            "recipes": [{"id": "s1-other", "stage": 1, "factors": ["human"]}],
        }
        error = self.apply_expect_error(
            {
                "schema": "challenge-ledger/v1",
                "policies": [other],
                "events": [B.register(event_id="r2", request_id="REQ-2")],
            },
            db=db,
        )
        self.assertEqual(error.code, "E_POLICY_CONFLICT")
        # The path names the offending field in the submitted file, not an
        # internal synthetic event.
        self.assertEqual(error.path, "policies[0].version")

    def test_redefining_an_identical_policy_is_a_no_op(self) -> None:
        db = self.db_path()
        first = self.apply(B.case(B.register(), batch_id="first"), db=db)
        # Re-declaring the same policy produces the same synthetic event, so it
        # is answered as an idempotent duplicate and no conflict is raised.
        second = self.apply(
            B.case(B.register(event_id="r2", request_id="REQ-2"), batch_id="second"), db=db
        )
        policy_event = next(e for e in second["events"] if e.get("type") == "define_policy")
        first_policy_event = next(e for e in first["events"] if e.get("type") == "define_policy")
        self.assertEqual(policy_event, first_policy_event)
        self.assertEqual(len(self.explain(db)["batches"]), 2)

    def test_proof_factor_enumeration(self) -> None:
        error = self.apply_expect_error(
            B.case(B.register(), B.proof("e2", "PF-x", factor="biometric"))
        )
        self.assertEqual(error.code, "E_SCHEMA_ENUM")
        self.assertEqual(error.path, "events[1].factor")

    def test_trusted_must_be_boolean(self) -> None:
        error = self.apply_expect_error(
            B.case(B.register(), B.proof("e2", "PF-x", trusted="yes"))
        )
        self.assertEqual(error.code, "E_SCHEMA_TYPE")
        self.assertEqual(error.path, "events[1].trusted")

    def test_no_side_effects_on_rejection(self) -> None:
        db = self.db_path()
        self.apply(B.case(B.register(), B.proof("e2", "PF-d", now=110), batch_id="ok"), db=db)
        error = self.apply_expect_error(
            B.case(B.register(event_id="fresh", risk="nope"), batch_id="bad"), db=db
        )
        self.assertEqual(error.code, "E_SCHEMA_ENUM")
        self.assertEqual(len(self.explain(db)["batches"]), 1)


class CliTests(LedgerTestCase):
    def test_apply_writes_json_and_returns_zero(self) -> None:
        path = self.write_case(B.case(B.register(), batch_id="cli"))
        code, document, raw = self.run_cli("apply", path, "--db", self.db_path())
        self.assertEqual(code, 0)
        self.assertTrue(document["ok"])
        self.assertEqual(document["commit"], 1)
        self.assertTrue(raw.endswith(b"\n"))
        # Output must be UTF-8 JSON regardless of the console code page.
        self.assertEqual(json.loads(raw.decode("utf-8")), document)

    def test_structural_error_uses_exit_code_two(self) -> None:
        path = self.write_case({"events": []})
        code, document, _raw = self.run_cli("apply", path, "--db", self.db_path())
        self.assertEqual(code, 2)
        self.assertFalse(document["ok"])
        self.assertEqual(document["error"]["code"], "E_SCHEMA_EMPTY")
        self.assertEqual(document["error"]["path"], "case.events")

    def test_domain_rejection_uses_exit_code_three(self) -> None:
        path = self.write_case(B.case(B.register(), B.advance("e2"), batch_id="cli-fail"))
        code, document, _raw = self.run_cli("apply", path, "--db", self.db_path())
        self.assertEqual(code, 3)
        self.assertEqual(document["error"]["code"], "E_STAGE1_NOT_SATISFIED")
        self.assertEqual(document["error"]["path"], "events[1].stage")

    def test_missing_case_file_is_a_located_error(self) -> None:
        code, document, _raw = self.run_cli("apply", "does-not-exist.json", "--db", self.db_path())
        self.assertEqual(code, 2)
        self.assertEqual(document["error"]["code"], "E_IO")

    def test_invalid_json_is_a_parse_error(self) -> None:
        import os

        path = os.path.join(self._tmp, "broken.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        code, document, _raw = self.run_cli("apply", path, "--db", self.db_path())
        self.assertEqual(code, 2)
        self.assertEqual(document["error"]["code"], "E_JSON_PARSE")

    def test_duplicate_json_keys_are_rejected(self) -> None:
        import os

        path = os.path.join(self._tmp, "dup.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write('{"events": [], "events": []}')
        code, document, _raw = self.run_cli("apply", path, "--db", self.db_path())
        self.assertEqual(code, 2)
        self.assertIn(document["error"]["code"], {"E_JSON_PARSE", "E_SCHEMA_EMPTY"})

    def test_missing_db_option_is_a_usage_error(self) -> None:
        path = self.write_case(B.case(B.register()))
        code, document, _raw = self.run_cli("apply", path)
        self.assertEqual(code, 2)
        self.assertEqual(document["error"]["code"], "E_USAGE")

    def test_explain_on_an_empty_ledger_is_empty_not_an_error(self) -> None:
        code, document, _raw = self.run_cli("explain", "--db", self.db_path())
        self.assertEqual(code, 0)
        self.assertEqual(document["commit"], 0)
        self.assertEqual(document["requests"], {})

    def test_explain_for_a_commit_that_does_not_exist(self) -> None:
        path = self.write_case(B.case(B.register(), batch_id="only"))
        db = self.db_path()
        self.run_cli("apply", path, "--db", db)
        code, document, _raw = self.run_cli("explain", "--db", db, "--commit", "42")
        self.assertEqual(code, 3)
        self.assertEqual(document["error"]["code"], "E_COMMIT_NOT_FOUND")

    def test_stdout_is_a_single_json_document(self) -> None:
        path = self.write_case(B.case(B.register(), batch_id="single"))
        _code, _document, raw = self.run_cli("apply", path, "--db", self.db_path())
        text = raw.decode("utf-8")
        self.assertEqual(text.count("\n"), 1)
        json.loads(text)

    def test_output_is_identical_for_identical_input(self) -> None:
        case = B.case(
            B.register(),
            B.proof("e2", "PF-d", factor="device", principal="PRIN-laptop",
                    trust_group="TG-devices", now=110),
            B.proof("e3", "PF-h", factor="human", principal="PRIN-bob",
                    trust_group="TG-staff", now=120),
            B.advance("e4", stage=1, now=130),
            batch_id="deterministic",
        )
        path = self.write_case(case)
        db_a = self.db_path("a.sqlite")
        db_b = self.db_path("b.sqlite")
        _c1, doc_a, raw_a = self.run_cli("apply", path, "--db", db_a)
        _c2, doc_b, raw_b = self.run_cli("apply", path, "--db", db_b)
        self.assertEqual(raw_a, raw_b)
        self.assertEqual(doc_a["receipts"][0]["digest"], doc_b["receipts"][0]["digest"])

    def test_version_command(self) -> None:
        code, document, _raw = self.run_cli("version")
        self.assertEqual(code, 0)
        self.assertEqual(document["kind"], "version")


if __name__ == "__main__":
    unittest.main()
