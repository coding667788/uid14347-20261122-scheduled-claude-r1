"""End-to-end scenarios that combine features.

These read like the specification's acceptance list: each test is one sentence
of the task turned into an executable check.  They are slower than the unit
tests because several of them use real subprocesses.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

from tests import builder as B
from tests.support import EXAMPLES, REPO_ROOT, LedgerTestCase


def _migrate_event(result: dict) -> dict:
    for event in result["events"]:
        if event.get("type") == "migrate":
            return event
    raise AssertionError("no migrate event in result")


def _advance_event(result: dict) -> dict:
    for event in result["events"]:
        if event.get("type") == "advance":
            return event
    raise AssertionError("no advance event in result")


class SpecScenarios(LedgerTestCase):
    def test_stage_one_preserved_but_stage_two_is_redone(self) -> None:
        db = self.db_path()
        self.apply(
            B.case(
                B.register(risk="high", challenge_id="C1"),
                B.proof("e2", "PF-d", factor="device", principal="PRIN-laptop",
                        trust_group="TG-devices", now=210),
                B.proof("e3", "PF-h", factor="human", principal="PRIN-bob",
                        trust_group="TG-staff", now=220),
                B.advance("e4", stage=1, now=230, next_challenge_id="C2"),
                B.token("e5", "TOK-1", challenge_id="C2", to_generation="GEN-2", now=240),
                B.migrate("e6", "TOK-1", to_generation="GEN-2", preserve_stage1=True,
                          now=250, next_challenge_id="C3"),
                batch_id="b1",
            ),
            db=db,
        )
        request = self.state(db)["requests"]["REQ-1"]
        # Stage 1 survived; the confirmation must be redone on the new challenge.
        self.assertTrue(request["stage1"]["valid"])
        self.assertTrue(request["stage1"]["retained"])
        self.assertEqual(request["status"], "stage1_complete")
        self.assertEqual(request["stage2_challenge_id"], "C3")

        error = self.apply_expect_error(
            B.case(
                B.proof("e7", "PF-confirm", stage=2, factor="human",
                        principal="PRIN-carol", challenge_id="C2", now=260),
                batch_id="b2",
            ),
            db=db,
        )
        # C2 was bound to GEN-1 and is closed by the migration.
        self.assertIn(error.code, {"E_CHALLENGE_CLOSED", "E_PROOF_GENERATION_MISMATCH"})

    def test_migration_then_issuance_lists_every_hop(self) -> None:
        db = self.db_path()
        self.apply(
            B.case(
                B.register(risk="high", challenge_id="C1"),
                B.proof("e2", "PF-d", factor="device", principal="PRIN-laptop",
                        trust_group="TG-devices", now=210),
                B.proof("e3", "PF-h", factor="human", principal="PRIN-bob",
                        trust_group="TG-staff", now=220),
                B.advance("e4", stage=1, now=230, next_challenge_id="C2"),
                B.token("e5", "TOK-1", challenge_id="C2", to_generation="GEN-2", now=240),
                B.migrate("e6", "TOK-1", to_generation="GEN-2", preserve_stage1=True,
                          now=250, next_challenge_id="C3"),
                batch_id="b1",
            ),
            db=db,
        )
        result = self.apply(
            B.case(
                B.proof("e7", "PF-confirm", stage=2, factor="human",
                        principal="PRIN-carol", challenge_id="C3", now=260),
                B.advance("e8", stage=2, now=270),
                batch_id="b2",
            ),
            db=db,
        )
        receipt = result["receipts"][0]
        self.assertEqual(receipt["generation"], "GEN-2")
        self.assertEqual([m["step"] for m in receipt["migrations"]], [1])
        self.assertEqual(receipt["migrations"][0]["from_generation"], "GEN-1")
        self.assertEqual(receipt["migrations"][0]["to_generation"], "GEN-2")
        self.assertEqual(receipt["stage1"]["generation"], "GEN-1")
        self.assertEqual(receipt["stage2"]["generation"], "GEN-2")

    def test_identical_batch_from_two_processes_yields_one_commit(self) -> None:
        db = self.db_path()
        case = B.case(
            B.register(risk="low", challenge_id="C1"),
            B.proof("e2", "PF-d", factor="device", principal="PRIN-laptop",
                    trust_group="TG-devices", now=110),
            B.proof("e3", "PF-h", factor="human", principal="PRIN-bob",
                    trust_group="TG-staff", now=120),
            B.advance("e4", stage=1, now=130),
            batch_id="same",
        )
        path = self.write_case(case)
        outputs = []
        for _ in range(2):
            completed = subprocess.run(
                [sys.executable, "-m", "solution", "apply", path, "--db", db],
                cwd=REPO_ROOT, capture_output=True, check=False,
            )
            self.assertEqual(completed.returncode, 0)
            outputs.append(completed.stdout)
        self.assertEqual(outputs[0], outputs[1])
        explained = self.explain(db)
        self.assertEqual(len(explained["batches"]), 1)
        self.assertEqual(len(explained["receipts"]), 1)

    def test_history_and_current_revocation_are_separate(self) -> None:
        db = self.db_path()
        self.apply(
            B.case(
                B.register(risk="low", challenge_id="C1"),
                B.proof("e2", "PF-d", factor="device", principal="PRIN-laptop",
                        trust_group="TG-devices", now=110),
                B.proof("e3", "PF-h", factor="human", principal="PRIN-bob",
                        trust_group="TG-staff", now=120),
                B.advance("e4", stage=1, now=130),
                batch_id="b1",
            ),
            db=db,
        )
        self.apply(
            B.case(
                {"event_id": "r1", "type": "revoke_request", "request_id": "REQ-1",
                 "reason": "operator", "now": 200},
                batch_id="b2",
            ),
            db=db,
        )
        at_one = self.explain(db, 1)
        at_two = self.explain(db, 2)
        self.assertEqual(at_one["requests"]["REQ-1"]["status"], "issued")
        self.assertEqual(at_two["requests"]["REQ-1"]["status"], "revoked")
        # The receipt itself is the same object at both commits.
        self.assertEqual(at_one["receipts"], at_two["receipts"])

    def test_partial_batch_failure_leaves_no_partial_consumption(self) -> None:
        db = self.db_path()
        self.apply(
            B.case(
                B.register(risk="high", challenge_id="C1"),
                B.proof("e2", "PF-d", factor="device", principal="PRIN-laptop",
                        trust_group="TG-devices", now=210),
                B.proof("e3", "PF-h", factor="human", principal="PRIN-bob",
                        trust_group="TG-staff", now=220),
                B.advance("e4", stage=1, now=230, next_challenge_id="C2"),
                batch_id="b1",
            ),
            db=db,
        )
        before = self.state(db)["requests"]["REQ-1"]
        error = self.apply_expect_error(
            B.case(
                B.advance("e5", stage=2, now=240),  # no stage-2 proof: fails
                batch_id="b2",
            ),
            db=db,
        )
        self.assertEqual(error.code, "E_STAGE2_NOT_SATISFIED")
        after = self.state(db)["requests"]["REQ-1"]
        self.assertEqual(before["stage1"], after["stage1"])
        for proof in after["proofs"]:
            self.assertEqual(proof["consumed_batch"], 1)


class ExampleFileTests(LedgerTestCase):
    """Every shipped example must produce its documented outcome."""

    def test_all_example_files_are_valid_json(self) -> None:
        files = sorted(name for name in os.listdir(EXAMPLES) if name.endswith(".json"))
        self.assertGreaterEqual(len(files), 14)
        for name in files:
            with open(os.path.join(EXAMPLES, name), encoding="utf-8") as handle:
                document = json.load(handle)
            self.assertEqual(document["schema"], "challenge-ledger/v1", name)
            self.assertIn("events", document, name)

    def test_example_report_runs_clean(self) -> None:
        completed = subprocess.run(
            [sys.executable, os.path.join(ROOT_TOOLS, "run_examples.py")],
            cwd=REPO_ROOT, capture_output=True, check=False,
        )
        self.assertEqual(
            completed.returncode, 0,
            completed.stdout.decode("utf-8", "replace") + completed.stderr.decode("utf-8", "replace"),
        )


ROOT_TOOLS = os.path.join(REPO_ROOT, "tools")


if __name__ == "__main__":
    unittest.main()
