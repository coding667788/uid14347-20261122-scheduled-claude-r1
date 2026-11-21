"""Basic issuance: low risk in one stage, high risk across two.

These tests pin the happy paths and the two rules that make the second stage
different: no reuse of stage-1 proofs, and a fresh stage-2 challenge.
"""

from __future__ import annotations

import unittest

from tests import builder as B
from tests.support import LedgerTestCase


class LowRiskTests(LedgerTestCase):
    def test_low_risk_issues_at_stage_one(self) -> None:
        case = B.case(
            B.register(risk="low"),
            B.proof("e2", "PF-d", factor="device", principal="PRIN-laptop", trust_group="TG-devices", now=110),
            B.proof("e3", "PF-h", factor="human", principal="PRIN-bob", trust_group="TG-staff", now=120),
            B.advance("e4", stage=1, now=130),
            batch_id="low-1",
        )
        result = self.apply(case)
        self.assertEqual(result["commit"], 1)
        last = result["events"][-1]
        self.assertEqual(last["outcome"], "issued")
        self.assertEqual(last["status"], "issued")
        self.assertEqual(sorted(last["proof_ids"]), ["PF-d", "PF-h"])
        self.assertEqual(len(result["receipts"]), 1)
        receipt = result["receipts"][0]
        self.assertEqual(receipt["risk"], "low")
        self.assertIsNone(receipt["stage2"])
        self.assertEqual(receipt["resource"], "FILESET-quarterly")

    def test_single_factor_is_not_enough(self) -> None:
        case = B.case(
            B.register(risk="low"),
            B.proof("e2", "PF-d", factor="device", now=110),
            B.advance("e3", stage=1, now=120),
            batch_id="low-missing",
        )
        error = self.apply_expect_error(case)
        self.assertEqual(error.code, "E_STAGE1_NOT_SATISFIED")
        self.assertEqual(error.path, "events[2].stage")
        self.assertFalse(error.detail["failures"] == [])

    def test_distinct_principals_required(self) -> None:
        case = B.case(
            B.register(risk="low"),
            B.proof("e2", "PF-d", factor="device", principal="PRIN-same", trust_group="TG-a", now=110),
            B.proof("e3", "PF-h", factor="human", principal="PRIN-same", trust_group="TG-b", now=120),
            B.advance("e4", stage=1, now=130),
            batch_id="low-same-principal",
        )
        error = self.apply_expect_error(case)
        self.assertEqual(error.code, "E_STAGE1_NOT_SATISFIED")
        reasons = {f["reason"] for f in error.detail["failures"]}
        self.assertIn("independence_not_satisfied", reasons)


class HighRiskTests(LedgerTestCase):
    def _stage1(self, **overrides: object) -> list[dict[str, object]]:
        return [
            B.register(risk="high", **overrides),
            B.proof("e2", "PF-d", factor="device", principal="PRIN-laptop", trust_group="TG-devices", now=210),
            B.proof("e3", "PF-h", factor="human", principal="PRIN-bob", trust_group="TG-staff", now=220),
            B.advance("e4", stage=1, now=230),
        ]

    def test_stage_one_stops_before_issuance(self) -> None:
        case = B.case(*self._stage1(), batch_id="hi-s1")
        result = self.apply(case)
        last = result["events"][-1]
        self.assertEqual(last["outcome"], "stage1_complete")
        self.assertEqual(last["status"], "stage1_complete")
        self.assertIsNotNone(last["stage2_challenge_id"])
        self.assertEqual(result["receipts"], [])

    def test_stage_one_proof_cannot_satisfy_stage_two(self) -> None:
        db = self.db_path()
        first = self.apply(B.case(*self._stage1(), batch_id="hi-s1"), db=db)
        stage2_challenge = first["events"][-1]["stage2_challenge_id"]

        # Present a stage-1 credential against the *stage-2* challenge: the
        # challenge's stage wins and the proof is refused outright.
        case = B.case(
            B.proof(
                "e5",
                "PF-h-again",
                stage=1,
                factor="human",
                principal="PRIN-bob",
                challenge_id=stage2_challenge,
                now=240,
            ),
            batch_id="hi-reuse",
        )
        error = self.apply_expect_error(case, db=db)
        self.assertEqual(error.code, "E_PROOF_STAGE_MISMATCH")
        self.assertEqual(error.path, "events[0].stage")

    def test_stage_one_challenge_is_closed_after_stage_one(self) -> None:
        db = self.db_path()
        self.apply(B.case(*self._stage1(), batch_id="hi-s1"), db=db)
        error = self.apply_expect_error(
            B.case(
                B.proof("e5", "PF-late", stage=1, factor="human", principal="PRIN-bob", now=240),
                batch_id="hi-late-s1",
            ),
            db=db,
        )
        self.assertEqual(error.code, "E_CHALLENGE_CLOSED")

    def test_stage_two_adjudication_excludes_stage_one_evidence(self) -> None:
        db = self.db_path()
        self.apply(B.case(*self._stage1(), batch_id="hi-s1"), db=db)
        with self.assertRaises(Exception):
            self.apply(B.case(B.advance("e5", stage=2, now=240), batch_id="hi-empty-s2"), db=db)
        explained = self.explain(db)
        unmet = explained["requests"]["REQ-1"]["unmet"]
        self.assertEqual(unmet["stage"], 2)
        self.assertFalse(unmet["satisfied"])
        excluded = {item["proof_id"]: item["reasons"] for item in unmet["excluded"]}
        self.assertIn("stage_mismatch", excluded["PF-d"])
        self.assertIn("stage_mismatch", excluded["PF-h"])

    def test_stage_one_proofs_stay_consumed_after_issuance(self) -> None:
        events = self._stage1()
        events.append(
            B.proof("e5", "PF-s2", stage=2, factor="human", principal="PRIN-carol", trust_group="TG-staff", now=240)
        )
        events.append(B.advance("e6", stage=2, now=250))
        db = self.db_path()
        first = self.apply(B.case(*events, batch_id="hi-ok"), db=db)
        receipt = first["receipts"][0]
        self.assertEqual(sorted(receipt["stage1"]["proof_ids"]), ["PF-d", "PF-h"])
        self.assertEqual(receipt["stage2"]["proof_ids"], ["PF-s2"])

        explained = self.explain(db)
        request = explained["requests"]["REQ-1"]
        by_id = {p["proof_id"]: p for p in request["proofs"]}
        self.assertEqual(by_id["PF-d"]["consumed_by"], "stage1")
        self.assertEqual(by_id["PF-h"]["consumed_by"], "stage1")
        self.assertEqual(by_id["PF-s2"]["consumed_by"], "stage2")

    def test_stage_two_requires_its_own_challenge(self) -> None:
        events = self._stage1()
        # Submit a stage-2 proof against the stage-1 challenge explicitly.
        stage1_challenge = "chl-known"
        events[0] = B.register(risk="high", challenge_id=stage1_challenge)
        events.append(
            B.proof(
                "e5",
                "PF-s2",
                stage=2,
                factor="human",
                principal="PRIN-carol",
                challenge_id=stage1_challenge,
                now=240,
            )
        )
        case = B.case(*events, batch_id="hi-wrong-challenge")
        error = self.apply_expect_error(case)
        self.assertEqual(error.code, "E_PROOF_STAGE_MISMATCH")

    def test_missing_stage_two_is_rejected(self) -> None:
        events = self._stage1()
        events.append(B.advance("e5", stage=2, now=240))
        case = B.case(*events, batch_id="hi-no-s2")
        error = self.apply_expect_error(case)
        self.assertEqual(error.code, "E_STAGE2_NOT_SATISFIED")


if __name__ == "__main__":
    unittest.main()
