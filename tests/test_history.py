"""Historical queries and post-issue behaviour.

``explain`` must describe a fixed commit.  A revocation appended afterwards is
visible in later commits, but never rewrites a receipt that already exists.
"""

from __future__ import annotations

import unittest

from tests import builder as B
from tests.support import LedgerTestCase


def _low_risk(batch_id: str = "low") -> dict:
    return B.case(
        B.register(risk="low"),
        B.proof("e2", "PF-d", factor="device", principal="PRIN-laptop",
                trust_group="TG-devices", now=110),
        B.proof("e3", "PF-h", factor="human", principal="PRIN-bob",
                trust_group="TG-staff", now=120),
        B.advance("e4", stage=1, now=130),
        batch_id=batch_id,
    )


class HistoryTests(LedgerTestCase):
    def _issued_then_revoked(self) -> tuple[str, dict, dict]:
        db = self.db_path()
        issued = self.apply(_low_risk("b1"), db=db)
        receipt = issued["receipts"][0]
        revoked = self.apply(
            B.case(
                {"event_id": "r1", "type": "revoke_proof", "request_id": "REQ-1",
                 "proof_id": "PF-d", "reason": "lost-device", "now": 200},
                {"event_id": "r2", "type": "revoke_request", "request_id": "REQ-1",
                 "reason": "operator", "now": 210},
                batch_id="b2",
            ),
            db=db,
        )
        return db, issued, revoked

    def test_explain_at_old_commit_shows_the_old_state(self) -> None:
        db, issued, _revoked = self._issued_then_revoked()
        at_one = self.explain(db, 1)
        request = at_one["requests"]["REQ-1"]
        self.assertEqual(request["status"], "issued")
        by_id = {p["proof_id"]: p for p in request["proofs"]}
        self.assertEqual(by_id["PF-d"]["status"], "active")
        self.assertIsNone(request["revoked_reason"])
        self.assertEqual(len(at_one["receipts"]), 1)

    def test_later_revocation_is_visible_at_the_later_commit(self) -> None:
        db, _issued, _revoked = self._issued_then_revoked()
        at_two = self.explain(db, 2)
        request = at_two["requests"]["REQ-1"]
        self.assertEqual(request["status"], "revoked")
        self.assertEqual(request["revoked_reason"], "operator")
        by_id = {p["proof_id"]: p for p in request["proofs"]}
        self.assertEqual(by_id["PF-d"]["status"], "revoked")
        self.assertEqual(by_id["PF-d"]["revoked_reason"], "lost-device")
        # The post-issue change is recorded, not folded into the receipt.
        kinds = [c["kind"] for c in request["post_issue_changes"]]
        self.assertIn("proof_revoked", kinds)

    def test_receipt_is_byte_identical_across_commits(self) -> None:
        db, issued, _revoked = self._issued_then_revoked()
        original = issued["receipts"][0]
        at_one = self.explain(db, 1)["receipts"][0]
        at_two = self.explain(db, 2)["receipts"][0]
        self.assertEqual(original, at_one)
        self.assertEqual(original, at_two)
        self.assertEqual(original["digest"], at_two["digest"])

    def test_post_issue_revocation_effects_are_marked(self) -> None:
        db = self.db_path()
        self.apply(_low_risk("b1"), db=db)
        revoked = self.apply(
            B.case(
                {"event_id": "r1", "type": "revoke_proof", "request_id": "REQ-1",
                 "proof_id": "PF-h", "reason": "reassigned", "now": 200},
                batch_id="b2",
            ),
            db=db,
        )
        event = next(e for e in revoked["events"] if e.get("type") == "revoke_proof")
        self.assertTrue(event["post_issue"])
        self.assertEqual(event["effect"], "recorded_post_issue")

    def test_revoking_a_live_proof_before_issuance_rolls_back(self) -> None:
        db = self.db_path()
        self.apply(
            B.case(
                B.register(risk="high"),
                B.proof("e2", "PF-d", factor="device", principal="PRIN-laptop",
                        trust_group="TG-devices", now=110),
                B.proof("e3", "PF-h", factor="human", principal="PRIN-bob",
                        trust_group="TG-staff", now=120),
                B.advance("e4", stage=1, now=130),
                batch_id="b1",
            ),
            db=db,
        )
        result = self.apply(
            B.case(
                {"event_id": "r1", "type": "revoke_proof", "request_id": "REQ-1",
                 "proof_id": "PF-d", "reason": "compromised", "now": 200},
                batch_id="b2",
            ),
            db=db,
        )
        event = next(e for e in result["events"] if e.get("type") == "revoke_proof")
        self.assertIn("rollback", event)
        self.assertEqual(event["rollback"]["rolled_back_to_stage"], 1)
        request = self.explain(db)["requests"]["REQ-1"]
        self.assertEqual(request["status"], "collecting")
        self.assertEqual(request["stage1"]["invalid_reason"], "evidence_revoked")
        # The revoked proof stays consumed.
        by_id = {p["proof_id"]: p for p in request["proofs"]}
        self.assertEqual(by_id["PF-d"]["consumed_by"], "stage1")

    def test_unknown_commit_is_a_located_error(self) -> None:
        db = self.db_path()
        self.apply(_low_risk("b1"), db=db)
        from solution.errors import CaseError

        with self.assertRaises(CaseError) as ctx:
            self.explain(db, 99)
        self.assertEqual(ctx.exception.code, "E_COMMIT_NOT_FOUND")

    def test_explain_lists_failures_for_an_incomplete_request(self) -> None:
        db = self.db_path()
        self.apply(
            B.case(
                B.register(risk="low"),
                B.proof("e2", "PF-d", factor="device", principal="PRIN-laptop",
                        trust_group="TG-devices", now=110),
                batch_id="b1",
            ),
            db=db,
        )
        unmet = self.explain(db)["requests"]["REQ-1"]["unmet"]
        self.assertFalse(unmet["satisfied"])
        self.assertEqual(unmet["stage"], 1)
        kinds = {f["kind"] for f in unmet["failures"]}
        self.assertIn("human", kinds)
        reasons = {f["reason"] for f in unmet["failures"]}
        self.assertIn("no_valid_combination", reasons)


class TimeTests(LedgerTestCase):
    def test_time_may_not_run_backwards_for_a_request(self) -> None:
        db = self.db_path()
        self.apply(
            B.case(
                B.register(risk="low", now=0),
                B.proof("e2", "PF-d", factor="device", now=500),
                batch_id="b1",
            ),
            db=db,
        )
        from solution.errors import CaseError

        with self.assertRaises(CaseError) as ctx:
            self.apply(
                B.case(
                    B.proof("e3", "PF-h", factor="human", now=50),
                    batch_id="b2",
                ),
                db=db,
            )
        self.assertEqual(ctx.exception.code, "E_TIME_REGRESSION")

    def test_expired_challenge_refuses_proofs(self) -> None:
        db = self.db_path()
        self.apply(
            B.case(
                B.register(risk="low", now=0, ttl=100),
                batch_id="b1",
            ),
            db=db,
        )
        error = self.apply_expect_error(
            B.case(B.proof("e2", "PF-d", factor="device", now=500), batch_id="b2"),
            db=db,
        )
        self.assertEqual(error.code, "E_CHALLENGE_EXPIRED")


if __name__ == "__main__":
    unittest.main()
