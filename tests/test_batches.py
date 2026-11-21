"""Batch semantics and edge cases called out by the specification.

* an out-of-order migration ticket inside one batch
* a stale ticket from an earlier hop, including a return to the origin org
* batch re-entry after a rollback back to stage 1
* a mixed batch where part of the work is consumed and a later event fails
"""

from __future__ import annotations

import unittest

from tests import builder as B
from tests.support import LedgerTestCase


def _stage1(risk: str = "high", **kw: object) -> list[dict[str, object]]:
    return [
        B.register(risk=risk, **kw),
        B.proof("e2", "PF-d", factor="device", principal="PRIN-laptop",
                trust_group="TG-devices", now=210),
        B.proof("e3", "PF-h", factor="human", principal="PRIN-bob",
                trust_group="TG-staff", now=220),
        B.advance("e4", stage=1, now=230),
    ]


class BatchOrderTests(LedgerTestCase):
    def test_migration_before_its_token_is_out_of_order(self) -> None:
        db = self.db_path()
        self.apply(B.case(*_stage1(risk="high"), batch_id="s1"), db=db)
        challenge = self.state(db)["requests"]["REQ-1"]["challenge_id"]
        error = self.apply_expect_error(
            B.case(
                B.migrate("m1", "TOK-1", to_generation="GEN-2", preserve_stage1=True, now=250),
                B.token("t1", "TOK-1", challenge_id=challenge, to_generation="GEN-2", now=240),
                batch_id="out-of-order",
            ),
            db=db,
        )
        self.assertEqual(error.code, "E_BATCH_OUT_OF_ORDER")
        self.assertEqual(error.path, "events[0].token_id")

    def test_token_after_migration_within_the_same_batch_is_accepted(self) -> None:
        db = self.db_path()
        self.apply(B.case(*_stage1(risk="high"), batch_id="s1"), db=db)
        challenge = self.state(db)["requests"]["REQ-1"]["challenge_id"]
        result = self.apply(
            B.case(
                B.token("t1", "TOK-1", challenge_id=challenge, to_generation="GEN-2", now=240),
                B.migrate("m1", "TOK-1", to_generation="GEN-2", preserve_stage1=True, now=250),
                batch_id="in-order",
            ),
            db=db,
        )
        self.assertEqual(len(result["receipts"]), 0)
        self.assertEqual(self.state(db)["requests"]["REQ-1"]["generation"], "GEN-2")


class StaleTicketTests(LedgerTestCase):
    def test_hop_one_ticket_cannot_carry_hop_two(self) -> None:
        db = self.db_path()
        self.apply(B.case(*_stage1(risk="high"), batch_id="s1"), db=db)
        challenge1 = self.state(db)["requests"]["REQ-1"]["challenge_id"]
        first = self.apply(
            B.case(
                B.token("t1", "TOK-1", challenge_id=challenge1, to_generation="GEN-2", now=240),
                B.migrate("m1", "TOK-1", to_generation="GEN-2", preserve_stage1=True, now=250),
                batch_id="hop1",
            ),
            db=db,
        )
        digest1 = _migrate_event(first)["migration_digest"]
        challenge2 = self.state(db)["requests"]["REQ-1"]["challenge_id"]

        error = self.apply_expect_error(
            B.case(
                B.migrate("m2", "TOK-1", to_generation="GEN-3", to_org="ORG-east",
                          preserve_stage1=True, now=260),
                batch_id="reuse-hop1",
            ),
            db=db,
        )
        self.assertEqual(error.code, "E_TOKEN_ALREADY_CONSUMED")

        # The same, but with a *fresh* token whose predecessor is the hop-1
        # digest and whose target org is the original org: still refused,
        # because GEN-1 is spent.
        error = self.apply_expect_error(
            B.case(
                B.token("t2", "TOK-2", challenge_id=challenge2, to_generation="GEN-1",
                        to_org="ORG-north", predecessor=digest1, now=270),
                batch_id="return-old-generation",
            ),
            db=db,
        )
        self.assertEqual(error.code, "E_TOKEN_REUSED_GENERATION")

    def test_return_to_origin_with_a_new_generation_is_allowed(self) -> None:
        db = self.db_path()
        self.apply(B.case(*_stage1(risk="high"), batch_id="s1"), db=db)
        challenge = self.state(db)["requests"]["REQ-1"]["challenge_id"]
        self.apply(
            B.case(
                B.token("t1", "TOK-1", challenge_id=challenge, to_generation="GEN-2",
                        to_org="ORG-south", now=240),
                B.migrate("m1", "TOK-1", to_generation="GEN-2", to_org="ORG-south",
                          preserve_stage1=True, now=250, next_challenge_id="CHL-2"),
                batch_id="hop1",
            ),
            db=db,
        )
        result = self.apply(
            B.case(
                B.token("t2", "TOK-2", challenge_id="CHL-2", to_generation="GEN-3",
                        to_org="ORG-north", predecessor=1, now=260),
                B.migrate("m2", "TOK-2", to_generation="GEN-3", to_org="ORG-north",
                          preserve_stage1=True, now=270),
                batch_id="hop2",
            ),
            db=db,
        )
        migrate = _migrate_event(result)
        self.assertEqual(migrate["to_org"], "ORG-north")
        self.assertEqual(migrate["step"], 2)
        request = self.state(db)["requests"]["REQ-1"]
        self.assertEqual(request["org"], "ORG-north")
        self.assertEqual(request["generation"], "GEN-3")


def _migrate_event(result: dict) -> dict:
    for event in result["events"]:
        if event.get("type") == "migrate":
            return event
    raise AssertionError("no migrate event")


class ReentryTests(LedgerTestCase):
    def test_batch_after_rollback_can_complete_stage1_again(self) -> None:
        db = self.db_path()
        self.apply(B.case(*_stage1(risk="high"), batch_id="s1"), db=db)
        # Revoke a consumed proof, which rolls the request back to stage 1.
        self.apply(
            B.case(
                {"event_id": "r1", "type": "revoke_proof", "request_id": "REQ-1",
                 "proof_id": "PF-d", "reason": "compromised", "now": 240},
                batch_id="revoke",
            ),
            db=db,
        )
        request = self.state(db)["requests"]["REQ-1"]
        self.assertEqual(request["status"], "collecting")
        challenge = request["stage1_challenge_id"]

        # A later batch supplies fresh evidence on the new challenge.
        result = self.apply(
            B.case(
                B.proof("e5", "PF-d2", factor="device", principal="PRIN-phone",
                        trust_group="TG-devices", challenge_id=challenge, now=250),
                B.proof("e6", "PF-h2", factor="human", principal="PRIN-bob",
                        trust_group="TG-staff", challenge_id=challenge, now=260),
                B.advance("e7", stage=1, now=270),
                batch_id="reentry",
            ),
            db=db,
        )
        advance = next(e for e in result["events"] if e.get("type") == "advance")
        self.assertEqual(advance["outcome"], "stage1_complete")
        self.assertEqual(sorted(advance["proof_ids"]), ["PF-d2", "PF-h2"])

    def test_partial_consumption_then_failure_leaves_nothing_behind(self) -> None:
        """One batch consumes stage-1 proofs and then fails at stage 2.

        The failure rolls the whole batch back, so the stage-1 proofs must not
        appear consumed in the committed history.
        """
        db = self.db_path()
        self.apply(B.case(*_stage1(risk="high"), batch_id="s1"), db=db)
        error = self.apply_expect_error(
            B.case(
                B.advance("e5", stage=2, now=240),  # stage 2 has no evidence
                batch_id="partial",
            ),
            db=db,
        )
        self.assertEqual(error.code, "E_STAGE2_NOT_SATISFIED")
        explained = self.explain(db)
        self.assertEqual(len(explained["batches"]), 1)
        request = explained["requests"]["REQ-1"]
        for proof in request["proofs"]:
            self.assertEqual(proof["consumed_batch"], 1)
        self.assertEqual(request["status"], "stage1_complete")


class TrustGroupIndependenceTests(LedgerTestCase):
    def test_recipe_rejects_factors_from_one_group(self) -> None:
        policy = {
            "version": 1,
            "recipes": [
                B.recipe("s1", 1, factors=["device", "human"],
                         distinct_principals=True, distinct_trust_groups=True),
                B.recipe("s2", 2, factors=["human"]),
            ],
        }
        case = B.case(
            B.register(risk="low"),
            B.proof("e2", "PF-d", factor="device", principal="PRIN-a", trust_group="TG-one", now=110),
            B.proof("e3", "PF-h", factor="human", principal="PRIN-b", trust_group="TG-one", now=120),
            B.advance("e4", stage=1, now=130),
            batch_id="same-group",
            policies=[policy],
        )
        error = self.apply_expect_error(case)
        self.assertEqual(error.code, "E_STAGE1_NOT_SATISFIED")
        reasons = {f["reason"] for f in error.detail["failures"]}
        self.assertIn("independence_not_satisfied", reasons)

    def test_untrusted_proof_is_excluded(self) -> None:
        case = B.case(
            B.register(risk="low"),
            B.proof("e2", "PF-d", factor="device", principal="PRIN-a",
                    trust_group="TG-devices", trusted=True, now=110),
            B.proof("e3", "PF-h", factor="human", principal="PRIN-b",
                    trust_group="TG-staff", trusted=False, now=120),
            B.advance("e4", stage=1, now=130),
            batch_id="untrusted",
        )
        error = self.apply_expect_error(case)
        self.assertEqual(error.code, "E_STAGE1_NOT_SATISFIED")
        reasons = {r for item in error.detail["excluded"] for r in item["reasons"]}
        self.assertIn("untrusted", reasons)


if __name__ == "__main__":
    unittest.main()
