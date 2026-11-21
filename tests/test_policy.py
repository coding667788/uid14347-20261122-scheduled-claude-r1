"""Policy upgrades, recipes and retained consumptions.

The central rule: a preserved stage-1 entry keeps its *consumed facts*.  It is
not automatically promoted into satisfying a later, stricter recipe, and proofs
already spent stay spent even when the entry that used them is thrown away.
"""

from __future__ import annotations

import unittest

from tests import builder as B
from tests.support import LedgerTestCase


def _advance(result: dict) -> dict:
    for event in result["events"]:
        if event.get("type") == "advance":
            return event
    raise AssertionError(f"no advance event in {[e.get('type') for e in result['events']]}")


def _v1_policy() -> dict:
    return B.standard_policy(1)


def _v2_policy_stricter() -> dict:
    return B.strict_policy(2)


def _stage1(risk: str = "high", **kw: object) -> list[dict[str, object]]:
    return [
        B.register(risk=risk, **kw),
        B.proof("e2", "PF-d", factor="device", principal="PRIN-laptop", trust_group="TG-devices", now=210),
        B.proof("e3", "PF-h", factor="human", principal="PRIN-bob", trust_group="TG-staff", now=220),
        B.advance("e4", stage=1, now=230),
    ]


class RetainedConsumptionTests(LedgerTestCase):
    def test_stricter_policy_forces_stage1_redo_but_keeps_consumption(self) -> None:
        db = self.db_path()
        self.apply(B.case(*_stage1(risk="high"), batch_id="v1"), db=db)
        request = self.state(db)["requests"]["REQ-1"]
        self.assertEqual(request["status"], "stage1_complete")

        # Define and adopt a stricter policy, then try to advance to stage 2.
        self.apply(
            B.case(
                {
                    "event_id": "e-policy",
                    "type": "define_policy",
                    "policy": _v2_policy_stricter(),
                },
                {"event_id": "e-adopt", "type": "adopt_policy", "request_id": "REQ-1", "policy_version": 2, "now": 240},
                batch_id="adopt-v2",
            ),
            db=db,
        )

        result = self.apply(
            B.case(B.advance("e5", stage=2, now=250), batch_id="adv-v2"),
            db=db,
        )
        advance = _advance(result)
        self.assertEqual(advance["outcome"], "rolled_back")
        self.assertEqual(advance["rolled_back_to_stage"], 1)
        self.assertEqual(advance["reason"], "policy_upgrade")

        request = self.state(db)["requests"]["REQ-1"]
        self.assertEqual(request["status"], "collecting")
        self.assertFalse(request["stage1"]["valid"])
        self.assertEqual(request["stage1"]["invalid_reason"], "policy_upgrade")
        # The old proofs remain consumed; they may not be offered again.
        by_id = {p["proof_id"]: p for p in request["proofs"]}
        self.assertEqual(by_id["PF-d"]["consumed_by"], "stage1")
        self.assertEqual(by_id["PF-h"]["consumed_by"], "stage1")

        # Re-submitting them would be a duplicate id; new proofs are required.
        error = self.apply_expect_error(
            B.case(
                B.proof("e6", "PF-d", factor="device", principal="PRIN-laptop",
                        trust_group="TG-devices", now=260),
                batch_id="reuse-old",
            ),
            db=db,
        )
        self.assertEqual(error.code, "E_PROOF_EXISTS")

    def test_retained_entry_can_be_reused_by_a_compatible_policy(self) -> None:
        db = self.db_path()
        self.apply(B.case(*_stage1(risk="high"), batch_id="v1"), db=db)

        # A *compatible* policy version (same recipes, new number) should let
        # the retained facts stand without consuming anything further.
        compatible = B.standard_policy(2)
        self.apply(
            B.case(
                {"event_id": "e-policy", "type": "define_policy", "policy": compatible},
                {"event_id": "e-adopt", "type": "adopt_policy", "request_id": "REQ-1", "policy_version": 2, "now": 240},
                batch_id="adopt-compatible",
            ),
            db=db,
        )
        request = self.state(db)["requests"]["REQ-1"]
        stage2_challenge = request["stage2_challenge_id"]
        self.assertIsNotNone(stage2_challenge)

        result = self.apply(
            B.case(
                B.proof("e5", "PF-s2", stage=2, factor="human", principal="PRIN-carol",
                        challenge_id=stage2_challenge, now=250),
                B.advance("e6", stage=2, now=260),
                batch_id="issue-v2",
            ),
            db=db,
        )
        advance = _advance(result)
        self.assertEqual(advance["outcome"], "issued")
        self.assertFalse(advance["stage1_revised"])
        # Only the fresh stage-2 proof was paid for; the retained stage-1
        # entry contributed at zero cost.
        self.assertEqual(advance["consumed_now"], ["PF-s2"])

    def test_new_proofs_can_satisfy_the_stricter_recipe(self) -> None:
        db = self.db_path()
        self.apply(B.case(*_stage1(risk="high"), batch_id="v1"), db=db)
        self.apply(
            B.case(
                {"event_id": "e-policy", "type": "define_policy", "policy": _v2_policy_stricter()},
                {"event_id": "e-adopt", "type": "adopt_policy", "request_id": "REQ-1", "policy_version": 2, "now": 240},
                batch_id="adopt-v2",
            ),
            db=db,
        )
        self.apply(B.case(B.advance("e5", stage=2, now=250), batch_id="adv-rollback"), db=db)

        request = self.state(db)["requests"]["REQ-1"]
        stage1_challenge = request["stage1_challenge_id"]
        self.assertIsNotNone(stage1_challenge)

        # Fresh device + human from two *different* trust groups satisfies the
        # stricter recipe.
        result = self.apply(
            B.case(
                B.proof("e6", "PF-d2", factor="device", principal="PRIN-phone",
                        trust_group="TG-hardware", challenge_id=stage1_challenge, now=260),
                B.proof("e7", "PF-h2", factor="human", principal="PRIN-carol",
                        trust_group="TG-staff", challenge_id=stage1_challenge, now=270),
                B.advance("e8", stage=1, now=280),
                batch_id="redo-v2",
            ),
            db=db,
        )
        advance = _advance(result)
        self.assertEqual(advance["outcome"], "stage1_complete")
        self.assertEqual(advance["recipe_id"], "s1-strict")
        self.assertEqual(sorted(advance["proof_ids"]), ["PF-d2", "PF-h2"])

        request = self.state(db)["requests"]["REQ-1"]
        self.assertEqual(request["status"], "stage1_complete")
        self.assertTrue(request["stage1"]["valid"])
        # Old proofs are still consumed but are not part of the new entry.
        by_id = {p["proof_id"]: p for p in request["proofs"]}
        self.assertNotIn("PF-d", request["stage1"]["proof_ids"])
        self.assertEqual(by_id["PF-d"]["consumed_by"], "stage1")


class MinimalConsumptionTests(LedgerTestCase):
    def test_cheapest_recipe_is_selected(self) -> None:
        policy = {
            "version": 1,
            "recipes": [
                B.recipe("s1-two", 1, factors=["device", "human"], distinct_principals=True),
                B.recipe(
                    "s1-one",
                    1,
                    requirements=[{"kind": "device", "count": 1, "trust_groups": ["TG-hardware"]}],
                ),
                B.recipe("s2", 2, factors=["human"]),
            ],
        }
        case = B.case(
            B.register(risk="low"),
            B.proof("e2", "PF-d", factor="device", principal="PRIN-laptop", trust_group="TG-devices", now=110),
            B.proof("e3", "PF-h", factor="human", principal="PRIN-bob", trust_group="TG-staff", now=120),
            B.proof("e4", "PF-dhw", factor="device", principal="PRIN-key", trust_group="TG-hardware", now=130),
            B.advance("e5", stage=1, now=140),
            batch_id="cheapest",
            policies=[policy],
        )
        result = self.apply(case)
        advance = _advance(result)
        self.assertEqual(advance["recipe_id"], "s1-one")
        self.assertEqual(advance["proof_ids"], ["PF-dhw"])

    def test_ties_resolve_on_smallest_proof_id(self) -> None:
        policy = {
            "version": 1,
            "recipes": [
                B.recipe(
                    "s1-a",
                    1,
                    requirements=[{"kind": "device", "count": 1, "trust_groups": ["TG-x"]}],
                ),
                B.recipe(
                    "s1-b",
                    1,
                    requirements=[{"kind": "device", "count": 1, "trust_groups": ["TG-x"]}],
                ),
                B.recipe("s2", 2, factors=["human"]),
            ],
        }
        case = B.case(
            B.register(risk="low"),
            B.proof("e2", "PF-bbb", factor="device", principal="PRIN-2", trust_group="TG-x", now=110),
            B.proof("e3", "PF-aaa", factor="device", principal="PRIN-1", trust_group="TG-x", now=120),
            B.advance("e4", stage=1, now=130),
            batch_id="tie",
            policies=[policy],
        )
        result = self.apply(case)
        advance = _advance(result)
        self.assertEqual(advance["proof_ids"], ["PF-aaa"])


class GroupIndependenceTests(LedgerTestCase):
    def test_three_devices_two_groups_is_not_independent(self) -> None:
        policy = B.group_independence_policy()
        case = B.case(
            B.register(risk="low"),
            # Each device is individually fine, but d1 and d3 share TG-red, so
            # no trio provides three independent groups.
            B.proof("e2", "PF-d1", factor="device", principal="PRIN-1", trust_group="TG-red", now=110),
            B.proof("e3", "PF-d2", factor="device", principal="PRIN-2", trust_group="TG-blue", now=120),
            B.proof("e4", "PF-d3", factor="device", principal="PRIN-3", trust_group="TG-red", now=130),
            B.advance("e5", stage=1, now=140),
            batch_id="group-indep",
            policies=[policy],
        )
        error = self.apply_expect_error(case)
        self.assertEqual(error.code, "E_STAGE1_NOT_SATISFIED")
        reasons = {f["reason"] for f in error.detail["failures"]}
        self.assertIn("independence_not_satisfied", reasons)

    def test_single_factor_rule_and_pair_rule_both_hold(self) -> None:
        policy = B.group_independence_policy()
        case = B.case(
            B.register(risk="low"),
            # Three devices, three principals, three groups: independent.
            B.proof("e2", "PF-d1", factor="device", principal="PRIN-1", trust_group="TG-red", now=110),
            B.proof("e3", "PF-d2", factor="device", principal="PRIN-2", trust_group="TG-blue", now=120),
            B.proof("e4", "PF-d3", factor="device", principal="PRIN-3", trust_group="TG-green", now=125),
            B.advance("e5", stage=1, now=130),
            batch_id="group-ok",
            policies=[policy],
        )
        result = self.apply(case)
        advance = _advance(result)
        self.assertEqual(advance["proof_ids"], ["PF-d1", "PF-d2", "PF-d3"])


if __name__ == "__main__":
    unittest.main()
