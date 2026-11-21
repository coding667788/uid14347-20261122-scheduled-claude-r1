"""Chained migration.

A migration is a per-step transfer: one token, one generation hop, one
predecessor digest, consumed exactly once.  These tests cover the chain rules,
the stale-credential injection failure mode, and the preserved-stage-1 rule.
"""

from __future__ import annotations

import unittest

from tests import builder as B
from tests.support import LedgerTestCase


def _by_type(result: dict, kind: str) -> dict:
    for event in result["events"]:
        if event.get("type") == kind:
            return event
    raise AssertionError(f"no {kind!r} event in result")


def _stage1_events(risk: str = "high") -> list[dict[str, object]]:
    return [
        B.register(risk=risk, challenge_id="chl-s1"),
        B.proof("e2", "PF-d", factor="device", principal="PRIN-laptop", trust_group="TG-devices", now=210),
        B.proof("e3", "PF-h", factor="human", principal="PRIN-bob", trust_group="TG-staff", now=220),
        B.advance("e4", stage=1, now=230),
    ]


class MigrationChainTests(LedgerTestCase):
    def _stage1_committed(self, db: str, risk: str = "high") -> dict[str, object]:
        return self.apply(B.case(*_stage1_events(risk), batch_id="s1"), db=db)

    def _challenge(self, db: str) -> str:
        return str(self.state(db)["requests"]["REQ-1"]["challenge_id"])

    def test_preserve_stage1_carries_through_one_hop(self) -> None:
        db = self.db_path()
        self._stage1_committed(db)
        challenge = self._challenge(db)
        result = self.apply(
            B.case(
                B.token("t1-evt", "TOK-1", challenge_id=challenge, to_generation="GEN-2", to_org="ORG-south", now=240),
                B.migrate(
                    "m1-evt", "TOK-1", to_generation="GEN-2", to_org="ORG-south", preserve_stage1=True, now=250
                ),
                batch_id="mig-1",
            ),
            db=db,
        )
        migration = _by_type(result, "migrate")
        self.assertEqual(migration["outcome"], "migrated")
        self.assertEqual(migration["stage1_state"], "preserved")
        self.assertEqual(migration["step"], 1)

        request = self.state(db)["requests"]["REQ-1"]
        self.assertEqual(request["generation"], "GEN-2")
        self.assertEqual(request["org"], "ORG-south")
        self.assertTrue(request["stage1"]["retained"])
        self.assertTrue(request["stage1"]["valid"])

    def test_stage2_still_required_after_preserved_migration(self) -> None:
        db = self.db_path()
        self._stage1_committed(db)
        first_challenge = self._challenge(db)
        self.apply(
            B.case(
                B.token("t1-evt", "TOK-1", challenge_id=first_challenge, to_generation="GEN-2", now=240),
                B.migrate("m1-evt", "TOK-1", to_generation="GEN-2", preserve_stage1=True, now=250),
                batch_id="mig-1",
            ),
            db=db,
        )
        request = self.state(db)["requests"]["REQ-1"]
        self.assertEqual(request["status"], "stage1_complete")
        self.assertIsNotNone(request["stage2_challenge_id"])
        # The stage-2 challenge is freshly minted for the new generation.
        self.assertNotEqual(request["stage2_challenge_id"], first_challenge)

    def test_injecting_old_generation_proof_fails(self) -> None:
        db = self.db_path()
        self._stage1_committed(db)
        first_challenge = self._challenge(db)
        self.apply(
            B.case(
                B.token("t1-evt", "TOK-1", challenge_id=first_challenge, to_generation="GEN-2", now=240),
                B.migrate("m1-evt", "TOK-1", to_generation="GEN-2", preserve_stage1=True, now=250),
                batch_id="mig-1",
            ),
            db=db,
        )
        stage2_challenge = self.state(db)["requests"]["REQ-1"]["stage2_challenge_id"]
        error = self.apply_expect_error(
            B.case(
                B.proof(
                    "e5",
                    "PF-s2-forged",
                    stage=2,
                    factor="human",
                    principal="PRIN-carol",
                    challenge_id=stage2_challenge,
                    generation="GEN-1",
                    now=260,
                ),
                batch_id="mig-forged",
            ),
            db=db,
        )
        self.assertEqual(error.code, "E_PROOF_GENERATION_MISMATCH")
        self.assertEqual(error.path, "events[0].generation")

    def test_old_challenge_is_closed_after_migration(self) -> None:
        db = self.db_path()
        self._stage1_committed(db)
        first_challenge = self._challenge(db)
        self.apply(
            B.case(
                B.token("t1-evt", "TOK-1", challenge_id=first_challenge, to_generation="GEN-2", now=240),
                B.migrate("m1-evt", "TOK-1", to_generation="GEN-2", preserve_stage1=True, now=250),
                batch_id="mig-1",
            ),
            db=db,
        )
        error = self.apply_expect_error(
            B.case(
                B.proof("e5", "PF-stale", stage=2, factor="human", principal="PRIN-carol",
                        challenge_id=first_challenge, now=260),
                batch_id="mig-stale-challenge",
            ),
            db=db,
        )
        self.assertEqual(error.code, "E_CHALLENGE_CLOSED")

    def test_token_is_single_use(self) -> None:
        db = self.db_path()
        self._stage1_committed(db)
        first_challenge = self._challenge(db)
        self.apply(
            B.case(
                B.token("t1-evt", "TOK-1", challenge_id=first_challenge, to_generation="GEN-2", now=240),
                B.migrate("m1-evt", "TOK-1", to_generation="GEN-2", preserve_stage1=True, now=250),
                batch_id="mig-1",
            ),
            db=db,
        )
        error = self.apply_expect_error(
            B.case(
                B.migrate("m2-evt", "TOK-1", to_generation="GEN-2", preserve_stage1=True, now=260),
                batch_id="mig-replay",
            ),
            db=db,
        )
        self.assertEqual(error.code, "E_TOKEN_ALREADY_CONSUMED")

    def test_chain_requires_predecessor_digest(self) -> None:
        db = self.db_path()
        self._stage1_committed(db)
        challenge1 = self._challenge(db)
        first = self.apply(
            B.case(
                B.token("t1-evt", "TOK-1", challenge_id=challenge1, to_generation="GEN-2", now=240),
                B.migrate("m1-evt", "TOK-1", to_generation="GEN-2", preserve_stage1=True, now=250),
                batch_id="mig-1",
            ),
            db=db,
        )
        digest1 = _by_type(first, "migrate")["migration_digest"]
        challenge2 = self._challenge(db)

        # Step two naming a step that does not exist yet.
        error = self.apply_expect_error(
            B.case(
                B.token("t2-evt", "TOK-2", challenge_id=challenge2, to_generation="GEN-3",
                        to_org="ORG-east", predecessor=9, now=260),
                batch_id="mig-2-bad",
            ),
            db=db,
        )
        self.assertEqual(error.code, "E_TOKEN_PREDECESSOR_MISMATCH")

        second = self.apply(
            B.case(
                B.token("t2-evt", "TOK-2", challenge_id=challenge2, to_generation="GEN-3",
                        to_org="ORG-east", predecessor=digest1, now=260),
                B.migrate("m2-evt", "TOK-2", to_generation="GEN-3", to_org="ORG-east",
                          preserve_stage1=True, now=270),
                batch_id="mig-2",
            ),
            db=db,
        )
        step2 = _by_type(second, "migrate")
        self.assertEqual(step2["step"], 2)
        self.assertEqual(step2["predecessor"], digest1)
        self.assertEqual(step2["from_org"], "ORG-south")
        self.assertEqual(step2["to_org"], "ORG-east")

    def test_generation_cannot_be_skipped_in_one_hop(self) -> None:
        db = self.db_path()
        self._stage1_committed(db)
        challenge = self._challenge(db)
        error = self.apply_expect_error(
            B.case(
                B.token("t1", "TOK-1", challenge_id=challenge, to_generation="GEN-2", now=240),
                B.migrate("m1", "TOK-1", to_generation="GEN-3", now=250),
                batch_id="mig-skip",
            ),
            db=db,
        )
        self.assertEqual(error.code, "E_TOKEN_GENERATION_MISMATCH")

    def test_returning_to_original_org_needs_a_fresh_generation(self) -> None:
        db = self.db_path()
        self._stage1_committed(db)
        challenge1 = self._challenge(db)
        first = self.apply(
            B.case(
                B.token("t1-evt", "TOK-1", challenge_id=challenge1, to_generation="GEN-2",
                        to_org="ORG-south", now=240),
                B.migrate("m1-evt", "TOK-1", to_generation="GEN-2", to_org="ORG-south",
                          preserve_stage1=True, now=250),
                batch_id="mig-1",
            ),
            db=db,
        )
        digest1 = _by_type(first, "migrate")["migration_digest"]
        challenge2 = self._challenge(db)

        # Returning to ORG-north still needs a fresh generation; GEN-1 is spent.
        error = self.apply_expect_error(
            B.case(
                B.token("t2", "TOK-2", challenge_id=challenge2, to_generation="GEN-1",
                        to_org="ORG-north", predecessor=digest1, now=260),
                batch_id="mig-old-gen",
            ),
            db=db,
        )
        self.assertEqual(error.code, "E_TOKEN_REUSED_GENERATION")

    def test_preserve_requires_unchanged_version(self) -> None:
        db = self.db_path()
        self._stage1_committed(db)
        challenge = self._challenge(db)
        # A token may not change the operation version at all.
        error = self.apply_expect_error(
            B.case(
                B.token("t1", "TOK-1", challenge_id=challenge, to_generation="GEN-2",
                        op_version=4, now=240),
                batch_id="mig-bad-version",
            ),
            db=db,
        )
        self.assertEqual(error.code, "E_TOKEN_RESOURCE_MISMATCH")

    def test_token_must_bind_current_challenge(self) -> None:
        db = self.db_path()
        self._stage1_committed(db)
        error = self.apply_expect_error(
            B.case(
                B.token("t1", "TOK-1", challenge_id="chl-s1", to_generation="GEN-2", now=240),
                batch_id="mig-old-challenge",
            ),
            db=db,
        )
        self.assertEqual(error.code, "E_TOKEN_CHALLENGE_MISMATCH")

    def test_migration_after_issuance_is_refused(self) -> None:
        db = self.db_path()
        self.apply(B.case(*_stage1_events(risk="low"), batch_id="low-issued"), db=db)
        challenge = self._challenge(db)
        error = self.apply_expect_error(
            B.case(
                B.token("t1", "TOK-1", challenge_id=challenge, to_generation="GEN-2", now=400),
                batch_id="mig-after-issue",
            ),
            db=db,
        )
        self.assertEqual(error.code, "E_MIGRATION_AFTER_ISSUE")


class MigrationAndIssuanceRaceTests(LedgerTestCase):
    def test_issuance_wins_the_race_against_migration(self) -> None:
        db = self.db_path()
        self.apply(B.case(*_stage1_events(risk="low"), batch_id="race-1"), db=db)
        challenge = self.state(db)["requests"]["REQ-1"]["challenge_id"]
        error = self.apply_expect_error(
            B.case(
                B.token("t1", "TOK-1", challenge_id=challenge, to_generation="GEN-2", now=400),
                batch_id="race-2",
            ),
            db=db,
        )
        self.assertEqual(error.code, "E_MIGRATION_AFTER_ISSUE")
        # Nothing from the losing batch was committed.
        self.assertEqual(len(self.explain(db)["batches"]), 1)

    def test_migration_before_stage_two_blocks_old_stage2_proof(self) -> None:
        db = self.db_path()
        # High risk: complete stage 1 and mint a stage-2 proof, but do not
        # advance yet.  Then migrate.  The old stage-2 proof must be void.
        events = _stage1_events(risk="high")
        self.apply(B.case(*events, batch_id="r1"), db=db)
        request = self.state(db)["requests"]["REQ-1"]
        self.apply(
            B.case(
                B.proof("e5", "PF-s2", stage=2, factor="human", principal="PRIN-carol",
                        challenge_id=request["stage2_challenge_id"], now=240),
                batch_id="r2",
            ),
            db=db,
        )
        request = self.state(db)["requests"]["REQ-1"]
        self.apply(
            B.case(
                B.token("t1", "TOK-1", challenge_id=request["stage2_challenge_id"],
                        to_generation="GEN-2", now=250),
                B.migrate("m1", "TOK-1", to_generation="GEN-2", preserve_stage1=True, now=260),
                batch_id="r3",
            ),
            db=db,
        )
        request = self.state(db)["requests"]["REQ-1"]
        self.assertIsNone(request["stage2"])
        by_id = {p["proof_id"]: p for p in request["proofs"]}
        self.assertEqual(by_id["PF-s2"]["status"], "active")
        self.assertIsNone(by_id["PF-s2"]["consumed_by"])

        # The stale stage-2 proof is unusable even though it is unrevoked,
        # because its generation no longer matches.
        error = self.apply_expect_error(
            B.case(B.advance("e6", stage=2, now=270), batch_id="r4"),
            db=db,
        )
        self.assertEqual(error.code, "E_STAGE2_NOT_SATISFIED")
        self.assertIn("generation_mismatch", {r for e in error.detail["excluded"] for r in e["reasons"]})


if __name__ == "__main__":
    unittest.main()
