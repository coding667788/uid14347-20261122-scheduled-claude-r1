"""Randomised differential testing against the finite-state model.

The generator walks the *model* forward, so it knows which stage challenge is
open and which events are meaningful.  It then emits the same stream through the
real engine and requires the two to agree on every observable: final status,
consumed proofs, receipt count and the receipt's proof set.

A fixed seed list keeps failures reproducible; each seed explores a different
interleaving of proof submissions, advances and risk upgrades.
"""

from __future__ import annotations

import random
import unittest
from typing import Any

from tests import builder as B
from tests import fsm_model as M
from tests.support import LedgerTestCase

from solution.errors import CaseError
from solution.policy import parse_policy

SEEDS = list(range(1, 201))


def _policy() -> dict:
    return {
        "version": 1,
        "recipes": [
            B.recipe("s1-two", 1, factors=["device", "human"], distinct_principals=True),
            B.recipe("s2-one", 2, factors=["human"]),
        ],
    }


def _generate(rng: random.Random) -> dict:
    """Build an event stream by consulting the model as we go."""
    policy_doc = _policy()
    policy = parse_policy(policy_doc, "case.policies[0]")

    risk = rng.choice(["low", "high"])
    model = M.ModelState(
        request_id="REQ-1",
        risk=risk,
        generation="GEN-1",
        policy_version=1,
        expires_at=1000,
    )
    events: list[dict] = [B.register(risk=risk, now=10, ttl=1000)]
    principals = ["PRIN-a", "PRIN-b", "PRIN-c"]
    groups = ["TG-x", "TG-y", "TG-z"]
    proof_no = 0
    now = 20
    # Count *consecutive unproductive* steps.  Submitting a proof is always
    # productive, so only repeated failing advances count.
    stalled = 0

    for _ in range(rng.randint(6, 14)):
        if stalled >= 3:
            break
        now += 5
        roll = rng.random()
        if roll < 0.55:
            proof_no += 1
            stage = 1 if model.stage1 is None else 2
            factor = rng.choice(["device", "human"])
            # Bias towards satisfying recipes: stage 1 needs one device and one
            # human from different principals; stage 2 needs a fresh human.
            if stage == 1:
                have = {p.factor for p in model.proofs.values() if p.stage == 1 and not p.consumed}
                if "device" in have and "human" not in have:
                    factor = "human"
                elif "human" in have and "device" not in have:
                    factor = "device"
            else:
                factor = "human"
            used = {p.principal for p in model.proofs.values() if p.stage == stage}
            free = [p for p in principals if p not in used]
            principal = rng.choice(free) if free and rng.random() < 0.8 else rng.choice(principals)
            candidate = M.ModelProof(
                proof_id=f"PF-{proof_no}",
                stage=stage,
                factor=factor,
                principal=principal,
                trust_group=rng.choice(groups),
                trusted=rng.random() > 0.05,
                expires_at=model.expires_at,
                generation=model.generation,
            )
            events.append(
                B.proof(
                    f"e{len(events)}",
                    candidate.proof_id,
                    stage=stage,
                    factor=factor,
                    principal=candidate.principal,
                    trust_group=candidate.trust_group,
                    trusted=candidate.trusted,
                    now=now,
                )
            )
            try:
                M.submit(model, candidate)
            except M.ModelRejection:
                pass
            stalled = 0
        elif roll < 0.9:
            stage = 1 if model.stage1 is None else 2
            events.append(B.advance(f"e{len(events)}", stage=stage, now=now))
            try:
                M.advance(model, policy, stage, now)
                stalled = 0
                if model.status == M.STATUS_ISSUED:
                    break
            except M.ModelRejection:
                stalled += 1
        else:
            # Risk upgrade is only legal while nothing is issued.
            if model.status != M.STATUS_ISSUED and model.risk == "low":
                events.append(
                    {
                        "event_id": f"e{len(events)}",
                        "type": "upgrade_risk",
                        "request_id": "REQ-1",
                        "risk": "high",
                        "now": now,
                    }
                )
                M.upgrade_risk(model, "high")
                stalled = 0
            else:
                stalled += 1

    return B.case(*events, batch_id="", policies=[policy_doc])


def _engine_run(case: dict) -> M.ModelState:
    """Drive the engine event by event, stopping at the first rejection."""
    from solution.engine import EventContext, apply_event, blank_state

    engine = blank_state()
    policy = parse_policy(case["policies"][0], "case.policies[0]")
    engine.policies = {1: policy}
    engine.policy_fingerprints = {1: policy.fingerprint()}
    error: str | None = None
    for index, event in enumerate(case["events"]):
        try:
            apply_event(engine, event, EventContext(batch_no=1, index=index, path=f"events[{index}]"))
        except CaseError as exc:
            error = exc.code
            break
    request = engine.requests["REQ-1"]
    return _project(engine, request, error)


def _model_run(case: dict) -> M.ModelState:
    policy = parse_policy(case["policies"][0], "case.policies[0]")
    model = M.ModelState(
        request_id="REQ-1",
        risk=case["events"][0]["risk"],
        generation="GEN-1",
        policy_version=1,
        expires_at=1000,
    )
    error: str | None = None
    for event in case["events"][1:]:
        try:
            if event["type"] == "submit_proof":
                M.submit(
                    model,
                    M.ModelProof(
                        proof_id=event["proof_id"],
                        stage=event["stage"],
                        factor=event["factor"],
                        principal=event["principal"],
                        trust_group=event["trust_group"],
                        trusted=event["trusted"],
                        expires_at=model.expires_at,
                        generation=model.generation,
                    ),
                )
            elif event["type"] == "advance":
                try:
                    M.advance(model, policy, event["stage"], event["now"])
                except M.ModelRejection as rejection:
                    if rejection.code != "E_ROLLED_BACK":
                        raise
            elif event["type"] == "upgrade_risk":
                M.upgrade_risk(model, event["risk"])
        except M.ModelRejection as rejection:
            error = rejection.code
            break
    model.last_error = error
    return model


def _project(engine: Any, request: Any, error: str | None) -> M.ModelState:
    receipt = engine.receipts.get(request.receipt_id) if request.receipt_id else None
    stage1 = request.stage1.proof_ids if request.stage1 and request.stage1.valid else None
    stage2 = request.stage2.proof_ids if request.stage2 and request.stage2.valid else None
    receipt_proofs: tuple[str, ...] = ()
    if receipt is not None:
        ids = list(receipt.payload["stage1"]["proof_ids"])
        if receipt.payload.get("stage2"):
            ids.extend(receipt.payload["stage2"]["proof_ids"])
        receipt_proofs = tuple(sorted(ids))
    return M.ModelState(
        request_id=request.request_id,
        risk=request.risk,
        generation=request.generation,
        policy_version=request.policy_version,
        expires_at=request.expires_at or 0,
        status=request.status,
        stage1=stage1,
        stage2=stage2,
        proofs={
            pid: M.ModelProof(
                proof_id=pid,
                stage=proof.stage,
                factor=proof.factor,
                principal=proof.principal,
                trust_group=proof.trust_group,
                trusted=proof.trusted,
                expires_at=proof.expires_at,
                generation=proof.generation,
                consumed=proof.consumed_by is not None,
            )
            for (rid, pid), proof in engine.proofs.items()
            if rid == request.request_id
        },
        receipt_count=1 if receipt is not None else 0,
        receipt_proofs=receipt_proofs,
        last_error=error,
    )


def _observable(state: M.ModelState) -> tuple:
    return (
        state.status,
        state.receipt_count,
        state.receipt_proofs,
        sorted(pid for pid, proof in state.proofs.items() if proof.consumed),
        sorted(pid for pid, proof in state.proofs.items()),
        state.risk,
    )


class DifferentialTests(LedgerTestCase):
    def test_random_small_cases_match_the_model(self) -> None:
        mismatches: list[dict] = []
        for seed in SEEDS:
            case = _generate(random.Random(seed))
            engine_result = _engine_run(case)
            model_result = _model_run(case)
            if _observable(engine_result) != _observable(model_result):
                mismatches.append(
                    {
                        "seed": seed,
                        "events": [(e["type"], e.get("stage"), e.get("proof_id")) for e in case["events"]],
                        "engine": _observable(engine_result),
                        "model": _observable(model_result),
                        "errors": (engine_result.last_error, model_result.last_error),
                    }
                )
        self.assertEqual(mismatches, [], f"{len(mismatches)} of {len(SEEDS)} seeds diverged")

    def test_generator_reaches_issuance_for_both_risks(self) -> None:
        """Guard against a generator that only ever explores failures."""
        seen: set[tuple[str, str]] = set()
        for seed in SEEDS:
            case = _generate(random.Random(seed))
            result = _engine_run(case)
            if result.receipt_count:
                seen.add((case["events"][0]["risk"], result.status))
        self.assertIn(("low", "issued"), seen)
        self.assertIn(("high", "issued"), seen)


if __name__ == "__main__":
    unittest.main()
