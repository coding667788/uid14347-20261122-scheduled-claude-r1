"""A deliberately naive finite-state reference model.

The model is written from the specification, not from the engine: it keeps a
flat dict of facts and answers the same questions with straightforward loops.
Property tests generate random small cases and require the engine to agree with
the model on every observable: final status, which proofs are consumed, receipt
count, and the reason for any refusal.

Scope is intentionally narrow -- stage 1 + issuance + risk upgrade -- because
that is where a small model can be exhaustive without becoming a second engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from solution.engine import adjudicate, blank_state
from solution.errors import CaseError
from solution.model import (
    STATUS_COLLECTING,
    STATUS_ISSUED,
    STATUS_STAGE1,
    STATUS_STAGE2,
)
from solution.policy import ProofView, evaluate_stage

FACTORS = ("device", "human")
STAGES = (1, 2)


@dataclass
class ModelProof:
    proof_id: str
    stage: int
    factor: str
    principal: str
    trust_group: str
    trusted: bool
    expires_at: int
    generation: str
    consumed: bool = False


@dataclass
class ModelState:
    """A request plus its proofs, as a flat, directly-inspectable record."""

    request_id: str
    risk: str
    generation: str
    policy_version: int
    expires_at: int
    status: str = STATUS_COLLECTING
    stage1: tuple[str, ...] | None = None
    stage2: tuple[str, ...] | None = None
    proofs: dict[str, ModelProof] = field(default_factory=dict)
    receipt_count: int = 0
    receipt_proofs: tuple[str, ...] = ()
    last_error: str | None = None


class ModelRejection(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _views(state: ModelState) -> list[ProofView]:
    return [
        ProofView(
            proof_id=p.proof_id,
            stage=p.stage,
            factor=p.factor,
            principal=p.principal,
            trust_group=p.trust_group,
            trusted=p.trusted,
            expires_at=p.expires_at,
            status="active",
            consumed=p.consumed,
            generation=p.generation,
            challenge_id="",
        )
        for p in state.proofs.values()
    ]


def _adjudicate(state: ModelState, policy: Any, stage: int, now: int, retained: Iterable[str]) -> Any:
    return evaluate_stage(
        policy,
        stage,
        _views(state),
        now=now,
        generation=state.generation,
        retained_ids=retained,
    )


def submit(state: ModelState, proof: ModelProof) -> None:
    if state.status == STATUS_ISSUED:
        raise ModelRejection("E_REQUEST_ISSUED")
    if proof.proof_id in state.proofs:
        raise ModelRejection("E_PROOF_EXISTS")
    if proof.generation != state.generation:
        raise ModelRejection("E_PROOF_GENERATION_MISMATCH")
    if proof.expires_at <= 0:
        raise ModelRejection("E_PROOF_EXPIRED")
    state.proofs[proof.proof_id] = proof


def advance(state: ModelState, policy: Any, stage: int, now: int) -> str:
    """Return ``issued`` / ``stage1_complete`` / raise ``ModelRejection``."""
    if state.status == STATUS_ISSUED:
        raise ModelRejection("E_REQUEST_ISSUED")
    if now > state.expires_at:
        raise ModelRejection("E_CHALLENGE_EXPIRED")

    if stage == 1:
        retained = state.stage1 or ()
        evaluation = _adjudicate(state, policy, 1, now, retained)
        if not evaluation.satisfied:
            raise ModelRejection("E_STAGE1_NOT_SATISFIED")
        for pid in evaluation.consumed_now:
            state.proofs[pid].consumed = True
        state.stage1 = tuple(evaluation.proof_ids)
        if state.risk == "low":
            _issue(state)
            return "issued"
        state.status = STATUS_STAGE1
        return "stage1_complete"

    if state.stage1 is None:
        raise ModelRejection("E_STAGE1_NOT_COMPLETE")

    # Stage 1 is re-checked; a stricter policy can force a redo.
    retained1 = state.stage1
    recheck = _adjudicate(state, policy, 1, now, retained1)
    if not recheck.satisfied:
        state.stage1 = None
        state.stage2 = None
        state.status = STATUS_COLLECTING
        raise ModelRejection("E_ROLLED_BACK")

    for pid in recheck.consumed_now:
        state.proofs[pid].consumed = True
    state.stage1 = tuple(recheck.proof_ids)

    retained2 = state.stage2 or ()
    evaluation = _adjudicate(state, policy, 2, now, retained2)
    if not evaluation.satisfied:
        raise ModelRejection("E_STAGE2_NOT_SATISFIED")
    for pid in evaluation.consumed_now:
        state.proofs[pid].consumed = True
    state.stage2 = tuple(evaluation.proof_ids)
    state.status = STATUS_STAGE2
    _issue(state)
    return "issued"


def _issue(state: ModelState) -> None:
    assert state.stage1 is not None
    ids = list(state.stage1)
    if state.risk == "high":
        assert state.stage2 is not None
        ids.extend(state.stage2)
    state.receipt_count += 1
    state.receipt_proofs = tuple(sorted(ids))
    state.status = STATUS_ISSUED


def upgrade_risk(state: ModelState, target: str) -> None:
    if state.status == STATUS_ISSUED:
        raise ModelRejection("E_REQUEST_ISSUED")
    if target == state.risk:
        raise ModelRejection("E_RISK_UNCHANGED")
    if target == "low":
        raise ModelRejection("E_RISK_DOWNGRADE")
    state.risk = target
    state.stage1 = None
    state.stage2 = None
    state.status = STATUS_COLLECTING


def replay_engine(events: list[dict[str, Any]], state: Any, policies: dict[int, Any]) -> Any:
    """Apply the same event stream through the engine, for comparison."""
    from solution.engine import EventContext, apply_event

    engine_state = blank_state()
    engine_state.policies = dict(policies)
    engine_state.policy_fingerprints = {v: p.fingerprint() for v, p in policies.items()}
    for index, event in enumerate(events):
        apply_event(engine_state, event, EventContext(batch_no=1, index=index, path=f"events[{index}]"))
    return engine_state
