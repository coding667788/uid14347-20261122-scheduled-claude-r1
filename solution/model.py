"""Ledger state objects and their JSON projections.

State is rebuilt by folding committed events, never mutated by ad-hoc SQL.
That is what makes ``explain`` at an old commit number trustworthy and what
lets the property tests compare the engine against an independent model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .canonical import canonical_json, digest
from .policy import Policy

STAGE1 = 1
STAGE2 = 2

STATUS_COLLECTING = "collecting"
STATUS_STAGE1 = "stage1_complete"
STATUS_STAGE2 = "stage2_complete"
STATUS_ISSUED = "issued"
STATUS_REVOKED = "revoked"


@dataclass
class Challenge:
    challenge_id: str
    request_id: str
    stage: int
    generation: str
    resource: str
    operation: str
    op_version: int
    risk: str
    policy_version: int
    expires_at: int
    factors: tuple[str, ...]
    batch_no: int
    open: bool = True

    def to_json(self) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "stage": self.stage,
            "generation": self.generation,
            "resource": self.resource,
            "op_version": self.op_version,
            "risk": self.risk,
            "policy_version": self.policy_version,
            "expires_at": self.expires_at,
            "factors": list(self.factors),
            "open": self.open,
        }


@dataclass
class Proof:
    proof_id: str
    request_id: str
    challenge_id: str
    stage: int
    factor: str
    principal: str
    trust_group: str
    trusted: bool
    expires_at: int
    generation: str
    batch_no: int
    status: str = "active"  # active | revoked
    revoked_reason: str | None = None
    consumed_by: str | None = None  # "stage1" / "stage2"
    consumed_batch: int | None = None
    generation_mismatch: bool = False

    def to_json(self, challenge_expiry: int | None = None) -> dict[str, Any]:
        effective = self.expires_at
        if challenge_expiry is not None:
            effective = min(effective, challenge_expiry)
        return {
            "proof_id": self.proof_id,
            "challenge_id": self.challenge_id,
            "stage": self.stage,
            "factor": self.factor,
            "principal": self.principal,
            "trust_group": self.trust_group,
            "trusted": self.trusted,
            "expires_at": self.expires_at,
            "effective_expires_at": effective,
            "generation": self.generation,
            "status": self.status,
            "consumed_by": self.consumed_by,
            "consumed_batch": self.consumed_batch,
            "generation_mismatch": self.generation_mismatch,
            "revoked_reason": self.revoked_reason,
        }


@dataclass
class StageEntry:
    stage: int
    challenge_id: str
    generation: str
    policy_version: int
    recipe_id: str
    proof_ids: tuple[str, ...]
    digest: str
    resource: str
    op_version: int
    risk: str
    batch_no: int
    valid: bool = True
    invalid_reason: str | None = None
    invalid_batch: int | None = None
    retained: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "challenge_id": self.challenge_id,
            "generation": self.generation,
            "policy_version": self.policy_version,
            "recipe_id": self.recipe_id,
            "proof_ids": list(self.proof_ids),
            "digest": self.digest,
            "resource": self.resource,
            "op_version": self.op_version,
            "risk": self.risk,
            "valid": self.valid,
            "invalid_reason": self.invalid_reason,
            "invalid_batch": self.invalid_batch,
            "retained": self.retained,
            "batch_no": self.batch_no,
        }


@dataclass
class MigrationRecord:
    step: int
    token_id: str
    from_generation: str
    to_generation: str
    from_org: str
    to_org: str
    resource: str
    op_version: int
    policy_version: int
    predecessor: str | None
    receipt_id: str
    digest: str
    batch_no: int
    preserved_stage1: bool

    def to_json(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "token_id": self.token_id,
            "from_generation": self.from_generation,
            "to_generation": self.to_generation,
            "from_org": self.from_org,
            "to_org": self.to_org,
            "resource": self.resource,
            "op_version": self.op_version,
            "policy_version": self.policy_version,
            "predecessor": self.predecessor,
            "receipt_id": self.receipt_id,
            "digest": self.digest,
            "preserved_stage1": self.preserved_stage1,
            "batch_no": self.batch_no,
        }


@dataclass
class Receipt:
    receipt_id: str
    request_id: str
    subject_id: str
    number: int
    payload: dict[str, Any]
    batch_no: int

    @property
    def digest(self) -> str:
        return str(self.payload["digest"])

    def to_json(self) -> dict[str, Any]:
        return dict(self.payload)


@dataclass
class Invalidation:
    stage: int
    reason: str
    detail: dict[str, Any]
    batch_no: int

    def to_json(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "reason": self.reason,
            "detail": dict(self.detail),
            "batch_no": self.batch_no,
        }


@dataclass
class RequestState:
    request_id: str
    subject_id: str
    org: str
    resource: str
    operation: str
    op_version: int
    risk: str
    generation: str
    policy_version: int
    expires_at: int | None
    status: str
    stage1_challenge_id: str
    stage2_challenge_id: str | None = None
    migration_step: int = 0
    last_migration_digest: str | None = None
    migrations: list[MigrationRecord] = field(default_factory=list)
    stage1: StageEntry | None = None
    stage2: StageEntry | None = None
    receipt_id: str | None = None
    invalidations: list[Invalidation] = field(default_factory=list)
    used_generations: list[str] = field(default_factory=list)
    revoked_reason: str | None = None
    created_batch: int = 0
    last_batch: int = 0
    last_now: int = 0
    post_issue_changes: list[dict[str, Any]] = field(default_factory=list)

    @property
    def challenge_id(self) -> str:
        return self.stage2_challenge_id or self.stage1_challenge_id

    def to_json(self, state: "LedgerState" | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {
            "request_id": self.request_id,
            "subject_id": self.subject_id,
            "org": self.org,
            "resource": self.resource,
            "operation": self.operation,
            "op_version": self.op_version,
            "risk": self.risk,
            "generation": self.generation,
            "policy_version": self.policy_version,
            "status": self.status,
            "challenge_id": self.challenge_id,
            "stage1_challenge_id": self.stage1_challenge_id,
            "stage2_challenge_id": self.stage2_challenge_id,
            "migration_step": self.migration_step,
            "last_migration_digest": self.last_migration_digest,
            "migrations": [m.to_json() for m in self.migrations],
            "stage1": self.stage1.to_json() if self.stage1 else None,
            "stage2": self.stage2.to_json() if self.stage2 else None,
            "receipt_id": self.receipt_id,
            "invalidations": [i.to_json() for i in self.invalidations],
            "used_generations": list(self.used_generations),
            "revoked_reason": self.revoked_reason,
            "expires_at": self.expires_at,
            "created_batch": self.created_batch,
            "last_batch": self.last_batch,
            "post_issue_changes": [dict(c) for c in self.post_issue_changes],
        }
        if state is not None:
            body["proofs"] = [
                p.to_json(challenge_expiry=_challenge_expiry(state, p))
                for p in state.proofs_for(self.request_id)
            ]
        return body


def _challenge_expiry(state: "LedgerState", proof: Proof) -> int | None:
    challenge = state.challenges.get(proof.challenge_id)
    return None if challenge is None else challenge.expires_at


@dataclass
class LedgerState:
    policies: dict[int, Policy] = field(default_factory=dict)
    policy_fingerprints: dict[int, str] = field(default_factory=dict)
    requests: dict[str, RequestState] = field(default_factory=dict)
    challenges: dict[str, Challenge] = field(default_factory=dict)
    proofs: dict[tuple[str, str], Proof] = field(default_factory=dict)
    tokens: dict[str, dict[str, Any]] = field(default_factory=dict)
    receipts: dict[str, Receipt] = field(default_factory=dict)
    receipt_counts: dict[str, int] = field(default_factory=dict)

    # -- lookups -----------------------------------------------------------
    def proofs_for(self, request_id: str) -> list[Proof]:
        return sorted(
            (p for (rid, _), p in self.proofs.items() if rid == request_id),
            key=lambda p: p.proof_id,
        )

    def proof(self, request_id: str, proof_id: str) -> Proof | None:
        return self.proofs.get((request_id, proof_id))

    def policy(self, version: int) -> Policy | None:
        return self.policies.get(version)

    def current_policy(self, request: RequestState) -> Policy | None:
        return self.policies.get(request.policy_version)

    # -- serialization -----------------------------------------------------
    def describe_request(self, request_id: str) -> dict[str, Any]:
        request = self.requests[request_id]
        return request.to_json(self)


def stage_entry_digest(
    *,
    stage: int,
    challenge_id: str,
    generation: str,
    policy_version: int,
    recipe_id: str,
    proof_ids: tuple[str, ...],
) -> str:
    return digest(
        {
            "kind": "stage-entry",
            "stage": stage,
            "challenge_id": challenge_id,
            "generation": generation,
            "policy_version": policy_version,
            "recipe_id": recipe_id,
            "proof_ids": list(proof_ids),
        }
    )


def migration_receipt_digest(
    *,
    request_id: str,
    step: int,
    token_id: str,
    from_generation: str,
    to_generation: str,
    from_org: str,
    to_org: str,
    resource: str,
    op_version: int,
    policy_version: int,
    predecessor: str | None,
) -> str:
    return digest(
        {
            "kind": "migration",
            "request_id": request_id,
            "step": step,
            "token_id": token_id,
            "from_generation": from_generation,
            "to_generation": to_generation,
            "from_org": from_org,
            "to_org": to_org,
            "resource": resource,
            "op_version": op_version,
            "policy_version": policy_version,
            "predecessor": predecessor,
        }
    )


def migration_receipt_id(d: str) -> str:
    return "mig-" + d.split(":", 1)[-1][:24]


def receipt_digest(payload: dict[str, Any]) -> str:
    """Recompute a receipt digest from its payload (id included, digest not)."""
    return digest({k: v for k, v in payload.items() if k != "digest"})


def make_receipt(
    *,
    request: RequestState,
    policy: Policy,
    number: int,
    stage1: StageEntry,
    stage2: StageEntry | None,
    migrations: list[MigrationRecord],
    now: int,
    batch_no: int,
) -> Receipt:
    body: dict[str, Any] = {
        "schema": "challenge-ledger/v1",
        "kind": "issuance",
        "request_id": request.request_id,
        "subject_id": request.subject_id,
        "org": request.org,
        "resource": request.resource,
        "operation": request.operation,
        "op_version": request.op_version,
        "risk": request.risk,
        "generation": request.generation,
        "policy_version": policy.version,
        "policy_fingerprint": policy.fingerprint(),
        "challenge_id": request.challenge_id,
        "number": number,
        "issued_at": now,
        "valid_until": request.expires_at,
        "stage1": {
            "recipe_id": stage1.recipe_id,
            "proof_ids": list(stage1.proof_ids),
            "generation": stage1.generation,
            "entry_digest": stage1.digest,
        },
        "stage2": (
            {
                "recipe_id": stage2.recipe_id,
                "proof_ids": list(stage2.proof_ids),
                "generation": stage2.generation,
                "entry_digest": stage2.digest,
            }
            if stage2 is not None
            else None
        ),
        "migrations": [
            {
                "step": m.step,
                "receipt_id": m.receipt_id,
                "digest": m.digest,
                "from_generation": m.from_generation,
                "to_generation": m.to_generation,
                "from_org": m.from_org,
                "to_org": m.to_org,
            }
            for m in migrations
        ],
    }
    body["digest"] = digest(body)
    receipt_id = "rcpt-" + body["digest"].split(":", 1)[-1][:24]
    body["receipt_id"] = receipt_id
    # Re-digest including the identifier so the value covers every field.
    body["digest"] = digest({k: v for k, v in body.items() if k != "digest"})
    return Receipt(
        receipt_id=receipt_id,
        request_id=request.request_id,
        subject_id=request.subject_id,
        number=number,
        payload=body,
        batch_no=batch_no,
    )
