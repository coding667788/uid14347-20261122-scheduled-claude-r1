"""Event handlers and the two-stage state machine.

Every handler is a pure function of ``(state, event)``.  It mutates the
in-memory state and returns a JSON-able result.  The same functions fold
committed history during ``explain``, so a historical view is exactly what the
engine saw at commit time.

Three invariants the tests lean on:

1. **Consumption is irreversible.**  A proof consumed by any stage entry stays
   consumed forever, across migrations, rollbacks and policy upgrades.
2. **Issuance is final.**  Once a receipt exists, nothing may rewrite it; later
   revocations are recorded as post-issue changes only.
3. **Bindings are per-step.**  A migration token names one challenge, one
   generation step and one predecessor digest, and is consumed exactly once.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .canonical import digest, short_id
from .errors import (
    CaseError,
    E_BINDING_MISMATCH,
    E_CHALLENGE_CLOSED,
    E_CHALLENGE_EXPIRED,
    E_CHALLENGE_NOT_FOUND,
    E_INJECTED_FAULT,
    E_INTERNAL,
    E_MIGRATION_AFTER_ISSUE,
    E_MIGRATION_LIMIT,
    E_POLICY_CONFLICT,
    E_POLICY_NOT_FOUND,
    E_PRESERVE_PRECONDITION,
    E_PROOF_ALREADY_CONSUMED,
    E_PROOF_CHALLENGE_MISMATCH,
    E_PROOF_EXISTS,
    E_PROOF_GENERATION_MISMATCH,
    E_PROOF_NOT_FOUND,
    E_PROOF_REVOKED,
    E_PROOF_STAGE_MISMATCH,
    E_REQUEST_EXISTS,
    E_REQUEST_ISSUED,
    E_REQUEST_NOT_FOUND,
    E_REQUEST_REVOKED,
    E_RISK_DOWNGRADE,
    E_RISK_UNCHANGED,
    E_SCHEMA_CONFLICT,
    E_SCHEMA_ENUM,
    E_SCHEMA_MISSING,
    E_SCHEMA_TYPE,
    E_STAGE1_NOT_COMPLETE,
    E_STAGE1_NOT_SATISFIED,
    E_STAGE2_NOT_SATISFIED,
    E_TIME_REGRESSION,
    E_TOKEN_ALREADY_CONSUMED,
    E_TOKEN_CHALLENGE_MISMATCH,
    E_TOKEN_CONFLICT,
    E_TOKEN_EXPIRED,
    E_TOKEN_GENERATION_MISMATCH,
    E_TOKEN_NOT_FOUND,
    E_TOKEN_POLICY_MISMATCH,
    E_TOKEN_PREDECESSOR_MISMATCH,
    E_TOKEN_REUSED_GENERATION,
    E_TOKEN_RESOURCE_MISMATCH,
    E_TOKEN_UNTRUSTED,
)
from .model import (
    STATUS_COLLECTING,
    STATUS_ISSUED,
    STATUS_REVOKED,
    STATUS_STAGE1,
    STATUS_STAGE2,
    Challenge,
    Invalidation,
    LedgerState,
    MigrationRecord,
    Proof,
    Receipt,
    RequestState,
    StageEntry,
    make_receipt,
    migration_receipt_digest,
    migration_receipt_id,
    stage_entry_digest,
)
from .policy import Policy, ProofView, StageEvaluation, evaluate_stage, parse_policy
from .schema import (
    FACTOR_KINDS,
    RISK_LEVELS,
    expect_bool,
    expect_enum,
    expect_id,
    expect_int,
    expect_object,
    expect_str,
    join,
)

EVENT_TYPES = (
    "register",
    "define_policy",
    "adopt_policy",
    "submit_proof",
    "advance",
    "issue_migration_token",
    "migrate",
    "upgrade_risk",
    "revoke_proof",
    "revoke_request",
    "fault",
)

DEFAULT_TTL = 600
DEFAULT_MAX_STEPS = 8


@dataclass
class EventContext:
    batch_no: int
    index: int
    path: str


# --------------------------------------------------------------------------
# Accessors with locatable errors
# --------------------------------------------------------------------------


def _fail(code: str, path: str, message: str, *, detail: Any = None) -> CaseError:
    return CaseError(code, path, message, detail=detail)


def _req(event: dict[str, Any], path: str, state: LedgerState) -> RequestState:
    if "request_id" not in event:
        raise CaseError(E_SCHEMA_MISSING, join(path, "request_id"), "required field is missing")
    request_id = expect_id(event["request_id"], join(path, "request_id"))
    request = state.requests.get(request_id)
    if request is None:
        raise CaseError(E_REQUEST_NOT_FOUND, join(path, "request_id"), f"unknown request {request_id!r}")
    return request


def _field(event: dict[str, Any], key: str, path: str, default: Any = ...) -> Any:
    if key not in event:
        if default is ...:
            raise CaseError(E_SCHEMA_MISSING, join(path, key), "required field is missing")
        return default
    return event[key]


def _get_id(event: dict[str, Any], key: str, path: str) -> str:
    return expect_id(_field(event, key, path), join(path, key))


def _opt_id(event: dict[str, Any], key: str, path: str) -> str | None:
    if key not in event or event[key] is None:
        return None
    return expect_id(event[key], join(path, key))


def _opt_int(event: dict[str, Any], key: str, path: str, *, minimum: int = 0) -> int | None:
    if key not in event or event[key] is None:
        return None
    return expect_int(event[key], join(path, key), minimum=minimum)


def _now_of(event: dict[str, Any], path: str, request: RequestState | None) -> int:
    base = request.last_now if request is not None else 0
    now = expect_int(event.get("now", base), join(path, "now"), minimum=0)
    if request is not None and now < request.last_now:
        raise CaseError(
            E_TIME_REGRESSION,
            join(path, "now"),
            f"now {now} is earlier than this request's last logical time {request.last_now}",
        )
    return now


def _touch(request: RequestState, now: int, batch_no: int) -> None:
    request.last_now = max(request.last_now, now)
    request.last_batch = batch_no


def _challenge(state: LedgerState, challenge_id: str | None) -> Challenge | None:
    return None if challenge_id is None else state.challenges.get(challenge_id)


def _current_challenge(state: LedgerState, request: RequestState) -> Challenge | None:
    """The challenge a new proof or token must bind right now."""
    if request.stage2_challenge_id is not None:
        return state.challenges.get(request.stage2_challenge_id)
    return state.challenges.get(request.stage1_challenge_id)


def _close_stage(state: LedgerState, request: RequestState, stage: int) -> None:
    for challenge in state.challenges.values():
        if challenge.request_id == request.request_id and challenge.stage == stage:
            challenge.open = False


def _close_stale_generations(state: LedgerState, request: RequestState, generation: str) -> None:
    for challenge in state.challenges.values():
        if challenge.request_id == request.request_id and challenge.generation != generation:
            challenge.open = False


def _new_challenge(
    state: LedgerState,
    request: RequestState,
    *,
    stage: int,
    generation: str,
    policy_version: int,
    now: int,
    batch_no: int,
    ttl: int | None = None,
    explicit_id: str | None = None,
) -> Challenge:
    _close_stage(state, request, stage)
    attempt = 1 + sum(
        1 for c in state.challenges.values() if c.request_id == request.request_id and c.stage == stage
    )
    challenge_id = explicit_id or short_id(
        "chl-",
        {
            "request": request.request_id,
            "stage": stage,
            "generation": generation,
            "policy": policy_version,
            "attempt": attempt,
        },
        20,
    )
    if challenge_id in state.challenges:
        raise CaseError(E_REQUEST_EXISTS, "challenge_id", f"challenge {challenge_id!r} already exists")
    expiry = now + (DEFAULT_TTL if ttl is None else ttl)
    if request.expires_at is None:
        request.expires_at = expiry
    challenge = Challenge(
        challenge_id=challenge_id,
        request_id=request.request_id,
        stage=stage,
        generation=generation,
        resource=request.resource,
        operation=request.operation,
        op_version=request.op_version,
        risk=request.risk,
        policy_version=policy_version,
        expires_at=expiry,
        factors=(("device", "human") if stage == 1 else ("human",)),
        batch_no=batch_no,
        open=True,
    )
    state.challenges[challenge_id] = challenge
    if stage == 1:
        request.stage1_challenge_id = challenge_id
    else:
        request.stage2_challenge_id = challenge_id
    return challenge


# --------------------------------------------------------------------------
# Adjudication glue
# --------------------------------------------------------------------------


def proof_view(proof: Proof, state: LedgerState) -> ProofView:
    challenge = state.challenges.get(proof.challenge_id)
    effective = proof.expires_at
    if challenge is not None:
        effective = min(effective, challenge.expires_at)
    return ProofView(
        proof_id=proof.proof_id,
        stage=proof.stage,
        factor=proof.factor,
        principal=proof.principal,
        trust_group=proof.trust_group,
        trusted=proof.trusted,
        expires_at=effective,
        status=proof.status,
        consumed=proof.consumed_by is not None,
        generation=proof.generation,
        challenge_id=proof.challenge_id,
    )


def adjudicate(
    state: LedgerState,
    request: RequestState,
    stage: int,
    *,
    now: int,
    retained_ids: Iterable[str] = (),
    generation: str | None = None,
) -> StageEvaluation:
    policy = state.policy(request.policy_version)
    if policy is None:
        raise CaseError(
            E_POLICY_NOT_FOUND,
            "request.policy_version",
            f"policy version {request.policy_version} is not registered",
        )
    views = [proof_view(p, state) for p in state.proofs_for(request.request_id)]
    return evaluate_stage(
        policy,
        stage,
        views,
        now=now,
        generation=request.generation if generation is None else generation,
        retained_ids=retained_ids,
    )


def _consume(
    state: LedgerState,
    request: RequestState,
    proof_ids: Iterable[str],
    *,
    stage: int,
    batch_no: int,
) -> None:
    for proof_id in proof_ids:
        proof = state.proof(request.request_id, proof_id)
        if proof is None:  # pragma: no cover - guarded by adjudication
            raise CaseError(E_INTERNAL, "proofs", f"adjudication selected unknown proof {proof_id!r}")
        if proof.consumed_by is not None:
            continue  # retained: already paid for
        proof.consumed_by = f"stage{stage}"
        proof.consumed_batch = batch_no


def _entry(
    request: RequestState,
    evaluation: StageEvaluation,
    *,
    stage: int,
    generation: str,
    batch_no: int,
    challenge_id: str,
    retained: bool,
) -> StageEntry:
    proof_ids = tuple(evaluation.proof_ids)
    recipe_id = str(evaluation.recipe_id)
    return StageEntry(
        stage=stage,
        challenge_id=challenge_id,
        generation=generation,
        policy_version=evaluation.policy_version,
        recipe_id=recipe_id,
        proof_ids=proof_ids,
        digest=stage_entry_digest(
            stage=stage,
            challenge_id=challenge_id,
            generation=generation,
            policy_version=evaluation.policy_version,
            recipe_id=recipe_id,
            proof_ids=proof_ids,
        ),
        resource=request.resource,
        op_version=request.op_version,
        risk=request.risk,
        batch_no=batch_no,
        retained=retained,
    )


def _invalidate(
    request: RequestState,
    stage: int,
    reason: str,
    detail: dict[str, Any],
    *,
    batch_no: int,
) -> StageEntry | None:
    entry = request.stage1 if stage == 1 else request.stage2
    if entry is None or not entry.valid:
        return None
    entry.valid = False
    entry.invalid_reason = reason
    entry.invalid_batch = batch_no
    request.invalidations.append(Invalidation(stage=stage, reason=reason, detail=detail, batch_no=batch_no))
    return entry


def _roll_back_to_stage1(
    state: LedgerState,
    request: RequestState,
    *,
    reason: str,
    detail: dict[str, Any],
    now: int,
    batch_no: int,
    next_challenge: str | None = None,
) -> dict[str, Any]:
    """Return to the first unmet stage, keeping every past consumption."""
    invalidated = _invalidate(request, 1, reason, detail, batch_no=batch_no)
    if request.stage2 is not None and request.stage2.valid:
        _invalidate(request, 2, "upstream_rollback", {"cause": reason}, batch_no=batch_no)
    request.stage2_challenge_id = None
    request.status = STATUS_COLLECTING
    if invalidated is not None:
        _new_challenge(
            state,
            request,
            stage=1,
            generation=request.generation,
            policy_version=request.policy_version,
            now=now,
            batch_no=batch_no,
            explicit_id=next_challenge,
        )
    return {
        "type": "advance",
        "request_id": request.request_id,
        "stage": 1,
        "outcome": "rolled_back",
        "rolled_back_to_stage": 1,
        "reason": reason,
        "invalidated_stage1_digest": invalidated.digest if invalidated else None,
        "failures": list(detail.get("failures", [])),
        "challenge_id": request.stage1_challenge_id,
        "detail": detail,
    }


# --------------------------------------------------------------------------
# Envelope
# --------------------------------------------------------------------------


def _check_event_envelope(event: Any, path: str) -> None:
    if not isinstance(event, dict):
        raise CaseError(E_SCHEMA_TYPE, path, "event must be a JSON object")
    if "event_id" not in event:
        raise CaseError(E_SCHEMA_MISSING, join(path, "event_id"), "required field is missing")
    expect_id(event["event_id"], join(path, "event_id"))
    if "type" not in event:
        raise CaseError(E_SCHEMA_MISSING, join(path, "type"), "required field is missing")
    kind = event["type"]
    if not isinstance(kind, str):
        raise CaseError(E_SCHEMA_TYPE, join(path, "type"), "expected a string")
    if kind not in EVENT_TYPES:
        raise CaseError(E_SCHEMA_ENUM, join(path, "type"), f"expected one of {list(EVENT_TYPES)}")


# --------------------------------------------------------------------------
# Handlers
# --------------------------------------------------------------------------


def _on_register(state: LedgerState, event: dict[str, Any], ctx: EventContext) -> dict[str, Any]:
    path = ctx.path
    request_id = _get_id(event, "request_id", path)
    if request_id in state.requests:
        raise CaseError(E_REQUEST_EXISTS, join(path, "request_id"), f"request {request_id!r} already exists")
    subject_id = _get_id(event, "subject_id", path)
    org = _get_id(event, "org", path)
    resource = expect_str(_field(event, "resource", path), join(path, "resource"))
    operation = _get_id(event, "operation", path)
    op_version = expect_int(_field(event, "op_version", path), join(path, "op_version"), minimum=1)
    risk = expect_enum(_field(event, "risk", path), join(path, "risk"), RISK_LEVELS)
    policy_version = expect_int(_field(event, "policy_version", path), join(path, "policy_version"), minimum=1)
    generation = _get_id(event, "generation", path)
    now = expect_int(event.get("now", 0), join(path, "now"), minimum=0)
    ttl = expect_int(event.get("ttl", DEFAULT_TTL), join(path, "ttl"), minimum=1, maximum=1_000_000)
    if state.policy(policy_version) is None:
        raise CaseError(
            E_POLICY_NOT_FOUND,
            join(path, "policy_version"),
            f"policy version {policy_version} is not registered",
        )

    request = RequestState(
        request_id=request_id,
        subject_id=subject_id,
        org=org,
        resource=resource,
        operation=operation,
        op_version=op_version,
        risk=risk,
        generation=generation,
        policy_version=policy_version,
        expires_at=now + ttl,
        status=STATUS_COLLECTING,
        stage1_challenge_id="",
        created_batch=ctx.batch_no,
        last_now=now,
        used_generations=[generation],
    )
    state.requests[request_id] = request
    challenge = _new_challenge(
        state,
        request,
        stage=1,
        generation=generation,
        policy_version=policy_version,
        now=now,
        batch_no=ctx.batch_no,
        ttl=ttl,
        explicit_id=_opt_id(event, "challenge_id", path),
    )
    _touch(request, now, ctx.batch_no)
    return {
        "type": "register",
        "request_id": request_id,
        "subject_id": subject_id,
        "status": STATUS_COLLECTING,
        "risk": risk,
        "policy_version": policy_version,
        "generation": generation,
        "challenge_id": challenge.challenge_id,
        "expires_at": request.expires_at,
        "now": now,
    }


def _on_define_policy(state: LedgerState, event: dict[str, Any], ctx: EventContext) -> dict[str, Any]:
    path = ctx.path
    # A policy supplied through the case's ``policies`` array is the element
    # itself, so its path carries no extra ``.policy`` segment.  A policy
    # supplied by a standalone event lives at ``events[i].policy``.
    inline = bool(event.get("@inline"))
    policy_path = path if inline else join(path, "policy")
    policy = parse_policy(_field(event, "policy", path), policy_path)
    return _register_policy(state, policy, path=policy_path)


def _register_policy(state: LedgerState, policy: Policy, *, path: str) -> dict[str, Any]:
    fingerprint = policy.fingerprint()
    existing = state.policy_fingerprints.get(policy.version)
    if existing is not None and existing != fingerprint:
        raise CaseError(
            E_POLICY_CONFLICT,
            join(path, "version"),
            f"policy version {policy.version} is already registered with different content",
        )
    state.policies[policy.version] = policy
    state.policy_fingerprints[policy.version] = fingerprint
    return {
        "type": "define_policy",
        "policy_version": policy.version,
        "fingerprint": fingerprint,
        "recipes": len(policy.recipes),
        "already_present": existing is not None,
    }


def _on_adopt_policy(state: LedgerState, event: dict[str, Any], ctx: EventContext) -> dict[str, Any]:
    path = ctx.path
    request = _req(event, path, state)
    now = _now_of(event, path, request)
    if request.status == STATUS_REVOKED:
        raise CaseError(E_REQUEST_REVOKED, join(path, "request_id"), "request is revoked")
    if request.status == STATUS_ISSUED:
        raise CaseError(E_REQUEST_ISSUED, join(path, "request_id"), "cannot change policy after issuance")
    version = expect_int(_field(event, "policy_version", path), join(path, "policy_version"), minimum=1)
    if state.policy(version) is None:
        raise CaseError(E_POLICY_NOT_FOUND, join(path, "policy_version"), f"policy version {version} is not registered")
    if version < request.policy_version:
        raise CaseError(
            E_TOKEN_POLICY_MISMATCH,
            join(path, "policy_version"),
            f"cannot move from policy {request.policy_version} back to {version}",
        )
    previous = request.policy_version
    request.policy_version = version
    _touch(request, now, ctx.batch_no)
    return {
        "type": "adopt_policy",
        "request_id": request.request_id,
        "previous_policy_version": previous,
        "policy_version": version,
        "now": now,
    }


def _on_submit_proof(state: LedgerState, event: dict[str, Any], ctx: EventContext) -> dict[str, Any]:
    path = ctx.path
    request = _req(event, path, state)
    now = _now_of(event, path, request)
    if request.status == STATUS_REVOKED:
        raise CaseError(E_REQUEST_REVOKED, join(path, "request_id"), "request is revoked")
    if request.status == STATUS_ISSUED:
        raise CaseError(E_REQUEST_ISSUED, join(path, "request_id"), "request is already issued")
    if request.expires_at is not None and now > request.expires_at:
        raise CaseError(E_CHALLENGE_EXPIRED, join(path, "now"), "request has expired")

    proof_id = _get_id(event, "proof_id", path)
    if state.proof(request.request_id, proof_id) is not None:
        raise CaseError(E_PROOF_EXISTS, join(path, "proof_id"), f"proof {proof_id!r} already exists")
    stage = expect_int(_field(event, "stage", path), join(path, "stage"), minimum=1, maximum=2)
    factor = expect_enum(_field(event, "factor", path), join(path, "factor"), FACTOR_KINDS)
    principal = _get_id(event, "principal", path)
    trust_group = _get_id(event, "trust_group", path)
    trusted = expect_bool(event.get("trusted", True), join(path, "trusted"))

    explicit = _opt_id(event, "challenge_id", path)
    if explicit is not None:
        challenge = state.challenges.get(explicit)
        if challenge is None:
            raise CaseError(E_CHALLENGE_NOT_FOUND, join(path, "challenge_id"), f"unknown challenge {explicit!r}")
        if challenge.request_id != request.request_id:
            raise CaseError(
                E_PROOF_CHALLENGE_MISMATCH,
                join(path, "challenge_id"),
                "challenge belongs to a different request",
            )
        challenge_id = explicit
    else:
        challenge = _challenge(
            state, request.stage1_challenge_id if stage == 1 else request.stage2_challenge_id
        )
        if challenge is None:
            raise CaseError(
                E_CHALLENGE_NOT_FOUND,
                join(path, "challenge_id"),
                f"no challenge is open for stage {stage}",
            )
        challenge_id = challenge.challenge_id

    if challenge.stage != stage:
        raise CaseError(
            E_PROOF_STAGE_MISMATCH,
            join(path, "stage"),
            f"challenge {challenge_id!r} is for stage {challenge.stage}",
        )
    if not challenge.open:
        raise CaseError(
            E_CHALLENGE_CLOSED,
            join(path, "challenge_id"),
            "challenge is closed; a proof must bind the current challenge",
        )
    if challenge.generation != request.generation:
        raise CaseError(
            E_PROOF_GENERATION_MISMATCH,
            join(path, "challenge_id"),
            "challenge belongs to a superseded identity generation",
        )
    if challenge.expires_at <= now:
        raise CaseError(E_CHALLENGE_EXPIRED, join(path, "challenge_id"), "challenge has expired")

    generation = _opt_id(event, "generation", path) or challenge.generation
    if generation != challenge.generation:
        # Injecting a stale credential: a proof may never assert a generation
        # other than the one its challenge was issued for.
        raise CaseError(
            E_PROOF_GENERATION_MISMATCH,
            join(path, "generation"),
            f"proof generation {generation!r} does not match challenge generation {challenge.generation!r}",
        )

    requested_expiry = _opt_int(event, "expires_at", path)
    effective_expiry = challenge.expires_at if requested_expiry is None else min(requested_expiry, challenge.expires_at)
    proof = Proof(
        proof_id=proof_id,
        request_id=request.request_id,
        challenge_id=challenge_id,
        stage=stage,
        factor=factor,
        principal=principal,
        trust_group=trust_group,
        trusted=trusted,
        expires_at=min(effective_expiry, request.expires_at or effective_expiry),
        generation=generation,
        batch_no=ctx.batch_no,
        generation_mismatch=generation != request.generation,
    )
    state.proofs[(request.request_id, proof_id)] = proof
    _touch(request, now, ctx.batch_no)
    return {
        "type": "submit_proof",
        "request_id": request.request_id,
        "proof_id": proof_id,
        "challenge_id": challenge_id,
        "stage": stage,
        "factor": factor,
        "principal": principal,
        "trust_group": trust_group,
        "trusted": trusted,
        "generation": generation,
        "expires_at": proof.expires_at,
        "generation_mismatch": proof.generation_mismatch,
        "now": now,
    }


def _require_binding(event: dict[str, Any], path: str, request: RequestState) -> None:
    expect = event.get("expect")
    if expect is None:
        return
    if not isinstance(expect, dict):
        raise CaseError(E_SCHEMA_TYPE, join(path, "expect"), "expected an object")
    actual = {
        "resource": request.resource,
        "op_version": request.op_version,
        "generation": request.generation,
        "risk": request.risk,
        "policy_version": request.policy_version,
        "subject_id": request.subject_id,
    }
    for key, value in expect.items():
        if key not in actual:
            raise CaseError(E_SCHEMA_ENUM, join(join(path, "expect"), key), f"unknown binding key {key!r}")
        if value != actual[key]:
            raise CaseError(
                E_BINDING_MISMATCH,
                join(join(path, "expect"), key),
                f"expected {key}={actual[key]!r} but the caller asserted {value!r}",
            )


def _on_advance(state: LedgerState, event: dict[str, Any], ctx: EventContext) -> dict[str, Any]:
    path = ctx.path
    request = _req(event, path, state)
    now = _now_of(event, path, request)
    if request.status == STATUS_REVOKED:
        raise CaseError(E_REQUEST_REVOKED, join(path, "request_id"), "request is revoked")
    if request.status == STATUS_ISSUED:
        raise CaseError(E_REQUEST_ISSUED, join(path, "request_id"), "request is already issued")
    if request.expires_at is not None and now > request.expires_at:
        raise CaseError(E_CHALLENGE_EXPIRED, join(path, "now"), "request has expired")
    _require_binding(event, path, request)

    stage = expect_int(_field(event, "stage", path), join(path, "stage"), minimum=1, maximum=2)
    # A caller may pin the identifier of the challenge this step opens, which
    # keeps multi-batch examples and tests readable and reproducible.
    next_challenge = _opt_id(event, "next_challenge_id", path)
    if stage == 1:
        return _advance_stage1(
            state, request, now=now, batch_no=ctx.batch_no, path=path, next_challenge=next_challenge
        )
    return _advance_stage2(
        state, request, now=now, batch_no=ctx.batch_no, path=path, next_challenge=next_challenge
    )


def _advance_stage1(
    state: LedgerState,
    request: RequestState,
    *,
    now: int,
    batch_no: int,
    path: str,
    next_challenge: str | None = None,
) -> dict[str, Any]:
    retained = request.stage1.proof_ids if (request.stage1 and request.stage1.valid) else ()
    evaluation = adjudicate(state, request, 1, now=now, retained_ids=retained)
    if not evaluation.satisfied:
        raise _fail(
            E_STAGE1_NOT_SATISFIED,
            join(path, "stage"),
            "stage 1 evidence does not satisfy any recipe under the current policy",
            detail={"failures": evaluation.failures, "excluded": evaluation.excluded},
        )

    unchanged = (
        request.stage1 is not None
        and request.stage1.valid
        and tuple(evaluation.proof_ids) == request.stage1.proof_ids
        and request.stage1.generation == request.generation
    )
    if unchanged:
        entry = request.stage1
    else:
        _consume(state, request, evaluation.consumed_now, stage=1, batch_no=batch_no)
        entry = _entry(
            request,
            evaluation,
            stage=1,
            generation=request.generation,
            batch_no=batch_no,
            challenge_id=request.stage1_challenge_id,
            retained=bool(request.stage1) and not evaluation.consumed_now,
        )
        request.stage1 = entry
    _touch(request, now, batch_no)

    base = {
        "type": "advance",
        "request_id": request.request_id,
        "stage": 1,
        "recipe_id": entry.recipe_id,
        "proof_ids": list(entry.proof_ids),
        "consumed_now": list(evaluation.consumed_now),
        "stage1_digest": entry.digest,
        "now": now,
    }

    if request.risk == "low":
        receipt = _issue(state, request, now=now, batch_no=batch_no, path=path)
        return {**base, "outcome": "issued", "status": STATUS_ISSUED,
                "receipt_id": receipt.receipt_id, "receipt_digest": receipt.digest}

    if unchanged and request.stage2_challenge_id is not None and request.stage2 is None:
        current = _challenge(state, request.stage2_challenge_id)
        if current is not None and current.open:
            return {
                **base,
                "outcome": "stage1_complete",
                "status": STATUS_STAGE1,
                "stage2_challenge_id": current.challenge_id,
            }

    _close_stage(state, request, 1)
    request.status = STATUS_STAGE1
    request.stage2_challenge_id = None
    challenge = _new_challenge(
        state,
        request,
        stage=2,
        generation=request.generation,
        policy_version=request.policy_version,
        now=now,
        batch_no=batch_no,
        explicit_id=next_challenge,
    )
    return {
        **base,
        "outcome": "stage1_complete",
        "status": STATUS_STAGE1,
        "stage2_challenge_id": challenge.challenge_id,
    }


def _advance_stage2(
    state: LedgerState,
    request: RequestState,
    *,
    now: int,
    batch_no: int,
    path: str,
    next_challenge: str | None = None,
) -> dict[str, Any]:
    if request.stage1 is None or not request.stage1.valid:
        raise _fail(
            E_STAGE1_NOT_COMPLETE,
            join(path, "stage"),
            "stage 2 requires a completed stage 1",
        )

    # Re-adjudicate stage 1 under the *current* policy.  The entry is judged
    # against the generation it was actually completed under: preservation is
    # exactly the permission to carry those consumed facts across the boundary.
    # Retained proofs cost nothing extra, but they are never grandfathered past
    # a stricter recipe -- if the new policy demands more, this fails.
    stage1_eval = adjudicate(
        state,
        request,
        1,
        now=now,
        retained_ids=request.stage1.proof_ids,
        generation=request.stage1.generation,
    )
    if not stage1_eval.satisfied:
        reason = (
            "policy_upgrade"
            if stage1_eval.policy_version != request.stage1.policy_version
            else "evidence_invalid"
        )
        return _roll_back_to_stage1(
            state,
            request,
            reason=reason,
            detail={
                "policy_version_before": request.stage1.policy_version,
                "policy_version_now": request.policy_version,
                "recipe_id_before": request.stage1.recipe_id,
                "failures": stage1_eval.failures,
                "excluded": stage1_eval.excluded,
            },
            now=now,
            batch_no=batch_no,
            next_challenge=next_challenge,
        )

    stage1_revised = False
    if tuple(stage1_eval.proof_ids) != request.stage1.proof_ids:
        _consume(state, request, stage1_eval.consumed_now, stage=1, batch_no=batch_no)
        request.stage1 = _entry(
            request,
            stage1_eval,
            stage=1,
            generation=request.stage1.generation,
            batch_no=batch_no,
            challenge_id=request.stage1.challenge_id,
            retained=True,
        )
        stage1_revised = True

    stage2_eval = adjudicate(
        state,
        request,
        2,
        now=now,
        retained_ids=request.stage2.proof_ids if (request.stage2 and request.stage2.valid) else (),
    )
    if not stage2_eval.satisfied:
        raise _fail(
            E_STAGE2_NOT_SATISFIED,
            join(path, "stage"),
            "stage 2 evidence does not satisfy any recipe under the current policy",
            detail={"failures": stage2_eval.failures, "excluded": stage2_eval.excluded},
        )

    _consume(state, request, stage2_eval.consumed_now, stage=2, batch_no=batch_no)
    stage2_entry = _entry(
        request,
        stage2_eval,
        stage=2,
        generation=request.generation,
        batch_no=batch_no,
        challenge_id=request.stage2_challenge_id or "",
        retained=False,
    )
    request.stage2 = stage2_entry
    request.status = STATUS_STAGE2
    _touch(request, now, batch_no)
    receipt = _issue(state, request, now=now, batch_no=batch_no, path=path)
    return {
        "type": "advance",
        "request_id": request.request_id,
        "stage": 2,
        "outcome": "issued",
        "status": STATUS_ISSUED,
        "recipe_id": stage2_entry.recipe_id,
        "proof_ids": list(stage2_entry.proof_ids),
        "consumed_now": list(stage2_eval.consumed_now),
        "stage1_digest": request.stage1.digest,
        "stage2_digest": stage2_entry.digest,
        "stage1_revised": stage1_revised,
        "receipt_id": receipt.receipt_id,
        "receipt_digest": receipt.digest,
        "now": now,
    }


def _issue(
    state: LedgerState,
    request: RequestState,
    *,
    now: int,
    batch_no: int,
    path: str,
) -> Receipt:
    """Final checks plus a unique receipt, inside the caller's transaction."""
    if request.status in (STATUS_ISSUED, STATUS_REVOKED):
        raise CaseError(E_REQUEST_ISSUED, join(path, "request_id"), "request cannot be issued again")
    if request.stage1 is None or not request.stage1.valid:
        raise CaseError(E_STAGE1_NOT_COMPLETE, join(path, "stage"), "stage 1 is not complete")
    if request.risk == "high":
        if request.stage2 is None or not request.stage2.valid:
            raise CaseError(E_STAGE1_NOT_COMPLETE, join(path, "stage"), "high risk requires stage 2")
        if request.stage2.generation != request.generation:
            raise CaseError(
                E_BINDING_MISMATCH,
                join(path, "stage"),
                "stage 2 evidence is bound to a superseded generation",
            )
    for entry in (request.stage1, request.stage2):
        if entry is None or not entry.valid:
            continue
        if entry.resource != request.resource or entry.op_version != request.op_version:
            raise CaseError(
                E_BINDING_MISMATCH,
                join(path, "stage"),
                "stage entry no longer matches the request's resource or operation version",
            )
        for proof_id in entry.proof_ids:
            proof = state.proof(request.request_id, proof_id)
            if proof is None or proof.status != "active":
                raise CaseError(
                    E_PROOF_REVOKED,
                    join(path, "stage"),
                    f"proof {proof_id!r} was revoked before issuance",
                )
    policy = state.policy(request.policy_version)
    if policy is None:
        raise CaseError(E_POLICY_NOT_FOUND, join(path, "stage"), "adopted policy version is missing")

    number = state.receipt_counts.get(request.subject_id, 0) + 1
    state.receipt_counts[request.subject_id] = number
    receipt = make_receipt(
        request=request,
        policy=policy,
        number=number,
        stage1=request.stage1,
        stage2=request.stage2 if request.risk == "high" else None,
        migrations=request.migrations,
        now=now,
        batch_no=batch_no,
    )
    request.receipt_id = receipt.receipt_id
    request.status = STATUS_ISSUED
    state.receipts[receipt.receipt_id] = receipt
    return receipt


def _on_upgrade_risk(state: LedgerState, event: dict[str, Any], ctx: EventContext) -> dict[str, Any]:
    path = ctx.path
    request = _req(event, path, state)
    now = _now_of(event, path, request)
    if request.status == STATUS_REVOKED:
        raise CaseError(E_REQUEST_REVOKED, join(path, "request_id"), "request is revoked")
    if request.status == STATUS_ISSUED:
        raise CaseError(E_REQUEST_ISSUED, join(path, "request_id"), "cannot change risk after issuance")
    target = expect_enum(_field(event, "risk", path), join(path, "risk"), RISK_LEVELS)
    if target == request.risk:
        raise CaseError(E_RISK_UNCHANGED, join(path, "risk"), f"risk is already {target!r}")
    if target == "low":
        raise CaseError(E_RISK_DOWNGRADE, join(path, "risk"), "risk may only be upgraded")

    next_challenge = _opt_id(event, "next_challenge_id", path)
    previous = request.risk
    if request.stage1 is not None and request.stage1.valid:
        _invalidate(request, 1, "risk_upgrade", {"from": previous, "to": target}, batch_no=ctx.batch_no)
        if request.stage2 is not None and request.stage2.valid:
            _invalidate(request, 2, "risk_upgrade", {"from": previous, "to": target}, batch_no=ctx.batch_no)
        request.stage2_challenge_id = None
        request.status = STATUS_COLLECTING
    request.risk = target
    _close_stage(state, request, 1)
    _new_challenge(
        state,
        request,
        stage=1,
        generation=request.generation,
        policy_version=request.policy_version,
        now=now,
        batch_no=ctx.batch_no,
        explicit_id=next_challenge,
    )
    _touch(request, now, ctx.batch_no)
    return {
        "type": "upgrade_risk",
        "request_id": request.request_id,
        "previous_risk": previous,
        "risk": target,
        "status": request.status,
        "stage1_invalidated": request.status == STATUS_COLLECTING,
        "challenge_id": request.stage1_challenge_id,
        "now": now,
    }


def _on_revoke_proof(state: LedgerState, event: dict[str, Any], ctx: EventContext) -> dict[str, Any]:
    path = ctx.path
    request = _req(event, path, state)
    now = _now_of(event, path, request)
    proof_id = _get_id(event, "proof_id", path)
    reason = expect_str(event.get("reason", "unspecified"), join(path, "reason"))
    proof = state.proof(request.request_id, proof_id)
    if proof is None:
        raise CaseError(E_PROOF_NOT_FOUND, join(path, "proof_id"), f"unknown proof {proof_id!r}")
    if proof.status == "revoked":
        raise CaseError(E_PROOF_REVOKED, join(path, "proof_id"), "proof is already revoked")
    proof.status = "revoked"
    proof.revoked_reason = reason
    _touch(request, now, ctx.batch_no)

    outcome: dict[str, Any] = {
        "type": "revoke_proof",
        "request_id": request.request_id,
        "proof_id": proof_id,
        "reason": reason,
        "consumed_by": proof.consumed_by,
        "post_issue": request.status == STATUS_ISSUED,
        "now": now,
    }
    if request.status == STATUS_ISSUED:
        # Issued receipts are immutable; record the change separately.
        request.post_issue_changes.append(
            {"kind": "proof_revoked", "proof_id": proof_id, "reason": reason, "batch_no": ctx.batch_no}
        )
        outcome["effect"] = "recorded_post_issue"
        return outcome

    if proof.consumed_by is not None:
        stage = 1 if proof.consumed_by == "stage1" else 2
        entry = request.stage1 if stage == 1 else request.stage2
        if entry is not None and entry.valid and proof_id in entry.proof_ids:
            if stage == 1 and request.stage1 is not None and request.stage1.valid:
                outcome["rollback"] = _roll_back_to_stage1(
                    state,
                    request,
                    reason="evidence_revoked",
                    detail={"proof_id": proof_id, "stage": stage},
                    now=now,
                    batch_no=ctx.batch_no,
                )
            else:
                _invalidate(request, stage, "evidence_revoked", {"proof_id": proof_id}, batch_no=ctx.batch_no)
                outcome["invalidated_stage"] = stage
                if stage == 2:
                    request.status = STATUS_STAGE1
                    _close_stage(state, request, 2)
                    request.stage2_challenge_id = None
                    challenge = _new_challenge(
                        state,
                        request,
                        stage=2,
                        generation=request.generation,
                        policy_version=request.policy_version,
                        now=now,
                        batch_no=ctx.batch_no,
                    )
                    outcome["challenge_id"] = challenge.challenge_id
    return outcome


def _on_revoke_request(state: LedgerState, event: dict[str, Any], ctx: EventContext) -> dict[str, Any]:
    path = ctx.path
    request = _req(event, path, state)
    now = _now_of(event, path, request)
    if request.status == STATUS_REVOKED:
        raise CaseError(E_REQUEST_REVOKED, join(path, "request_id"), "request is already revoked")
    reason = expect_str(event.get("reason", "unspecified"), join(path, "reason"))
    request.status = STATUS_REVOKED
    request.revoked_reason = reason
    for challenge in state.challenges.values():
        if challenge.request_id == request.request_id:
            challenge.open = False
    _touch(request, now, ctx.batch_no)
    return {
        "type": "revoke_request",
        "request_id": request.request_id,
        "status": STATUS_REVOKED,
        "reason": reason,
        "receipt_kept": request.receipt_id,
        "now": now,
    }


def _parse_predecessor(raw: Any, path: str) -> Any:
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise CaseError(E_SCHEMA_TYPE, path, "predecessor must be null, a step number, or a digest")
    if isinstance(raw, int):
        if raw < 1:
            raise CaseError(E_SCHEMA_ENUM, path, "predecessor step must be at least 1")
        return {"step": raw}
    if isinstance(raw, str):
        if raw.startswith("sha256:") and len(raw) == 71:
            return raw
        raise CaseError(E_SCHEMA_ENUM, path, "predecessor digest must look like sha256:<64 hex>")
    raise CaseError(E_SCHEMA_TYPE, path, "predecessor must be null, a step number, or a digest")


def _resolve_predecessor(request: RequestState, predecessor: Any) -> str | None:
    """Resolve a token's predecessor reference against the current chain.

    Returns the digest the token claims, or raises when the reference cannot
    name the chain's current tip.  ``None`` is a real value (the chain head),
    so an unresolvable step must not be confused with it.
    """
    if predecessor is None:
        return None
    if isinstance(predecessor, str):
        return predecessor
    step = int(predecessor["step"])
    for record in request.migrations:
        if record.step == step:
            return record.digest
    raise CaseError(
        E_TOKEN_PREDECESSOR_MISMATCH,
        "predecessor",
        f"predecessor step {step} has not been migrated yet in this chain",
    )


def _on_issue_token(state: LedgerState, event: dict[str, Any], ctx: EventContext) -> dict[str, Any]:
    path = ctx.path
    request = _req(event, path, state)
    now = _now_of(event, path, request)
    if request.status == STATUS_REVOKED:
        raise CaseError(E_REQUEST_REVOKED, join(path, "request_id"), "request is revoked")
    if request.status == STATUS_ISSUED:
        raise CaseError(E_MIGRATION_AFTER_ISSUE, join(path, "request_id"), "cannot plan a migration after issuance")

    token_id = _get_id(event, "token_id", path)
    if token_id in state.tokens:
        raise CaseError(E_TOKEN_CONFLICT, join(path, "token_id"), f"token {token_id!r} already exists")
    challenge_id = _get_id(event, "challenge_id", path)
    challenge = state.challenges.get(challenge_id)
    if challenge is None or challenge.request_id != request.request_id:
        raise CaseError(E_CHALLENGE_NOT_FOUND, join(path, "challenge_id"), f"unknown challenge {challenge_id!r}")
    current = _current_challenge(state, request)
    if current is None or current.challenge_id != challenge_id or not challenge.open:
        raise CaseError(
            E_TOKEN_CHALLENGE_MISMATCH,
            join(path, "challenge_id"),
            "a migration token must bind the request's current open challenge",
        )

    from_generation = _opt_id(event, "from_generation", path) or request.generation
    if from_generation != request.generation:
        raise CaseError(
            E_TOKEN_GENERATION_MISMATCH,
            join(path, "from_generation"),
            f"token starts at {from_generation!r} but the request is at {request.generation!r}",
        )
    to_generation = _get_id(event, "to_generation", path)
    if to_generation == from_generation:
        raise CaseError(
            E_TOKEN_GENERATION_MISMATCH,
            join(path, "to_generation"),
            "a migration must advance to a different generation",
        )
    if to_generation in request.used_generations:
        raise CaseError(
            E_TOKEN_REUSED_GENERATION,
            join(path, "to_generation"),
            f"generation {to_generation!r} was already used by this request",
        )

    predecessor = _parse_predecessor(event.get("predecessor"), join(path, "predecessor"))
    resolved = _resolve_predecessor(request, predecessor)
    if resolved != request.last_migration_digest:
        raise CaseError(
            E_TOKEN_PREDECESSOR_MISMATCH,
            join(path, "predecessor"),
            "token predecessor must name the request's current last migration receipt",
        )

    to_org = _get_id(event, "to_org", path)
    resource = expect_str(event.get("resource", request.resource), join(path, "resource"))
    op_version = expect_int(
        event.get("op_version", request.op_version), join(path, "op_version"), minimum=1
    )
    risk = expect_enum(event.get("risk", request.risk), join(path, "risk"), RISK_LEVELS)
    if resource != request.resource or op_version != request.op_version:
        raise CaseError(
            E_TOKEN_RESOURCE_MISMATCH,
            join(path, "resource"),
            "a migration token may not change the resource or operation version",
        )
    if risk != request.risk:
        raise CaseError(
            E_TOKEN_RESOURCE_MISMATCH,
            join(path, "risk"),
            "a migration token may not change the risk level",
        )
    policy_version = expect_int(
        event.get("policy_version", request.policy_version), join(path, "policy_version"), minimum=1
    )
    if policy_version != request.policy_version:
        raise CaseError(
            E_TOKEN_POLICY_MISMATCH,
            join(path, "policy_version"),
            f"token policy {policy_version} does not match the adopted policy {request.policy_version}",
        )
    if state.policy(policy_version) is None:
        raise CaseError(E_POLICY_NOT_FOUND, join(path, "policy_version"), "policy version is not registered")

    expires_at = expect_int(event.get("expires_at", now + DEFAULT_TTL), join(path, "expires_at"), minimum=0)
    fingerprint = digest(
        {
            "token_id": token_id,
            "challenge_id": challenge_id,
            "from_generation": from_generation,
            "to_generation": to_generation,
            "to_org": to_org,
            "resource": resource,
            "op_version": op_version,
            "risk": risk,
            "policy_version": policy_version,
            "predecessor": predecessor,
            "expires_at": expires_at,
        }
    )
    state.tokens[token_id] = {
        "token_id": token_id,
        "request_id": request.request_id,
        "challenge_id": challenge_id,
        "from_generation": from_generation,
        "to_generation": to_generation,
        "to_org": to_org,
        "resource": resource,
        "op_version": op_version,
        "risk": risk,
        "policy_version": policy_version,
        "predecessor": predecessor,
        "expires_at": expires_at,
        "trusted": expect_bool(event.get("trusted", True), join(path, "trusted")),
        "consumed": False,
        "consumed_by_batch": None,
        "consumed_at_step": None,
        "fingerprint": fingerprint,
    }
    _touch(request, now, ctx.batch_no)
    return {
        "type": "issue_migration_token",
        "request_id": request.request_id,
        "token_id": token_id,
        "challenge_id": challenge_id,
        "from_generation": from_generation,
        "to_generation": to_generation,
        "to_org": to_org,
        "policy_version": policy_version,
        "predecessor": resolved,
        "expires_at": expires_at,
        "fingerprint": fingerprint,
        "now": now,
    }


def _on_migrate(state: LedgerState, event: dict[str, Any], ctx: EventContext) -> dict[str, Any]:
    path = ctx.path
    request = _req(event, path, state)
    now = _now_of(event, path, request)
    if request.status == STATUS_REVOKED:
        raise CaseError(E_REQUEST_REVOKED, join(path, "request_id"), "request is revoked")
    if request.status == STATUS_ISSUED:
        raise CaseError(E_MIGRATION_AFTER_ISSUE, join(path, "request_id"), "request was already issued")

    max_steps = expect_int(event.get("max_steps", DEFAULT_MAX_STEPS), join(path, "max_steps"), minimum=1)
    if len(request.migrations) >= max_steps:
        raise CaseError(
            E_MIGRATION_LIMIT,
            join(path, "max_steps"),
            f"migration chain limit of {max_steps} reached",
        )

    token_id = _get_id(event, "token_id", path)
    token = state.tokens.get(token_id)
    if token is None or token["request_id"] != request.request_id:
        raise CaseError(E_TOKEN_NOT_FOUND, join(path, "token_id"), f"unknown migration token {token_id!r}")
    if token["consumed"]:
        raise CaseError(
            E_TOKEN_ALREADY_CONSUMED,
            join(path, "token_id"),
            f"token {token_id!r} was consumed by batch {token['consumed_by_batch']}",
        )
    if not token["trusted"]:
        raise CaseError(E_TOKEN_UNTRUSTED, join(path, "token_id"), "migration token is not trusted")
    if token["expires_at"] <= now:
        raise CaseError(E_TOKEN_EXPIRED, join(path, "token_id"), "migration token has expired")

    current = _current_challenge(state, request)
    if current is None or not current.open or token["challenge_id"] != current.challenge_id:
        raise CaseError(
            E_TOKEN_CHALLENGE_MISMATCH,
            join(path, "token_id"),
            "token is bound to a challenge that is no longer current (issuance may have raced it)",
        )
    if token["from_generation"] != request.generation:
        raise CaseError(
            E_TOKEN_GENERATION_MISMATCH,
            join(path, "token_id"),
            f"token starts at {token['from_generation']!r} but the request is at {request.generation!r}",
        )

    to_generation = _get_id(event, "to_generation", path)
    if to_generation != token["to_generation"]:
        raise CaseError(
            E_TOKEN_GENERATION_MISMATCH,
            join(path, "to_generation"),
            "migration target does not match the token",
        )
    if to_generation == request.generation or to_generation in request.used_generations:
        raise CaseError(
            E_TOKEN_SKIPS_GENERATION,
            join(path, "to_generation"),
            "a migration must reach a generation this request has never used",
        )
    to_org = _get_id(event, "to_org", path)
    if to_org != token["to_org"]:
        raise CaseError(E_TOKEN_RESOURCE_MISMATCH, join(path, "to_org"), "organisation does not match the token")
    resource = expect_str(event.get("resource", request.resource), join(path, "resource"))
    if resource != token["resource"] or resource != request.resource:
        raise CaseError(E_TOKEN_RESOURCE_MISMATCH, join(path, "resource"), "resource does not match the token")
    op_version = expect_int(event.get("op_version", request.op_version), join(path, "op_version"), minimum=1)
    if op_version != token["op_version"] or op_version != request.op_version:
        raise CaseError(E_TOKEN_RESOURCE_MISMATCH, join(path, "op_version"), "op_version does not match the token")
    risk = expect_enum(event.get("risk", request.risk), join(path, "risk"), RISK_LEVELS)
    if risk != token["risk"] or risk != request.risk:
        raise CaseError(E_TOKEN_RESOURCE_MISMATCH, join(path, "risk"), "risk does not match the token")
    policy_version = expect_int(
        event.get("policy_version", request.policy_version), join(path, "policy_version"), minimum=1
    )
    if policy_version != token["policy_version"]:
        raise CaseError(E_TOKEN_POLICY_MISMATCH, join(path, "policy_version"), "policy does not match the token")
    if policy_version != request.policy_version:
        raise CaseError(
            E_TOKEN_POLICY_MISMATCH,
            join(path, "policy_version"),
            "migration policy must equal the request's adopted policy",
        )

    if _resolve_predecessor(request, token["predecessor"]) != request.last_migration_digest:
        raise CaseError(
            E_TOKEN_PREDECESSOR_MISMATCH,
            join(path, "token_id"),
            "token predecessor does not match the request's last migration receipt",
        )

    next_challenge = _opt_id(event, "next_challenge_id", path)
    preserve = expect_bool(event.get("preserve_stage1", False), join(path, "preserve_stage1"))
    if preserve:
        if request.stage1 is None or not request.stage1.valid:
            raise CaseError(
                E_PRESERVE_PRECONDITION,
                join(path, "preserve_stage1"),
                "there is no valid stage 1 to preserve",
            )
        if (
            resource != request.resource
            or op_version != request.op_version
            or risk != request.risk
            or request.stage1.resource != resource
            or request.stage1.op_version != op_version
            or request.stage1.risk != risk
        ):
            raise CaseError(
                E_PRESERVE_PRECONDITION,
                join(path, "preserve_stage1"),
                "stage 1 may be preserved only when resource, op_version and risk are unchanged",
            )

    step = len(request.migrations) + 1
    predecessor_digest = request.last_migration_digest
    from_generation = request.generation
    from_org = request.org
    digest_value = migration_receipt_digest(
        request_id=request.request_id,
        step=step,
        token_id=token_id,
        from_generation=from_generation,
        to_generation=to_generation,
        from_org=from_org,
        to_org=to_org,
        resource=resource,
        op_version=op_version,
        policy_version=policy_version,
        predecessor=predecessor_digest,
    )
    record = MigrationRecord(
        step=step,
        token_id=token_id,
        from_generation=from_generation,
        to_generation=to_generation,
        from_org=from_org,
        to_org=to_org,
        resource=resource,
        op_version=op_version,
        policy_version=policy_version,
        predecessor=predecessor_digest,
        receipt_id=migration_receipt_id(digest_value),
        digest=digest_value,
        batch_no=ctx.batch_no,
        preserved_stage1=preserve,
    )
    token["consumed"] = True
    token["consumed_by_batch"] = ctx.batch_no
    token["consumed_at_step"] = step

    request.org = to_org
    request.resource = resource
    request.op_version = op_version
    request.risk = risk
    request.generation = to_generation
    request.used_generations.append(to_generation)
    request.migrations.append(record)
    request.migration_step = step
    request.last_migration_digest = digest_value
    _close_stale_generations(state, request, to_generation)

    outcome: dict[str, Any] = {
        "type": "migrate",
        "request_id": request.request_id,
        "outcome": "migrated",
        "step": step,
        "token_id": token_id,
        "from_generation": from_generation,
        "to_generation": to_generation,
        "from_org": from_org,
        "to_org": to_org,
        "resource": resource,
        "op_version": op_version,
        "risk": risk,
        "policy_version": policy_version,
        "migration_receipt_id": record.receipt_id,
        "migration_digest": digest_value,
        "predecessor": predecessor_digest,
        "preserved_stage1": preserve,
        "now": now,
    }

    # Stage-2 evidence is always bound to the generation that produced it.
    if request.stage2 is not None and request.stage2.valid:
        _invalidate(
            request,
            2,
            "generation_changed",
            {"from": from_generation, "to": to_generation},
            batch_no=ctx.batch_no,
        )
        request.stage2_challenge_id = None

    if request.stage1 is not None and request.stage1.valid:
        if preserve:
            request.stage1.retained = True
            outcome["stage1_state"] = "preserved"
        else:
            _invalidate(
                request,
                1,
                "migration_not_preserved",
                {"step": step, "from": from_generation, "to": to_generation},
                batch_no=ctx.batch_no,
            )
            request.status = STATUS_COLLECTING
            request.stage2_challenge_id = None
            outcome["stage1_state"] = "invalidated"
    else:
        request.status = STATUS_COLLECTING

    target_stage = 2 if (request.status == STATUS_STAGE1 and request.stage1 and request.stage1.valid) else 1
    if request.status == STATUS_COLLECTING:
        target_stage = 1
    _close_stage(state, request, target_stage)
    if target_stage == 1:
        request.stage2_challenge_id = None
    challenge = _new_challenge(
        state,
        request,
        stage=target_stage,
        generation=to_generation,
        policy_version=request.policy_version,
        now=now,
        batch_no=ctx.batch_no,
        explicit_id=next_challenge,
    )
    outcome["challenge_id"] = challenge.challenge_id
    outcome["next_stage"] = target_stage
    outcome["status"] = request.status
    _touch(request, now, ctx.batch_no)
    return outcome


def _on_fault(state: LedgerState, event: dict[str, Any], ctx: EventContext) -> dict[str, Any]:
    path = ctx.path
    point = expect_enum(
        _field(event, "point", path), join(path, "point"), ("at_event", "before_commit", "after_commit")
    )
    return {"type": "fault", "point": point, "__fault__": point, "now": event.get("now")}


HANDLERS = {
    "register": _on_register,
    "define_policy": _on_define_policy,
    "adopt_policy": _on_adopt_policy,
    "submit_proof": _on_submit_proof,
    "advance": _on_advance,
    "issue_migration_token": _on_issue_token,
    "migrate": _on_migrate,
    "upgrade_risk": _on_upgrade_risk,
    "revoke_proof": _on_revoke_proof,
    "revoke_request": _on_revoke_request,
    "fault": _on_fault,
}


STRUCTURAL_CODES = {
    "E_SCHEMA_TYPE",
    "E_SCHEMA_MISSING",
    "E_SCHEMA_ENUM",
    "E_SCHEMA_RANGE",
    "E_SCHEMA_UNKNOWN",
    "E_SCHEMA_DUPLICATE",
    "E_SCHEMA_EMPTY",
    "E_SCHEMA_CONFLICT",
}


def validate_event_structure(event: dict[str, Any], path: str) -> None:
    """Validate every field of *event* that does not need ledger state.

    Running this before any state is touched guarantees a malformed event is
    reported as malformed -- never as "request not found" or "event id taken".
    """
    _check_event_envelope(event, path)
    kind = event["type"]
    validator = STRUCTURAL_VALIDATORS.get(kind)
    if validator is not None:
        validator(event, path)


def _structural_register(event: dict[str, Any], path: str) -> None:
    for key in ("request_id", "subject_id", "org", "operation", "generation"):
        _get_id(event, key, path)
    expect_str(_field(event, "resource", path), join(path, "resource"))
    expect_int(_field(event, "op_version", path), join(path, "op_version"), minimum=1)
    expect_enum(_field(event, "risk", path), join(path, "risk"), RISK_LEVELS)
    expect_int(_field(event, "policy_version", path), join(path, "policy_version"), minimum=1)
    if "now" in event:
        expect_int(event["now"], join(path, "now"), minimum=0)
    if "ttl" in event:
        expect_int(event["ttl"], join(path, "ttl"), minimum=1, maximum=1_000_000)
    if "challenge_id" in event and event["challenge_id"] is not None:
        expect_id(event["challenge_id"], join(path, "challenge_id"))


def _structural_define_policy(event: dict[str, Any], path: str) -> None:
    parse_policy(_field(event, "policy", path), join(path, "policy"))


def _structural_simple_request(event: dict[str, Any], path: str) -> None:
    _get_id(event, "request_id", path)
    if "now" in event:
        expect_int(event["now"], join(path, "now"), minimum=0)


def _structural_adopt_policy(event: dict[str, Any], path: str) -> None:
    _structural_simple_request(event, path)
    expect_int(_field(event, "policy_version", path), join(path, "policy_version"), minimum=1)


def _structural_submit_proof(event: dict[str, Any], path: str) -> None:
    _structural_simple_request(event, path)
    _get_id(event, "proof_id", path)
    expect_int(_field(event, "stage", path), join(path, "stage"), minimum=1, maximum=2)
    expect_enum(_field(event, "factor", path), join(path, "factor"), FACTOR_KINDS)
    _get_id(event, "principal", path)
    _get_id(event, "trust_group", path)
    if "trusted" in event:
        expect_bool(event["trusted"], join(path, "trusted"))
    for key in ("challenge_id", "generation"):
        if key in event and event[key] is not None:
            expect_id(event[key], join(path, key))
    if "expires_at" in event and event["expires_at"] is not None:
        expect_int(event["expires_at"], join(path, "expires_at"), minimum=0)


def _structural_advance(event: dict[str, Any], path: str) -> None:
    _structural_simple_request(event, path)
    expect_int(_field(event, "stage", path), join(path, "stage"), minimum=1, maximum=2)
    if "expect" in event and event["expect"] is not None:
        if not isinstance(event["expect"], dict):
            raise CaseError(E_SCHEMA_TYPE, join(path, "expect"), "expected an object")
    if "next_challenge_id" in event and event["next_challenge_id"] is not None:
        expect_id(event["next_challenge_id"], join(path, "next_challenge_id"))


def _structural_issue_token(event: dict[str, Any], path: str) -> None:
    _structural_simple_request(event, path)
    _get_id(event, "token_id", path)
    _get_id(event, "challenge_id", path)
    _get_id(event, "to_generation", path)
    _get_id(event, "to_org", path)
    for key in ("from_generation",):
        if key in event and event[key] is not None:
            expect_id(event[key], join(path, key))
    for key in ("resource",):
        if key in event:
            expect_str(event[key], join(path, key))
    for key in ("op_version",):
        if key in event:
            expect_int(event[key], join(path, key), minimum=1)
    if "risk" in event:
        expect_enum(event["risk"], join(path, "risk"), RISK_LEVELS)
    if "policy_version" in event:
        expect_int(event["policy_version"], join(path, "policy_version"), minimum=1)
    if "predecessor" in event:
        _parse_predecessor(event["predecessor"], join(path, "predecessor"))
    if "expires_at" in event:
        expect_int(event["expires_at"], join(path, "expires_at"), minimum=0)
    if "trusted" in event:
        expect_bool(event["trusted"], join(path, "trusted"))


def _structural_migrate(event: dict[str, Any], path: str) -> None:
    _structural_simple_request(event, path)
    _get_id(event, "token_id", path)
    _get_id(event, "to_generation", path)
    _get_id(event, "to_org", path)
    if "preserve_stage1" in event:
        expect_bool(event["preserve_stage1"], join(path, "preserve_stage1"))
    if "policy_version" in event:
        expect_int(event["policy_version"], join(path, "policy_version"), minimum=1)
    if "max_steps" in event:
        expect_int(event["max_steps"], join(path, "max_steps"), minimum=1)
    if "next_challenge_id" in event and event["next_challenge_id"] is not None:
        expect_id(event["next_challenge_id"], join(path, "next_challenge_id"))
    for key in ("resource",):
        if key in event:
            expect_str(event[key], join(path, key))
    if "op_version" in event:
        expect_int(event["op_version"], join(path, "op_version"), minimum=1)
    if "risk" in event:
        expect_enum(event["risk"], join(path, "risk"), RISK_LEVELS)


def _structural_upgrade_risk(event: dict[str, Any], path: str) -> None:
    _structural_simple_request(event, path)
    expect_enum(_field(event, "risk", path), join(path, "risk"), RISK_LEVELS)
    if "next_challenge_id" in event and event["next_challenge_id"] is not None:
        expect_id(event["next_challenge_id"], join(path, "next_challenge_id"))


def _structural_revoke_proof(event: dict[str, Any], path: str) -> None:
    _structural_simple_request(event, path)
    _get_id(event, "proof_id", path)
    if "reason" in event:
        expect_str(event["reason"], join(path, "reason"))


def _structural_revoke_request(event: dict[str, Any], path: str) -> None:
    _structural_simple_request(event, path)
    if "reason" in event:
        expect_str(event["reason"], join(path, "reason"))


def _structural_fault(event: dict[str, Any], path: str) -> None:
    expect_enum(
        _field(event, "point", path), join(path, "point"), ("at_event", "before_commit", "after_commit")
    )
    if "now" in event:
        expect_int(event["now"], join(path, "now"), minimum=0)


STRUCTURAL_VALIDATORS = {
    "register": _structural_register,
    "define_policy": _structural_define_policy,
    "adopt_policy": _structural_adopt_policy,
    "submit_proof": _structural_submit_proof,
    "advance": _structural_advance,
    "issue_migration_token": _structural_issue_token,
    "migrate": _structural_migrate,
    "upgrade_risk": _structural_upgrade_risk,
    "revoke_proof": _structural_revoke_proof,
    "revoke_request": _structural_revoke_request,
    "fault": _structural_fault,
}


def apply_event(state: LedgerState, event: dict[str, Any], ctx: EventContext) -> dict[str, Any]:
    _check_event_envelope(event, ctx.path)
    result = HANDLERS[event["type"]](state, event, ctx)
    result["event_id"] = event["event_id"]
    result["index"] = ctx.index
    return result


def blank_state() -> LedgerState:
    return LedgerState()
