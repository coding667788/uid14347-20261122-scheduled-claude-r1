"""Small helpers for building synthetic cases in examples and tests.

All identifiers here are made up.  Nothing calls a network, a clock, or a
random source; logical time is supplied explicitly by each case.
"""

from __future__ import annotations

import copy
from typing import Any

SCHEMA = "challenge-ledger/v1"


def recipe(recipe_id: str, stage: int, **kwargs: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"id": recipe_id, "stage": stage}
    body.update(kwargs)
    return body


def standard_policy(version: int = 1) -> dict[str, Any]:
    """Stage 1 needs two independent factors; stage 2 needs a fresh human."""
    return {
        "version": version,
        "recipes": [
            recipe("s1-two-factor", 1, factors=["device", "human"], distinct_principals=True),
            recipe("s2-confirm", 2, factors=["human"]),
        ],
    }


def strict_policy(version: int) -> dict[str, Any]:
    """A stricter policy: the device must come from the hardware group.

    The v1 stages still pass in name, but a v1 device credential (any trust
    group) no longer satisfies stage 1, so a preserved entry is not enough.
    """
    return {
        "version": version,
        "recipes": [
            recipe(
                "s1-strict",
                1,
                requirements=[
                    {"kind": "device", "count": 1, "trust_groups": ["TG-hardware"]},
                    {"kind": "human", "count": 1},
                ],
                distinct_principals=True,
                distinct_trust_groups=True,
            ),
            recipe("s2-strict", 2, factors=["human"], distinct_trust_groups=True),
        ],
    }


def group_independence_policy(version: int = 1) -> dict[str, Any]:
    """Three devices from three principals but only two trust groups.

    Each device is individually valid and every pair passes the per-factor
    rule, but the required trio is not independent because two share a group.
    """
    return {
        "version": version,
        "recipes": [
            recipe(
                "s1-three-way",
                1,
                requirements=[
                    {"kind": "device", "count": 3, "distinct_principals": True},
                ],
                distinct_trust_groups=True,
            ),
            recipe("s2-confirm", 2, factors=["human"]),
        ],
    }


def case(*events: dict[str, Any], batch_id: str = "", policies: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "batch_id": batch_id,
        "policies": policies if policies is not None else [standard_policy()],
        "events": list(events),
    }


def register(
    event_id: str = "e-register",
    *,
    request_id: str = "REQ-1",
    subject_id: str = "SUBJ-alice",
    org: str = "ORG-north",
    resource: str = "FILESET-quarterly",
    operation: str = "read",
    op_version: int = 3,
    risk: str = "low",
    policy_version: int = 1,
    generation: str = "GEN-1",
    now: int = 100,
    ttl: int = 5000,
    challenge_id: str | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "event_id": event_id,
        "type": "register",
        "request_id": request_id,
        "subject_id": subject_id,
        "org": org,
        "resource": resource,
        "operation": operation,
        "op_version": op_version,
        "risk": risk,
        "policy_version": policy_version,
        "generation": generation,
        "now": now,
        "ttl": ttl,
    }
    if challenge_id is not None:
        event["challenge_id"] = challenge_id
    return event


def proof(
    event_id: str,
    proof_id: str,
    *,
    request_id: str = "REQ-1",
    stage: int = 1,
    factor: str = "device",
    principal: str = "PRIN-laptop",
    trust_group: str = "TG-devices",
    trusted: bool = True,
    now: int | None = None,
    challenge_id: str | None = None,
    generation: str | None = None,
    expires_at: int | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "event_id": event_id,
        "type": "submit_proof",
        "request_id": request_id,
        "proof_id": proof_id,
        "stage": stage,
        "factor": factor,
        "principal": principal,
        "trust_group": trust_group,
        "trusted": trusted,
    }
    if now is not None:
        event["now"] = now
    if challenge_id is not None:
        event["challenge_id"] = challenge_id
    if generation is not None:
        event["generation"] = generation
    if expires_at is not None:
        event["expires_at"] = expires_at
    return event


def advance(
    event_id: str,
    *,
    request_id: str = "REQ-1",
    stage: int = 1,
    now: int | None = None,
    expect: dict[str, Any] | None = None,
    next_challenge_id: str | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "event_id": event_id,
        "type": "advance",
        "request_id": request_id,
        "stage": stage,
    }
    if now is not None:
        event["now"] = now
    if expect is not None:
        event["expect"] = expect
    if next_challenge_id is not None:
        event["next_challenge_id"] = next_challenge_id
    return event


def token(
    event_id: str,
    token_id: str,
    *,
    challenge_id: str,
    request_id: str = "REQ-1",
    to_generation: str = "GEN-2",
    to_org: str = "ORG-south",
    resource: str | None = None,
    op_version: int | None = None,
    risk: str | None = None,
    policy_version: int | None = None,
    predecessor: Any = None,
    expires_at: int | None = None,
    trusted: bool = True,
    now: int | None = None,
) -> dict[str, Any]:
    """Build a token event.

    Omitted ``resource``, ``op_version``, ``risk`` and ``policy_version`` are
    filled in by the engine from the request, so a test only has to name the
    field it is actually exercising.
    """
    event: dict[str, Any] = {
        "event_id": event_id,
        "type": "issue_migration_token",
        "request_id": request_id,
        "token_id": token_id,
        "challenge_id": challenge_id,
        "to_generation": to_generation,
        "to_org": to_org,
        "predecessor": predecessor,
        "trusted": trusted,
    }
    for key, value in (
        ("resource", resource),
        ("op_version", op_version),
        ("risk", risk),
        ("policy_version", policy_version),
    ):
        if value is not None:
            event[key] = value
    if expires_at is not None:
        event["expires_at"] = expires_at
    if now is not None:
        event["now"] = now
    return event


def migrate(
    event_id: str,
    token_id: str,
    *,
    request_id: str = "REQ-1",
    to_generation: str = "GEN-2",
    to_org: str = "ORG-south",
    preserve_stage1: bool = False,
    policy_version: int | None = None,
    now: int | None = None,
    max_steps: int | None = None,
    next_challenge_id: str | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "event_id": event_id,
        "type": "migrate",
        "request_id": request_id,
        "token_id": token_id,
        "to_generation": to_generation,
        "to_org": to_org,
        "preserve_stage1": preserve_stage1,
    }
    if policy_version is not None:
        event["policy_version"] = policy_version
    if now is not None:
        event["now"] = now
    if max_steps is not None:
        event["max_steps"] = max_steps
    if next_challenge_id is not None:
        event["next_challenge_id"] = next_challenge_id
    return event


def clone(value: Any) -> Any:
    return copy.deepcopy(value)
