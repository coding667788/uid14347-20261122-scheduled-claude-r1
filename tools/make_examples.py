"""Generate the runnable example cases.

Run from the repository root:

    python tools/make_examples.py

Every example is a self-contained JSON file.  Cases that need several batches
pin their challenge identifiers explicitly (``challenge_id`` on register and
``next_challenge_id`` on a step) so the files read the same way every time.
"""

from __future__ import annotations

import json
import os
from typing import Any

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(ROOT, "examples")

SCHEMA = "challenge-ledger/v1"

POLICY_V1: dict[str, Any] = {
    "version": 1,
    "recipes": [
        {"id": "s1-two-factor", "stage": 1, "factors": ["device", "human"], "distinct_principals": True},
        {"id": "s2-confirm", "stage": 2, "factors": ["human"]},
    ],
}

POLICY_V2_STRICT: dict[str, Any] = {
    "version": 2,
    "recipes": [
        {
            "id": "s1-hardware-plus-human",
            "stage": 1,
            "requirements": [
                {"kind": "device", "count": 1, "trust_groups": ["TG-hardware"]},
                {"kind": "human", "count": 1},
            ],
            "distinct_principals": True,
            "distinct_trust_groups": True,
        },
        {"id": "s2-fresh-human", "stage": 2, "factors": ["human"], "distinct_trust_groups": True},
    ],
}

POLICY_V3_THREE_WAY: dict[str, Any] = {
    "version": 3,
    "recipes": [
        {
            "id": "s1-three-groups",
            "stage": 1,
            "requirements": [{"kind": "device", "count": 3, "distinct_principals": True}],
            "distinct_trust_groups": True,
        },
        {"id": "s2-fresh-human", "stage": 2, "factors": ["human"]},
    ],
}


def write(name: str, document: dict[str, Any]) -> None:
    path = os.path.join(EXAMPLES, name)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(document, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(f"wrote {os.path.relpath(path, ROOT)}")


def case(batch_id: str, events: list[dict[str, Any]], policies: list[dict[str, Any]], **extra: Any) -> dict:
    document: dict[str, Any] = {
        "schema": SCHEMA,
        "batch_id": batch_id,
        "policies": policies,
        "events": events,
    }
    document.update(extra)
    return document


def register(**over: Any) -> dict[str, Any]:
    event = {
        "event_id": "e-register",
        "type": "register",
        "request_id": "REQ-1",
        "subject_id": "SUBJ-alice",
        "org": "ORG-north",
        "resource": "FILESET-quarterly",
        "operation": "read",
        "op_version": 3,
        "risk": "low",
        "policy_version": 1,
        "generation": "GEN-1",
        "now": 100,
        "ttl": 5000,
    }
    event.update(over)
    return event


def proof(event_id: str, proof_id: str, **over: Any) -> dict[str, Any]:
    event = {
        "event_id": event_id,
        "type": "submit_proof",
        "request_id": "REQ-1",
        "proof_id": proof_id,
        "stage": 1,
        "factor": "device",
        "principal": "PRIN-laptop",
        "trust_group": "TG-devices",
        "trusted": True,
    }
    event.update(over)
    return event


def advance(event_id: str, stage: int, **over: Any) -> dict[str, Any]:
    event = {"event_id": event_id, "type": "advance", "request_id": "REQ-1", "stage": stage}
    event.update(over)
    return event


def token(event_id: str, token_id: str, **over: Any) -> dict[str, Any]:
    event = {
        "event_id": event_id,
        "type": "issue_migration_token",
        "request_id": "REQ-1",
        "token_id": token_id,
        "to_generation": "GEN-2",
        "to_org": "ORG-south",
        "predecessor": None,
    }
    event.update(over)
    return event


def migrate(event_id: str, token_id: str, **over: Any) -> dict[str, Any]:
    event = {
        "event_id": event_id,
        "type": "migrate",
        "request_id": "REQ-1",
        "token_id": token_id,
        "to_generation": "GEN-2",
        "to_org": "ORG-south",
        "preserve_stage1": False,
    }
    event.update(over)
    return event


# --------------------------------------------------------------------------
# 01 -- low risk, one stage, single transaction
# --------------------------------------------------------------------------
write(
    "01_low_risk_issuance.json",
    case(
        "b-low-risk",
        [
            register(challenge_id="CHL-1a"),
            proof("e1", "PF-device", stage=1, factor="device", principal="PRIN-laptop",
                  trust_group="TG-devices", now=110),
            proof("e2", "PF-human", stage=1, factor="human", principal="PRIN-bob",
                  trust_group="TG-staff", now=120),
            advance("e3", 1, now=130),
        ],
        [POLICY_V1],
    ),
)

# --------------------------------------------------------------------------
# 02 -- high risk, two stages, fresh confirmation required
# --------------------------------------------------------------------------
write(
    "02_high_risk_two_stage.json",
    case(
        "b-high-risk",
        [
            register(risk="high", challenge_id="CHL-1a", now=200, ttl=9000),
            proof("e1", "PF-device", stage=1, factor="device", principal="PRIN-laptop",
                  trust_group="TG-devices", now=210),
            proof("e2", "PF-human", stage=1, factor="human", principal="PRIN-bob",
                  trust_group="TG-staff", now=220),
            advance("e3", 1, now=230, next_challenge_id="CHL-2a"),
            proof("e4", "PF-confirm", stage=2, factor="human", principal="PRIN-carol",
                  trust_group="TG-staff", challenge_id="CHL-2a", now=240),
            advance("e5", 2, now=250),
        ],
        [POLICY_V1],
    ),
)

# --------------------------------------------------------------------------
# 03 -- chained migration: two hops and a return to the original organisation
# --------------------------------------------------------------------------
write(
    "03_migration_step1_preserve.json",
    case(
        "b-mig-step1",
        [
            register(risk="high", challenge_id="CHL-s1", now=100, ttl=9000),
            proof("e1", "PF-device", factor="device", principal="PRIN-laptop",
                  trust_group="TG-devices", now=110),
            proof("e2", "PF-human", factor="human", principal="PRIN-bob",
                  trust_group="TG-staff", now=120),
            advance("e3", 1, now=130, next_challenge_id="CHL-s2"),
            token("e4", "TOK-1", challenge_id="CHL-s2", to_generation="GEN-2",
                  to_org="ORG-south", now=140),
            migrate("e5", "TOK-1", to_generation="GEN-2", to_org="ORG-south",
                    preserve_stage1=True, now=150, next_challenge_id="CHL-s2-after"),
        ],
        [POLICY_V1],
    ),
)

write(
    "04_migration_step2_chain.json",
    case(
        "b-mig-step2",
        [
            token("s2a", "TOK-2", challenge_id="CHL-s2-after", to_generation="GEN-3",
                  to_org="ORG-east", predecessor=1, now=200),
            migrate("s2b", "TOK-2", to_generation="GEN-3", to_org="ORG-east",
                    preserve_stage1=True, now=210, next_challenge_id="CHL-s2-east"),
        ],
        [POLICY_V1],
    ),
)

write(
    "05_migration_back_to_origin.json",
    case(
        "b-mig-back",
        [
            token("s3a", "TOK-3", challenge_id="CHL-s2-east", to_generation="GEN-4",
                  to_org="ORG-north", predecessor=2, now=300),
            migrate("s3b", "TOK-3", to_generation="GEN-4", to_org="ORG-north",
                    preserve_stage1=True, now=310, next_challenge_id="CHL-final"),
        ],
        [POLICY_V1],
    ),
)

# --------------------------------------------------------------------------
# 05a -- after three hops the plan still needs a fresh stage-2 confirmation
# --------------------------------------------------------------------------
write(
    "05a_chain_stage2_issuance.json",
    case(
        "b-mig-issue",
        [
            proof("i1", "PF-final", stage=2, factor="human", principal="PRIN-carol",
                  trust_group="TG-staff", challenge_id="CHL-final", now=320),
            advance("i2", 2, now=330),
        ],
        [POLICY_V1],
    ),
)

# --------------------------------------------------------------------------
# 05b -- an old ticket cannot carry a later hop, even back to the origin org
# --------------------------------------------------------------------------
write(
    "05b_stale_ticket_rejected.json",
    case(
        "b-mig-stale",
        [
            # This token was minted at the *first* hop and is long spent.
            # Naming a later challenge must not revive it.
            migrate("stale-b", "TOK-1", to_generation="GEN-5", to_org="ORG-west",
                    preserve_stage1=True, now=410),
        ],
        [POLICY_V1],
    ),
)

# --------------------------------------------------------------------------
# 06 -- a migration that omits preservation throws stage 1 away
# --------------------------------------------------------------------------
write(
    "06_migration_drops_stage1.json",
    case(
        "b-mig-drop",
        [
            register(risk="high", challenge_id="CHL-s1", now=100, ttl=9000),
            proof("e1", "PF-device", factor="device", principal="PRIN-laptop",
                  trust_group="TG-devices", now=110),
            proof("e2", "PF-human", factor="human", principal="PRIN-bob",
                  trust_group="TG-staff", now=120),
            advance("e3", 1, now=130, next_challenge_id="CHL-s2"),
            token("e4", "TOK-1", challenge_id="CHL-s2", to_generation="GEN-2", now=140),
            migrate("e5", "TOK-1", to_generation="GEN-2", preserve_stage1=False, now=150),
        ],
        [POLICY_V1],
    ),
)

# --------------------------------------------------------------------------
# 07 -- policy upgrade invalidates a preserved stage 1, consumption persists
# --------------------------------------------------------------------------
write(
    "07_policy_upgrade_rollback.json",
    case(
        "b-policy",
        [
            register(risk="high", challenge_id="CHL-s1", now=100, ttl=9000),
            proof("e1", "PF-device", factor="device", principal="PRIN-laptop",
                  trust_group="TG-devices", now=110),
            proof("e2", "PF-human", factor="human", principal="PRIN-bob",
                  trust_group="TG-staff", now=120),
            advance("e3", 1, now=130, next_challenge_id="CHL-s2"),
            token("e4", "TOK-1", challenge_id="CHL-s2", to_generation="GEN-2", now=140),
            migrate("e5", "TOK-1", to_generation="GEN-2", preserve_stage1=True, now=150,
                    next_challenge_id="CHL-s2-after"),
            {"event_id": "e6", "type": "define_policy", "policy": POLICY_V2_STRICT},
            {"event_id": "e7", "type": "adopt_policy", "request_id": "REQ-1",
             "policy_version": 2, "now": 160},
            advance("e8", 2, now=170, next_challenge_id="CHL-s1-redo"),
        ],
        [POLICY_V1],
    ),
)

# --------------------------------------------------------------------------
# 08 -- group independence: three devices, two groups
# --------------------------------------------------------------------------
write(
    "08_group_independence_failure.json",
    case(
        "b-groups",
        [
            register(risk="low", challenge_id="CHL-g", now=100, ttl=9000, policy_version=3),
            proof("e1", "PF-d1", factor="device", principal="PRIN-1",
                  trust_group="TG-red", now=110),
            proof("e2", "PF-d2", factor="device", principal="PRIN-2",
                  trust_group="TG-blue", now=120),
            proof("e3", "PF-d3", factor="device", principal="PRIN-3",
                  trust_group="TG-red", now=130),
            advance("e4", 1, now=140),
        ],
        [POLICY_V3_THREE_WAY],
    ),
)

# --------------------------------------------------------------------------
# 09 -- same proof id, different content is a conflict for the whole batch
# --------------------------------------------------------------------------
write(
    "09_conflict_rejected_batch.json",
    case(
        "b-conflict",
        [
            register(challenge_id="CHL-c", now=100),
            proof("e1", "PF-device", factor="device", principal="PRIN-laptop",
                  trust_group="TG-devices", now=110),
            proof("e1", "PF-device", factor="device", principal="PRIN-other",
                  trust_group="TG-devices", now=120),
        ],
        [POLICY_V1],
    ),
)

# --------------------------------------------------------------------------
# 10 -- a crash between commit and response; retry returns the same answer
# --------------------------------------------------------------------------
write(
    "10_crash_after_commit.json",
    case(
        "b-crash",
        [
            register(risk="low", challenge_id="CHL-k", now=100),
            proof("e1", "PF-device", factor="device", principal="PRIN-laptop",
                  trust_group="TG-devices", now=110),
            proof("e2", "PF-human", factor="human", principal="PRIN-bob",
                  trust_group="TG-staff", now=120),
            advance("e3", 1, now=130),
            {"event_id": "e4", "type": "fault", "point": "after_commit"},
        ],
        [POLICY_V1],
    ),
)

# --------------------------------------------------------------------------
# 11 -- two writers race the same batch: one commit, one identical answer
# --------------------------------------------------------------------------
write(
    "11_duplicate_batch_retry.json",
    case(
        "b-retry",
        [
            register(risk="low", challenge_id="CHL-r", now=100),
            proof("e1", "PF-device", factor="device", principal="PRIN-laptop",
                  trust_group="TG-devices", now=110),
            proof("e2", "PF-human", factor="human", principal="PRIN-bob",
                  trust_group="TG-staff", now=120),
            advance("e3", 1, now=130),
        ],
        [POLICY_V1],
    ),
)

# --------------------------------------------------------------------------
# 12 -- expired challenge refuses a late proof
# --------------------------------------------------------------------------
write(
    "12_expired_challenge.json",
    case(
        "b-expired",
        [
            register(risk="low", challenge_id="CHL-x", now=0, ttl=100),
            proof("e1", "PF-device", factor="device", principal="PRIN-laptop",
                  trust_group="TG-devices", now=500),
        ],
        [POLICY_V1],
    ),
)

# --------------------------------------------------------------------------
# 13 -- risk upgrade part-way through invalidates collected stage 1
# --------------------------------------------------------------------------
write(
    "13_risk_upgrade.json",
    case(
        "b-upgrade",
        [
            register(risk="low", challenge_id="CHL-u", now=100, ttl=9000),
            proof("e1", "PF-device", factor="device", principal="PRIN-laptop",
                  trust_group="TG-devices", now=110),
            proof("e2", "PF-human", factor="human", principal="PRIN-bob",
                  trust_group="TG-staff", now=120),
            {"event_id": "e3", "type": "upgrade_risk", "request_id": "REQ-1",
             "risk": "high", "now": 130, "next_challenge_id": "CHL-u2"},
        ],
        [POLICY_V1],
    ),
)

# --------------------------------------------------------------------------
# 14 -- structural error with a locatable path
# --------------------------------------------------------------------------
write(
    "14_structural_error.json",
    case(
        "b-structural",
        [
            register(risk="medium"),
        ],
        [POLICY_V1],
    ),
)
