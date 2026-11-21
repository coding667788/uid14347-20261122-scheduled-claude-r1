"""Proof recipes and stage adjudication.

A *policy version* holds recipes.  A recipe targets one stage and lists the
factors it needs.  A requirement may restrict the allowed principals and trust
groups and may demand that the chosen factors come from distinct principals
and distinct trust groups -- the condition that catches "three individually
valid factors, any two of which are not independent".

Adjudication answers one question: given every proof known for a request, which
still-valid, non-revoked, stage-bound set should be consumed?  The answer is the
set with the smallest *new* consumption, ties broken by the lexicographically
smallest sorted proof identifiers, so the outcome is reproducible.

"New" matters because a retained stage entry has already paid for its proofs.
Re-adjudication is free to keep them, add to them, or abandon them -- but it
never forgets that they were consumed.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence

from .canonical import digest
from .errors import (
    CaseError,
    E_POLICY_CONFLICT,
    E_POLICY_TOO_COMPLEX,
    E_SCHEMA_CONFLICT,
    E_SCHEMA_ENUM,
    E_SCHEMA_MISSING,
    E_SCHEMA_TYPE,
)
from .schema import (
    FACTOR_KINDS,
    STAGES,
    expect_bool,
    expect_id,
    expect_int,
    expect_list,
    expect_object,
    join,
)

MAX_CANDIDATES = 48
MAX_COMBINATIONS = 200_000


@dataclass(frozen=True)
class Requirement:
    kind: str
    count: int
    principals: tuple[str, ...] | None = None
    trust_groups: tuple[str, ...] | None = None
    distinct_principals: bool = False
    distinct_trust_groups: bool = False
    require_trusted: bool = True


@dataclass(frozen=True)
class Recipe:
    id: str
    stage: int
    requirements: tuple[Requirement, ...]
    distinct_principals: bool = True
    distinct_trust_groups: bool = False
    require_trusted: bool = True

    @property
    def size(self) -> int:
        return sum(r.count for r in self.requirements)


@dataclass(frozen=True)
class Policy:
    version: int
    recipes: tuple[Recipe, ...]

    def recipes_for(self, stage: int) -> tuple[Recipe, ...]:
        return tuple(r for r in self.recipes if r.stage == stage)

    def recipe(self, recipe_id: str) -> Recipe | None:
        for r in self.recipes:
            if r.id == recipe_id:
                return r
        return None

    def to_json(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "recipes": [
                {
                    "id": r.id,
                    "stage": r.stage,
                    "requirements": [
                        {
                            "kind": q.kind,
                            "count": q.count,
                            "principals": list(q.principals) if q.principals else None,
                            "trust_groups": list(q.trust_groups) if q.trust_groups else None,
                            "distinct_principals": q.distinct_principals,
                            "distinct_trust_groups": q.distinct_trust_groups,
                            "require_trusted": q.require_trusted,
                        }
                        for q in r.requirements
                    ],
                    "distinct_principals": r.distinct_principals,
                    "distinct_trust_groups": r.distinct_trust_groups,
                    "require_trusted": r.require_trusted,
                }
                for r in self.recipes
            ],
        }

    def fingerprint(self) -> str:
        return digest(self.to_json())


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

_REQUIREMENT_FIELDS = (
    "kind",
    "count",
    "principals",
    "trust_groups",
    "distinct_principals",
    "distinct_trust_groups",
    "require_trusted",
)
_RECIPE_FIELDS = (
    "id",
    "stage",
    "requirements",
    "factors",
    "distinct_principals",
    "distinct_trust_groups",
    "require_trusted",
)


def _parse_kind(value: Any, path: str) -> str:
    if not isinstance(value, str):
        raise CaseError(E_SCHEMA_TYPE, path, "expected a factor kind string")
    if value not in FACTOR_KINDS:
        raise CaseError(E_SCHEMA_ENUM, path, f"expected one of {list(FACTOR_KINDS)}")
    return value


def _parse_ids(value: Any, path: str) -> tuple[str, ...]:
    items = expect_list(value, path, non_empty=True)
    out: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        text = expect_id(item, join(path, index))
        if text in seen:
            raise CaseError(E_SCHEMA_ENUM, join(path, index), f"duplicate identifier {text!r}")
        seen.add(text)
        out.append(text)
    return tuple(out)


def parse_requirement(raw: Any, path: str) -> Requirement:
    expect_object(raw, path, ("kind", "count"), _REQUIREMENT_FIELDS)
    return Requirement(
        kind=_parse_kind(raw["kind"], join(path, "kind")),
        count=expect_int(raw["count"], join(path, "count"), minimum=1, maximum=16),
        principals=_parse_ids(raw["principals"], join(path, "principals")) if "principals" in raw else None,
        trust_groups=_parse_ids(raw["trust_groups"], join(path, "trust_groups")) if "trust_groups" in raw else None,
        distinct_principals=expect_bool(raw.get("distinct_principals", False), join(path, "distinct_principals")),
        distinct_trust_groups=expect_bool(
            raw.get("distinct_trust_groups", False), join(path, "distinct_trust_groups")
        ),
        require_trusted=expect_bool(raw.get("require_trusted", True), join(path, "require_trusted")),
    )


def parse_recipe(raw: Any, path: str) -> Recipe:
    expect_object(raw, path, ("id", "stage"), _RECIPE_FIELDS)
    recipe_id = expect_id(raw["id"], join(path, "id"))
    stage = expect_int(raw["stage"], join(path, "stage"))
    if stage not in STAGES:
        raise CaseError(E_SCHEMA_ENUM, join(path, "stage"), "stage must be 1 or 2")

    if "requirements" in raw and "factors" in raw:
        raise CaseError(E_SCHEMA_CONFLICT, join(path, "requirements"), "use 'requirements' or 'factors', not both")
    requirements: list[Requirement] = []
    if "requirements" in raw:
        req_path = join(path, "requirements")
        for index, item in enumerate(expect_list(raw["requirements"], req_path, non_empty=True)):
            requirements.append(parse_requirement(item, join(req_path, index)))
    elif "factors" in raw:
        fac_path = join(path, "factors")
        for index, item in enumerate(expect_list(raw["factors"], fac_path, non_empty=True)):
            if isinstance(item, str):
                requirements.append(Requirement(kind=_parse_kind(item, join(fac_path, index)), count=1))
            else:
                requirements.append(parse_requirement(item, join(fac_path, index)))
    else:
        raise CaseError(E_SCHEMA_MISSING, join(path, "requirements"), "recipe needs 'requirements' or 'factors'")

    seen: set[str] = set()
    for index, req in enumerate(requirements):
        if req.kind in seen:
            raise CaseError(
                E_SCHEMA_ENUM, join(join(path, "requirements"), index), "duplicate factor kind in recipe"
            )
        seen.add(req.kind)

    return Recipe(
        id=recipe_id,
        stage=stage,
        requirements=tuple(requirements),
        distinct_principals=expect_bool(raw.get("distinct_principals", True), join(path, "distinct_principals")),
        distinct_trust_groups=expect_bool(raw.get("distinct_trust_groups", False), join(path, "distinct_trust_groups")),
        require_trusted=expect_bool(raw.get("require_trusted", True), join(path, "require_trusted")),
    )


def parse_policy(raw: Any, path: str) -> Policy:
    expect_object(raw, path, ("version", "recipes"))
    version = expect_int(raw["version"], join(path, "version"), minimum=1, maximum=1_000_000)
    recipes: list[Recipe] = []
    seen: set[str] = set()
    recipe_path = join(path, "recipes")
    for index, item in enumerate(expect_list(raw["recipes"], recipe_path, non_empty=True)):
        recipe = parse_recipe(item, join(recipe_path, index))
        if recipe.id in seen:
            raise CaseError(E_POLICY_CONFLICT, join(recipe_path, index), f"duplicate recipe id {recipe.id!r}")
        seen.add(recipe.id)
        recipes.append(recipe)
    if not any(r.stage == 1 for r in recipes):
        raise CaseError(E_SCHEMA_MISSING, recipe_path, "policy needs at least one stage-1 recipe")
    return Policy(version=version, recipes=tuple(recipes))


# --------------------------------------------------------------------------
# Adjudication
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ProofView:
    """Everything adjudication may look at for one proof."""

    proof_id: str
    stage: int
    factor: str
    principal: str
    trust_group: str
    trusted: bool
    expires_at: int
    status: str
    consumed: bool
    generation: str
    challenge_id: str


@dataclass
class StageEvaluation:
    satisfied: bool
    stage: int
    policy_version: int
    recipe_id: str | None
    proof_ids: list[str]
    consumed_now: list[str]
    retained: list[str]
    failures: list[dict[str, Any]]
    excluded: list[dict[str, Any]]

    def to_json(self) -> dict[str, Any]:
        return {
            "satisfied": self.satisfied,
            "stage": self.stage,
            "policy_version": self.policy_version,
            "recipe_id": self.recipe_id,
            "proof_ids": list(self.proof_ids),
            "consumed_now": list(self.consumed_now),
            "retained": list(self.retained),
            "failures": [dict(f) for f in self.failures],
            "excluded": [dict(e) for e in self.excluded],
        }


def reject_reason(
    proof: ProofView,
    requirement: Requirement,
    *,
    stage: int,
    generation: str,
    now: int,
    retained: frozenset[str],
) -> str | None:
    """Why *proof* cannot serve *requirement*, or ``None`` when it can."""
    if proof.stage != stage:
        return "stage_mismatch"
    if proof.generation != generation:
        return "generation_mismatch"
    if proof.status != "active":
        return "revoked"
    if proof.consumed and proof.proof_id not in retained:
        return "already_consumed"
    if proof.expires_at <= now:
        return "expired"
    if requirement.require_trusted and not proof.trusted:
        return "untrusted"
    if proof.factor != requirement.kind:
        return "factor_mismatch"
    if requirement.principals is not None and proof.principal not in requirement.principals:
        return "principal_not_allowed"
    if requirement.trust_groups is not None and proof.trust_group not in requirement.trust_groups:
        return "trust_group_not_allowed"
    return None


class _Budget:
    def __init__(self, limit: int):
        self.left = limit

    def spend(self) -> None:
        self.left -= 1
        if self.left < 0:
            raise CaseError(
                E_POLICY_TOO_COMPLEX,
                "policy.recipes",
                "adjudication exceeded its search budget; simplify the recipe or reduce candidates",
            )


def _select_for_recipe(
    recipe: Recipe,
    proofs: Sequence[ProofView],
    *,
    now: int,
    generation: str,
    retained: frozenset[str],
    budget: _Budget,
) -> tuple[tuple[str, ...] | None, list[dict[str, Any]]]:
    per_requirement: list[list[tuple[ProofView, ...]]] = []
    failures: list[dict[str, Any]] = []

    for index, requirement in enumerate(recipe.requirements):
        eligible: list[ProofView] = []
        rejected: list[dict[str, Any]] = []
        for proof in proofs:
            reason = reject_reason(
                proof, requirement, stage=recipe.stage, generation=generation, now=now, retained=retained
            )
            if reason is None:
                eligible.append(proof)
            elif reason not in ("stage_mismatch", "factor_mismatch"):
                rejected.append({"proof_id": proof.proof_id, "reason": reason})
        eligible.sort(key=lambda p: p.proof_id)
        if len(eligible) > MAX_CANDIDATES:
            raise CaseError(
                E_POLICY_TOO_COMPLEX, "policy.recipes", f"{len(eligible)} candidates exceed the {MAX_CANDIDATES} limit"
            )
        options = []
        for combo in itertools.combinations(eligible, requirement.count):
            budget.spend()
            if _combo_ok(combo, requirement):
                options.append(combo)
        if not options:
            failures.append(
                {
                    "stage": recipe.stage,
                    "recipe_id": recipe.id,
                    "requirement_index": index,
                    "kind": requirement.kind,
                    "needed": requirement.count,
                    "eligible": len(eligible),
                    "reason": "no_valid_combination",
                    "rejected": rejected[:16],
                }
            )
            return None, failures
        per_requirement.append(options)

    best: tuple[int, tuple[str, ...]] | None = None
    for combination in itertools.product(*per_requirement):
        budget.spend()
        chosen = [p for combo in combination for p in combo]
        ids = [p.proof_id for p in chosen]
        if len(set(ids)) != len(ids):
            continue
        if recipe.distinct_principals and len({p.principal for p in chosen}) != len(chosen):
            continue
        if recipe.distinct_trust_groups and len({p.trust_group for p in chosen}) != len(chosen):
            continue
        cost = sum(1 for pid in ids if pid not in retained)
        key = (cost, tuple(sorted(ids)))
        if best is None or key < best:
            best = key
    if best is None:
        failures.append(
            {
                "stage": recipe.stage,
                "recipe_id": recipe.id,
                "requirement_index": None,
                "kind": None,
                "needed": recipe.size,
                "eligible": sum(len(o) for o in per_requirement),
                "reason": "independence_not_satisfied",
                "rejected": [],
            }
        )
        return None, failures
    return best[1], failures


def _combo_ok(combo: Sequence[ProofView], requirement: Requirement) -> bool:
    if requirement.distinct_principals and len({p.principal for p in combo}) != len(combo):
        return False
    if requirement.distinct_trust_groups and len({p.trust_group for p in combo}) != len(combo):
        return False
    return True


def evaluate_stage(
    policy: Policy,
    stage: int,
    proofs: Iterable[ProofView],
    *,
    now: int,
    generation: str,
    retained_ids: Iterable[str] = (),
    group_of: Callable[[str], str] | None = None,
) -> StageEvaluation:
    """Adjudicate *stage* under *policy*, choosing the cheapest valid recipe."""
    proof_list = sorted(proofs, key=lambda p: p.proof_id)
    retained = frozenset(retained_ids)
    budget = _Budget(MAX_COMBINATIONS)
    recipes = policy.recipes_for(stage)
    excluded = _global_exclusions(proof_list, stage=stage, now=now, generation=generation, retained=retained)

    if not recipes:
        return StageEvaluation(
            satisfied=False,
            stage=stage,
            policy_version=policy.version,
            recipe_id=None,
            proof_ids=[],
            consumed_now=[],
            retained=[],
            failures=[
                {
                    "stage": stage,
                    "recipe_id": None,
                    "requirement_index": None,
                    "kind": None,
                    "needed": 0,
                    "eligible": 0,
                    "reason": "no_recipe_for_stage",
                    "rejected": [],
                }
            ],
            excluded=excluded,
        )

    best: tuple[tuple[int, tuple[str, ...]], str, tuple[str, ...]] | None = None
    all_failures: list[dict[str, Any]] = []
    for recipe in sorted(recipes, key=lambda r: (r.size, r.id)):
        selection, failures = _select_for_recipe(
            recipe, proof_list, now=now, generation=generation, retained=retained, budget=budget
        )
        if selection is None:
            all_failures.extend(failures)
            continue
        cost = sum(1 for pid in selection if pid not in retained)
        key = (cost, selection)
        if best is None or key < best[0]:
            best = (key, recipe.id, selection)

    if best is None:
        return StageEvaluation(
            satisfied=False,
            stage=stage,
            policy_version=policy.version,
            recipe_id=None,
            proof_ids=[],
            consumed_now=[],
            retained=[],
            failures=all_failures,
            excluded=excluded,
        )

    _, recipe_id, selection = best
    return StageEvaluation(
        satisfied=True,
        stage=stage,
        policy_version=policy.version,
        recipe_id=recipe_id,
        proof_ids=list(selection),
        consumed_now=[pid for pid in selection if pid not in retained],
        retained=[pid for pid in selection if pid in retained],
        failures=[],
        excluded=excluded,
    )


def _global_exclusions(
    proofs: Sequence[ProofView],
    *,
    stage: int,
    now: int,
    generation: str,
    retained: frozenset[str],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for proof in proofs:
        reasons: list[str] = []
        if proof.stage != stage:
            reasons.append("stage_mismatch")
        if proof.generation != generation:
            reasons.append("generation_mismatch")
        if proof.status != "active":
            reasons.append("revoked")
        if proof.consumed and proof.proof_id not in retained:
            reasons.append("already_consumed")
        if proof.expires_at <= now:
            reasons.append("expired")
        if not proof.trusted:
            reasons.append("untrusted")
        if reasons:
            out.append({"proof_id": proof.proof_id, "reasons": reasons})
    return out
