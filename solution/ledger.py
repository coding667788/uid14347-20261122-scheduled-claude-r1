"""Batch application, idempotency and history.

The public surface is small:

``parse_case``   structural validation with locatable paths
``apply_case``   apply a whole batch in one transaction, or return the result
                 already recorded for an identical batch
``explain``      fold committed events up to a batch number and report each
                 request's state, receipts and unmet requirements

Replay is the single source of truth for history.  Handlers are pure functions
of ``(state, event)``, so folding a fixed prefix always yields the same state.
That is why a revocation appended later can never reach into an old receipt.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any, Iterable

from .canonical import canonical_json, digest, load_json_bytes
from .errors import (
    CaseError,
    E_BATCH_OUT_OF_ORDER,
    E_COMMIT_NOT_FOUND,
    E_EVENT_CONFLICT,
    E_EVENT_DUPLICATE_IN_BATCH,
    E_INJECTED_FAULT,
    E_IO,
    E_JSON_PARSE,
    E_SCHEMA_EMPTY,
    E_SCHEMA_MISSING,
    E_SCHEMA_TYPE,
    E_SCHEMA_UNKNOWN,
    E_USAGE,
    E_VERIFY_COMMIT,
    E_VERIFY_DIGEST,
    E_VERIFY_KEY,
    E_VERIFY_RECEIPT,
)
from .model import (
    STATUS_COLLECTING,
    STATUS_ISSUED,
    STATUS_REVOKED,
    STATUS_STAGE1,
    STATUS_STAGE2,
    LedgerState,
    RequestState,
    receipt_digest,
)
from .policy import parse_policy
from .schema import expect_id, expect_list, join
from .store import EventStore

from .engine import (
    EventContext,
    adjudicate,
    apply_event,
    blank_state,
    validate_event_structure,
)

from . import SCHEMA as SCHEMA_NAME  # single source of the wire constant
CASE_FIELDS = ("schema", "batch_id", "policies", "events", "expect_at", "description")


# --------------------------------------------------------------------------
# Case parsing
# --------------------------------------------------------------------------


@dataclass
class Case:
    batch_id: str
    policies: list[dict[str, Any]]
    events: list[dict[str, Any]]

    def scheduled(self) -> list[tuple[dict[str, Any], str]]:
        """Return ``(event, path)`` pairs in application order.

        Policy definitions are applied first and carry a ``policies[j]`` path;
        case events keep their original ``events[i]`` position so every error
        points at the line the author wrote.

        A policy's synthetic event id includes its content fingerprint.  That
        makes re-declaring the *same* policy idempotent while letting a
        same-version-different-content declaration reach the handler, which
        reports ``E_POLICY_CONFLICT`` at the field rather than a bare event-id
        collision.
        """
        out: list[tuple[dict[str, Any], str]] = []
        for index, policy in enumerate(self.policies):
            fingerprint = digest(policy).split(":", 1)[-1][:12]
            out.append(
                (
                    {
                        "event_id": f"@policy-v{int(policy['version'])}-{fingerprint}",
                        "type": "define_policy",
                        "policy": policy,
                        "@inline": True,
                    },
                    f"policies[{index}]",
                )
            )
        for index, event in enumerate(self.events):
            out.append((event, f"events[{index}]"))
        return out


def parse_case(document: Any, *, path: str = "case") -> Case:
    if isinstance(document, list):
        document = {"events": document}
    if not isinstance(document, dict):
        raise CaseError(E_SCHEMA_TYPE, path, "case must be a JSON object or an array of events")
    if "events" not in document:
        raise CaseError(E_SCHEMA_MISSING, join(path, "events"), "required field is missing")
    for key in document:
        if key not in CASE_FIELDS:
            raise CaseError(E_SCHEMA_UNKNOWN, join(path, key), "unknown case field")
    if "schema" in document and document["schema"] != SCHEMA_NAME:
        raise CaseError(E_SCHEMA_TYPE, join(path, "schema"), f"expected {SCHEMA_NAME!r}")

    raw_events = expect_list(document["events"], join(path, "events"), non_empty=True)
    if not raw_events:
        raise CaseError(E_SCHEMA_EMPTY, join(path, "events"), "case needs at least one event")

    policies: list[dict[str, Any]] = []
    if "policies" in document:
        for index, item in enumerate(expect_list(document["policies"], join(path, "policies"), non_empty=True)):
            parse_policy(item, join(join(path, "policies"), index))
            policies.append(item)

    batch_id = document.get("batch_id")
    if batch_id is not None:
        batch_id = expect_id(batch_id, join(path, "batch_id")) if batch_id != "" else ""

    return Case(batch_id=batch_id or "", policies=policies, events=raw_events)


# --------------------------------------------------------------------------
# Replay
# --------------------------------------------------------------------------


def replay(store: EventStore, *, upto_batch: int | None = None) -> tuple[LedgerState, list[dict[str, Any]]]:
    """Fold committed events (optionally up to a batch, inclusive)."""
    state = blank_state()
    applied: list[dict[str, Any]] = []
    for index, stored in enumerate(store.events_upto(upto_batch)):
        payload = json.loads(stored.payload_json)
        ctx = EventContext(batch_no=stored.batch_no, index=index, path=f"history[{index}]")
        result = apply_event(state, payload, ctx)
        result.pop("__fault__", None)
        applied.append(
            {
                "seq": stored.seq,
                "batch_no": stored.batch_no,
                "event_id": stored.event_id,
                "type": stored.event_type,
                "result": json.loads(stored.result_json),
            }
        )
    return state, applied


# --------------------------------------------------------------------------
# Ordering constraint
# --------------------------------------------------------------------------


def _scope_of(event: dict[str, Any]) -> str:
    request_id = event.get("request_id")
    return "@global" if request_id is None else str(request_id)


def _check_batch_order(scheduled: list[tuple[dict[str, Any], str]]) -> None:
    """Reject a migration that names a token this batch issues *later*.

    A migration whose token is already committed is fine; only a forward
    reference inside the same batch is out of order.  Rejecting beats quietly
    sorting, since sorting would hide exactly the ordering hazard this ledger
    exists to make visible.
    """
    issuance_index: dict[str, int] = {}
    for index, (event, _path) in enumerate(scheduled):
        if event.get("type") == "issue_migration_token":
            token_id = event.get("token_id")
            if isinstance(token_id, str):
                issuance_index.setdefault(token_id, index)
    for index, (event, path) in enumerate(scheduled):
        if event.get("type") != "migrate":
            continue
        token_id = event.get("token_id")
        if isinstance(token_id, str) and issuance_index.get(token_id, -1) > index:
            raise CaseError(
                E_BATCH_OUT_OF_ORDER,
                join(path, "token_id"),
                f"migration consumes token {token_id!r} before this batch issues it",
            )


# --------------------------------------------------------------------------
# Apply
# --------------------------------------------------------------------------


class AfterCommitFault(Exception):
    """Raised after COMMIT to model a crash between commit and response."""

    def __init__(self, batch_no: int):
        super().__init__(f"injected crash after commit of batch {batch_no}")
        self.batch_no = batch_no


def apply_case(store: EventStore, case: Case) -> dict[str, Any]:
    scheduled = case.scheduled()
    payload_digest = digest({"policies": case.policies, "events": case.events})
    key = case.batch_id or ("auto-" + payload_digest.split(":", 1)[-1][:24])

    existing = store.get_batch(key)
    if existing is not None:
        if existing["payload_digest"] != payload_digest:
            raise CaseError(
                E_EVENT_CONFLICT,
                "batch_id",
                f"batch {key!r} was already committed with different content",
            )
        # Exact retry: return the first answer byte for byte.
        return json.loads(existing["result_json"])

    # Structural validation runs before any lookup against ledger state, so a
    # malformed event is always reported as malformed.
    for event, path in scheduled:
        validate_event_structure(event, path)
    _check_batch_order(scheduled)

    try:
        return _apply_in_transaction(store, case, scheduled, key, payload_digest)
    except sqlite3.IntegrityError:
        # Two processes may both pass the pre-check for a fresh batch key.  Only
        # one insert wins; the loser returns the winner's answer instead of
        # failing.  A conflict on anything else is a real bug, so re-raise.
        existing = store.get_batch(key)
        if existing is None:
            raise
        if existing["payload_digest"] != payload_digest:
            raise CaseError(
                E_EVENT_CONFLICT,
                "batch_id",
                f"batch {key!r} was committed concurrently with different content",
            )
        return json.loads(existing["result_json"])


def _apply_in_transaction(
    store: EventStore,
    case: Case,
    scheduled: list[tuple[dict[str, Any], str]],
    key: str,
    payload_digest: str,
) -> dict[str, Any]:
    assert store.conn is not None
    with store.transaction() as conn:
        state, _ = replay(store)

        # Reserve the batch number so every event applied below records the
        # batch it actually belongs to.
        batch_no = store.insert_batch(
            conn,
            batch_key=key,
            payload_digest=payload_digest,
            request_digest=digest(sorted({_scope_of(e) for e, _ in scheduled})),
            result={},
        )

        seen: dict[tuple[str, str], str] = {}
        batch_index: dict[tuple[str, str], int] = {}
        fresh: list[tuple[int, dict[str, Any], str]] = []
        results: list[dict[str, Any]] = []
        fault_after_commit = False

        for index, (event, path) in enumerate(scheduled):
            scope = _scope_of(event)
            event_id = str(event["event_id"])
            event_digest = digest(event)
            cache_key = (scope, event_id)

            if cache_key in seen:
                if seen[cache_key] != event_digest:
                    raise CaseError(
                        E_EVENT_DUPLICATE_IN_BATCH,
                        join(path, "event_id"),
                        f"event id {event_id!r} appears twice in this batch with different content",
                    )
                results.append(results[batch_index[cache_key]])
                continue

            stored = store.get_event(scope, event_id)
            if stored is not None:
                if stored.payload_digest != event_digest:
                    raise CaseError(
                        E_EVENT_CONFLICT,
                        join(path, "event_id"),
                        f"event id {event_id!r} was already committed with different content",
                        event_id=event_id,
                    )
                # Idempotent duplicate: original result, no state change.
                results.append(json.loads(stored.result_json))
                seen[cache_key] = event_digest
                batch_index[cache_key] = len(results) - 1
                continue

            result = apply_event(state, event, EventContext(batch_no=batch_no, index=index, path=path))
            point = result.pop("__fault__", None)
            if point in ("at_event", "before_commit", "commit"):
                raise CaseError(
                    E_INJECTED_FAULT,
                    path,
                    f"injected fault at {point!r}; nothing in this batch may commit",
                    event_id=event_id,
                )
            if point == "after_commit":
                fault_after_commit = True
            seen[cache_key] = event_digest
            batch_index[cache_key] = len(results)
            fresh.append((index, event, path))
            results.append(result)

        document = {
            "schema": SCHEMA_NAME,
            "kind": "apply",
            "commit": batch_no,
            "batch_key": key,
            "batch_id": case.batch_id or None,
            "events": results,
            "receipts": _batch_receipts(results, state),
            "requests": _touched_requests(results, state),
        }

        # Only events that were genuinely applied are written; duplicates are
        # answered from the row that already exists.
        for index, event, _path in fresh:
            store.insert_event(
                conn,
                batch_no=batch_no,
                scope=_scope_of(event),
                event=event,
                result=results[index],
            )
        for result in results:
            receipt_id = result.get("receipt_id")
            if not receipt_id:
                continue
            record = state.receipts.get(receipt_id)
            if record is None or store.receipt(receipt_id) is not None:
                continue
            store.insert_receipt(
                conn,
                payload=record.payload,
                request_id=record.request_id,
                subject_id=record.subject_id,
                batch_no=batch_no,
            )
        conn.execute(
            "UPDATE batches SET result_json = ? WHERE batch_no = ?",
            (canonical_json(document), batch_no),
        )

    if fault_after_commit:
        raise AfterCommitFault(int(document["commit"]))
    return document


def _batch_receipts(results: list[dict[str, Any]], state: LedgerState) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for result in results:
        receipt_id = result.get("receipt_id")
        if receipt_id and receipt_id not in seen and receipt_id in state.receipts:
            seen.add(receipt_id)
            out.append(state.receipts[receipt_id].to_json())
    return out


def _touched_requests(results: list[dict[str, Any]], state: LedgerState) -> dict[str, Any]:
    touched: list[str] = []
    for result in results:
        request_id = result.get("request_id")
        if isinstance(request_id, str) and request_id not in touched:
            touched.append(request_id)
    return {rid: state.requests[rid].to_json() for rid in sorted(touched) if rid in state.requests}


# --------------------------------------------------------------------------
# Explain
# --------------------------------------------------------------------------


def explain(store: EventStore, commit: int | None = None) -> dict[str, Any]:
    batches = store.all_batches()
    if not batches and commit is None:
        # Nothing has been committed yet; that is an empty ledger, not an
        # error.  Asking for a specific commit still fails below.
        return {
            "schema": SCHEMA_NAME,
            "kind": "explain",
            "commit": 0,
            "batches": [],
            "events": [],
            "requests": {},
            "receipts": [],
        }
    if commit is None:
        commit = int(batches[-1]["batch_no"])
    if commit not in {int(b["batch_no"]) for b in batches}:
        raise CaseError(E_COMMIT_NOT_FOUND, "commit", f"no committed batch numbered {commit}")

    state, applied = replay(store, upto_batch=commit)
    requests: dict[str, Any] = {}
    for request_id in sorted(state.requests):
        request = state.requests[request_id]
        body = state.describe_request(request_id)
        body["unmet"] = _unmet_requirements(state, request)
        body["receipts"] = sorted(
            (r.to_json() for r in state.receipts.values() if r.request_id == request_id),
            key=lambda r: int(r["number"]),
        )
        requests[request_id] = body

    receipts = sorted((r.to_json() for r in state.receipts.values()), key=lambda r: r["receipt_id"])
    return {
        "schema": SCHEMA_NAME,
        "kind": "explain",
        "commit": commit,
        "batches": [
            {
                "batch_no": int(b["batch_no"]),
                "batch_key": b["batch_key"],
                "committed_at": b["committed_at"],
            }
            for b in batches
            if int(b["batch_no"]) <= commit
        ],
        "events": applied,
        "requests": requests,
        "receipts": receipts,
    }


def _unmet_requirements(state: LedgerState, request: RequestState) -> dict[str, Any]:
    if request.status in (STATUS_ISSUED, STATUS_REVOKED):
        return {
            "satisfied": True,
            "reason": request.status,
            "stage": None,
            "failures": [],
            "excluded": [],
        }

    if request.status == STATUS_COLLECTING or request.stage1 is None or not request.stage1.valid:
        stage: int = 1
        retained: Iterable[str] = ()
    else:
        stage = 2
        retained = request.stage1.proof_ids if request.stage1 else ()

    try:
        evaluation = adjudicate(state, request, stage, now=request.last_now, retained_ids=retained)
    except CaseError as exc:
        return {
            "satisfied": False,
            "stage": stage,
            "recipe_id": None,
            "failures": [exc.to_dict()],
            "excluded": [],
        }
    return {
        "satisfied": evaluation.satisfied,
        "stage": stage,
        "policy_version": evaluation.policy_version,
        "recipe_id": evaluation.recipe_id,
        "failures": evaluation.failures,
        "excluded": evaluation.excluded,
    }


# --------------------------------------------------------------------------
# Other commands
# --------------------------------------------------------------------------


def verify(store: EventStore) -> dict[str, Any]:
    """Re-fold history and check that every stored artifact still matches."""
    problems: list[dict[str, Any]] = []
    batches = store.all_batches()
    for batch in batches:
        batch_no = int(batch["batch_no"])
        stored = json.loads(batch["result_json"])
        if stored.get("commit") != batch_no:
            problems.append(
                {
                    "code": E_VERIFY_COMMIT,
                    "path": f"batches[{batch_no}].result_json",
                    "message": "stored commit number does not match the batch number",
                }
            )
        if stored.get("batch_key") != batch["batch_key"]:
            problems.append(
                {
                    "code": E_VERIFY_KEY,
                    "path": f"batches[{batch_no}].batch_key",
                    "message": "stored batch key does not match the batch row",
                }
            )
        for event in store.events_for_batch(batch_no):
            if digest(json.loads(event.payload_json)) != event.payload_digest:
                problems.append(
                    {
                        "code": E_VERIFY_DIGEST,
                        "path": f"events[{event.seq}].payload_digest",
                        "message": "stored payload digest does not match its payload",
                    }
                )
    for row in store.receipts_upto(None):
        payload = json.loads(row["payload_json"])
        if receipt_digest(payload) != payload.get("digest"):
            problems.append(
                {
                    "code": E_VERIFY_RECEIPT,
                    "path": f"receipts[{payload.get('receipt_id')}].digest",
                    "message": "stored receipt digest does not match its payload",
                }
            )
        if payload.get("receipt_id") != row["receipt_id"]:
            problems.append(
                {
                    "code": E_VERIFY_RECEIPT,
                    "path": f"receipts[{row['receipt_id']}].receipt_id",
                    "message": "receipt id does not match the stored row",
                }
            )
    state, _ = replay(store)
    return {
        "schema": SCHEMA_NAME,
        "kind": "verify",
        "ok": not problems,
        "batches": len(batches),
        "requests": len(state.requests),
        "receipts": len(state.receipts),
        "problems": problems,
    }


def state_report(store: EventStore, commit: int | None = None) -> dict[str, Any]:
    if commit is None:
        batches = store.all_batches()
        commit = int(batches[-1]["batch_no"]) if batches else 0
    state, _ = replay(store, upto_batch=commit if commit else None)
    return {
        "schema": SCHEMA_NAME,
        "kind": "state",
        "commit": commit,
        "requests": {rid: state.describe_request(rid) for rid in sorted(state.requests)},
    }


def read_json(path: str) -> Any:
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise CaseError(E_IO, "case", f"cannot read case file: {exc}") from exc
    try:
        return load_json_bytes(raw)
    except UnicodeDecodeError as exc:
        raise CaseError(E_JSON_PARSE, "case", f"case file is not valid UTF-8: {exc}") from exc
    except ValueError as exc:
        raise CaseError(E_JSON_PARSE, "case", f"case file is not valid JSON: {exc}") from exc
