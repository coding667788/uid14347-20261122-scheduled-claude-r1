"""Locatable error objects.

Structural errors carry an ``E_SCHEMA_*`` (or parse) code plus a JSON-path
like ``events[2].token.to_generation``.  Domain rejections carry an
``E_*`` code and, where one event is responsible, the event path.
"""

from __future__ import annotations

from typing import Any


class CaseError(Exception):
    """An error that renders as a locatable JSON document."""

    def __init__(
        self,
        code: str,
        path: str,
        message: str,
        *,
        event_id: str | None = None,
        detail: Any = None,
    ):
        super().__init__(message)
        self.code = code
        self.path = path
        self.message = message
        self.event_id = event_id
        self.detail = detail

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "code": self.code,
            "path": self.path,
            "message": self.message,
        }
        if self.event_id is not None:
            body["event_id"] = self.event_id
        if self.detail is not None:
            body["detail"] = self.detail
        return body

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"CaseError({self.code!r}, {self.path!r}, {self.message!r})"


# Structural ---------------------------------------------------------------
E_JSON_PARSE = "E_JSON_PARSE"
E_SCHEMA_TYPE = "E_SCHEMA_TYPE"
E_SCHEMA_MISSING = "E_SCHEMA_MISSING"
E_SCHEMA_ENUM = "E_SCHEMA_ENUM"
E_SCHEMA_RANGE = "E_SCHEMA_RANGE"
E_SCHEMA_UNKNOWN = "E_SCHEMA_UNKNOWN"
E_SCHEMA_DUPLICATE = "E_SCHEMA_DUPLICATE"
E_SCHEMA_EMPTY = "E_SCHEMA_EMPTY"
E_SCHEMA_CONFLICT = "E_SCHEMA_CONFLICT"

# CLI ----------------------------------------------------------------------
E_USAGE = "E_USAGE"
E_IO = "E_IO"
E_DB = "E_DB"

# Batch / idempotency ------------------------------------------------------
E_EVENT_CONFLICT = "E_EVENT_CONFLICT"
E_EVENT_DUPLICATE_IN_BATCH = "E_EVENT_DUPLICATE_IN_BATCH"
E_BATCH_CYCLE = "E_BATCH_CYCLE"
E_BATCH_REJECTED = "E_BATCH_REJECTED"
E_BATCH_OUT_OF_ORDER = "E_BATCH_OUT_OF_ORDER"
E_POLICY_TOO_COMPLEX = "E_POLICY_TOO_COMPLEX"
E_VERIFY_COMMIT = "E_VERIFY_COMMIT"
E_VERIFY_KEY = "E_VERIFY_KEY"
E_VERIFY_DIGEST = "E_VERIFY_DIGEST"
E_VERIFY_RECEIPT = "E_VERIFY_RECEIPT"
E_FAULT_AFTER_COMMIT = "E_FAULT_AFTER_COMMIT"

# Domain -------------------------------------------------------------------
E_REQUEST_EXISTS = "E_REQUEST_EXISTS"
E_REQUEST_NOT_FOUND = "E_REQUEST_NOT_FOUND"
E_REQUEST_REVOKED = "E_REQUEST_REVOKED"
E_REQUEST_ISSUED = "E_REQUEST_ISSUED"
E_POLICY_NOT_FOUND = "E_POLICY_NOT_FOUND"
E_POLICY_CONFLICT = "E_POLICY_CONFLICT"
E_CHALLENGE_NOT_FOUND = "E_CHALLENGE_NOT_FOUND"
E_CHALLENGE_CLOSED = "E_CHALLENGE_CLOSED"
E_CHALLENGE_EXPIRED = "E_CHALLENGE_EXPIRED"
E_PROOF_EXISTS = "E_PROOF_EXISTS"
E_PROOF_EXPIRED = "E_PROOF_EXPIRED"
E_PROOF_GENERATION_MISMATCH = "E_PROOF_GENERATION_MISMATCH"
E_PROOF_CHALLENGE_MISMATCH = "E_PROOF_CHALLENGE_MISMATCH"
E_PROOF_STAGE_MISMATCH = "E_PROOF_STAGE_MISMATCH"
E_PROOF_UNTRUSTED = "E_PROOF_UNTRUSTED"
E_PROOF_ALREADY_CONSUMED = "E_PROOF_ALREADY_CONSUMED"
E_PROOF_REVOKED = "E_PROOF_REVOKED"
E_PROOF_NOT_FOUND = "E_PROOF_NOT_FOUND"
E_STAGE2_NOT_OPEN = "E_STAGE2_NOT_OPEN"
E_STAGE1_NOT_COMPLETE = "E_STAGE1_NOT_COMPLETE"
E_STAGE1_NOT_SATISFIED = "E_STAGE1_NOT_SATISFIED"
E_STAGE2_NOT_SATISFIED = "E_STAGE2_NOT_SATISFIED"
E_TOKEN_NOT_FOUND = "E_TOKEN_NOT_FOUND"
E_TOKEN_ALREADY_CONSUMED = "E_TOKEN_ALREADY_CONSUMED"
E_TOKEN_CONFLICT = "E_TOKEN_CONFLICT"
E_TOKEN_CHALLENGE_MISMATCH = "E_TOKEN_CHALLENGE_MISMATCH"
E_TOKEN_GENERATION_MISMATCH = "E_TOKEN_GENERATION_MISMATCH"
E_TOKEN_SKIPS_GENERATION = "E_TOKEN_SKIPS_GENERATION"
E_TOKEN_REUSED_GENERATION = "E_TOKEN_REUSED_GENERATION"
E_MIGRATION_LIMIT = "E_MIGRATION_LIMIT"
E_TOKEN_RESOURCE_MISMATCH = "E_TOKEN_RESOURCE_MISMATCH"
E_TOKEN_POLICY_MISMATCH = "E_TOKEN_POLICY_MISMATCH"
E_TOKEN_PREDECESSOR_MISMATCH = "E_TOKEN_PREDECESSOR_MISMATCH"
E_TOKEN_EXPIRED = "E_TOKEN_EXPIRED"
E_TOKEN_UNTRUSTED = "E_TOKEN_UNTRUSTED"
E_MIGRATION_AFTER_ISSUE = "E_MIGRATION_AFTER_ISSUE"
E_MIGRATION_RECEIPT_MISMATCH = "E_MIGRATION_RECEIPT_MISMATCH"
E_PRESERVE_PRECONDITION = "E_PRESERVE_PRECONDITION"
E_RISK_DOWNGRADE = "E_RISK_DOWNGRADE"
E_RISK_UNCHANGED = "E_RISK_UNCHANGED"
E_TIME_REGRESSION = "E_TIME_REGRESSION"
E_BINDING_MISMATCH = "E_BINDING_MISMATCH"
E_INJECTED_FAULT = "E_INJECTED_FAULT"
E_INTERNAL = "E_INTERNAL"
E_COMMIT_NOT_FOUND = "E_COMMIT_NOT_FOUND"

STRUCTURAL_CODES = {
    E_JSON_PARSE,
    E_SCHEMA_TYPE,
    E_SCHEMA_MISSING,
    E_SCHEMA_ENUM,
    E_SCHEMA_RANGE,
    E_SCHEMA_UNKNOWN,
    E_SCHEMA_DUPLICATE,
    E_SCHEMA_EMPTY,
    E_SCHEMA_CONFLICT,
    E_USAGE,
    E_IO,
}

# Exit status per class.  The JSON document on stdout is authoritative; the
# process status is only a convenience for shells and tests.
EXIT_OK = 0
EXIT_STRUCTURAL = 2
EXIT_REJECTED = 3
EXIT_FAULT = 4
EXIT_INTERNAL = 5
