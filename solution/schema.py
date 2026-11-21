"""Structural validation with locatable JSON paths.

Validation is intentionally explicit rather than declarative: every rejection
names the exact field that failed so callers never have to guess.
"""

from __future__ import annotations

from typing import Any, Iterable

from .errors import (
    CaseError,
    E_SCHEMA_DUPLICATE,
    E_SCHEMA_EMPTY,
    E_SCHEMA_ENUM,
    E_SCHEMA_MISSING,
    E_SCHEMA_RANGE,
    E_SCHEMA_TYPE,
    E_SCHEMA_UNKNOWN,
)

MISSING = object()

FACTOR_KINDS = ("device", "human")
STAGES = (1, 2)
RISK_LEVELS = ("low", "high")
PROOF_STATUSES = ("active", "revoked")
REQUEST_STATUSES = ("collecting", "stage1_complete", "issued", "revoked", "failed")

_ID_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-/#@")


def join(path: str, key: str | int) -> str:
    if isinstance(key, int):
        return f"{path}[{key}]"
    return f"{path}.{key}" if path else key


def expect_object(value: Any, path: str, required: Iterable[str], optional: Iterable[str] = (), *, allow_extra: bool = False) -> None:
    if not isinstance(value, dict):
        raise CaseError(E_SCHEMA_TYPE, path, "expected a JSON object")
    required = list(required)
    optional = list(optional)
    for key in required:
        if key not in value:
            raise CaseError(E_SCHEMA_MISSING, join(path, key), "required field is missing")
    if not allow_extra:
        allowed = set(required) | set(optional)
        for key in value:
            if key not in allowed:
                raise CaseError(E_SCHEMA_UNKNOWN, join(path, key), "unknown field")
    for key in value:
        if not isinstance(key, str):
            raise CaseError(E_SCHEMA_TYPE, path, "object keys must be strings")


def expect_list(value: Any, path: str, *, non_empty: bool = False) -> list[Any]:
    if not isinstance(value, list):
        raise CaseError(E_SCHEMA_TYPE, path, "expected a JSON array")
    if non_empty and not value:
        raise CaseError(E_SCHEMA_EMPTY, path, "array must not be empty")
    return value


def expect_str(value: Any, path: str, *, non_empty: bool = True, max_len: int = 256) -> str:
    if not isinstance(value, str):
        raise CaseError(E_SCHEMA_TYPE, path, "expected a string")
    if non_empty and value == "":
        raise CaseError(E_SCHEMA_EMPTY, path, "string must not be empty")
    if len(value) > max_len:
        raise CaseError(E_SCHEMA_RANGE, path, f"string longer than {max_len} characters")
    return value


def expect_id(value: Any, path: str) -> str:
    text = expect_str(value, path)
    bad = [ch for ch in text if ch not in _ID_CHARS]
    if bad:
        raise CaseError(E_SCHEMA_ENUM, path, "identifier contains unsupported characters")
    return text


def expect_bool(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise CaseError(E_SCHEMA_TYPE, path, "expected a boolean")
    return value


def expect_int(value: Any, path: str, *, minimum: int | None = None, maximum: int | None = None) -> int:
    # bool is an int subclass; reject it explicitly so ``true`` is not a time.
    if isinstance(value, bool) or not isinstance(value, int):
        raise CaseError(E_SCHEMA_TYPE, path, "expected an integer")
    if minimum is not None and value < minimum:
        raise CaseError(E_SCHEMA_RANGE, path, f"must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise CaseError(E_SCHEMA_RANGE, path, f"must be <= {maximum}")
    return value


def expect_str_list(value: Any, path: str, *, non_empty: bool = True, unique: bool = True) -> list[str]:
    items = expect_list(value, path, non_empty=non_empty)
    seen: set[str] = set()
    out: list[str] = []
    for index, item in enumerate(items):
        text = expect_id(item, join(path, index))
        if unique and text in seen:
            raise CaseError(E_SCHEMA_DUPLICATE, join(path, index), f"duplicate identifier {text!r}")
        seen.add(text)
        out.append(text)
    return out


def expect_enum(value: Any, path: str, allowed: Iterable[Any]) -> Any:
    allowed = list(allowed)
    if isinstance(value, str) and value not in [a for a in allowed if isinstance(a, str)]:
        raise CaseError(E_SCHEMA_ENUM, path, f"expected one of {allowed!r}")
    if not any(type(value) is type(a) and value == a for a in allowed):
        raise CaseError(E_SCHEMA_ENUM, path, f"expected one of {allowed!r}")
    return value


def warn_unknown_keys(value: dict[str, Any], path: str, known: Iterable[str]) -> list[dict[str, str]]:
    known_set = set(known)
    return [
        {"code": E_SCHEMA_UNKNOWN, "path": join(path, key), "message": "unknown field ignored"}
        for key in sorted(value)
        if key not in known_set
    ]
