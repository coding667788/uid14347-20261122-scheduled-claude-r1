"""Canonical JSON encoding and deterministic digests.

Every digest in the ledger is derived from this canonical form, so the same
logical value always produces the same digest and therefore the same receipt
identifier on every platform.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    """Return the canonical, key-sorted, whitespace-free JSON text."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def digest(value: Any) -> str:
    """Return ``sha256:<hex>`` for the canonical encoding of *value*."""
    payload = canonical_json(value).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def short_id(prefix: str, value: Any, length: int = 24) -> str:
    """Derive a stable, readable identifier from *value*."""
    payload = canonical_json(value).encode("utf-8")
    return prefix + hashlib.sha256(payload).hexdigest()[:length]


def load_json_bytes(raw: bytes) -> Any:
    """Decode UTF-8 JSON with strict duplicate-key rejection."""
    text = raw.decode("utf-8-sig")

    def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate object key: {key}")
            out[key] = value
        return out

    return json.loads(text, object_pairs_hook=_pairs)
