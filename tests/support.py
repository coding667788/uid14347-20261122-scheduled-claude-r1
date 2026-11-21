"""Shared test scaffolding: temp databases, in-process CLI, assertions."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from typing import Any

from solution.ledger import apply_case, parse_case
from solution.store import EventStore

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(REPO_ROOT, "examples")


class LedgerTestCase(unittest.TestCase):
    """Base class giving every test an isolated database and apply helper."""

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp(prefix="ledger-test-")
        self.addCleanup(shutil.rmtree, self._tmp, True)
        self._counter = 0

    def db_path(self, name: str | None = None) -> str:
        if name is None:
            self._counter += 1
            name = f"db-{self._counter}.sqlite"
        return os.path.join(self._tmp, name)

    # -- applying ----------------------------------------------------------
    def apply(self, case: dict[str, Any], db: str | None = None) -> dict[str, Any]:
        db = db or self.db_path()
        parsed = parse_case(case)
        with EventStore(db) as store:
            return apply_case(store, parsed)

    def apply_expect_error(self, case: dict[str, Any], db: str | None = None) -> Any:
        from solution.errors import CaseError

        db = db or self.db_path()
        with self.assertRaises(CaseError) as ctx:
            parsed = parse_case(case)
            with EventStore(db) as store:
                apply_case(store, parsed)
        return ctx.exception

    def apply_chain(self, *cases: dict[str, Any], db: str | None = None) -> list[dict[str, Any]]:
        db = db or self.db_path()
        results = []
        for case in cases:
            parsed = parse_case(case)
            with EventStore(db) as store:
                results.append(apply_case(store, parsed))
        return results

    def explain(self, db: str, commit: int | None = None) -> dict[str, Any]:
        from solution.ledger import explain

        with EventStore(db, writable=False) as store:
            return explain(store, commit)

    def state(self, db: str, commit: int | None = None) -> dict[str, Any]:
        from solution.ledger import state_report

        with EventStore(db, writable=False) as store:
            return state_report(store, commit)

    # -- CLI ---------------------------------------------------------------
    def run_cli(self, *args: str) -> tuple[int, dict[str, Any], bytes]:
        """Run ``python -m solution`` in a subprocess; return (code, json, raw)."""
        completed = subprocess.run(
            [sys.executable, "-m", "solution", *args],
            cwd=REPO_ROOT,
            capture_output=True,
            check=False,
        )
        raw = completed.stdout
        try:
            document = json.loads(raw.decode("utf-8"))
        except Exception as exc:  # pragma: no cover - diagnostic path
            self.fail(f"stdout was not JSON ({exc}): {raw!r} stderr={completed.stderr!r}")
        return completed.returncode, document, raw

    def write_case(self, case: dict[str, Any], name: str = "case.json") -> str:
        path = os.path.join(self._tmp, name)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(case, handle, ensure_ascii=False, indent=2)
        return path
