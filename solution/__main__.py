"""``python -m solution <command> CASE.json [--db DB.sqlite]``.

Every command prints exactly one UTF-8 JSON document to stdout and nothing
else.  Diagnostics go to stderr only when the process itself misbehaves; a
rejected case is still a JSON document on stdout with a non-zero exit status.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from . import SCHEMA, __version__
from .canonical import canonical_json
from .errors import (
    EXIT_FAULT,
    EXIT_INTERNAL,
    EXIT_OK,
    EXIT_REJECTED,
    EXIT_STRUCTURAL,
    STRUCTURAL_CODES,
    CaseError,
    E_FAULT_AFTER_COMMIT,
    E_INTERNAL,
    E_USAGE,
)
from .ledger import (
    AfterCommitFault,
    apply_case,
    explain,
    parse_case,
    read_json,
    replay,
    state_report,
    verify,
)
from .store import EventStore

USAGE = "python -m solution <apply|explain|state|verify|version> [CASE.json] [--db DB.sqlite] [--commit N]"

PERSISTENT = {"apply", "explain", "state", "verify"}


def _parse_argv(argv: list[str]) -> tuple[str, dict[str, Any]]:
    if not argv:
        raise CaseError(E_USAGE, "argv", f"no command given; usage: {USAGE}")
    command = argv[0]
    options: dict[str, Any] = {"case": None, "db": None, "commit": None, "help": False}
    rest = argv[1:]
    index = 0
    while index < len(rest):
        arg = rest[index]
        if arg == "--help" or arg == "-h":
            options["help"] = True
        elif arg == "--db":
            index += 1
            if index >= len(rest):
                raise CaseError(E_USAGE, "argv", "--db requires a path")
            options["db"] = rest[index]
        elif arg.startswith("--db="):
            options["db"] = arg.split("=", 1)[1]
        elif arg == "--commit":
            index += 1
            if index >= len(rest):
                raise CaseError(E_USAGE, "argv", "--commit requires a batch number")
            options["commit"] = _int_arg(rest[index], "argv")
        elif arg.startswith("--commit="):
            options["commit"] = _int_arg(arg.split("=", 1)[1], "argv")
        elif arg.startswith("-"):
            raise CaseError(E_USAGE, "argv", f"unknown option {arg!r}")
        else:
            if options["case"] is not None:
                raise CaseError(E_USAGE, "argv", "only one case file may be supplied")
            options["case"] = arg
        index += 1
    return command, options


def _int_arg(text: str, path: str) -> int:
    try:
        return int(text, 10)
    except ValueError as exc:
        raise CaseError(E_USAGE, path, f"expected an integer, got {text!r}") from exc


def _emit(document: dict[str, Any]) -> None:
    # Write UTF-8 JSON directly: stdout may be a pipe with a non-UTF-8 locale.
    data = canonical_json(document) + "\n"
    sys.stdout.buffer.write(data.encode("utf-8"))
    sys.stdout.buffer.flush()


def _error_document(exc: CaseError) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "ok": False,
        "error": exc.to_dict(),
    }


def _exit_code(exc: CaseError) -> int:
    if exc.code in STRUCTURAL_CODES:
        return EXIT_STRUCTURAL
    return EXIT_REJECTED


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        command, options = _parse_argv(argv)
    except CaseError as exc:
        _emit(_error_document(exc))
        return _exit_code(exc)

    if command in ("version", "--version", "-V"):
        _emit({"schema": SCHEMA, "kind": "version", "version": __version__})
        return EXIT_OK
    if command in ("help", "--help", "-h") or options["help"]:
        _emit({"schema": SCHEMA, "kind": "help", "usage": USAGE, "commands": sorted(PERSISTENT | {"version"})})
        return EXIT_OK
    if command not in PERSISTENT:
        exc = CaseError(E_USAGE, "argv", f"unknown command {command!r}; usage: {USAGE}")
        _emit(_error_document(exc))
        return _exit_code(exc)

    try:
        if command == "apply":
            if not options["case"]:
                raise CaseError(E_USAGE, "argv", "apply requires a case file")
            if not options["db"]:
                raise CaseError(E_USAGE, "argv", "apply requires --db DB.sqlite")
            document = read_json(options["case"])
            case = parse_case(document)
            with EventStore(options["db"]) as store:
                result = apply_case(store, case)
            _emit({"schema": SCHEMA, "ok": True, **result})
            return EXIT_OK

        if command == "explain":
            _require_db(options, "explain")
            with EventStore(options["db"], writable=False) as store:
                result = explain(store, options["commit"])
            _emit({"schema": SCHEMA, "ok": True, **result})
            return EXIT_OK

        if command == "state":
            _require_db(options, "state")
            with EventStore(options["db"], writable=False) as store:
                result = state_report(store, options["commit"])
            _emit({"schema": SCHEMA, "ok": True, **result})
            return EXIT_OK

        if command == "verify":
            _require_db(options, "verify")
            with EventStore(options["db"], writable=False) as store:
                result = verify(store)
            _emit({"schema": SCHEMA, "ok": bool(result["ok"]), **result})
            # A failed verification is a finding, not a successful run.
            return EXIT_OK if result["ok"] else EXIT_REJECTED
    except AfterCommitFault as fault:
        # The transaction committed; the process "died" before answering.
        # Emitting the stored result on retry is what makes this idempotent.
        _emit(
            {
                "schema": SCHEMA,
                "ok": False,
                "error": {
                    "code": E_FAULT_AFTER_COMMIT,
                    "path": "events",
                    "message": str(fault),
                    "detail": {"commit": fault.batch_no, "committed": True},
                },
                "commit": fault.batch_no,
            }
        )
        return EXIT_FAULT
    except CaseError as exc:
        _emit(_error_document(exc))
        return _exit_code(exc)
    except Exception as exc:  # pragma: no cover - last-resort guard
        _emit(
            {
                "schema": SCHEMA,
                "ok": False,
                "error": {
                    "code": E_INTERNAL,
                    "path": "internal",
                    "message": f"{type(exc).__name__}: {exc}",
                },
            }
        )
        return EXIT_INTERNAL
    return EXIT_OK


def _require_db(options: dict[str, Any], command: str) -> None:
    if not options["db"]:
        raise CaseError(E_USAGE, "argv", f"{command} requires --db DB.sqlite")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
