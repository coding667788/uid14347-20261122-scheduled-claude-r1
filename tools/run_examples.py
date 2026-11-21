"""Run the example cases end to end and print a short report.

Usage (from the repository root):

    python tools/run_examples.py [--db-dir DIR]

Each example is applied against its own database, except the migration chain
(03 -> 04 -> 05), which is deliberately applied to one database so the chain
rules can be seen across commits.  Exit status is non-zero if any example
produced a different outcome than the one documented in README.md.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(ROOT, "examples")

# Each entry: (label, case file, expected exit code, expected error code or None)
SINGLE: list[tuple[str, str, int, str | None]] = [
    ("01 low risk issuance", "01_low_risk_issuance.json", 0, None),
    ("02 high risk two stage", "02_high_risk_two_stage.json", 0, None),
    ("06 migration drops stage 1", "06_migration_drops_stage1.json", 0, None),
    ("07 policy upgrade rollback", "07_policy_upgrade_rollback.json", 0, None),
    ("08 group independence", "08_group_independence_failure.json", 3, "E_STAGE1_NOT_SATISFIED"),
    ("09 conflicting event ids", "09_conflict_rejected_batch.json", 3, "E_EVENT_DUPLICATE_IN_BATCH"),
    ("10 crash after commit", "10_crash_after_commit.json", 4, "E_FAULT_AFTER_COMMIT"),
    ("11 duplicate batch retry", "11_duplicate_batch_retry.json", 0, None),
    ("12 expired challenge", "12_expired_challenge.json", 3, "E_CHALLENGE_EXPIRED"),
    ("13 risk upgrade", "13_risk_upgrade.json", 0, None),
    ("14 structural error", "14_structural_error.json", 2, "E_SCHEMA_ENUM"),
]

CHAIN = [
    ("03 migration step 1", "03_migration_step1_preserve.json"),
    ("04 migration step 2", "04_migration_step2_chain.json"),
    ("05 migration back to origin", "05_migration_back_to_origin.json"),
    ("05b stale ticket rejected", "05b_stale_ticket_rejected.json"),
    ("05a chain stage-2 issuance", "05a_chain_stage2_issuance.json"),
]


def run(command: list[str]) -> tuple[int, dict[str, Any]]:
    completed = subprocess.run(
        [sys.executable, "-m", "solution", *command],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    try:
        document = json.loads(completed.stdout.decode("utf-8"))
    except Exception:  # pragma: no cover - diagnostic only
        raise SystemExit(
            f"command {command} did not emit JSON\n"
            f"stdout={completed.stdout!r}\nstderr={completed.stderr.decode('utf-8', 'replace')}"
        )
    return completed.returncode, document


def describe(document: dict[str, Any]) -> str:
    if not document.get("ok"):
        error = document["error"]
        return f"rejected {error['code']} at {error['path']}"
    notes = []
    for event in document["events"]:
        outcome = event.get("outcome")
        if outcome:
            notes.append(f"{event['type']}={outcome}")
    receipts = len(document.get("receipts", []))
    return f"commit {document['commit']}, {receipts} receipt(s)" + (
        f", {', '.join(notes)}" if notes else ""
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-dir", default=None, help="directory for the example databases")
    args = parser.parse_args(argv)

    db_dir = args.db_dir or tempfile.mkdtemp(prefix="challenge-ledger-examples-")
    os.makedirs(db_dir, exist_ok=True)
    failures = 0

    for label, name, expected_code, expected_error in SINGLE:
        db = os.path.join(db_dir, name.replace(".json", ".sqlite"))
        if os.path.exists(db):
            os.remove(db)
        code, document = run(["apply", os.path.join(EXAMPLES, name), "--db", db])
        status = "ok" if code == expected_code else "EXIT MISMATCH"
        if code != expected_code:
            failures += 1
        if expected_error is not None and document.get("error", {}).get("code") != expected_error:
            status = "ERROR CODE MISMATCH"
            failures += 1
        print(f"{label:34s} exit={code} {status:12s} {describe(document)}")

    chain_db = os.path.join(db_dir, "chain.sqlite")
    for suffix in ("", "-wal", "-shm"):
        with_suffix = chain_db + suffix
        if os.path.exists(with_suffix):
            os.remove(with_suffix)
    expected_chain = {
        "05b_stale_ticket_rejected.json": (3, "E_TOKEN_ALREADY_CONSUMED"),
    }
    for label, name in CHAIN:
        code, document = run(["apply", os.path.join(EXAMPLES, name), "--db", chain_db])
        want_code, want_error = expected_chain.get(name, (0, None))
        ok = code == want_code and (want_error is None or document.get("error", {}).get("code") == want_error)
        if not ok:
            failures += 1
        marker = "ok" if ok else "MISMATCH"
        print(f"{label:34s} exit={code} {marker:10s} {describe(document)}")

    code, document = run(["explain", "--db", chain_db])
    if code != 0:
        failures += 1
        print("chain explain failed:", document)
    else:
        request = document["requests"]["REQ-1"]
        print(
            f"chain explain: commit {document['commit']}, status={request['status']}, "
            f"generation={request['generation']}, org={request['org']}, "
            f"migrations={[m['step'] for m in request['migrations']]}"
        )

    code, document = run(["verify", "--db", chain_db])
    print(f"verify: ok={document.get('ok')} batches={document.get('batches')}")

    if args.db_dir is None:
        shutil.rmtree(db_dir, ignore_errors=True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
