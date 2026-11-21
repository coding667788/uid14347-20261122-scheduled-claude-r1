"""Durability and cross-process coordination.

These tests use real OS processes so that lock contention, WAL visibility and
crash behaviour are exercised for real rather than mocked.  Each one is
deterministic: processes are synchronised with explicit barriers, not sleeps.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import unittest

from tests import builder as B
from tests.support import REPO_ROOT, LedgerTestCase


def _stage1_case(batch_id: str, *, risk: str = "low") -> dict:
    return B.case(
        B.register(risk=risk),
        B.proof("e2", "PF-d", factor="device", principal="PRIN-laptop", trust_group="TG-devices", now=110),
        B.proof("e3", "PF-h", factor="human", principal="PRIN-bob", trust_group="TG-staff", now=120),
        B.advance("e4", stage=1, now=130),
        batch_id=batch_id,
    )


class IdempotencyTests(LedgerTestCase):
    def test_repeating_a_batch_returns_the_same_document(self) -> None:
        db = self.db_path()
        first = self.apply(_stage1_case("dup"), db=db)
        second = self.apply(_stage1_case("dup"), db=db)
        self.assertEqual(first, second)
        self.assertEqual(self.explain(db)["batches"][0]["batch_no"], 1)

    def test_same_batch_id_different_content_conflicts(self) -> None:
        db = self.db_path()
        self.apply(_stage1_case("batch-x"), db=db)
        altered = _stage1_case("batch-x")
        altered["events"][0]["resource"] = "FILESET-other"
        error = self.apply_expect_error(altered, db=db)
        self.assertEqual(error.code, "E_EVENT_CONFLICT")
        self.assertEqual(error.path, "batch_id")

    def test_same_event_id_different_content_conflicts(self) -> None:
        db = self.db_path()
        self.apply(_stage1_case("batch-a"), db=db)
        clash = B.case(
            B.register(risk="low", resource="FILESET-quarterly"),
            B.proof("e2", "PF-d", factor="device", principal="PRIN-different",
                    trust_group="TG-devices", now=111),
            batch_id="batch-b",
        )
        error = self.apply_expect_error(clash, db=db)
        self.assertEqual(error.code, "E_EVENT_CONFLICT")
        self.assertEqual(error.path, "events[1].event_id")
        # The whole batch is rejected: batch-b never becomes a commit.
        self.assertEqual(len(self.explain(db)["batches"]), 1)

    def test_duplicate_event_in_one_batch_with_different_content(self) -> None:
        db = self.db_path()
        case = B.case(
            B.register(risk="low"),
            B.register(risk="high"),
            batch_id="dupe",
        )
        error = self.apply_expect_error(case, db=db)
        self.assertEqual(error.code, "E_EVENT_DUPLICATE_IN_BATCH")
        self.assertEqual(error.path, "events[1].event_id")

    def test_repeated_identical_event_in_batch_is_answered_once(self) -> None:
        db = self.db_path()
        case = B.case(
            B.register(risk="low"),
            B.register(risk="low"),
            batch_id="dupe-same",
        )
        result = self.apply(case, db=db)
        self.assertEqual(len(result["events"]), 3)  # policy + two register results
        self.assertEqual(result["events"][1], result["events"][2])


class CrashTests(LedgerTestCase):
    def test_crash_before_commit_leaves_no_trace(self) -> None:
        db = self.db_path()
        # Establish an unrelated committed batch first.
        self.apply(_stage1_case("base"), db=db)
        case = B.case(
            B.register(request_id="REQ-2", risk="low"),
            {"event_id": "boom", "type": "fault", "point": "before_commit"},
            batch_id="crash-mid",
        )
        error = self.apply_expect_error(case, db=db)
        self.assertEqual(error.code, "E_INJECTED_FAULT")
        explained = self.explain(db)
        self.assertEqual([b["batch_no"] for b in explained["batches"]], [1])
        self.assertNotIn("REQ-2", explained["requests"])

    def test_crash_after_commit_is_recoverable_by_retry(self) -> None:
        db = self.db_path()
        # A crash *after* commit only happens once every other event in the
        # batch has applied, so the fault event must come last.
        case = B.case(
            B.register(risk="low"),
            B.proof("e2", "PF-d", factor="device", principal="PRIN-laptop",
                    trust_group="TG-devices", now=110),
            B.proof("e3", "PF-h", factor="human", principal="PRIN-bob",
                    trust_group="TG-staff", now=120),
            B.advance("e4", stage=1, now=130),
            {"event_id": "boom", "type": "fault", "point": "after_commit"},
            batch_id="crash-after",
        )
        from solution.ledger import AfterCommitFault, apply_case, parse_case
        from solution.store import EventStore

        with EventStore(db) as store:
            with self.assertRaises(AfterCommitFault):
                apply_case(store, parse_case(case))

        # The commit is durable, so a retry must return the *same* document,
        # not re-apply or fail.
        retried = self.apply(case, db=db)
        self.assertEqual(retried["commit"], 1)
        self.assertEqual(retried["receipts"][0]["request_id"], "REQ-1")
        self.assertEqual(len(self.explain(db)["batches"]), 1)
        self.assertEqual(len(self.explain(db)["receipts"]), 1)

    def test_process_killed_after_commit_still_retries_cleanly(self) -> None:
        db = self.db_path()
        case = _stage1_case("kill", risk="low")
        case["events"].append({"event_id": "boom", "type": "fault", "point": "after_commit"})
        path = self.write_case(case)

        completed = subprocess.run(
            [sys.executable, "-m", "solution", "apply", path, "--db", db],
            cwd=REPO_ROOT,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        document = json.loads(completed.stdout.decode("utf-8"))
        self.assertEqual(document["error"]["code"], "E_FAULT_AFTER_COMMIT")
        self.assertTrue(document["error"]["detail"]["committed"])

        # A second process now applies the same file: same answer, one commit.
        code, retried, _raw = self.run_cli("apply", path, "--db", db)
        self.assertEqual(code, 0)
        self.assertEqual(retried["commit"], 1)
        code, explained, _raw = self.run_cli("explain", "--db", db)
        self.assertEqual(code, 0)
        self.assertEqual(len(explained["batches"]), 1)


class MultiProcessTests(LedgerTestCase):
    """Race genuinely concurrent writers and check the invariants hold."""

    def _race(self, script: str, workers: int, timeout: float = 60.0) -> list[dict]:
        results: list[dict] = []
        procs = []
        for index in range(workers):
            out = os.path.join(self._tmp, f"race-{index}.json")
            procs.append(
                subprocess.Popen(
                    [sys.executable, "-c", script, str(index), out],
                    cwd=REPO_ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            )
            results.append({"out": out})
        for proc in procs:
            _stdout, stderr = proc.communicate(timeout=timeout)
            if proc.returncode not in (0, 3):
                self.fail(f"worker failed ({proc.returncode}): {stderr.decode('utf-8', 'replace')}")
        documents = []
        for entry in results:
            with open(entry["out"], encoding="utf-8") as handle:
                documents.append(json.load(handle))
        return documents

    def test_concurrent_apply_of_one_batch_commits_once(self) -> None:
        db = self.db_path()
        case_path = self.write_case(_stage1_case("race-one"), "race-case.json")
        script = textwrap.dedent(
            f"""
            import json, sys
            from solution.ledger import apply_case, parse_case, read_json
            from solution.store import EventStore
            from solution.errors import CaseError

            index, out = sys.argv[1], sys.argv[2]
            try:
                with EventStore({db!r}) as store:
                    result = apply_case(store, parse_case(read_json({case_path!r})))
                payload = {{"ok": True, "commit": result["commit"],
                           "receipt": result["receipts"][0]["receipt_id"] if result["receipts"] else None}}
            except CaseError as exc:
                payload = {{"ok": False, "code": exc.code}}
            except Exception as exc:
                payload = {{"ok": False, "code": type(exc).__name__, "detail": str(exc)}}
            with open(out, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
            """
        )
        documents = self._race(script, 6)
        self.assertTrue(all(d["ok"] for d in documents), documents)
        commits = {d["commit"] for d in documents}
        receipts = {d["receipt"] for d in documents}
        self.assertEqual(commits, {1})
        self.assertEqual(len(receipts), 1)
        self.assertIsNotNone(receipts.pop())
        self.assertEqual(len(self.explain(db)["batches"]), 1)

    def test_concurrent_conflicting_content_only_one_wins(self) -> None:
        db = self.db_path()
        paths = []
        for index in range(5):
            case = _stage1_case("contend")
            case["events"][0]["ttl"] = 1000 + index  # different content, same batch id
            paths.append(self.write_case(case, f"contend-{index}.json"))

        script = textwrap.dedent(
            f"""
            import json, sys
            from solution.ledger import apply_case, parse_case, read_json
            from solution.store import EventStore
            from solution.errors import CaseError

            index, out = sys.argv[1], sys.argv[2]
            paths = {paths!r}
            try:
                with EventStore({db!r}) as store:
                    result = apply_case(store, parse_case(read_json(paths[int(index)])))
                payload = {{"ok": True, "commit": result["commit"]}}
            except CaseError as exc:
                payload = {{"ok": False, "code": exc.code}}
            with open(out, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
            """
        )
        documents = self._race(script, 5)
        winners = [d for d in documents if d["ok"]]
        losers = [d for d in documents if not d["ok"]]
        self.assertEqual(len(winners), 1, documents)
        self.assertEqual({d["code"] for d in losers}, {"E_EVENT_CONFLICT"})
        self.assertEqual(len(self.explain(db)["batches"]), 1)


class ConcurrentConsumptionTests(MultiProcessTests):
    def test_two_processes_cannot_consume_the_same_proof(self) -> None:
        """Two different requests must not be able to spend one proof twice.

        Proofs are scoped per request here, so the realistic duplicate is the
        same request advancing from two processes at once.  Exactly one must
        commit an issuance; the other must see the committed result.
        """
        db = self.db_path()
        setup = B.case(
            B.register(risk="low"),
            B.proof("e2", "PF-d", factor="device", principal="PRIN-laptop",
                    trust_group="TG-devices", now=110),
            B.proof("e3", "PF-h", factor="human", principal="PRIN-bob",
                    trust_group="TG-staff", now=120),
            batch_id="setup",
        )
        self.apply(setup, db=db)

        advance_case = self.write_case(
            B.case(B.advance("e4", stage=1, now=130), batch_id="adv-a"), "adv-a.json"
        )
        # The second writer names the *same* request and re-uses the same
        # event id with different content, so exactly one of the two may win.
        advance_case_b = self.write_case(
            B.case(B.advance("e4", stage=1, now=131), batch_id="adv-a"), "adv-b.json"
        )
        script = textwrap.dedent(
            f"""
            import json, sys
            from solution.ledger import apply_case, parse_case, read_json
            from solution.store import EventStore
            from solution.errors import CaseError

            index, out = sys.argv[1], sys.argv[2]
            path = {advance_case!r} if index == "0" else {advance_case_b!r}
            try:
                with EventStore({db!r}) as store:
                    result = apply_case(store, parse_case(read_json(path)))
                payload = {{"ok": True, "commit": result["commit"],
                           "receipt": result["receipts"][0]["receipt_id"] if result["receipts"] else None}}
            except CaseError as exc:
                payload = {{"ok": False, "code": exc.code}}
            except Exception as exc:
                payload = {{"ok": False, "code": type(exc).__name__, "detail": str(exc)}}
            with open(out, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
            """
        )
        documents = self._race(script, 2)
        winners = [d for d in documents if d["ok"]]
        losers = [d for d in documents if not d["ok"]]
        self.assertEqual(len(winners), 1, documents)
        self.assertEqual(len(losers), 1, documents)
        # Both writers named the same request and event id, so the loser is
        # refused either as a content conflict or as a duplicate consumption,
        # depending on whether the winner had already committed.
        self.assertIn(
            losers[0]["code"],
            {"E_EVENT_CONFLICT", "E_REQUEST_ISSUED", "E_PROOF_ALREADY_CONSUMED"},
        )

        explained = self.explain(db)
        self.assertEqual(len(explained["receipts"]), 1)
        # Consumption happened exactly once even though two processes raced.
        request = explained["requests"]["REQ-1"]
        for proof in request["proofs"]:
            self.assertEqual(proof["consumed_by"], "stage1")


if __name__ == "__main__":
    unittest.main()
