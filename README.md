# Two-stage challenge ledger (fictional internal authentication)

A self-contained, CPU-only reference implementation of a two-stage
challenge/response ledger for a **made-up** internal authentication system.
Everything here is synthetic: subjects, challenges, proofs and trust groups are
invented identifiers, and every trust signal is a boolean. There is no
cryptography, no network access, and no clock — logical time is supplied by
each case.

The implementation is pure Python 3.12 standard library and runs natively on
Windows. State lives in a single SQLite database with full durability
(`journal_mode=WAL`, `synchronous=FULL`).

---

## Quick start

```console
# One batch, one database
python -m solution apply examples/01_low_risk_issuance.json --db ledger.sqlite

# Inspect a committed state (omit --commit for the latest)
python -m solution explain --db ledger.sqlite

# Walk every example and print a report
python tools/run_examples.py

# Run the test suite
python -m unittest discover -s tests -v
```

Every command writes exactly one UTF-8 JSON document to stdout. Exit statuses:

| status | meaning |
| --- | --- |
| `0` | success |
| `2` | structural rejection (malformed case, bad CLI usage, unreadable file) |
| `3` | domain rejection (the events parsed but the ledger refused them) |
| `4` | injected fault after commit (see [crash recovery](#crash-between-commit-and-response)) |
| `5` | internal error (a bug; carries `E_INTERNAL`) |

The JSON document on stdout is authoritative; the status code is a convenience.

---

## Commands

```
python -m solution <command> [CASE.json] [--db DB.sqlite] [--commit N]
```

| command | needs a case | needs `--db` | writes | purpose |
| --- | --- | --- | --- | --- |
| `apply` | yes | yes | yes | apply one batch atomically |
| `explain` | no | yes | no | state + unmet requirements at a commit |
| `state` | no | yes | no | the same state without requirement text |
| `verify` | no | yes | no | re-fold history and check stored digests |
| `version` | no | no | no | print the schema name and version |

`--commit N` restricts `explain` and `state` to batch `N` and everything before
it. Omitting it means "the latest commit". `explain` and `state` on a database
with no commits report commit `0` with no requests; asking for a commit number
that does not exist is `E_COMMIT_NOT_FOUND`.

---

## Case file format

A case is a single JSON object (an array is also accepted and treated as
`{"events": [...]}`).

```jsonc
{
  "schema": "challenge-ledger/v1",   // optional; if present must match
  "batch_id": "b-low-risk",          // optional; identity of this batch
  "policies": [ /* policy documents, see below */ ],
  "events": [ /* one event object per element, applied in order */ ]
}
```

| field | type | notes |
| --- | --- | --- |
| `schema` | string | must be `challenge-ledger/v1` when present |
| `batch_id` | string | 1–256 chars from `A-Za-z0-9._:-/#@`; the idempotency key |
| `policies` | array | each is applied as a `define_policy` event **before** `events` |
| `events` | array | required, non-empty |

Unknown top-level fields are rejected with `E_SCHEMA_UNKNOWN` at `case.<field>`.
Duplicate object keys anywhere in the file are rejected while parsing
(`E_JSON_PARSE`).

### Determinism

The same logical input always produces byte-identical output. Batch keys,
challenge ids, entry digests, migration digests and receipt ids are all derived
from canonical, key-sorted JSON via SHA-256. Nothing depends on wall-clock time,
process identity, hash randomisation or iteration order.

Two batches with no `batch_id` are identified by the digest of their content, so
replaying an identical anonymous case is idempotent too.

---

## Policies and recipes

A policy is a numbered set of *recipes*. Each recipe targets a stage and lists
the factors it needs.

```jsonc
{
  "version": 1,
  "recipes": [
    {
      "id": "s1-two-factor",
      "stage": 1,
      "factors": ["device", "human"],   // shorthand for count-1 requirements
      "distinct_principals": true
    },
    {
      "id": "s2-confirm",
      "stage": 2,
      "requirements": [
        {"kind": "human", "count": 1, "principals": ["PRIN-carol"]}
      ]
    }
  ]
}
```

A recipe may use either `factors` (a list of kind strings or requirement
objects) or `requirements`, never both (`E_SCHEMA_CONFLICT`).

### Requirement fields

| field | default | meaning |
| --- | --- | --- |
| `kind` | required | `"device"` or `"human"` |
| `count` | required | how many proofs of this kind, 1–16 |
| `principals` | any | allow-list of principals |
| `trust_groups` | any | allow-list of trust groups |
| `distinct_principals` | `false` | the chosen proofs must have distinct principals |
| `distinct_trust_groups` | `false` | … and distinct trust groups |
| `require_trusted` | `true` | untrusted proofs are excluded |

### Recipe fields

| field | default | meaning |
| --- | --- | --- |
| `id` | required | unique within the policy |
| `stage` | required | `1` or `2` |
| `distinct_principals` | `true` | applied across the whole selection |
| `distinct_trust_groups` | `false` | applied across the whole selection |
| `require_trusted` | `true` | applied across the whole selection |

### How a stage is adjudicated

Given every proof known for the request:

1. A proof is usable for a requirement when it is bound to the right stage, the
   right identity generation, is `active`, not already consumed (unless it is
   being retained), has not expired, and satisfies the requirement's filters.
2. Every recipe for the stage is tried. For each, every combination of eligible
   proofs is enumerated subject to `count`, the per-requirement distinctness
   rules and the recipe-wide distinctness rules.
3. Among all valid `(recipe, selection)` pairs the winner is the one with the
   **smallest new consumption**, then the lexicographically smallest sorted
   proof-id list, then the smallest recipe id. Because this ordering is total,
   the outcome never depends on input order.

A selection that satisfies each requirement in isolation but whose combination
violates group independence fails with `independence_not_satisfied`. This is the
"three individually valid factors, any two of which are not independent" case.

---

## Identities, generations and proof binding

A proof is bound to:

* the **challenge** it answers (which is itself bound to a request, stage,
  resource, operation, op-version, risk and policy version),
* its **stage**,
* its **factor kind**,
* the **account identity generation** active when the challenge was minted.

A proof may never assert a generation other than its challenge's. Injecting a
credential minted for an earlier generation fails with
`E_PROOF_GENERATION_MISMATCH` at `events[i].generation`.

Every proof has an explicit deadline. It is the smaller of the proof's own
`expires_at` and its challenge's expiry, and it is never later than the
request's own `expires_at`.

---

## Event reference

Every event has `event_id` (unique within its request) and `type`. Optional
`now` advances logical time; time may never move backwards for a request
(`E_TIME_REGRESSION`).

### `register`

| field | type | required |
| --- | --- | --- |
| `request_id`, `subject_id`, `org`, `operation`, `generation` | id | yes |
| `resource` | string | yes |
| `op_version` | int ≥ 1 | yes |
| `risk` | `"low"` or `"high"` | yes |
| `policy_version` | int ≥ 1 | yes |
| `now` | int ≥ 0 | no (default 0) |
| `ttl` | int ≥ 1 | no (default 600) |
| `challenge_id` | id | no (pins the stage-1 challenge id) |

Creates the request and opens the stage-1 challenge. The referenced policy
version must already exist.

### `define_policy`

`policy` — a policy document. Re-defining an existing version with different
content is `E_POLICY_CONFLICT`; re-defining it identically is a no-op.

### `adopt_policy`

`request_id`, `policy_version`. Policies may only move forward
(`E_TOKEN_POLICY_MISMATCH` when asked to go back). Refused after issuance.

### `submit_proof`

| field | type | required |
| --- | --- | --- |
| `request_id`, `proof_id` | id | yes |
| `stage` | 1 or 2 | yes |
| `factor` | `"device"` or `"human"` | yes |
| `principal`, `trust_group` | id | yes |
| `trusted` | boolean | no (default `true`) |
| `challenge_id` | id | no (defaults to the current challenge for that stage) |
| `generation` | id | no (must equal the challenge's generation if given) |
| `expires_at` | int | no (clamped to the challenge expiry) |
| `now` | int | no |

Rejected when the challenge is closed (`E_CHALLENGE_CLOSED`), belongs to an
older generation (`E_PROOF_GENERATION_MISMATCH`), is for a different stage
(`E_PROOF_STAGE_MISMATCH`), or has expired (`E_CHALLENGE_EXPIRED`).
`proof_id` is unique per request (`E_PROOF_EXISTS`).

### `advance`

`request_id`, `stage`, optional `now`, optional `expect`, optional
`next_challenge_id`.

* `expect` is an object of binding assertions (`resource`, `op_version`,
  `generation`, `risk`, `policy_version`, `subject_id`). Any mismatch is
  `E_BINDING_MISMATCH` at `events[i].expect.<field>`. This is how a caller says
  "only proceed against *this* version of the resource".
* `next_challenge_id` pins the id of the challenge this step opens.

**Stage 1.** Adjudicates stage 1. On success it consumes the selected proofs
and records a stage entry. If `risk` is `"low"` it immediately re-checks
bindings, revocations and the current generation, then issues a receipt — all
inside the same transaction. If `risk` is `"high"` the request moves to
`stage1_complete` and a fresh stage-2 challenge is minted.

**Stage 2.** First re-adjudicates stage 1 under the *current* policy against
the generation the entry was completed under. If that still holds, adjudicates
stage 2 and issues. If stage 1 no longer holds, the request rolls back to
stage 1 and the result carries `outcome: "rolled_back"` with
`invalidated_stage1_digest`, the failing requirements, and a fresh stage-1
challenge.

Failure to satisfy a stage is `E_STAGE1_NOT_SATISFIED` /
`E_STAGE2_NOT_SATISFIED`, with the per-requirement diagnostics in
`error.detail.failures` and per-proof exclusions in `error.detail.excluded`.

### `issue_migration_token`

| field | required | notes |
| --- | --- | --- |
| `request_id`, `token_id` | yes | `token_id` unique across the ledger |
| `challenge_id` | yes | must be the request's **current open** challenge |
| `to_generation` | yes | must differ from the current generation and be unused |
| `to_org` | yes | destination organisation |
| `from_generation` | no | defaults to the current generation; must match it |
| `resource`, `op_version`, `risk` | no | default to the request's; a token may not change them |
| `policy_version` | no | defaults to the adopted version; must match it |
| `predecessor` | no | `null`, a step number, or a `sha256:` digest; must name the chain's current tip |
| `expires_at` | no | absolute logical time |
| `trusted` | no | default `true` |

### `migrate`

`request_id`, `token_id`, `to_generation`, `to_org`, optional
`preserve_stage1` (default `false`), optional `max_steps` (default 8), plus
optional echoes of `resource`, `op_version`, `risk`, `policy_version` which
must all match both the token and the request.

Consumes the token, appends a migration record, advances the generation and
closes every challenge bound to the old generation. Stage-2 evidence is always
invalidated by a generation change.

`preserve_stage1: true` keeps the completed stage-1 entry **only when** the
resource, operation version and risk are unchanged; otherwise
`E_PRESERVE_PRECONDITION`. A preserved entry keeps its consumed facts and is
re-adjudicated under the current policy at the next stage-2 advance — it is
never grandfathered past a stricter recipe.

### `upgrade_risk`

`request_id`, `risk` (must be `"high"`). Invalidates any stage-1 entry and
reopens stage 1. Downgrades are `E_RISK_DOWNGRADE`; no-ops are
`E_RISK_UNCHANGED`.

### `revoke_proof`

`request_id`, `proof_id`, optional `reason`. A revoked proof can never be
consumed again. If it was already consumed and the request has not been issued,
the dependent stage entry is invalidated and the request rolls back to stage 1.
If the request **was** issued, the revocation is recorded as a post-issue change
and the receipt is untouched.

### `revoke_request`

`request_id`, optional `reason`. Closes every challenge. An existing receipt is
kept.

### `fault` (testing only)

`point` — `"at_event"`, `"before_commit"`, or `"after_commit"`.

---

## Output reference

### `apply`

```jsonc
{
  "schema": "challenge-ledger/v1",
  "ok": true,
  "kind": "apply",
  "commit": 3,                  // batch number, 1-based
  "batch_key": "b-low-risk",
  "batch_id": "b-low-risk",
  "events": [ /* one result per scheduled event, in order */ ],
  "receipts": [ /* receipts created by this batch */ ],
  "requests": { "REQ-1": { /* state of each touched request */ } }
}
```

Each element of `events` is the handler's result plus `event_id` and `index`.
Every result also carries `type`.

### Receipts

```jsonc
{
  "schema": "challenge-ledger/v1",
  "kind": "issuance",
  "receipt_id": "rcpt-…",
  "digest": "sha256:…",
  "number": 1,                       // per subject, monotonically increasing
  "request_id": "REQ-1",
  "subject_id": "SUBJ-alice",
  "org": "ORG-north",
  "resource": "FILESET-quarterly",
  "operation": "read",
  "op_version": 3,
  "risk": "low",
  "generation": "GEN-1",
  "policy_version": 1,
  "policy_fingerprint": "sha256:…",
  "challenge_id": "chl-…",
  "issued_at": 130,
  "valid_until": 5100,
  "stage1": { "recipe_id": "…", "proof_ids": ["…"], "generation": "GEN-1", "entry_digest": "sha256:…" },
  "stage2": null,                    // or the same shape for high risk
  "migrations": [ /* every hop, with step, receipt id, digest and orgs */ ]
}
```

A receipt is immutable. `digest` covers every field except itself.

### `explain`

```jsonc
{
  "schema": "challenge-ledger/v1",
  "ok": true,
  "kind": "explain",
  "commit": 4,
  "batches":   [ {"batch_no": 1, "batch_key": "…", "committed_at": "…"} ],
  "events":    [ {"seq": 1, "batch_no": 1, "event_id": "…", "type": "…", "result": {…}} ],
  "requests":  { "REQ-1": { /* state, receipts, proofs, unmet */ } },
  "receipts":  [ /* every receipt visible at this commit */ ]
}
```

`requests[<id>]` contains the request fields, a `proofs` array (with
`consumed_by`, `consumed_batch`, `status`, `revoked_reason` and
`effective_expires_at`), the `stage1`/`stage2` entries, every `migrations`
record, `invalidations`, `post_issue_changes`, and `unmet`:

```jsonc
"unmet": {
  "satisfied": false,
  "stage": 2,
  "policy_version": 1,
  "recipe_id": null,
  "failures": [ {"stage": 2, "requirement_index": 0, "kind": "human",
                 "needed": 1, "eligible": 0, "reason": "no_valid_combination",
                 "rejected": [{"proof_id": "PF-d", "reason": "stage_mismatch"}]} ],
  "excluded": [ {"proof_id": "PF-h", "reasons": ["already_consumed"]} ]
}
```

Failure reasons: `no_valid_combination`, `independence_not_satisfied`,
`no_recipe_for_stage`. Exclusion reasons: `stage_mismatch`,
`generation_mismatch`, `revoked`, `already_consumed`, `expired`, `untrusted`.

### `verify`

Re-folds every committed event and checks stored payload digests, batch keys,
receipt digests and receipt identifiers. Returns
`{"ok": true|false, "batches": N, "requests": N, "receipts": N, "problems": [...]}`
and exits `0` when `ok` is true, `3` when it is false.

### Errors

```jsonc
{
  "schema": "challenge-ledger/v1",
  "ok": false,
  "error": {
    "code": "E_STAGE1_NOT_SATISFIED",
    "path": "events[2].stage",
    "message": "stage 1 evidence does not satisfy any recipe under the current policy",
    "detail": { "failures": [...], "excluded": [...] }   // when applicable
  }
}
```

`path` is a JSON path in the submitted file: `case.<field>`, `policies[i]…`,
`events[i].<field>`, or `history[i]` for a replay problem. `detail` is present
for adjudication failures and attached context.

### Error codes

Structural (exit `2`):

| code | raised when |
| --- | --- |
| `E_JSON_PARSE` | the file is not UTF-8 JSON, or an object repeats a key |
| `E_SCHEMA_TYPE` | a field has the wrong JSON type (booleans are not integers) |
| `E_SCHEMA_MISSING` | a required field is absent |
| `E_SCHEMA_ENUM` | a value is outside its allowed set, or an identifier has bad characters |
| `E_SCHEMA_RANGE` | a number is outside its allowed range |
| `E_SCHEMA_UNKNOWN` | an unrecognised field |
| `E_SCHEMA_DUPLICATE` | a list contains a duplicate identifier |
| `E_SCHEMA_EMPTY` | a required array or string is empty |
| `E_SCHEMA_CONFLICT` | two mutually exclusive fields are both present |
| `E_USAGE` | bad command line |
| `E_IO` | the case file cannot be read |

Domain (exit `3`):

| code | raised when |
| --- | --- |
| `E_BATCH_OUT_OF_ORDER` | a migration uses a token this batch issues later |
| `E_BATCH_REJECTED` | reserved for whole-batch refusal summaries |
| `E_BATCH_CYCLE` | reserved for a cyclic batch dependency |
| `E_BINDING_MISMATCH` | an `expect` assertion, or an issuance-time re-check, fails |
| `E_CHALLENGE_CLOSED` | the challenge is closed (superseded or migrated away) |
| `E_CHALLENGE_EXPIRED` | the request or challenge deadline has passed |
| `E_CHALLENGE_NOT_FOUND` | no such challenge |
| `E_COMMIT_NOT_FOUND` | `--commit` names a batch that does not exist |
| `E_EVENT_CONFLICT` | a batch key or event id is reused with different content |
| `E_EVENT_DUPLICATE_IN_BATCH` | the same event id appears twice with different content |
| `E_INJECTED_FAULT` | a `fault` event with `before_commit` or `at_event` |
| `E_MIGRATION_AFTER_ISSUE` | a token or migration after issuance |
| `E_MIGRATION_LIMIT` | the migration chain reached `max_steps` |
| `E_POLICY_CONFLICT` | a policy version is redefined with different content |
| `E_POLICY_NOT_FOUND` | the referenced policy version is not registered |
| `E_POLICY_TOO_COMPLEX` | adjudication exceeded its search budget |
| `E_PRESERVE_PRECONDITION` | `preserve_stage1` without an eligible entry |
| `E_PROOF_ALREADY_CONSUMED` | a spent proof was offered again |
| `E_PROOF_CHALLENGE_MISMATCH` | the challenge belongs to another request |
| `E_PROOF_EXISTS` | the proof id is taken |
| `E_PROOF_EXPIRED` | the proof's own deadline had already passed |
| `E_PROOF_GENERATION_MISMATCH` | the proof or challenge is from another generation |
| `E_PROOF_NOT_FOUND` | no such proof |
| `E_PROOF_REVOKED` | a revoked proof was used |
| `E_PROOF_STAGE_MISMATCH` | the proof's stage does not match its challenge |
| `E_PROOF_UNTRUSTED` | reserved for direct untrusted-proof rejection |
| `E_REQUEST_EXISTS` | the request id is taken |
| `E_REQUEST_ISSUED` | the request has already been issued |
| `E_REQUEST_NOT_FOUND` | no such request |
| `E_REQUEST_REVOKED` | the request was revoked |
| `E_RISK_DOWNGRADE` | an attempt to lower risk |
| `E_RISK_UNCHANGED` | an attempt to set the current risk |
| `E_STAGE1_NOT_COMPLETE` | stage 2 was requested without a valid stage 1 |
| `E_STAGE1_NOT_SATISFIED` | no stage-1 recipe is satisfied |
| `E_STAGE2_NOT_OPEN` | reserved: stage 2 requested while stage 2 is closed |
| `E_STAGE2_NOT_SATISFIED` | no stage-2 recipe is satisfied |
| `E_TIME_REGRESSION` | `now` moved backwards for the request |
| `E_TOKEN_ALREADY_CONSUMED` | the migration token is spent |
| `E_TOKEN_CHALLENGE_MISMATCH` | the token does not bind the current challenge |
| `E_TOKEN_CONFLICT` | the token id is taken |
| `E_TOKEN_EXPIRED` | the token deadline has passed |
| `E_TOKEN_GENERATION_MISMATCH` | the token's generation does not fit the request |
| `E_TOKEN_NOT_FOUND` | no such token |
| `E_TOKEN_POLICY_MISMATCH` | the token's policy version disagrees |
| `E_TOKEN_PREDECESSOR_MISMATCH` | the predecessor does not name the chain tip |
| `E_TOKEN_RESOURCE_MISMATCH` | the token's resource, version or risk disagrees |
| `E_TOKEN_REUSED_GENERATION` | the target generation was already used |
| `E_TOKEN_SKIPS_GENERATION` | reserved: a migration asserted a multi-hop jump |
| `E_TOKEN_UNTRUSTED` | an untrusted token |
| `E_MIGRATION_RECEIPT_MISMATCH` | reserved: a migration receipt does not match its record |

`E_DB` reports a SQLite open/prepare/commit failure. Verification findings use
`E_VERIFY_COMMIT`, `E_VERIFY_KEY`, `E_VERIFY_DIGEST` and `E_VERIFY_RECEIPT`.

Exit `4` carries `E_FAULT_AFTER_COMMIT`; exit `5` carries `E_INTERNAL`.

---

## Transaction, idempotency and concurrency

* One `apply` invocation is one `BEGIN IMMEDIATE` transaction. All events of a
  batch commit or none do.
* Proof consumption, state transitions and the unique receipt are written in
  that same transaction. A receipt id is derived from its full content, and the
  per-subject `number` is allocated inside the transaction, so two racing
  issuers can never both succeed.
* Batches are keyed by `batch_id` (or by content digest when absent). Repeating
  a batch returns the stored result verbatim. Reusing a key with different
  content is `E_EVENT_CONFLICT` at `batch_id`.
* Events are keyed by `(request_id, event_id)` plus a content digest. Repeating
  one returns its original result; reusing the id with different content is
  `E_EVENT_CONFLICT` at `events[i].event_id` and rejects the whole batch.
* A batch that names the same event id twice with different content is
  `E_EVENT_DUPLICATE_IN_BATCH`; with identical content it is answered once.
* `journal_mode=WAL` and `synchronous=FULL` mean a committed batch survives a
  process crash. `busy_timeout` is 30 s with bounded retries on `BEGIN`.

### Crash between commit and response

`{"type": "fault", "point": "after_commit"}` commits the batch and then exits
with status `4` and `E_FAULT_AFTER_COMMIT` (`detail.committed: true`). Re-running
the same case returns the original result and creates no second commit. This is
the tested "process dies before responding" path.

`before_commit` (and `at_event`) abort the transaction, so nothing — including
any partial proof consumption from earlier events in that batch — is visible.

---

## Invariants the tests enforce

1. A consumed proof is never usable again, across migrations, rollbacks and
   policy upgrades.
2. An issued receipt is final. Later revocations are recorded in
   `post_issue_changes`, never folded into the receipt.
3. A preserved stage-1 entry keeps its consumption but must still satisfy the
   current recipe, judged against the generation it was completed under. The
   outcome is binary: the entry stands unchanged, or the request rolls back to
   stage 1. A retained set is never silently rewritten, because a re-selection
   at zero cost can only pick the retained set itself.
4. A migration token names exactly one challenge, one generation hop and one
   predecessor digest, and is consumed exactly once — so a token can never skip
   a generation, even when the destination is the original organisation.
5. Stage-2 evidence from a superseded generation is excluded even though it is
   still `active` and unconsumed.
6. Adjudication picks the smallest new consumption, with a total tie-break, so
   the same proof set always yields the same selection.

---

## Reproducing the examples

```console
python tools/make_examples.py     # regenerate examples/*.json
python tools/run_examples.py      # apply them and print a one-line report each
```

| file | scenario | expected |
| --- | --- | --- |
| `01_low_risk_issuance.json` | one-stage low risk | issued at commit 1 |
| `02_high_risk_two_stage.json` | stage-1 then a fresh stage-2 human | issued at stage 2 |
| `03_migration_step1_preserve.json` | complete stage 1, hop to another org with preservation | `migrated`, stage 1 preserved |
| `04_migration_step2_chain.json` | second hop, predecessor = step 1 | `migrated`, step 2 |
| `05_migration_back_to_origin.json` | third hop back to the original org | `migrated`, new generation |
| `05b_stale_ticket_rejected.json` | reuse the hop-1 ticket | `E_TOKEN_ALREADY_CONSUMED` |
| `05a_chain_stage2_issuance.json` | confirm and issue after three hops | issued, receipt lists all hops |
| `06_migration_drops_stage1.json` | migrate without preserving | stage 1 invalidated |
| `07_policy_upgrade_rollback.json` | stricter policy after preserving | `rolled_back` to stage 1 |
| `08_group_independence_failure.json` | three devices, two groups | `E_STAGE1_NOT_SATISFIED` |
| `09_conflict_rejected_batch.json` | same event id, different content | `E_EVENT_DUPLICATE_IN_BATCH` |
| `10_crash_after_commit.json` | crash after commit | `E_FAULT_AFTER_COMMIT`, committed |
| `11_duplicate_batch_retry.json` | replay an identical batch | unchanged, one commit |
| `12_expired_challenge.json` | proof after the deadline | `E_CHALLENGE_EXPIRED` |
| `13_risk_upgrade.json` | low → high mid-flight | stage 1 reopened |
| `14_structural_error.json` | `risk: "medium"` | `E_SCHEMA_ENUM` at `events[0].risk` |

Examples `03 → 04 → 05 → 05b → 05a` must run **against one database**, in that
order; `tools/run_examples.py` does exactly that. All other examples use their
own fresh database.

---

## Tests

```console
python -m unittest discover -s tests -v
```

| module | covers |
| --- | --- |
| `test_basic_flow.py` | low/high risk happy paths, stage separation, no proof reuse |
| `test_migration.py` | chained hops, preservation, generation injection, races |
| `test_batches.py` | out-of-order tickets, stale tickets, re-entry after rollback |
| `test_policy.py` | recipes, retained consumption, minimal selection, ties, groups |
| `test_history.py` | `explain` at old commits, post-issue revocations, deadlines |
| `test_concurrency.py` | real multi-process races, idempotency, crash recovery |
| `test_schema_and_cli.py` | structural paths, exit codes, determinism |
| `test_differential.py` | 200 seeded random cases against an independent model |

`tests/fsm_model.py` is a deliberately naive finite-state model written from
the specification. `test_differential.py` generates small cases by walking that
model forward, then replays the same events through the engine and requires the
two to agree on status, consumed proofs, receipt count and receipt contents.

---

## Layout

```
solution/
  __main__.py   CLI, exit-code mapping, single JSON document on stdout
  engine.py     event handlers and the two-stage state machine
  policy.py     recipe parsing and adjudication
  model.py      state objects, digests, receipts
  ledger.py     case parsing, batch application, replay, explain
  store.py      SQLite schema, transactions, queries
  schema.py     field-level validation with locatable paths
  canonical.py  canonical JSON and stable digests
  errors.py     error codes and exit statuses
tests/          assert-backed suite (stdlib unittest)
examples/       runnable synthetic cases
tools/          example generator and runner
```

## Scope and safety

This is a model of a ledger, not a security product. It performs no
cryptography, stores no secrets, and its "trust" flags are inputs, not
attestations. All identifiers in the examples are invented.
