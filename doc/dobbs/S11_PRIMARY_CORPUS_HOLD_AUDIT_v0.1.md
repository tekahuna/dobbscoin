# Independent audit — S11_PRIMARY_CORPUS_HOLD_V0_1

**Audit date:** 2026-09-17
**Subject:** `S11_primary_corpus_hold_v0.1.zip` (15 files)
**Mode:** read-only evidence audit. No replay, no network, no candidate mutation.
**Verdict:** **Conclusion sound; evidence chain not.** The `HOLD_MISSING_PRIMARY_CORPUS`
result is correct and correctly reasoned. The bookkeeping that is supposed to make
that result trustworthy has gaps — including one blocking S11 prerequisite that is
unaccounted for, and two holds that left the ledger without being closed.

---

## 1. What verifies

These were checked mechanically, not taken on assertion.

| Check | Result |
|---|---|
| All 9 `input_artifacts` SHA-256 vs packaged bytes | **9/9 exact match** |
| `parent_receipt_sha256` (`727be22f…`) vs actual S10 receipt hash | **match** |
| Host pin (commit `9be056a8`, tree `109dc8b3`, tag obj `bfa6a4b7`) across S10 receipt, W8 contract, W9 manifest, W9 addendum, S11 receipt | **consistent** |
| `ORACLE_RECOVERY_CHECK.manifest_sha256` vs packaged golden oracle manifest | **match** (`9bab652c…`) |
| Oracle manifest ↔ recovery check: 34 members, path + sha256 + bytes | **34/34 identical, zero disagreements** |
| Oracle recovery fixtures (34 positive_exact, 34 same-length bitflip, 34 truncation) | **102/102 pass** |
| Tracked diff unchanged S10→S11 (`75e69fbf…`) vs `changed_files: []` | **consistent** |
| Claim boundary: `LOCAL_BUILD_HANDOFF` / `CONSENSUS_PARITY_EARNED` / `RELEASE_READY` | **all false** |
| External-action attestation (network, peer, pool, broadcast, release, wallet) | **all false, consistent across receipt, ledger, browser observations** |

The substantive judgment is right. The three "corpus-like" files found
(`block413567.raw`, `ip_asn.dat`, `asmap.raw`) are indeed Bitcoin Core bench/test
assets, not Dobbs canonical blocks. The explorer material is correctly classified
`RECEIVER_OBSERVATION_NOT_RAW_HTTP_CUSTODY` with `canonical_block_bytes_acquired: 0`,
and the stopped `ERR_BLOCKED_BY_CLIENT` attempt is honestly recorded as a client-side
failure rather than inflated into a claim about the site. Refusing to proceed was
the correct call.

---

## 2. Findings

### F-01 · HIGH · A blocking S11 prerequisite is unaccounted for

`DOBBS_W9_HARDENED_PREBUILD_ADDENDUM_v0.1.json` sets:

```
effective_dag_constraints.S11_additional_prerequisites = [
  A00_GOLDEN_ORACLE_ADMISSION,
  A04_GENERIC_VALIDATION_AND_MATURITY,
  A06_CHECKPOINT_GATE
]
```

Status of each:

- **A04** — closed at S10 (three holds, with fixture evidence). ✅
- **A00** — evidence exists (`ORACLE_RECOVERY_CHECK`, 34/34), but its hold
  `H-W9-GOLDEN-ORACLE-BINDING` is closed in **no** receipt and appears in **no**
  ledger, open or closed. Evidence without a disposition.
- **A06_CHECKPOINT_GATE** — `blocking: true`, inserted *"after W8-S10; before
  W8-S11"*. Its hold `H-W9-CHECKPOINT-TRANSPLANT` (adversarial finding **W9-F04**,
  HIGH, `affected: [W7-26, W8-S11]`) appears **nowhere** in the S10 ledger, the S11
  ledger, or either receipt. No checkpoint fixture exists in either stage. ❌

`H-W9-POW-CALLSITE-COMPLETENESS` (**W9-F02**, CRITICAL, `affected: […, W8-S11]`) is
likewise untracked.

S11 halted on a *later* gate (corpus) while an *earlier* blocking gate was never
recorded as satisfied or held. The hold is therefore under-stated, not over-stated —
but the ledger is not a faithful record of why S11 could not proceed.

**Repair:** enter `H-W9-CHECKPOINT-TRANSPLANT` and `H-W9-POW-CALLSITE-COMPLETENESS`
as open holds; either close A06 with the pinned-map / enabled-reject / disabled-bypass
fixtures the addendum specifies, or record it explicitly held with A06 named as an
unsatisfied S11 entry predicate.

Eleven of the sixteen W9 adversarial-finding holds are untracked in both ledgers;
eight of those are `blocking: true` (F01, F02, F03, F04, F08, F12, F13, F15). Some
may have been dispositioned in S02–S09 receipts not included in this packet — but
A06 is inserted between S10 and S11 and can only have been handled here.

### F-02 · HIGH · Two holds left the ledger without being closed

`OPEN_HOLDS_AFTER_S10.open` carries 8 holds. `OPEN_HOLDS_AFTER_S11.open` carries the
new `HOLD_MISSING_PRIMARY_CORPUS` plus 6 of those 8. Missing:

- `H-CORPUS-PRIMARY-BYTES`
- `H-W8-PRIMARY-CORPUS-ADMISSION-BEFORE-S11`

`OPEN_HOLDS_AFTER_S11.closed` is `[]`. Both vanished holds are the *corpus* holds.

The S11 receipt disagrees with its own ledger: `holds.preserved` lists **all 8**,
including both of the above. The receipt is right; the ledger dropped two rows.

Relatedly, `holds.added` is `[]` even though `HOLD_MISSING_PRIMARY_CORPUS` is new in
the open list (it is filed under `holds.blocking` instead), so the
added/closed/preserved accounting does not reconcile against the ledger delta in
either direction.

If the intent was that the two holds were absorbed into `HOLD_MISSING_PRIMARY_CORPUS`,
that is a rename and must be narrated as one. An unexplained disappearance of corpus
holds from a corpus-hold ledger is precisely the failure mode this program exists to
prevent.

### F-03 · HIGH · The contractually required negative fixture was not run

W8 contract, stage S11:

```
"negative_fixture_ids": ["NF-REPLAY-SPOTCHECK"]
"forbidden_leakage": [..., "spot-check substitution", ...]
```

`S11_NEGATIVE_FIXTURES.json` runs four fixtures — `S11-EXACT-CANONICAL-GENESIS-TO-TIP-CORPUS`,
`S11-EXPLORER-SUBSTITUTION`, `S11-SYNTHETIC-CHAIN-SUBSTITUTION`,
`S11-ASSUMEVALID-CHECKPOINT-SUBSTITUTION`. **None is `NF-REPLAY-SPOTCHECK`.**

The substitutes are reasonable and arguably broader, but the one fixture the contract
names — the one guarding the specific `forbidden_leakage` entry "spot-check
substitution" — was not executed, and the substitution was not declared. The packet
also omits `DOBBS_W8_NEGATIVE_FIXTURE_CATALOG_v0.1.json`, so `NF-REPLAY-SPOTCHECK`'s
definition cannot be checked from these bytes alone.

### F-04 · MEDIUM-HIGH · No command log digests; packaged logs are unbound

W8 contract S11 `evidence_required` includes **"command log digests"**. The S11
receipt contains **no `log_sha256` anywhere**. The S10 receipt recorded one for every
build and test command — including a genuine `exit_code: 2` first build, so the
discipline existed one stage earlier.

The three files in `logs/` are referenced only by path (and only the fixtures JSON is
referenced at all). They can be edited with no receipt-detectable effect. The hold
state does not excuse this: commands *were* run, and their digests were required.

For reference, the packaged bytes hash to:

```
b19c9e92451c63fc9b30490173d6e09a0088b2315117ed43b03da6df5e2f40dc  logs/S11_PRIMARY_CORPUS_ADMISSION_CHECK.log
9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa  logs/S11_PRIMARY_CORPUS_ADMISSION_CHECK.exit
48099b4a573b932c4b493802e8edd7d5f4a90106219aa40df5dc9eeae6d8d92c  logs/S11_NEGATIVE_FIXTURES.json
a0329e0d250c75c4187f630938f43c527f64512fd881053c34a825dd1cf73439  holds/OPEN_HOLDS_AFTER_S11.json
c91d7c179a3c4930ec4e655313bab0d7e856bf288a73df42016ee53925122cca  S11_STAGE_RECEIPT.json
f5c64e975e018f5eea125293ba15e340180096d3017096cb0c0589df79ccfc1c  README.md
```

### F-05 · MEDIUM · Worktree integrity control weakened — and one file is missing

S10 recorded `diff_identity.kind = working_tree_file_manifest_sha256`,
`sha256 = a5d0a41d…`, `file_count = 54`. That hash covers **untracked** files.

S11 dropped it. Its `diff_identity` records only `git_diff_binary_sha256_before_s11`
and `git_diff_name_status_sha256_before_s11` — **tracked-only** digests. So
`candidate_mutation: false` is demonstrated for tracked files and asserted for
everything else.

The S11 log's own `git status --short` shows why that matters. Reconciling it against
S10's 54-file manifest:

| bucket | S10 | S11 log |
|---|---|---|
| tracked ` M` | 20 | 20 |
| `?? src/dobbs/` (collapsed) | 22 | ✓ |
| `?? depends/logs/` (collapsed) | 2 | ✓ |
| `?? docs/` (collapsed) | 1 | ✓ |
| `?? src/test/dobbs_*.cpp` (listed individually) | **9** | **8** |
| **total** | **54** | **53** |

`src/test/dobbs_subsidy_tests.cpp` is absent from the S11 worktree listing. Git does
not collapse untracked files under a tracked directory — the other eight are listed
individually, so its absence is real, not a display artifact. S10 lists it in
`changed_files` and ran `--run_test=…,dobbs_subsidy_tests,…` to exit 0.
(`src/dobbs/consensus/subsidy.{cpp,h}` fall under the collapsed `?? src/dobbs/` entry,
so only the test file is demonstrably gone.)

Either a file disappeared between S10 and S11 — contradicting S10's *"preserved all
prior dirty candidate work"* and the plain reading of `candidate_mutation: false` —
or the log is incomplete. The single control that would have caught this
(`a5d0a41d…`) is the one S11 stopped recording.

**Repair:** recompute the working-tree manifest hash and compare against `a5d0a41d…`.
That settles it in one command.

### F-06 · MEDIUM · The receipt predates its parent; the outcome was pre-declared

- S11 receipt `created_at`/`updated_at`: **2026-09-10T00:00:00Z**
- S10 receipt `created_at`/`updated_at`: **2026-09-10T08:30:00Z**

The child receipt is timestamped 8½ hours *before* the parent it consumes by hash.

Further, S10 already recorded the S11 result before S11 ran — `S10_STAGE_RECEIPT.claims`
carries `"S11_RESULT": "HOLD_MISSING_PRIMARY_CORPUS"`, `OPEN_HOLDS_AFTER_S10.claim_boundary`
carries `"S11_result": "HOLD_MISSING_PRIMARY_CORPUS"`, and S10's `next_stage_predicate`
mandates it.

The admission log records only boolean assertions
(`explorer_observations_as_primary=false`, `synthetic_chain_as_primary=false`,
`checkpoint_or_assumevalid_as_primary=false`) with no evidence of an executed fixture
harness behind the four `observed` values in `S11_NEGATIVE_FIXTURES.json`. Nothing in
the packet shows the check *could* have returned anything else.

The answer is right. It is not shown to be independently derived, and the timestamps
cannot be reconciled with the stated order of operations.

### F-07 · MEDIUM · Fail-closed preflight exits 0

`logs/S11_PRIMARY_CORPUS_ADMISSION_CHECK.exit` contains `0`, while the log's last
substantive line is `result=HOLD_MISSING_PRIMARY_CORPUS` and the README states S11
*"correctly failed closed."*

Any wrapper, CI step, or `&&` chain keying on exit status reads this hold as success —
the exact inversion a fail-closed gate exists to prevent. S10's receipt records a real
`exit_code: 2`, so meaningful exit codes are the convention elsewhere in the program.

**Repair:** reserve a distinct non-zero code for HOLD (e.g. `3`) and keep `0` for
admitted-and-passed.

### F-08 · LOW-MEDIUM · Lineage: 2 of 9 archives not re-verified, including the denominator

`DOBBS_W9_GOLDEN_ORACLE_MANIFEST_v0.1.json` declares a 9-entry `lineage_zip_chain`.
`ORACLE_RECOVERY_CHECK.archives` verifies **7**. Not re-verified:

- `DOBBSBRAINS_W1_SURFACE_DEFERRAL_TRANCHE_0008_v0.1.zip`
- `DOBBSBRAINS_W8_CODEX_BOUNDED_TRANSPLANT_CONTRACT_TRANCHE_0015_v0.1.zip` (`4b112e45…`)

The second is `parent.parent_w8` and the head of the addendum's
`effective_receiver_denominator`. All six W8-lane members were taken from an
already-extracted `…/w8_parent_members/` directory rather than from the sealed zip.

Member hashes match the manifest, so this is not a byte problem — it is a custody gap
on the one archive the contract designates as the governing denominator.

### F-09 · LOW · `program_id` changed

S11 uses `DOBBSCOIN_MODERNIZATION`. The S10 receipt, W8 contract, W9 golden oracle
manifest, W9 addendum and W9 adversarial findings all use
`DOBBSCOIN-MODERNIZATION-RECON-KBP-001`. Breaks automated program-identity binding
across the receipt chain.

### F-10 · LOW · Dangling parent reference

`host_pin.w9_parent_sha256 = c3cc1c8267f0bcd577242bf04505d50eed1f21d396debf317ce4bb535fd22c01`
matches no packaged file and is named by no packaged artifact. Unresolvable from this
packet.

### F-11 · LOW · Fixture status strings disagree

`S11_NEGATIVE_FIXTURES.json` reports `S11-EXACT-CANONICAL-GENESIS-TO-TIP-CORPUS` as
`status: "PASS_HOLD"`; the receipt's `fixture_results` reports the same fixture as
`status: "HOLD_MISSING_PRIMARY_CORPUS"`. Cosmetic, but it is the fixture the whole
stage turns on.

---

## 3. Packaging gaps

Artifacts referenced by the evidence chain but absent from the packet, which prevent
it from being self-verifying:

- `DOBBS_W8_NEGATIVE_FIXTURE_CATALOG_v0.1.json` — defines `NF-REPLAY-SPOTCHECK` (F-03)
- `DOBBS_W8_TEST_GATE_MATRIX_v0.1.json`
- `DOBBSCOIN_MODERNIZATION_HOLD_LEDGER_v1.0.json` and
  `DOBBSCOIN_MODERNIZATION_ACCEPTANCE_MATRIX_v1.0.json` — both consumed by S10
- S02–S09 receipts — the only place the 11 untracked W9 holds (F-01) could have been
  dispositioned

---

## 4. Disposition

The hold itself should stand. Nothing in this audit suggests the corpus exists or that
S11 should have advanced, and the refusal to substitute explorer data, synthetic
chains, checkpoints or assume-valid is exactly right.

Before S11 is restarted, and independently of corpus acquisition:

1. Reinstate `H-CORPUS-PRIMARY-BYTES` and `H-W8-PRIMARY-CORPUS-ADMISSION-BEFORE-S11`
   in the ledger, or narrate their absorption. **(F-02)**
2. Disposition `A06_CHECKPOINT_GATE` / `H-W9-CHECKPOINT-TRANSPLANT` and
   `H-W9-POW-CALLSITE-COMPLETENESS`; audit the other 9 untracked W9 holds against the
   S02–S09 receipts. **(F-01)**
3. Run `NF-REPLAY-SPOTCHECK` as named, or declare the substitution. **(F-03)**
4. Recompute the working-tree manifest hash against `a5d0a41d…` and account for
   `src/test/dobbs_subsidy_tests.cpp`. **(F-05)**
5. Add `log_sha256` for every command log and bind the packaged `logs/` files to the
   receipt. **(F-04)**
6. Make the preflight exit non-zero on HOLD. **(F-07)**
7. Re-verify tranche 0008 and tranche 0015 zips from sealed bytes. **(F-08)**
8. Correct the timestamp inversion and `program_id`. **(F-06, F-09)**

Items 1, 3, 5, 6 and 8 are bookkeeping and cost minutes. Items 2 and 4 are the ones
that could change what the record means.

---

*Audit performed read-only against the packaged bytes. No network access, no peer or
pool contact, no broadcast, no candidate mutation, no replay attempted.*
