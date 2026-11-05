# M1 results

One evidence run on 2026-11-05, from fresh deployments, in one environment.
Every number below comes from that run's raw results, which stay local
because they hold identities, hashes and timings of one machine. These are
observations within the tested scope, not a security guarantee.

## Environment

| Item | Value |
|---|---|
| Database | MySQL Enterprise Server 26.7.0-commercial, Windows x64 ZIP, component `component_object_policy` |
| Instances | two on one host (lab and shadow), loopback only, binary logging on |
| OS and runtime | Windows 11, CPython 3.13.15 |
| Embedder | fastembed 0.9.1, onnxruntime 1.31.1, numpy 2.5.4, tokenizers 0.23.3 (hashed wheels in `requirements.lock`) |
| Model | `BAAI/bge-small-en-v1.5`, revision `5c38ec7c405ec4b44b94cc5a9bb96e735b38267a`, files checked against a SHA-256 manifest, one thread, network sockets blocked |
| Data | synthetic: 24 suppliers, 72 invoices; masked columns `tax_id` (last four characters visible), `compliance_note` (constant), `risk_score` (0) |
| Twins | 6 per verification (3 permutation, 3 synthetic), seed 20261113, coverage minimum 0.8 of rows per masked column |

The files under `m1/`, `sql/` and `tests/` that ran match, by SHA-256, the
files in the commit that adds this document.

## Sequence

| Step | Outcome |
|---|---|
| Unit tests | 41 tests, OK |
| Phase A: gate negatives on a deployment without the gate (`--core-only`) | 4 of 54 met |
| Phase B: gate negatives on a fresh deployment with the gate | 54 of 54 met |
| Phase C: experiments on fresh lab and shadow instances | 7 of 7 as expected |
| Phase C: clearance negatives, same instances | 13 of 13 as expected; lab and shadow state restored |
| Agent demo on the latest released batch | ranked released chunks only |

Expectations were written in the code before the runs; no expectation or
result was changed afterwards.

## Experiments

| ID | Question | Builder | Expected | Observed | Published rows |
|---|---|---|---|---|---|
| C0 | Does a privileged build that uses no masked data pass? | privileged | PASS | PASS (privileged build) | 24 |
| P0 | Is a direct disclosure of masked data rejected? | privileged | FAIL | FAIL: output differs in all 6 twins | 0 |
| P0b | Is an omission decided on masked data rejected, although no masked value is in the output? | privileged | FAIL | FAIL: output differs in all 6 twins | 0 |
| P1 | Does the same code pass when run by an identity that sees what the agent sees? | restricted | PASS | PASS (reader-equivalent build) | 24 |
| P2 | Does privileged internal processing with no disclosure pass, with the internal difference reported? | privileged | PASS | PASS; internal output differed in all 6 twins, published output in none | 24 |
| PND | Is a nondeterministic build left inconclusive rather than judged? | restricted | INCONCLUSIVE | INCONCLUSIVE: A/A replay does not reproduce the sealed hash | 0 |
| A/A | Does building the same pipeline twice on the lab instance give the same sealed hash? | restricted | equal | equal | n/a |

For every non-PASS verdict, approval was refused (`only a PASS verification
can be approved`) and release was refused (`latest verification is not
PASS`), both with error 1644, and no row was published. Every PASS was
approved, released, and its published copy hashed to the sealed hash.

What the experiments show, within this scope:

- **P0b is the case a content scan misses.** A naive content scan of the
  published text (patterns plus the real masked text values) flagged 14 of
  24 chunks in P0 and 0 of 16 in P0b. The privileged P0b build left out the
  8 suppliers whose masked compliance note mentions an investigation; the
  twin replay caught the dependency in all 6 twins.
- **P1 passes because the masks turn its filter into a no-op.** Under the
  masks every compliance note reads as the same constant, so the filter
  removes nothing: all 24 suppliers are published and the content hash
  equals C0's. The build is safe for the agent and no longer does what the
  filter was written to do. M1 detects dependence on masked data; it does
  not preserve a pipeline's business intent.
- **P2 separates internal use from disclosure.** The internal review queue
  changed with the masked data, the published output did not, and the
  difference was reported without blocking.
- **A/A.** Two builds on the lab instance and each PASS verification's two
  shadow replays reproduced the sealed hash. C0, P1, P2 and both A/A builds
  sealed the same content hash.
- **Twins.** In every verification that reached the twins (all except PND
  here, and the three clearance scenarios whose contract check failed), all
  6 twins were valid, and every masked column had all 24 rows changed in at
  least one twin. In each permutation
  twin the agent-view check moved 24 cells to their synthetic candidate in a
  second round, which matches the 24 `tax_id` cells: `tax_id` is the only
  mask that leaves part of the value visible, and a value borrowed from
  another row changes that part. Per twin, 0 to 2 cells kept their original
  value for lack of a candidate.

## Clearance negatives

The restricted builder runs the P1 code under each perturbation; the last
scenario uses the privileged builder and the C0 code. Each perturbation is
applied to the lab and the shadow instance alike and reverted before the
next one; the run checks that the original state is restored on both.

| ID | Perturbation | Expected | Observed | Expected checks flagged | Published rows |
|---|---|---|---|---|---|
| C00 | none (control) | PASS | PASS | none expected | 24 |
| C01 | unmasking role granted to the restricted builder, not activated | INCONCLUSIVE | INCONCLUSIVE | C1 | 0 |
| C02 | `activate_all_roles_on_login` switched on | INCONCLUSIVE | INCONCLUSIVE | C2 | 0 |
| C03 | unmasking role named in `mandatory_roles` | INCONCLUSIVE | INCONCLUSIVE | C2, C3, C7 | 0 |
| C04 | DEFINER view over the source, owned by an account that reads unmasked data | INCONCLUSIVE | INCONCLUSIVE | C3 | 0 |
| C05 | policy gatekeeper changed to name the restricted builder | INCONCLUSIVE | INCONCLUSIVE | C7 | 0 |
| C06 | column UPDATE on a masked source column | INCONCLUSIVE | INCONCLUSIVE | C5, W | 0 |
| C07 | DDL privilege on the source table | INCONCLUSIVE | INCONCLUSIVE | C5, W | 0 |
| C08 | INSERT on the published table | FAIL | FAIL | W | 0 |
| C09 | SELECT on the internal schema the agent cannot read | INCONCLUSIVE | INCONCLUSIVE | C5 | 0 |
| C10 | global SELECT | INCONCLUSIVE | INCONCLUSIVE | C5 | 0 |
| C11 | masked column moved to another existing policy | INCONCLUSIVE | INCONCLUSIVE | C7 | 0 |
| C12 | masking policy administration privilege for the privileged builder | FAIL | FAIL | W | 0 |

Every non-PASS scenario was refused at approval and at release with error
1644. Some scenarios flagged more checks than the expected ones; the raw
results keep the full lists. Three of them are worth knowing:

- C05 also flagged C6: once the gatekeeper names it, the builder reads
  values the agent does not, so the observed comparison differs.
- C10 also flagged C3, because two DEFINER views left on the lab instance by
  an earlier, unrelated experiment became reachable with global SELECT. The
  flagged set depends on what else exists on the instance.
- C12 also flagged C1, C4, C5 and C6. The privileged builder holds the
  unmasking role by design, so C1, C4 and C6 fail for it in every run; they
  do not affect its verdict because it is not declared a reader.

## Gate negatives

Each negative attempts one action the gate must refuse (or, for the
positive controls, one it must allow) and compares the result with the
expected error number and message. Categories map to the cases required for
this milestone: publish without valid approval, forged PASS, modify a sealed
artifact, change content between verification and publication, write
directly to the published tables, and separate accounts.

| Category | Scenarios | With the gate (phase B) | Without the gate (phase A) |
|---|---|---|---|
| publish without valid approval | 9 | 9 | 0 |
| forged verification | 9 | 9 | 0 |
| modify a sealed artifact | 7 | 7 | 0 |
| change between verification and publication | 4 | 4 | 0 |
| direct write to published tables | 9 | 9 | 3 |
| separation of duties | 9 | 9 | 1 |
| identity preconditions | 2 | 2 | 0 |
| observation state | 1 | 1 | 0 |
| administrator (trusted computing base) | 2 | 2 | 0 |
| positive control | 2 | 2 | 0 |
| **Total** | **54** | **54** | **4** |

What phase A shows and does not show: without the gate, 47 of the 50 unmet
negatives could not even be set up, because the quarantine and control
tables do not exist and no batch could be opened, and the other 3 failed on
the same missing tables during the attempt. The 4 that were still
met are refused by plain privileges (three direct writes, error 1142) or by
the locked definer account (error 3118), not by the gate. Phase A therefore
shows that the harness does not produce the expected refusals by itself. It
does not show that each refused action would succeed without the gate; a
deployment with the control tables but without the triggers and the release
procedure would be that stronger control, and it was not run.

## Agent demo

`python -m m1 agent` read the latest released batch (the C00 control
build) as `m1_agent`.

| Question | Top 3 released chunks (cosine) |
|---|---|
| Which suppliers are under compliance investigation? | three supplier profiles (0.643, 0.640, 0.632), none with compliance information |
| cold-chain logistics for pharma | two cold-chain logistics suppliers (0.765, 0.727), one freight forwarder (0.648) |

The first question asks for exactly what is masked. The agent returns
released profiles that carry no compliance information, because none was
released.

## Other observations

- **INCONCLUSIVE takes precedence over FAIL.** In C06 and C07 the write
  surface check failed, but the reader-equivalence check failed first, so the
  verdict is INCONCLUSIVE rather than FAIL. Both block publication; a
  reviewer who wants a write violation always reported as FAIL would change
  the decision order.
- **A broken masking contract stops the replay.** When the contract check
  fails (C03, C05, C11), the verifier does not replay the pipeline, and
  world and A/A are reported as not established in addition to the contract.
- **Timing.** Phase B (teardown, deploy and negatives) took about 17
  seconds, the experiments about 1.5 minutes and the clearance negatives
  about 3 minutes on this host.

## Limitations

- One host, one OS, one server version, both instances on the same host.
- Finite coverage: one source table with three masked columns, 6 twins per
  verification, 7 experiments, 13 clearance scenarios and 54 gate
  negatives. A PASS means no dependency on masked data was observed across
  the tested twins; it does not mean none exists.
- Each verification tells the builder one bit about masked data (published
  or not).
- The verifier varies only the database source. Inputs that do not come
  from it (files, environment, network, the model) are not varied.
- Batch ids and timestamps are not part of the content hash.
- The release procedure does not see which policy a column is bound to; the
  verifier checks bindings (C11), but a binding change between verification
  and release is not refused by the database.
- The lab administrator is in the trusted computing base. Separation of
  duties is between accounts, not people, and approvals in these runs were
  scripted.
- The gate attributes actions with `USER()`, whose user part is the name the
  client sent. It equals the authenticated account only because the
  identity preconditions refuse anonymous accounts and proxy mappings.
- The observation state hash covers the grants of every account on the
  instance, so an unrelated grant change also invalidates a pending
  verification (fails closed).
- C3 inspects views, routines and triggers; scheduled events are not
  inspected. Metadata the agent can read (for example statistics in
  `information_schema`) is not analysed.
- The content-scan baseline does not look for numeric masked values; the
  twins do vary them.
- The write-surface check W is conservative: any privilege other than SELECT
  outside the quarantine tables and internal schemas is a violation, even
  where it would be harmless.
- Phase A is a weak control (see above).
