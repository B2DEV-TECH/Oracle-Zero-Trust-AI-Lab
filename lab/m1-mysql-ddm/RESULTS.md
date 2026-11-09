# M1 results

Evidence runs on 2026-11-05 (Runs 1 to 3) and 2026-11-09 (Run 4), each from
fresh deployments, in one environment. Every number below comes from the
runs' raw results, which stay local because they hold identities, hashes and
timings of one machine. These are observations within the tested scope, not
a security guarantee.

| Run | Code | Instances | What it is |
|---|---|---|---|
| Run 1 | `c7688b8` | lab and shadow | the original evidence, kept below as recorded |
| Run 2 | `c7688b8` | a second pair, created for these runs | the same sequence again, to check reproducibility under isolated conditions |
| Run 2b | `917bb91` | second pair | first run of the phase A control (54 gate negatives) |
| Run 3 | `4d09c75` | second pair, every M1 object redeployed | full sequence, phase A control, `activate_mandatory_roles` |
| Run 4 | `8954e87` | second pair, every M1 object redeployed | the current evidence: G50 closed at release, before and after, then the full sequence |

For each run, the files under `m1/`, `sql/` and `tests/` that ran match, by
SHA-256, the files of the commit named in the table. The commit that adds
this version of the document changes documentation only, so its code is
Run 4's.

## Environment

| Item | Value |
|---|---|
| Database | MySQL Enterprise Server 26.7.0-commercial, Windows x64 ZIP, component `component_object_policy` |
| Instances | two on one host (lab and shadow), loopback only, binary logging on; Runs 2, 2b, 3 and 4 used a second pair on the same host and version, created for them |
| OS and runtime | Windows 11, CPython 3.13.15 |
| Embedder | fastembed 0.9.1, onnxruntime 1.31.1, numpy 2.5.4, tokenizers 0.23.3 (hashed wheels in `requirements.lock`) |
| Model | `BAAI/bge-small-en-v1.5`, revision `5c38ec7c405ec4b44b94cc5a9bb96e735b38267a`, files checked against a SHA-256 manifest, one thread, network sockets blocked |
| Data | synthetic: 24 suppliers, 72 invoices; masked columns `tax_id` (last four characters visible), `compliance_note` (constant), `risk_score` (0) |
| Twins | 6 per verification (3 permutation, 3 synthetic), seed 20261113, coverage minimum 0.8 of rows per masked column |

## Run 1: original evidence (`c7688b8`)

Kept as recorded. Where a later run changes how a passage reads, the later
section says so: phase A (Run 3) and the C3 flag in C10 (Run 2).

### Sequence

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

### Experiments

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

### Clearance negatives

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

### Gate negatives

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

### Agent demo

`python -m m1 agent` read the latest released batch (the C00 control
build) as `m1_agent`.

| Question | Top 3 released chunks (cosine) |
|---|---|
| Which suppliers are under compliance investigation? | three supplier profiles (0.643, 0.640, 0.632), none with compliance information |
| cold-chain logistics for pharma | two cold-chain logistics suppliers (0.765, 0.727), one freight forwarder (0.648) |

The first question asks for exactly what is masked. The agent returns
released profiles that carry no compliance information, because none was
released.

### Other observations

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

## Run 2: reproduction under isolated conditions (`c7688b8`)

Run 1's lab instance had hosted earlier, unrelated experiments, and C10
showed that their leftovers can change what the clearance checks flag. Run 2
repeated Run 1's whole sequence, with the same code, on a second pair of
instances created for it on the same host, which had never hosted anything
else.

| Step | Run 1 | Run 2 |
|---|---|---|
| Unit tests | 41, OK | 41, OK |
| Phase A (`--core-only`) | 4 of 54 | 4 of 54, the same four |
| Phase B | 54 of 54 | 54 of 54 |
| Experiments | 7 of 7 | 7 of 7 |
| Clearance negatives | 13 of 13, state restored | 13 of 13, state restored |
| Agent demo (first question) | 0.643, 0.640, 0.632 | three supplier profiles, same scores |

Every scenario flagged the same set of checks in both runs except C10, which
flagged C5 only in Run 2: the extra C3 of Run 1 came from the leftover
DEFINER views, not from M1. The sealed content hashes of C0, P0, P0b, P1 and
P2 were the same in Runs 1, 2 and 3; PND's differ, as a nondeterministic
build should.

## Run 3: phase A control and mandatory role activation (`4d09c75`)

Kept as recorded. Run 4 changes G50's outcome and adds G56 and G57 (see
Run 4).

Two commits separate Run 3's code from Run 1's:

- `917bb91` adds the phase A control: a deployment option, a release
  procedure without checks, and a prediction for every gate negative,
  written before the control first ran (Run 2b).
- `4d09c75` adds `activate_mandatory_roles` to what the gate and the
  verifier observe: the clearance snapshot records it, the observation state
  hash covers it (tag `m1-obs-v2`), teardown resets it, and gate negative
  G55 and clearance scenario C13 test it.

The verifier's decision rules, the pipelines, the masking policies and the
gate's checks are otherwise unchanged.

### Sequence

| Step | Outcome |
|---|---|
| Unit tests | 50 tests, OK |
| Weak phase A: gate negatives without the gate (`--core-only`) | 4 of 55 met, the same four as Run 1 |
| Phase B: gate negatives with the gate | 55 of 55 met |
| Phase A control (`--control`, then `phase-a`) | 55 of 55 predictions held; the gate adds a refusal in 34 of 52 comparable scenarios |
| Experiments on fresh lab and shadow instances | 7 of 7 as expected, same verdicts and published rows as Run 1 |
| Clearance negatives, same instances | 14 of 14 as expected; lab and shadow state restored |
| Agent demo (first question) | three supplier profiles, same scores as Run 1 |

The expectations of G55 and C13, and G55's phase A prediction, were written
in commit `4d09c75` before Run 3.

### Phase A control

The weak phase A of Run 1 removes the gate's tables along with the gate, so
most negatives cannot even start. The control keeps everything an attempt
touches and removes only what enforces:

| Kept, as in the gate deployment | Removed |
|---|---|
| schemas, quarantine, control and published tables, keys | the 21 gate triggers |
| accounts, grants, the locked definer account | every check in the release procedure |
| the four functions (content hashes, observation state hash, identity preconditions) | |
| the release procedure's name, definer, `SQL SECURITY DEFINER`, transaction and copy into the published table | |

It ran on the second pair of instances, never on Run 1's. The same 55 gate
negatives run on it, and each result is compared with a prediction written
before the control first ran and with phase B. Outcome classes:

| Class | Meaning | Count |
|---|---|---|
| succeeded | the action the gate refuses goes through | 34 |
| met | the expectation is met without the gate | 17 |
| other | refused, by a mechanism other than the expected one | 1 |
| not executable | cannot run as written without the gate | 2 |
| not comparable | runs, but its result means nothing without the gate | 1 |

By category:

| Category | Scenarios | With the gate (phase B) | Control: succeeded, refused only with the gate | Control: met | Control: other, not executable, not comparable | Weak phase A (`--core-only`) |
|---|---|---|---|---|---|---|
| publish without valid approval | 9 | 9 | 9 | 0 | 0 | 0 |
| forged verification | 9 | 9 | 5 (1 administrator) | 4 | 0 | 0 |
| modify a sealed artifact | 7 | 7 | 5 (4 administrator) | 1 | 1 not executable | 0 |
| change between verification and publication | 5 | 5 | 4 | 0 | 1 not executable | 0 |
| direct write to published tables | 9 | 9 | 5 (5 administrator) | 3 | 1 other | 3 |
| separation of duties | 9 | 9 | 3 | 6 | 0 | 1 |
| identity preconditions | 2 | 2 | 2 | 0 | 0 | 0 |
| observation state | 1 | 1 | 1 | 0 | 0 | 0 |
| administrator (trusted computing base) | 2 | 2 | 0 | 2 | 0 | 0 |
| positive control | 2 | 2 | 0 | 1 | 1 not comparable | 0 |
| **Total** | **55** | **55** | **34 (10 administrator)** | **17** | **4** | **4** |

Comparable: 52 scenarios, everything except the three below.

- **Not executable (G18, G46).** Both begin with the administrator dropping
  a gate trigger, which does not exist without the gate (error 1360). G14 is
  the comparable administrator edit.
- **Not comparable (G40).** This positive control checks that the seal
  carries the hash a gate trigger computes. Without the gate the seal has
  none, which says nothing about a refusal.

What each comparable result shows:

- **The gate adds a refusal in 34 scenarios.** Each went through on the
  control and was refused with error 1644 in phase B, so the refusal is the
  gate's and not the result of privileges, the account lock or the keys. In
  24 the actor is not the administrator: approval or release without a
  valid PASS behind it (9), invalid PASS records by the verifier account (4),
  a chunk added after the seal (1), role, policy and role activation
  changes between approval and release (4, G55 among them), a builder
  writing into or sealing another builder's batch and the seal of an empty
  batch (3), an anonymous account or a proxy mapping (2) and a grant change
  during a build (1). In 10 the actor is the administrator, who
  can drop the triggers (G18 does, in phase B), so there the gate is a
  guardrail, not a boundary.
- **17 are met without the gate.** Plain privileges refuse 11 (error 1142)
  and the EXECUTE grant on the release procedure 2 (error 1370); the locked
  definer account refuses 1 (error 3118). G39, a positive control, shows that
  the release interface works without the gate. G50 is the known gap below:
  it is released with and without the gate. G54 is detective only: the
  integrity audit finds a truncated published table in both deployments, and
  neither prevents it.
- **1 is refused by something else.** G41, a second release of a released
  batch, is refused by the published table's primary key (error 1062)
  instead of the gate (error 1644). It is refused either way; the gate's
  refusal comes first and names the reason.
- **What the control released.** At the end of the control run its release
  log held 11 releases, 2 of them recorded with no verification or no
  approval for the batch.

The counts are of scenarios written for this milestone. They are not a
coverage measure and do not weigh one scenario against another. Run 2b, the
first control run, at `917bb91` without G55, held 54 of 54 predictions, with
the gate adding a refusal in 33 of 51 comparable scenarios.

### Clearance negatives

Same procedure as Run 1, with C13 added. The last column is the full set of
flagged checks; the expected checks are a subset of it.

| ID | Perturbation | Expected | Observed | Expected checks | All checks flagged |
|---|---|---|---|---|---|
| C00 | none (control) | PASS | PASS | none | none |
| C01 | unmasking role granted to the restricted builder, not activated | INCONCLUSIVE | INCONCLUSIVE | C1 | C1 |
| C02 | `activate_all_roles_on_login` switched on | INCONCLUSIVE | INCONCLUSIVE | C2 | C2 |
| C03 | unmasking role named in `mandatory_roles` | INCONCLUSIVE | INCONCLUSIVE | C2, C3, C7 | C2, C3, C4, C7 |
| C04 | DEFINER view over the source, owned by an account that reads unmasked data | INCONCLUSIVE | INCONCLUSIVE | C3 | C3 |
| C05 | policy gatekeeper changed to name the restricted builder | INCONCLUSIVE | INCONCLUSIVE | C7 | C6, C7 |
| C06 | column UPDATE on a masked source column | INCONCLUSIVE | INCONCLUSIVE | C5, W | C5, W |
| C07 | DDL privilege on the source table | INCONCLUSIVE | INCONCLUSIVE | C5, W | C5, W |
| C08 | INSERT on the published table | FAIL | FAIL | W | W |
| C09 | SELECT on the internal schema the agent cannot read | INCONCLUSIVE | INCONCLUSIVE | C5 | C5 |
| C10 | global SELECT | INCONCLUSIVE | INCONCLUSIVE | C5 | C5 |
| C11 | masked column moved to another existing policy | INCONCLUSIVE | INCONCLUSIVE | C7 | C7 |
| C12 | masking policy administration privilege for the privileged builder | FAIL | FAIL | W | C1, C4, C5, C6, W |
| C13 | as C03, with `activate_mandatory_roles` switched off | INCONCLUSIVE | INCONCLUSIVE | C2, C3, C7 | C2, C3, C7 |

Every non-PASS scenario was refused at approval and at release with error
1644, and no row was published. The flagged sets of C00 to C12 are the same
as in Runs 1 and 2, except C10's C3 in Run 1 (see Run 2).

### Mandatory roles

`activate_mandatory_roles`, ON by default, makes the server activate the
roles named in `mandatory_roles` at login, even with
`activate_all_roles_on_login` OFF. C03 and C13 differ only in that setting:

| | C03 (setting ON, the default) | C13 (setting OFF) |
|---|---|---|
| active role at login, restricted builder | `m1_r_unmask` | none |
| active role at login, `m1_agent` | `m1_r_unmask` | none |
| unmasking role reachable by `m1_agent` | yes | yes |
| checks flagged | C2, C3, C4, C7 | C2, C3, C7 |
| verdict | INCONCLUSIVE | INCONCLUSIVE |

C4 is flagged only in C03 because only there does a live login come up with
an active role. Under both, the role is granted to every account, so the
agent can activate it; switching the setting off does not remove the
exposure, and the verdict does not change.

G55 switches the setting off between approval and release. In Run 3 the
release was refused with error 1644 (`observation state changed`). The same
G55 steps against a deployment of `917bb91`, whose observation state hash
(`m1-obs-v1`) did not cover the setting, released the batch: before
`4d09c75` that change went unnoticed by the release checks.

A configuration lesson that holds without M1: the masking policies unmask
for `CURRENT_ROLE_IN('m1_r_unmask')`, and in C03 the agent's own login
already has that role active, so the agent's reads of the source tables
return original values. M1 refused approval and release; that protects the
published knowledge base, not the source read path. `mandatory_roles` must
never name a role that a masking policy's gatekeeper tests, and
`mandatory_roles`, `activate_mandatory_roles` and
`activate_all_roles_on_login` are all part of the masking boundary. This is
documented server behavior, not a defect.

## Run 4: G50 closed at release (`8954e87`)

One commit separates Run 4's code from Run 3's. `8954e87` adds one check to
the release procedure and the tests for it. The verifier, the pipelines, the
masking policies, the observation state hash (`m1-obs-v2`) and every other
gate check are unchanged.

### The gap and the check that closes it

Through Run 3, G50 moved a masked column to another existing policy after
approval, and the batch was released with and without the gate. Column
bindings are visible only through `SHOW CREATE TABLE`, which a routine cannot
read, and no catalog a routine can read records them on this server:
`mysql.column_masking_policies` and `performance_schema.column_masking_policy`
list policies only, and `information_schema.COLUMNS.EXTRA` says
`MASKING POLICY` without naming it. Moving a column to another policy changes
none of them, so the observation state hash cannot cover bindings.

Every statement that changes a binding is DDL on the source table, and on
this server every such DDL sets the table's `CREATE_TIME` in
`information_schema.TABLES`. Probed on the lab instance of the second pair
before the change, comparing every column of the candidate catalogs:

| Statement on `m1_src.suppliers` | Binding changed | `CREATE_TIME` changed |
|---|---|---|
| `MODIFY ... MASKING POLICY`, with the default algorithm, `INSTANT`, `INPLACE` and `COPY` | yes | yes |
| `CHANGE ... MASKING POLICY` | yes | yes |
| `ALTER COLUMN ... SET MASKING POLICY`, `ALTER COLUMN ... DROP MASKING POLICY` | yes | yes |
| `MODIFY` without a policy (unbind) | yes | yes |
| two columns swap their policies in one statement | yes | yes |
| `CREATE` and `DROP MASKING POLICY`, `GRANT` and `REVOKE` (a role, `ALTER`), `SET GLOBAL`, `UPDATE`, `ANALYZE TABLE` | no | no |

`CREATE_TIME` has whole-second resolution (truncated) and is shown in the
session time zone, like the batch's `created_at`. Of everything else read,
only the InnoDB table id changed, and only with `COPY`.

The release procedure now refuses a batch when any `m1_src` table has a
`CREATE_TIME` in or after the second the batch was opened (error 1644,
`source table definition changed after the batch was opened`). If no source
table is visible, it refuses too. The check runs after the observation state
check, so the refusals of Run 3 keep their messages.

How it covers the window between the binding check and the release: the
verifier checks the bindings (C7, from `SHOW CREATE TABLE`) during
verification, which can only start after the batch was opened and sealed. A
binding that differs from the contract at that check gives INCONCLUSIVE,
which is never approved or released. A binding changed at any later moment,
up to the release, gives the table a `CREATE_TIME` in or after the second the
batch was opened, and the release is refused. Because the comparison is with
the batch's opening second and not with an earlier `CREATE_TIME`, a change in
the same second as an earlier DDL cannot hide, and moving a column and moving
it back (G57) is refused as well.

### Sequence

Commands as in the README, from `lab/m1-mysql-ddm`, with `M1_CONFIG` pointing
at the second pair's settings. Every deployment was fresh (teardown first).

| Step | Commands | Outcome |
|---|---|---|
| Unit tests | `python -m unittest discover -s tests` | 58 tests, OK |
| G50 before: the code of `8954e87` with `sql/20_gate.sql` of `f226ed1` | `deploy --instance lab`, then `negatives --only G39 G50 G56 G57` | G39 and G56 met; G50 and G57 not met: each batch was released, 2 rows published, 1 release record |
| G50 after: the code of `8954e87` | the same | 4 of 4 met |
| Weak phase A | `deploy --instance lab --core-only`, `negatives` | 4 of 57 met, the same four as Runs 1 and 3 |
| Phase B | `deploy --instance lab`, `negatives` | 57 of 57 met; observation state restored |
| Phase A control | `deploy --instance lab --control`, `phase-a --gate-result <phase B result>` | 57 of 57 predictions held; the gate adds a refusal in 36 of 54 comparable scenarios |
| Experiments on fresh lab and shadow instances | `deploy` on both, `experiments` | 7 of 7 as expected, same verdicts and published rows as Run 1 |
| Clearance negatives, same instances | `clearance-negatives` | 14 of 14 as expected; lab and shadow state restored |
| Agent demo | `agent --question ... -k 3` | the same top three scores as Run 1 for both questions (0.643, 0.640, 0.632: three supplier profiles with no compliance information; 0.765, 0.727, 0.648: two cold-chain suppliers and a freight forwarder) |

The code sets of the before and after steps differ only in `sql/20_gate.sql`;
both were recorded by SHA-256.

### G50 before and after, and the scenarios added with it

| ID | What happens | Before (`f226ed1` gate) | After (`8954e87`) | Phase A control |
|---|---|---|---|---|
| G50 | masked column moved to another existing policy after approval, then release | released: 2 rows published, 1 release record | refused, 1644, `source table definition changed after the batch was opened`; 0 rows published, no release record | released |
| G57 | moved after the seal and moved back before the verification is recorded; PASS, APPROVE, release | released: 2 rows, 1 release record | refused, same error and message; 0 rows, no release record | released |
| G56 | positive control: moved and moved back 1.1 seconds before the batch is opened; seal, PASS, APPROVE, release | released: 2 of 2 rows, 1 release record | released: 2 of 2 rows, 1 release record | released |
| G39 | positive control: seal, PASS, APPROVE, release, binding untouched | released | released | released |

G50 and G57 now also check what reached publication: a refusal is met only
with no published row and no release record for the batch, and G56 only when
every quarantined row is published under one release record. G57's
verification is recorded after the binding is back, so a binding check at
that moment finds the contract in force; the release is refused because the
table was altered after the batch was opened. G56 shows the other side: a
change made and undone before the batch is opened does not block it.

The legitimate flow with the real verifier is unchanged: C0, P1 and P2 in the
experiments and C00 in the clearance negatives were approved and released,
and each published copy hashed to its seal.

### Phase A control

Same procedure as Run 3, with 57 scenarios. G50 moved to the category
"change between verification and publication" and out of the administrator
set: the change is the administrator's, as in G47 to G49 and G55, but the
action the gate refuses is the release by the release account. The
predictions for G50, G56 and G57 were written in `8954e87`, before the
control ran.

| Class | Run 3 | Run 4 |
|---|---|---|
| succeeded | 34 | 36 (G50, met in Run 3, and G57) |
| met | 17 | 17 (G56 in, G50 out) |
| other | 1 | 1 |
| not executable | 2 | 2 |
| not comparable | 1 | 1 |

| Category | Scenarios | With the gate (phase B) | Control: succeeded, refused only with the gate | Control: met | Control: other, not executable, not comparable | Weak phase A (`--core-only`) |
|---|---|---|---|---|---|---|
| publish without valid approval | 9 | 9 | 9 | 0 | 0 | 0 |
| forged verification | 9 | 9 | 5 (1 administrator) | 4 | 0 | 0 |
| modify a sealed artifact | 7 | 7 | 5 (4 administrator) | 1 | 1 not executable | 0 |
| change between verification and publication | 7 | 7 | 6 | 0 | 1 not executable | 0 |
| direct write to published tables | 9 | 9 | 5 (5 administrator) | 3 | 1 other | 3 |
| separation of duties | 9 | 9 | 3 | 6 | 0 | 1 |
| identity preconditions | 2 | 2 | 2 | 0 | 0 | 0 |
| observation state | 1 | 1 | 1 | 0 | 0 | 0 |
| administrator (trusted computing base) | 1 | 1 | 0 | 1 | 0 | 0 |
| positive control | 3 | 3 | 0 | 2 | 1 not comparable | 0 |
| **Total** | **57** | **57** | **36 (10 administrator)** | **17** | **4** | **4** |

The gate adds a refusal in 36 of 54 comparable scenarios: 26 where the actor
is not the administrator (Run 3's 24, G50 and G57) and the same 10 where it
is. At the end of the control run its release log held 13 releases, 2 of
them with no verification or no approval for the batch. As in Run 3, these
counts are of the scenarios written for this milestone, not a coverage
measure.

### Reproducibility against Run 3

- Phase B: every scenario of Run 3 gave the same result and the same observed
  error and message, except G50 (released in Run 3, refused now). G56 and G57
  are new.
- Weak phase A: the same four met (G34, G35, G36, G44).
- Experiments: same verdicts and published rows; the sealed content hashes of
  C0, P0, P0b, P1 and P2 are the same as in Runs 1, 2 and 3, and PND's differs
  again, as a nondeterministic build should.
- Clearance negatives: every scenario gave the same verdict, the same full
  set of flagged checks and the same published rows as Run 3.
- Unit tests: 58, Run 3's 50 plus 8 for the publication checks of the
  negatives and the release message.
- Timing: phase B (teardown, deploy and negatives) about 17 seconds, the
  experiments about 1 minute, the clearance negatives about 2.5 minutes.

No other divergence from Run 3 was observed.

## Review checks

Four points from the review of the first version, and where each stands:

1. **P1 is safe for the agent, not faithful to its intent.** P1 passed every
   check, but under the masks its compliance filter removes nothing (Run 1,
   experiments; again in Run 3, with C0's content hash). A PASS says the
   published output does not depend on masked data. It does not say the
   pipeline still does its job, and P1 must not be read as a working filter.
2. **The weak phase A is not causal.** The `--core-only` deployment shows
   only that the harness does not produce the refusals by itself; it
   attributes no refusal to the gate. It is kept, and was rerun in Run 3,
   for comparison; the attribution comes from the phase A control.
3. **G50 is closed at release (Run 4).** Through Run 3, a masked column
   moved to another existing policy between verification and release was
   released, with the gate and without it (phase A control): the verifier
   refuses the binding change at verification time (C11), and the
   observation state hash cannot see bindings, which are visible only through
   `SHOW CREATE TABLE`. The release procedure now refuses a batch whose
   source tables were altered in or after the second it was opened, which
   every binding change on this server does. G50 and G57 are refused with no
   published row; G39, G56 and the experiments' PASS builds are still
   released. The limits of the check are listed below.
4. **Isolated reproducibility.** Run 2 reproduced Run 1 on instances that
   had hosted nothing else, with one difference, explained by the leftover
   DEFINER views of Run 1's instance (C10). Runs 3 and 4, on the same
   isolated pair, agree with both, apart from what Run 4's change explains.

## Limitations

- One host, one OS, one server version, both instances of a pair on the same
  host.
- Finite coverage: one source table with three masked columns, 6 twins per
  verification, 7 experiments, 14 clearance scenarios and 57 gate
  negatives. A PASS means no dependency on masked data was observed across
  the tested twins; it does not mean none exists.
- Each verification tells the builder one bit about masked data (published
  or not).
- The verifier varies only the database source. Inputs that do not come
  from it (files, environment, network, the model) are not varied.
- Batch ids and timestamps are not part of the content hash.
- The release procedure does not see which policy a column is bound to. It
  refuses a batch whose source tables had DDL in or after the second it was
  opened, and the verifier checks the bindings themselves (C7). That check
  rests on `CREATE_TIME` changing with every DDL, observed on
  26.7.0-commercial for the statements listed in Run 4, and on the server
  clock not going backwards. It fails closed in two harmless cases: any DDL
  on a source table refuses pending batches, and so does a DDL in the same
  second as a batch is opened. A DDL that commits after the release
  procedure's check and before its commit is not refused, as for the other
  release checks. The refusal does not say which binding changed; the
  verifier does.
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
- The gate protects publication only. It does not protect the source tables:
  a role misconfiguration that unmasks the agent's reads (C03) is detected
  and blocks publication, but the agent's own reads are not M1's to stop.
- The phase A control removes the gate's enforcement and keeps the rest of
  this deployment. Its counts depend on these grants and on the scenarios
  written; they are not a general measure of what the gate adds.
