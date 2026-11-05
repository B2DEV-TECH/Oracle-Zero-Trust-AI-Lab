# M1 — A release gate for an AI agent's knowledge base on MySQL Dynamic Data Masking

Status: implementation under review on a feature branch. Results come from
one environment (two local MySQL Enterprise instances on Windows) and are
described, with their limits, in [`RESULTS.md`](RESULTS.md). Nothing here is
a general security guarantee.

## The problem

MySQL Enterprise Dynamic Data Masking decides, at query time, what each
identity sees in a masked column. An AI agent that reads the source tables
through the masks gets the masked values. That is the read path.

Agents also read derived data: a knowledge base of chunks and embeddings
that a pipeline builds ahead of time. If that pipeline runs as an identity
that sees unmasked values, masking does not follow the data into the
knowledge base. The leak can be direct (a masked value copied into a chunk)
or indirect (a decision taken on a masked value, such as leaving out every
supplier under investigation, with no masked value in the output). A content
scan of the published text finds the first and cannot find the second.

M1 asks one question about each knowledge-base build: does the published
output depend on data the agent is not allowed to see? Only a build whose
answer is "no, within the tested scope" can reach the agent, and the
database enforces that.

## What M1 does

1. **Build-as-Reader.** The pipeline can run as a restricted builder that
   holds exactly the agent's read surface. A PASS for such a build is scoped
   as reader-equivalent only when the identity checks hold: granted, latent
   and nested roles, global role activation, DEFINER objects, effective
   identity at login, privileges, and an observed comparison of what the
   builder and the agent read. A declared reader that fails them is never
   approved automatically (verdict INCONCLUSIVE).
2. **Verification by replay and twin worlds.** The verifier replays the
   declared pipeline, as the same identity, on a separate shadow instance.
   It loads twin worlds that differ from the real data only in masked values
   and that read back identically to the agent (checked by reading them as
   the agent). If the published output changes across twins, it depends on
   masked data (verdict FAIL). A replay that does not reproduce the sealed
   output (A/A) is INCONCLUSIVE, not judged.
3. **A publication gate inside MySQL.** Quarantine, seal, verification,
   human approval and release are tables, triggers and one release procedure
   owned by a locked definer account. Only the verifier account can record a
   verification, only the approver can approve, only the release account can
   release, and release recomputes every hash and refuses anything but an
   approved PASS whose content, code, masking policy definitions, grants and
   role settings are still the ones that were verified. (Column bindings of
   policies are checked by the verifier, not by the release procedure; see
   the limitations in `RESULTS.md`.)
4. **An agent that reads only what was released.** `m1_agent` embeds the
   question with the same pinned model and ranks the published chunks by
   cosine similarity. There is no language model in the loop.

Privileged processing is allowed: a build that reads unmasked data for an
internal purpose (a review queue the agent cannot read) and publishes output
that does not depend on it passes, and the internal difference is reported.

## Accounts

| Account | Role in the flow |
|---|---|
| `m1_builder_p` | Privileged builder: holds the unmasking role as a default role |
| `m1_builder_r` | Restricted builder: reads what the agent reads (Build-as-Reader) |
| `m1_verifier` | Records verifications; reads quarantine and control data |
| `m1_approver` | Records the human decision (APPROVE or REJECT) |
| `m1_release` | Calls the release procedure and nothing else |
| `m1_agent` | Reads the sources through the masks and the published knowledge base |
| `m1_world` | Verifier's reader of the true source data, used only to load the shadow instance |
| `m1_gate_def` | Locked definer of every gate trigger and routine; cannot log in |

The lab administrator (root) deploys everything and is part of the trusted
computing base. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the
data flow, the schemas and the verdict rules.

## Layout

| Path | Content |
|---|---|
| `sql/10_core.sql` | Schemas, unmasking role, masking policies, synthetic source tables |
| `sql/20_gate.sql` | Quarantine and control tables, gate triggers, hash functions, release procedure |
| `sql/30_grants.sql` | Grants for every account |
| `sql/99_teardown.sql` | Removes every M1 object from an instance |
| `m1/` | Python package: setup, pipelines, build, verifier, clearance checks, twins, gate negatives, experiments, agent |
| `tests/` | Unit tests of the pure parts (hashing, twins, verdict rules, clearance evaluation, ranking) |
| `ops/` | Instance setup and stop scripts, model download with SHA-256 manifest, wheel lock builder |
| `requirements.lock` | Pinned and hashed wheels of the embedder environment (Windows x64, CPython 3.13) |
| `config.template.json` | Local settings: client path, secrets folder, results folder, model folder |

## Running it

Requirements: two disposable MySQL Enterprise Server instances of the same
version (tested: 26.7.0-commercial, Windows x64 ZIP), with the masking
component `component_object_policy` registered and binary logging on;
Python 3.13; no network access is needed after the wheels and the model are
downloaded.

1. Create the instances with `ops/setup-instance.ps1` (one call per instance,
   names `lab` and `shadow`, each on its own loopback port). It writes the
   administrator's client option file to `<lab folder>/secrets/`. Passwords
   are random and never printed.
2. Create a virtual environment and install the pinned wheels:
   `python -m pip install --require-hashes --no-deps -r requirements.lock`.
   Fetch the model once with `ops/fetch_model.py <model folder>`; it checks
   the ONNX weights against the hub digest and writes `MANIFEST.sha256`.
   The embedder refuses to load if any file differs from the manifest.
3. Copy `config.template.json` outside the repository, fill it in and point
   `M1_CONFIG` at it.
4. From this folder, with the virtual environment's Python:

   ```text
   python -m unittest discover -s tests
   python -m m1 deploy --instance lab
   python -m m1 deploy --instance shadow
   python -m m1 negatives               # gate negatives (lab)
   python -m m1 experiments             # C0, P0, P0b, P1, P2, PND, A/A
   python -m m1 clearance-negatives     # identity and policy perturbations (lab and shadow)
   python -m m1 agent --question "cold-chain logistics for pharma" -k 3
   python -m m1 teardown --instance lab
   ```

   `python -m m1 deploy --instance lab --core-only` deploys without the gate.
   Most gate negatives then cannot even be set up, because the control
   tables do not exist, which shows that the harness does not produce the
   expected refusals by itself; four are still met through plain privileges
   and the locked definer account (see `RESULTS.md`). Teardown before
   switching between the two deployments.

Every command that runs tests writes its raw result as JSON to the local
results folder. Those files contain identities, hashes and timings of one
environment and stay local; `RESULTS.md` holds the sanitized summary.

## Scope

In scope: MySQL Enterprise Dynamic Data Masking policies on one source
table, two builder identities, one shadow instance, a fixed set of twin
worlds, the gate negatives and the experiments listed in `RESULTS.md`.

Out of scope for this milestone: Oracle APEX, Oracle Deep Data Security,
HeatWave, MySQL REST Service, hosted models and language-model answers. All
data is synthetic.
