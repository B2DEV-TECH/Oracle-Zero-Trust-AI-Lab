# Oracle Zero Trust AI Lab

A gated, documentation-first laboratory that studies how Oracle APEX and
Oracle Deep Data Security (end-user security contexts, data roles and data
grants) can enforce least-privilege data access for AI-assisted database
applications. Identity federation with an external identity provider is
planned for later phases.

## Status

- Early stage. Lab sources are proposed on feature branches and reviewed
  through pull requests before they reach `main`.
- No laboratory step has been executed against a database as part of this
  repository. No test results, measurements or security guarantees are
  claimed.
- Each phase advances only after explicit human approval.

## Work in progress (feature/e1-deepsec-foundation)

This branch is incomplete and is published for review only. It is not ready
to run.

Present:

- `lab/e1/*.sql`: experiment E1 SQL scripts (preflight, principals, synthetic
  schema and data, audit policies, end-user identities, data grants, access
  tests, evidence collection, retain-and-lock, provenance-checked cleanup,
  active-session guard and target assertion).

Pending, not yet committed:

- `lab/e1/run_e1.sh`: the runner, with SQL*Plus timeout supervision and
  approval checkpoints bound to source hashes.
- `lab/e1/RUNBOOK.md` and `lab/e1/e1_local.env.template`.
- `lab/e1/E1-SOURCES.sha256`: the source manifest.
- Architecture overview, decision records (including the ADR referenced by
  `04b_data_grants.sql`), threat model, risk register, the separate MAC
  experiment design and the list of runtime assumptions.
- Static validation under `tests/static/`.

The SQL scripts reference the runner and documents listed above. Nothing on
this branch has been executed against a database, and no security property
described here has been verified at runtime.

## Principles

- Synthetic data only. The repository never contains production data,
  credentials, generated secrets, wallets, logs, execution state or details
  of a specific environment (hostnames, ports, local paths, database
  identifiers). Local settings are supplied through templates.
- Official Oracle documentation is the primary reference.
- Verified facts, assumptions, hypotheses and open questions are tracked
  separately and labeled as such.
- Database-enforced security is the subject under study; application-level
  authorization is documented as a separate layer, not as a substitute.

## License

No license has been selected for this repository yet.

## Trademarks

Oracle, Java, MySQL and NetSuite are registered trademarks of Oracle and/or
its affiliates. This project is independent and is not affiliated with or
endorsed by Oracle.
