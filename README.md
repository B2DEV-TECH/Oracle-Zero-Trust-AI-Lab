# Oracle Zero Trust AI Lab

A gated, documentation-first laboratory that studies how Oracle APEX and
Oracle Deep Data Security (end-user security contexts, data roles and data
grants) can enforce least-privilege data access for AI-assisted database
applications. Identity federation with an external identity provider is
planned for later phases.

## Status

- Experiment E1 (Deep Data Security foundation) was executed for the first
  time on 2026-10-12 against a disposable local Oracle Database Free 23.26.3.
  All access tests and evidence checks passed after two fixes to the
  evidence script. Results, observed behavior and limitations are in
  [`lab/e1/RESULTS.md`](lab/e1/RESULTS.md). They come from one run in one
  environment and are not a general security guarantee.
- Next phases: E2 (APEX application with external identity and end-user
  propagation), E3 (APEX AI agents and tools bound to database permissions),
  E4 (attack scenarios such as prompt injection, unauthorized access and
  privileged paths).
- Changes reach `main` only through reviewed pull requests.

## Running E1

E1 needs a database you can discard. The scripts create the lab principals
`DDS_INV_OWNER`, `DDS_ADMIN`, `DDS_INV_PARSE`, the role `DDS_SESSION_ROLE`,
the data roles `DDS_DR_*`, the end users `DDS_EU_*`, the table
`DDS_INV_OWNER.INVOICES` and the audit policies `DDS_E1_*`. They target the
PDB `FREEPDB1`.

1. Copy `lab/e1/*.sql` to a working folder outside the repository and create
   two local files there (both match `*.local.sql` and are ignored by Git):
   - `e1_conn.local.sql` with one line:
     `define dds_conn = "//<db-host>:<listener-port>/<pdb-service>"`
   - `secrets/e1_secrets.local.sql` with five lines
     `define dds_admin_pwd = "..."`, `dds_eu_north_pwd`, `dds_eu_south_pwd`,
     `dds_eu_noaccess_pwd`, `dds_eu_norole_pwd`, each a unique random value
     made of `E1` and 22 letters or digits (the evidence step searches for
     that pattern).
2. With `ORACLE_HOME` and `ORACLE_SID` pointing at the database home, run the
   steps in order with `sqlplus -L -S <connection> @<script> </dev/null`:
   `00` to `04a` and `06` as `"/ as sysdba"`; `04b` and `05a` to `05d` with
   `/nolog` (they connect by themselves). Stop at the first setup step
   (`00` to `04b`) that does not exit with 0. `00` writes
   `e1_target.local.sql`, which the later steps need.
3. Read each test log: every assert prints `PASS` or `FAIL` and a `SUMMARY`
   line. `05d` exits with 0 and passes when its log shows ORA-01045.
4. `99_cleanup.sql` removes only the lab objects. The repository does not run
   it automatically.

The SQL comments still mention a runner, a runbook and decision records from
an earlier plan. That runner was dropped.

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
