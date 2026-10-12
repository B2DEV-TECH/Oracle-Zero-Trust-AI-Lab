# E1 results: Deep Data Security foundation

First real execution of experiment E1, run on 2026-10-12 against a disposable
local database. Everything below was observed in that run. Nothing here is
extrapolated to other versions, platforms or configurations.

## Environment

- Oracle Database Free, version 23.26.3, native Windows installation, CDB with
  the pluggable database `FREEPDB1`.
- SQL*Plus 23.26.3 from the same Oracle home, driven from Git Bash.
- SYS steps connect with operating system authentication and switch to the
  PDB. Lab account steps connect over TCP to the PDB service.
- Synthetic data only: 12 invoices (NORTH 5, SOUTH 4, EAST 3; total 76000).

## Outcome

| Step | Connects as | Result |
|---|---|---|
| 00 preflight | SYS | OK (`E1_PREFLIGHT_OK`) |
| 01 principals | SYS | OK, schema-scoped `ADMINISTER ANY DATA GRANT ON SCHEMA` accepted |
| 02 schema and data | SYS | OK, 12 rows / 76000 |
| 03 audit policies | SYS | OK, 3 policies enabled, every audited action name accepted |
| 04a identities | SYS | OK, 3 data roles, 4 end users, 3 data role grants |
| 04b data grants | DDS_ADMIN | OK, 3 data grants |
| 05a NORTH tests | DDS_EU_NORTH | 17/17 PASS |
| 05b SOUTH tests | DDS_EU_SOUTH | 13/13 PASS |
| 05c NOACCESS tests | DDS_EU_NOACCESS | 4/4 PASS |
| 05d NOROLE logon | DDS_EU_NOROLE | PASS, logon refused with ORA-01045 |
| 06 evidence | SYS | 19/19 PASS (after the two fixes below) |

Steps 00 to 05d ran once and were not repeated. Only 06, which is read-only,
was run again after the fixes.

### History of the 06 evidence step

1. First run: exit code 2 and no PASS/FAIL line in the log. Cause: the
   PL/SQL output was lost (see U1). Fixed in every SYS script.
2. Second run: 18/19. E11 failed: the expectation (security contexts only
   for NORTH, SOUTH and NOACCESS) was a documentation hypothesis. The
   database also created and audited one for NOROLE (see U2). E11 now asserts
   the observed behavior.
3. Third run: E11 passed, E18 failed: a repeating scheduler job of another
   application, which existed before the lab, had started during the run.
   Each job start updates its `LAST_DDL_TIME` (see U4). E18 now ignores a job
   whose `LAST_DDL_TIME` matches its last start.
4. Fourth run: 19/19, exit code 0.

## What the run showed about Deep Data Security

1. **Row filtering by data grant.** NORTH saw exactly its 5 rows (sum 15000),
   SOUTH its 4 rows (sum 1000). EAST was invisible to both. Rows of another
   region could not be reached by key either.
2. **Column scope with `ALL COLUMNS EXCEPT`.** The excluded column
   (`SUPPLIER_TAX_ID`) came back as NULL in the select list, without an
   error. Filtering on it returned 0 rows, also without an error, so the
   predicate could not be used to infer the real value (N07, N14).
3. **Identity propagation into the predicate.** A data grant with
   `assigned_to = ora_end_user_context.username` let NORTH update its own
   invoice (1 row) and silently updated 0 rows on a visible invoice of the
   same region assigned to another identity.
4. **Three different denial shapes for DML and queries:**
   - row or column outside a grant the data role does have: silent
     "0 rows", no error (N11, N12, N13, N14);
   - data role without any grant for that privilege: ORA-41900 (INSERT and
     DELETE for NORTH; UPDATE, INSERT and DELETE for SOUTH);
   - data role without any grant on the table: ORA-00942, the table looks
     like it does not exist (NOACCESS).
5. **Session identity.** In an end-user session, `SESSION_USER`,
   `CURRENT_USER` and `CURRENT_SCHEMA` are `XS$NULL`. The active data role is
   visible in `V$END_USER_DATA_ROLE`.
6. **Identity in the audit trail.** Data access records carry
   `DBUSERNAME = XS$NULL`, the end user in `END_USER_NAME` and a non-null
   `END_USER_SECURITY_CONTEXT_ID`. Configuration actions (data grants by
   DDS_ADMIN, end users and data roles by SYS) leave `END_USER_NAME` empty.
7. **Silent denials are visible in the audit trail.** Every DML that the
   client saw as "0 rows" was audited with return code 2004 (security
   violation). ORA-41900 and ORA-00942 were also recorded as 2004. Each DML
   also produced a SELECT record with the same statement text and the same
   return code.
8. **Direct logon.** `CREATE SESSION` reaches the end user through a database
   role granted to a data role. An end user without a data role is refused
   with ORA-01045.
9. **Least privilege for the grant administrator.** DDS_ADMIN created the 3
   data grants holding only `CREATE SESSION`, `CREATE DATA GRANT` and
   `ADMINISTER ANY DATA GRANT ON SCHEMA DDS_INV_OWNER`, no role.
10. **Auditing of the configuration.** Unified Auditing accepted
    `CREATE/DROP DATA ROLE` and `GRANT/REVOKE DATA ROLE` as policy actions and
    captured the 10 SYS configuration actions of step 04a.
11. **Dictionary.** `DBA_DATA_GRANTS` returns one row per granted column for
    an `ALL COLUMNS EXCEPT` grant, with the excluded column in
    `GRANTED_WITH_ALL_COLUMNS_EXCEPT`. Direct-logon security contexts are no
    longer listed in `DBA_END_USER_SECURITY_CONTEXTS` once the session ends.
12. **No credential exposure.** No generated password appeared in the audited
    `SQL_TEXT` (E15) or in a `V$SQL` cursor (O05), and a scan of the local
    logs for the exact password values found none.

## Unexpected behavior

- **U1. `DBMS_OUTPUT` after `ALTER SESSION SET CONTAINER`.** `SET
  SERVEROUTPUT ON` issued in the root did not apply after the switch to the
  PDB, so every `DBMS_OUTPUT` line of the SYS scripts was dropped without an
  error. Checks that raise an exception still stopped the scripts, so no
  failure went unnoticed. The scripts now repeat `SET SERVEROUTPUT ON` after
  the switch.
- **U2. A refused logon looks like a successful context creation.** For
  DDS_EU_NOROLE the database created and audited the end-user security
  context with return code 0, then refused the logon with ORA-01045. No
  failed LOGON record was written, in this PDB or in any other container,
  although `ORA_LOGIN_LOGOUT` is enabled for failures. Consequence: a
  successful context record is not proof of a successful logon, and refused
  end-user logons were not visible in the audit trail of this configuration.
- **U3. N14 differs from the documented semantics.** An UPDATE filtering on a
  column without SELECT returned 0 rows rather than the documented
  ORA-41900. The test accepted both outcomes, so it passed, and the
  divergence is recorded as an observation.
- **U4. Scheduler job runs change `LAST_DDL_TIME`.** This is general database
  behavior, not Deep Data Security, but it made the "no DDL outside the lab"
  check fail on a busy database.
- **U5. Return code 2004 on some queries.** Some SELECT statements that
  returned normally to the client (a filter on the excluded column, a filter
  on invoice ids of another region) were audited with return code 2004,
  while others with zero visible rows (`region <> 'NORTH'`) were audited with
  0. The exact rule is not characterized yet.

## Not verified by E1

- Bypass by privileged database users, `SET USE DATA GRANTS ONLY` (MAC) and
  other privileged paths. Planned for E4.
- Whether `DBA_END_USER_SECURITY_CONTEXTS` lists a context while its session
  is still open. The active-session guard relies on it. E1 only showed that
  closed sessions are not listed.
- Whether a dedicated audit policy captures refused end-user logons (U2).
- Concurrency, performance, APEX, ORDS and external identity providers.

## Limitations

- One run, one environment, one platform.
- Comments in the SQL scripts still mention a runner, a runbook, decision
  records and runtime assumption ids (RA-xx) from an earlier plan. That runner
  was dropped. The scripts are run directly with SQL*Plus (see the README).
