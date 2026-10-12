-- ============================================================================
-- E1 / 98 - RETAIN WITH LOCKED ACCOUNTS       [C4-retain, SYS privilege, reversible]
-- Run as: sqlplus -L -S "/ as sysdba" @98_retain_lock.sql <Y|N>
--   Parameter 1 (decided by the runner): Y = step 06 of this run passed and the
--   evidence has been collected; N = no 06 PASS (containment of an interrupted
--   run). Any other value aborts before any LOCK (ORA-20993).
--
-- Purpose: keep every E1 object for E2 and close the logon surface. This is the
-- default C4 path.
-- Effects in PDB FREEPDB1 (exact allowlist names only):
--   ALTER USER     dds_admin ACCOUNT LOCK
--   ALTER END USER dds_eu_north | dds_eu_south | dds_eu_noaccess | dds_eu_norole ACCOUNT LOCK
--   Only with parameter Y and every account confirmed LOCKED:
--   NOAUDIT POLICY dds_e1_config_pol | dds_e1_ctx_pol  (the two PDB-wide policies)
--   DDS_E1_DATA_POL (DDS_INV_OWNER.INVOICES only) stays enabled.
-- Does not: REVOKE, DROP, DROP AUDIT POLICY, or change any data grant, data role
--   or table. DDS_INV_OWNER and DDS_INV_PARSE are not touched: they are
--   NO AUTHENTICATION accounts (no logon possible).
-- Auditing: NOAUDIT is always audited (ORA$MANDATORY, Oracle AI Database
--   Security Guide 26, "Activities That Are Mandatorily Audited"). Records
--   already written stay in the trail. E2 re-enables with AUDIT POLICY in its
--   own checkpoint, before ACCOUNT UNLOCK; 99 re-enables DDS_E1_CONFIG_POL
--   before any DROP.
-- Reversal (only with E2 approval): ACCOUNT UNLOCK on the same names. The runner
--   deletes the password file when this script ends, PASS or not, so E2 must
--   set new passwords in its own reopening checkpoint.
-- Session guard (e1_session_guard.sql) runs before any DDL: open lab sessions,
--   active end-user security contexts or orphaned runner sessions abort with
--   ORA-20990; untrustworthy detection aborts with ORA-20995. No session is
--   ever killed.
-- Idempotent: LOCK on a locked account is repeatable; a missing name is a SKIP
--   counted as "missing" in SUMMARY (partial state stays visible); NOAUDIT on
--   a disabled policy is a SKIP.
-- Exit criteria: E1_RETAIN_OK. Any error, any account not LOCKED or, with Y, any
--   policy in an unexpected state aborts.
-- ============================================================================
set echo off verify off feedback off heading on pagesize 100 linesize 250
set trimspool on tab off serveroutput on size unlimited
whenever sqlerror exit failure rollback
whenever oserror exit failure rollback

@@e1_target.local.sql

alter session set container = FREEPDB1;
@@e1_assert_target.sql
exec dbms_application_info.set_module('E1_LAB', '98_retain_lock')

-- Read-only guard; aborts before any DDL if detection fails or finds sessions
@@e1_session_guard.sql

-- Positional parameter from the runner (Y or N); validated before any DDL
define e1_narrow_audit = "&1"

declare
  -- Exact allowlist: the only source of names in this script
  c_db_users constant sys.odcivarchar2list := sys.odcivarchar2list('DDS_ADMIN');
  c_eusers   constant sys.odcivarchar2list := sys.odcivarchar2list('DDS_EU_NORTH', 'DDS_EU_SOUTH',
                                                                   'DDS_EU_NOACCESS', 'DDS_EU_NOROLE');
  -- PDB-wide policies disabled on retention; the data policy stays enabled
  c_broad_pols constant sys.odcivarchar2list := sys.odcivarchar2list('DDS_E1_CONFIG_POL', 'DDS_E1_CTX_POL');
  c_data_pol   constant varchar2(30) := 'DDS_E1_DATA_POL';
  -- Y only with 06 PASS in this run (runner decision); N keeps all 3 policies
  c_narrow     constant varchar2(10) := upper(trim('&e1_narrow_audit'));
  v_errors   pls_integer := 0;
  v_missing  pls_integer := 0;
  v_status   varchar2(64);

  -- Runs one DDL statement; logs OK or ERROR and continues (counted at the end)
  procedure p_exec(p_stmt in varchar2) is
  begin
    execute immediate p_stmt;
    dbms_output.put_line('OK    ' || p_stmt);
  exception
    when others then
      v_errors := v_errors + 1;
      dbms_output.put_line('ERROR ' || p_stmt || ' | ' || substr(sqlerrm, 1, 300));
  end p_exec;

  -- Names come from constants, still validated before entering DDL
  function f_name(p_name in varchar2) return varchar2 is
  begin
    return dbms_assert.simple_sql_name(p_name);
  end f_name;

  -- Account status read with a bind variable; NULL when the principal is missing
  function f_status(p_sql in varchar2, p_name in varchar2) return varchar2 is
    v_val varchar2(64);
  begin
    execute immediate p_sql into v_val using p_name;
    return v_val;
  exception
    when no_data_found then
      return null;
  end f_status;

  -- Is the policy enabled? Static SQL: the PL/SQL variable is a bind
  function f_enabled(p_policy in varchar2) return boolean is
    v_n pls_integer;
  begin
    select count(*) into v_n
      from audit_unified_enabled_policies
     where policy_name = p_policy;
    return v_n > 0;
  end f_enabled;

begin
  -- 0. Runner parameter: Y or N only; any other value aborts before any LOCK
  if c_narrow is null or c_narrow not in ('Y', 'N') then
    raise_application_error(-20993, 'Invalid parameter 1 (expected Y or N): ' || nvl(c_narrow, '<empty>'));
  end if;
  dbms_output.put_line('INFO  narrow audit=' || c_narrow || ' (Y only with 06 PASS)');

  -- 1. Active sessions: checked by e1_session_guard.sql above (SESSION_GUARD_OK)

  -- 2. Database user with a password
  for i in 1 .. c_db_users.count loop
    if f_status(q'[select account_status from dba_users where username = :b1]', c_db_users(i)) is null then
      v_missing := v_missing + 1;
      dbms_output.put_line('SKIP  user ' || c_db_users(i) || ' does not exist');
    else
      p_exec('alter user ' || f_name(c_db_users(i)) || ' account lock');
    end if;
  end loop;

  -- 3. End users (ALTER END USER ... ACCOUNT LOCK syntax, Deep Sec Guide)
  for i in 1 .. c_eusers.count loop
    if f_status(q'[select account_status from dba_end_users where username = :b1]', c_eusers(i)) is null then
      v_missing := v_missing + 1;
      dbms_output.put_line('SKIP  end user ' || c_eusers(i) || ' does not exist');
    else
      p_exec('alter end user ' || f_name(c_eusers(i)) || ' account lock');
    end if;
  end loop;

  -- 4. Verification: every existing allowlist account must be LOCKED.
  --    [H] exact DBA_END_USERS.ACCOUNT_STATUS value (RA-11); accepts any value
  --    containing LOCKED, including EXPIRED & LOCKED.
  for i in 1 .. c_db_users.count loop
    v_status := f_status(q'[select account_status from dba_users where username = :b1]', c_db_users(i));
    dbms_output.put_line('INFO  ' || c_db_users(i) || ' status=' || nvl(v_status, '<missing>'));
    if v_status is not null and instr(v_status, 'LOCKED') = 0 then
      v_errors := v_errors + 1;
    end if;
  end loop;
  for i in 1 .. c_eusers.count loop
    v_status := f_status(q'[select account_status from dba_end_users where username = :b1]', c_eusers(i));
    dbms_output.put_line('INFO  ' || c_eusers(i) || ' status=' || nvl(v_status, '<missing>'));
    if v_status is not null and instr(v_status, 'LOCKED') = 0 then
      v_errors := v_errors + 1;
    end if;
  end loop;

  -- 5. Audit scope on retention. Runs only with Y and no error in steps 2 to 4:
  --    the ALTER END USER ... ACCOUNT LOCK statements above were already
  --    recorded by DDS_E1_CONFIG_POL. No policy is dropped; the data policy
  --    stays enabled.
  if c_narrow = 'N' then
    dbms_output.put_line('INFO  no 06 PASS: all 3 E1 policies stay enabled;'
                         || ' narrowing later requires a human decision');
  elsif v_errors > 0 then
    dbms_output.put_line('SKIP  NOAUDIT deferred: retention had errors, broad auditing kept');
  else
    for i in 1 .. c_broad_pols.count loop
      if f_enabled(c_broad_pols(i)) then
        p_exec('noaudit policy ' || f_name(c_broad_pols(i)));
      else
        dbms_output.put_line('SKIP  ' || c_broad_pols(i) || ' already disabled or missing');
      end if;
    end loop;

    -- 6. Verification: data policy enabled, broad policies disabled
    if not f_enabled(c_data_pol) then
      v_errors := v_errors + 1;
      dbms_output.put_line('ERROR ' || c_data_pol || ' is not enabled');
    end if;
    for i in 1 .. c_broad_pols.count loop
      if f_enabled(c_broad_pols(i)) then
        v_errors := v_errors + 1;
        dbms_output.put_line('ERROR ' || c_broad_pols(i) || ' is still enabled');
      end if;
    end loop;
  end if;

  -- Final state of the lab audit policies, read-only
  for i in 1 .. c_broad_pols.count loop
    dbms_output.put_line('INFO  ' || c_broad_pols(i) || ' enabled='
                         || case when f_enabled(c_broad_pols(i)) then 'Y' else 'N' end);
  end loop;
  dbms_output.put_line('INFO  ' || c_data_pol || ' enabled='
                       || case when f_enabled(c_data_pol) then 'Y' else 'N' end);

  dbms_output.put_line('SUMMARY 98_retain_lock | errors=' || v_errors
                       || ' | missing=' || v_missing || ' | narrow=' || c_narrow);
  if v_errors > 0 then
    raise_application_error(-20992, 'Retention incomplete: errors=' || v_errors);
  end if;
  dbms_output.put_line('E1_RETAIN_OK');
end;
/

exit success
