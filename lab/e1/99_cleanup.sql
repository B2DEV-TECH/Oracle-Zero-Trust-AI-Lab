-- ============================================================================
-- E1 / 99 - IDEMPOTENT LAB TEARDOWN          [C4-teardown, SYS privilege - DESTRUCTIVE]
-- Run as: sqlplus -L -S "/ as sysdba" @99_cleanup.sql
-- Runs only with explicit human approval of C4-teardown (the C4 default is 98).
--
-- Removes ONLY the exact allowlist names below. No DROP uses LIKE, no DROP USER
-- uses CASCADE. Order:
--   0. session guard (e1_session_guard.sql): open lab sessions, active end-user
--      security contexts or orphaned runner sessions abort with ORA-20990;
--      untrustworthy detection aborts with ORA-20995 (no session is killed)
--   P. provenance gate (read-only): the objects carrying allowlist names must
--      have been created by this run and must not be referenced from outside
--      the lab; any failure aborts with ORA-20996 before any DDL
--  1b. if 98 disabled DDS_E1_CONFIG_POL, re-enable it before any DROP
--      (AUDIT POLICY is mandatorily audited); on failure, abort with no DROP
--   2. DROP DATA GRANT  dds_admin.inv_north_read / inv_south_read / inv_north_own_status_upd
--   3. DROP END USER    dds_eu_north / south / noaccess / norole
--   4. DROP DATA ROLE   dds_dr_north / south / session_only
--   5. DROP ROLE        dds_session_role
--   6. NOAUDIT + DROP AUDIT POLICY dds_e1_data_pol (before the table goes)
--   7. DROP TABLE dds_inv_owner.invoices PURGE (the only object created in the schema)
--   8. confirm the 3 lab users own no other object; if they do, list it and do
--      NOT drop the user (an unexpected object needs a human decision)
--   9. DROP USER without CASCADE  dds_admin, dds_inv_parse, dds_inv_owner
--  10. NOAUDIT + DROP AUDIT POLICY dds_e1_config_pol and dds_e1_ctx_pol, last and
--      only if nothing failed before (the DROP statements of 2 to 5 stay
--      audited, and a rerun after an error stays audited)
--  11. residue counted by the exact allowlist; E1_CLEANUP_OK or ORA-20991
--  12. read-only INFO: DDS_-prefixed names outside the allowlist (never dropped)
--
-- Idempotent: every name is checked in the dictionary with a bind variable
-- before its DROP. Full target guard (CON_NAME + CON_DBID from
-- e1_target.local.sql). If that file is lost, RUNBOOK.md explains how to rebuild
-- it from the 00 log.
-- Does NOT: purge UNIFIED_AUDIT_TRAIL (lab evidence stays in SYSAUX), kill
-- sessions, DROP ... CASCADE, or touch anything outside the allowlist.
-- ============================================================================
set echo off verify off feedback off heading on pagesize 100 linesize 250
set trimspool on tab off serveroutput on size unlimited
whenever sqlerror exit failure rollback
whenever oserror exit failure rollback

@@e1_target.local.sql

alter session set container = FREEPDB1;
-- DBMS_OUTPUT state is per container: re-enable it after the switch (verified in
-- the first E1 run, the PL/SQL output was silently lost without this line)
set serveroutput on size unlimited
@@e1_assert_target.sql
exec dbms_application_info.set_module('E1_LAB', '99_cleanup')

-- 0. Read-only guard; aborts before any DDL if detection fails or finds sessions
@@e1_session_guard.sql

-- ----------------------------------------------------------------------------
-- P. PROVENANCE GATE (read-only, before any DDL including step 1b)
-- The exact allowlist decides WHICH names may be dropped. This gate decides
-- WHETHER the objects carrying those names are the ones this run created and
-- whether dropping them would affect anything outside the lab. Each check
-- applies only to objects that exist (a partial run is normal). Every failed
-- check is listed; any failure aborts with ORA-20996 and no DROP is attempted.
-- Time base: DBA_USERS.CREATED, DBA_OBJECTS.CREATED and
-- DBA_END_USERS.CREATED_DATE are compared with dds_run_start_db, the database
-- SYSDATE captured by 00. Check P06 of 00 already proved that no allowlist name
-- existed at that moment. A backwards change of the server clock between 00
-- and 99 makes this gate fail closed (RUNBOOK.md, "Provenance gate failed").
-- ----------------------------------------------------------------------------
declare
  -- Same exact allowlist as the teardown block below
  c_users    constant sys.odcivarchar2list := sys.odcivarchar2list('DDS_ADMIN', 'DDS_INV_PARSE', 'DDS_INV_OWNER');
  c_eusers   constant sys.odcivarchar2list := sys.odcivarchar2list('DDS_EU_NORTH', 'DDS_EU_SOUTH',
                                                                   'DDS_EU_NOACCESS', 'DDS_EU_NOROLE');
  c_droles   constant sys.odcivarchar2list := sys.odcivarchar2list('DDS_DR_NORTH', 'DDS_DR_SOUTH',
                                                                   'DDS_DR_SESSION_ONLY');
  c_dgrants  constant sys.odcivarchar2list := sys.odcivarchar2list('INV_NORTH_READ', 'INV_SOUTH_READ',
                                                                   'INV_NORTH_OWN_STATUS_UPD');
  -- Exact grants made by 04a, as GRANTED_ROLE>GRANTEE (DBA_DATA_ROLE_GRANTS
  -- lists data role grants and database role grants to data roles, G50191-05 21.1.2)
  c_role_pairs constant sys.odcivarchar2list := sys.odcivarchar2list(
                 'DDS_DR_NORTH>DDS_EU_NORTH', 'DDS_DR_SOUTH>DDS_EU_SOUTH',
                 'DDS_DR_SESSION_ONLY>DDS_EU_NOACCESS',
                 'DDS_SESSION_ROLE>DDS_DR_NORTH', 'DDS_SESSION_ROLE>DDS_DR_SOUTH',
                 'DDS_SESSION_ROLE>DDS_DR_SESSION_ONLY');
  c_lab_pols    constant sys.odcivarchar2list := sys.odcivarchar2list('DDS_E1_CONFIG_POL', 'DDS_E1_CTX_POL',
                                                                      'DDS_E1_DATA_POL');
  c_role        constant varchar2(30) := 'DDS_SESSION_ROLE';
  c_grant_owner constant varchar2(30) := 'DDS_ADMIN';
  c_data_pol    constant varchar2(30) := 'DDS_E1_DATA_POL';
  c_tab_owner   constant varchar2(30) := 'DDS_INV_OWNER';
  c_tab_name    constant varchar2(30) := 'INVOICES';
  -- Substituted by SQL*Plus from e1_target.local.sql (written by 00)
  c_run_start_txt constant varchar2(30) := '&dds_run_start_db';
  v_run_start date;
  v_fail      pls_integer := 0;
  v_failed    varchar2(400);
  v_n         pls_integer;
  v_list      varchar2(4000);

  -- One line per check; failures are collected for the final ORA-20996
  procedure p_check(p_id in varchar2, p_desc in varchar2, p_bad in pls_integer, p_detail in varchar2) is
  begin
    if p_bad = 0 then
      dbms_output.put_line('CHECK OK   ' || p_id || ' | ' || p_desc);
    else
      v_fail   := v_fail + 1;
      v_failed := v_failed || ' ' || p_id;
      dbms_output.put_line('CHECK FAIL ' || p_id || ' | ' || p_desc || ' | ' || nvl(p_detail, '-'));
    end if;
  end p_check;

begin
  -- V00. Run start from 00. An empty or malformed value aborts (no default).
  begin
    v_run_start := to_date(c_run_start_txt, 'YYYY-MM-DD HH24:MI:SS');
  exception
    when others then
      dbms_output.put_line('ERROR V00 dds_run_start_db unreadable: ' || substr(sqlerrm, 1, 200));
      v_run_start := null;
  end;
  if v_run_start is null then
    raise_application_error(-20996, 'Provenance gate: run start missing or malformed;'
                            || ' teardown aborted before any DDL');
  end if;
  dbms_output.put_line('INFO  run start (database time)=' || to_char(v_run_start, 'YYYY-MM-DD HH24:MI:SS'));

  -- V01. Lab users: created by this run, local, not Oracle-maintained, and with
  --      the authentication type 01 gave them (PASSWORD only for DDS_ADMIN)
  select count(*),
         listagg(username || ':' || to_char(created, 'YYYY-MM-DD HH24:MI:SS') || ':'
                 || oracle_maintained || ':' || common || ':' || authentication_type,
                 ',' on overflow truncate) within group (order by username)
    into v_n, v_list
    from dba_users
   where username in (select column_value from table(c_users))
     and (created < v_run_start
          or nvl(oracle_maintained, '-') <> 'N'
          or nvl(common, '-') <> 'NO'
          or nvl(authentication_type, '-') <> case username when 'DDS_ADMIN' then 'PASSWORD'
                                                             else 'NONE' end);
  p_check('V01', 'lab users created by this run with the expected account shape', v_n, v_list);

  -- V02. Lab end users: created by this run, password-authenticated as in 04a
  select count(*),
         listagg(username || ':' || nvl(to_char(created_date, 'YYYY-MM-DD HH24:MI:SS'), '<NULL>')
                 || ':' || authentication_type, ',' on overflow truncate) within group (order by username)
    into v_n, v_list
    from dba_end_users
   where username in (select column_value from table(c_eusers))
     and (created_date is null
          or created_date < v_run_start
          or nvl(authentication_type, '-') <> 'PASSWORD');
  p_check('V02', 'lab end users created by this run', v_n, v_list);

  -- V03. Every object owned by a lab user was created by this run
  select count(*),
         listagg(owner || '.' || object_name || ':' || object_type, ',' on overflow truncate)
           within group (order by owner, object_name)
    into v_n, v_list
    from dba_objects
   where owner in (select column_value from table(c_users))
     and created < v_run_start;
  p_check('V03', 'objects owned by lab users created by this run', v_n, v_list);

  -- V04. Nothing outside the lab depends on lab objects: no object privileges
  --      on them (data grants are not listed in DBA_TAB_PRIVS, G50191-05 21.1.3),
  --      no dependent objects and no synonyms owned by other schemas
  select count(*), listagg(n, ',' on overflow truncate) within group (order by n)
    into v_n, v_list
    from (select 'PRIV:' || p.grantee || ':' || p.privilege || ':' || p.owner || '.' || p.table_name n
            from dba_tab_privs p
           where p.owner in (select column_value from table(c_users))
          union all
          select 'DEP:' || d.owner || '.' || d.name || ':' || d.type
            from dba_dependencies d
           where d.referenced_owner in (select column_value from table(c_users))
             and d.owner not in (select column_value from table(c_users))
          union all
          select 'SYN:' || s.owner || '.' || s.synonym_name
            from dba_synonyms s
           where s.table_owner in (select column_value from table(c_users))
             and s.owner not in (select column_value from table(c_users)));
  p_check('V04', 'no external privileges, dependencies or synonyms on lab objects', v_n, v_list);

  -- V05. Allowlisted data grants protect only the lab table and go only to the
  --      data role 04b used for each of them
  select count(*),
         listagg(grant_name || ':' || object_owner || '.' || object_name || ':' || grantee,
                 ',' on overflow truncate) within group (order by grant_name)
    into v_n, v_list
    from dba_data_grants
   where owner = c_grant_owner
     and grant_name in (select column_value from table(c_dgrants))
     and (nvl(object_owner, '-') <> c_tab_owner
          or nvl(object_name, '-') <> c_tab_name
          or nvl(grantee, '-') <> case grant_name
                                    when 'INV_NORTH_READ'           then 'DDS_DR_NORTH'
                                    when 'INV_SOUTH_READ'           then 'DDS_DR_SOUTH'
                                    when 'INV_NORTH_OWN_STATUS_UPD' then 'DDS_DR_NORTH'
                                  end);
  p_check('V05', 'allowlisted data grants match the 04b definitions', v_n, v_list);

  -- V06. No data grant outside the allowlist touches the lab: none owned by
  --      DDS_ADMIN, none on a lab-owned object, none granted to a lab data role
  --      or lab end user
  select count(*),
         listagg(owner || '.' || grant_name || ':' || object_owner || '.' || object_name || ':' || grantee,
                 ',' on overflow truncate) within group (order by owner, grant_name)
    into v_n, v_list
    from dba_data_grants
   where (owner <> c_grant_owner
          or grant_name not in (select column_value from table(c_dgrants)))
     and (owner = c_grant_owner
          or object_owner in (select column_value from table(c_users))
          or grantee in (select column_value from table(c_droles))
          or grantee in (select column_value from table(c_eusers)));
  p_check('V06', 'no foreign data grant references lab objects or lab grantees', v_n, v_list);

  -- V07. Lab data roles are local (not mapped to an external application role)
  select count(*),
         listagg(data_role || ':' || mapped_to, ',' on overflow truncate) within group (order by data_role)
    into v_n, v_list
    from dba_data_roles
   where data_role in (select column_value from table(c_droles))
     and mapped_to is not null;
  p_check('V07', 'lab data roles are not mapped to external roles', v_n, v_list);

  -- V08. Every grant involving a lab data role, DDS_SESSION_ROLE or a lab end
  --      user is one of the six grants made by 04a. A grant to SYS is tolerated
  --      because the creator representation is not documented (RA-09).
  select count(*),
         listagg(data_role || '>' || grantee || ':' || grantee_type, ',' on overflow truncate)
           within group (order by data_role, grantee)
    into v_n, v_list
    from dba_data_role_grants
   where (data_role in (select column_value from table(c_droles))
          or data_role = c_role
          or grantee in (select column_value from table(c_droles))
          or grantee in (select column_value from table(c_eusers)))
     and data_role || '>' || grantee not in (select column_value from table(c_role_pairs))
     and not (grantee = 'SYS'
              and (data_role = c_role or data_role in (select column_value from table(c_droles))));
  p_check('V08', 'data role grants match the 04a definitions', v_n, v_list);

  -- V09. DDS_SESSION_ROLE carries only CREATE SESSION, holds no other role and
  --      is held only by SYS (creator) or by lab data roles
  select count(*), listagg(n, ',' on overflow truncate) within group (order by n)
    into v_n, v_list
    from (select 'SYSPRIV:' || privilege n
            from dba_sys_privs
           where grantee = c_role and privilege <> 'CREATE SESSION'
          union all
          select 'TABPRIV:' || owner || '.' || table_name || ':' || privilege
            from dba_tab_privs
           where grantee = c_role
          union all
          select 'HOLDS:' || granted_role
            from dba_role_privs
           where grantee = c_role
          union all
          select 'HELD_BY:' || grantee
            from dba_role_privs
           where granted_role = c_role
             and grantee <> 'SYS'
             and grantee not in (select column_value from table(c_droles)));
  p_check('V09', 'DDS_SESSION_ROLE has only the 01 privilege and lab grantees', v_n, v_list);

  -- V10. Lab audit policies are custom and local; the data policy audits only
  --      the lab table and the other two audit no object at all. Dropping them
  --      therefore removes no auditing of anything outside the lab.
  --      [H] statement-action rows show OBJECT_NAME NULL or 'NONE' (RA-08).
  select count(*),
         listagg(policy_name || ':' || audit_option || ':' || object_schema || '.' || object_name,
                 ',' on overflow truncate) within group (order by policy_name, audit_option)
    into v_n, v_list
    from audit_unified_policies
   where policy_name in (select column_value from table(c_lab_pols))
     and (nvl(oracle_supplied, '-') <> 'NO'
          or nvl(common, '-') <> 'NO'
          or (policy_name = c_data_pol
              and (nvl(object_schema, '-') <> c_tab_owner or nvl(object_name, '-') <> c_tab_name))
          or (policy_name <> c_data_pol and nvl(object_name, 'NONE') <> 'NONE'));
  p_check('V10', 'lab audit policies cover only the lab', v_n, v_list);

  -- Option rows per policy, recorded for the runtime evidence (not a check)
  for r in (select policy_name, count(*) n
              from audit_unified_policies
             where policy_name in (select column_value from table(c_lab_pols))
             group by policy_name
             order by policy_name) loop
    dbms_output.put_line('INFO  ' || r.policy_name || ' option rows=' || r.n);
  end loop;

  dbms_output.put_line('SUMMARY 99_provenance | failed=' || v_fail);
  if v_fail > 0 then
    raise_application_error(-20996, 'Provenance gate failed:' || v_failed
                            || '; teardown aborted before any DDL');
  end if;
  dbms_output.put_line('E1_PROVENANCE_OK');
end;
/

-- ----------------------------------------------------------------------------
-- TEARDOWN (reached only after SESSION_GUARD_OK and E1_PROVENANCE_OK)
-- ----------------------------------------------------------------------------
declare
  -- Exact allowlist: the only source of names this script may remove
  c_users    constant sys.odcivarchar2list := sys.odcivarchar2list('DDS_ADMIN', 'DDS_INV_PARSE', 'DDS_INV_OWNER');
  c_eusers   constant sys.odcivarchar2list := sys.odcivarchar2list('DDS_EU_NORTH', 'DDS_EU_SOUTH',
                                                                   'DDS_EU_NOACCESS', 'DDS_EU_NOROLE');
  c_droles   constant sys.odcivarchar2list := sys.odcivarchar2list('DDS_DR_NORTH', 'DDS_DR_SOUTH',
                                                                   'DDS_DR_SESSION_ONLY');
  c_dgrants  constant sys.odcivarchar2list := sys.odcivarchar2list('INV_NORTH_READ', 'INV_SOUTH_READ',
                                                                   'INV_NORTH_OWN_STATUS_UPD');
  c_config_pol  constant varchar2(30) := 'DDS_E1_CONFIG_POL';
  c_policies constant sys.odcivarchar2list := sys.odcivarchar2list(c_config_pol, 'DDS_E1_CTX_POL');
  c_role        constant varchar2(30) := 'DDS_SESSION_ROLE';
  c_grant_owner constant varchar2(30) := 'DDS_ADMIN';
  c_data_pol    constant varchar2(30) := 'DDS_E1_DATA_POL';
  c_tab_owner   constant varchar2(30) := 'DDS_INV_OWNER';
  c_tab_name    constant varchar2(30) := 'INVOICES';
  v_errors   pls_integer := 0;
  v_count    pls_integer;
  v_list     varchar2(4000);

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

  -- Dictionary existence with binds; p_sql is an internal constant, never external input
  function f_exists(p_sql in varchar2, p_b1 in varchar2, p_b2 in varchar2 default null) return boolean is
    v_n pls_integer;
  begin
    if p_b2 is null then
      execute immediate p_sql into v_n using p_b1;
    else
      execute immediate p_sql into v_n using p_b1, p_b2;
    end if;
    return v_n > 0;
  end f_exists;

  -- Removes one allowlisted audit policy: NOAUDIT if enabled, then DROP
  procedure p_drop_policy(p_policy in varchar2) is
  begin
    if f_exists(q'[select count(*) from audit_unified_enabled_policies where policy_name = :b1]', p_policy) then
      p_exec('noaudit policy ' || f_name(p_policy));
    end if;
    if f_exists(q'[select count(*) from audit_unified_policies where policy_name = :b1]', p_policy) then
      p_exec('drop audit policy ' || f_name(p_policy));
    else
      dbms_output.put_line('SKIP  audit policy ' || p_policy || ' does not exist');
    end if;
  end p_drop_policy;

begin
  -- 1. Active sessions and provenance: checked by the two read-only blocks above

  -- 1b. Retention with 06 PASS leaves DDS_E1_CONFIG_POL created but disabled.
  --     Re-enable it before any DROP so the teardown is audited; otherwise abort.
  if f_exists(q'[select count(*) from audit_unified_policies where policy_name = :b1]', c_config_pol)
     and not f_exists(q'[select count(*) from audit_unified_enabled_policies where policy_name = :b1]',
                      c_config_pol) then
    p_exec('audit policy ' || f_name(c_config_pol));
    if v_errors > 0 then
      raise_application_error(-20994, 'Could not re-enable ' || c_config_pol
                                      || '; teardown aborted before any DROP');
    end if;
  end if;

  -- 2. Data grants (before the data roles that are their grantees)
  for i in 1 .. c_dgrants.count loop
    if f_exists(q'[select count(*) from dba_data_grants where owner = :b1 and grant_name = :b2]',
                c_grant_owner, c_dgrants(i)) then
      p_exec('drop data grant if exists ' || f_name(c_grant_owner) || '.' || f_name(c_dgrants(i)));
    else
      dbms_output.put_line('SKIP  data grant ' || c_grant_owner || '.' || c_dgrants(i) || ' does not exist');
    end if;
  end loop;

  -- 3. End users (their data role grants go with them)
  for i in 1 .. c_eusers.count loop
    if f_exists(q'[select count(*) from dba_end_users where username = :b1]', c_eusers(i)) then
      p_exec('drop end user if exists ' || f_name(c_eusers(i)));
    else
      dbms_output.put_line('SKIP  end user ' || c_eusers(i) || ' does not exist');
    end if;
  end loop;

  -- 4. Data roles
  for i in 1 .. c_droles.count loop
    if f_exists(q'[select count(*) from dba_data_roles where data_role = :b1]', c_droles(i)) then
      p_exec('drop data role if exists ' || f_name(c_droles(i)));
    else
      dbms_output.put_line('SKIP  data role ' || c_droles(i) || ' does not exist');
    end if;
  end loop;

  -- 5. Database role that gives CREATE SESSION to the data roles
  if f_exists(q'[select count(*) from dba_roles where role = :b1]', c_role) then
    p_exec('drop role ' || f_name(c_role));
  else
    dbms_output.put_line('SKIP  role ' || c_role || ' does not exist');
  end if;

  -- 6. Data policy goes before the table (no policy left pointing at a dropped object)
  p_drop_policy(c_data_pol);

  -- 7. The only object created in the lab schema; PURGE leaves no BIN$ copy behind
  if f_exists(q'[select count(*) from dba_tables where owner = :b1 and table_name = :b2]',
              c_tab_owner, c_tab_name) then
    p_exec('drop table ' || f_name(c_tab_owner) || '.' || f_name(c_tab_name) || ' purge');
  else
    dbms_output.put_line('SKIP  table ' || c_tab_owner || '.' || c_tab_name || ' does not exist');
  end if;

  -- 8 and 9. DROP USER without CASCADE. A user that still owns an object is
  --          listed and NOT dropped: an unexpected object needs a human decision.
  for i in 1 .. c_users.count loop
    if not f_exists(q'[select count(*) from dba_users where username = :b1]', c_users(i)) then
      dbms_output.put_line('SKIP  user ' || c_users(i) || ' does not exist');
    else
      select count(*),
             substr(listagg(object_type || ':' || object_name, ',' on overflow truncate)
                      within group (order by object_type, object_name), 1, 1000)
        into v_count, v_list
        from dba_objects
       where owner = c_users(i);
      if v_count > 0 then
        v_errors := v_errors + 1;
        dbms_output.put_line('ERROR user ' || c_users(i) || ' still owns ' || v_count
                             || ' object(s), DROP not run: ' || v_list);
      else
        p_exec('drop user ' || f_name(c_users(i)));
      end if;
    end if;
  end loop;

  -- 10. Configuration and context policies last, and only with no earlier error
  if v_errors = 0 then
    for i in 1 .. c_policies.count loop
      p_drop_policy(c_policies(i));
    end loop;
  else
    dbms_output.put_line('SKIP  DDS_E1_CONFIG_POL and DDS_E1_CTX_POL kept: an earlier step failed,'
                         || ' a rerun stays audited');
  end if;

  -- 11. Residue counted ONLY by the exact allowlist
  select (select count(*) from dba_users
           where username in (select column_value from table(c_users)))
       + (select count(*) from dba_roles where role = c_role)
       + (select count(*) from dba_end_users
           where username in (select column_value from table(c_eusers)))
       + (select count(*) from dba_data_roles
           where data_role in (select column_value from table(c_droles)))
       + (select count(*) from dba_data_grants where owner = c_grant_owner)
       + (select count(*) from dba_tables where owner = c_tab_owner and table_name = c_tab_name)
       + (select count(distinct policy_name) from audit_unified_policies
           where policy_name = c_data_pol
              or policy_name in (select column_value from table(c_policies)))
    into v_count
    from dual;

  -- 12. Read-only INFO: lab-prefixed names that are NOT in the allowlist.
  --     They are never removed here; if any appear, the decision is human.
  select substr(listagg(n, ',' on overflow truncate) within group (order by n), 1, 1000)
    into v_list
    from (select 'USER:' || username n from dba_users
           where username like 'DDS\_%' escape '\'
             and username not in (select column_value from table(c_users))
          union all
          select 'END_USER:' || username from dba_end_users
           where username like 'DDS\_%' escape '\'
             and username not in (select column_value from table(c_eusers))
          union all
          select 'DATA_ROLE:' || data_role from dba_data_roles
           where data_role like 'DDS\_%' escape '\'
             and data_role not in (select column_value from table(c_droles))
          union all
          select 'ROLE:' || role from dba_roles
           where role like 'DDS\_%' escape '\' and role <> c_role);
  dbms_output.put_line('INFO  DDS_ names outside the allowlist (not touched)=' || nvl(v_list, '<none>'));

  dbms_output.put_line('SUMMARY 99_cleanup | errors=' || v_errors || ' | residue=' || v_count);
  if v_errors > 0 or v_count > 0 then
    raise_application_error(-20991, 'Teardown incomplete: errors=' || v_errors || ' residue=' || v_count);
  end if;
  dbms_output.put_line('E1_CLEANUP_OK');
end;
/

exit success
