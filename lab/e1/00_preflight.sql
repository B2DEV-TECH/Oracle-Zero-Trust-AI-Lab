-- ============================================================================
-- E1 / 00 - PREFLIGHT (read-only)                           [C1, SYS privilege]
-- Run as: sqlplus -L -S "/ as sysdba" @00_preflight.sql
-- Database effect: NONE. SELECT on dictionary and V$ views only.
--                  ALTER SESSION SET CONTAINER and the module tag
--                  (DBMS_APPLICATION_INFO) are session-scoped.
-- Local effect   : writes e1_target.local.sql (no secrets) with the expected
--                  CON_DBID, the run start (UTC and database clock) and the
--                  baselines that 06 uses to show nothing outside the lab changed.
-- Session check  : e1_session_guard.sql replaces the v1 V$SESSION.USERNAME check
--                  (P08). Here it also proves, before anything is created, that
--                  the detection used by 98 and 99 works on this database
--                  (ORA-20995 otherwise).
-- Exit criteria  : prints SESSION_GUARD_OK and E1_PREFLIGHT_OK. Any CHECK FAIL aborts.
-- ============================================================================
set echo off verify off feedback off heading on pagesize 200 linesize 200
set trimspool on tab off sqlblanklines on serveroutput on size unlimited
whenever sqlerror exit failure rollback
whenever oserror exit failure rollback

alter session set container = FREEPDB1;
-- DBMS_OUTPUT state is per container: re-enable it after the switch (verified in
-- the first E1 run, the PL/SQL output was silently lost without this line)
set serveroutput on size unlimited
exec dbms_application_info.set_module('E1_LAB', '00_preflight')

-- Values measured here and written to the local file at the end
variable g_dg_other varchar2(10)
variable g_dr_other varchar2(10)
variable g_apex_fp  varchar2(100)

declare
  -- Preflight counters (local variables, nothing is written to the database)
  v_fail      pls_integer := 0;
  v_cnt       number;
  v_txt       varchar2(400);
  v_major     number;
  v_minor     number;
  v_ru        number;

  -- Records one check result and accumulates failures
  procedure p_check(p_id in varchar2, p_ok in boolean, p_detail in varchar2) is
  begin
    if p_ok then
      dbms_output.put_line('CHECK OK   ' || p_id || ' | ' || p_detail);
    else
      v_fail := v_fail + 1;
      dbms_output.put_line('CHECK FAIL ' || p_id || ' | ' || p_detail);
    end if;
  end p_check;
begin
  -- P01: container and open mode
  select open_mode into v_txt from v$pdbs where name = 'FREEPDB1';
  p_check('P01', sys_context('USERENV','CON_NAME') = 'FREEPDB1' and v_txt = 'READ WRITE',
          'container=' || sys_context('USERENV','CON_NAME') || ' open_mode=' || v_txt);

  -- P02: minimum Deep Sec version (23.26.2) - guide G50191-05, chapter 2
  select version_full into v_txt from v$instance;
  v_major := to_number(regexp_substr(v_txt, '[0-9]+', 1, 1));
  v_minor := to_number(regexp_substr(v_txt, '[0-9]+', 1, 2));
  v_ru    := to_number(regexp_substr(v_txt, '[0-9]+', 1, 3));
  p_check('P02', v_major > 23 or (v_major = 23 and (v_minor > 26 or (v_minor = 26 and v_ru >= 2))),
          'version_full=' || v_txt || ' (minimum 23.26.2)');

  -- P03: COMPATIBLE >= 20 is required for ORA_END_USER_CONTEXT (guide 3.5 and chapter 16)
  select value into v_txt from v$parameter where name = 'compatible';
  p_check('P03', to_number(regexp_substr(v_txt, '[0-9]+', 1, 1)) >= 20, 'compatible=' || v_txt);

  -- P04: Unified Auditing enabled (the E1 evidence depends on it)
  select value into v_txt from v$option where parameter = 'Unified Auditing';
  p_check('P04', v_txt = 'TRUE', 'Unified Auditing=' || v_txt);

  -- P05: every privilege used by setup, tests and teardown exists in
  --      SYSTEM_PRIVILEGE_MAP (SQL Reference G57157-07, Table 18-2)
  select count(*) into v_cnt from system_privilege_map
   where name in ('CREATE END USER','ALTER END USER','DROP END USER',
                  'CREATE DATA ROLE','DROP DATA ROLE','GRANT ANY DATA ROLE',
                  'CREATE DATA GRANT','ADMINISTER ANY DATA GRANT','DROP ANY DATA GRANT');
  p_check('P05', v_cnt = 9, 'Deep Sec privileges found=' || v_cnt || ' of 9');

  -- P06: clean state - no object on the lab allowlist may exist.
  --      Exact names, no wildcard: an unrelated object with a DDS_ prefix does not count.
  select (select count(*) from dba_users
           where username in ('DDS_ADMIN','DDS_INV_OWNER','DDS_INV_PARSE'))
       + (select count(*) from dba_roles where role = 'DDS_SESSION_ROLE')
       + (select count(*) from dba_end_users
           where username in ('DDS_EU_NORTH','DDS_EU_SOUTH','DDS_EU_NOACCESS','DDS_EU_NOROLE'))
       + (select count(*) from dba_data_roles
           where data_role in ('DDS_DR_NORTH','DDS_DR_SOUTH','DDS_DR_SESSION_ONLY'))
       + (select count(*) from dba_data_grants
           where owner = 'DDS_ADMIN'
             and grant_name in ('INV_NORTH_READ','INV_SOUTH_READ','INV_NORTH_OWN_STATUS_UPD'))
       + (select count(*) from audit_unified_policies
           where policy_name in ('DDS_E1_CONFIG_POL','DDS_E1_CTX_POL','DDS_E1_DATA_POL'))
    into v_cnt
    from dual;
  p_check('P06', v_cnt = 0, 'lab objects already present=' || v_cnt
          || ' (if > 0, decide C4 for the previous run before rerunning 00)');

  -- P07: tablespace USERS online (the only tablespace the lab uses)
  select status into v_txt from dba_tablespaces where tablespace_name = 'USERS';
  p_check('P07', v_txt = 'ONLINE', 'USERS status=' || v_txt);

  -- P08 (v1) removed: the V$SESSION.USERNAME check could not see end-user
  -- sessions. The session guard after this block replaces it.

  -- ---------- Baselines (read-only; 06 compares against them) ----------
  select count(*) into v_cnt from dba_objects where status = 'INVALID';
  dbms_output.put_line('INFO       baseline INVALID objects in PDB=' || v_cnt);

  -- Deep Sec objects that already existed outside the lab
  -- (for example SYS.END_USER_CONTEXT_DEFAULT_GRANT)
  select count(*) into v_cnt from dba_data_grants where owner <> 'DDS_ADMIN';
  :g_dg_other := to_char(v_cnt);
  select count(*) into v_cnt from dba_data_roles
   where data_role not in ('DDS_DR_NORTH','DDS_DR_SOUTH','DDS_DR_SESSION_ONLY');
  :g_dr_other := to_char(v_cnt);
  select count(*) into v_cnt from dba_end_users
   where username not in ('DDS_EU_NORTH','DDS_EU_SOUTH','DDS_EU_NOACCESS','DDS_EU_NOROLE');
  dbms_output.put_line('INFO       baseline outside lab: data_grants=' || :g_dg_other
                       || ' data_roles=' || :g_dr_other || ' end_users=' || v_cnt);

  -- Fingerprint of existing APEX applications (count and last update).
  -- [H] column APEX_APPLICATIONS.LAST_UPDATED_ON; dynamic SQL so that its absence
  -- becomes INFO instead of aborting the preflight. No APEX table is changed.
  begin
    execute immediate q'[select count(*) || ':'
                                || nvl(to_char(max(last_updated_on), 'YYYYMMDDHH24MISS'), '-')
                           from apex_applications]'
      into v_txt;
    :g_apex_fp := v_txt;
  exception
    when others then
      dbms_output.put_line('INFO       APEX fingerprint unavailable: ' || substr(sqlerrm, 1, 200));
      :g_apex_fp := 'UNAVAILABLE';
  end;
  dbms_output.put_line('INFO       baseline APEX (apps:last_update)=' || :g_apex_fp);
  dbms_output.put_line('INFO       CON_DBID=' || sys_context('USERENV','CON_DBID'));

  if v_fail > 0 then
    raise_application_error(-20900, 'E1 PREFLIGHT ABORT: ' || v_fail || ' check(s) failed');
  end if;
end;
/

-- Session guard (read-only). Proves the detection works here before anything
-- exists; ORA-20995 means the detection cannot be trusted and E1 must not start.
@@e1_session_guard.sql

-- Writes the values the later steps use (local file, no secrets)
set termout off heading off feedback off pagesize 0 linesize 200
spool e1_target.local.sql
select 'define dds_expected_con_dbid = "' || sys_context('USERENV','CON_DBID') || '"' from dual;
select 'define dds_run_start_utc = "'
       || to_char(sys_extract_utc(systimestamp), 'YYYY-MM-DD HH24:MI:SS') || '"' from dual;
-- Database clock (SYSDATE): same time base as DBA_OBJECTS.CREATED and
-- DBA_USERS.CREATED (RA-10). The 99 provenance gate compares against it.
select 'define dds_run_start_db = "' || to_char(sysdate, 'YYYY-MM-DD HH24:MI:SS') || '"' from dual;
select 'define dds_baseline_invalid = "' || count(*) || '"'
  from dba_objects where status = 'INVALID';
select 'define dds_baseline_dg_other = "' || :g_dg_other || '"' from dual;
select 'define dds_baseline_dr_other = "' || :g_dr_other || '"' from dual;
select 'define dds_baseline_apex = "' || :g_apex_fp || '"' from dual;
spool off
set termout on

prompt E1_PREFLIGHT_OK
exit success
