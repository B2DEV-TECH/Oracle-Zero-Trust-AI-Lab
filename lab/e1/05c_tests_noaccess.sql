-- E1_EXPECTED_ASSERTS=4
-- ============================================================================
-- E1 / 05c - NO-ACCESS USER TESTS          [end user DDS_EU_NOACCESS TCP, C3]
-- Run as: sqlplus -L -S /nolog @05c_tests_noaccess.sql
--
-- Database effect: NONE persistent. Every DML is followed by ROLLBACK, the script
-- uses EXITCOMMIT OFF and ends with EXIT ... ROLLBACK. It generates audit records
-- (DDS_E1_CTX_POL and DDS_E1_DATA_POL), which are the evidence for 06.
-- Logs: no context data (JSON, CONTEXT_ID, LOOKUP_KEY) is printed; only the
-- identity (SESSION_USER/CURRENT_USER) and the active data roles.
--
-- Exit codes: 0 = every assert PASS | 2 = some FAIL or wrong count
--             3 = end user cannot run PL/SQL (harness BLOCKED)
-- Format: PASS/FAIL <id> | description | expected | actual. OBS = divergence from
-- the documented semantics that still preserves the security property.
-- Expected values are hypotheses derived from the documentation (RA-03), not
-- verified results.
-- ============================================================================
set echo off verify off feedback off heading on pagesize 100 linesize 250
set trimspool on tab off sqlblanklines on exitcommit off
whenever sqlerror exit failure rollback
whenever oserror exit failure rollback

@@e1_config.sql
@@secrets\e1_secrets.local.sql
@@e1_target.local.sql

connect dds_eu_noaccess/"&dds_eu_noaccess_pwd"@&dds_conn
@@e1_assert_target.sql

-- Pure SQL canary: proves direct end-user logon (CREATE SESSION via data role)
select 'CANARY_SQL_OK' as canary from dual;

-- PL/SQL canary: the harness depends on PL/SQL; if it fails, exit 3 (BLOCKED)
set serveroutput on size unlimited
whenever sqlerror exit 3 rollback
begin
  dbms_output.put_line('CANARY_PLSQL_OK');
end;
/
whenever sqlerror exit failure rollback

variable g_rc number

declare
  c_expected constant pls_integer := 4;
  v_pass     pls_integer := 0;
  v_fail     pls_integer := 0;
  v_out      varchar2(4000);
  v_out2     varchar2(4000);

  -- Normalizes the error code to the ORA-NNNNN format
  function f_ora(p_code in number) return varchar2 is
  begin
    return 'ORA-' || to_char(abs(p_code), 'FM00000');
  end f_ora;

  -- Strict assert: actual must equal expected. NULL never passes.
  procedure p_check(p_id in varchar2, p_desc in varchar2,
                    p_expected in varchar2, p_actual in varchar2) is
  begin
    if p_actual is not null and p_actual = p_expected then
      v_pass := v_pass + 1;
      dbms_output.put_line('PASS ' || p_id || ' | ' || p_desc
                           || ' | expected=' || p_expected || ' | actual=' || p_actual);
    else
      v_fail := v_fail + 1;
      dbms_output.put_line('FAIL ' || p_id || ' | ' || p_desc
                           || ' | expected=' || p_expected || ' | actual=' || nvl(p_actual, '<NULL>'));
    end if;
  end p_check;

  -- Security property assert: actual must be in the allowed list
  -- (separated by |). If it differs from the documented behavior, prints OBS.
  procedure p_check_any(p_id in varchar2, p_desc in varchar2, p_allowed in varchar2,
                        p_doc in varchar2, p_actual in varchar2) is
  begin
    if p_actual is not null and instr('|' || p_allowed || '|', '|' || p_actual || '|') > 0 then
      v_pass := v_pass + 1;
      dbms_output.put_line('PASS ' || p_id || ' | ' || p_desc
                           || ' | allowed=' || p_allowed || ' | actual=' || p_actual);
      if p_doc is not null and p_actual <> p_doc then
        dbms_output.put_line('OBS  ' || p_id || ' | diverges from the documented semantics'
                             || ' | doc=' || p_doc || ' | actual=' || p_actual);
      end if;
    else
      v_fail := v_fail + 1;
      dbms_output.put_line('FAIL ' || p_id || ' | ' || p_desc
                           || ' | allowed=' || p_allowed || ' | actual=' || nvl(p_actual, '<NULL>'));
    end if;
  end p_check_any;

  -- Dynamic scalar query with 0, 1 or 2 binds. Returns the value or ORA-NNNNN.
  -- Dynamic SQL avoids a block compilation failure when access is denied.
  function f_query(p_sql in varchar2, p_b1 in varchar2 default null,
                   p_b2 in varchar2 default null) return varchar2 is
    v_val  varchar2(4000);
    v_code number;
  begin
    if p_b2 is not null then
      execute immediate p_sql into v_val using p_b1, p_b2;
    elsif p_b1 is not null then
      execute immediate p_sql into v_val using p_b1;
    else
      execute immediate p_sql into v_val;
    end if;
    return v_val;
  exception
    when others then
      -- Expected error in a negative test: logged and returned as the result
      v_code := sqlcode;
      dbms_output.put_line('INFO      error caught in query: ' || substr(sqlerrm, 1, 200));
      return f_ora(v_code);
  end f_query;

  -- Dynamic DML with 0, 1 or 2 binds. Returns ROWS=n or ORA-NNNNN.
  -- With p_rollback = false the caller must issue the ROLLBACK.
  function f_dml(p_sql in varchar2, p_b1 in varchar2 default null,
                 p_b2 in varchar2 default null, p_rollback in boolean default true)
    return varchar2 is
    v_res  varchar2(100);
    v_code number;
  begin
    if p_b2 is not null then
      execute immediate p_sql using p_b1, p_b2;
    elsif p_b1 is not null then
      execute immediate p_sql using p_b1;
    else
      execute immediate p_sql;
    end if;
    v_res := 'ROWS=' || sql%rowcount;
    if p_rollback then
      rollback;
    end if;
    return v_res;
  exception
    when others then
      v_code := sqlcode;
      dbms_output.put_line('INFO      error caught in DML: ' || substr(sqlerrm, 1, 200));
      rollback;
      return f_ora(v_code);
  end f_dml;

begin
  -- ---------- INFO: identity as seen by the database (not an assert) ----------
  dbms_output.put_line('INFO      SESSION_USER=' || sys_context('USERENV','SESSION_USER')
                       || ' CURRENT_USER=' || sys_context('USERENV','CURRENT_USER')
                       || ' CURRENT_SCHEMA=' || sys_context('USERENV','CURRENT_SCHEMA'));
  dbms_output.put_line('INFO      active data roles (all)=' || f_query(
    q'[select listagg(role_name, ',') within group (order by role_name) from v$end_user_data_role]'));

  -- X01/X02: logon works, identity is propagated, and the only DDS data role is the session one
  p_check('X01', 'identity in the security context', 'MATCH', f_query(
    q'[select case when ora_end_user_context.username = 'DDS_EU_NOACCESS'
                   then 'MATCH' else 'MISMATCH' end from dual]'));
  p_check('X02', 'active DDS data roles', 'DDS_DR_SESSION_ONLY', f_query(
    q'[select listagg(role_name, ',') within group (order by role_name)
         from v$end_user_data_role
        where substr(role_name, 1, 7) = 'DDS_DR_']'));

  -- X03: no data grant = no row exposed. The guide does not document which of
  --      these results occurs [Q]; the actual value is recorded on the PASS line.
  p_check_any('X03', 'SELECT exposes no rows', '0|ORA-00942|ORA-41900', null, f_query(
    q'[select to_char(count(*)) from dds_inv_owner.invoices]'));

  -- X04: UPDATE changes nothing (ROLLBACK in any case)
  p_check_any('X04', 'UPDATE without privilege', 'ORA-41900|ORA-00942|ROWS=0', null,
    f_dml(q'[update dds_inv_owner.invoices set status = :b1
              where invoice_id = to_number(:b2)]', 'APPROVED', '101'));

  dbms_output.put_line('SUMMARY 05c_tests_noaccess | pass=' || v_pass || ' | fail=' || v_fail
                       || ' | expected=' || c_expected);
  :g_rc := case when v_fail = 0 and v_pass = c_expected then 0 else 2 end;
end;
/

rollback;
exit :g_rc rollback
