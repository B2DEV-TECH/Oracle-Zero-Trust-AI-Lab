-- E1_EXPECTED_ASSERTS=17
-- ============================================================================
-- E1 / 05a - NORTH ANALYST TESTS                 [end user DDS_EU_NORTH TCP, C3]
-- Run as: sqlplus -L -S /nolog @05a_tests_north.sql
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

connect dds_eu_north/"&dds_eu_north_pwd"@&dds_conn
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
  c_expected constant pls_integer := 17;
  v_pass     pls_integer := 0;
  v_fail     pls_integer := 0;
  v_out      varchar2(4000);
  v_out2     varchar2(4000);
  v_out3     varchar2(4000);

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
                       || ' CURRENT_SCHEMA=' || sys_context('USERENV','CURRENT_SCHEMA')
                       || ' (guide 15.4: CURRENT_USER expected XS$NULL)');
  dbms_output.put_line('INFO      active data roles (all)=' || f_query(
    q'[select listagg(role_name, ',') within group (order by role_name) from v$end_user_data_role]'));

  -- ---------- Identity propagation ----------
  -- N01: the security context carries the right end user. Comparison in SQL, with
  --      the same semantics as the predicate of data grant INV_NORTH_OWN_STATUS_UPD.
  p_check('N01', 'identity in the security context', 'MATCH', f_query(
    q'[select case when ora_end_user_context.username = 'DDS_EU_NORTH'
                   then 'MATCH' else 'MISMATCH' end from dual]'));

  -- N02: only the NORTH data role among the DDS_DR_ roles (PUBLIC may appear and is ignored)
  p_check('N02', 'active DDS data roles', 'DDS_DR_NORTH', f_query(
    q'[select listagg(role_name, ',') within group (order by role_name)
         from v$end_user_data_role
        where substr(role_name, 1, 7) = 'DDS_DR_']'));

  -- ---------- Authorized access: NORTH rows ----------
  p_check('N03', 'visible rows', '5', f_query(
    q'[select to_char(count(*)) from dds_inv_owner.invoices]'));
  p_check('N04', 'rows outside NORTH', '0', f_query(
    q'[select to_char(count(*)) from dds_inv_owner.invoices where region <> 'NORTH']'));
  p_check('N05', 'visible amount sum', '15000', f_query(
    q'[select to_char(sum(amount)) from dds_inv_owner.invoices]'));

  -- ---------- Unauthorized access: sensitive column and other regions ----------
  p_check('N06', 'tax id masked (NULL) in the visible rows', '0', f_query(
    q'[select to_char(count(supplier_tax_id)) from dds_inv_owner.invoices]'));
  -- N07: filtering on a masked column must not work as an inference oracle
  p_check_any('N07', 'tax id filter reveals no row', '0|ORA-41900', '0', f_query(
    q'[select to_char(count(*)) from dds_inv_owner.invoices where supplier_tax_id = :b1]',
    'SYN-TAX-N-0101'));
  p_check('N08', 'SOUTH invoice 201 and EAST invoice 301 invisible', '0', f_query(
    q'[select to_char(count(*)) from dds_inv_owner.invoices
        where invoice_id in (to_number(:b1), to_number(:b2))]', '201', '301'));
  -- N09: positive control for the mask: an authorized column stays visible
  p_check('N09', 'supplier_name visible in the 5 rows', '5', f_query(
    q'[select to_char(count(supplier_name)) from dds_inv_owner.invoices]'));

  -- ---------- UPDATE with identity in the predicate ----------
  -- N10: invoice 101 is NORTH and assigned_to = DDS_EU_NORTH. Proof in 3 reads:
  --      (1) the UPDATE affected 1 row, (2) the same session reads APPROVED before
  --      the ROLLBACK, (3) after the ROLLBACK the row is back to PENDING. Without (3)
  --      the test would not prove that the ROLLBACK undid the change.
  v_out  := f_dml(q'[update dds_inv_owner.invoices set status = :b1
                      where invoice_id = to_number(:b2)]', 'APPROVED', '101', p_rollback => false);
  v_out2 := f_query(q'[select status from dds_inv_owner.invoices
                        where invoice_id = to_number(:b1)]', '101');
  rollback;
  v_out3 := f_query(q'[select status from dds_inv_owner.invoices
                        where invoice_id = to_number(:b1)]', '101');
  p_check('N10', 'UPDATE of own invoice 101 and effective ROLLBACK',
          'ROWS=1;STATUS=APPROVED;AFTER_ROLLBACK=PENDING',
          v_out || ';STATUS=' || v_out2 || ';AFTER_ROLLBACK=' || v_out3);

  -- N11: 103 is NORTH (visible) but assigned to another identity: the predicate of
  --      the UPDATE data grant does not cover the row. Precondition: the row is
  --      visible (otherwise the test would only prove the SELECT rule). After the
  --      UPDATE, the read in the same session, before the ROLLBACK, proves that the
  --      status did not change.
  v_out3 := f_query(q'[select status from dds_inv_owner.invoices
                        where invoice_id = to_number(:b1)]', '103');
  v_out  := f_dml(q'[update dds_inv_owner.invoices set status = :b1
                      where invoice_id = to_number(:b2)]', 'APPROVED', '103', p_rollback => false);
  v_out2 := f_query(q'[select status from dds_inv_owner.invoices
                        where invoice_id = to_number(:b1)]', '103');
  rollback;
  p_check_any('N11', 'UPDATE of 103 (visible, other identity)',
              'VISIBLE=PENDING;ROWS=0;STATUS=PENDING|VISIBLE=PENDING;ORA-41900;STATUS=PENDING',
              'VISIBLE=PENDING;ROWS=0;STATUS=PENDING',
              'VISIBLE=' || v_out3 || ';' || v_out || ';STATUS=' || v_out2);

  -- N12: 201 is SOUTH, not even visible
  p_check_any('N12', 'UPDATE status of 201 (SOUTH)', 'ROWS=0|ORA-41900', 'ROWS=0',
    f_dml(q'[update dds_inv_owner.invoices set status = :b1
              where invoice_id = to_number(:b2)]', 'APPROVED', '201'));

  -- N13: column AMOUNT is outside the UPDATE grant (status): unauthorized cell, row skipped
  v_out  := f_dml(q'[update dds_inv_owner.invoices set amount = amount + 1
                      where invoice_id = to_number(:b1)]', '101', p_rollback => false);
  v_out2 := f_query(q'[select to_char(amount) from dds_inv_owner.invoices
                        where invoice_id = to_number(:b1)]', '101');
  rollback;
  p_check_any('N13', 'UPDATE of amount (column without privilege)',
              'ROWS=0;AMOUNT=1000|ORA-41900;AMOUNT=1000', 'ROWS=0;AMOUNT=1000',
              v_out || ';AMOUNT=' || v_out2);

  -- N14: WHERE on a column without SELECT. ROWS=1 would prove a leak of the real tax id.
  p_check_any('N14', 'UPDATE filtering by tax id', 'ORA-41900|ROWS=0', 'ORA-41900',
    f_dml(q'[update dds_inv_owner.invoices set status = 'APPROVED'
              where invoice_id = to_number(:b1) and supplier_tax_id = :b2]', '101', 'SYN-TAX-N-0101'));

  -- N15 and N16: no INSERT or DELETE data grant for DDS_DR_NORTH
  p_check_any('N15', 'INSERT without privilege', 'ORA-41900|ORA-28115', 'ORA-41900',
    f_dml(q'[insert into dds_inv_owner.invoices
               (invoice_id, invoice_no, region, supplier_name, supplier_tax_id, amount, issue_date)
             values (to_number(:b1), 'INV-N-0999', 'NORTH', 'Synthetic Supplier Test',
                     'SYN-TAX-N-0999', 1, date '2026-04-01')]', '999'));
  p_check_any('N16', 'DELETE without privilege (own invoice 101)', 'ORA-41900|ROWS=0', 'ORA-41900',
    f_dml(q'[delete from dds_inv_owner.invoices where invoice_id = to_number(:b1)]', '101'));

  -- N17: nothing that was tested persisted
  p_check('N17', 'integrity after rollback', 'ROWS=5;NOT_PENDING=0', f_query(
    q'[select 'ROWS=' || count(*) || ';NOT_PENDING='
              || sum(case when status <> 'PENDING' then 1 else 0 end)
         from dds_inv_owner.invoices]'));

  dbms_output.put_line('SUMMARY 05a_tests_north | pass=' || v_pass || ' | fail=' || v_fail
                       || ' | expected=' || c_expected);
  :g_rc := case when v_fail = 0 and v_pass = c_expected then 0 else 2 end;
end;
/

rollback;
exit :g_rc rollback
