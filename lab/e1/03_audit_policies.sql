-- ============================================================================
-- E1 / 03 - UNIFIED AUDITING POLICIES                      [C2, SYS privilege]
-- Run as: sqlplus -L -S "/ as sysdba" @03_audit_policies.sql
--
-- Why before 04a/04b: the Deep Sec configuration (identities by SYS in 04a,
-- data grants by DDS_ADMIN in 04b) must be recorded from the first statement
-- (evidence E10 and O06 in 06_evidence.sql).
--
-- Effects in PDB FREEPDB1 (reverted by 99_cleanup.sql with NOAUDIT + DROP):
--   DDS_E1_CONFIG_POL  Deep Sec configuration actions, any user in the PDB.
--                      PDB-wide scope, but it only AUDITS: it blocks and changes nothing
--   DDS_E1_CTX_POL     creation of end-user security contexts (end-user logon).
--                      Not part of ACTIONS ALL; must be explicit (G50191-05 19.1)
--   DDS_E1_DATA_POL    SELECT/INSERT/UPDATE/DELETE on DDS_INV_OWNER.INVOICES only
-- No existing policy is changed. Records written to the audit trail (SYSAUX)
-- are NOT deleted by the cleanup: they are the lab evidence.
-- ============================================================================
set echo off verify off feedback on heading on pagesize 100 linesize 200
set trimspool on tab off sqlblanklines on
whenever sqlerror exit failure rollback
whenever oserror exit failure rollback

@@e1_target.local.sql

alter session set container = FREEPDB1;
-- DBMS_OUTPUT state is per container: re-enable it after the switch (verified in
-- the first E1 run, the PL/SQL output was silently lost without this line)
set serveroutput on size unlimited
@@e1_assert_target.sql
exec dbms_application_info.set_module('E1_LAB', '03_audit_policies')

prompt [SYS] 03.1 Deep Sec configuration policy (G50191-05 19.2, extended with data roles)
create audit policy dds_e1_config_pol
  actions
    create end user,
    alter end user,
    drop end user,
    create data role,
    drop data role,
    grant data role,
    revoke data role,
    create data grant,
    drop data grant;

prompt [SYS] 03.2 Security context lifecycle policy (G50191-05 19.1)
create audit policy dds_e1_ctx_pol
  actions
    create end user security context;

prompt [SYS] 03.3 Data access policy, restricted to the lab table (G50191-05 19.3)
create audit policy dds_e1_data_pol
  actions
    select on dds_inv_owner.invoices,
    insert on dds_inv_owner.invoices,
    update on dds_inv_owner.invoices,
    delete on dds_inv_owner.invoices;

prompt [SYS] 03.4 Enable the three policies (success and failure, all users)
audit policy dds_e1_config_pol;
audit policy dds_e1_ctx_pol;
audit policy dds_e1_data_pol;

prompt 03.5 Review
col policy_name    format a22
col enabled_option format a16
col entity_name    format a12
col success        format a8
col failure        format a8
select policy_name, enabled_option, entity_name, success, failure
  from audit_unified_enabled_policies
 where policy_name like 'DDS\_E1\_%' escape '\'
 order by policy_name;

declare
  v_cnt number;
begin
  select count(distinct policy_name) into v_cnt
    from audit_unified_enabled_policies
   where policy_name in ('DDS_E1_CONFIG_POL','DDS_E1_CTX_POL','DDS_E1_DATA_POL');
  if v_cnt <> 3 then
    raise_application_error(-20903, 'E1 AUDIT ABORT: enabled policies=' || v_cnt || ' of 3');
  end if;
end;
/

prompt INFO logon policies already enabled before E1 (read-only, not changed)
select policy_name, enabled_option, entity_name, success, failure
  from audit_unified_enabled_policies
 where policy_name in ('ORA_LOGIN_LOGOUT','ORA_LOGON_FAILURES')
 order by policy_name;

prompt E1_AUDIT_OK
exit success
