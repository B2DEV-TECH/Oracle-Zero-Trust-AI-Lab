-- ============================================================================
-- E1 / 01 - PRINCIPALS                                      [C2, SYS privilege]
-- Run as: sqlplus -L -S "/ as sysdba" @01_principals.sql
-- Prerequisite : 00 printed E1_PREFLIGHT_OK, secrets\e1_secrets.local.sql generated
--
-- Design A2 (least privilege): SYS handles ALL identity work (end users,
-- data roles, role grants, in 04a). DDS_ADMIN only creates data grants in its
-- own schema on DDS_INV_OWNER objects (04b). No PDB-wide identity privilege is
-- held by a non-SYS account.
--
-- Effects in PDB FREEPDB1 (reverted by 99, or locked by 98):
--   CREATE USER  DDS_INV_OWNER  NO AUTHENTICATION, quota 10M on USERS (data owner)
--   CREATE USER  DDS_INV_PARSE  NO AUTHENTICATION, no privilege (reserved for E2)
--   CREATE USER  DDS_ADMIN      generated password, creates the lab data grants
--   CREATE ROLE  DDS_SESSION_ROLE with CREATE SESSION (04a grants it to the data roles)
--   DDS_ADMIN receives exactly:
--     CREATE SESSION                                    (system)
--     CREATE DATA GRANT                                 (system, own schema only)
--     ADMINISTER ANY DATA GRANT ON SCHEMA DDS_INV_OWNER (schema, never system)
-- ============================================================================
set echo off verify off feedback on heading on pagesize 100 linesize 200
set trimspool on tab off sqlblanklines on serveroutput on size unlimited
whenever sqlerror exit failure rollback
whenever oserror exit failure rollback

@@secrets\e1_secrets.local.sql
@@e1_target.local.sql

alter session set container = FREEPDB1;
-- DBMS_OUTPUT state is per container: re-enable it after the switch (verified in
-- the first E1 run, the PL/SQL output was silently lost without this line)
set serveroutput on size unlimited
@@e1_assert_target.sql
exec dbms_application_info.set_module('E1_LAB', '01_principals')

prompt [SYS] 01.1 Synthetic data owner (no password: nobody logs on as this user)
create user dds_inv_owner no authentication
  default tablespace users
  quota 10m on users;

prompt [SYS] 01.2 Data grant administrator (generated password, never printed)
-- IDENTIFIED BY stays on its own line; the runner also redacts the password pattern in the log
create user dds_admin
  identified by "&dds_admin_pwd"
  default tablespace users;

prompt [SYS] 01.3 Schema privilege FIRST (fail fast)
-- Syntax: Security Guide G43025-08 "GRANT SELECT ANY TABLE ON SCHEMA HR TO psmith".
-- Deep Sec Guide G50191-05 chapter 17: ADMINISTER ANY DATA GRANT "can also be granted
-- at the schema level for a non-SYS schema". SQL Reference G57157-07 (Table 18-3)
-- does NOT list DATA GRANT privileges among schema privileges: the sources disagree [H].
-- If this GRANT fails, the script aborts here. There is NO automatic fallback
-- to the system level; any alternative requires a new human approval.
grant administer any data grant on schema dds_inv_owner to dds_admin;

prompt [SYS] 01.4 Minimal system privileges for DDS_ADMIN
-- Logon for the administrator itself
grant create session to dds_admin;
-- Create data grants ONLY in the DDS_ADMIN schema (G50191-05 chapter 17)
grant create data grant to dds_admin;

prompt [SYS] 01.5 Isolated parsing schema for E2 (no password, no privilege)
create user dds_inv_parse no authentication
  default tablespace users;

prompt [SYS] 01.6 Database role with CREATE SESSION (data roles need it for direct logon)
create role dds_session_role;
grant create session to dds_session_role;

prompt 01.7 Review: system privileges, schema privileges and roles of the lab principals
col grantee   format a20
col kind      format a8
col privilege format a32
col detail    format a30
select grantee, 'SYSTEM' as kind, privilege, 'admin=' || admin_option as detail
  from dba_sys_privs
 where grantee in ('DDS_ADMIN','DDS_SESSION_ROLE','DDS_INV_OWNER','DDS_INV_PARSE')
union all
select grantee, 'SCHEMA', privilege, "SCHEMA" || ' admin=' || admin_option
  from dba_schema_privs
 where grantee in ('DDS_ADMIN','DDS_SESSION_ROLE','DDS_INV_OWNER','DDS_INV_PARSE')
union all
select grantee, 'ROLE', granted_role, 'admin=' || admin_option
  from dba_role_privs
 where grantee in ('DDS_ADMIN','DDS_INV_OWNER','DDS_INV_PARSE')
 order by 1, 2, 3;

prompt E1_PRINCIPALS_OK
exit success
