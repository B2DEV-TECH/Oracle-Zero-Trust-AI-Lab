-- ============================================================================
-- E1 / 04a - DEEP SEC IDENTITIES                           [C2, SYS privilege]
-- Run as: sqlplus -L -S "/ as sysdba" @04a_identities.sql
--
-- Design A2: identities stay with SYS so that no ordinary account needs
-- CREATE END USER, CREATE DATA ROLE or GRANT ANY DATA ROLE (PDB-wide
-- privileges with no schema scope in SQL Reference G57157-07, Table 18-2).
--
-- Effects in PDB FREEPDB1 (reverted by 99, or locked by 98):
--   3 data roles   DDS_DR_NORTH, DDS_DR_SOUTH, DDS_DR_SESSION_ONLY
--   GRANT DDS_SESSION_ROLE (database role with CREATE SESSION) to the 3 data roles
--   4 end users    DDS_EU_NORTH, DDS_EU_SOUTH, DDS_EU_NOACCESS, DDS_EU_NOROLE,
--                  each with ITS OWN random password (secrets\e1_secrets.local.sql)
--   3 GRANT DATA ROLE (DDS_EU_NOROLE is left without a data role on purpose)
-- Every action is recorded in the audit trail through DDS_E1_CONFIG_POL (03),
-- if SYS is audited by unified policies [H] (measured by O06 in 06).
-- Nothing here grants a classic object privilege (GRANT SELECT ON ...).
-- ============================================================================
set echo off verify off feedback on heading on pagesize 100 linesize 200
set trimspool on tab off sqlblanklines on
whenever sqlerror exit failure rollback
whenever oserror exit failure rollback

@@secrets\e1_secrets.local.sql
@@e1_target.local.sql

alter session set container = FREEPDB1;
@@e1_assert_target.sql
exec dbms_application_info.set_module('E1_LAB', '04a_identities')

prompt [SYS] 04a.1 Local data roles (G50191-05 chapter 14)
create data role dds_dr_north;
create data role dds_dr_south;
-- Control role: only allows logon, no data grant points to it
create data role dds_dr_session_only;

prompt [SYS] 04a.2 Direct logon requires CREATE SESSION via a database role on the data role (G50191-05 3.4)
grant dds_session_role to dds_dr_north;
grant dds_session_role to dds_dr_south;
grant dds_session_role to dds_dr_session_only;

prompt [SYS] 04a.3 Local end users, UNIQUE password per user (G50191-05 chapter 11)
-- IDENTIFIED BY on its own line; the runner also redacts the password pattern in the log
create end user dds_eu_north
  identified by "&dds_eu_north_pwd";
create end user dds_eu_south
  identified by "&dds_eu_south_pwd";
create end user dds_eu_noaccess
  identified by "&dds_eu_noaccess_pwd";
create end user dds_eu_norole
  identified by "&dds_eu_norole_pwd";

prompt [SYS] 04a.4 Data role assignment (G50191-05 14.1; DDS_EU_NOROLE gets none)
grant data role dds_dr_north        to dds_eu_north;
grant data role dds_dr_south        to dds_eu_south;
grant data role dds_dr_session_only to dds_eu_noaccess;

prompt 04a.5 Review
col grantee   format a20
col data_role format a22
col role_type format a16
select grantee, data_role, role_type
  from dba_data_role_grants
 where grantee in ('DDS_EU_NORTH','DDS_EU_SOUTH','DDS_EU_NOACCESS','DDS_EU_NOROLE',
                   'DDS_DR_NORTH','DDS_DR_SOUTH','DDS_DR_SESSION_ONLY')
 order by grantee, data_role;

prompt E1_IDENTITIES_OK
exit success
