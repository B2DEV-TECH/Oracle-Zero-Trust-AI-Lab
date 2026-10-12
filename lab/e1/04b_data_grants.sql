-- ============================================================================
-- E1 / 04b - DATA GRANTS                     [C2, DDS_ADMIN over TCP, not SYS]
-- Run as: sqlplus -L -S /nolog @04b_data_grants.sql
--
-- Privileges used (granted in 01, checked by E07/E08 in 06):
--   CREATE DATA GRANT                                 creates in the DDS_ADMIN schema itself
--   ADMINISTER ANY DATA GRANT ON SCHEMA DDS_INV_OWNER target restricted to the lab schema
-- (G50191-05 chapter 17: "CREATE DATA GRANT ... on schema A, and ... ADMINISTER ANY
--  DATA GRANT privilege at the system level or on schema B")
--
-- Effects in PDB FREEPDB1 (reverted by 99, preserved by 98):
--   3 data grants  DDS_ADMIN.INV_NORTH_READ, INV_SOUTH_READ, INV_NORTH_OWN_STATUS_UPD
-- The target data roles already exist (04a). DDS_ADMIN creates no identities.
--
-- Column scope (see docs/decisions/0004-column-scope-all-columns-except.md):
--   The read grants use ALL COLUMNS EXCEPT SUPPLIER_TAX_ID. That is a deny list:
--   any column added to INVOICES later becomes readable by DDS_DR_NORTH and
--   DDS_DR_SOUTH without any change to these grants. Acceptable for E1 because
--   the table is synthetic and dropped by 99. The final architecture should use
--   an explicit column allow list instead.
-- ============================================================================
set echo off verify off feedback on heading on pagesize 100 linesize 200
set trimspool on tab off sqlblanklines on
whenever sqlerror exit failure rollback
whenever oserror exit failure rollback

@@e1_config.sql
@@secrets\e1_secrets.local.sql
@@e1_target.local.sql

-- TCP connection as the data grant administrator (the password is not shown: verify off)
connect dds_admin/"&dds_admin_pwd"@&dds_conn
@@e1_assert_target.sql
exec dbms_application_info.set_module('E1_LAB', '04b_data_grants')

prompt 04b.1 NORTH read data grant: rows of the region, all columns except the tax id
create data grant dds_admin.inv_north_read
  as select (all columns except supplier_tax_id)
  on dds_inv_owner.invoices
  where region = 'NORTH'
  to dds_dr_north;

prompt 04b.2 SOUTH read data grant: same rule for the SOUTH region
create data grant dds_admin.inv_south_read
  as select (all columns except supplier_tax_id)
  on dds_inv_owner.invoices
  where region = 'SOUTH'
  to dds_dr_south;

prompt 04b.3 UPDATE data grant with identity propagation in the predicate
-- Only the STATUS column, only NORTH rows assigned to the session end user itself.
-- ORA_END_USER_CONTEXT.username comes from the security context, not from an
-- application parameter.
create data grant dds_admin.inv_north_own_status_upd
  as update (status)
  on dds_inv_owner.invoices
  where region = 'NORTH'
    and assigned_to = ora_end_user_context.username
  to dds_dr_north;

prompt E1_DATA_GRANTS_OK
exit success
