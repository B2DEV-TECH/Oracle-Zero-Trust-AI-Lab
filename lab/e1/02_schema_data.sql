-- ============================================================================
-- E1 / 02 - TABLE AND SYNTHETIC DATA                      [C2, SYS privilege]
-- Run as: sqlplus -L -S "/ as sysdba" @02_schema_data.sql
--
-- Effects: creates DDS_INV_OWNER.INVOICES in tablespace USERS and inserts 12
--          fully synthetic rows (fictitious suppliers and tax ids). COMMIT at the end.
-- Reverted by: 99_cleanup.sql (explicit DROP TABLE with PURGE, then DROP USER
--              without CASCADE). Preserved for E2 by 98_retain_lock.sql.
--
-- Data design (each row exists to prove something):
--   NORTH 101-105 sum 15000 | 101,102 = DDS_EU_NORTH, 103 = another fictitious identity
--   SOUTH 201-204 sum  1000 | 201,202 = DDS_EU_SOUTH
--   EAST  301-303 sum 60000 | no data role covers EAST (deny by default)
--   Total 12 rows, sum 76000, all PENDING.
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
exec dbms_application_info.set_module('E1_LAB', '02_schema_data')

prompt [SYS] 02.1 Synthetic invoice table
create table dds_inv_owner.invoices (
  invoice_id       number(10)     not null,
  invoice_no       varchar2(20)   not null,
  region           varchar2(10)   not null,
  supplier_name    varchar2(60)   not null,
  supplier_tax_id  varchar2(20)   not null,   -- sensitive column: excluded from every data grant
  amount           number(12,2)   not null,
  currency         varchar2(3)    default 'BRL' not null,
  status           varchar2(12)   default 'PENDING' not null,
  assigned_to      varchar2(128),             -- responsible end user (UPDATE predicate)
  issue_date       date           not null,
  constraint dds_inv_pk        primary key (invoice_id),
  constraint dds_inv_region_ck check (region in ('NORTH','SOUTH','EAST')),
  constraint dds_inv_status_ck check (status in ('PENDING','APPROVED','REJECTED'))
) tablespace users;

comment on table dds_inv_owner.invoices is 'E1 Deep Data Security lab - fully synthetic data';

prompt [SYS] 02.2 Load of the 12 synthetic rows (NORTH 5, SOUTH 4, EAST 3)
insert into dds_inv_owner.invoices
  (invoice_id, invoice_no, region, supplier_name, supplier_tax_id, amount, assigned_to, issue_date)
select 101, 'INV-N-0101', 'NORTH', 'Synthetic Supplier Alpha',   'SYN-TAX-N-0101',  1000, 'DDS_EU_NORTH',       date '2026-01-05' from dual union all
select 102, 'INV-N-0102', 'NORTH', 'Synthetic Supplier Beta',    'SYN-TAX-N-0102',  2000, 'DDS_EU_NORTH',       date '2026-01-06' from dual union all
select 103, 'INV-N-0103', 'NORTH', 'Synthetic Supplier Gamma',   'SYN-TAX-N-0103',  3000, 'DDS_EU_NORTH_OTHER', date '2026-01-07' from dual union all
select 104, 'INV-N-0104', 'NORTH', 'Synthetic Supplier Delta',   'SYN-TAX-N-0104',  4000, null,                 date '2026-01-08' from dual union all
select 105, 'INV-N-0105', 'NORTH', 'Synthetic Supplier Eta',     'SYN-TAX-N-0105',  5000, null,                 date '2026-01-09' from dual union all
select 201, 'INV-S-0201', 'SOUTH', 'Synthetic Supplier Theta',   'SYN-TAX-S-0201',   100, 'DDS_EU_SOUTH',       date '2026-02-05' from dual union all
select 202, 'INV-S-0202', 'SOUTH', 'Synthetic Supplier Iota',    'SYN-TAX-S-0202',   200, 'DDS_EU_SOUTH',       date '2026-02-06' from dual union all
select 203, 'INV-S-0203', 'SOUTH', 'Synthetic Supplier Kappa',   'SYN-TAX-S-0203',   300, null,                 date '2026-02-07' from dual union all
select 204, 'INV-S-0204', 'SOUTH', 'Synthetic Supplier Lambda',  'SYN-TAX-S-0204',   400, null,                 date '2026-02-08' from dual union all
select 301, 'INV-E-0301', 'EAST',  'Synthetic Supplier Mu',      'SYN-TAX-E-0301', 10000, null,                 date '2026-03-05' from dual union all
select 302, 'INV-E-0302', 'EAST',  'Synthetic Supplier Nu',      'SYN-TAX-E-0302', 20000, null,                 date '2026-03-06' from dual union all
select 303, 'INV-E-0303', 'EAST',  'Synthetic Supplier Xi',      'SYN-TAX-E-0303', 30000, null,                 date '2026-03-07' from dual;

prompt 02.3 Check before COMMIT (SYS view, no Deep Sec)
declare
  v_cnt number;
  v_sum number;
begin
  select count(*), sum(amount) into v_cnt, v_sum from dds_inv_owner.invoices;
  if v_cnt <> 12 or v_sum <> 76000 then
    raise_application_error(-20902, 'E1 DATA ABORT: expected 12/76000, actual '
                                    || v_cnt || '/' || v_sum);
  end if;
end;
/

commit;

select region, count(*) as row_count, sum(amount) as total
  from dds_inv_owner.invoices
 group by rollup(region)
 order by region;

prompt E1_DATA_OK
exit success
