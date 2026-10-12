-- ============================================================================
-- E1 - target guard. Ends the session if it is NOT in the native PDB measured
-- by 00_preflight (CON_NAME and CON_DBID written to e1_target.local.sql).
-- Protects against landing in another database on the same port (for example
-- a container that publishes the same listener port).
-- SQL only: end users may not be allowed to run PL/SQL (not yet verified).
-- ============================================================================
whenever sqlerror exit failure rollback
select case
         when sys_context('USERENV','CON_NAME') = 'FREEPDB1'
          and sys_context('USERENV','CON_DBID') = '&dds_expected_con_dbid'
         then 'TARGET_OK'
         -- Wrong target: TO_NUMBER of text raises ORA-01722 and WHENEVER ends the session.
         -- Non-constant expression on purpose, so it is not evaluated at parse time.
         else to_char(to_number('WRONG_TARGET_' || sys_context('USERENV','CON_NAME')))
       end as e1_target_guard
  from dual;
