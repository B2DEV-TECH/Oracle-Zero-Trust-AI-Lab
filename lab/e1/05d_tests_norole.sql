-- E1_EXPECTED_ASSERTS=0
-- ============================================================================
-- E1 / 05d - END USER WITHOUT DATA ROLE   [logon attempt DDS_EU_NOROLE TCP, C3]
-- Run as: sqlplus -L -S /nolog @05d_tests_norole.sql
--
-- What it proves: without a data role there is no path to CREATE SESSION, so
-- direct logon must fail even with the correct password (RA-04).
--
-- Unique password per end user: DDS_EU_NOROLE has its own password, which no
-- other test uses. Therefore there is no direct positive control of this user's
-- password. The control is indirect: the same generator and the same secrets
-- file authenticated DDS_EU_NORTH, DDS_EU_SOUTH and DDS_EU_NOACCESS in 05a-05c,
-- and evidence O02 in 06 shows the logon attempt in the audit trail. Even so,
-- ORA-01017 here remains INCONCLUSIVE: it does not distinguish a wrong password
-- from an authorization refusal.
--
-- Evaluation done by run_e1.sh (this script has no PL/SQL block, because there
-- is no session to run it):
--   PASS          ORA-01045 in the log and no UNEXPECTED_LOGON_OK  [H in the code]
--   INCONCLUSIVE  ORA-01017 or ORA-12xxx (password or network, not authorization)
--   INCONCLUSIVE  any other ORA- (for example a locked account or a Deep Sec
--                 specific code): manual classification from the log, no automatic PASS
--   FAIL          UNEXPECTED_LOGON_OK present, incomplete script or no ORA-
-- No target guard (e1_assert_target): it requires a session, and here the
-- expected outcome is no session. The connection uses the same &dds_conn as the
-- other tests.
-- Database effect: none. The logon failure may create a record under ORA_LOGIN_LOGOUT.
-- ============================================================================
set echo off verify off feedback off heading off pagesize 0 linesize 200
whenever sqlerror continue
whenever oserror exit failure

@@e1_config.sql
@@secrets\e1_secrets.local.sql
@@e1_target.local.sql

connect dds_eu_norole/"&dds_eu_norole_pwd"@&dds_conn

-- Prints only if the logon worked (which would be a security failure)
select 'UNEXPECTED_LOGON_OK ' || sys_context('USERENV','SESSION_USER') from dual;

prompt E1_NOROLE_ATTEMPT_DONE
exit success
