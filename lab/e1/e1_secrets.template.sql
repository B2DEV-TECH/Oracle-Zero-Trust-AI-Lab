-- ============================================================================
-- E1 - secrets template for a MANUAL run (without the runner).
-- Runner use: "./run_e1.sh secrets" generates secrets\e1_secrets.local.sql with
-- 5 UNIQUE random passwords (prefix E1 + 22 alphanumerics from /dev/urandom),
-- inside the secrets\ folder with an owner-only ACL (icacls, verified).
-- Manual use: copy to secrets\e1_secrets.local.sql and run it in SQL*Plus.
-- The passwords are read without echo (HIDE). With VERIFY OFF and ECHO OFF they
-- are not printed. Never use DEFINE without an argument: it lists every variable.
-- ============================================================================
accept dds_admin_pwd       char prompt 'DDS_ADMIN password (lab E1): ' hide
accept dds_eu_north_pwd    char prompt 'DDS_EU_NORTH password (lab E1): ' hide
accept dds_eu_south_pwd    char prompt 'DDS_EU_SOUTH password (lab E1): ' hide
accept dds_eu_noaccess_pwd char prompt 'DDS_EU_NOACCESS password (lab E1): ' hide
accept dds_eu_norole_pwd   char prompt 'DDS_EU_NOROLE password (lab E1): ' hide
