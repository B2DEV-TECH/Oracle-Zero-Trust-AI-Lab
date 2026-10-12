-- ============================================================================
-- E1 / e1_session_guard.sql - ACTIVE-SESSION GUARD          [include, read-only]
-- Included by 00_preflight.sql, 98_retain_lock.sql and 99_cleanup.sql after the
-- container switch, the target assertion and the module tag, and before any
-- DDL. It changes nothing: SELECT statements and DBMS_OUTPUT only.
--
-- Why it exists: v1 looked for lab sessions with V$SESSION.USERNAME IN
-- (<allowlist>). That is the standard representation for database users, but
-- the Deep Data Security guide (G50191-05) does not describe how a direct-logon
-- end-user session appears in V$SESSION, and it states that CURRENT_USER becomes
-- XS$NULL once the end-user security context is attached. Matching end users by
-- V$SESSION.USERNAME alone was an unverified assumption, so it is no longer the
-- only signal.
--
-- Trust checks. Any failure aborts with ORA-20995 (detection not trustworthy):
--   T1  This session must see itself in V$SESSION with MODULE = 'E1_LAB'. If it
--       cannot, V$SESSION visibility from this container is not what the
--       other checks rely on.
--   T2  DBA_END_USER_SECURITY_CONTEXTS must be queryable with the documented
--       columns (guide 21.4.1). Any error means end-user detection is blind.
-- Detection layers. Any hit aborts with ORA-20990; all hits are listed together:
--   G1  Database-user sessions: V$SESSION.USERNAME in DDS_ADMIN, DDS_INV_OWNER,
--       DDS_INV_PARSE.
--   G2  End-user security contexts: DBA_END_USER_SECURITY_CONTEXTS rows for the
--       four lab end users. The guide lists active or cached contexts in this
--       view and states that direct-logon contexts are destroyed when the
--       session closes. This is the authoritative layer for end users.
--   G3  Unattributable sessions: other USER sessions in this container whose
--       V$SESSION.USERNAME is NULL, XS$NULL or a lab end-user name. Defense in
--       depth for G2. It can also block on an unrelated session; the operator
--       must identify it and close it by hand (fail closed, never killed here).
--   G4  Orphaned runner sessions: other sessions tagged MODULE = 'E1_LAB', for
--       example a server session left behind after a client-side timeout.
-- Runtime assumptions (not verified, see docs/architecture/assumptions.md):
--   RA-05 (T1 visibility) and RA-06 (G2 shows an open direct-logon session and
--   drops it after close) and RA-07 (G3 representation).
-- Output: SESSION_GUARD_OK on success. The runner requires this marker in the
-- logs of 00, 98 and 99.
-- ============================================================================
declare
  -- Exact allowlists; the only names this guard looks for
  c_db_users  constant sys.odcivarchar2list := sys.odcivarchar2list('DDS_ADMIN', 'DDS_INV_OWNER',
                                                                    'DDS_INV_PARSE');
  c_end_users constant sys.odcivarchar2list := sys.odcivarchar2list('DDS_EU_NORTH', 'DDS_EU_SOUTH',
                                                                    'DDS_EU_NOACCESS', 'DDS_EU_NOROLE');
  c_module    constant varchar2(48) := 'E1_LAB';
  -- Dynamic SQL keeps a missing view or column catchable (T2) instead of
  -- failing the whole block at compile time with a less clear message
  c_ctx_sql   constant varchar2(1000) :=
    q'[select listagg(username || '#' || security_context_type, ',' on overflow truncate)
                within group (order by username)
         from dba_end_user_security_contexts
        where upper(username) in (:b1, :b2, :b3, :b4)]';
  v_own_sid   number := to_number(sys_context('USERENV', 'SID'));
  v_con_id    number := to_number(sys_context('USERENV', 'CON_ID'));
  v_count     pls_integer;
  v_list      varchar2(4000);
  v_hits      varchar2(32767);

  -- Adds one detection layer result to the final message
  procedure p_hit(p_layer in varchar2, p_list in varchar2) is
  begin
    if p_list is not null then
      dbms_output.put_line('ERROR ' || p_layer || ' ' || p_list);
      v_hits := v_hits || ' ' || p_layer || '[' || p_list || ']';
    else
      dbms_output.put_line('INFO  ' || p_layer || ' none');
    end if;
  end p_hit;

begin
  -- T1. Own session visible with the module tag set by the including script
  select count(*)
    into v_count
    from v$session s
   where s.sid = v_own_sid
     and s.module = c_module;
  if v_count <> 1 then
    raise_application_error(-20995, 'Session guard: own session (SID ' || v_own_sid
                            || ') not visible in V$SESSION with MODULE ' || c_module
                            || '; active-session detection cannot be trusted');
  end if;
  dbms_output.put_line('INFO  T1 own session visible in V$SESSION');

  -- T2 + G2. End-user security contexts. Any query error is fatal (fail closed).
  begin
    execute immediate c_ctx_sql
      into v_list
      using c_end_users(1), c_end_users(2), c_end_users(3), c_end_users(4);
  exception
    when others then
      dbms_output.put_line('ERROR T2 DBA_END_USER_SECURITY_CONTEXTS not queryable: '
                           || substr(sqlerrm, 1, 300));
      raise_application_error(-20995, 'Session guard: end-user security contexts cannot be read;'
                              || ' active-session detection cannot be trusted', true);
  end;
  dbms_output.put_line('INFO  T2 DBA_END_USER_SECURITY_CONTEXTS queryable');
  p_hit('G2 end-user security contexts:', v_list);

  -- G1. Database-user sessions (any container visible from here)
  select listagg(s.username || '#' || s.sid, ',' on overflow truncate)
           within group (order by s.username, s.sid)
    into v_list
    from v$session s
   where s.username in (select column_value from table(c_db_users));
  p_hit('G1 database-user sessions:', v_list);

  -- G3. Unattributable USER sessions in this container. MODULE and PROGRAM are
  --     listed so the operator can identify the session; nothing is killed.
  select listagg(nvl(s.username, '<NULL>') || '#' || s.sid || '#'
                 || nvl(s.module, '-') || '#' || nvl(s.program, '-'), ',' on overflow truncate)
           within group (order by s.sid)
    into v_list
    from v$session s
   where s.con_id = v_con_id
     and s.type = 'USER'
     and s.sid <> v_own_sid
     and (s.username is null
          or s.username = 'XS$NULL'
          or upper(s.username) in (select column_value from table(c_end_users)));
  p_hit('G3 unattributable sessions:', v_list);

  -- G4. Other sessions still tagged by this runner (orphans of a failed step)
  select listagg(nvl(s.username, '<NULL>') || '#' || s.sid || '#' || nvl(s.action, '-'),
                 ',' on overflow truncate)
           within group (order by s.sid)
    into v_list
    from v$session s
   where s.module = c_module
     and s.sid <> v_own_sid;
  p_hit('G4 orphaned E1_LAB sessions:', v_list);

  if v_hits is not null then
    raise_application_error(-20990, substr('Session guard: lab sessions or contexts are active,'
                            || ' nothing was changed. Close them and rerun.' || v_hits, 1, 2000));
  end if;
  dbms_output.put_line('SESSION_GUARD_OK');
end;
/
