-- M1 publication gate: quarantine -> seal -> verification -> human approval
-- -> release, enforced inside MySQL.
--
-- Every trigger and routine runs as 'm1_gate_def'@'%', a locked account that
-- nobody can log in as. It needs SUPER-level deployment (binary logging is on),
-- so the lab administrator installs this file and names the definer.
--
-- Attribution uses USER() (the client account; CURRENT_USER() is the definer
-- inside a trigger). USER() is asserted by the client, so it is trusted only
-- while there are no anonymous accounts and no proxy mappings; every
-- attributing trigger checks that first and fails closed. Authorization itself
-- comes from GRANTs (30_grants.sql); the USER() checks are a second layer.
--
-- The lab administrator remains in the trusted computing base: it can drop
-- triggers. The release procedure recomputes every hash so that content
-- changed behind the triggers' back is refused, but an administrator who
-- rewrites content, seal, verification and approval consistently is not
-- detected by the database alone.

-- ---------------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------------
CREATE TABLE m1_kb_q.batches (
  batch_id   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  pipeline   VARCHAR(40)  NOT NULL,
  code_hash  CHAR(64)     NOT NULL,
  builder    VARCHAR(288) NOT NULL DEFAULT '',   -- set by trigger: USER()
  obs_hash   CHAR(64)     NOT NULL DEFAULT '',   -- set by trigger: observation state at build start
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE = InnoDB;

CREATE TABLE m1_kb_q.chunks (
  batch_id  BIGINT UNSIGNED NOT NULL,
  chunk_no  INT UNSIGNED    NOT NULL,
  doc_key   VARCHAR(40)     NOT NULL,
  content   VARCHAR(2000)   NOT NULL,
  embedding VECTOR(384)     NOT NULL,
  PRIMARY KEY (batch_id, chunk_no)
) ENGINE = InnoDB;

CREATE TABLE m1_ctl.seals (
  batch_id    BIGINT UNSIGNED NOT NULL PRIMARY KEY,
  sealed_hash CHAR(64)     NOT NULL DEFAULT '',  -- set by trigger
  row_count   INT UNSIGNED NOT NULL DEFAULT 0,   -- set by trigger
  obs_hash    CHAR(64)     NOT NULL DEFAULT '',  -- set by trigger
  sealed_by   VARCHAR(288) NOT NULL DEFAULT '',  -- set by trigger
  sealed_at   TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE = InnoDB;

CREATE TABLE m1_ctl.verifications (
  verification_id    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  batch_id           BIGINT UNSIGNED NOT NULL,
  verdict            ENUM('PASS', 'FAIL', 'INCONCLUSIVE') NOT NULL,
  content_hash       CHAR(64)     NOT NULL,
  obs_hash           CHAR(64)     NOT NULL,
  pipeline_code_hash CHAR(64)     NOT NULL,
  verifier_code_hash CHAR(64)     NOT NULL,
  evidence_hash      CHAR(64)     NOT NULL,
  verified_by        VARCHAR(288) NOT NULL DEFAULT '',  -- set by trigger
  verified_at        TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  KEY verifications_batch_ix (batch_id)
) ENGINE = InnoDB;

CREATE TABLE m1_ctl.approvals (
  approval_id     BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  verification_id BIGINT UNSIGNED NOT NULL,
  batch_id        BIGINT UNSIGNED NOT NULL,
  decision        ENUM('APPROVE', 'REJECT') NOT NULL,
  content_hash    CHAR(64)     NOT NULL,
  note            VARCHAR(400) NOT NULL DEFAULT '',
  approved_by     VARCHAR(288) NOT NULL DEFAULT '',  -- set by trigger
  approved_at     TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  KEY approvals_batch_ix (batch_id)
) ENGINE = InnoDB;

CREATE TABLE m1_ctl.releases (
  batch_id        BIGINT UNSIGNED NOT NULL PRIMARY KEY,
  verification_id BIGINT UNSIGNED NOT NULL,
  approval_id     BIGINT UNSIGNED NOT NULL,
  content_hash    CHAR(64)     NOT NULL,
  obs_hash        CHAR(64)     NOT NULL,
  row_count       INT UNSIGNED NOT NULL,
  released_by     VARCHAR(288) NOT NULL DEFAULT '',  -- set by trigger
  released_at     TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE = InnoDB;

CREATE TABLE m1_kb_pub.chunks (
  batch_id  BIGINT UNSIGNED NOT NULL,
  chunk_no  INT UNSIGNED    NOT NULL,
  doc_key   VARCHAR(40)     NOT NULL,
  content   VARCHAR(2000)   NOT NULL,
  embedding VECTOR(384)     NOT NULL,
  PRIMARY KEY (batch_id, chunk_no)
) ENGINE = InnoDB;

DELIMITER //

-- ---------------------------------------------------------------------------
-- Functions
-- ---------------------------------------------------------------------------

-- Content hash of a quarantined batch: a hash chain over the rows in chunk
-- order. batch_id and timestamps are excluded so that the same content built
-- in another instance (the verifier's shadow) hashes the same. Locking reads
-- make the function see the latest committed rows.
CREATE DEFINER = 'm1_gate_def'@'%' FUNCTION m1_ctl.batch_hash(p_batch BIGINT UNSIGNED)
  RETURNS CHAR(64) READS SQL DATA SQL SECURITY DEFINER
BEGIN
  DECLARE v_done INT DEFAULT 0;
  DECLARE v_row CHAR(64);
  DECLARE v_hash CHAR(64) DEFAULT SHA2('m1-batch-v1', 256);
  DECLARE c_rows CURSOR FOR
    SELECT SHA2(CONCAT_WS('|', chunk_no, doc_key, HEX(content), HEX(embedding)), 256)
      FROM m1_kb_q.chunks WHERE batch_id = p_batch ORDER BY chunk_no FOR SHARE;
  DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = 1;
  OPEN c_rows;
  read_rows: LOOP
    FETCH c_rows INTO v_row;
    IF v_done = 1 THEN LEAVE read_rows; END IF;
    SET v_hash = SHA2(CONCAT(v_hash, v_row), 256);
  END LOOP;
  CLOSE c_rows;
  RETURN v_hash;
END//

-- The same hash over the published copy of a batch.
CREATE DEFINER = 'm1_gate_def'@'%' FUNCTION m1_ctl.pub_hash(p_batch BIGINT UNSIGNED)
  RETURNS CHAR(64) READS SQL DATA SQL SECURITY DEFINER
BEGIN
  DECLARE v_done INT DEFAULT 0;
  DECLARE v_row CHAR(64);
  DECLARE v_hash CHAR(64) DEFAULT SHA2('m1-batch-v1', 256);
  DECLARE c_rows CURSOR FOR
    SELECT SHA2(CONCAT_WS('|', chunk_no, doc_key, HEX(content), HEX(embedding)), 256)
      FROM m1_kb_pub.chunks WHERE batch_id = p_batch ORDER BY chunk_no FOR SHARE;
  DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = 1;
  OPEN c_rows;
  read_rows: LOOP
    FETCH c_rows INTO v_row;
    IF v_done = 1 THEN LEAVE read_rows; END IF;
    SET v_hash = SHA2(CONCAT(v_hash, v_row), 256);
  END LOOP;
  CLOSE c_rows;
  RETURN v_hash;
END//

-- Observation state: everything that decides what an identity observes or may
-- do. Masking policy definitions, which source columns carry a policy, role
-- grants and default roles, static and dynamic privileges, proxy mappings, the
-- three global role settings, and the definitions of the gate's own triggers
-- and routines. Password hashes and grant timestamps are excluded.
-- v2 adds activate_mandatory_roles (default ON), which activates the roles
-- named in mandatory_roles at login even with activate_all_roles_on_login OFF.
-- Known gap: the column -> policy binding (which policy a column uses) is only
-- visible through SHOW CREATE TABLE, which a routine cannot capture. Swapping
-- a column between two existing policies does not change this hash; the
-- verifier records SHOW CREATE TABLE separately.
CREATE DEFINER = 'm1_gate_def'@'%' FUNCTION m1_ctl.observation_state_hash()
  RETURNS CHAR(64) READS SQL DATA SQL SECURITY DEFINER
BEGIN
  SET SESSION group_concat_max_len = 16777216;
  RETURN SHA2(CONCAT_WS('#', 'm1-obs-v2',
    IFNULL((SELECT GROUP_CONCAT(CONCAT_WS('|', policy_name, HEX(expression), HEX(argument))
                                ORDER BY policy_name SEPARATOR ';')
              FROM mysql.column_masking_policies), '-'),
    IFNULL((SELECT GROUP_CONCAT(CONCAT_WS('|', TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, EXTRA)
                                ORDER BY TABLE_NAME, ORDINAL_POSITION SEPARATOR ';')
              FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'm1_src'), '-'),
    IFNULL((SELECT GROUP_CONCAT(CONCAT_WS('|', FROM_HOST, FROM_USER, TO_HOST, TO_USER, WITH_ADMIN_OPTION)
                                ORDER BY FROM_USER, FROM_HOST, TO_USER, TO_HOST SEPARATOR ';')
              FROM mysql.role_edges), '-'),
    IFNULL((SELECT GROUP_CONCAT(CONCAT_WS('|', HOST, USER, DEFAULT_ROLE_HOST, DEFAULT_ROLE_USER)
                                ORDER BY USER, HOST, DEFAULT_ROLE_USER, DEFAULT_ROLE_HOST SEPARATOR ';')
              FROM mysql.default_roles), '-'),
    IFNULL((SELECT GROUP_CONCAT(CONCAT_WS('|', Host, User, Select_priv, Insert_priv, Update_priv, Delete_priv,
                                          Create_priv, Drop_priv, Alter_priv, Index_priv, Super_priv,
                                          Grant_priv, Trigger_priv, Execute_priv, Create_routine_priv,
                                          Alter_routine_priv, Create_view_priv, Show_view_priv,
                                          Create_user_priv, Lock_tables_priv, account_locked)
                                ORDER BY User, Host SEPARATOR ';')
              FROM mysql.user), '-'),
    IFNULL((SELECT GROUP_CONCAT(CONCAT_WS('|', Host, Db, User, Select_priv, Insert_priv, Update_priv,
                                          Delete_priv, Create_priv, Drop_priv, Alter_priv, Index_priv,
                                          Grant_priv, Trigger_priv, Execute_priv, Create_routine_priv,
                                          Alter_routine_priv, Create_view_priv, Show_view_priv,
                                          Lock_tables_priv, References_priv)
                                ORDER BY User, Host, Db SEPARATOR ';')
              FROM mysql.db), '-'),
    IFNULL((SELECT GROUP_CONCAT(CONCAT_WS('|', Host, Db, User, Table_name, Table_priv, Column_priv)
                                ORDER BY User, Host, Db, Table_name SEPARATOR ';')
              FROM mysql.tables_priv), '-'),
    IFNULL((SELECT GROUP_CONCAT(CONCAT_WS('|', Host, Db, User, Table_name, Column_name, Column_priv)
                                ORDER BY User, Host, Db, Table_name, Column_name SEPARATOR ';')
              FROM mysql.columns_priv), '-'),
    IFNULL((SELECT GROUP_CONCAT(CONCAT_WS('|', Host, Db, User, Routine_name, Routine_type, Proc_priv)
                                ORDER BY User, Host, Db, Routine_name, Routine_type SEPARATOR ';')
              FROM mysql.procs_priv), '-'),
    IFNULL((SELECT GROUP_CONCAT(CONCAT_WS('|', USER, HOST, PRIV, WITH_GRANT_OPTION)
                                ORDER BY USER, HOST, PRIV SEPARATOR ';')
              FROM mysql.global_grants), '-'),
    IFNULL((SELECT GROUP_CONCAT(CONCAT_WS('|', Host, User, Proxied_host, Proxied_user, With_grant)
                                ORDER BY User, Host, Proxied_user, Proxied_host SEPARATOR ';')
              FROM mysql.proxies_priv), '-'),
    @@GLOBAL.mandatory_roles,
    @@GLOBAL.activate_all_roles_on_login,
    @@GLOBAL.activate_mandatory_roles,
    IFNULL((SELECT GROUP_CONCAT(CONCAT_WS('|', TRIGGER_SCHEMA, TRIGGER_NAME, EVENT_OBJECT_TABLE,
                                          ACTION_TIMING, EVENT_MANIPULATION, DEFINER,
                                          SHA2(ACTION_STATEMENT, 256))
                                ORDER BY TRIGGER_SCHEMA, TRIGGER_NAME SEPARATOR ';')
              FROM information_schema.TRIGGERS
             WHERE TRIGGER_SCHEMA IN ('m1_kb_q', 'm1_ctl', 'm1_kb_pub')), '-'),
    IFNULL((SELECT GROUP_CONCAT(CONCAT_WS('|', ROUTINE_NAME, ROUTINE_TYPE, DEFINER, SECURITY_TYPE,
                                          SHA2(ROUTINE_DEFINITION, 256))
                                ORDER BY ROUTINE_NAME SEPARATOR ';')
              FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = 'm1_ctl'), '-')
  ), 256);
END//

-- USER() is only meaningful when no anonymous account or proxy mapping can
-- make the client-asserted name differ from the authenticated account.
CREATE DEFINER = 'm1_gate_def'@'%' FUNCTION m1_ctl.identity_preconditions_ok()
  RETURNS TINYINT READS SQL DATA SQL SECURITY DEFINER
BEGIN
  RETURN (SELECT COUNT(*) FROM mysql.user WHERE User = '') = 0
     AND (SELECT COUNT(*) FROM mysql.proxies_priv WHERE Proxied_user <> '' OR User <> 'root') = 0;
END//

-- ---------------------------------------------------------------------------
-- Quarantine
-- ---------------------------------------------------------------------------
CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_kb_q.batches_bi BEFORE INSERT ON m1_kb_q.batches FOR EACH ROW
BEGIN
  IF NOT m1_ctl.identity_preconditions_ok() THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: identity preconditions failed (anonymous account or proxy mapping)';
  END IF;
  SET NEW.builder = USER(),
      NEW.obs_hash = m1_ctl.observation_state_hash(),
      NEW.created_at = CURRENT_TIMESTAMP(6);
END//

CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_kb_q.batches_bu BEFORE UPDATE ON m1_kb_q.batches FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: batches are append-only'//

CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_kb_q.batches_bd BEFORE DELETE ON m1_kb_q.batches FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: batches are append-only'//

CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_kb_q.chunks_bi BEFORE INSERT ON m1_kb_q.chunks FOR EACH ROW
BEGIN
  DECLARE v_builder VARCHAR(288) DEFAULT NULL;
  DECLARE v_sealed INT DEFAULT 0;
  -- Shared lock on the batch row: a concurrent seal (exclusive lock) waits for
  -- this insert to commit, or this insert waits for the seal and then fails.
  SELECT builder INTO v_builder FROM m1_kb_q.batches WHERE batch_id = NEW.batch_id FOR SHARE;
  IF v_builder IS NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: unknown batch';
  END IF;
  IF SUBSTRING_INDEX(v_builder, '@', 1) <> SUBSTRING_INDEX(USER(), '@', 1) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: only the batch builder may add chunks';
  END IF;
  SELECT COUNT(*) INTO v_sealed FROM m1_ctl.seals WHERE batch_id = NEW.batch_id FOR SHARE;
  IF v_sealed <> 0 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: batch is sealed';
  END IF;
END//

CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_kb_q.chunks_bu BEFORE UPDATE ON m1_kb_q.chunks FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: quarantined chunks are append-only'//

CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_kb_q.chunks_bd BEFORE DELETE ON m1_kb_q.chunks FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: quarantined chunks are append-only'//

-- ---------------------------------------------------------------------------
-- Seal
-- ---------------------------------------------------------------------------
CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_ctl.seals_bi BEFORE INSERT ON m1_ctl.seals FOR EACH ROW
BEGIN
  DECLARE v_builder VARCHAR(288) DEFAULT NULL;
  DECLARE v_obs CHAR(64) DEFAULT NULL;
  DECLARE v_count INT DEFAULT 0;
  IF NOT m1_ctl.identity_preconditions_ok() THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: identity preconditions failed (anonymous account or proxy mapping)';
  END IF;
  SELECT builder, obs_hash INTO v_builder, v_obs FROM m1_kb_q.batches WHERE batch_id = NEW.batch_id FOR UPDATE;
  IF v_builder IS NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: unknown batch';
  END IF;
  IF SUBSTRING_INDEX(v_builder, '@', 1) <> SUBSTRING_INDEX(USER(), '@', 1) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: only the batch builder may seal it';
  END IF;
  SELECT COUNT(*) INTO v_count FROM m1_kb_q.chunks WHERE batch_id = NEW.batch_id FOR SHARE;
  IF v_count = 0 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: empty batch';
  END IF;
  SET NEW.obs_hash = m1_ctl.observation_state_hash();
  IF NEW.obs_hash <> v_obs THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: observation state changed during the build';
  END IF;
  SET NEW.sealed_hash = m1_ctl.batch_hash(NEW.batch_id),
      NEW.row_count = v_count,
      NEW.sealed_by = USER(),
      NEW.sealed_at = CURRENT_TIMESTAMP(6);
END//

CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_ctl.seals_bu BEFORE UPDATE ON m1_ctl.seals FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: seals are append-only'//

CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_ctl.seals_bd BEFORE DELETE ON m1_ctl.seals FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: seals are append-only'//

-- ---------------------------------------------------------------------------
-- Verification
-- ---------------------------------------------------------------------------
CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_ctl.verifications_bi BEFORE INSERT ON m1_ctl.verifications FOR EACH ROW
BEGIN
  DECLARE v_sealed CHAR(64) DEFAULT NULL;
  DECLARE v_builder VARCHAR(288) DEFAULT NULL;
  DECLARE v_code CHAR(64) DEFAULT NULL;
  IF NOT m1_ctl.identity_preconditions_ok() THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: identity preconditions failed (anonymous account or proxy mapping)';
  END IF;
  IF SUBSTRING_INDEX(USER(), '@', 1) <> 'm1_verifier' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: only m1_verifier may record a verification';
  END IF;
  SELECT s.sealed_hash, b.builder, b.code_hash INTO v_sealed, v_builder, v_code
    FROM m1_ctl.seals s JOIN m1_kb_q.batches b ON b.batch_id = s.batch_id
   WHERE s.batch_id = NEW.batch_id FOR SHARE;
  IF v_sealed IS NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: batch is not sealed';
  END IF;
  IF SUBSTRING_INDEX(v_builder, '@', 1) = SUBSTRING_INDEX(USER(), '@', 1) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: a builder cannot verify its own batch';
  END IF;
  IF NEW.content_hash <> v_sealed THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: content hash does not match the seal';
  END IF;
  IF NEW.content_hash <> m1_ctl.batch_hash(NEW.batch_id) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: quarantined content changed after the seal';
  END IF;
  IF NEW.obs_hash <> m1_ctl.observation_state_hash() THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: observation state differs from the verified one';
  END IF;
  IF NEW.verdict = 'PASS' AND NEW.pipeline_code_hash <> v_code THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: PASS requires the verified code to be the batch code';
  END IF;
  SET NEW.verified_by = USER(),
      NEW.verified_at = CURRENT_TIMESTAMP(6);
END//

CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_ctl.verifications_bu BEFORE UPDATE ON m1_ctl.verifications FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: verifications are append-only'//

CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_ctl.verifications_bd BEFORE DELETE ON m1_ctl.verifications FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: verifications are append-only'//

-- ---------------------------------------------------------------------------
-- Human approval
-- ---------------------------------------------------------------------------
CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_ctl.approvals_bi BEFORE INSERT ON m1_ctl.approvals FOR EACH ROW
BEGIN
  DECLARE v_batch BIGINT UNSIGNED DEFAULT NULL;
  DECLARE v_verdict VARCHAR(12) DEFAULT NULL;
  DECLARE v_hash CHAR(64) DEFAULT NULL;
  DECLARE v_verifier VARCHAR(288) DEFAULT NULL;
  DECLARE v_builder VARCHAR(288) DEFAULT NULL;
  DECLARE v_latest BIGINT UNSIGNED DEFAULT NULL;
  IF NOT m1_ctl.identity_preconditions_ok() THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: identity preconditions failed (anonymous account or proxy mapping)';
  END IF;
  IF SUBSTRING_INDEX(USER(), '@', 1) <> 'm1_approver' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: only m1_approver may record an approval';
  END IF;
  SELECT v.batch_id, v.verdict, v.content_hash, v.verified_by, b.builder
    INTO v_batch, v_verdict, v_hash, v_verifier, v_builder
    FROM m1_ctl.verifications v JOIN m1_kb_q.batches b ON b.batch_id = v.batch_id
   WHERE v.verification_id = NEW.verification_id FOR SHARE;
  IF v_batch IS NULL OR v_batch <> NEW.batch_id THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: verification does not belong to this batch';
  END IF;
  IF NEW.decision = 'APPROVE' THEN
    IF v_verdict <> 'PASS' THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: only a PASS verification can be approved';
    END IF;
    SELECT MAX(verification_id) INTO v_latest FROM m1_ctl.verifications WHERE batch_id = NEW.batch_id FOR SHARE;
    IF v_latest <> NEW.verification_id THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: verification is not the latest for this batch';
    END IF;
    IF NEW.content_hash <> v_hash THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: approved hash differs from the verified hash';
    END IF;
    IF SUBSTRING_INDEX(USER(), '@', 1) IN (SUBSTRING_INDEX(v_verifier, '@', 1), SUBSTRING_INDEX(v_builder, '@', 1)) THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: approver must differ from builder and verifier';
    END IF;
  END IF;
  SET NEW.approved_by = USER(),
      NEW.approved_at = CURRENT_TIMESTAMP(6);
END//

CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_ctl.approvals_bu BEFORE UPDATE ON m1_ctl.approvals FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: approvals are append-only'//

CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_ctl.approvals_bd BEFORE DELETE ON m1_ctl.approvals FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: approvals are append-only'//

-- ---------------------------------------------------------------------------
-- Release and the published table
-- ---------------------------------------------------------------------------
CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_ctl.releases_bi BEFORE INSERT ON m1_ctl.releases FOR EACH ROW
BEGIN
  IF SUBSTRING_INDEX(USER(), '@', 1) <> 'm1_release' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: releases are recorded only by m1_ctl.release_batch';
  END IF;
  SET NEW.released_by = USER(),
      NEW.released_at = CURRENT_TIMESTAMP(6);
END//

CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_ctl.releases_bu BEFORE UPDATE ON m1_ctl.releases FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: releases are append-only'//

CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_ctl.releases_bd BEFORE DELETE ON m1_ctl.releases FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: releases are append-only'//

-- A published row must be the byte-identical copy of a sealed quarantine row,
-- written by the release procedure. Fires for every account, root included.
CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_kb_pub.chunks_bi BEFORE INSERT ON m1_kb_pub.chunks FOR EACH ROW
BEGIN
  DECLARE v_match INT DEFAULT 0;
  IF SUBSTRING_INDEX(USER(), '@', 1) <> 'm1_release' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: publication only through m1_ctl.release_batch';
  END IF;
  SELECT COUNT(*) INTO v_match FROM m1_kb_q.chunks q
   WHERE q.batch_id = NEW.batch_id AND q.chunk_no = NEW.chunk_no
     AND HEX(q.doc_key) = HEX(NEW.doc_key) AND HEX(q.content) = HEX(NEW.content)
     AND HEX(q.embedding) = HEX(NEW.embedding)
  FOR SHARE;
  IF v_match <> 1 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: published row is not a sealed quarantine row';
  END IF;
END//

CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_kb_pub.chunks_bu BEFORE UPDATE ON m1_kb_pub.chunks FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: published chunks are immutable'//

CREATE DEFINER = 'm1_gate_def'@'%' TRIGGER m1_kb_pub.chunks_bd BEFORE DELETE ON m1_kb_pub.chunks FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: published chunks are immutable'//

-- One transaction: lock the seal, check the latest verification and approval,
-- recompute the content and observation hashes, copy, and check the copy.
CREATE DEFINER = 'm1_gate_def'@'%' PROCEDURE m1_ctl.release_batch(IN p_batch BIGINT UNSIGNED)
  MODIFIES SQL DATA SQL SECURITY DEFINER
BEGIN
  DECLARE v_sealed CHAR(64) DEFAULT NULL;
  DECLARE v_count INT UNSIGNED DEFAULT 0;
  DECLARE v_builder VARCHAR(288) DEFAULT NULL;
  DECLARE v_code CHAR(64) DEFAULT NULL;
  DECLARE v_ver BIGINT UNSIGNED DEFAULT NULL;
  DECLARE v_verdict VARCHAR(12) DEFAULT NULL;
  DECLARE v_vhash CHAR(64) DEFAULT NULL;
  DECLARE v_vobs CHAR(64) DEFAULT NULL;
  DECLARE v_vcode CHAR(64) DEFAULT NULL;
  DECLARE v_verifier VARCHAR(288) DEFAULT NULL;
  DECLARE v_appr BIGINT UNSIGNED DEFAULT NULL;
  DECLARE v_appr_ver BIGINT UNSIGNED DEFAULT NULL;
  DECLARE v_decision VARCHAR(8) DEFAULT NULL;
  DECLARE v_ahash CHAR(64) DEFAULT NULL;
  DECLARE v_approver VARCHAR(288) DEFAULT NULL;
  DECLARE v_now CHAR(64);
  DECLARE v_now_count INT UNSIGNED;
  DECLARE v_obs CHAR(64);
  DECLARE EXIT HANDLER FOR SQLEXCEPTION
  BEGIN
    ROLLBACK;
    RESIGNAL;
  END;

  IF SUBSTRING_INDEX(USER(), '@', 1) <> 'm1_release' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: only m1_release may release';
  END IF;
  IF NOT m1_ctl.identity_preconditions_ok() THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: identity preconditions failed (anonymous account or proxy mapping)';
  END IF;

  START TRANSACTION;
  SELECT s.sealed_hash, s.row_count, b.builder, b.code_hash INTO v_sealed, v_count, v_builder, v_code
    FROM m1_ctl.seals s JOIN m1_kb_q.batches b ON b.batch_id = s.batch_id
   WHERE s.batch_id = p_batch FOR UPDATE;
  IF v_sealed IS NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: batch is not sealed';
  END IF;
  IF EXISTS (SELECT 1 FROM m1_ctl.releases WHERE batch_id = p_batch FOR SHARE) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: batch already released';
  END IF;

  SELECT verification_id, verdict, content_hash, obs_hash, pipeline_code_hash, verified_by
    INTO v_ver, v_verdict, v_vhash, v_vobs, v_vcode, v_verifier
    FROM m1_ctl.verifications WHERE batch_id = p_batch
   ORDER BY verification_id DESC LIMIT 1 FOR SHARE;
  IF v_ver IS NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: batch has no verification';
  END IF;
  IF v_verdict <> 'PASS' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: latest verification is not PASS';
  END IF;
  IF SUBSTRING_INDEX(v_verifier, '@', 1) <> 'm1_verifier' OR v_vcode <> v_code THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: verification record is not valid for this batch';
  END IF;

  SELECT approval_id, verification_id, decision, content_hash, approved_by
    INTO v_appr, v_appr_ver, v_decision, v_ahash, v_approver
    FROM m1_ctl.approvals WHERE batch_id = p_batch
   ORDER BY approval_id DESC LIMIT 1 FOR SHARE;
  IF v_appr IS NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: batch has no human approval';
  END IF;
  IF v_decision <> 'APPROVE' OR v_appr_ver <> v_ver OR SUBSTRING_INDEX(v_approver, '@', 1) <> 'm1_approver' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: latest approval does not approve the latest verification';
  END IF;

  SET v_now = m1_ctl.batch_hash(p_batch);
  SELECT COUNT(*) INTO v_now_count FROM m1_kb_q.chunks WHERE batch_id = p_batch FOR SHARE;
  IF v_now <> v_sealed OR v_now <> v_vhash OR v_now <> v_ahash OR v_now_count <> v_count THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: quarantined content differs from the sealed, verified and approved content';
  END IF;
  SET v_obs = m1_ctl.observation_state_hash();
  IF v_obs <> v_vobs THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: observation state changed since the verification';
  END IF;

  INSERT INTO m1_kb_pub.chunks (batch_id, chunk_no, doc_key, content, embedding)
    SELECT batch_id, chunk_no, doc_key, content, embedding
      FROM m1_kb_q.chunks WHERE batch_id = p_batch ORDER BY chunk_no;
  IF m1_ctl.pub_hash(p_batch) <> v_sealed
     OR (SELECT COUNT(*) FROM m1_kb_pub.chunks WHERE batch_id = p_batch) <> v_count THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'M1 gate: published copy differs from the sealed content';
  END IF;
  INSERT INTO m1_ctl.releases (batch_id, verification_id, approval_id, content_hash, obs_hash, row_count)
    VALUES (p_batch, v_ver, v_appr, v_sealed, v_obs, v_count);
  COMMIT;
END//

DELIMITER ;
