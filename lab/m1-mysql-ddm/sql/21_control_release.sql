-- Phase A control only (python -m m1 deploy --control): the release procedure
-- without the gate's checks. It is installed instead of the release procedure
-- of 20_gate.sql, on a deployment that keeps that file's tables and functions
-- but none of its triggers (see m1/setup.py, control_gate_sql).
--
-- Same name, parameter, definer, security and transaction as the gated
-- procedure, and the same grant (30_grants.sql): only m1_release can call it.
-- It copies the quarantined rows of the batch to the published table and
-- records the release with the latest verification and approval ids (0 when
-- there is none), whatever they say. Nothing is checked.

DELIMITER //

CREATE DEFINER = 'm1_gate_def'@'%' PROCEDURE m1_ctl.release_batch(IN p_batch BIGINT UNSIGNED)
  MODIFIES SQL DATA SQL SECURITY DEFINER
BEGIN
  DECLARE EXIT HANDLER FOR SQLEXCEPTION
  BEGIN
    ROLLBACK;
    RESIGNAL;
  END;

  START TRANSACTION;
  INSERT INTO m1_kb_pub.chunks (batch_id, chunk_no, doc_key, content, embedding)
    SELECT batch_id, chunk_no, doc_key, content, embedding
      FROM m1_kb_q.chunks WHERE batch_id = p_batch ORDER BY chunk_no;
  INSERT INTO m1_ctl.releases (batch_id, verification_id, approval_id, content_hash, obs_hash, row_count)
    VALUES (p_batch,
            IFNULL((SELECT MAX(verification_id) FROM m1_ctl.verifications WHERE batch_id = p_batch), 0),
            IFNULL((SELECT MAX(approval_id) FROM m1_ctl.approvals WHERE batch_id = p_batch), 0),
            m1_ctl.batch_hash(p_batch), m1_ctl.observation_state_hash(),
            (SELECT COUNT(*) FROM m1_kb_q.chunks WHERE batch_id = p_batch));
  COMMIT;
END//

DELIMITER ;
