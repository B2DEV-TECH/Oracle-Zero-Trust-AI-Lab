-- M1 grants. Run as the lab administrator after 10_core.sql and 20_gate.sql,
-- once the accounts exist (the Python setup creates them with generated
-- passwords). Every account is separate: builder, verifier, approver and
-- release never share credentials, and the agent can only read.

-- ---------------------------------------------------------------------------
-- Gate definer: locked, cannot log in. Owns every trigger and routine.
-- ---------------------------------------------------------------------------
GRANT SELECT, LOCK TABLES, TRIGGER ON m1_kb_q.*   TO 'm1_gate_def'@'%';
GRANT SELECT, LOCK TABLES, TRIGGER ON m1_ctl.*    TO 'm1_gate_def'@'%';
GRANT SELECT, LOCK TABLES, TRIGGER ON m1_kb_pub.* TO 'm1_gate_def'@'%';
GRANT EXECUTE ON m1_ctl.* TO 'm1_gate_def'@'%';
GRANT INSERT ON m1_kb_pub.chunks TO 'm1_gate_def'@'%';
GRANT INSERT ON m1_ctl.releases  TO 'm1_gate_def'@'%';
-- Columns the BEFORE triggers assign through NEW.
GRANT UPDATE (builder, obs_hash, created_at) ON m1_kb_q.batches TO 'm1_gate_def'@'%';
GRANT UPDATE (sealed_hash, row_count, obs_hash, sealed_by, sealed_at) ON m1_ctl.seals TO 'm1_gate_def'@'%';
GRANT UPDATE (verified_by, verified_at) ON m1_ctl.verifications TO 'm1_gate_def'@'%';
GRANT UPDATE (approved_by, approved_at) ON m1_ctl.approvals TO 'm1_gate_def'@'%';
GRANT UPDATE (released_by, released_at) ON m1_ctl.releases TO 'm1_gate_def'@'%';
-- Metadata read by observation_state_hash() and identity_preconditions_ok().
-- REFERENCES gives information_schema.COLUMNS visibility without row access.
GRANT REFERENCES ON m1_src.* TO 'm1_gate_def'@'%';
GRANT SELECT ON mysql.column_masking_policies TO 'm1_gate_def'@'%';
GRANT SELECT ON mysql.role_edges     TO 'm1_gate_def'@'%';
GRANT SELECT ON mysql.default_roles  TO 'm1_gate_def'@'%';
GRANT SELECT ON mysql.db             TO 'm1_gate_def'@'%';
GRANT SELECT ON mysql.tables_priv    TO 'm1_gate_def'@'%';
GRANT SELECT ON mysql.columns_priv   TO 'm1_gate_def'@'%';
GRANT SELECT ON mysql.procs_priv     TO 'm1_gate_def'@'%';
GRANT SELECT ON mysql.global_grants  TO 'm1_gate_def'@'%';
GRANT SELECT ON mysql.proxies_priv   TO 'm1_gate_def'@'%';
-- Privilege columns only: never the password hash.
GRANT SELECT (Host, User, Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv,
              Alter_priv, Index_priv, Super_priv, Grant_priv, Trigger_priv, Execute_priv,
              Create_routine_priv, Alter_routine_priv, Create_view_priv, Show_view_priv,
              Create_user_priv, Lock_tables_priv, account_locked)
  ON mysql.user TO 'm1_gate_def'@'%';

-- ---------------------------------------------------------------------------
-- Builders. Same write surface: open a batch, add chunks, seal. The
-- privileged builder holds the unmasking role as a default role; the
-- restricted builder reads exactly what the agent reads.
-- ---------------------------------------------------------------------------
GRANT 'm1_r_unmask' TO 'm1_builder_p'@'%';
SET DEFAULT ROLE 'm1_r_unmask' TO 'm1_builder_p'@'%';
GRANT SELECT ON m1_src.* TO 'm1_builder_p'@'%', 'm1_builder_r'@'%';
GRANT INSERT ON m1_kb_q.batches TO 'm1_builder_p'@'%', 'm1_builder_r'@'%';
GRANT INSERT ON m1_kb_q.chunks  TO 'm1_builder_p'@'%', 'm1_builder_r'@'%';
GRANT INSERT ON m1_ctl.seals    TO 'm1_builder_p'@'%', 'm1_builder_r'@'%';
-- Batch ids come back through LAST_INSERT_ID(); SELECT on the batch table lets
-- the builder confirm its own batch row.
GRANT SELECT ON m1_kb_q.batches TO 'm1_builder_p'@'%', 'm1_builder_r'@'%';
-- Internal outputs of privileged processing (experiment P2).
GRANT SELECT, INSERT ON m1_ops.* TO 'm1_builder_p'@'%';

-- ---------------------------------------------------------------------------
-- Verifier: reads quarantine and control data, records verdicts.
-- ---------------------------------------------------------------------------
GRANT SELECT ON m1_kb_q.*   TO 'm1_verifier'@'%';
GRANT SELECT ON m1_ctl.*    TO 'm1_verifier'@'%';
GRANT SELECT ON m1_ops.*    TO 'm1_verifier'@'%';
GRANT SELECT ON m1_kb_pub.* TO 'm1_verifier'@'%';
GRANT INSERT ON m1_ctl.verifications TO 'm1_verifier'@'%';
GRANT EXECUTE ON FUNCTION m1_ctl.batch_hash TO 'm1_verifier'@'%';
GRANT EXECUTE ON FUNCTION m1_ctl.pub_hash TO 'm1_verifier'@'%';
GRANT EXECUTE ON FUNCTION m1_ctl.observation_state_hash TO 'm1_verifier'@'%';

-- ---------------------------------------------------------------------------
-- Approver: the human decision, recorded under its own account.
-- ---------------------------------------------------------------------------
GRANT SELECT ON m1_ctl.*  TO 'm1_approver'@'%';
GRANT SELECT ON m1_kb_q.* TO 'm1_approver'@'%';
GRANT INSERT ON m1_ctl.approvals TO 'm1_approver'@'%';
GRANT EXECUTE ON FUNCTION m1_ctl.batch_hash TO 'm1_approver'@'%';

-- ---------------------------------------------------------------------------
-- Release: one procedure and nothing else.
-- ---------------------------------------------------------------------------
GRANT EXECUTE ON PROCEDURE m1_ctl.release_batch TO 'm1_release'@'%';

-- ---------------------------------------------------------------------------
-- Agent: reads the sources through the masks and the published knowledge base.
-- ---------------------------------------------------------------------------
GRANT SELECT ON m1_src.*    TO 'm1_agent'@'%';
GRANT SELECT ON m1_kb_pub.* TO 'm1_agent'@'%';

-- ---------------------------------------------------------------------------
-- World reader: the verifier's view of the true source data, used only to
-- copy it into the shadow instance. Never used by a pipeline.
-- ---------------------------------------------------------------------------
GRANT 'm1_r_unmask' TO 'm1_world'@'%';
SET DEFAULT ROLE 'm1_r_unmask' TO 'm1_world'@'%';
GRANT SELECT ON m1_src.* TO 'm1_world'@'%';
