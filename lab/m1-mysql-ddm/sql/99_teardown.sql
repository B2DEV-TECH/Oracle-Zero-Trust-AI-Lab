-- M1 teardown. Run as the lab administrator on the disposable lab instance.
-- Removes every M1 schema, policy, role and account. Global role settings are
-- reset to the server defaults the experiments assume.
SET GLOBAL activate_all_roles_on_login = OFF;
SET GLOBAL mandatory_roles = '';
DROP DATABASE IF EXISTS m1_kb_pub;
DROP DATABASE IF EXISTS m1_ctl;
DROP DATABASE IF EXISTS m1_kb_q;
DROP DATABASE IF EXISTS m1_ops;
DROP DATABASE IF EXISTS m1_src;
DROP MASKING POLICY IF EXISTS m1_p_tax;
DROP MASKING POLICY IF EXISTS m1_p_note;
DROP MASKING POLICY IF EXISTS m1_p_risk;
DROP USER IF EXISTS 'm1_gate_def'@'%', 'm1_builder_p'@'%', 'm1_builder_r'@'%', 'm1_verifier'@'%',
                    'm1_approver'@'%', 'm1_release'@'%', 'm1_agent'@'%', 'm1_world'@'%';
DROP ROLE IF EXISTS 'm1_r_unmask';
