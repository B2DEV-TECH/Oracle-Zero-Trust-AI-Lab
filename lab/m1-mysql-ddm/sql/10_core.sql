-- M1 core: schemas, the unmasking role, masking policies and the synthetic
-- source tables. Run as the lab administrator (deployer) on a disposable
-- MySQL Enterprise instance with component_object_policy installed.
-- Accounts are created by the Python setup (generated passwords); grants are
-- in 30_grants.sql.

CREATE DATABASE m1_src;     -- source data the agent may read, through the masks
CREATE DATABASE m1_kb_q;    -- quarantine: batches built by a pipeline, not yet published
CREATE DATABASE m1_kb_pub;  -- published knowledge base the agent reads
CREATE DATABASE m1_ctl;     -- seals, verifications, approvals, releases and the gate routines
CREATE DATABASE m1_ops;     -- internal outputs of privileged processing, never readable by the agent

-- The role holds no object privilege. It is only the gatekeeper marker the
-- policies test with CURRENT_ROLE_IN.
CREATE ROLE 'm1_r_unmask';

CREATE MASKING POLICY m1_p_tax(v)
  CASE WHEN CURRENT_ROLE_IN('m1_r_unmask') THEN v ELSE CONCAT('***-***-', RIGHT(v, 4)) END;
CREATE MASKING POLICY m1_p_note(v)
  CASE WHEN CURRENT_ROLE_IN('m1_r_unmask') THEN v ELSE '[RESTRICTED]' END;
CREATE MASKING POLICY m1_p_risk(v)
  CASE WHEN CURRENT_ROLE_IN('m1_r_unmask') THEN v ELSE 0 END;

CREATE TABLE m1_src.suppliers (
  supplier_id     INT          NOT NULL PRIMARY KEY,
  supplier_name   VARCHAR(80)  NOT NULL,
  region          VARCHAR(10)  NOT NULL,
  category        VARCHAR(40)  NOT NULL,
  capabilities    VARCHAR(300) NOT NULL,
  tax_id          VARCHAR(24)  NOT NULL MASKING POLICY m1_p_tax,   -- partial mask, last 4 visible
  compliance_note VARCHAR(300) NULL     MASKING POLICY m1_p_note,  -- constant mask
  risk_score      INT          NOT NULL MASKING POLICY m1_p_risk,  -- integer mask (0)
  CONSTRAINT suppliers_region_ck CHECK (region IN ('NORTH', 'SOUTH', 'EAST'))
) ENGINE = InnoDB;

CREATE TABLE m1_src.invoices (
  invoice_id  INT           NOT NULL PRIMARY KEY,
  supplier_id INT           NOT NULL,
  amount      DECIMAL(12,2) NOT NULL,
  issue_date  DATE          NOT NULL,
  KEY invoices_supplier_ix (supplier_id)
) ENGINE = InnoDB;

-- Internal review queue written by privileged processing (experiment P2).
CREATE TABLE m1_ops.review_queue (
  run_tag         BIGINT UNSIGNED NOT NULL,
  supplier_id     INT          NOT NULL,
  tax_id          VARCHAR(24)  NOT NULL,
  compliance_note VARCHAR(300) NULL,
  risk_score      INT          NOT NULL,
  priority        VARCHAR(10)  NOT NULL,
  PRIMARY KEY (run_tag, supplier_id)
) ENGINE = InnoDB;
