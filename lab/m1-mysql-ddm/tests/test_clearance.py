"""Clearance rules on synthetic snapshots shaped like the lab deployment.
The same perturbations are applied to a live instance by the clearance
negatives (m1/clearance_negatives.py)."""

import copy
import unittest

from m1 import clearance

R, P = "m1_builder_r@%", "m1_builder_p@%"
QUARANTINE = ["table|m1_kb_q.batches|INSERT", "table|m1_kb_q.batches|SELECT", "table|m1_kb_q.chunks|INSERT",
              "table|m1_ctl.seals|INSERT"]


def base():
    trig = lambda table, name: {"kind": "trigger", "object": table, "name": name, "definer": "m1_gate_def@%",
                                "security": "DEFINER"}
    return {
        "globals": {"mandatory_roles": [], "activate_all_roles_on_login": "0", "activate_mandatory_roles": "1"},
        "anonymous_accounts": [],
        "edges": [["m1_r_unmask@%", P], ["m1_r_unmask@%", "m1_world@%"]],
        "defaults": {P: ["m1_r_unmask@%"], "m1_world@%": ["m1_r_unmask@%"]},
        "accounts": {
            "m1_agent@%": {"privileges": ["db|m1_kb_pub|SELECT", "db|m1_src|SELECT"], "proxies": []},
            R: {"privileges": ["db|m1_src|SELECT"] + QUARANTINE, "proxies": []},
            P: {"privileges": ["db|m1_ops|INSERT", "db|m1_ops|SELECT", "db|m1_src|SELECT"] + QUARANTINE,
                "proxies": []},
            "m1_world@%": {"privileges": ["db|m1_src|SELECT"], "proxies": []},
            "m1_gate_def@%": {"privileges": ["db|m1_ctl|EXECUTE", "db|m1_ctl|SELECT", "db|m1_src|REFERENCES"],
                              "proxies": []},
            "m1_r_unmask@%": {"privileges": [], "proxies": []},
        },
        "objects": [trig("m1_kb_q.batches", "batches_bi"), trig("m1_kb_q.chunks", "chunks_bi"),
                    trig("m1_ctl.seals", "seals_bi"),
                    {"kind": "view", "object": "g1_views.v", "definer": "g1_owner@%", "security": "DEFINER"}],
        "tables": {"suppliers": "DDL", "invoices": "DDL"},
        "bindings": dict(clearance.CONTRACT_BINDINGS),
        "policies": copy.deepcopy(clearance.CONTRACT_POLICIES),
    }


def live(role="NONE", views_equal=True, user=R):
    return {"builder": {"login": True, "current_user": user, "current_role": role},
            "agent": {"login": True, "current_user": "m1_agent@%", "current_role": "NONE"},
            "views_equal": views_equal}


def failing(snap, builder=R, facts=None):
    ev = clearance.evaluate(snap, builder, facts or live(user=builder))
    return sorted(c for c, r in ev["checks"].items() if not r["ok"]), ev


def grant(snap, account, *tokens):
    snap["accounts"][account]["privileges"] = sorted(set(snap["accounts"][account]["privileges"]) | set(tokens))
    return snap


class ClearanceTest(unittest.TestCase):
    def test_baseline_restricted_builder_is_reader_equivalent(self):
        bad, ev = failing(base())
        self.assertEqual(bad, [])
        self.assertTrue(ev["reader_equivalent"] and ev["contract_ok"] and ev["write_ok"])

    def test_baseline_privileged_builder_is_not(self):
        bad, ev = failing(base(), P, live(role="`m1_r_unmask`@`%`", views_equal=False, user=P))
        self.assertEqual(bad, ["C1", "C4", "C5", "C6"])
        self.assertTrue(ev["contract_ok"] and ev["write_ok"])

    def test_latent_role(self):
        s = base()
        s["edges"].append(["m1_r_unmask@%", R])
        bad, ev = failing(s)
        self.assertEqual(bad, ["C1"])
        self.assertEqual(ev["checks"]["C1"]["latent"], ["m1_r_unmask@%"])

    def test_nested_role(self):
        s = base()
        s["accounts"]["m1_r_x@%"] = {"privileges": [], "proxies": []}
        s["edges"] += [["m1_r_x@%", R], ["m1_r_unmask@%", "m1_r_x@%"]]
        self.assertIn("m1_r_unmask@%", failing(s)[1]["checks"]["C1"]["closure"])

    def test_role_activation_settings(self):
        s = base()
        s["globals"]["activate_all_roles_on_login"] = "1"
        self.assertEqual(failing(s)[0], ["C2"])
        s = base()
        s["globals"]["mandatory_roles"] = ["m1_r_unmask@%"]
        # the agent would hold the unmasking role too, and the gate definer is no longer trusted
        self.assertEqual(failing(s)[0], ["C2", "C3", "C7"])

    def test_mandatory_role_activation(self):
        # with no mandatory role, activate_mandatory_roles has no effect either way
        s = base()
        s["globals"]["activate_mandatory_roles"] = "0"
        bad, ev = failing(s)
        self.assertEqual(bad, [])
        self.assertEqual(ev["checks"]["C2"]["activate_mandatory_roles"], "0")
        # switched off, a mandatory unmasking role is still granted to every account
        # (SET ROLE ALL activates it), so nothing is relaxed
        s["globals"]["mandatory_roles"] = ["m1_r_unmask@%"]
        self.assertEqual(failing(s)[0], ["C2", "C3", "C7"])
        self.assertIn("m1_r_unmask@%", clearance.closure(s, clearance.AGENT))

    def test_definer_view_over_the_source(self):
        s = base()
        s["objects"].append({"kind": "view", "object": "m1_src.v_all", "definer": "m1_world@%",
                             "security": "DEFINER"})
        bad, ev = failing(s)
        self.assertEqual(bad, ["C3"])
        self.assertEqual(ev["checks"]["C3"]["objects"][0]["object"], "m1_src.v_all")

    def test_invoker_view_is_not_flagged(self):
        s = base()
        s["objects"].append({"kind": "view", "object": "m1_src.v_all", "definer": "m1_world@%",
                             "security": "INVOKER"})
        self.assertEqual(failing(s)[0], [])

    def test_gate_definer_is_trusted_only_while_it_cannot_read_the_source(self):
        s = grant(base(), "m1_gate_def@%", "db|m1_src|SELECT")
        bad, ev = failing(s)
        self.assertEqual(bad, ["C3"])
        self.assertTrue(ev["checks"]["C3"]["gate_definer_reads_source"])

    def test_identity_ambiguity(self):
        s = base()
        s["anonymous_accounts"] = ["@localhost"]
        self.assertEqual(failing(s)[0], ["C4"])
        s = base()
        s["accounts"]["m1_builder_r@localhost"] = {"privileges": [], "proxies": []}
        self.assertEqual(failing(s)[0], ["C4"])
        s = base()
        s["accounts"][R]["proxies"] = ["m1_builder_r@%->m1_world@%"]
        self.assertEqual(failing(s)[0], ["C4"])
        self.assertEqual(failing(base(), facts=live(role="`m1_r_unmask`@`%`"))[0], ["C4"])

    def test_privileges(self):
        # global SELECT also reaches the unrelated DEFINER view in g1_views
        self.assertEqual(failing(grant(base(), R, "global|*|SELECT"))[0], ["C3", "C5"])
        self.assertEqual(failing(grant(base(), R, "dynamic|*|MANAGE_DATA_MASKING_POLICY"))[0], ["C5", "W"])
        self.assertEqual(failing(grant(base(), R, "db|m1_ops|SELECT"))[0], ["C5"])
        self.assertEqual(failing(grant(base(), R, "table|m1_src.suppliers|ALTER"))[0], ["C5", "W"])
        self.assertEqual(failing(grant(base(), R, "column|m1_src.suppliers.risk_score|UPDATE"))[0], ["C5", "W"])

    def test_write_surface(self):
        self.assertEqual(failing(grant(base(), R, "table|m1_kb_pub.chunks|INSERT"))[0], ["W"])
        self.assertEqual(failing(grant(base(), R, "db|m1_src|INSERT"))[0], ["W"])
        self.assertEqual(failing(grant(base(), R, "routine|m1_ctl.release_batch|EXECUTE"))[0], ["C5", "W"])
        s = grant(base(), "m1_agent@%", "db|m1_ops|SELECT")
        self.assertEqual(failing(s, P, live(role="`m1_r_unmask`@`%`", views_equal=False, user=P))[1]["write_ok"],
                         False)
        # the privileged builder is judged on twins, so W must also see non-data privileges
        privileged = live(role="`m1_r_unmask`@`%`", views_equal=False, user=P)
        for token in ("dynamic|*|MANAGE_DATA_MASKING_POLICY", "db|m1_src|TRIGGER", "global|*|CREATE_USER"):
            self.assertFalse(failing(grant(base(), P, token), P, privileged)[1]["write_ok"], token)

    def test_observed_view_difference(self):
        self.assertEqual(failing(base(), facts=live(views_equal=False))[0], ["C6"])

    def test_contract(self):
        s = base()
        # the server accepts exactly one WHEN with one gatekeeper, so a widened policy swaps the gatekeeper
        s["policies"]["m1_p_note"][0] = s["policies"]["m1_p_note"][0].replace(
            "current_role_in(_utf8mb4'm1_r_unmask')", "current_user_in(_utf8mb4'm1_builder_r')")
        self.assertEqual(failing(s)[0], ["C7"])
        s = base()
        s["bindings"]["suppliers.tax_id"], s["bindings"]["suppliers.compliance_note"] = "m1_p_note", "m1_p_tax"
        self.assertEqual(failing(s)[0], ["C7"])
        s = base()
        del s["bindings"]["suppliers.risk_score"]
        self.assertEqual(failing(s)[0], ["C7"])

    def test_compare(self):
        accounts = [R, clearance.AGENT, "m1_world@%"]
        self.assertEqual(clearance.compare(base(), base(), accounts), [])
        other = base()
        other["policies"]["m1_p_risk"][0] = "x"
        self.assertEqual(clearance.compare(base(), other, accounts), ["policies"])
        other = base()
        other["globals"]["activate_mandatory_roles"] = "0"
        self.assertEqual(clearance.compare(base(), other, accounts), ["globals"])
        self.assertEqual(clearance.compare(base(), grant(base(), R, "db|m1_ops|SELECT"), accounts),
                         [f"{R}:privileges"])


if __name__ == "__main__":
    unittest.main()
