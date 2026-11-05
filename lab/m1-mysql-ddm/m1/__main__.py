"""Command line: python -m m1 <command>. See README.md."""

from __future__ import annotations

import argparse
import json

from .config import INSTANCES, LAB


def main() -> None:
    p = argparse.ArgumentParser(prog="m1")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("deploy", help="deploy M1 on one instance")
    d.add_argument("--instance", choices=INSTANCES, required=True)
    d.add_argument("--core-only", action="store_true", help="without the gate (shows the negatives failing)")
    t = sub.add_parser("teardown", help="remove M1 from one instance")
    t.add_argument("--instance", choices=INSTANCES, required=True)
    sub.add_parser("negatives", help="gate negative tests on the lab instance")
    b = sub.add_parser("build", help="build one batch in the lab quarantine and seal it")
    b.add_argument("--pipeline", required=True)
    b.add_argument("--builder", choices=["m1_builder_p", "m1_builder_r"], required=True)
    v = sub.add_parser("verify", help="verify one sealed batch and record the verdict")
    v.add_argument("--batch", type=int, required=True)
    v.add_argument("--no-record", action="store_true", help="write the evidence file only")
    x = sub.add_parser("experiments", help="C0, P0, P0b, P1, P2, PND and AA on the lab instance")
    x.add_argument("--only", nargs="*", help="experiment ids")
    c = sub.add_parser("clearance-negatives", help="identity and policy perturbations on both instances")
    c.add_argument("--only", nargs="*", help="scenario ids")
    g = sub.add_parser("agent", help="semantic search over the released knowledge base, as the agent")
    g.add_argument("--question", required=True)
    g.add_argument("-k", type=int, default=5)
    g.add_argument("--batch", type=int, help="a released batch (default: the latest)")
    a = p.parse_args()

    if a.cmd == "deploy":
        from . import setup
        setup.deploy(a.instance, with_gate=not a.core_only)
    elif a.cmd == "teardown":
        from . import setup
        setup.teardown(a.instance)
    elif a.cmd == "negatives":
        from . import negatives
        negatives.run_all()
    elif a.cmd == "build":
        from . import build
        print(json.dumps(build.build_lab(a.pipeline, a.builder), indent=2, default=str))
    elif a.cmd == "verify":
        from . import verifier
        print(json.dumps(verifier.verify(a.batch, record=not a.no_record), indent=2, default=str))
    elif a.cmd == "experiments":
        from . import experiments
        experiments.run_all(a.only)
    elif a.cmd == "clearance-negatives":
        from . import clearance_negatives
        clearance_negatives.run_all(a.only)
    elif a.cmd == "agent":
        from . import agent
        print(json.dumps(agent.search(a.question, a.k, a.batch), indent=2))


if __name__ == "__main__":
    main()
