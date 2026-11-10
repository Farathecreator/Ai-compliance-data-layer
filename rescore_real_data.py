"""Re-score saved real-data runs with the current evaluators, without asking the agent again.

    python rescore_real_data.py

Use this after an evaluator fix: the agent's saved answers are checked again (the model is only
called for the judge steps), and data/real_data_report.json is rebuilt.
"""
from __future__ import annotations

import json

import frameworks
import gateway
import store
from evaluators.common import max_severity
import argparse

from llm import get_judge, get_llm
from run_real_data import REPORT, print_report, real_records, run_tag_of, summarise


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default=None, help="which run to re-score (default: the most recent run)")
    args = ap.parse_args()
    llm = get_llm()
    judge = get_judge(agent_llm=llm)
    allrecs = real_records()
    if not allrecs:
        raise SystemExit("No real-data runs saved yet.")
    tag = args.tag or run_tag_of(max(allrecs, key=lambda r: r["timestamp"]))
    recs = [r for r in allrecs if run_tag_of(r) == tag]
    print(f"Re-scoring {len(recs)} executions of run '{tag}' with judge {getattr(judge, 'model', None)}...")
    for i, r in enumerate(recs, 1):
        evals = gateway.evaluate_trace(r["trace"], judge=judge)
        for e in evals:
            e["framework_refs"] = frameworks.refs_for(e)
        r["evaluations"] = evals
        r["failed_dimensions"] = [e["dimension"] for e in evals if not e["passed"]]
        r["overall_pass"] = not r["failed_dimensions"]
        r["max_severity"] = max_severity([e["severity"] for e in evals])
        r["judge_followed"] = None  # re-judge BIPIA too
        r["evaluator_version"] = gateway.EVALUATOR_VERSION
        store.save(r)
        if i % 20 == 0:
            print(f"  {i}/{len(recs)}")
    providers = {r["trace"]["provider"] for r in recs}
    report = {"run_tag": tag, "provider": ", ".join(sorted(providers)), "policy_set": "aib",
              "judge_model": getattr(judge, "model", None), "evaluator_version": gateway.EVALUATOR_VERSION,
              "rescored": True}
    report.update(summarise([r for r in real_records() if run_tag_of(r) == tag], judge))
    REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print_report(report)


if __name__ == "__main__":
    main()
