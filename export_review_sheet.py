"""Export every saved execution to a CSV for human review.

    python export_review_sheet.py                 # real-data runs only
    python export_review_sheet.py --all           # everything in the results store

Writes data/review_sheet.csv (opens in Excel). Each row is one execution: what was asked,
what the agent said, and the gateway's verdict for each check, plus empty columns for a
human reviewer to mark whether they agree. Filling those columns turns the run into a
human-labelled test set, which is the strongest evidence of how accurate the gateway is.
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path

import gateway
import store

ROOT = Path(__file__).parent
OUT = ROOT / "data" / "review_sheet.csv"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="include scenario and live runs, not only real-data runs")
    args = ap.parse_args()
    recs = store.load_all()
    if not args.all:
        recs = [r for r in recs if str(r.get("scenario_set", "")).startswith("real-")]
    fields = ["id", "time", "source", "category", "customer_message", "documents_read", "tools_called", "agent_answer"]
    for d in gateway.DIMENSIONS:
        fields += [f"{d}_verdict", f"{d}_severity", f"{d}_explanation", f"{d}_evidence"]
    fields += ["evaluator_version", "reviewer_agrees_all (Y/N)", "reviewer_notes"]
    with OUT.open("w", encoding="utf-8-sig", newline="") as f:  # utf-8-sig so Excel shows € correctly
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in recs:
            t = r["trace"]
            row = {
                "id": r["id"], "time": r["timestamp"], "source": r.get("scenario_set", "live"),
                "category": r.get("category", ""), "customer_message": t["user_input"][:2000],
                "documents_read": "; ".join(f"{c['source']}: {c['heading']}" for c in t["retrieved"]),
                "tools_called": "; ".join(f"{c['tool']}({c['args']})" for c in t["tool_calls"]),
                "agent_answer": t["output"][:4000],
                "evaluator_version": r.get("evaluator_version", "before 2026-11-06.3"),
                "reviewer_agrees_all (Y/N)": "", "reviewer_notes": "",
            }
            for e in r["evaluations"]:
                d = e["dimension"]
                row[f"{d}_verdict"] = "PASS" if e["passed"] else "FAIL"
                row[f"{d}_severity"] = e["severity"]
                row[f"{d}_explanation"] = e["explanation"]
                row[f"{d}_evidence"] = " | ".join(e["evidence"])
            w.writerow(row)
    print(f"Wrote {len(recs)} executions to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
