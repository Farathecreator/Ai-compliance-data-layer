"""Run the test scenarios and measure how accurate the evaluators are.

    python run_scenarios.py                      # development + held-out sets
    python run_scenarios.py --set holdout        # held-out set only
    python run_scenarios.py --reset              # clear the results store first

Each scenario has a hand-written expected result per dimension ("pass", "fail"
or "not_scored"). The evaluators never see these labels. This script compares
the evaluator verdicts with the labels and reports precision and recall.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import agent
import gateway
import store

# The hand-labelled scenarios were written against the fictional document set
agent.set_policies("fictional")

ROOT = Path(__file__).parent
SETS = {"dev": ROOT / "scenarios.json", "holdout": ROOT / "scenarios_holdout.json"}


def score(records: list[dict]) -> dict:
    out = {}
    for dim in gateway.DIMENSIONS:
        tp = fp = fn = tn = 0
        misses = []
        for r in records:
            exp = (r.get("expected") or {}).get(dim)
            if exp in (None, "not_scored"):
                continue
            pred_fail = dim in r["failed_dimensions"]
            exp_fail = exp == "fail"
            if pred_fail and exp_fail:
                tp += 1
            elif pred_fail and not exp_fail:
                fp += 1
                misses.append(f"{r['scenario_id']}: false alarm")
            elif exp_fail:
                fn += 1
                misses.append(f"{r['scenario_id']}: missed")
            else:
                tn += 1
        n = tp + fp + fn + tn
        out[dim] = {
            "true_positives": tp, "false_positives": fp, "false_negatives": fn, "true_negatives": tn,
            "precision": round(tp / (tp + fp), 2) if tp + fp else None,
            "recall": round(tp / (tp + fn), 2) if tp + fn else None,
            "accuracy": round((tp + tn) / n, 2) if n else None,
            "errors": misses,
        }
    sec = [r for r in records if r.get("expect_security_finding")]
    found = [r for r in sec if any(e["severity"] != "none" for e in r["evaluations"]
                                   if e["dimension"] in ("injection", "leakage"))]
    out["security_findings"] = {
        "scenarios": len(sec), "with_finding": len(found),
        "rate": round(len(found) / len(sec), 2) if sec else None,
        "missed": [r["scenario_id"] for r in sec if r not in found],
    }
    return out


def run_set(name: str, base_time: datetime | None = None, spread_hours: float = 0) -> list[dict]:
    scenarios = json.loads(SETS[name].read_text(encoding="utf-8"))
    records = []
    for i, s in enumerate(scenarios):
        ts = None
        if base_time is not None:
            ts = (base_time + timedelta(hours=spread_hours * i / max(len(scenarios) - 1, 1))).isoformat(timespec="seconds")
        s = dict(s, category=f"{s['category']}" )
        rec = gateway.run(s["input"], guardrails=s.get("guardrails", False), scenario=s, timestamp=ts)
        rec["scenario_set"] = name
        rec["simulated_timestamp"] = base_time is not None
        store.save(rec)
        records.append(rec)
    return records


def print_report(title: str, rep: dict) -> None:
    print(f"\n=== {title} ===")
    print(f"{'dimension':14} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3} {'precision':>9} {'recall':>7} {'accuracy':>8}")
    for dim in gateway.DIMENSIONS:
        m = rep[dim]
        f = lambda v: "-" if v is None else f"{v:.2f}"
        print(f"{dim:14} {m['true_positives']:>3} {m['false_positives']:>3} {m['false_negatives']:>3} {m['true_negatives']:>3} "
              f"{f(m['precision']):>9} {f(m['recall']):>7} {f(m['accuracy']):>8}   {'; '.join(m['errors'])}")
    s = rep["security_findings"]
    print(f"security scenarios with an identifiable finding: {s['with_finding']}/{s['scenarios']}"
          + (f"  missed: {', '.join(s['missed'])}" if s["missed"] else ""))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", choices=["dev", "holdout", "all"], default="all")
    ap.add_argument("--reset", action="store_true", help="clear the results store first")
    ap.add_argument("--spread-days", type=float, default=0,
                    help="spread run timestamps over the past N days (demo trend view only)")
    args = ap.parse_args()
    if args.reset:
        store.clear()
    names = ["dev", "holdout"] if args.set == "all" else [args.set]
    report = {}
    for k, name in enumerate(names):
        base = None
        if args.spread_days:
            base = datetime.now(timezone.utc) - timedelta(days=args.spread_days) + timedelta(days=args.spread_days * k / len(names))
        recs = run_set(name, base, spread_hours=24 * args.spread_days / len(names))
        report[name] = score(recs)
        print_report(f"{name} set ({len(recs)} scenarios)", report[name])
    (ROOT / "data" / "accuracy_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("\nSaved data/accuracy_report.json")


if __name__ == "__main__":
    main()
