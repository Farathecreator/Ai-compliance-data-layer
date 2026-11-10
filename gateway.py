"""Evaluation gateway.

User input -> AI agent -> Evaluation gateway -> Evaluation engines -> Results store -> Dashboard

run() sends one message to the agent, captures the full trace, runs the four
evaluators and saves one structured evaluation record.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import frameworks
import store
from agent import CANARY, CUSTOMERS, SYSTEM_PROMPT, run_agent
from evaluators import hallucination, injection, leakage, quality
from evaluators.common import max_severity
from llm import get_judge, get_llm

# Bumped whenever an evaluator changes, so every saved record says which version scored it
EVALUATOR_VERSION = "2026-11-06.4"

DIMENSIONS = ["hallucination", "injection", "leakage", "quality"]
LABELS = {
    "hallucination": "Hallucination / factuality",
    "injection": "Prompt injection / security",
    "leakage": "Sensitive-data leakage",
    "quality": "Output quality / relevance",
}


def evaluate_trace(trace: dict, judge=None) -> list[dict]:
    return [
        hallucination.evaluate(trace, judge=judge),
        injection.evaluate(trace, canary=CANARY, system_prompt=SYSTEM_PROMPT, judge=judge),
        leakage.evaluate(trace, customers=CUSTOMERS, judge=judge),
        quality.evaluate(trace, judge=judge),
    ]


def run(user_input: str, session_customer: str = "C001", guardrails: bool = False,
        scenario: dict | None = None, provider: str | None = None, use_judge: bool = True,
        timestamp: str | None = None, save: bool = True, injected_context: list[dict] | None = None,
        llm=None, judge=None, privacy_guard: bool = False) -> dict:
    llm = llm or get_llm(provider)
    trace = run_agent(user_input, session_customer=session_customer, guardrails=guardrails, llm=llm,
                      injected_context=injected_context, privacy_guard=privacy_guard)
    if judge is None and use_judge:
        judge = get_judge(provider, agent_llm=llm)
    evaluations = evaluate_trace(trace, judge=judge)
    for e in evaluations:
        e["framework_refs"] = frameworks.refs_for(e)
    failed = [e for e in evaluations if not e["passed"]]
    record = {
        "id": "ex-" + uuid.uuid4().hex[:10],
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scenario_id": scenario.get("id") if scenario else None,
        "category": scenario.get("category", "live") if scenario else "live",
        "expected": scenario.get("expected") if scenario else None,
        "expect_security_finding": scenario.get("expect_security_finding", False) if scenario else False,
        "label_note": scenario.get("label_note") if scenario else None,
        "trace": trace,
        "evaluations": evaluations,
        "overall_pass": not failed,
        "failed_dimensions": [e["dimension"] for e in failed],
        "max_severity": max_severity([e["severity"] for e in evaluations]),
        "evaluator_mode": "heuristic + llm_judge" if judge else "heuristic",
        "evaluator_version": EVALUATOR_VERSION,
        "agent_model": getattr(llm, "model", llm.name),
        "judge_model": getattr(judge, "model", None) if judge else None,
    }
    if save:
        store.save(record)
    return record


if __name__ == "__main__":
    import json
    import sys
    rec = run(" ".join(sys.argv[1:]) or "What is the monthly fee?", save=False)
    print(json.dumps({k: rec[k] for k in ("overall_pass", "failed_dimensions", "max_severity")}, indent=2))
    for e in rec["evaluations"]:
        print(f"- {e['dimension']:13} pass={e['passed']!s:5} sev={e['severity']:8} {e['explanation']}")
        for ev in e["evidence"]:
            print(f"      evidence: {ev}")
