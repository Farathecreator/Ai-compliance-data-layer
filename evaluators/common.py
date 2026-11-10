"""Shared helpers for the evaluators."""
from __future__ import annotations

import json
import re

SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]

REFUSAL = re.compile(
    r"(i (?:do not|don't) have (?:the |that |enough |any |this )?(?:information|details|data)"
    r"|i (?:can't|cannot|can not) (?:help|share|answer|assist|provide)"
    r"|i can only (?:help|show)|i'm not able to|i am not able to|i'm unable to|i am unable to"
    r"|please contact .* support|i'm sorry, but i (?:can't|cannot|don't|do not))",
    re.I,
)


def normalise(text: str) -> str:
    """Straighten curly quotes so patterns match real model output."""
    return text.replace("\u2019", "'").replace("\u2018", "'").replace("\u201c", '"').replace("\u201d", '"')


def sev_rank(s: str) -> int:
    return SEVERITY_ORDER.index(s)


def max_severity(levels: list[str]) -> str:
    return max(levels, key=sev_rank) if levels else "none"


def result(dimension: str, passed: bool, score: float, severity: str, explanation: str,
           evidence: list[str] | None = None, confidence: float = 0.8, method: str = "heuristic",
           details: dict | None = None) -> dict:
    """One evaluation result. Every evaluator returns exactly this shape."""
    return {
        "dimension": dimension,
        "passed": passed,
        "score": round(max(0.0, min(1.0, score)), 2),   # 1.0 = best
        "severity": severity,                            # none / low / medium / high / critical
        "confidence": round(confidence, 2),              # how sure the evaluator is
        "explanation": explanation,
        "evidence": evidence or [],
        "method": method,                                # heuristic or llm_judge
        "details": details or {},
    }


def is_refusal(text: str) -> bool:
    return bool(REFUSAL.search(normalise(text)))


def parse_json_block(text: str) -> dict | None:
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
