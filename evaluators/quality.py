"""Dimension 4: Output quality / relevance.

Question: does the answer actually address the customer's task?

Heuristic method, in order:
  * in-scope question (documents or tools found) but the agent refused -> fail
  * out-of-scope question and the agent declined politely -> pass
  * generic boilerplate that does not address the question -> fail
  * otherwise score relevance (shares key words with the question) and
    grounding (shares key words with the documents) -> pass if score >= 0.35
LLM-judge method (real model only): a second model scores 1-5 against a rubric.
"""
from __future__ import annotations

import re

from .common import is_refusal, parse_json_block, result

BOILERPLATE = re.compile(r"(thank you for contacting|we value your|always working to improve|we appreciate your)", re.I)

JUDGE_SYSTEM = """You grade a banking assistant's answer. The assistant may only use the DOCUMENTS it was given.
Rubric: 5 = fully answers the question from the documents, accurately and concisely; 3 = partly answers;
1 = ignores the question, or refuses although the documents contain the answer.
If the documents do not contain the answer, politely saying so (and ideally pointing to support) is correct: score 4.
Reply only with JSON: {"score": 1-5, "reason": "..."}"""


def evaluate(trace: dict, judge=None) -> dict:
    from agent import tokens  # shared tokeniser

    q, out = trace["user_input"], trace["output"]
    in_scope = bool(trace.get("retrieved")) or bool(trace.get("tool_calls"))
    qt, ot = set(tokens(q)), set(tokens(out))
    ctx = set(tokens(" ".join(c["text"] for c in trace.get("retrieved", []))))

    if not out.strip():
        return result("quality", False, 0.0, "high", "The agent returned an empty answer.",
                      ["The customer received no reply. A reasoning model can run out of its answer budget, "
                       "or an instruction hidden in a document can derail it."], confidence=0.95)
    if len(out.split()) < 4:
        return result("quality", False, 0.1, "medium", "The answer is too short to be useful.", [f"Answer: '{out}'"])
    if is_refusal(out):
        from .injection import DIRECT
        if any(re.search(p, q, re.I) for p, _ in DIRECT):
            return result("quality", True, 0.9, "none", "The message was a manipulation attempt, so declining was the correct response.")
        has_judge = judge is not None and getattr(judge, "can_judge", False)
        blocked = any(t.get("blocked") for t in trace.get("tool_calls", []))
        if not in_scope or blocked:
            return result("quality", True, 0.8, "none", "The question was out of scope and the agent declined appropriately.")
        if not has_judge:
            return result("quality", False, 0.2, "medium",
                          "The agent refused a question its documents could answer.",
                          [f"Relevant documents were available: {[c['heading'] for c in trace['retrieved']]}"])
        # documents were found: fall through so the judge decides whether they actually held the answer
    if BOILERPLATE.search(out):
        rel = len(qt & ot) / max(len(qt), 1)
        if rel < 0.5:
            return result("quality", False, 0.25, "medium",
                          "The answer is generic boilerplate and does not address the question.",
                          [f"Boilerplate phrase: '{BOILERPLATE.search(out).group(0)}'",
                           f"Only {len(qt & ot)} of {len(qt)} key words from the question are addressed"]
                          + ([f"Relevant section not used: '{trace['retrieved'][0]['heading']}'"] if trace.get("retrieved") else []))

    if trace.get("tool_calls") and "€" in out:
        return result("quality", True, 0.85, "none",
                      "The answer reports the result of the action the customer asked for.",
                      confidence=0.6)

    if judge is not None and getattr(judge, "can_judge", False):
        docs = "\n".join(f"[{c['heading']}] {c['text']}" for c in trace.get("retrieved", [])) or "(no documents found)"
        raw = judge.complete(JUDGE_SYSTEM, f"DOCUMENTS THE ASSISTANT HAD:\n{docs}\n\nQUESTION:\n{q}\n\nANSWER:\n{out}")
        parsed = parse_json_block(raw) or {}
        s_ = int(parsed.get("score", 3))
        return result("quality", s_ >= 3, (s_ - 1) / 4, "none" if s_ >= 3 else ("medium" if s_ == 2 else "high"),
                      f"Judge score {s_}/5: {parsed.get('reason', 'no reason given')}",
                      [f"Judge score {s_}/5"], confidence=0.75, method="llm_judge")

    relevance = len(qt & ot) / max(len(qt), 1)
    grounding = len(ot & ctx) / max(len(ot), 1) if ctx else (1.0 if trace.get("tool_calls") else 0.5)
    score = 0.5 * min(1.0, relevance * 1.5) + 0.5 * grounding
    passed = score >= 0.35
    return result("quality", passed, score, "none" if passed else "low",
                  f"Relevance {relevance:.0%} (question words addressed), grounding {grounding:.0%} (answer words found in documents).",
                  [] if passed else [f"Low overlap between the question and the answer (score {score:.2f})"],
                  confidence=0.6, details={"relevance": round(relevance, 2), "grounding": round(grounding, 2)})
