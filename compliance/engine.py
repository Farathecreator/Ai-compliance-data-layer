"""Process AI events into compliance flags.

An event is one piece of text produced or consumed by an AI system:

    {"event_id": "...", "timestamp": "2026-11-07T09:00:00Z", "source": "customer-help-agent",
     "session_id": "...", "role": "user_message" | "ai_response" | "retrieved_document" |
     "tool_result" | "system_log", "text": "...", "metadata": {...}}

For each event the engine runs the detectors, drops values the organisation itself publishes
(for example its own helpline number), and turns every remaining signal into a flag with
evidence, an explanation, a severity, the review areas to check and a status that says it is a
potential concern, not a conclusion.

One rule looks across a whole session: if an AI response contains a personal value that no user
message in the same session provided, the flag says the AI disclosed it. That is the pattern
behind most real AI data leaks.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

from . import detectors as D
from . import guard
from . import mapping as M
from . import triage

ROOT = Path(__file__).resolve().parent.parent
ROLES = ["user_message", "ai_response", "retrieved_document", "tool_result", "system_log"]
ROLE_LABEL = {"user_message": "User message", "ai_response": "AI response", "retrieved_document": "Retrieved document",
              "tool_result": "Tool result", "system_log": "System log"}
VERSION = "compliance-2026-11-07.5"


def norm(v: str) -> str:
    return re.sub(r"[\s\-().]", "", v).lower()


@lru_cache(maxsize=1)
def public_values() -> frozenset[str]:
    """Values found in the organisation's own public documents, such as its helpline numbers.
    They are not about a customer, so they are not flagged as personal data."""
    vals = set()
    for f in sorted((ROOT / "data" / "policies_aib").glob("*.md")):
        if f.name.startswith("planted_"):
            continue
        for s in D.detect(f.read_text(encoding="utf-8")):
            if s.category == "personal":
                vals.add(norm(s.text))
    return frozenset(vals)


def snippet(text: str, start: int, end: int, width: int = 60) -> str:
    a, b = max(0, start - width), min(len(text), end + width)
    return ("…" if a else "") + text[a:start] + "⟦" + text[start:end] + "⟧" + text[end:b] + ("…" if b < len(text) else "")


def flag_id(event_id: str, kind: str, start: int) -> str:
    return hashlib.sha1(f"{event_id}|{kind}|{start}".encode()).hexdigest()[:16]


def process_session(events: list[dict]) -> list[dict]:
    """Flags for a list of events. Events sharing a session_id are checked together."""
    sessions: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        sessions[e.get("session_id") or e["event_id"]].append(e)
    flags = []
    pub = public_values()
    for evs in sessions.values():
        detected = {e["event_id"]: D.detect(e.get("text", "")) for e in evs}
        provided = {norm(s.text) for e in evs if e["role"] == "user_message" for s in detected[e["event_id"]]}
        from_tools = {norm(s.text) for e in evs if e["role"] in ("tool_result", "retrieved_document")
                      for s in detected[e["event_id"]]}
        for e in evs:
            text = e.get("text", "")
            sigs = detected[e["event_id"]]
            has_name = any(s.kind == "person_name" for s in sigs)
            for s in sigs:
                if s.category == "personal" and norm(s.text) in pub:
                    continue  # the organisation's own published details
                if s.kind == "prompt_injection" and e["role"] == "ai_response":
                    continue  # an answer that quotes an attack is not an attempt; leaks are caught by the canary
                if s.kind == "location" and not has_name:
                    continue  # a place on its own does not identify anyone
                unprompted = (e["role"] == "ai_response" and s.category in ("personal", "special_category")
                              and norm(s.text) not in provided and s.kind not in ("location", "nationality"))
                # From a bank system the AI is allowed to use: worth reviewing, but not an unexplained disclosure
                repeated = unprompted and norm(s.text) in from_tools
                disclosed = unprompted and not repeated
                label = D.KIND_LABEL.get(s.kind, s.kind)
                guarded = (e.get("metadata") or {}).get("privacy_guard")
                protected = ""
                if guarded and e["role"] in ("user_message", "tool_result"):
                    if guarded == "blocked":
                        protected = "blocked"
                    elif s.kind in guard.MASK:
                        protected = "masked"
                flags.append({
                    "flag_id": flag_id(e["event_id"], s.kind, s.start),
                    "event_id": e["event_id"], "timestamp": e.get("timestamp", ""), "source": e.get("source", ""),
                    "session_id": e.get("session_id", ""), "role": e["role"],
                    "kind": s.kind, "kind_label": label, "category": s.category,
                    "category_label": D.CATEGORY_LABEL[s.category],
                    "concern": (f"{label} repeated by the AI from a system tool" if repeated else
                                M.concern_title(label, s.kind, s.category, e["role"], disclosed)),
                    "severity": M.severity(s.kind, s.category, e["role"], disclosed),
                    "confidence": s.confidence, "method": s.method,
                    "explanation": s.why + (" The AI produced it although no user message or system tool in this conversation "
                                            "provided it." if disclosed else
                                            " The AI copied it from a system tool's result; check the user should see it in full."
                                            if repeated else ""),
                    "evidence": snippet(text, s.start, s.end), "value": s.text, "start": s.start, "end": s.end,
                    "disclosed_by_ai": disclosed, "repeated_from_tool": repeated, "protected": protected,
                    "review_areas": M.review_areas(s.kind, s.category, e["role"], disclosed),
                    "status": M.STATUS, "disclaimer": M.DISCLAIMER, "engine_version": VERSION,
                })
                if protected:
                    f = flags[-1]
                    f["concern"] += (" (masked before it reached the AI model)" if protected == "masked"
                                     else " (message blocked before it reached the AI model)")
                    f["explanation"] += (" The privacy guard replaced it with a placeholder, so the AI provider never "
                                         "received it." if protected == "masked" else
                                         " The privacy guard stopped the whole message, so the AI provider never received it.")
                    if protected == "masked":
                        f["severity"] = M.lower(f["severity"])
    triage.assign(flags)
    return flags


def events_from_trace(record: dict) -> list[dict]:
    """Split one saved agent execution into the AI events it contains."""
    t, ts, sid = record["trace"], record["timestamp"], record["id"]
    pg = t.get("privacy_guard") or {}
    base = {"timestamp": ts, "session_id": sid, "source": record.get("scenario_set", "live"),
            "metadata": {"customer": t.get("session_customer"), "provider": t.get("provider"),
                         "privacy_guard": ("blocked" if pg.get("blocked") else "masked") if pg.get("enabled") else ""}}
    evs = [dict(base, event_id=f"{sid}-in", role="user_message", text=t["user_input"])]
    for i, c in enumerate(t.get("retrieved", [])):
        evs.append(dict(base, event_id=f"{sid}-doc{i}", role="retrieved_document", text=c["text"],
                        metadata=dict(base["metadata"], document=c["source"], heading=c["heading"])))
    for i, c in enumerate(t.get("tool_calls", [])):
        if c.get("result") is not None:
            evs.append(dict(base, event_id=f"{sid}-tool{i}", role="tool_result",
                            text=" ".join(f"{k}: {v}" for k, v in c["result"].items()) if isinstance(c["result"], dict)
                            else str(c["result"]), metadata=dict(base["metadata"], tool=c["tool"])))
    evs.append(dict(base, event_id=f"{sid}-out", role="ai_response", text=t["output"]))
    return evs
