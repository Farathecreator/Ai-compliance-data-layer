"""Sort flags so a reviewer sees what matters first.

Each flag gets a priority and a one-line reason:

  * urgent: the AI disclosed personal data nobody gave it, revealed its hidden instructions,
    or a password or key appeared; also special-category data in an AI response;
  * review: other high or medium signals, such as a PPS number or card typed by a customer,
    special-category data shared by a customer, or an injection attempt;
  * low: names, ages, places and nationalities on their own, names that sit inside attack text
    (usually characters in a made-up story), and values the privacy guard masked before they
    reached the AI model.

Low priority is automatic sorting, not a decision: every low flag stays visible and a person
can still open it, confirm it or dismiss it. Conversations are ranked by their most urgent flag.
"""
from __future__ import annotations

from collections import defaultdict

from evaluators.common import SEVERITY_ORDER

LEVELS = ["urgent", "review", "low"]
SPECIAL = {"health", "religion", "ethnicity", "political_opinion", "trade_union", "sex_life_orientation",
           "biometric_genetic", "criminal_offence"}
MINOR = {"person_name", "age", "location", "nationality", "ip_address"}


def priority(f: dict, event_has_attack: bool) -> tuple[str, str]:
    k, sev = f["kind"], f["severity"]
    if f.get("protected") == "masked":
        return "low", "Masked before it reached the AI model"
    if f.get("disclosed_by_ai"):
        return "urgent", "The AI disclosed personal data nobody in the conversation gave it"
    if k == "system_prompt_leak":
        return "urgent", "The AI revealed its hidden instructions"
    if k in ("credential", "secret_key", "private_key"):
        if f.get("protected") == "blocked":
            return "review", "A secret was typed; the message was blocked, but the customer may need to change it"
        return "urgent", "A password or key is exposed"
    if k in SPECIAL and f["role"] == "ai_response":
        return "urgent", "Special-category data in an AI response"
    if k in MINOR:
        if event_has_attack and k == "person_name":
            return "low", "A name inside attack text, usually a made-up character"
        return "low", "On its own this rarely identifies someone"
    if sev in ("critical",):
        return "urgent", "Critical severity"
    return "review", "Needs a person to check the context"


def assign(flags: list[dict]) -> None:
    attack_events = {f["event_id"] for f in flags if f["kind"] == "prompt_injection"}
    for f in flags:
        f["priority"], f["priority_reason"] = priority(f, f["event_id"] in attack_events)


def queue(flags: list[dict]) -> list[dict]:
    """One item per conversation, most urgent first."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in flags:
        groups[f.get("session_id") or f["event_id"]].append(f)
    items = []
    for sid, fl in groups.items():
        best = min(LEVELS.index(f.get("priority", "review")) for f in fl)
        worst = max((f["severity"] for f in fl), key=SEVERITY_ORDER.index)
        top = sorted(fl, key=lambda f: (LEVELS.index(f.get("priority", "review")), -SEVERITY_ORDER.index(f["severity"])))
        items.append({"session_id": sid, "priority": LEVELS[best], "worst_severity": worst, "flags": len(fl),
                      "urgent": sum(f.get("priority") == "urgent" for f in fl),
                      "to_review": sum(f.get("priority") in ("urgent", "review") for f in fl),
                      "open": sum(f.get("review", {}).get("decision", "open") == "open" for f in fl),
                      "headline": top[0]["concern"], "reason": top[0]["priority_reason"],
                      "source": fl[0]["source"], "time": max(f["timestamp"] for f in fl),
                      "first_flag": top[0]["flag_id"]})
    items.sort(key=lambda i: (LEVELS.index(i["priority"]), -SEVERITY_ORDER.index(i["worst_severity"]), -i["urgent"],
                              -i["to_review"]))
    return items
