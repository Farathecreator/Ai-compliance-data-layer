"""Person finder: answer GDPR access and erasure requests across stored AI events.

    find("sam.doyle@example.com")   -> every event mentioning that value, grouped by conversation
    erase("sam.doyle@example.com")  -> replace it with [ERASED] everywhere in the data layer's store

Matching ignores spaces, dashes, brackets, dots and letter case, so "087 555 0198" also finds
"0875550198" and "Sam Doyle" also finds "sam doyle". Use the most specific value you have (an
email, PPS number or IBAN); a name alone can match other people with the same name.

Erasure covers this store only. The report from find() lists every source the value appeared in,
so the same request can be carried out in those systems too. The erasure log keeps a one-way hash
of the value, never the value itself.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone

from . import detectors as D
from . import store

SEP = re.compile(r"[\s\-().]")


def norm_with_map(text: str) -> tuple[str, list[int]]:
    """Normalised text plus, for each of its characters, the index in the original text."""
    out, idx = [], []
    for i, ch in enumerate(text):
        if not SEP.match(ch):
            out.append(ch.lower())
            idx.append(i)
    return "".join(out), idx


def spans(text: str, query: str) -> list[tuple[int, int]]:
    q, _ = norm_with_map(query)
    if len(q) < 4:
        return []
    n, idx = norm_with_map(text)
    found, start = [], 0
    while True:
        k = n.find(q, start)
        if k < 0:
            return found
        found.append((idx[k], idx[k + len(q) - 1] + 1))
        start = k + len(q)


def find(query: str) -> dict:
    q, _ = norm_with_map(query)
    if len(q) < 4:
        return {"query": query, "error": "Enter at least 4 letters or digits.", "conversations": []}
    hits = defaultdict(list)
    for e in store.load_events():
        sp = spans(e["text"], query)
        if sp:
            hits[e["session_id"] or e["event_id"]].append(dict(e, matches=sp))
    flags = [f for f in store.load_flags() if f["session_id"] in hits or f["event_id"] in hits]
    kinds = sorted({D.KIND_LABEL.get(f["kind"], f["kind"]) for f in flags
                    if f["category"] != "security" and spans(f["evidence"].replace("⟦", "").replace("⟧", ""), query)})
    convs = []
    for sid, evs in hits.items():
        convs.append({"session_id": sid, "source": evs[0]["source"], "first": min(e["timestamp"] for e in evs),
                      "last": max(e["timestamp"] for e in evs), "events": evs,
                      "roles": sorted({e["role"] for e in evs})})
    convs.sort(key=lambda c: c["first"])
    sent = sum(1 for c in convs for e in c["events"]
               if e["role"] in ("user_message", "tool_result") and (e.get("metadata") or {}).get("privacy_guard") == "masked"
               and not spans((e.get("metadata") or {}).get("sent_to_model", ""), query))
    return {"query": query, "conversations": convs, "events": sum(len(c["events"]) for c in convs),
            "sources": sorted({c["source"] for c in convs}), "data_types_nearby": kinds,
            "first_seen": convs[0]["first"] if convs else "", "last_seen": convs[-1]["last"] if convs else "",
            "masked_before_model": sent}


def report(result: dict) -> dict:
    """An access-request report: where the value appears, without anything else from other people."""
    return {
        "request": "Search of AI events for one person's data (GDPR Art. 15 access / Art. 17 erasure)",
        "searched_for": result["query"], "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "conversations": len(result["conversations"]), "events": result["events"],
        "sources": result["sources"], "first_seen": result["first_seen"], "last_seen": result["last_seen"],
        "data_types_nearby": result["data_types_nearby"],
        "items": [{"conversation": c["session_id"], "source": c["source"], "time": e["timestamp"], "where": e["role"],
                   "text": e["text"]} for c in result["conversations"] for e in c["events"]],
        "note": ("Review each item before sending it: a conversation can also contain other people's data, "
                 "which must be removed from the copy given to the requester."),
    }


def erase(query: str, note: str = "") -> dict:
    """Replace every occurrence of the value with [ERASED] in stored events and flags."""
    q, _ = norm_with_map(query)
    if len(q) < 4:
        raise ValueError("Enter at least 4 letters or digits.")

    def scrub(text: str) -> tuple[str, int]:
        sp = spans(text or "", query)
        for a, b in reversed(sp):
            text = text[:a] + "[ERASED]" + text[b:]
        return text, len(sp)

    ev_changed = fl_changed = 0
    with store.connect() as con:
        for eid, text, meta in con.execute("SELECT event_id, text, metadata FROM events").fetchall():
            new, n = scrub(text)
            m = json.loads(meta or "{}")
            if m.get("sent_to_model"):
                m["sent_to_model"], n2 = scrub(m["sent_to_model"])
                n += n2
            if n:
                con.execute("UPDATE events SET text = ?, metadata = ? WHERE event_id = ?",
                            (new, json.dumps(m, ensure_ascii=False), eid))
                ev_changed += 1
        for fid, rec in con.execute("SELECT flag_id, record FROM flags").fetchall():
            f = json.loads(rec)
            n = 0
            for k in ("evidence", "value"):
                f[k], c = scrub(f.get(k, ""))
                n += c
            if n:
                con.execute("UPDATE flags SET record = ? WHERE flag_id = ?", (json.dumps(f, ensure_ascii=False), fid))
                fl_changed += 1
        con.execute("CREATE TABLE IF NOT EXISTS erasures (at TEXT, value_sha256 TEXT, events INTEGER, flags INTEGER, note TEXT)")
        at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        con.execute("INSERT INTO erasures VALUES (?,?,?,?,?)",
                    (at, hashlib.sha256(q.encode()).hexdigest(), ev_changed, fl_changed, note))
    return {"events_changed": ev_changed, "flags_changed": fl_changed, "at": at}


def erasure_log() -> list[dict]:
    with store.connect() as con:
        con.execute("CREATE TABLE IF NOT EXISTS erasures (at TEXT, value_sha256 TEXT, events INTEGER, flags INTEGER, note TEXT)")
        rows = con.execute("SELECT at, value_sha256, events, flags, note FROM erasures ORDER BY at DESC").fetchall()
    return [{"at": r[0], "value_sha256": r[1][:16] + "…", "events": r[2], "flags": r[3], "note": r[4]} for r in rows]
