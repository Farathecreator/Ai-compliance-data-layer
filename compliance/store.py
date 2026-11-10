"""SQLite store for AI events, compliance flags and reviewer decisions (data/compliance.db).

Reviewer decisions are kept in their own table, keyed by flag id, so re-processing the events
never wipes out a human decision.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB = Path(__file__).resolve().parent.parent / "data" / "compliance.db"
DECISIONS = ["open", "confirmed concern", "not a concern"]


def connect(path: Path = DB) -> sqlite3.Connection:
    path.parent.mkdir(exist_ok=True)
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS events (event_id TEXT PRIMARY KEY, ts TEXT, source TEXT, session_id TEXT,
                                           role TEXT, text TEXT, metadata TEXT);
        CREATE TABLE IF NOT EXISTS flags (flag_id TEXT PRIMARY KEY, event_id TEXT, ts TEXT, source TEXT, role TEXT,
                                          kind TEXT, category TEXT, severity TEXT, record TEXT);
        CREATE TABLE IF NOT EXISTS reviews (flag_id TEXT PRIMARY KEY, decision TEXT, note TEXT, decided_at TEXT);
    """)
    return con


def reset(keep_reviews: bool = True) -> None:
    with connect() as con:
        con.execute("DELETE FROM events")
        con.execute("DELETE FROM flags")
        if not keep_reviews:
            con.execute("DELETE FROM reviews")


def save(events: list[dict], flags: list[dict]) -> None:
    with connect() as con:
        con.executemany("INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?)", [
            (e["event_id"], e.get("timestamp", ""), e.get("source", ""), e.get("session_id", ""), e["role"],
             e.get("text", ""), json.dumps(e.get("metadata", {}), ensure_ascii=False)) for e in events])
        con.executemany("INSERT OR REPLACE INTO flags VALUES (?,?,?,?,?,?,?,?,?)", [
            (f["flag_id"], f["event_id"], f["timestamp"], f["source"], f["role"], f["kind"], f["category"],
             f["severity"], json.dumps(f, ensure_ascii=False)) for f in flags])


def load_flags() -> list[dict]:
    with connect() as con:
        rows = con.execute("SELECT f.record, r.decision, r.note, r.decided_at FROM flags f "
                           "LEFT JOIN reviews r ON r.flag_id = f.flag_id").fetchall()
    out = []
    for rec, decision, note, at in rows:
        f = json.loads(rec)
        f["review"] = {"decision": decision or "open", "note": note or "", "decided_at": at or ""}
        out.append(f)
    return out


def load_events(session_id: str | None = None) -> list[dict]:
    q, args = "SELECT event_id, ts, source, session_id, role, text, metadata FROM events", ()
    if session_id is not None:
        q, args = q + " WHERE session_id = ?", (session_id,)
    with connect() as con:
        rows = con.execute(q + " ORDER BY ts, event_id", args).fetchall()
    return [{"event_id": r[0], "timestamp": r[1], "source": r[2], "session_id": r[3], "role": r[4], "text": r[5],
             "metadata": json.loads(r[6] or "{}")} for r in rows]


def count_events() -> int:
    with connect() as con:
        return con.execute("SELECT COUNT(*) FROM events").fetchone()[0]


def set_review(flag_id: str, decision: str, note: str = "") -> None:
    assert decision in DECISIONS
    with connect() as con:
        con.execute("INSERT OR REPLACE INTO reviews VALUES (?,?,?,?)",
                    (flag_id, decision, note, datetime.now(timezone.utc).isoformat(timespec="seconds")))
