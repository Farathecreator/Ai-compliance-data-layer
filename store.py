"""Results store: one SQLite table, one row per agent execution.

The full structured evaluation record is kept as JSON in record_json, and the
fields the dashboard filters on most are copied into their own columns.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "data" / "runs.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS executions (
    id            TEXT PRIMARY KEY,
    ts            TEXT NOT NULL,
    scenario_id   TEXT,
    category      TEXT,
    user_input    TEXT,
    output        TEXT,
    overall_pass  INTEGER,
    max_severity  TEXT,
    provider      TEXT,
    guardrails    INTEGER,
    record_json   TEXT NOT NULL
);
"""


def connect(path: Path = DB_PATH) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute(SCHEMA)
    return con


def save(record: dict, path: Path = DB_PATH) -> None:
    with connect(path) as con:
        con.execute(
            "INSERT OR REPLACE INTO executions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (record["id"], record["timestamp"], record.get("scenario_id"), record.get("category"),
             record["trace"]["user_input"], record["trace"]["output"], int(record["overall_pass"]),
             record["max_severity"], record["trace"]["provider"], int(record["trace"]["guardrails"]),
             json.dumps(record, ensure_ascii=False)),
        )


def load_all(path: Path = DB_PATH) -> list[dict]:
    if not path.exists():
        return []
    with connect(path) as con:
        rows = con.execute("SELECT record_json FROM executions ORDER BY ts").fetchall()
    return [json.loads(r[0]) for r in rows]


def clear(path: Path = DB_PATH) -> None:
    with connect(path) as con:
        con.execute("DELETE FROM executions")
