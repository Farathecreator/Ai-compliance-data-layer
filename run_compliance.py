"""Process AI events into compliance flags and save them for the compliance dashboard.

    python run_compliance.py                    # everything below, then open the dashboard
    python run_compliance.py --only scenarios   # the 24 hand-labelled conversations, with accuracy
    python run_compliance.py --file my_events.jsonl   # your own events, one JSON object per line

Sources:
  * agent: every real-data execution of the customer help agent saved in data/runs.db, split
    into its events (customer message, documents read, tool results, AI answer);
  * scenarios: 24 hand-written conversations in data/compliance_scenarios.json, each event
    labelled with what should be flagged. Accuracy against those labels is printed and saved;
  * presidio: 300 sentences from the held-out part of the Presidio dataset, treated as
    customer messages, so the dashboard has realistic personal data to review.

Reviewer decisions made in the dashboard are kept when you run this again.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import store as agent_store
from compliance import detectors as D
from compliance import engine
from compliance import guard, store, triage

ROOT = Path(__file__).parent
SCEN = ROOT / "data" / "compliance_scenarios.json"
PRESIDIO = ROOT / "data" / "real_datasets" / "presidio_synth_dataset_v2.json"
ACC_OUT = ROOT / "data" / "compliance_scenario_accuracy.json"
NOT_SCORED = {"location", "nationality"}


def agent_events() -> list[dict]:
    recs = [r for r in agent_store.load_all() if str(r.get("scenario_set", "")).startswith("real-")]
    evs = []
    for r in recs:
        for e in engine.events_from_trace(r):
            e["source"] = "help-agent: " + e["source"].replace("real-", "")
            evs.append(e)
    return evs


def scenario_events() -> list[dict]:
    data = json.loads(SCEN.read_text(encoding="utf-8"))
    base = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=6)
    evs = []
    for i, s in enumerate(data["sessions"]):
        for j, e in enumerate(s["events"]):
            ts = base + timedelta(hours=6 * i, minutes=j)
            evs.append({"event_id": f"{s['id']}-{j}", "timestamp": ts.isoformat(), "source": "labelled scenarios",
                        "session_id": s["id"], "role": e["role"], "text": e["text"],
                        "metadata": {"title": s["title"], "expect": e["expect"]}})
    return evs


def presidio_events(n: int = 300) -> list[dict]:
    rows = json.loads(PRESIDIO.read_text(encoding="utf-8"))
    held_out = [r for i, r in enumerate(rows) if i % 3 != 0][:n]
    base = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=5)
    return [{"event_id": f"P{i:04d}", "timestamp": (base + timedelta(minutes=23 * i)).isoformat(),
             "source": "presidio synthetic messages", "session_id": f"P{i:04d}", "role": "user_message",
             "text": r["full_text"], "metadata": {"labelled": [s["entity_type"] for s in r["spans"]]}}
            for i, r in enumerate(held_out)]


def file_events(path: Path) -> list[dict]:
    evs = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if line.strip():
            e = json.loads(line)
            e.setdefault("event_id", f"{path.stem}-{i}")
            e.setdefault("role", "user_message")
            e.setdefault("source", path.name)
            e.setdefault("timestamp", datetime.now(timezone.utc).isoformat(timespec="seconds"))
            if e["role"] not in engine.ROLES:
                raise SystemExit(f"Line {i + 1}: role must be one of {engine.ROLES}")
            evs.append(e)
    return evs


def apply_guard(events: list[dict]) -> list[dict]:
    """Replay the events as if the privacy guard had been switched on: customer messages and
    tool results pass through it before the AI model. Returns new events; the originals stay
    the bank's own record, and the text the model would have received is kept in metadata."""
    pub = engine.public_values()
    out = []
    for e in events:
        e = dict(e, metadata=dict(e.get("metadata") or {}))
        if e["role"] in ("user_message", "tool_result"):
            g = guard.protect(e.get("text", ""), guard.Vault(), pub)
            e["metadata"]["privacy_guard"] = "blocked" if g.blocked else "masked"
            e["metadata"]["sent_to_model"] = "" if g.blocked else g.text
        out.append(e)
    return out


def queue_stats(flags: list[dict]) -> dict:
    q = triage.queue(flags)
    return {"flags": len(flags), "conversations": len(q),
            "urgent": sum(i["priority"] == "urgent" for i in q), "review": sum(i["priority"] == "review" for i in q),
            "low": sum(i["priority"] == "low" for i in q)}


def scenario_accuracy(events: list[dict], flags: list[dict]) -> dict:
    got: dict[str, set] = {}
    for f in flags:
        got.setdefault(f["event_id"], set()).add(f["kind"])
    tp, fp, fn = Counter(), Counter(), Counter()
    mismatches = []
    clean_events = clean_ok = 0
    for e in events:
        exp = set(e["metadata"]["expect"])
        found = got.get(e["event_id"], set()) - NOT_SCORED
        for k in found & exp:
            tp[k] += 1
        for k in found - exp:
            fp[k] += 1
        for k in exp - found:
            fn[k] += 1
        if not exp:
            clean_events += 1
            clean_ok += not found
        if found != exp:
            mismatches.append({"event": e["event_id"], "text": e["text"][:120],
                               "missed": sorted(exp - found), "false_alarm": sorted(found - exp)})
    kinds = sorted(set(tp) | set(fp) | set(fn))
    per = {k: {"label": D.KIND_LABEL.get(k, k), "found": tp[k], "missed": fn[k], "false_alarms": fp[k]} for k in kinds}
    T, F, N = sum(tp.values()), sum(fp.values()), sum(fn.values())
    return {"events": len(events), "expected_signals": T + N, "found": T, "missed": N, "false_alarms": F,
            "recall": round(T / (T + N), 3) if T + N else None, "precision": round(T / (T + F), 3) if T + F else None,
            "events_that_should_be_clean": clean_events, "of_which_clean": clean_ok,
            "by_kind": per, "mismatches": mismatches, "engine_version": engine.VERSION}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=["agent", "scenarios", "presidio"], help="process one source only")
    ap.add_argument("--file", type=Path, help="a JSONL file of your own AI events")
    ap.add_argument("--presidio", type=int, default=300, help="how many Presidio sentences to include")
    ap.add_argument("--reset", action="store_true", help="clear stored events and flags first (reviews are kept)")
    ap.add_argument("--no-guard", action="store_true",
                    help="store the events as they happened, without replaying them through the privacy guard")
    args = ap.parse_args()

    print(f"Language model for names and places: {D.nlp_status()}")
    if args.reset:
        store.reset()
    sources = {}
    if args.file:
        sources["file"] = file_events(args.file)
    else:
        if args.only in (None, "scenarios"):
            sources["scenarios"] = scenario_events()
        if args.only in (None, "agent"):
            sources["agent"] = agent_events()
        if args.only in (None, "presidio"):
            sources["presidio"] = presidio_events(args.presidio)
    stats = {"without_guard": {}, "with_guard": {}}
    all_without, all_with = [], []
    for name, evs in sources.items():
        flags_raw = engine.process_session(evs)
        guarded = apply_guard(evs)
        flags_g = engine.process_session(guarded)
        all_without += flags_raw
        all_with += flags_g
        if not args.no_guard:
            evs, flags = guarded, flags_g
        else:
            flags = flags_raw
        store.save(evs, flags)
        sev = Counter(f["severity"] for f in flags)
        print(f"{name:10} {len(evs):5} events -> {len(flags):5} flags  "
              + "  ".join(f"{s}: {sev[s]}" for s in ["critical", "high", "medium", "low"] if sev[s]))
        if name == "scenarios":
            acc = scenario_accuracy(evs, flags)
            ACC_OUT.write_text(json.dumps(acc, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"\nLabelled scenarios: found {acc['found']}/{acc['expected_signals']} expected signals "
                  f"(recall {acc['recall']:.0%}), {acc['false_alarms']} false alarms (precision {acc['precision']:.0%}); "
                  f"{acc['of_which_clean']}/{acc['events_that_should_be_clean']} clean events left clean")
            for m in acc["mismatches"]:
                print(f"   {m['event']}: missed {m['missed']} false alarm {m['false_alarm']} | {m['text'][:80]}")
            print()
    stats = {"without_guard": queue_stats(all_without), "with_guard": queue_stats(all_with),
             "masked_before_model": sum(f.get("protected") == "masked" for f in all_with),
             "blocked_before_model": sum(f.get("protected") == "blocked" for f in all_with),
             "stored_mode": "without guard" if args.no_guard else "with guard (replayed)", "engine_version": engine.VERSION}
    (ROOT / "data" / "compliance_queue_stats.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    w, g = stats["without_guard"], stats["with_guard"]
    print(f"\nReview queue without the privacy guard: {w['urgent']} urgent + {w['review']} to review "
          f"({w['low']} low priority) of {w['conversations']} conversations")
    print(f"Review queue with the privacy guard:    {g['urgent']} urgent + {g['review']} to review "
          f"({g['low']} low priority); {stats['masked_before_model']} values masked and "
          f"{stats['blocked_before_model']} secrets blocked before reaching the AI model")
    print(f"\nStored {store.count_events()} events in data/compliance.db. Open the dashboard with:\n"
          f"   streamlit run compliance_dashboard.py")


if __name__ == "__main__":
    main()
