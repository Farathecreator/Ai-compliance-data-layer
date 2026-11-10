"""Play a bank customer: chat with the bank's AI assistant, with the compliance layer plugged in.

    python bank_chat.py                      # offline practice model, no key needed
    python bank_chat.py --customer C002      # chat as another (fictional) customer
    python bank_chat.py --provider groq      # a real AI model (needs GROQ_API_KEY)

For each message it shows what the customer typed, what the AI model actually received after
the privacy guard, the answer the customer sees, and the compliance flags. Every turn is stored,
so it appears in the compliance dashboard under the source "bank pilot". Type 'quit' to stop.
"""
from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timezone

import agent
from compliance import engine, store
from llm import get_llm

PRI = {"urgent": "URGENT", "review": "to review", "low": "low"}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--customer", default="C001", help="fictional customer id from data/customers.json")
    ap.add_argument("--provider", default=None, help="mock (default), groq, gemini, openai or anthropic")
    args = ap.parse_args()
    agent.set_policies("aib")
    llm = get_llm(args.provider)
    customers = {c["id"]: c for c in json.load(open("data/customers.json", encoding="utf-8"))["customers"]}
    who = customers.get(args.customer, {}).get("name", args.customer)
    conv = f"pilot-{uuid.uuid4().hex[:8]}"
    print(f"\nBank assistant (demo, public AIB documents). Logged in as {who} ({args.customer}). "
          f"Model: {getattr(llm, 'name', 'mock')}. Conversation {conv}. Type 'quit' to stop.\n")
    events: list[dict] = []
    turn = 0
    while True:
        try:
            msg = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not msg or msg.lower() in ("quit", "exit"):
            break
        turn += 1
        trace = agent.run_agent(msg, session_customer=args.customer, llm=llm, privacy_guard=True)
        pg = trace["privacy_guard"] or {}
        rec = {"id": f"{conv}-t{turn}", "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "scenario_set": "bank pilot", "trace": trace}
        evs = engine.events_from_trace(rec)
        for e in evs:
            e["session_id"] = conv
            e["source"] = "bank pilot"
            if e["role"] == "user_message":
                e["metadata"]["sent_to_model"] = pg.get("sent_to_model", "")
        events += evs
        flags = engine.process_session(events)
        store.save(events, flags)

        print(f"\n  AI model received: {'(nothing, message blocked)' if pg.get('blocked') else pg.get('sent_to_model', '')}")
        print(f"  Bank AI answers:   {trace['output']}")
        new = [f for f in flags if f["event_id"].startswith(rec["id"])]
        if new:
            print("  Compliance flags:")
            for f in new:
                print(f"    - [{PRI.get(f.get('priority'), '')}] {f['concern']}  ({f['value'][:40]})")
        else:
            print("  Compliance flags: none")
        print()
    print(f"Saved conversation {conv} ({turn} messages). Open the compliance dashboard and filter the source "
          f"'bank pilot' to review it.")


if __name__ == "__main__":
    main()
