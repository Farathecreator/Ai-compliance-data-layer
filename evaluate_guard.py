"""Measure how much personal data the privacy guard keeps away from the AI model.

    python evaluate_guard.py

1. Presidio held-out sentences (the same 1,000 used in evaluate_compliance.py): for each
   labelled identifier, is it hidden before the text would be sent to the model?
   "Hidden" = at least 90% of its characters replaced by a placeholder.
2. Hand-labelled conversations: are passwords and keys blocked, and identifiers masked?
3. Banking77 customer questions (real, mostly no personal data): how often does the guard
   mask something in an ordinary question? Each one is listed so a person can judge it.

Writes data/guard_accuracy.json.
"""
from __future__ import annotations

import csv
import json
import random
from collections import defaultdict
from pathlib import Path

from compliance import guard
from compliance.engine import public_values

ROOT = Path(__file__).parent
OUT = ROOT / "data" / "guard_accuracy.json"
TYPES = {"PERSON": "Names", "EMAIL_ADDRESS": "Email addresses", "PHONE_NUMBER": "Phone numbers",
         "STREET_ADDRESS": "Street addresses", "CREDIT_CARD": "Payment cards", "IBAN_CODE": "IBANs",
         "US_SSN": "National ID numbers", "IP_ADDRESS": "IP addresses"}


def masked_chars(text: str, pub) -> list[bool]:
    """Which characters of the original text the guard replaces."""
    g = guard.protect(text, guard.Vault(), pub)
    cover = [False] * len(text)
    if g.blocked:
        return [True] * len(text)
    from compliance import detectors as D  # same spans the guard used
    sigs = D.detect(text)
    for m in D.IBAN.finditer(text):
        sigs.append(D.Signal("iban", "personal", m.start(), m.end(), m.group(), 0, "", ""))
    for s in sigs:
        if s.kind in guard.MASK and guard._norm(s.text) not in pub:
            for i in range(s.start, s.end):
                cover[i] = True
    return cover


def main() -> None:
    pub = public_values()
    rows = json.loads((ROOT / "data" / "real_datasets" / "presidio_synth_dataset_v2.json").read_text(encoding="utf-8"))
    test = [r for i, r in enumerate(rows) if i % 3 != 0]
    hidden, partly, total, examples = defaultdict(int), defaultdict(int), defaultdict(int), defaultdict(list)
    for r in test:
        cover = masked_chars(r["full_text"], pub)
        for g in r["spans"]:
            t = g["entity_type"]
            if t not in TYPES:
                continue
            a, b = g["start_position"], g["end_position"]
            total[t] += 1
            share = sum(cover[a:b]) / max(b - a, 1)
            if share >= 0.9:
                hidden[t] += 1
                continue
            if share > 0:
                partly[t] += 1
            if len(examples[t]) < 4:
                examples[t].append(g["entity_value"][:50])
    by_type = {TYPES[t]: {"hidden": hidden[t], "partly_hidden": partly[t], "total": total[t],
                          "share": round(hidden[t] / total[t], 3),
                          "examples_sent": examples[t]} for t in TYPES if total[t]}
    H, T = sum(hidden.values()), sum(total.values())

    scen = json.loads((ROOT / "data" / "compliance_scenarios.json").read_text(encoding="utf-8"))
    blocked_ok = blocked_n = masked_ok = masked_n = 0
    scen_rows = []
    for s in scen["sessions"]:
        for e in s["events"]:
            if e["role"] != "user_message":
                continue
            g = guard.protect(e["text"], guard.Vault(), pub)
            exp = set(e["expect"])
            if exp & guard.BLOCK:
                blocked_n += 1
                blocked_ok += g.blocked
            for k in exp & guard.MASK:
                masked_n += 1
                ok = any(m["kind"] == k for m in g.masked)
                masked_ok += ok
            scen_rows.append({"session": s["id"], "sent_to_model": "(blocked)" if g.blocked else g.text})

    random.seed(11)
    with (ROOT / "data" / "real_datasets" / "banking77_test.csv").open(encoding="utf-8") as f:
        qs = [r["text"] for r in csv.DictReader(f)]
    sample = random.sample(qs, 300)
    over = []
    for q in sample:
        g = guard.protect(q, guard.Vault(), pub)
        if g.blocked or g.masked:
            over.append({"question": q, "sent_to_model": "(blocked)" if g.blocked else g.text})

    P = sum(partly.values())
    rep = {"presidio_held_out": {"sentences": len(test), "identifiers": T, "hidden": H, "share_hidden": round(H / T, 3),
                                 "partly_hidden": P,
                                 "by_type": by_type},
           "scenarios": {"passwords_and_keys_blocked": f"{blocked_ok}/{blocked_n}",
                         "identifiers_masked": f"{masked_ok}/{masked_n}", "examples": scen_rows},
           "banking77_ordinary_questions": {"questions": len(sample), "changed_by_guard": len(over), "changes": over}}
    OUT.write_text(json.dumps(rep, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Presidio held-out: {H}/{T} identifiers fully hidden before reaching the model ({H / T:.0%}), "
          f"{P} more partly hidden")
    for k, v in by_type.items():
        print(f"   {k:22} {v['hidden']:>4}/{v['total']:<4} {v['share']:.0%}  partly {v['partly_hidden']:>3}   sent e.g.: {v['examples_sent'][:2]}")
    print(f"Scenarios: passwords and keys blocked {blocked_ok}/{blocked_n}; identifiers masked {masked_ok}/{masked_n}")
    print(f"Banking77: {len(over)} of {len(sample)} ordinary questions changed by the guard")
    for o in over:
        print("   ", o["question"][:80], "->", o["sent_to_model"][:80])
    print(f"Saved {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
