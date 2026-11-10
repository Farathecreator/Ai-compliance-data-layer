"""Measure how accurately the compliance detectors find personal data, using labelled text.

    python evaluate_compliance.py --split dev     # the 500 sentences used while building the detectors
    python evaluate_compliance.py --split test    # the 1,000 held-out sentences (the honest number)

Data: Microsoft Presidio research, synth_dataset_v2.json (MIT licence): 1,500 synthetic sentences
with every personal-data value marked by hand-written templates. Every third sentence (index 0, 3,
6, ...) is the development split; the rest are held out.

Matching: a detected value counts as correct when it overlaps a labelled value of a matching
type. Recall = labelled values found / labelled values. Precision = detections that match a
labelled value / detections. Types the detectors do not try to find (organisations, job titles,
web domains, general dates) are listed but not scored.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from compliance import detectors as D

ROOT = Path(__file__).parent
DATA = ROOT / "data" / "real_datasets" / "presidio_synth_dataset_v2.json"
OUT = ROOT / "data" / "compliance_accuracy.json"

# Labelled type -> our kinds that count as finding it
GOLD_TO_OURS = {
    "PERSON": {"person_name"}, "EMAIL_ADDRESS": {"email"}, "PHONE_NUMBER": {"phone"},
    "STREET_ADDRESS": {"address"}, "CREDIT_CARD": {"payment_card"}, "IBAN_CODE": {"iban"},
    "US_SSN": {"national_id"}, "IP_ADDRESS": {"ip_address"}, "AGE": {"age"},
    "NRP": {"nationality", "religion", "political_opinion", "ethnicity"},
    "GPE": {"location"},
}
NOT_SCORED = ["ORGANIZATION", "TITLE", "DATE_TIME", "DOMAIN_NAME", "ZIP_CODE", "US_DRIVER_LICENSE"]
# For precision, a detection is also fine if it overlaps any of these labelled types
COMPATIBLE = {
    "address": {"STREET_ADDRESS", "ZIP_CODE", "GPE"}, "location": {"GPE", "STREET_ADDRESS"},
    "phone": {"PHONE_NUMBER"}, "national_id": {"US_SSN", "US_DRIVER_LICENSE"},
    "date_of_birth": {"DATE_TIME"}, "person_name": {"PERSON"},
}
LABEL = {"PERSON": "Names", "EMAIL_ADDRESS": "Email addresses", "PHONE_NUMBER": "Phone numbers",
         "STREET_ADDRESS": "Street addresses", "CREDIT_CARD": "Payment cards", "IBAN_CODE": "IBANs",
         "US_SSN": "National ID (US SSN)", "IP_ADDRESS": "IP addresses", "AGE": "Ages",
         "NRP": "Nationality, religion or political group", "GPE": "Place names"}


def split(rows: list[dict], name: str) -> list[dict]:
    return [r for i, r in enumerate(rows) if (i % 3 == 0) == (name == "dev")]


def overlap(a, b) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def evaluate(rows: list[dict]) -> dict:
    found, total = defaultdict(int), defaultdict(int)
    det_ok, det_all = defaultdict(int), defaultdict(int)
    misses, false_alarms = defaultdict(list), defaultdict(list)
    for r in rows:
        text, gold = r["full_text"], r["spans"]
        # Security signals and special-category keywords are not labelled in this dataset, so they are
        # measured on the hand-labelled scenarios instead (run_compliance.py --scenarios)
        sigs = [s for s in D.detect(text) if s.category != "security" and s.method != "keyword"]
        for g in gold:
            t = g["entity_type"]
            if t not in GOLD_TO_OURS:
                continue
            total[t] += 1
            gspan = (g["start_position"], g["end_position"])
            if any(s.kind in GOLD_TO_OURS[t] and overlap((s.start, s.end), gspan) for s in sigs):
                found[t] += 1
            elif len(misses[t]) < 6:
                misses[t].append(g["entity_value"][:60])
        for s in sigs:
            ok_types = {t for t, kinds in GOLD_TO_OURS.items() if s.kind in kinds} | COMPATIBLE.get(s.kind, set())
            det_all[s.kind] += 1
            if any(g["entity_type"] in ok_types and overlap((s.start, s.end), (g["start_position"], g["end_position"]))
                   for g in gold):
                det_ok[s.kind] += 1
            elif len(false_alarms[s.kind]) < 6:
                false_alarms[s.kind].append(f"{s.text[:40]!r} in: {text[:70]!r}")
    recall = {t: {"label": LABEL[t], "found": found[t], "total": total[t],
                  "recall": round(found[t] / total[t], 3) if total[t] else None,
                  "examples_missed": misses[t]} for t in GOLD_TO_OURS if total[t]}
    precision = {k: {"label": D.KIND_LABEL.get(k, k), "correct": det_ok[k], "detections": det_all[k],
                     "precision": round(det_ok[k] / det_all[k], 3) if det_all[k] else None,
                     "examples_false_alarm": false_alarms[k]} for k in sorted(det_all)}
    tot_g, tot_f = sum(total.values()), sum(found.values())
    tot_d, tot_ok = sum(det_all.values()), sum(det_ok.values())
    return {"sentences": len(rows), "recall_by_type": recall, "precision_by_kind": precision,
            "overall": {"labelled_values": tot_g, "found": tot_f, "recall": round(tot_f / tot_g, 3),
                        "detections": tot_d, "correct_detections": tot_ok, "precision": round(tot_ok / tot_d, 3)}}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=["dev", "test"], default="dev")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    rows = split(json.loads(DATA.read_text(encoding="utf-8")), args.split)
    rep = evaluate(rows)
    rep.update({"split": args.split, "dataset": "Microsoft Presidio research, synth_dataset_v2.json (MIT)",
                "language_model": D.nlp_status(), "not_scored": NOT_SCORED})
    o = rep["overall"]
    print(f"Split: {args.split} ({rep['sentences']} sentences) · language model: {rep['language_model']}")
    print(f"Overall: found {o['found']}/{o['labelled_values']} labelled values (recall {o['recall']:.0%}), "
          f"{o['correct_detections']}/{o['detections']} detections correct (precision {o['precision']:.0%})\n")
    print(f"{'Labelled type':42} {'found':>12} {'recall':>7}")
    for t, v in rep["recall_by_type"].items():
        print(f"{v['label']:42} {v['found']:>5}/{v['total']:<6} {v['recall']:>7.0%}")
        if not args.quiet and v["examples_missed"]:
            print("      missed e.g.:", "; ".join(repr(x) for x in v["examples_missed"][:3]))
    print(f"\n{'Detector':42} {'correct':>12} {'precision':>9}")
    for k, v in rep["precision_by_kind"].items():
        print(f"{v['label']:42} {v['correct']:>5}/{v['detections']:<6} {v['precision']:>9.0%}")
        if not args.quiet and v["examples_false_alarm"]:
            print("      false alarm e.g.:", "; ".join(v["examples_false_alarm"][:2]))
    if args.split == "test":
        OUT.write_text(json.dumps(rep, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nSaved {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
