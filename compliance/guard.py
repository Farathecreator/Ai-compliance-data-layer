"""Privacy guard: protect personal data BEFORE it reaches an AI model.

The guard sits between the bank's systems and the AI model provider:

    customer / bank systems  ->  guard (mask)  ->  AI model  ->  guard (restore)  ->  customer

  * mask: identifiers (PPS numbers, cards, IBANs, emails, phones, addresses, dates of birth,
    names, IP addresses) are replaced by numbered placeholders such as [IBAN_1]. The same value
    always gets the same placeholder, so the model can still refer to it.
  * block: a message containing a password, PIN, API key or private key is not sent at all.
  * pass and flag: special-category topics (health, religion...) cannot be removed without
    changing what the customer asked, so they pass through and are flagged for review.

The table that links placeholders to real values (the "vault") stays inside the bank. The
model's reply is restored from it, so the customer still sees their own details.

This is pseudonymisation (GDPR Art. 4(5), Art. 25 data protection by design) and data masking
(ISO/IEC 27001:2022 A.8.11). It reduces what an outside provider receives; it does not stop
the model from repeating data the bank's own systems gave it, which the gateway checks.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import detectors as D

MASK = {"national_id", "payment_card", "iban", "email", "phone", "address", "date_of_birth",
        "person_name", "ip_address"}
BLOCK = {"credential", "secret_key", "private_key"}
BLOCK_MESSAGE = ("For your security this message was not sent to the assistant, because it contains a password, "
                 "PIN or secret key. Please never share these. If you think someone knows your password, change it now.")
PLACEHOLDER = re.compile(r"\[([A-Z_]+)_(\d+)\]")


def _norm(v: str) -> str:
    return re.sub(r"[\s\-().]", "", v).lower()


@dataclass
class Vault:
    """Placeholder -> original value. Kept inside the bank, never sent to the model."""
    values: dict[str, str] = field(default_factory=dict)
    by_value: dict[str, str] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)

    def placeholder(self, kind: str, value: str) -> str:
        key = (kind, _norm(value))
        if key in self.by_value:
            return self.by_value[key]
        self.counts[kind] = self.counts.get(kind, 0) + 1
        ph = f"[{kind.upper()}_{self.counts[kind]}]"
        self.values[ph] = value
        self.by_value[key] = ph
        return ph


@dataclass
class GuardResult:
    text: str                 # what the model receives
    blocked: bool
    masked: list[dict]        # [{"placeholder", "kind", "label"}], no original values
    passed_flagged: list[dict]  # special-category and other signals that went through
    reason: str = ""


def protect(text: str, vault: Vault | None = None, public: frozenset[str] = frozenset()) -> GuardResult:
    """Mask identifiers in text. `public` holds values the organisation itself publishes
    (such as its helpline), which are left as they are."""
    vault = vault if vault is not None else Vault()
    sigs = D.detect(text or "")
    secrets = [s for s in sigs if s.kind in BLOCK]
    if secrets:
        return GuardResult(text="", blocked=True, masked=[], passed_flagged=[],
                           reason=f"{D.KIND_LABEL[secrets[0].kind]} found; the message was not sent")
    # For masking, anything shaped like an IBAN is hidden even if its check digits are wrong:
    # hiding too much is cheap here, sending a real account number is not
    spans = [(s.start, s.end) for s in sigs]
    for m in D.IBAN.finditer(text or ""):
        if not any(a < m.end() and m.start() < b for a, b in spans):
            sigs.append(D.Signal("iban", "personal", m.start(), m.end(), m.group(), 0.6, "pattern",
                                 "Shaped like a bank account number (IBAN)."))
    out, last, masked = [], 0, []
    for s in sorted((s for s in sigs if s.kind in MASK and _norm(s.text) not in public), key=lambda s: s.start):
        if s.start < last:
            continue
        ph = vault.placeholder(s.kind, s.text)
        out += [text[last:s.start], ph]
        masked.append({"placeholder": ph, "kind": s.kind, "label": D.KIND_LABEL[s.kind]})
        last = s.end
    out.append(text[last:])
    flagged = [{"kind": s.kind, "label": D.KIND_LABEL[s.kind]} for s in sigs
               if s.category == "special_category" or s.kind == "prompt_injection"]
    return GuardResult(text="".join(out), blocked=False, masked=masked, passed_flagged=flagged)


def restore(text: str, vault: Vault) -> str:
    """Put the real values back into the model's reply, for the customer."""
    return PLACEHOLDER.sub(lambda m: vault.values.get(m.group(0), m.group(0)), text or "")
