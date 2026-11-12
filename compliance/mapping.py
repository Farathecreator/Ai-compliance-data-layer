"""Turn a detected signal into a potential compliance concern and the review areas to check.

The references point a reviewer to the part of each framework worth reading. They are review
areas, not findings: whether a rule was actually broken depends on facts the tool cannot see,
such as consent, contracts, the purpose of processing or whether the system is high-risk.
"""
from __future__ import annotations

from evaluators.common import SEVERITY_ORDER

DISCLAIMER = ("Potential compliance concern for human review. The tool points to areas a reviewer should check; "
              "it does not decide whether a law or standard was breached. That needs a qualified person and the full "
              "context, such as the lawful basis, consent and purpose.")
STATUS = "Potential concern: needs human review"

GDPR, AIA, ISO = "GDPR", "EU AI Act", "ISO/IEC 27001:2022"
DORA, PCI, NIST = "DORA", "PCI DSS v4.0.1", "NIST AI RMF 1.0"
# Every framework a flag can point to, in the order the dashboard lists them.
FRAMEWORKS = [GDPR, AIA, ISO, DORA, PCI, NIST]


def ref(fw: str, reference: str, area: str) -> dict:
    return {"framework": fw, "reference": reference, "area": area}


PERSONAL_DATA = ref(GDPR, "Art. 4(1)", "Is this information about an identifiable person?")
BY_KIND: dict[str, list[dict]] = {
    "national_id": [ref(GDPR, "Art. 87", "National identification numbers")],
    "payment_card": [ref(GDPR, "Art. 32", "Security of processing"), ref(ISO, "A.8.11", "Data masking"),
                     ref(PCI, "Req. 3", "Protect stored account data")],
    "iban": [ref(GDPR, "Art. 32", "Security of processing"), ref(ISO, "A.8.11", "Data masking")],
    "date_of_birth": [ref(ISO, "A.5.34", "Privacy and protection of PII")],
    "criminal_offence": [ref(GDPR, "Art. 10", "Personal data relating to criminal convictions and offences"),
                         ref(ISO, "A.5.34", "Privacy and protection of PII")],
    "credential": [ref(ISO, "A.5.17", "Authentication information"), ref(GDPR, "Art. 32", "Security of processing"),
                   ref(PCI, "Req. 8", "Identify users and authenticate access"),
                   ref(DORA, "Art. 9", "ICT protection and prevention, including confidentiality of data")],
    "secret_key": [ref(ISO, "A.5.17", "Authentication information"), ref(ISO, "A.8.12", "Data leakage prevention"),
                   ref(DORA, "Art. 9", "ICT protection and prevention, including confidentiality of data")],
    "private_key": [ref(ISO, "A.8.24", "Use of cryptography"), ref(ISO, "A.8.12", "Data leakage prevention"),
                    ref(DORA, "Art. 9", "ICT protection and prevention, including confidentiality of data")],
    "prompt_injection": [ref(AIA, "Art. 15(5)", "Resilience against attempts to alter the system's use or outputs"),
                         ref(ISO, "A.8.26", "Application security requirements"),
                         ref(DORA, "Art. 10", "Detection of anomalous activities"),
                         ref(NIST, "MEASURE 2.7", "AI system security and resilience evaluated and documented")],
    "system_prompt_leak": [ref(AIA, "Art. 15(5)", "Resilience against attempts to alter the system's use or outputs"),
                           ref(ISO, "A.8.12", "Data leakage prevention"),
                           ref(NIST, "MEASURE 2.7", "AI system security and resilience evaluated and documented")],
}
SPECIAL_REFS = [ref(GDPR, "Art. 9", "Special categories of personal data"),
                ref(AIA, "Art. 10(5)", "Special-category data in high-risk AI systems, only when strictly necessary"),
                ref(ISO, "A.5.34", "Privacy and protection of PII"),
                ref(NIST, "MEASURE 2.10", "Privacy risk of the AI system examined and documented")]
# Personal data the AI disclosed on its own is a possible incident, not just a data-handling question.
DISCLOSED_REFS = [ref(NIST, "MEASURE 2.10", "Privacy risk of the AI system examined and documented"),
                  ref(DORA, "Art. 17", "ICT-related incident management process")]
# Instructions hidden in documents or tool results come from data the bank did not write.
THIRD_PARTY_REFS = [ref(NIST, "MAP 4.1", "Risks of third-party data or software mapped and documented")]
BY_ROLE: dict[str, tuple[str, list[dict]]] = {
    "user_message": ("shared with the AI by a user",
                     [ref(GDPR, "Art. 5(1)(c)", "Data minimisation"), ref(ISO, "A.8.11", "Data masking")]),
    "ai_response": ("in an AI response",
                    [ref(GDPR, "Art. 5(1)(f)", "Integrity and confidentiality"), ref(ISO, "A.8.12", "Data leakage prevention")]),
    "retrieved_document": ("passed to the AI from a document",
                           [ref(GDPR, "Art. 5(1)(c)", "Data minimisation"), ref(GDPR, "Art. 25", "Data protection by design and by default")]),
    "tool_result": ("passed to the AI by a system tool",
                    [ref(GDPR, "Art. 5(1)(c)", "Data minimisation"), ref(GDPR, "Art. 25", "Data protection by design and by default")]),
    "system_log": ("stored in an AI log",
                   [ref(GDPR, "Art. 5(1)(e)", "Storage limitation"), ref(ISO, "A.8.15", "Logging")]),
}
BASE_SEVERITY = {
    "credential": "critical", "secret_key": "critical", "private_key": "critical",
    "system_prompt_leak": "high", "prompt_injection": "medium",
    "national_id": "high", "payment_card": "high", "iban": "high",
    "date_of_birth": "medium", "phone": "medium", "email": "medium", "address": "medium",
    "person_name": "low", "age": "low", "ip_address": "low", "nationality": "low", "location": "low",
}
SPECIAL_KINDS = {"health", "religion", "ethnicity", "political_opinion", "trade_union", "sex_life_orientation",
                 "biometric_genetic"}


def bump(sev: str, n: int = 1) -> str:
    return SEVERITY_ORDER[min(len(SEVERITY_ORDER) - 1, SEVERITY_ORDER.index(sev) + n)]


def lower(sev: str) -> str:
    return SEVERITY_ORDER[max(1, SEVERITY_ORDER.index(sev) - 1)]


def review_areas(kind: str, category: str, role: str, disclosed: bool) -> list[dict]:
    refs = []
    if category in ("personal", "special_category"):
        refs.append(PERSONAL_DATA)
    if kind in SPECIAL_KINDS:
        refs += SPECIAL_REFS
    refs += BY_KIND.get(kind, [])
    if category != "security" or kind in ("credential", "secret_key", "private_key"):
        refs += BY_ROLE.get(role, ("", []))[1]
    if disclosed:
        refs += BY_ROLE["ai_response"][1] + DISCLOSED_REFS
    if kind == "prompt_injection" and role in ("retrieved_document", "tool_result"):
        refs += THIRD_PARTY_REFS
    seen, out = set(), []
    for r in refs:
        key = (r["framework"], r["reference"])
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def severity(kind: str, category: str, role: str, disclosed: bool) -> str:
    sev = "high" if kind in SPECIAL_KINDS or kind == "criminal_offence" else BASE_SEVERITY.get(kind, "low")
    if kind == "prompt_injection" and role in ("retrieved_document", "tool_result"):
        sev = "high"  # hidden instructions in data the AI reads are the more dangerous kind
    if disclosed:
        sev = bump(sev)
    return sev


def concern_title(label: str, kind: str, category: str, role: str, disclosed: bool) -> str:
    if disclosed:
        return f"{label} disclosed by the AI, not provided by the user"
    if kind == "prompt_injection":
        return f"Prompt injection attempt {BY_ROLE.get(role, ('in AI text', []))[0].replace('shared with the AI by a user', 'from a user')}"
    if kind == "system_prompt_leak":
        return "AI revealed its hidden instructions"
    where = BY_ROLE.get(role, ("in AI text", []))[0]
    return f"{label} {where}"
