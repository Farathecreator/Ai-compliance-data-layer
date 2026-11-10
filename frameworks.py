"""Maps each finding to the framework areas a reviewer should look at.

These references point a reviewer to the relevant area. They are not a legal or
compliance conclusion. For example, EU AI Act Article 15 applies directly only to
high-risk AI systems.

Frameworks used:
  OWASP LLM Top 10 (2025)  - security risks for applications built on language models
  EU AI Act                - Article 15 accuracy, robustness and cybersecurity
  GDPR                     - personal data protection
  ISO/IEC 27001:2022       - information security controls
  NIST AI RMF              - trustworthiness characteristics of AI systems
"""
from __future__ import annotations

REF = {
    "LLM01": ("OWASP LLM Top 10", "LLM01:2025", "Prompt Injection"),
    "LLM02": ("OWASP LLM Top 10", "LLM02:2025", "Sensitive Information Disclosure"),
    "LLM06": ("OWASP LLM Top 10", "LLM06:2025", "Excessive Agency"),
    "LLM07": ("OWASP LLM Top 10", "LLM07:2025", "System Prompt Leakage"),
    "LLM09": ("OWASP LLM Top 10", "LLM09:2025", "Misinformation"),
    "AIA15": ("EU AI Act", "Article 15", "Accuracy, robustness and cybersecurity"),
    "GDPR5": ("GDPR", "Article 5(1)(f)", "Integrity and confidentiality"),
    "GDPR32": ("GDPR", "Article 32", "Security of processing"),
    "ISO812": ("ISO/IEC 27001:2022", "Annex A 8.12", "Data leakage prevention"),
    "NIST_VR": ("NIST AI RMF", "Valid and reliable", "Trustworthiness characteristic"),
    "NIST_SR": ("NIST AI RMF", "Secure and resilient", "Trustworthiness characteristic"),
}


def _refs(keys: list[str]) -> list[dict]:
    seen, out = set(), []
    for k in keys:
        if k not in seen:
            seen.add(k)
            fw, ref, title = REF[k]
            out.append({"framework": fw, "reference": ref, "title": title})
    return out


def refs_for(evaluation: dict) -> list[dict]:
    """Framework areas for one evaluation. Empty when nothing was found."""
    if evaluation["passed"] and evaluation["severity"] == "none":
        return []
    dim = evaluation["dimension"]
    ev = " ".join(evaluation["evidence"]).lower()
    keys: list[str] = []
    if dim == "hallucination":
        keys = ["LLM09", "AIA15", "NIST_VR"]
    elif dim == "quality":
        keys = ["NIST_VR"]
    elif dim == "leakage":
        keys = ["LLM02", "GDPR5", "GDPR32", "ISO812"]
    elif dim == "injection":
        keys = ["LLM01"]
        if "canary" in ev or "private instructions" in ev:
            keys.append("LLM07")
        if "unauthorised tool" in ev or "triggered by text" in ev:
            keys.append("LLM06")
        if not evaluation["passed"]:
            keys += ["AIA15", "NIST_SR"]
    return _refs(keys)
