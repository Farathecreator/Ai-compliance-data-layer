"""Detectors for personal, sensitive and security-sensitive signals in AI text.

Each detector returns Signal objects with the exact characters it matched, so a reviewer can
see the evidence. Three methods are used, from most to least certain:

  * validated pattern: a pattern plus a checksum (IBAN mod-97, card Luhn, Irish PPS number);
  * pattern or language model: a fixed pattern (email, phone) or spaCy's named-entity model
    (names, places, nationalities);
  * keyword: a word list for special-category topics such as health or religion. These are the
    least certain, because a word like "hospital" can appear without revealing anything about
    a person.

A signal is a hint that something may need review. It is never a legal conclusion.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from evaluators.injection import DIRECT, INDIRECT, REPLY_DIRECTIVE

CANARY = "CANARY-7F3K-91QZ"


@dataclass
class Signal:
    kind: str          # e.g. "email", "health", "credential"
    category: str      # "personal", "special_category", "security"
    start: int
    end: int
    text: str
    confidence: float
    method: str        # "validated pattern", "pattern", "language model", "keyword"
    why: str           # one sentence, plain English
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


KIND_LABEL = {
    "person_name": "Person's name", "email": "Email address", "phone": "Phone number",
    "address": "Postal address", "location": "Place name", "date_of_birth": "Date of birth",
    "age": "Age", "iban": "Bank account (IBAN)", "payment_card": "Payment card number",
    "national_id": "National ID number", "ip_address": "IP address", "nationality": "Nationality",
    "health": "Health information", "religion": "Religious belief", "ethnicity": "Racial or ethnic origin",
    "political_opinion": "Political opinion", "trade_union": "Trade union membership",
    "sex_life_orientation": "Sex life or sexual orientation", "biometric_genetic": "Biometric or genetic data",
    "criminal_offence": "Criminal offence or conviction",
    "credential": "Password or PIN", "secret_key": "API key or secret", "private_key": "Private key",
    "prompt_injection": "Prompt injection attempt", "system_prompt_leak": "Hidden instructions revealed",
}
CATEGORY_LABEL = {"personal": "Personal data", "special_category": "Special-category data",
                  "security": "Security-sensitive"}


# ---------------------------------------------------------------- validators
def iban_valid(s: str) -> bool:
    s = re.sub(r"\s", "", s).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        return False
    digits = "".join(str(int(ch, 36)) for ch in s[4:] + s[:4])
    return int(digits) % 97 == 1


def luhn_valid(s: str) -> bool:
    d = [int(c) for c in re.sub(r"\D", "", s)]
    if not 12 <= len(d) <= 19 or len(set(d)) < 3:  # "0101 0011 ..." is binary, not a card
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2:
            n *= 2
            n -= 9 if n > 9 else 0
        total += n
    return total % 10 == 0


def ppsn_valid(s: str) -> bool:
    """Irish Personal Public Service Number: 7 digits, a check letter, optional second letter."""
    m = re.fullmatch(r"(\d{7})([A-W])([A-IW]?)", s.upper())
    if not m:
        return False
    digits, check, extra = m.groups()
    total = sum(int(d) * w for d, w in zip(digits, range(8, 1, -1)))
    if extra:
        total += (0 if extra == "W" else ord(extra) - 64) * 9
    r = total % 23
    return check == ("W" if r == 0 else chr(64 + r))


def ssn_valid(s: str) -> bool:
    a, b, c = s.split("-")
    return a not in ("000", "666") and not a.startswith("9") and b != "00" and c != "0000"


# ---------------------------------------------------------------- patterns
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b")
CARD = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
PPSN = re.compile(r"\b\d{7}[A-Wa-w][A-IWa-iw]?\b")
SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b")
PHONE = re.compile(
    r"(?<![\w.+-])(?:\+|00)?(?:\d{1,3}[ .-]?)?(?:\(\d{1,4}\)[ .-]?)?\d{1,4}(?:[ .-]?\d{2,4}){1,4}"
    r"(?:[ ]?(?:x|ext\.?)[ ]?\d{1,5})?(?![\w-])"
)
PHONE_CONTEXT = re.compile(r"\b(phone|tel|telephone|mobile|call|cell|contact|number|fax|ring|text)\b", re.I)
EIRCODE = re.compile(r"\b[AC-FHKNPRTV-Y]\d{2}[ ]?[AC-FHKNPRTV-Y0-9]{4}\b")
STREET = re.compile(
    r"\b\d{1,5}[A-Za-z]?,?\s+(?:[A-Z][\w'.-]*\s+){0,4}"
    r"(?:Street|St\.?|Road|Rd\.?|Avenue|Ave\.?|Lane|Ln\.?|Drive|Dr\.?|Court|Ct\.?|Boulevard|Blvd\.?|Way|Place|Pl\.?|"
    r"Terrace|Square|Sq\.?|Park|Crescent|Close|Grove|Row|Quay|Parade|Highway|Hwy|Plaza|Circle|Trail|Path|Walk|"
    r"Hill|View|Heights|Gardens|Mews|Green|Port|Pike|Loop|Point|Ridge|Ranch|Station|Village|Route|Mall)\b"
    r"(?:[\w .,'#-]{0,60}?(?:Apt\.?|Suite|Unit)\s*\d+)?",
)
# Street words in several languages, for addresses like "Koskikatu 25" or "Rua do Arenque 1634"
STREET_WORDS = (r"strasse|straße|gasse|weg|platz|gade|vej|gatan|vägen|katu|tie|straat|laan|plein|rue|avenue|boulevard|"
                r"via|viale|piazza|calle|avenida|rua|travessa|ulica|utca|u\.|street|road|lane|drive|terrace")
INTL_STREET = re.compile(
    r"(?:\b\d{1,6}\s+)?(?:\b(?:Rua|Via|Rue|Calle|Avenida|Viale|Piazza|Travessa|Ulica|ul\.|Av\.?)\s+(?:\w+\s+){0,3}\w+\s+\d{1,5}\b"
    r"|\b[\w'-]*(?:" + STREET_WORDS + r")\s+\d{1,5}\b)", re.I)
# A postcode written after the country, as on the last line of an address ("Denmark 35018")
COUNTRY_POSTCODE = re.compile(
    r"\b(?:Ireland|United Kingdom|UK|Denmark|Finland|Sweden|Norway|Iceland|Greenland(?:er)?|Estonia|Latvia|Lithuania|Poland|"
    r"Germany|Austria|Switzerland|Netherlands|Belgium|Luxembourg|France|Spain|Portugal|Italy|Malta|Greece|Cyprus|Slovenia|"
    r"Croatia|Slovakia|Czech Republic|Czechia|Hungary|Romania|Bulgaria|Serbia|Ukraine|Turkey|Tunisia|Morocco|Algeria|Egypt|"
    r"South Africa|Australia|New Zealand|Canada|United States|USA|Brazil|Mexico|Argentina|Chile|India|Japan|China)"
    r"[ \t]+(\d{3,6})\b")
# A whole line that looks like a street line in an address block ("91215 Harjukuja 54", "Skogstien 106 Apt. 12")
ADDRESS_LINE = re.compile(
    r"^[ \t>?]*((?:\d{1,6}[ \t]+)?[A-ZÀ-ÖØ-ÞĀ-Ž][\wÀ-ÿĀ-ž'.-]{3,}(?:[ \t]+[\wÀ-ÿĀ-ž'.-]+){0,2}[ \t]+\d{1,5}"
    r"(?:[ \t]+(?:Apt\.?|Suite)[ \t]*\d{1,5})?)[ \t]*$", re.M)
LEAD_NUMBER = re.compile(r"(?<![\w.])(\d{1,6})[ \t]+$")
UNIT = re.compile(r"\b(?:Apt\.?|Apartment|Suite|Unit|Flat)\s*#?\d{1,5}\b|\b(?:P\.?O\.? Box|PSC)\s*\d{1,6}(?:,\s*Box\s*\d{1,6})?", re.I)
ADDRESS_CUE = re.compile(r"\b(?:address(?:es)?(?: is| was)?\s*(?::|is|here they are:)?|lives? at|living at|located at|"
                         r"(?:office|shop|store|house|home) is (?:at|on)|meet (?:me|you) at|send (?:it|them|a new one)? ?to|"
                         r"deliver(?:ed)? to|ship(?:ped)? to|moved to|stay(?:ing)? at|registered at)\s*", re.I)
AGE = re.compile(r"\b(?:aged?\s*:?\s*(\d{1,3})|(\d{1,3})[\s-]*(?:years?|yrs?)[\s-]*old|(\d{1,3})\s*y/?o|"
                 r"turn(?:ed|s|ing)?\s+(\d{1,3})(?!\s*(?:%|euro|€|\$|percent))|age of\s+(\d{1,3}))\b", re.I)
DATE = r"(?:\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|\d{4}-\d{2}-\d{2}|\d{1,2}(?:st|nd|rd|th)?\s+[A-Z][a-z]+\.?,?\s+\d{4}|[A-Z][a-z]+\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4})"
DOB = re.compile(r"\b(?:born(?:\s+on)?|date of birth|birth ?date|d\.?o\.?b\.?|birthday)\s*(?:is|:|was|on)?\s*(" + DATE + r")", re.I)

CREDENTIAL = re.compile(r"\b(pass(?:word|code|phrase)|pwd|pin(?: code| number)?|login code|one[- ]time code|otp)\b\s*(?:is|:|=)\s*['\"]?([^\s'\".,]{3,})", re.I)
NOT_A_SECRET = re.compile(r"^(?:not|wrong|incorrect|correct|blocked|locked|expired|invalid|valid|required|needed|"
                          r"reset|changed|forgotten|lost|stolen|the|my|your|a|an|too|still|being|now|working|provided|entered|"
                          r"contained|accepted|given|typed|shared|set|sent|case[- ]sensitive)$|^[^A-Za-z0-9]+$", re.I)
SECRET_KEYS = [
    (re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b"), "OpenAI or Anthropic style API key"),
    (re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b"), "Groq API key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "GitHub token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Google API key"),
    (re.compile(r"(?i)\b(?:api[_ -]?key|secret|access[_ -]?token|auth[_ -]?token)\b\s*(?:is|:|=)\s*['\"]?([A-Za-z0-9_\-]{16,})"), "secret value"),
]
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")

# Special categories (GDPR Art. 9) and criminal data (Art. 10). Word lists, matched as whole words.
SPECIAL = {
    "health": r"diagnos(?:is|ed)|cancer|tumou?r|diabet(?:es|ic)|depression|depressed|anxiety disorder|panic attacks?|"
              r"HIV|AIDS|pregnan(?:t|cy)|miscarriage|disabilit(?:y|ies)|disabled|wheelchair|chemotherapy|"
              r"surgery|operation on|hospitali[sz]ed|in hospital|mental health|psychiatr\w*|therap(?:y|ist)|"
              r"counsell?ing|illness|sick leave|medical (?:condition|leave|history|records?)|asthma|ADHD|autis(?:m|tic)|"
              r"dementia|alzheimer'?s|epilep(?:sy|tic)|addiction|rehab|alcoholi(?:sm|c)|blood (?:test|pressure)|"
              r"prescri(?:bed|ption)|medication|antidepressants?|insulin|stroke|heart (?:attack|condition)|"
              r"multiple sclerosis|parkinson'?s|covid(?:-19)? positive|tested positive|terminal(?:ly)? ill|hearing loss|blind",
    "religion": r"muslim|islam(?:ic)?|christian|catholic|protestant|church of ireland|jewish|judaism|hindu(?:ism)?|"
                r"buddhis[tm]|sikh|atheist|agnostic|mosque|synagogue|temple|church|religio(?:n|us)|faith|"
                r"ramadan|mass on sunday|bible study|prayer group|pastor|imam|rabbi",
    "ethnicity": r"ethnic(?:ity| origin| background| minority)?|racial|race|traveller community|irish traveller|roma|"
                 r"black (?:man|woman|person|people|community)|african[- ]american|asian (?:man|woman|person|community)|"
                 r"hispanic|latin[oa]|caucasian|mixed[- ]race|indigenous",
    "political_opinion": r"political (?:party|views?|opinions?|affiliation|beliefs?)|voted? (?:for|against)|"
                         r"party member(?:ship)?|fianna f[aá]il|fine gael|sinn f[eé]in|labour party|green party|"
                         r"social democrats|people before profit|republican party|democratic party|conservative party|"
                         r"socialist|communist|left[- ]wing|right[- ]wing|activist|protest(?:er|ed)?",
    "trade_union": r"trade union|union member(?:ship)?|siptu|f[oó]rsa|unite the union|ictu|shop steward|collective bargaining",
    "sex_life_orientation": r"gay|lesbian|bisexual|homosexual|heterosexual|transgender|non[- ]binary|LGBTQ?\+?|"
                            r"same[- ]sex (?:partner|marriage|couple)|sexual orientation|sex life|queer|coming out",
    "biometric_genetic": r"fingerprints?|facial recognition|face scan|retina(?:l)? scan|iris scan|voice ?print|"
                         r"DNA|genetic (?:test|testing|data|condition)|genome|biometric",
    "criminal_offence": r"convicted|conviction|criminal record|arrested|prison|jail(?:ed)?|offen[cs]es?|"
                        r"charged with (?:an? |the )?(?:crime|offen[cs]e|assault|theft|fraud|murder|robbery|burglary|drink[- ]driving|possession)|sentenced|probation|garda (?:vetting|caution)|court case|on bail|fraudster",
}
SPECIAL_RE = {k: re.compile(r"\b(?:" + v + r")\b", re.I) for k, v in SPECIAL.items()}
# Words that only count when they are about a person, not a place name or product
PERSONAL_CONTEXT = re.compile(r"\b(I|I'm|I've|my|me|he|she|his|her|him|they|their|patient|customer|employee|"
                              r"client|member|applicant|staff|colleague|son|daughter|wife|husband|partner|mother|"
                              r"father|is a|was a|am a)\b|(?-i:[A-Z][a-z]+) (?:is|was|has|had)\b(?! (?:closed|open|located|available))", re.I)

NORP_SPECIAL = {
    "religion": re.compile(r"^(?:muslims?|christians?|catholics?|protestants?|jews?|jewish|hindus?|buddhists?|sikhs?|"
                           r"atheists?|mormons?|orthodox|islamic|evangelical|baptists?|methodists?|lutherans?)$", re.I),
    "political_opinion": re.compile(r"^(?:republicans?|democrats?|conservatives?|liberals?|socialists?|communists?|"
                                    r"labour|tor(?:y|ies)|nationalists?|unionists?|libertarians?|greens?)$", re.I),
}


# Words the language model sometimes tags as names in banking and AI text
NOT_NAME_WORDS = {"access", "granted", "denied", "atm", "card", "account", "balance", "password", "prompt", "code",
                  "bank", "app", "pin", "iban", "swift", "visa", "mastercard", "apple", "google", "pay", "user",
                  "assistant", "system", "admin", "hello", "dear", "sir", "madam", "thanks", "thank", "regards"}
PARTICLES = {"de", "da", "van", "von", "der", "den", "del", "della", "la", "le", "di", "du", "bin", "al", "el", "ó",
             "mac", "mc", "and", "y", "e", "ten", "ter", "st"}
SUFFIXES = {"ii", "iii", "iv", "jr", "sr", "jr.", "sr."}


def name_token(w: str) -> bool:
    w = re.sub(r"['’]s$", "", w.strip(".,;:"))
    if not w:
        return False
    if w.lower() in PARTICLES or w.lower() in SUFFIXES:
        return True
    if len(w) == 1:
        return w.isalpha() and w.isupper()  # a middle initial
    parts = re.split(r"[-'’]", w)
    return all(p[:1].isupper() and p.isalpha() and not (len(p) > 3 and p.isupper()) for p in parts if p)


LANGUAGE_BEFORE = re.compile(r"(?:translat\w*|language|speak\w*|in|into|to|reply|respond|answer|write|say|said|the)\s+(?:this\s+)?$", re.I)
LANGUAGE_AFTER = re.compile(r"\s*(?:language|into|to English|equivalent|translation|word|phrase|text)\b", re.I)


def looks_like_name(t: str) -> bool:
    """A person's name: one to five capitalised words in any alphabet (initials, particles such as
    'van' or 'de', and suffixes such as 'II' allowed), with no digits, underscores or everyday
    banking words."""
    if re.search(r"[\d_@#/\\]", t) or len(t) < 2:
        return False
    toks = t.replace("\n", " ").split()
    if not 1 <= len(toks) <= 5 or any(w.lower().strip(".,") in NOT_NAME_WORDS for w in toks):
        return False
    if all(w.lower() in PARTICLES for w in toks):
        return False
    return all(name_token(w) for w in toks)


# ---------------------------------------------------------------- spaCy (optional)
_NLP = None
_NLP_ERROR = ""


def nlp():
    """Load spaCy's small English model once. Returns None if it is not installed."""
    global _NLP, _NLP_ERROR
    if _NLP is None and not _NLP_ERROR:
        try:
            import spacy
        except Exception as e:  # spaCy not installed
            _NLP_ERROR = f"{type(e).__name__}: {e}"
            return None
        import os
        preferred = os.environ.get("AI_COMPLIANCE_SPACY_MODEL")  # e.g. en_core_web_trf for the transformer model
        # The transformer model is the most accurate (names, places, nationalities); the medium model is the fallback
        for name in tuple(n for n in (preferred, "en_core_web_trf", "en_core_web_md", "en_core_web_sm") if n):
            try:
                _NLP = spacy.load(name, disable=["lemmatizer"])
                _NLP.meta["_used"] = name
                break
            except Exception as e:
                _NLP_ERROR = f"{type(e).__name__}: {e}"
    return _NLP


def nlp_status() -> str:
    nlp()
    return f"spaCy {_NLP.meta['_used']}" if _NLP is not None else f"not available ({_NLP_ERROR[:80]})"


# ---------------------------------------------------------------- detection
def _overlaps(a: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
    return any(a[0] < e and s < a[1] for s, e in spans)


def detect(text: str) -> list[Signal]:
    """Find every signal in one piece of text."""
    if not text or not text.strip():
        return []
    sig: list[Signal] = []
    taken: list[tuple[int, int]] = []  # spans claimed by a more specific detector

    def add(s: Signal, claim: bool = True):
        sig.append(s)
        if claim:
            taken.append((s.start, s.end))

    # 1. Security-sensitive
    if CANARY in text:
        i = text.index(CANARY)
        add(Signal("system_prompt_leak", "security", i, i + len(CANARY), CANARY, 0.99, "validated pattern",
                   "The secret marker hidden in the AI's instructions appears, so its instructions were exposed."))
    for m in PRIVATE_KEY.finditer(text):
        add(Signal("private_key", "security", m.start(), m.end(), m.group(), 0.99, "pattern",
                   "A private cryptographic key appears in the text."))
    for rx, what in SECRET_KEYS:
        for m in rx.finditer(text):
            if not _overlaps(m.span(), taken):
                add(Signal("secret_key", "security", m.start(), m.end(), m.group(), 0.9, "pattern",
                           f"Looks like a {what}, which gives access to a system."))
    for m in CREDENTIAL.finditer(text):
        if NOT_A_SECRET.match(m.group(2)):
            continue
        add(Signal("credential", "security", m.start(), m.end(), m.group(), 0.85, "pattern",
                   f"A {m.group(1).lower()} is written out in full."))
    attempts = []
    for pat, label in DIRECT:
        m = re.search(pat, text, re.I)
        if m:
            attempts.append((m, label))
    for rx, label in ((INDIRECT, "hidden instruction for an AI"), (REPLY_DIRECTIVE, "orders about the AI's reply")):
        m = rx.search(text)
        if m:
            attempts.append((m, label))
    if attempts:
        m, label = attempts[0]
        add(Signal("prompt_injection", "security", m.start(), m.end(), m.group(), 0.75, "pattern",
                   f"Text that tries to change how an AI behaves ({label})."), claim=False)

    # 2. Validated identifiers
    for m in IBAN.finditer(text):
        if iban_valid(m.group()):
            add(Signal("iban", "personal", m.start(), m.end(), m.group(), 0.97, "validated pattern",
                       "A bank account number (IBAN) with valid check digits."))
    for m in re.finditer(r"(?<![\d-])(?:\d[ -]?){11}\d(?![\d-])", text):  # 12-digit cards (e.g. Maestro)
        near = text[max(0, m.start() - 40):m.start()]
        if not _overlaps(m.span(), taken) and luhn_valid(m.group()) and re.search(r"\bcard\b|maestro|debit|credit", near, re.I):
            add(Signal("payment_card", "personal", m.start(), m.end(), m.group(), 0.85, "validated pattern",
                       "A 12-digit payment card number that passes the Luhn check, next to the word card."))
    for m in CARD.finditer(text):
        if not _overlaps(m.span(), taken) and luhn_valid(m.group()):
            add(Signal("payment_card", "personal", m.start(), m.end(), m.group(), 0.93, "validated pattern",
                       "A payment card number that passes the Luhn check."))
    for m in PPSN.finditer(text):
        if not _overlaps(m.span(), taken) and ppsn_valid(m.group()):
            add(Signal("national_id", "personal", m.start(), m.end(), m.group(), 0.95, "validated pattern",
                       "An Irish PPS number with a valid check letter.", {"scheme": "PPSN"}))
    for m in SSN.finditer(text):
        if not _overlaps(m.span(), taken) and ssn_valid(m.group()):
            add(Signal("national_id", "personal", m.start(), m.end(), m.group(), 0.85, "pattern",
                       "A US Social Security number.", {"scheme": "SSN"}))
    for m in EMAIL.finditer(text):
        add(Signal("email", "personal", m.start(), m.end(), m.group(), 0.97, "pattern",
                   "An email address, which can identify a person."))
    for rx in (IPV4, IPV6):
        for m in rx.finditer(text):
            if not _overlaps(m.span(), taken):
                add(Signal("ip_address", "personal", m.start(), m.end(), m.group(), 0.85, "pattern",
                           "An IP address, which can identify a person's device."))
    for m in DOB.finditer(text):
        add(Signal("date_of_birth", "personal", m.start(1), m.end(1), m.group(1), 0.9, "pattern",
                   "A date described as someone's date of birth."))
    for m in EIRCODE.finditer(text):
        if not _overlaps(m.span(), taken):
            add(Signal("address", "personal", m.start(), m.end(), m.group(), 0.8, "pattern",
                       "An Irish Eircode, which points to a single address."))
    def lead(start: int) -> int:
        """Include a building number written just before the street ("935 69 Gordon Terrace")."""
        mm = LEAD_NUMBER.search(text[max(0, start - 10):start])
        return start - (len(mm.group(0)) if mm else 0)
    for m in STREET.finditer(text):
        if not _overlaps(m.span(), taken):
            st = lead(m.start())
            add(Signal("address", "personal", st, m.end(), text[st:m.end()].strip(), 0.75, "pattern",
                       "A street address."))
    for rx in (INTL_STREET, UNIT):
        for m in rx.finditer(text):
            if not _overlaps(m.span(), taken):
                st = lead(m.start())
                add(Signal("address", "personal", st, m.end(), text[st:m.end()].strip(), 0.65, "pattern",
                           "Part of a postal address."))
    for m in COUNTRY_POSTCODE.finditer(text):
        if not _overlaps(m.span(1), taken):
            add(Signal("address", "personal", m.start(1), m.end(1), m.group(1), 0.7, "pattern",
                       "A postcode written after a country name."))
    if text.count("\n") >= 2:  # only in multi-line text, where address blocks appear
        for m in ADDRESS_LINE.finditer(text):
            if not _overlaps(m.span(1), taken) and not re.search(r"\b(?:19|20)\d{2}$", m.group(1)):
                add(Signal("address", "personal", m.start(1), m.end(1), m.group(1), 0.6, "pattern",
                           "A street line in an address block."))
    for m in ADDRESS_CUE.finditer(text):
        rest = text[m.end():]
        stop = re.search(r"\.\s|\n\s*\n|,\s+(?:and|but|so|please)\b|$", rest)
        chunk = rest[:min(stop.start() if stop else len(rest), 120)].rstrip(" .,")
        if re.search(r"\d", chunk) and len(chunk) >= 5 and not _overlaps((m.end(), m.end() + len(chunk)), taken):
            add(Signal("address", "personal", m.end(), m.end() + len(chunk), chunk, 0.7, "pattern",
                       "Text introduced as an address."))
    for m in PHONE.finditer(text):
        s = m.group()
        digits = re.sub(r"\D", "", s)
        if _overlaps(m.span(), taken) or not 7 <= len(digits) <= 15:
            continue
        formatted = bool(re.search(r"[ .()-]", s.strip())) or s.startswith("+")
        if re.fullmatch(r"\d{4}", s) or re.fullmatch(DATE, s) or re.match(r"\d{4}-\d{2}-\d{2}", s.strip()):
            continue
        if re.search(r"\b(licen[cs]e|account|order|invoice|ref(?:erence)?|serial|policy|passport|id)\b[^\d]{0,25}$",
                     text[max(0, m.start() - 35):m.start()], re.I):
            continue
        context = PHONE_CONTEXT.search(text[max(0, m.start() - 40):m.start()])
        if (formatted and len(digits) >= 9) or context or "x" in s.lower():
            add(Signal("phone", "personal", m.start(), m.end(), s.strip(), 0.8 if context else 0.65, "pattern",
                       "A phone number."))
    for m in AGE.finditer(text):
        n = next(g for g in m.groups() if g)
        if 0 < int(n) < 120 and not _overlaps(m.span(), taken):
            add(Signal("age", "personal", m.start(), m.end(), m.group(), 0.7, "pattern", "A person's age."))

    # 3. Names, places and groups from the language model
    # The language model is English: on text in another language it reads ordinary capitalised
    # words (German nouns, for example) as names, so it is only used on English text
    from evaluators.injection import language_of
    lang = language_of(text)
    doc = nlp()(text) if nlp() is not None and lang in (None, "English") else None
    if doc is not None:
        for ent in doc.ents:
            span = (ent.start_char, ent.end_char)
            if _overlaps(span, taken):
                continue
            t = ent.text.strip()
            if ent.label_ == "PERSON" and looks_like_name(t):
                add(Signal("person_name", "personal", *span, t, 0.7, "language model",
                           "A person's name, as recognised by the spaCy language model."))
            elif ent.label_ in ("GPE", "LOC", "FAC"):
                add(Signal("location", "personal", *span, t, 0.5, "language model",
                           "A place. On its own it rarely identifies anyone, but combined with a name it can."), claim=False)
            elif (ent.label_ == "NORP" and t[:1].isupper() and t.replace("-", "").isalpha()
                  and not LANGUAGE_BEFORE.search(text[max(0, ent.start_char - 40):ent.start_char])
                  and not LANGUAGE_AFTER.match(text[ent.end_char:ent.end_char + 25])):  # "reply in German" is a language
                kind = next((k for k, rx in NORP_SPECIAL.items() if rx.match(t)), "nationality")
                cat = "special_category" if kind != "nationality" else "personal"
                why = ("A nationality. It is personal data and can hint at ethnic origin." if kind == "nationality"
                       else f"A word that can reveal a person's {KIND_LABEL[kind].lower()}.")
                add(Signal(kind, cat, *span, t, 0.65, "language model", why))

    # 4. Special categories by keyword, only when the sentence is about a person
    for kind, rx in SPECIAL_RE.items():
        for m in rx.finditer(text):
            if _overlaps(m.span(), taken):
                continue
            s0 = max(text.rfind(".", 0, m.start()), text.rfind("\n", 0, m.start())) + 1
            e0 = min([i for i in (text.find(".", m.end()), text.find("\n", m.end())) if i != -1] or [len(text)])
            if not PERSONAL_CONTEXT.search(text[s0:e0]):
                continue
            add(Signal(kind, "special_category", m.start(), m.end(), m.group(), 0.6, "keyword",
                       f"The word '{m.group()}' in a sentence about a person may reveal {KIND_LABEL[kind].lower()}."))
            break  # one signal per kind per text is enough evidence
    return sorted(sig, key=lambda s: s.start)


def mask(text: str, signals: list[Signal]) -> str:
    """Replace each detected value with its type, for example [EMAIL]. Used to show a safe copy."""
    out, last = [], 0
    for s in sorted((s for s in signals if s.kind not in ("prompt_injection", "location") and s.category != "special_category"),
                    key=lambda s: s.start):
        if s.start < last:
            continue
        out += [text[last:s.start], f"[{s.kind.upper()}]"]
        last = s.end
    out.append(text[last:])
    return "".join(out)
