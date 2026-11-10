"""AI Compliance Data Layer SDK.

Five lines in any Python AI app:

    from ai_compliance import Guard

    guard = Guard(source="customer-chatbot")
    safe = guard.protect(message)          # mask personal data before the AI model sees it
    reply = your_ai(safe.text)             # your own model call (skip it if safe.blocked)
    answer = guard.restore(reply)          # real values back for the customer
    guard.log(message, answer)             # flags go to the compliance dashboard

Other entry points:

    check(text, role="user_message")       # flags for one piece of text, nothing stored
    find_person("sam.doyle@example.com")   # every stored AI event mentioning someone (GDPR access request)

Everything runs locally, inside your own network. Nothing is sent anywhere by this package.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from compliance import engine, guard as _guard, store as _store, subject as _subject

__version__ = "0.1.0"
__all__ = ["Guard", "SafeText", "check", "find_person", "__version__"]


@dataclass
class SafeText:
    """The result of Guard.protect."""
    text: str                    # what may be sent to the AI model
    blocked: bool                # True: do not call the model; show block_message instead
    block_message: str
    masked: list[dict]           # placeholders used, e.g. {"placeholder": "[IBAN_1]", "kind": "iban"}
    flagged: list[dict]          # special-category or attack signals that passed through
    session_id: str
    _vault: _guard.Vault = field(repr=False, default_factory=_guard.Vault)


class Guard:
    """Protects one AI application. Keep one Guard per app; pass session_id to group a conversation."""

    def __init__(self, source: str = "sdk", public_values: list[str] | None = None, store: bool = True):
        self.source = source
        self.store = store
        self.public = (frozenset(_guard._norm(v) for v in public_values) if public_values is not None
                       else engine.public_values())
        self._last: SafeText | None = None

    def protect(self, message: str, session_id: str | None = None) -> SafeText:
        """Mask personal data before the text goes to an AI model. Block passwords and keys."""
        vault = _guard.Vault()
        g = _guard.protect(message, vault, self.public)
        safe = SafeText(text=g.text, blocked=g.blocked, block_message=_guard.BLOCK_MESSAGE if g.blocked else "",
                        masked=g.masked, flagged=g.passed_flagged, session_id=session_id or uuid.uuid4().hex[:12],
                        _vault=vault)
        self._last = safe
        return safe

    def protect_more(self, text: str, safe: SafeText) -> str:
        """Mask further text (for example a tool result) with the same placeholders as the message."""
        return _guard.protect(text, safe._vault, self.public).text

    def restore(self, reply: str, safe: SafeText | None = None) -> str:
        """Put the real values back into the model's reply. Uses the last protect() if safe is not given."""
        safe = safe or self._last
        if safe is None:
            return reply
        return safe.block_message if safe.blocked else _guard.restore(reply, safe._vault)

    def log(self, message: str, answer: str, safe: SafeText | None = None, extra: list[dict] | None = None) -> list[dict]:
        """Record the conversation turn and return its compliance flags.
        extra: more events, e.g. [{"role": "tool_result", "text": "..."}]."""
        safe = safe or self._last
        sid = safe.session_id if safe else uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        meta = {"privacy_guard": ("blocked" if safe.blocked else "masked") if safe else "",
                "sent_to_model": safe.text if safe else ""}
        events = [{"event_id": f"{sid}-{uuid.uuid4().hex[:6]}", "timestamp": now, "source": self.source,
                   "session_id": sid, "role": "user_message", "text": message, "metadata": meta}]
        for e in extra or []:
            events.append({"event_id": f"{sid}-{uuid.uuid4().hex[:6]}", "timestamp": now, "source": self.source,
                           "session_id": sid, "role": e.get("role", "tool_result"), "text": e.get("text", ""),
                           "metadata": {"privacy_guard": meta["privacy_guard"] if e.get("role") == "tool_result" else ""}})
        events.append({"event_id": f"{sid}-{uuid.uuid4().hex[:6]}", "timestamp": now, "source": self.source,
                       "session_id": sid, "role": "ai_response", "text": answer, "metadata": {}})
        flags = engine.process_session(events)
        if self.store:
            _store.save(events, flags)
        return flags


def check(text: str, role: str = "user_message") -> list[dict]:
    """Flags for one piece of text. Nothing is stored."""
    evt = {"event_id": "check", "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "source": "check", "session_id": "", "role": role, "text": text, "metadata": {}}
    return engine.process_session([evt])


def find_person(query: str) -> dict:
    """Every stored AI event that mentions a person's email, phone, ID number, IBAN or name."""
    return _subject.find(query)
