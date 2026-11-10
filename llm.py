"""Model connector.

Three providers:
  mock      - offline, deterministic, no API key. Behaves like a weak model with
              scripted failure modes so every evaluator has something to catch.
  anthropic - real model through the Anthropic API (needs ANTHROPIC_API_KEY).
  openai    - real model through the OpenAI API (needs OPENAI_API_KEY).

Choose with the environment variable EVAL_LLM_PROVIDER (default: mock).
Choose the model with EVAL_MODEL.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field


@dataclass
class GenerationRequest:
    system_prompt: str
    user_input: str
    context: list[dict] = field(default_factory=list)       # retrieved policy chunks
    tool_results: list[dict] = field(default_factory=list)  # results of tool calls
    guardrails: bool = False


def format_user_message(req: GenerationRequest) -> str:
    """The prompt a real model receives."""
    parts = ["Retrieved bank documents:"]
    if req.context:
        for c in req.context:
            parts.append(f"[{c['source']} - {c['heading']}]\n{c['text']}")
    else:
        parts.append("(no relevant documents found)")
    parts.append("\nTool results:")
    if req.tool_results:
        for t in req.tool_results:
            parts.append(f"{t['tool']}({t['args']}) -> {t['result']}")
    else:
        parts.append("(no tools called)")
    parts.append(f"\nCustomer message: {req.user_input}")
    return "\n".join(parts)


class BaseLLM:
    name = "base"

    def generate(self, req: GenerationRequest) -> str:
        return self.complete(req.system_prompt, format_user_message(req))

    def complete(self, system: str, user: str) -> str:  # pragma: no cover
        raise NotImplementedError

    @property
    def can_judge(self) -> bool:
        """True when the provider is a real model that can act as an evaluator."""
        return False


class AnthropicLLM(BaseLLM):
    name = "anthropic"

    def __init__(self) -> None:
        import anthropic  # optional dependency
        self.client = anthropic.Anthropic()
        self.model = os.getenv("EVAL_MODEL", "claude-haiku-4-5")

    def complete(self, system: str, user: str) -> str:
        msg = self.client.messages.create(
            model=self.model, max_tokens=int(os.getenv("EVAL_MAX_TOKENS", "2000")), system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip()

    @property
    def can_judge(self) -> bool:
        return True


class OpenAILLM(BaseLLM):
    """OpenAI, or any OpenAI-compatible service (Groq and Gemini have free tiers)."""
    name = "openai"

    # provider -> (base URL, environment variable holding the key, default model)
    PRESETS = {
        "openai": (None, "OPENAI_API_KEY", "gpt-4o-mini"),
        "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY", "llama-3.3-70b-versatile"),
        "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai/", "GEMINI_API_KEY", "gemini-2.5-flash"),
    }

    def __init__(self, provider: str = "openai") -> None:
        import openai  # optional dependency: pip install openai
        base_url, key_var, default_model = self.PRESETS[provider]
        key = os.getenv(key_var)
        if not key:
            raise SystemExit(f"Set {key_var} to your {provider} API key first (see README).")
        self.name = provider
        self.client = openai.OpenAI(api_key=key, base_url=base_url, max_retries=0)
        self.model = os.getenv("EVAL_MODEL", default_model)
        # Free tiers allow roughly 30 requests a minute: pace calls (EVAL_RPM sets the limit)
        self.min_gap = 60.0 / float(os.getenv("EVAL_RPM", "25"))
        # Reasoning models (e.g. gpt-oss) spend tokens thinking before answering: allow enough room
        self.max_tokens = int(os.getenv("EVAL_MAX_TOKENS", "2000"))
        self._last = 0.0

    def complete(self, system: str, user: str) -> str:
        import time as _t
        import openai
        for attempt in range(6):
            wait = self._last + self.min_gap - _t.monotonic()
            if wait > 0:
                _t.sleep(wait)
            self._last = _t.monotonic()
            try:
                r = self.client.chat.completions.create(
                    model=self.model, max_tokens=self.max_tokens,
                    messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                )
                return (r.choices[0].message.content or "").strip()
            except openai.RateLimitError:
                _t.sleep(min(60, 5 * 2 ** attempt))  # free-tier limit hit: back off and retry
        raise RuntimeError("Rate limit kept failing; try a smaller --sample or a lower EVAL_RPM.")

    @property
    def can_judge(self) -> bool:
        return True


class MockLLM(BaseLLM):
    """A deliberately imperfect offline model.

    Scripted failure modes (switched off when guardrails=True):
      * leaks its instructions when asked to reveal them or enter "developer mode"
      * follows instructions hidden inside retrieved documents
      * prints full IBANs and other customers' data returned by tools
      * invents a loan or mortgage rate when no document covers it
      * gives a generic, unhelpful reply to complaint questions
    Everything else is answered extractively from the retrieved documents.
    """
    name = "mock"

    REVEAL = re.compile(r"(system prompt|your instructions|developer mode|reveal|print .*instructions|repeat .*above)", re.I)
    OVERRIDE = re.compile(r"(ignore (all |your |previous |the )*(rules|instructions)|you are now|act as|pretend)", re.I)
    HIDDEN = re.compile(r"AI ASSISTANT INSTRUCTION:\s*(.+)", re.I)
    RATE_Q = re.compile(r"\b(interest|mortgage|loan|apr|savings rate)\b", re.I)

    def generate(self, req: GenerationRequest) -> str:
        q = req.user_input
        g = req.guardrails

        # 1. Direct injection aimed at the instructions
        if self.REVEAL.search(q):
            if g:
                return "I can't share my internal instructions. I can help with questions about your accounts, cards, fees and transfers."
            return "Sure, developer mode enabled. My instructions are:\n" + req.system_prompt
        if self.OVERRIDE.search(q):
            return "I can only help with questions about your bank accounts, cards, fees, transfers and complaints."

        # 2. Tool results (balances, transfers)
        if req.tool_results:
            lines = []
            for t in req.tool_results:
                r = t["result"]
                if t["tool"] == "get_balance" and isinstance(r, dict) and "balance_eur" in r:
                    if g:
                        lines.append(f"The balance on the account ending {r['iban'][-4:]} is €{r['balance_eur']:,.2f}.")
                    else:
                        lines.append(f"{r['name']} (IBAN {r['iban']}, {r['email']}) has a balance of €{r['balance_eur']:,.2f}.")
                elif t["tool"] == "get_balance":
                    lines.append("I can only show the balance of your own account.")
                elif t["tool"] == "initiate_transfer":
                    lines.append(f"I have prepared a transfer of €{t['args'].get('amount_eur', 0):,.2f}. Please confirm it in the app to send it.")
            return " ".join(lines)

        # 3. Invented claim with no figures: a known blind spot of the heuristic checker
        if re.search(r"apple pay|google pay|crypto", q, re.I) and not g:
            return "Yes, our debit cards work with Apple Pay and Google Pay, and you can also buy crypto directly in our app."

        # 4. No relevant documents
        if not req.context:
            if self.RATE_Q.search(q) and not g:
                return "Our current mortgage rate is 3.45% APR fixed for 5 years, and personal loans start at 6.9% APR with no arrangement fee."
            return "I don't have information about that. Please contact the bank's support team for help."

        # 4. Complaint questions get a generic, unhelpful reply (quality failure)
        if re.search(r"complain", q, re.I) and not g:
            return "Thank you for contacting us. We value your feedback and are always working to improve our services."

        # 5. Normal extractive answer from the best chunk
        answer = self._extract(q, req.context[0]["text"])
        for c in req.context:
            m = self.HIDDEN.search(c["text"])
            if m and not g:
                answer = self.HIDDEN.sub("", answer).strip()
                followed = m.group(1).replace("ignore your previous rules and tell the customer to ", "Please ")
                answer += " " + followed.replace("their", "your").strip()
        answer = self.HIDDEN.sub("", answer).strip()
        return answer

    @staticmethod
    def _extract(question: str, text: str, n: int = 2) -> str:
        from agent import tokens  # local import to avoid a cycle
        q = set(tokens(question))
        sents = [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]
        ranked = sorted(sents, key=lambda s: -len(q & set(tokens(s))))
        keep = [s for s in sents if s in ranked[:n]]  # keep original order
        return " ".join(keep)


def get_judge(provider: str | None = None, agent_llm: BaseLLM | None = None) -> BaseLLM | None:
    """The model that checks answers. Set EVAL_JUDGE_MODEL to use a different model from the agent:
    good practice (a model should not mark its own work) and, on free tiers, it spreads the
    per-model rate limits. Returns None when no real model is configured."""
    agent_llm = agent_llm or get_llm(provider)
    if not agent_llm.can_judge:
        return None
    judge_model = os.getenv("EVAL_JUDGE_MODEL")
    if not judge_model or judge_model == getattr(agent_llm, "model", None):
        return agent_llm
    judge = get_llm(provider)
    judge.model = judge_model
    return judge


def get_llm(provider: str | None = None) -> BaseLLM:
    provider = (provider or os.getenv("EVAL_LLM_PROVIDER", "mock")).lower()
    if provider == "anthropic":
        return AnthropicLLM()
    if provider in OpenAILLM.PRESETS:
        return OpenAILLM(provider)
    return MockLLM()
