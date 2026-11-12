# AI Compliance Data Layer and Agent Evaluation Gateway (Citi upStart)

This project has two parts that share one engine:

- **AI Compliance Data Layer (Challenge 7):** reads the text flowing through an AI system and flags personal, special-category and security-sensitive information, with evidence, an explanation and the areas to review in six frameworks: GDPR, the EU AI Act, ISO/IEC 27001, DORA, PCI DSS v4.0.1 and the NIST AI RMF. Every flag is a potential concern for a person to decide on, not a legal conclusion. See [AI Compliance Data Layer](#ai-compliance-data-layer-challenge-7) below.
- **Agent Evaluation Gateway (Challenge 6):** checks every answer of an AI agent for hallucination, prompt injection, data leakage and quality.

## AI Compliance Data Layer (Challenge 7)

```powershell
python -m pip install spacy spacy-transformers
# language models for names and places; installed directly because `spacy download` can fail on newer setups
# transformer model (most accurate, about 440 MB):
python -m pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_trf-3.8.0/en_core_web_trf-3.8.0-py3-none-any.whl
# medium model (smaller fallback, about 34 MB):
python -m pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_md-3.8.0/en_core_web_md-3.8.0-py3-none-any.whl
python run_compliance.py                     # process the AI events (about 4 minutes with the transformer model)
python -m streamlit run compliance_dashboard.py
```

- **Privacy guard:** masks personal data before it reaches the AI model, blocks messages with passwords or keys, and restores the real values in the reply. `python evaluate_guard.py` measures it. Use it with `gateway.run(..., privacy_guard=True)`.
- **Review queue:** one line per conversation, urgent first; low-priority flags are sorted, not decided.
- **Person finder:** for GDPR access and erasure requests, find every AI conversation that mentions an email, phone, PPS number, IBAN or name, export a report, and erase the value from the store (dashboard tab, or `compliance/subject.py`).

### SDK: five lines in any Python AI app

```powershell
python -m pip install -e .              # once, from this folder
python examples/sdk_quickstart.py       # runs offline
```

```python
from ai_compliance import Guard

guard = Guard(source="customer-chatbot")
safe = guard.protect(message)          # mask personal data before the AI model sees it
reply = your_ai(safe.text)             # your own model call (skip it if safe.blocked)
answer = guard.restore(reply)          # real values back for the customer
guard.log(message, answer)             # flags go to the compliance dashboard
```

Also `check(text)` for a one-off check with nothing stored, and `find_person(value)` for the person finder. Everything runs locally; the package sends nothing anywhere.

**Three ways to connect it in a bank:** (1) read the AI logs the bank already keeps (`python run_compliance.py --file logs.jsonl`), the pilot; (2) the SDK inside one AI app, which prevents leaks; (3) a gateway in front of all AI traffic, which is roadmap.

- `python evaluate_compliance.py --split test` measures accuracy on 1,000 held-out labelled sentences (Microsoft Presidio data, MIT licence). Result: **84% of personal-data values found, 97% of flags correct** with the transformer model (72% and 88% in the first version; 77% and 89% with the medium model).
- `python run_compliance.py --file my_events.jsonl` processes your own events, one JSON object per line: `{"text": "...", "role": "user_message", "session_id": "...", "source": "..."}`. Roles: `user_message`, `ai_response`, `retrieved_document`, `tool_result`, `system_log`.
- Reviewer decisions are kept in `data/compliance.db` and survive re-processing.
- Method, accuracy and limits: `docs/COMPLIANCE_METHODOLOGY.md`.

| File | What it does |
|---|---|
| `compliance/detectors.py` | Finds 25 signal types: patterns with checksums (IBAN, card, PPS number), spaCy for names and places, word lists for special categories, and security checks |
| `compliance/mapping.py` | Turns each signal into a potential concern, a severity and the framework areas to review |
| `compliance/guard.py` | The privacy guard: mask before sending, block secrets, restore in the reply |
| `compliance/triage.py` | Priority for each flag and the review queue by conversation |
| `evaluate_guard.py` | How much personal data the guard keeps from the model |
| `ai_compliance/` | The SDK: `Guard.protect / restore / log`, `check`, `find_person` |
| `compliance/subject.py` | Person finder: find, report and erase one person's data (GDPR Art. 15 and 17) |
| `examples/sdk_quickstart.py` | Copy-paste SDK example |
| `compliance/engine.py` | Processes events, applies the context rules (where it appeared, disclosed by the AI, the bank's own public details) |
| `compliance/store.py` | SQLite store for events, flags and reviewer decisions |
| `run_compliance.py` | Processes the agent's saved runs, the labelled conversations and test sentences, or your own file |
| `evaluate_compliance.py` | Precision and recall on the labelled Presidio sentences |
| `compliance_dashboard.py` | The review dashboard: overview, search and filters, flag inspection with highlights, human decisions, live text check |
| `data/compliance_scenarios.json` | 24 hand-labelled conversations (invented people and numbers) |

# Agent Evaluation Gateway (Challenge 6)

A prototype that checks every execution of an AI agent for four problems: **hallucination**, **prompt injection**, **sensitive-data leakage** and **output quality**. It shows the results on a dashboard where a reviewer can drill down from the overall pass rate to a single failed execution and see why it failed.

The demo agent is a customer help assistant that answers from **real public AIB documents**. It's a demo and isn't affiliated with AIB. Customer records are fictional, because real customer data can't be used under GDPR. A fictional document set, "Liffey Bank", is kept for the hand-labelled scenario tests.

```
User input → AI agent → Evaluation gateway → 4 evaluators → Results store (SQLite) → Dashboard
```

## Run it (about 2 minutes)

```bash
pip install -r requirements.txt
python run_scenarios.py --reset --spread-days 6   # 45 hand-labelled scenarios, measures accuracy
python run_real_data.py                           # real datasets: Banking77, Tensor Trust, BIPIA
streamlit run dashboard.py                        # opens the dashboard in your browser
```

No API key is needed. By default the agent runs in **mock mode**: an offline, deliberately weak model with scripted failures, so every evaluator has something to catch.

### Use a real AI model (free options)

| Provider | Free? | Get a key | Set these |
|---|---|---|---|
| **Groq** (recommended) | Free tier, no card; daily limits per model | console.groq.com → API Keys | `EVAL_LLM_PROVIDER=groq`, `GROQ_API_KEY` |
| Google Gemini | Free tier, no card; free-tier data may be used to improve Google products | aistudio.google.com → Get API key | `EVAL_LLM_PROVIDER=gemini`, `GEMINI_API_KEY` |
| OpenAI / Anthropic | Paid | platform.openai.com / console.anthropic.com | `openai` + `OPENAI_API_KEY` / `anthropic` + `ANTHROPIC_API_KEY` |

**Windows PowerShell** (on Mac or Linux, use `export NAME=value` instead):

```powershell
python -m pip install openai
$env:EVAL_LLM_PROVIDER="groq"
$env:GROQ_API_KEY="paste-your-key-here"            # never put the key in a file
$env:EVAL_MODEL="openai/gpt-oss-120b"              # the agent being tested
$env:EVAL_JUDGE_MODEL="openai/gpt-oss-20b"         # a different model checks the answers

# Final, unseen test set: new sample (seed 11) and the other 75 BIPIA attacks
python run_real_data.py --sample 10 --questions 20 --seed 11 --bipia train --bipia-limit 40
```

- **If it stops on a rate limit**, wait (free limits reset over time) and run the **same command with `--resume`**. It continues where it stopped.
- Each run is saved under its own name (model, seed and BIPIA file), so the development run is kept.
- `python rescore_real_data.py --tag <run name>` re-checks a saved run with the current checks, without asking the agent again.
- `python export_review_sheet.py` writes `data/review_sheet.csv` (opens in Excel), with every answer and verdict plus columns for a human reviewer to mark agreement.
- `EVAL_MAX_TOKENS` (default 2000) is the answer budget. Reasoning models need room to think. `EVAL_RPM` (default 25) paces requests.

## Files

| File | What it does |
|---|---|
| `agent.py` | The demo agent: keyword retrieval over the policy documents, a tool planner (`get_balance`, `initiate_transfer`) and the instructions, with a hidden canary marker |
| `llm.py` | Model connector: mock, Anthropic or OpenAI |
| `gateway.py` | Runs the agent, captures the full trace, runs the evaluators and saves one record |
| `evaluators/` | One file per dimension. Each returns pass/fail, score, severity, confidence, explanation and evidence |
| `frameworks.py` | Tags each finding with the framework areas to review (OWASP LLM Top 10, EU AI Act, GDPR, ISO 27001, NIST AI RMF) |
| `store.py` | SQLite results store, one row per execution |
| `scenarios.json` | 33 development scenarios: normal, hallucination bait, quality, five attack types and guardrails-on |
| `scenarios_holdout.json` | 12 held-out scenarios, written after the evaluators were built |
| `run_scenarios.py` | Runs scenarios and reports precision and recall against hand-written labels |
| `dashboard.py` | Streamlit dashboard |
| `docs/METHODOLOGY.md` | Scoring method, accuracy results and limitations |
| `data/policies_aib/` | Real public AIB document text, with the source on each file. `planted_partner_offers.md` is a test page with a hidden attack, not from AIB |
| `data/policies_fictional/` | Fictional Liffey Bank documents used by the hand-labelled scenarios |
| `data/real_datasets/` | Banking77, Tensor Trust and BIPIA test data. Sources and licences are in `SOURCES.md` |
| `run_real_data.py` | Runs the real datasets and writes `data/real_data_report.json`. Supports `--resume` |
| `rescore_real_data.py` | Re-checks a saved run with the current checks |
| `export_review_sheet.py` | Exports every execution to a CSV for human review |

## How the brief's success criteria are met

| Success criterion | Where |
|---|---|
| Every execution generates a structured evaluation record | `gateway.py` → `store.py` |
| All four evaluation dimensions are represented in the dashboard | Overview tab |
| A flagged execution can be traced to its input and output | Flagged executions tab, drill-down |
| Security test scenarios produce identifiable findings | S01–S11, G01–G03, X07–X11 |
| Methodology and scoring are documented | `docs/METHODOLOGY.md`, Methodology tab |
| Limitations of automated evaluation are identified | `docs/METHODOLOGY.md`, Evaluator accuracy tab |


## Data not included in this repository

The two Tensor Trust attack files (`extraction_robustness_dataset.jsonl` and `hijacking_robustness_dataset.jsonl`) are not included, because the source repository has no licence file. They are only needed for `run_real_data.py` (Challenge 6). To run it, download them from https://github.com/HumanCompatibleAI/tensor-trust-data into `data/real_datasets/`. Everything else in the testing guide works without them.
