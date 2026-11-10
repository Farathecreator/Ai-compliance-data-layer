# AI Compliance Data Layer: method, accuracy and limits

**What it does.** It reads the text that flows through an AI system and flags personal, special-category and security-sensitive information. For each flag it shows the evidence, explains it in plain English and points to the GDPR, EU AI Act and ISO/IEC 27001 areas a reviewer should check. A person then records a decision. Every flag is a **potential concern for human review, not a legal conclusion**.

## How the brief's success criteria are met

| Challenge 7 criterion | How |
|---|---|
| 1. Representative AI text or events are processed automatically | `run_compliance.py` turns every saved run of the customer help agent into events (customer message, documents read, tool results, AI answer) and processes them, together with 24 labelled conversations and 300 test sentences. Your own events can be loaded from a JSONL file with `--file` |
| 2. Personal, sensitive and security-sensitive signals are detected | 25 signal types in three groups (table below) |
| 3. Signals are mapped to GDPR, EU AI Act or ISO 27001 review areas | `compliance/mapping.py`. The area depends on the signal and on where it appeared |
| 4. Each flag has evidence and an explanation | The matched text in context, highlighted, plus a one-sentence reason, the method and a confidence |
| 5. A reviewer can search, filter and inspect flagged events | Search box, filters (category, signal, severity, where it appeared, framework, review decision), the whole conversation with highlights, a masked copy and CSV export |
| 6. A potential concern is clearly separate from a legal conclusion | Every flag has the status "Potential concern: needs human review", the disclaimer is shown on every screen, and only a person can mark a flag "confirmed concern" or "not a concern" |

## What is detected

| Group | Signals | Method |
|---|---|---|
| **Personal data** | Name, email, phone, postal address and Eircode, date of birth, age, IBAN, payment card, national ID (Irish PPS number, US SSN), IP address, nationality | Patterns, checksums for IBAN (mod-97), cards (Luhn) and PPS numbers (check letter), and the spaCy language model for names, places and nationalities |
| **Special-category data** (GDPR Art. 9, plus criminal data under Art. 10) | Health, religion, racial or ethnic origin, political opinion, trade union membership, sex life or sexual orientation, biometric or genetic data, criminal offences | Word lists, counted only in a sentence about a person ("I", "my", "he", "patient", a name…) |
| **Security-sensitive** | Passwords and PINs, API keys and secrets, private keys, prompt injection attempts, the AI revealing its hidden instructions | Patterns, the injection checks from the evaluation gateway, and the hidden canary marker |

## Rules that use context

- **Where it appeared.** The same email address raises different questions in a customer's message (data minimisation: should it reach the AI at all?) than in an AI answer (confidentiality: who saw it?). The review areas change with the place.
- **Disclosed by the AI.** If an AI answer contains personal data that no customer message and no system tool in the same conversation provided, the flag says the AI disclosed it and its severity goes up one level. This is the pattern behind most AI data leaks. If the value came from a system tool, the flag says the AI repeated it, so a reviewer checks whether the customer should see it in full.
- **The organisation's own details are not personal data.** Values found in the bank's public documents, such as its helpline numbers, are never flagged.
- **A place alone is not flagged.** A city on its own rarely identifies anyone, so places are flagged only next to a name.
- **Attack text quoted in an answer is not an attack.** Injection attempts are looked for in what goes into the AI, not in its answers. A leak of the hidden instructions is caught by the canary.


## Prevention: the privacy guard

Flagging after the fact does not stop data reaching an outside AI provider. The privacy guard (`compliance/guard.py`) sits between the bank's systems and the AI model:

- **Mask:** PPS numbers, cards, IBANs, emails, phones, addresses, dates of birth, names and IP addresses in customer messages and system tool results become numbered placeholders, such as `[IBAN_1]`. The same value always gets the same placeholder, so the model can still refer to it. Anything shaped like an IBAN is masked even when its check digits are wrong, because hiding too much is cheap here.
- **Block:** a message containing a password, PIN, API key or private key is not sent at all. The customer is told to change the secret.
- **Pass and flag:** special-category topics (health, religion…) cannot be removed without changing what the customer asked, so they pass through and are flagged for a person.
- **Restore:** the table linking placeholders to real values stays inside the bank, and the model's reply is restored from it, so the customer still sees their own details.

This is pseudonymisation (GDPR Art. 4(5)) and data protection by design (Art. 25), and data masking (ISO/IEC 27001:2022 A.8.11). Retrieval and tools run inside the bank on the original text; only the call to the model is masked. Switch it on with `privacy_guard=True` in `gateway.run` or `agent.run_agent`.

**Measured** (`python evaluate_guard.py`):

| Test | Result |
|---|---|
| Presidio held-out sentences: labelled identifiers fully hidden before reaching the model | **65%** (770 of 1,176); 133 more partly hidden. Cards, emails, ID numbers and IP addresses 100%, IBANs 93%, phones 83%, names 73%, street addresses 36% fully (most others partly) |
| Hand-labelled conversations | Passwords and keys blocked 2 of 2; identifiers masked 7 of 7 |
| 300 real Banking77 customer questions | **0 changed**: the guard does not interfere with ordinary questions |

What it does not do: it does not stop the model repeating data the bank's own systems gave it (the data layer and the evaluation gateway still flag that), and an identifier the detectors miss is sent as it is.

## Reviewer load: the priority queue

A tool that raises hundreds of alerts gets ignored. Flags are sorted automatically (`compliance/triage.py`):

| Priority | When |
|---|---|
| Urgent | The AI disclosed personal data nobody in the conversation gave it, revealed its hidden instructions, or a password or key is exposed; special-category data in an AI response |
| To review | Other high and medium signals: an ID number or card typed by a customer, special-category data shared by a customer, injection attempts, a secret that was blocked but may need changing |
| Low | Names, ages, places and nationalities on their own; names inside attack text (usually made-up characters); values the privacy guard masked before the model saw them |

The dashboard shows one line per conversation, most urgent first. **Priority is sorting, not a decision:** low-priority flags stay open and can be reviewed like any other. A reviewer can apply one decision to every flag in a conversation.

**Effect on the demo data** (1,028 events, `data/compliance_queue_stats.json`): without the guard, 220 conversations need a person (9 urgent); with the guard, **104** (5 urgent), because 321 values were masked and 4 secrets blocked before reaching the model.

## Requests from one person: the person finder

Under GDPR a person can ask for their data (Art. 15) or for it to be erased (Art. 17). If AI conversations are stored, they are part of the answer. The person finder (`compliance/subject.py`, dashboard tab "Person finder") searches every stored event for an email, phone number, PPS number, IBAN or name. It ignores spaces, dashes, dots, brackets and letter case, so "087 555 0198" also finds "0875550198".

- **Access:** it lists the conversations, sources, first and last time seen, and the other kinds of personal data in the same events. The report downloads as JSON or CSV. A person must check the report before sending it, because a conversation can also hold other people's data.
- **Erasure:** it replaces the value with `[ERASED]` in every stored event, in the text sent to the model, and in every flag. The erasure log keeps the date, the counts, the request reference and a one-way SHA-256 fingerprint of the value, never the value itself. Erasure covers this store only; the report names the source systems where the same request must be carried out.
- **Limits:** a name can match other people with the same name, so the most specific value should be used. A value written differently (for example a nickname) is not found.

## The SDK

`ai_compliance` wraps the same engine for developers: `Guard.protect` (mask before the model), `Guard.restore` (real values back), `Guard.log` (store the turn and return its flags), `check` and `find_person`. It installs with `pip install -e .` and runs inside the bank's own network; it sends nothing anywhere.

## Severity

| Severity | Signals |
|---|---|
| Critical | Passwords and PINs, API keys, private keys |
| High | Special-category and criminal data, national ID numbers, card numbers, IBANs, revealed hidden instructions, injection hidden in a document |
| Medium | Email, phone, address, date of birth, injection attempt from a user |
| Low | Name, age, IP address, nationality, place |

Data the AI disclosed without being given it goes up one level.

## Accuracy

**1. Personal data in labelled text, held-out test.** Microsoft Presidio research `synth_dataset_v2.json` (MIT licence): 1,500 synthetic sentences in which every personal-data value is labelled. Every third sentence (500) was used while building the detectors. The other **1,000 were held out and run once** at the end.

| | Development (500) | **Held-out test (1,000)** |
|---|---|---|
| Labelled values found (recall) | 72% | **72%** (1,097 of 1,527) |
| Detections that were correct (precision) | 88% | **88%** (1,171 of 1,332) |

By type on the test set: cards 100%, emails 100%, national IDs 100%, IP addresses 100%, ages 94%, IBANs 93%, phone numbers 83%, names 74%, street addresses 68%, places 53%, nationality, religion or political group 47%.

The same numbers on both halves suggest the rules were not fitted to the development sentences.

**2. Hand-labelled conversations.** 24 conversations (39 events) written for this project, covering what the Presidio data does not label: special categories, passwords, keys, injection and disclosure. 30 of 30 expected signals found, 2 false alarms ("Can I use my fingerprint to log in?" read as biometric data; "Ranelagh" read as a name), 15 of 17 events that should be clean stayed clean. These were written while the detectors were being built, so the result is optimistic.

**3. Real AI traffic.** The real-data runs of the customer help agent (real customer questions from Banking77, and real attacks from Tensor Trust and BIPIA) were processed as events. A hand review of the flags led to five general fixes: phrases like "Access Granted" read as names, "my PIN was blocked" read as a PIN, binary code read as a card number, languages read as nationalities, and the AI repeating a customer's own record read as a disclosure.

## Limitations

1. **About one personal-data value in four is missed**, mostly unusual address formats, bare postcodes, names in lower case and some phone formats. A missed value leaves no flag, so this layer reduces risk but cannot guarantee that no personal data passes.
2. **Special categories use word lists.** They miss informal or indirect wording ("I have chemotherapy on Monday" is caught; "my chemo starts Monday" and "my treatment starts Monday" are not) and can fire on a topic that reveals nothing about a person. They are tested only on the 24 hand-written conversations, not on an independent labelled set.
3. **Names in stories are flagged.** Fictional names inside attack prompts ("play the role of Kevin") are flagged as names. A reviewer can mark them "not a concern".
4. **The test data is synthetic and mostly English.** The Presidio sentences are generated from templates, and many addresses and names are non-Irish. Real customer messages are messier. Irish formats are covered by the PPS, Eircode and phone rules, but no labelled Irish dataset was available to measure them.
5. **No legal judgement.** Whether processing is lawful depends on the purpose, the lawful basis, consent, contracts and whether the AI system is high-risk under the EU AI Act. The tool sees none of these. It points to review areas only.
6. **Names in other languages are not detected.** The language model is English, so it is switched off for text in another language (it was reading German nouns as names). Names in a French or German message are missed.
7. **One reviewer.** The labels on the hand-written conversations come from one person.
