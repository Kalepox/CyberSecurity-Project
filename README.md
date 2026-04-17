# Cybersecurity and National Defence -- Technical Project

## Topic C -- Phishing Detection and Explanation Engine

---

## Group Members

- Alp Kale -- s325632
- Ege Kaya -- s326635
- Dogan Ege Bulte -- s325192

---

## Project Description

This project implements a rule-based phishing detection and explanation engine.
The program reads a JSON file containing messages from different communication
channels, applies a set of explicit detection rules to
each message, and produces a JSON output with a classification, a numerical risk
score, and a list of triggered indicators with evidence strings explaining why
each rule fired.

---

## Project Structure

- `main.py` — main entry point; parses arguments, loads input JSON, writes output JSON
- `src/knowledge_base.py` — constants: trusted domains, keyword lists, weights, thresholds
- `src/indicators.py` — 13 indicator functions
- `src/engine.py` — orchestrates indicator execution, scoring, and output construction
- `input/messages.json` — example input file with 5 messages
- `output/output.json` — expected output for the example input
- `requirements.txt` — list of required Python libraries (empty, standard library only)

---

## Python Version

Python 3.11 or later.

---

## Required Libraries

This project uses only the Python standard library.
No external libraries are required.

---

## Installation

No installation is required beyond a standard Python 3.11+ environment.

### Optional: create a virtual environment

**Linux / macOS**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows**
```bash
python -m venv .venv
.venv\Scripts\activate
```

---

## How to Run

```bash
python3 main.py --input input/messages.json --output output/output.json
```

`--input` may point to any JSON file following the message schema described below.
The output file is created automatically.

---

## Input Format

The input is a single JSON file named `messages.json` containing a list of messages.
Each message has the following fields:

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique message identifier |
| `channel` | string | `email`, `sms`, or `social` |
| `sender_name` | string | Display name of the sender |
| `sender_address` | string | Email address, phone number, or social handle |
| `subject` | string | Message subject (may be empty for SMS/social) |
| `body` | string | Message body text |
| `links` | list | Optional list of `{display_text, actual_url}` objects |
| `attachments` | list | Optional list of `{filename, type}` objects |

Missing `links` or `attachments` fields are treated as empty lists.

---

## Output Format

The output JSON contains two sections:

- `summary` — total message counts by classification and the highest risk score
- `results` — per-message result with `id`, `channel`, `classification`, `risk_score`,
  and `triggered_indicators` (each with `name`, `weight`, and `evidence`)

---

## Detection Rules

The engine implements 13 indicators. Each triggered indicator contributes its weight
to the total risk score. The final classification is derived from the score using the
thresholds documented below.

| Indicator | Weight | Description |
|---|---|---|
| `suspicious_or_unknown_sender` | 20 | Email domain not in trusted set; SMS from long-form number; social handle inconsistent with claimed name |
| `lookalike_domain` | 30 | Sender or link domain resembles a trusted domain (Levenshtein distance <= 2) |
| `urgent_language` | 20 | Subject or body contains urgency keywords |
| `credential_request` | 30 | Subject or body asks for authentication information |
| `payment_request` | 25 | Subject or body requests a financial action |
| `suspicious_link` | 20 | Link domain has a suspicious TLD or excessive hyphens |
| `non_https_link` | 20 | At least one link uses HTTP instead of HTTPS |
| `dangerous_attachment` | 25 | At least one attachment has a dangerous type (executable, macro-enabled, etc.) |
| `authority_impersonation` | 25 | Sender name claims a known brand but address does not match the brand's legitimate domain |
| `external_link_inconsistent` | 20 | Link domain is unrelated to the sender's own domain (email only) |
| `display_text_destination_mismatch` | 20 | Link display text implies a trusted brand but actual URL points elsewhere |
| `suspicious_phone_pattern` | 15 | SMS sender is a long-form phone number rather than a short service code (SMS only) |
| `suspicious_shortening_service` | 15 | At least one link uses a known URL shortening service |

### Classification thresholds

| Score range | Classification |
|---|---|
| 0 - 19 | `legitimate` |
| 20 - 49 | `suspicious` |
| 50 and above | `phishing` |

---

## Example Input and Output

The example input is `input/messages.json`.
The corresponding expected output is `output/output.json`.

Classifications produced on the example input:

| ID | Channel | Classification | Score |
|---|---|---|---|
| M1 | email | phishing | 205 |
| M2 | email | legitimate | 0 |
| M3 | email | phishing | 90 |
| M4 | sms | phishing | 75 |
| M5 | social | phishing | 50 |

---

## Edge Cases

**Missing optional fields:** if `links` or `attachments` are absent from a message,
they are treated as empty lists. No indicator that relies on links or attachments
will fire.

---
 
## Limitations

The lookalike domain check uses Levenshtein edit distance against a fixed set of
trusted domains. It does not detect Unicode homoglyph attacks (e.g. Cyrillic
characters that visually resemble Latin letters), as these require Unicode
normalisation beyond the scope of this project.
