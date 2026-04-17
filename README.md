# Cybersecurity and National Defence -- Technical Project

## Topic C -- Phishing Detection and Explanation Engine

---

## Group Members
- Alp Kale -- s325632
- Ege Kaya -- s326635
- Dogan Ege Bulte -- s325192

---

## Project Description
This project analyzes messages (email/SMS/social media) and score how "phishy" they look using explicit rules—no AI/ML.

Sender name/address
Subject/body text
Links (display text vs actual URL)
Attachments

Detection rules:
-Each rule checks for suspicious patterns and assigns a weight if triggered:

-Lookalike domain (weight: 30)

-Sender is no-reply@rnicrosoft.com (looks like microsoft.com)
 Evidence: "sender domain rnicrosoft.com resembles microsoft.com"

-Urgent language (weight: 20)
 Subject/body contains: "urgent", "immediately", "today", "account will be disabled"
 Evidence: "subject contains: urgent; body contains: today, immediately"

-Credential request (weight: 25)
 Text mentions: "password", "reset your password", "username", "login"
 Evidence: "credential-related terms found: password, reset your password"

-Non-HTTPS link (weight: 20)
 Link uses http:// instead of https://
 Evidence: "link http://bad-site.com uses http instead of https"

-Dangerous attachment (weight: 25)
 File type: .xlsm (macro-enabled Excel), .exe, .zip
 Evidence: "attachment invoice.xlsm has dangerous type spreadsheet_macro_enabled"

Scoring:
Project adds up the weights of all triggered rules.
Total score → classification: (0-19: legitimate, 20-49: suspicious, 50+: phishing)
---

## Project Structure
Describe briefly the files and folders included in the submission.

Example:
- `main.py`: main program
- `src/`: Python modules used by the program
- `input/`: example input files
- `output/`: example output files
- `requirements.txt`: list of required Python libraries

---

## Python Version
Specify the Python version used for the project.

Python 3.14

---

## Required Libraries
Explain whether the project uses only the Python standard library or also external libraries.

Example 1:
This project uses only the Python standard library.

Example 2:
This project requires the libraries listed in `requirements.txt`.

---

## Creating a Virtual Environment
A virtual environment is recommended in order to install the project libraries in an isolated way.

### Linux / macOS
```bash
python -m venv .venv
source .venv/bin/activate
```

### Windows
```bash
python -m venv .venv
.venv\Scripts\activate
```