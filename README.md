# Email Forensics Web Tool (FastAPI)

Stateless web tool to analyze `.eml` files for authenticity checks, phishing indicators, Google infrastructure detection, URL/attachment risks, and an overall risk score.

## Folder Structure

```text
email/
  app/
    __init__.py
    main.py
    analyzers/
      __init__.py
      email_analyzer.py
  templates/
    upload.html
    result.html
  static/
    style.css
  requirements.txt
  README.md
```

## Features

- Upload and parse `.eml` files
- Extract: From, To, Subject, Date, Return-Path, full headers, plain/html body
- Header checks: Received chain, origin IP, SPF, DKIM, DMARC, spoofing mismatch
- Google classification:
  - Gmail
  - Google Workspace
  - Other
- Domain intelligence:
  - Public vs custom domain
  - Suspicious domain pattern flags
- URL analysis:
  - IP-based links
  - Lookalike domains
  - Numeric-heavy hostnames
- Attachment analysis:
  - File name, MIME type, size, SHA256
- Risk score:
  - SPF fail +30
  - DKIM missing +20
  - Suspicious URLs +30
  - From/Return-Path mismatch +20
  - Non-Google infrastructure +10
- Bonus:
  - Suspicious findings highlighted in red
  - Origin IP geolocation (best-effort via free API)

## Run Instructions

1. Open terminal in `email` directory.
2. Create and activate a virtual environment:
   - Windows PowerShell:
     - `python -m venv .venv`
     - `.venv\Scripts\Activate.ps1`
3. Install dependencies:
   - `pip install -r requirements.txt`
4. Start server:
   - `uvicorn app.main:app --reload`
5. Open:
   - `http://127.0.0.1:8000`

## Notes

- No database is used.
- The app is stateless.
- SPF/DKIM/DMARC are derived from available email headers (`Authentication-Results`, `Received-SPF`, `DKIM-Signature`), so results depend on source email quality.
- WHOIS/newly-registered domain lookup is marked optional and not enabled by default.
