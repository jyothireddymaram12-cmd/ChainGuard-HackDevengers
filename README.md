# ChainGuard — Full Hack Devengers Prototype

## Run in VS Code (Windows)

Open this folder in VS Code, then Terminal → New Terminal.

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open:

http://127.0.0.1:5000

For this full-stack version, **do not use Live Server**. Flask serves the site and `/api/analyze`.

## Demo examples
High risk:
`Congratulations! You have won ₹10,000. Forward this to 10 people within 5 minutes and click https://claim-reward.example to receive your prize.`

Bank scam:
`Your bank account will be blocked today. Verify immediately by sharing your OTP and clicking https://secure-account.example.`

Normal:
`Hey! The library workshop starts at 10 AM tomorrow. Please bring your college ID and notebook.`

## Important
This prototype flags suspicious patterns; a score is not proof that a message is malicious. A production version should add validated threat-intelligence feeds, safe URL reputation checks, privacy controls, evaluation, and official reporting flows.

The current core uses deterministic rules so the demo is reliable. An LLM can be added server-side later to explain already-detected signals in simple language. Never send OTPs, PINs, passwords or other secrets to an AI model.


## New demo features
- **URL analyzer:** checks HTTPS, IP-host URLs, URL length, deep subdomains, @ characters, sensitive keywords, shorteners and other suspicious patterns.
- **Screenshot scanner:** uses browser OCR to extract text from a screenshot and send the extracted text through the same message analyzer.
- **Quick Response center:** shows what a user should do after detecting a scam.
- **Three scan modes:** Message / URL / Screenshot.

### Screenshot OCR note
The OCR library is loaded from a public CDN, so screenshot extraction requires an internet connection during the demo. If it is unavailable, paste the message manually.


## Final additions
- Local security dashboard with scan counts
- Recent scan history stored only in the browser
- Threat-pattern activity bars
- Export security report as TXT
- Share/copy result
- No login or database required for the demo

## Suggested 3-minute demo
1. Start with the fake reward message.
2. Show the high-risk score and four warning signals.
3. Show the AI-style explanation and action guidance.
4. Switch to URL and analyze a suspicious URL.
5. Switch to Screenshot and OCR a scam screenshot.
6. Open Security Dashboard and show the scan history and threat activity.
7. Export the report.


## 🤖 Live AI integration

This build supports a real Gemini AI layer on the **server side**. Google recommends the official `google-genai` SDK for Python, and its current API supports `models.generate_content` for text generation. citeturn0search10turn0search0

### Setup
1. Get a Gemini API key from Google AI Studio.
2. In the VS Code terminal, set the key for the current PowerShell session:
```powershell
$env:GEMINI_API_KEY="YOUR_KEY_HERE"
```
3. Install the updated dependencies:
```powershell
pip install -r requirements.txt
```
4. Start:
```powershell
python app.py
```

The key stays on the Flask server and is **not placed in HTML/JavaScript**.

### What the AI does
- Explains why the rule engine flagged a message.
- Gives safe next steps.
- Answers cybersecurity questions in the ChainGuard AI panel.
- Uses the detected signals and risk score as context rather than blindly replacing the deterministic security checks.

If no API key is configured, ChainGuard still works in a clearly labeled fallback mode.

**Never put a real API key into GitHub or frontend JavaScript.**


## 🗄️ Real database + authentication

The final build now uses **SQLite + Flask sessions** for real account storage in the prototype.

### Database tables
- `users`: name, email, securely hashed password, created time
- `scans`: user ID, scan type, preview, risk score/level, detected signals, AI explanation, timestamp

The SQLite file `chainguard.db` is created automatically the first time `app.py` runs.

### Run
```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open:
`http://127.0.0.1:5000`

### Important security note
Passwords are stored as hashes using Werkzeug's password hashing utilities, not as plain text. The app uses a Flask session cookie for login state. For a production deployment, use a strong random `CHAIN_GUARD_SECRET`, HTTPS, secure cookie settings, CSRF protection, rate limiting, email verification, password reset, and a managed database such as PostgreSQL.

Do not commit `chainguard.db`, `.env`, or API keys to GitHub.


## Visual theme
The UI uses a custom Nebula cybersecurity palette: deep navy, electric violet, cyan, and distinct red/orange/green risk states. The theme is applied consistently across authentication, dashboard, scanner, AI assistant, and reports.


## New UI features
- Safety Center with a persistent 5-step security checklist
- Safety Shield progress indicator
- Scam Playbook cards that send focused questions to ChainGuard AI
- Updated hero feature strip and premium Nebula visual treatment
