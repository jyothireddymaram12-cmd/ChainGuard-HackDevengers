from flask import Flask, jsonify, request, send_from_directory
import re
from pathlib import Path
from urllib.parse import urlparse
import os
import sqlite3
import json
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session

ROOT = Path(__file__).resolve().parent

app = Flask(__name__, static_folder=str(ROOT), static_url_path="")
app.secret_key = os.getenv("CHAIN_GUARD_SECRET", "dev-only-change-this-secret")
DB_PATH = ROOT / "chainguard.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        input_type TEXT NOT NULL,
        input_preview TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        signals_json TEXT,
        ai_explanation TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)
    conn.commit()
    conn.close()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return fn(*args, **kwargs)
    return wrapper

init_db()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")

def gemini_text(prompt):
    if not GEMINI_API_KEY:
        return None
    try:
        from google import genai
        client = genai.Client(api_key=GEMINI_API_KEY)
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt
        )
        return (response.text or "").strip()
    except Exception as exc:
        print("Gemini error:", exc)
        return None

RULES = [
    (r"(forward|share|send).{0,70}(10|5|20|15|people|contacts|groups|friends)", 25,
     "Viral forwarding pressure",
     "The message asks you to forward or share it with multiple people, a common way scam content spreads."),
    (r"(won|winner|prize|reward|cashback|lottery|₹\s?[\d,]+|free money|gift|claim)", 20,
     "Reward or money claim",
     "Unexpected prizes or money claims can be used to trigger excitement before a victim clicks or pays."),
    (r"(urgent|immediately|within \d+|act now|expires?|last chance|today only|hurry|blocked today)", 15,
     "Urgency / pressure tactic",
     "Time pressure can stop people from pausing to verify a message through an official channel."),
    (r"(otp|one[- ]time password|pin|cvv|password|passcode|card number|bank details|upi pin)", 25,
     "Sensitive credential request",
     "Requests for OTPs, PINs, passwords or card details are a major warning sign."),
    (r"(pay|payment|transfer|deposit|fee|send money|qr|upi|refund fee)", 18,
     "Financial action requested",
     "The message asks for or refers to a financial action that should be independently verified."),
    (r"(https?://|www\.|bit\.ly|tinyurl|t\.co/|is\.gd/)", 15,
     "Link detected",
     "Links deserve extra caution, especially when the surrounding message asks for money, credentials or urgent action."),
    (r"(apk|install|download|app)", 15,
     "Download / app request",
     "Unexpected app or file downloads can expose users to malicious software.")
]

def analyze_message(text):
    score = 0
    signals = []
    for pattern, points, label, explanation in RULES:
        if re.search(pattern, text, re.I | re.S):
            score += points
            signals.append({"label": label, "explain": explanation})

    if not signals:
        score = 6
    score = min(99, score)

    if score >= 55:
        level = "high"
        title = "High risk"
        verdict = "Multiple suspicious signals were detected. Pause before clicking, paying, replying, or forwarding."
        recommendation = "Do not forward or follow the message. Verify the claim using the organization's official website/app or a trusted phone number."
    elif score >= 25:
        level = "medium"
        title = "Suspicious"
        verdict = "The message contains warning signs. Treat it cautiously and verify the sender or claim independently."
        recommendation = "Avoid sharing sensitive information or making payments until you have verified the message through an official channel."
    else:
        level = "low"
        title = "Low risk"
        verdict = "No strong scam pattern was detected by this prototype. That does not guarantee the message is safe."
        recommendation = "Still verify unfamiliar links, payment requests, and claims before taking action."

    explanation = " ".join(s["explain"] for s in signals[:3]) if signals else (
        "No major social-engineering pattern matched the current rules. ChainGuard cannot prove that a message is safe."
    )

    return {
        "score": score, "level": level, "title": title,
        "verdict": verdict, "recommendation": recommendation,
        "explanation": explanation,
        "signals": [{"label": s["label"]} for s in signals]
    }

def analyze_url(url):
    raw = url.strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw

    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    full = raw.lower()

    score = 0
    signals = []

    if parsed.scheme != "https":
        score += 18
        signals.append("Not using HTTPS")

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 28
        signals.append("IP address used as destination")

    if len(raw) > 100:
        score += 12
        signals.append("Unusually long URL")

    if host.count(".") >= 3:
        score += 10
        signals.append("Unusually deep subdomain structure")

    if "@" in raw:
        score += 18
        signals.append("URL contains @ character")

    if re.search(r"(login|verify|secure|account|wallet|payment|claim|reward|gift|otp|bank)", full):
        score += 14
        signals.append("Sensitive-action keywords in URL")

    if re.search(r"(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|shorturl)", host):
        score += 12
        signals.append("URL shortener detected")

    if re.search(r"xn--|[^\x00-\x7F]", host):
        score += 16
        signals.append("Potentially deceptive internationalized domain")

    if re.search(r"[-_]{2,}", host):
        score += 6
        signals.append("Unusual domain character pattern")

    score = min(score, 99)
    level = "high" if score >= 55 else "medium" if score >= 25 else "low"

    return {
        "url": raw,
        "host": host,
        "score": score,
        "level": level,
        "signals": signals,
        "message": (
            "Multiple URL warning signs detected. Avoid logging in or entering payment details."
            if level == "high" else
            "Some URL warning signs were detected. Verify the destination independently."
            if level == "medium" else
            "No major URL warning pattern was detected by this prototype. This does not guarantee safety."
        )
    }



@app.post("/api/auth/signup")
def signup():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if not name or not email or len(password) < 6:
        return jsonify({"error": "Name, valid email and a 6+ character password are required"}), 400
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO users(name,email,password_hash) VALUES(?,?,?)",
            (name, email, generate_password_hash(password))
        )
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "An account with this email already exists"}), 409
    conn.close()
    session["user_id"] = user_id
    session["user_name"] = name
    session["user_email"] = email
    return jsonify({"user": {"id": user_id, "name": name, "email": email}})

@app.post("/api/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid email or password"}), 401
    session["user_id"] = user["id"]
    session["user_name"] = user["name"]
    session["user_email"] = user["email"]
    return jsonify({"user": {"id": user["id"], "name": user["name"], "email": user["email"]}})

@app.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})

@app.get("/api/auth/me")
def me():
    if "user_id" not in session:
        return jsonify({"user": None})
    return jsonify({"user": {
        "id": session["user_id"],
        "name": session["user_name"],
        "email": session["user_email"]
    }})

@app.get("/api/scans")
@login_required
def scans():
    conn = get_db()
    rows = conn.execute(
        """SELECT id,input_type,input_preview,risk_score,risk_level,signals_json,ai_explanation,created_at
           FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 30""",
        (session["user_id"],)
    ).fetchall()
    conn.close()
    items = []
    for row in rows:
        item = dict(row)
        try: item["signals"] = json.loads(item["signals_json"] or "[]")
        except: item["signals"] = []
        del item["signals_json"]
        items.append(item)
    return jsonify({"scans": items})

@app.post("/api/scans")
@login_required
def save_scan():
    data = request.get_json(silent=True) or {}
    input_type = str(data.get("input_type", "Message"))
    preview = str(data.get("input_preview", "")).strip()
    score = int(data.get("risk_score", 0))
    level = str(data.get("risk_level", "low"))
    signals = data.get("signals", [])
    ai_explanation = str(data.get("ai_explanation", ""))
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO scans(user_id,input_type,input_preview,risk_score,risk_level,signals_json,ai_explanation)
           VALUES(?,?,?,?,?,?,?)""",
        (session["user_id"], input_type, preview[:500], score, level, json.dumps(signals), ai_explanation[:8000])
    )
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return jsonify({"id": scan_id})

@app.post("/api/ai-explain")
def ai_explain():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()
    result = data.get("result") or {}
    if not message:
        return jsonify({"error": "Message is required"}), 400
    if len(message) > 10000:
        return jsonify({"error": "Message is too long"}), 400

    signals = ", ".join(
        s.get("label", "") for s in result.get("signals", []) if isinstance(s, dict)
    )
    prompt = f"""
You are ChainGuard AI, a cybersecurity safety assistant.
Analyze the user's message for social-engineering/scam risk.
This is NOT a medical, legal, or financial-advice system.
Do not tell the user to share OTPs, PINs, passwords, CVVs, seed phrases, or other secrets.
Do not claim certainty. Explain why the detected signals matter.
Return concise plain text with exactly these headings:
WHY IT LOOKS SUSPICIOUS:
WHAT TO DO NOW:
WHAT NOT TO DO:
VERIFICATION TIP:

Rule-engine score: {result.get("score", "unknown")}/100
Detected signals: {signals or "none"}

Message to analyze:
{message}
"""
    ai = gemini_text(prompt)
    if not ai:
        ai = (
            "WHY IT LOOKS SUSPICIOUS:\n"
            f"The security engine detected: {signals or 'no major warning pattern'}.\n\n"
            "WHAT TO DO NOW:\n"
            "Pause and verify the claim using the organization's official app, website, or trusted contact.\n\n"
            "WHAT NOT TO DO:\n"
            "Do not click unfamiliar links, forward the message, pay money, or share OTPs, PINs, passwords, or card details.\n\n"
            "VERIFICATION TIP:\n"
            "Open the official service yourself rather than using a link or phone number supplied by the message."
        )
    return jsonify({"ai": ai, "live": bool(GEMINI_API_KEY)})

@app.post("/api/ai-chat")
def ai_chat():
    data = request.get_json(silent=True) or {}
    question = str(data.get("question", "")).strip()
    context = str(data.get("context", "")).strip()
    if not question:
        return jsonify({"error": "Question is required"}), 400
    if len(question) > 4000:
        return jsonify({"error": "Question is too long"}), 400

    prompt = f"""
You are ChainGuard AI, a defensive cybersecurity assistant for everyday users.
Answer the user's question simply and practically.
Focus on scam detection, phishing, suspicious messages, account safety, OTP safety,
payment scams, malicious links, and digital safety.
Never ask for or encourage sharing passwords, OTPs, PINs, CVVs, recovery codes,
bank credentials, private keys, or other secrets.
If the user appears to be in immediate financial fraud, tell them to contact their
bank/service through an official channel and the appropriate official cyber-fraud
reporting service in their country.
Do not claim you verified a URL unless a tool actually did so.
Keep the answer under 180 words.

Current scan context:
{context or "No scan context"}

User question:
{question}
"""
    ai = gemini_text(prompt)
    if not ai:
        ai = (
            "I’m running in demo fallback mode because a Gemini API key is not configured. "
            "For a suspicious message, pause, do not click or pay, never share OTP/PIN/password "
            "details, and verify the claim through the service's official app or website."
        )
    return jsonify({"answer": ai, "live": bool(GEMINI_API_KEY)})


@app.get("/")
def home():
    return send_from_directory(ROOT, "index.html")

@app.post("/api/analyze-url")
def analyze_url_endpoint():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    if len(url) > 5000:
        return jsonify({"error": "URL is too long"}), 400
    return jsonify(analyze_url(url))

@app.post("/api/analyze")
def analyze():
    data = request.get_json(silent=True) or {}
    text = str(data.get("message", "")).strip()
    if not text:
        return jsonify({"error": "Message is required"}), 400
    if len(text) > 10000:
        return jsonify({"error": "Message is too long"}), 400
    return jsonify(analyze_message(text))

if __name__ == "__main__":
    print("ChainGuard running at http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
