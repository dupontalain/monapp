import os
import sqlite3
import imaplib
import email
import base64
from email.header import decode_header
from flask import Flask, request, render_template, redirect, url_for, jsonify
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import jwt
from datetime import datetime

# Chargement des variables d'environnement
load_dotenv()
DB_NAME = os.getenv("DB_NAME")
FERNET_KEY = os.getenv("FERNET_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")
WEBAPP_URL = os.getenv("WEBAPP_URL")

app = Flask(__name__)
fernet = Fernet(FERNET_KEY.encode())

# Connexion à la base de données
def get_db():
    return sqlite3.connect(DB_NAME)

# Récupération et déchiffrement du mot de passe IMAP
def get_credentials(email):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT password FROM webmails WHERE email = ?", (email,))
    row = cur.fetchone()
    db.close()
    if row:
        return fernet.decrypt(row[0]).decode()
    return None

# Récupération des e-mails
def fetch_emails(mail, folder="INBOX", limit=10):
    messages = []
    try:
        mail.select(folder)
        typ, data = mail.search(None, 'ALL')
        mail_ids = data[0].split()[-limit:]

        for mail_id in reversed(mail_ids):
            typ, msg_data = mail.fetch(mail_id, '(RFC822)')
            msg = email.message_from_bytes(msg_data[0][1])
            subject = decode_header(msg.get("Subject"))[0][0]
            subject = subject.decode() if isinstance(subject, bytes) else subject
            sender = msg.get("From")
            date = msg.get("Date")
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode(errors="ignore")
                        break
                else:
                    body = ""
            else:
                body = msg.get_payload(decode=True).decode(errors="ignore")
            messages.append({
                "subject": subject,
                "from": sender,
                "date": date,
                "body": body[:300] + "..." if len(body) > 300 else body
            })
    except Exception as e:
        print(f"[ERREUR IMAP] {e}")
    return messages

@app.route("/")
def home():
    token = request.args.get("token")
    if not token:
        return "⛔ Accès interdit : token manquant."

    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = decoded["user_id"]
    except jwt.ExpiredSignatureError:
        return "⛔ Token expiré."
    except jwt.InvalidTokenError:
        return "⛔ Token invalide."

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT email FROM webmails WHERE active = 1")
    emails = [row[0] for row in cur.fetchall()]
    db.close()

    return render_template("home.html", emails=emails, user_id=user_id)


@app.route("/inbox")
def inbox():
    email_addr = request.args.get("email")
    folder = request.args.get("folder", "INBOX")
    user_id = request.args.get("user_id")

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT 1 FROM licenses WHERE user_id = ? AND expires_at > ?", (user_id, datetime.utcnow().isoformat()))
    if not cur.fetchone():
        return "⛔ Accès non autorisé ou licence expirée."

    password = get_credentials(email_addr)
    if not password:
        return "Mot de passe introuvable pour cet email."

    try:
        mail = imaplib.IMAP4_SSL("imap."+email_addr.split("@")[1])
        mail.login(email_addr, password)
    except Exception as e:
        return f"Erreur de connexion à la boîte mail : {e}"

    mails = fetch_emails(mail, folder)
    mail.logout()
    return render_template("inbox.html", mails=mails, email=email_addr, folder=folder)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
