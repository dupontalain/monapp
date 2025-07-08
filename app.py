import sqlite3
import imaplib
import email
import jwt
import os
import base64
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from email.header import decode_header

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
FERNET_KEY = os.getenv("FERNET_KEY")
DB_NAME = os.getenv("DB_NAME", "imap_bot.db")
fernet = Fernet(FERNET_KEY)

app = Flask(__name__)

@app.route("/")
def home():
    return "✅ App Flask déployée avec succès !"

# 🔒 Générer un JWT sécurisé après vérif licence + mot de passe
@app.route("/auth")
def auth():
    user_id = request.args.get("user_id")
    email_addr = request.args.get("email")

    if not user_id or not email_addr:
        return jsonify({"success": False, "error": "Paramètres manquants"}), 400

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute("SELECT expiration FROM licenses WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    if not row:
        return jsonify({"success": False, "error": "Licence non trouvée"}), 403

    if datetime.strptime(row[0], "%Y-%m-%d") < datetime.now():
        return jsonify({"success": False, "error": "Licence expirée"}), 403

    # 🔐 Récupération mot de passe chiffré
    c.execute("SELECT password FROM webmails WHERE email = ? AND active = 1", (email_addr,))
    row = c.fetchone()
    if not row:
        return jsonify({"success": False, "error": "Webmail non trouvé"}), 404

    encrypted_password = row[0]
    try:
        decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
    except Exception as e:
        return jsonify({"success": False, "error": "Erreur de déchiffrement"}), 500

    imap_host = get_imap_host(email_addr)

    token = jwt.encode({
        "user_id": user_id,
        "email": email_addr,
        "imap": imap_host,
        "password": decrypted_password,
        "exp": datetime.utcnow() + timedelta(minutes=15)
    }, JWT_SECRET, algorithm="HS256")

    return jsonify({"success": True, "token": token})

def get_imap_host(email):
    domain = email.split("@")[-1].lower()
    return {
        "gmail.com": "imap.gmail.com",
        "outlook.com": "imap-mail.outlook.com",
        "yahoo.com": "imap.mail.yahoo.com",
        "free.fr": "imap.free.fr",
        "orange.fr": "imap.orange.fr",
        "laposte.net": "imap.laposte.net"
    }.get(domain, f"imap.{domain}")
# (ajoute ceci à la suite directe du code précédent que je t’ai envoyé)

def decode_token(request):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, "Token manquant ou invalide"

    token = auth_header.replace("Bearer ", "")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload, None
    except Exception as e:
        return None, str(e)

# 📂 Liste des dossiers IMAP
@app.route("/folders", methods=["GET"])
def folders():
    payload, err = decode_token(request)
    if err:
        return jsonify({"success": False, "error": err}), 401

    try:
        mail = imaplib.IMAP4_SSL(payload["imap"])
        mail.login(payload["email"], payload["password"])
        status, folders = mail.list()
        folder_list = []

        for folder in folders:
            parts = folder.decode().split(' "/" ')
            if len(parts) > 1:
                folder_list.append(parts[1].replace('"', ''))

        return jsonify({"success": True, "folders": folder_list})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# 📬 Récupère les e-mails d’un dossier donné avec pagination
@app.route("/emails", methods=["POST"])
def emails():
    payload, err = decode_token(request)
    if err:
        return jsonify({"success": False, "error": err}), 401

    data = request.json
    folder = data.get("folder")
    page = int(data.get("page", 1))
    per_page = 10
    start_index = (page - 1) * per_page

    try:
        mail = imaplib.IMAP4_SSL(payload["imap"])
        mail.login(payload["email"], payload["password"])
        mail.select(f'"{folder}"', readonly=True)

        status, data = mail.search(None, 'ALL')
        mail_ids = data[0].split()
        mail_ids = list(reversed(mail_ids))
        selected_ids = mail_ids[start_index:start_index + per_page]

        result = []
        for mail_id in selected_ids:
            status, msg_data = mail.fetch(mail_id, "(RFC822)")
            msg = email.message_from_bytes(msg_data[0][1])

            subject, _ = decode_header(msg.get("Subject", ""))[0]
            if isinstance(subject, bytes):
                subject = subject.decode(errors="ignore")

            sender, _ = decode_header(msg.get("From", ""))[0]
            if isinstance(sender, bytes):
                sender = sender.decode(errors="ignore")

            date = msg.get("Date", "")
            snippet = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/plain":
                        snippet = part.get_payload(decode=True).decode(errors="ignore")
                        break
            else:
                snippet = msg.get_payload(decode=True).decode(errors="ignore")

            result.append({
                "subject": subject,
                "from": sender,
                "date": date,
                "snippet": snippet[:120]
            })

        return jsonify({"success": True, "emails": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# Lancer l’app si en local
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
