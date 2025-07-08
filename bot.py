import imaplib
import email
import sqlite3
import base64
import os
import json
import urllib.parse
from dotenv import load_dotenv
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from email.header import decode_header
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update, WebAppInfo
from telegram.ext import (
    ApplicationBuilder, CommandHandler, CallbackQueryHandler, ContextTypes,
    MessageHandler, filters, ConversationHandler
)
from flask import Flask, render_template, request, jsonify
import threading

# ═══════════════════════════════════════════════════════════════════════════════
#                              CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

load_dotenv()

# Variables d'environnement
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
ADMIN_IDS = [int(id.strip()) for id in os.getenv('ADMIN_IDS', '').split(',') if id.strip()]
ADMIN_LOG_CHAT_ID = int(os.getenv('ADMIN_LOG_CHAT_ID'))
DB_NAME = os.getenv('DB_NAME', 'imap_bot.db')
FERNET_KEY = os.getenv("FERNET_KEY")
WEBAPP_URL = os.getenv('WEBAPP_URL', 'https://votre-domaine.com')

# Vérifications
required_vars = {
    'TELEGRAM_BOT_TOKEN': TELEGRAM_BOT_TOKEN,
    'ADMIN_IDS': ADMIN_IDS,
    'ADMIN_LOG_CHAT_ID': ADMIN_LOG_CHAT_ID,
    'FERNET_KEY': FERNET_KEY
}

for var_name, var_value in required_vars.items():
    if not var_value:
        raise ValueError(f"{var_name} n'est pas défini dans le fichier .env")

fernet = Fernet(FERNET_KEY)

# ═══════════════════════════════════════════════════════════════════════════════
#                              BASE DE DONNÉES
# ═══════════════════════════════════════════════════════════════════════════════

conn = sqlite3.connect(DB_NAME, check_same_thread=False)
c = conn.cursor()

# Création des tables
tables = [
    """CREATE TABLE IF NOT EXISTS licenses (
        license TEXT PRIMARY KEY, 
        user_id INTEGER, 
        expires_at TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS webmails (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        name TEXT, 
        category TEXT, 
        email TEXT, 
        password TEXT, 
        imap TEXT, 
        active INTEGER DEFAULT 1, 
        last_check TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS bans (
        user_id INTEGER PRIMARY KEY
    )"""
]

for table in tables:
    c.execute(table)
conn.commit()

# ═══════════════════════════════════════════════════════════════════════════════
#                              FLASK WEB APP
# ═══════════════════════════════════════════════════════════════════════════════

app_flask = Flask(__name__)

@app_flask.route('/')
def index():
    """Page d'accueil de la webapp"""
    user_id = request.args.get('user_id')
    email_addr = request.args.get('email')
    category = request.args.get('category')
    
    return render_template('index.html', 
                         user_id=user_id, 
                         email=email_addr, 
                         category=category)

@app_flask.route('/connect', methods=['POST'])
def connect_webmail():
    """Endpoint pour se connecter au webmail"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        email_addr = data.get('email')
        
        # Vérifier la licence
        c.execute("SELECT license, expires_at FROM licenses WHERE user_id = ?", (user_id,))
        license_data = c.fetchone()
        
        if not license_data:
            return jsonify({
                'success': False, 
                'error': 'Aucune licence trouvée pour cet utilisateur'
            })
        
        license, expires = license_data
        expires = datetime.fromisoformat(expires) if isinstance(expires, str) else expires
        
        if expires < datetime.now():
            return jsonify({
                'success': False, 
                'error': 'Votre licence a expiré'
            })
        
        # Récupérer les informations du webmail
        c.execute("SELECT email, password, imap FROM webmails WHERE email = ? AND active = 1", (email_addr,))
        webmail_data = c.fetchone()
        
        if not webmail_data:
            return jsonify({
                'success': False, 
                'error': 'Webmail non trouvé ou inactif'
            })
        
        email_addr, enc_pwd, imap_server = webmail_data
        pwd = fernet.decrypt(enc_pwd.encode()).decode()
        
        # Connexion IMAP
        try:
            imap = imaplib.IMAP4_SSL(imap_server)
            imap.login(email_addr, pwd)
            imap.select('inbox')
            
            # Récupérer les emails
            status, messages = imap.search(None, 'ALL')
            email_ids = messages[0].split()
            
            emails = []
            # Récupérer les 10 derniers emails
            for email_id in email_ids[-10:]:
                status, msg_data = imap.fetch(email_id, '(RFC822)')
                email_message = email.message_from_bytes(msg_data[0][1])
                
                # Décoder le sujet
                subject = decode_header(email_message["Subject"])[0][0]
                if isinstance(subject, bytes):
                    subject = subject.decode()
                
                # Récupérer l'expéditeur
                from_addr = email_message.get("From")
                
                # Récupérer la date
                date = email_message.get("Date")
                
                # Récupérer le contenu
                body = ""
                if email_message.is_multipart():
                    for part in email_message.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_payload(decode=True).decode()
                            break
                else:
                    body = email_message.get_payload(decode=True).decode()
                
                emails.append({
                    'id': email_id.decode(),
                    'subject': subject,
                    'from': from_addr,
                    'date': date,
                    'body': body[:200] + "..." if len(body) > 200 else body
                })
            
            imap.logout()
            
            return jsonify({
                'success': True,
                'emails': emails,
                'account': email_addr
            })
            
        except Exception as e:
            return jsonify({
                'success': False, 
                'error': f'Erreur de connexion IMAP: {str(e)}'
            })
            
    except Exception as e:
        return jsonify({
            'success': False, 
            'error': f'Erreur serveur: {str(e)}'
        })

# ═══════════════════════════════════════════════════════════════════════════════
#                              UTILITAIRES
# ═══════════════════════════════════════════════════════════════════════════════

class MessageDesign:
    """Classe pour gérer le design des messages"""
    
    @staticmethod
    def header(title, subtitle=""):
        """Crée un en-tête stylé"""
        line = "━" * 32
        if subtitle:
            return f"╭{line}╮\n│ {title:^30} │\n│ {subtitle:^30} │\n╰{line}╯"
        return f"╭{line}╮\n│ {title:^30} │\n╰{line}╯"
    
    @staticmethod
    def box(content, title=""):
        """Crée une boîte avec contenu"""
        line = "─" * 30
        if title:
            return f"┌{line}┐\n│ {title:^28} │\n├{line}┤\n{content}\n└{line}┘"
        return f"┌{line}┐\n{content}\n└{line}┘"
    
    @staticmethod
    def status_emoji(days_left):
        """Retourne l'emoji de statut selon les jours restants"""
        if days_left > 7:
            return "🟢", "PREMIUM ACTIF"
        elif days_left > 1:
            return "🟡", "EXPIRE BIENTÔT"
        elif days_left > 0:
            return "🟠", "EXPIRE AUJOURD'HUI"
        else:
            return "🔴", "LICENCE EXPIRÉE"

class DatabaseHelper:
    """Classe pour les opérations de base de données"""
    
    @staticmethod
    def is_banned(user_id):
        c.execute("SELECT 1 FROM bans WHERE user_id = ?", (user_id,))
        return c.fetchone() is not None
    
    @staticmethod
    def get_license(user_id):
        c.execute("SELECT license, expires_at FROM licenses WHERE user_id = ?", (user_id,))
        return c.fetchone()
    
    @staticmethod
    def get_active_webmails_count():
        c.execute("SELECT COUNT(*) FROM webmails WHERE active = 1")
        return c.fetchone()[0]
    
    @staticmethod
    def get_webmails_by_category(category):
        c.execute("SELECT email, password FROM webmails WHERE category = ? AND active = 1", (category,))
        return c.fetchall()

async def log(app, message, user_id="ID"):
    """Fonction de logging améliorée"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        log_msg = (
            f"📊 **SYSTÈME LOG**\n"
            f"{'─' * 25}\n"
            f"🕐 **Heure:** `{now}`\n"
            f"👤 **ID:** `{user_id}`\n"
            f"📝 **Action:** {message}\n"
            f"{'─' * 25}"
        )
        await app.bot.send_message(
            chat_id=ADMIN_LOG_CHAT_ID, 
            text=log_msg,
            parse_mode='Markdown'
        )
    except Exception as e:
        print(f"❌ [LOG ERROR] {e}")

# ═══════════════════════════════════════════════════════════════════════════════
#                              VALIDATION WEBMAILS
# ═══════════════════════════════════════════════════════════════════════════════

async def check_webmail_validity(context: ContextTypes.DEFAULT_TYPE):
    """Vérifie la validité des webmails"""
    c.execute("SELECT id, email, password, imap FROM webmails WHERE active = 1")
    
    for webmail_id, email_addr, enc_pwd, imap_server in c.fetchall():
        try:
            pwd = fernet.decrypt(enc_pwd.encode()).decode()
            imap = imaplib.IMAP4_SSL(imap_server)
            imap.login(email_addr, pwd)
            imap.logout()
            
            c.execute(
                "UPDATE webmails SET last_check = ?, active = 1 WHERE id = ?", 
                (datetime.now(), webmail_id)
            )
        except Exception:
            c.execute("UPDATE webmails SET active = 0 WHERE id = ?", (webmail_id,))
            
            error_msg = (
                f"🔴 **CONNEXION ÉCHOUÉE**\n"
                f"{'━' * 25}\n"
                f"📧 **Email:** `{email_addr}`\n"
                f"⚠️ **Statut:** Webmail désactivé automatiquement\n"
                f"🕐 **Heure:** {datetime.now().strftime('%H:%M:%S')}"
            )
            
            await context.bot.send_message(
                chat_id=ADMIN_LOG_CHAT_ID,
                text=error_msg,
                parse_mode='Markdown'
            )
    conn.commit()

# ═══════════════════════════════════════════════════════════════════════════════
#                              GESTION DES WEBMAILS
# ═══════════════════════════════════════════════════════════════════════════════

CHOOSING_CATEGORY, SENDING_CREDENTIALS = range(2)

async def add_webmail_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Commande pour ajouter un webmail"""
    if update.effective_user.id not in ADMIN_IDS:
        await update.message.reply_text(
            f"{MessageDesign.header('🚫 ACCÈS REFUSÉ')}\n\n"
            "⚠️ Cette commande est réservée aux administrateurs.\n"
            "📞 Contact: @bluebackpack",
            parse_mode='Markdown'
        )
        return ConversationHandler.END

    buttons = [
        [
            InlineKeyboardButton("🇫🇷 France", callback_data="cat_add_fr"),
            InlineKeyboardButton("🌍 International", callback_data="cat_add_world")
        ],
        [InlineKeyboardButton("❌ Annuler", callback_data="cancel_add")]
    ]
    
    message = (
        f"{MessageDesign.header('📬 AJOUT WEBMAIL', 'Sélection de catégorie')}\n\n"
        "🎯 **Choisissez la catégorie** pour votre nouveau webmail :\n\n"
        "🇫🇷 **France** - Fournisseurs français\n"
        "🌍 **International** - Fournisseurs étrangers"
    )
    
    await update.message.reply_text(
        message,
        reply_markup=InlineKeyboardMarkup(buttons),
        parse_mode='Markdown'
    )
    return CHOOSING_CATEGORY

async def choose_category(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Choix de la catégorie pour l'ajout"""
    query = update.callback_query
    await query.answer()
    
    if query.data == "cancel_add":
        await query.edit_message_text(
            f"{MessageDesign.header('❌ OPÉRATION ANNULÉE')}\n\n"
            "🔄 Retour au menu principal avec /start"
        )
        return ConversationHandler.END
    
    category = "France" if query.data == "cat_add_fr" else "International"
    context.user_data["category"] = category
    
    message = (
        f"{MessageDesign.header('✉️ SAISIE IDENTIFIANTS', category)}\n\n"
        "📝 **Format requis:**\n"
        "└─ `email@exemple.com:motdepasse`\n\n"
        "📋 **Options d'envoi:**\n"
        "├─ Plusieurs lignes dans un message\n"
        "└─ Fichier texte (.txt)\n\n"
        "💡 **Astuce:** Un email:mot de passe par ligne"
    )
    
    await query.edit_message_text(message, parse_mode='Markdown')
    return SENDING_CREDENTIALS

async def receive_credentials(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Réception et traitement des identifiants"""
    # Lecture du contenu
    if update.message.document:
        file = await update.message.document.get_file()
        data = await file.download_as_bytearray()
        text = data.decode('utf-8')
    else:
        text = update.message.text or ""

    lines = [l.strip() for l in text.splitlines() if l.strip()]
    successes, failures = [], []

    # Traitement de chaque ligne
    for line in lines:
        if ':' not in line:
            failures.append((line, 'Format invalide'))
            continue
            
        email_addr, pwd = line.split(':', 1)
        email_addr, pwd = email_addr.strip(), pwd.strip()
        domain = email_addr.split('@')[-1].lower()
        imap_server = f"imap.{domain}"
        
        try:
            # Test de connexion IMAP
            imap = imaplib.IMAP4_SSL(imap_server)
            imap.login(email_addr, pwd)
            imap.logout()
            
            # Chiffrement et sauvegarde
            enc_pwd = fernet.encrypt(pwd.encode()).decode()
            name = domain.split('.')[0].capitalize()
            now = datetime.now()
            
            c.execute(
                "INSERT INTO webmails (name, category, email, password, imap, active, last_check) VALUES (?, ?, ?, ?, ?, 1, ?)",
                (name, context.user_data["category"], email_addr, enc_pwd, imap_server, now)
            )
            conn.commit()
            successes.append(email_addr)
            
            await log(context.application, f"✅ Ajout réussi: {email_addr}", update.effective_user.id)
            
        except Exception as e:
            failures.append((email_addr, str(e)[:50]))
            await log(context.application, f"❌ Échec ajout {email_addr}: {e}", update.effective_user.id)

    # Rapport de résultats
    msg = f"{MessageDesign.header('📬 RÉSULTAT AJOUT', f'{len(successes)} succès, {len(failures)} échecs')}\n\n"
    
    if successes:
        msg += "✅ **SUCCÈS:**\n"
        for email in successes:
            msg += f"├─ `{email}`\n"
        msg += "\n"
    
    if failures:
        msg += "❌ **ÉCHECS:**\n"
        for email, error in failures:
            msg += f"├─ `{email}` : {error}\n"
    
    await update.message.reply_text(msg, parse_mode='Markdown')
    return ConversationHandler.END

# ═══════════════════════════════════════════════════════════════════════════════
#                              COMMANDES PRINCIPALES
# ═══════════════════════════════════════════════════════════════════════════════

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Commande /start avec design amélioré"""
    user_id = update.effective_user.id
    full_name = update.effective_user.full_name
    now = datetime.now()
    
    # Vérification bannissement
    if DatabaseHelper.is_banned(user_id):
        await update.message.reply_text(
            f"{MessageDesign.header('🚫 ACCÈS SUSPENDU')}\n\n"
            "⛔ **Votre compte a été temporairement suspendu**\n\n"
            "📞 **Pour faire appel:**\n"
            "└─ Contactez @bluebackpack\n\n"
            "💡 **Rappel:** Respectez les conditions d'utilisation",
            parse_mode='Markdown'
        )
        return
    
    # Récupération des données
    license_data = DatabaseHelper.get_license(user_id)
    nb_box = DatabaseHelper.get_active_webmails_count()
    
    if license_data:
        license, expires = license_data
        expires = datetime.fromisoformat(expires) if isinstance(expires, str) else expires
        time_left = expires - now
        is_active = expires > now
        
        if is_active:
            days_left = time_left.days
            hours_left = time_left.seconds // 3600
            
            status_emoji, status_text = MessageDesign.status_emoji(days_left)
            
            if days_left > 0:
                time_remaining = f"{days_left} jour{'s' if days_left > 1 else ''} et {hours_left}h"
            else:
                time_remaining = f"{hours_left}h restantes"
        else:
            status_emoji, status_text = "🔴", "LICENCE EXPIRÉE"
            time_remaining = "Renouvelez votre licence"
        
        exp_txt = (
            f"📅 **Expiration:** {expires.strftime('%d/%m/%Y à %H:%M')}\n"
            f"⏰ **Temps restant:** {time_remaining}"
        )
        
        buttons = [
            [
                InlineKeyboardButton("🇫🇷 France", callback_data="cat_show_fr"), 
                InlineKeyboardButton("🌍 International", callback_data="cat_show_world")
            ],
            [
                InlineKeyboardButton("👤 Mon Profil", callback_data="show_profil"),
                InlineKeyboardButton("📥 Mes Accès", callback_data="mes_acces")
            ]
        ]
        
        # Ajout du bouton admin si c'est un admin
        if user_id in ADMIN_IDS:
            buttons.append([InlineKeyboardButton("🔧 Administration", callback_data="admin_panel")])
            
    else:
        status_emoji, status_text = "❌", "AUCUNE LICENCE"
        exp_txt = (
            f"🔑 **Statut:** Non connecté\n"
            f"💡 **Action:** Connectez-vous pour accéder aux services"
        )
        buttons = [[InlineKeyboardButton("🔑 Se Connecter", callback_data="btn_login")]]
    
    # Construction du message principal avec design amélioré
    message = (
        f"{MessageDesign.header('🎯 TELEGRA MAIL', 'Service Premium de Messagerie')}\n\n"
        f"👋 **Bienvenue {full_name}!**\n\n"
        f"╭─ 📊 **INFORMATIONS COMPTE** ─╮\n"
        f"│ 🆔 ID: `{user_id}`\n"
        f"│ {status_emoji} Statut: **{status_text}**\n"
        f"│ {exp_txt.replace(chr(10), chr(10) + '│ ')}\n"
        f"╰─────────────────────────────╯\n\n"
        f"╭─ 📬 **SERVICES DISPONIBLES** ─╮\n"
        f"│ 📮 Boîtes actives: **{nb_box}**\n"
        f"│ 🇫🇷 Fournisseurs français\n"
        f"│ 🌍 Fournisseurs internationaux\n"
        f"│ 🔄 Vérification automatique\n"
        f"╰─────────────────────────────╯\n\n"
        f"🕐 Mis à jour: {now.strftime('%H:%M:%S')} | 📞 Support: @bluebackpack"
    )
    
    await update.message.reply_text(
        message,
        reply_markup=InlineKeyboardMarkup(buttons),
        parse_mode='Markdown'
    )
    
    await log(context.application, f"🚀 Commande /start utilisée", user_id)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Commande d'aide avec design amélioré"""
    user_id = update.effective_user.id
    
    if DatabaseHelper.is_banned(user_id):
        await update.message.reply_text(
            f"{MessageDesign.header('🚫 ACCÈS SUSPENDU')}\n\n"
            "⛔ Votre compte est suspendu.\n"
            "📞 Contactez @bluebackpack pour un appel.",
            parse_mode='Markdown'
        )
        return

    if user_id in ADMIN_IDS:
        message = (
            f"{MessageDesign.header('🛠️ COMMANDES ADMIN', 'Guide Administrateur')}\n\n"
            "╭─ 📬 **GESTION WEBMAILS** ─╮\n"
            "│ `/add_webmail` - Ajouter un webmail\n"
            "│ `/webmail` - Lister les webmails\n"
            "│ `/del_webmail <email>` - Supprimer\n"
            "╰─────────────────────────╯\n\n"
            "╭─ 🎫 **GESTION LICENCES** ─╮\n"
            "│ `/add_license <licence> <user_id> <durée>`\n"
            "│ `/renew <licence> <durée>` - Renouveler\n"
            "│ `/del_license <licence>` - Supprimer\n"
            "╰─────────────────────────╯\n\n"
            "╭─ 👥 **GESTION UTILISATEURS** ─╮\n"
            "│ `/user` - Statistiques utilisateurs\n"
            "│ `/ban <user_id>` - Bannir\n"
            "│ `/unban <user_id>` - Débannir\n"
            "╰─────────────────────────╯\n\n"
            "⚠️ **Attention:** Utilisez ces commandes avec précaution"
        )
    else:
        message = (
            f"{MessageDesign.header('📘 AIDE UTILISATEUR', 'Guide d utilisation')}\n\n"
            "╭─ 🚀 **COMMANDES DISPONIBLES** ─╮\n"
            "│ `/start` - Menu principal\n"
            "│ `/login <licence>` - Se connecter\n"
            "│ `/cancel` - Annuler une action\n"
            "│ `/help` - Cette aide\n"
            "╰─────────────────────────╯\n\n"
            "╭─ 🎯 **COMMENT UTILISER** ─╮\n"
            "│ 1️⃣ Utilisez `/start` pour le menu\n"
            "│ 2️⃣ Connectez-vous avec votre licence\n"
            "│ 3️⃣ Choisissez votre catégorie\n"
            "│ 4️⃣ Accédez aux webmails\n"
            "╰─────────────────────────╯\n\n"
            "📞 **Support:** @bluebackpack\n"
            "💡 **Astuce:** Gardez votre licence confidentielle!"
        )
    
    await update.message.reply_text(message, parse_mode='Markdown')

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Commande d'annulation"""
    user_id = update.effective_user.id
    
    if DatabaseHelper.is_banned(user_id):
        await update.message.reply_text(
            f"{MessageDesign.header('🚫 ACCÈS SUSPENDU')}\n\n"
            "⛔ Votre compte est suspendu.\n"
            "📞 Contactez @bluebackpack pour un appel.",
            parse_mode='Markdown'
        )
        return
        
    await update.message.reply_text(
        f"{MessageDesign.header('❌ ACTION ANNULÉE')}\n\n"
        "🔄 Retour au menu principal avec /start",
        parse_mode='Markdown'
    )
    return ConversationHandler.END

async def login(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Commande de connexion avec licence"""
    user_id = update.effective_user.id
    full_name = update.effective_user.full_name
    now = datetime.now()

    if DatabaseHelper.is_banned(user_id):
        await update.message.reply_text(
            f"{MessageDesign.header('🚫 ACCÈS SUSPENDU')}\n\n"
            "⛔ Votre compte a été suspendu.\n"
            "📞 Contactez @bluebackpack pour faire appel.",
            parse_mode='Markdown'
        )
        return

    if len(context.args) != 1:
        await update.message.reply_text(
            f"{MessageDesign.header('❌ FORMAT INCORRECT')}\n\n"
            "📝 **Usage correct:** `/login <licence>`\n\n"
            "💡 **Exemple:** `/login ABC123DEF456`\n"
            "🔐 **Astuce:** Copiez-collez votre licence",
            parse_mode='Markdown'
        )
        return

    license = context.args[0]

    # Vérifie si la licence existe
    c.execute("SELECT user_id, expires_at FROM licenses WHERE license = ?", (license,))
    row = c.fetchone()
    if not row:
        await update.message.reply_text(
            f"{MessageDesign.header('❌ LICENCE INTROUVABLE')}\n\n"
            "🔍 La licence saisie n'existe pas dans notre base.\n\n"
            "╭─ 🔍 **VÉRIFICATIONS** ─╮\n"
            "│ ✓ Licence correctement copiée ?\n"
            "│ ✓ Pas d'espaces en trop ?\n"
            "│ ✓ Majuscules/minuscules respectées ?\n"
            "╰─────────────────────╯\n\n"
            "📞 **Support:** @bluebackpack",
            parse_mode='Markdown'
        )
        return

    current_user_id, expires_at = row
    expires_at = datetime.fromisoformat(expires_at) if isinstance(expires_at, str) else expires_at

    if expires_at < now:
        days_expired = (now - expires_at).days
        await update.message.reply_text(
            f"{MessageDesign.header('⏰ LICENCE EXPIRÉE')}\n\n"
            f"📅 **Expirée le:** {expires_at.strftime('%d/%m/%Y à %H:%M')}\n"
            f"⏳ **Depuis:** {days_expired} jour{'s' if days_expired > 1 else ''}\n\n"
            "🔄 **Pour renouveler:**\n"
                        "└─ Contactez @bluebackpack\n\n"
            "💡 **Info:** Vos données sont conservées",
            parse_mode='Markdown'
        )
        return

    if current_user_id != 0 and current_user_id != user_id:
        await update.message.reply_text(
            f"{MessageDesign.header('⚠️ LICENCE DÉJÀ UTILISÉE')}\n\n"
            "🔒 Cette licence est déjà associée à un autre compte.\n\n"
            "╭─ 🛡️ **SÉCURITÉ** ─╮\n"
            "│ Une licence = Un utilisateur\n"
            "│ Protection contre le partage\n"
            "╰─────────────────────╯\n\n"
            "📞 **Si c'est votre licence:** @bluebackpack",
            parse_mode='Markdown'
        )
        return

    # Connexion réussie
    c.execute("UPDATE licenses SET user_id = ? WHERE license = ?", (user_id, license))
    conn.commit()

    # Calcul du temps restant
    time_left = expires_at - now
    days_left = time_left.days
    hours_left = time_left.seconds // 3600

    await update.message.reply_text(
        f"{MessageDesign.header('✅ CONNEXION RÉUSSIE', 'Bienvenue!')}\n\n"
        f"👋 **Félicitations {full_name}!**\n"
        "🎉 Votre licence est maintenant activée.\n\n"
        f"╭─ ⏰ **INFORMATIONS LICENCE** ─╮\n"
        f"│ Temps restant: {days_left} jour{'s' if days_left > 1 else ''} et {hours_left}h\n"
        f"│ Expire le: {expires_at.strftime('%d/%m/%Y à %H:%M')}\n"
        f"╰─────────────────────────╯\n\n"
        "🚀 **Prochaine étape:** Utilisez /start pour accéder aux services",
        parse_mode='Markdown'
    )
    await log(context.application, f"🔐 Connexion réussie avec licence {license[:8]}***", user_id)

# ═══════════════════════════════════════════════════════════════════════════════
#                              GESTION DES CALLBACKS
# ═══════════════════════════════════════════════════════════════════════════════

async def handle_callbacks(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gestionnaire principal des callbacks"""
    query = update.callback_query
    user_id = query.from_user.id
    full_name = query.from_user.full_name
    now = datetime.now()

    # Vérifie bannissement
    if DatabaseHelper.is_banned(user_id):
        await query.answer()
        await query.edit_message_text(
            f"{MessageDesign.header('🚫 ACCÈS SUSPENDU')}\n\n"
            "⛔ Votre compte a été suspendu.\n"
            "📞 Contactez @bluebackpack pour faire appel.",
            parse_mode='Markdown'
        )
        return

    data = query.data

    if data == "btn_login":
        await query.answer()
        await query.edit_message_text(
            f"{MessageDesign.header('🔐 CONNEXION REQUISE', 'Guide de connexion')}\n\n"
            "🎯 **Pour vous connecter:**\n"
            "└─ Utilisez `/login <votre_licence>`\n\n"
            "💡 **Exemple:**\n"
            "└─ `/login ABC123DEF456`\n\n"
            "╭─ 🔒 **SÉCURITÉ** ─╮\n"
            "│ Gardez votre licence confidentielle\n"
            "│ Ne la partagez jamais\n"
            "│ Une licence = Un utilisateur\n"
            "╰─────────────────────╯\n\n"
            "📞 **Besoin d'aide?** @bluebackpack",
            parse_mode="Markdown"
        )
        return

    if data == "retour_menu":
        license_data = DatabaseHelper.get_license(user_id)
        nb_box = DatabaseHelper.get_active_webmails_count()

        if license_data:
            license, expires = license_data
            expires = datetime.fromisoformat(expires) if isinstance(expires, str) else expires
            time_left = expires - now
            is_active = expires > now
            
            if is_active:
                days_left = time_left.days
                hours_left = time_left.seconds // 3600
                status_emoji, status_text = MessageDesign.status_emoji(days_left)
                
                if days_left > 0:
                    time_remaining = f"{days_left} jour{'s' if days_left > 1 else ''} et {hours_left}h"
                else:
                    time_remaining = f"{hours_left}h restantes"
            else:
                status_emoji, status_text = "🔴", "LICENCE EXPIRÉE"
                time_remaining = "Renouvelez votre licence"
            
            exp_txt = (
                f"📅 Expiration: {expires.strftime('%d/%m/%Y à %H:%M')}\n"
                f"⏰ Temps restant: {time_remaining}"
            )
        else:
            status_emoji, status_text = "❌", "AUCUNE LICENCE"
            exp_txt = "🔑 Action: Connectez-vous avec /login <licence>"

        btns = [
            [
                InlineKeyboardButton("🇫🇷 France", callback_data="cat_show_fr"), 
                InlineKeyboardButton("🌍 International", callback_data="cat_show_world")
            ],
            [
                InlineKeyboardButton("👤 Mon Profil", callback_data="show_profil"),
                InlineKeyboardButton("📥 Mes Accès", callback_data="mes_acces")
            ]
        ]

        if user_id in ADMIN_IDS:
            btns.append([InlineKeyboardButton("🔧 Administration", callback_data="admin_panel")])

        message = (
            f"{MessageDesign.header('🎯 TELEGRA MAIL', 'Service Premium de Messagerie')}\n\n"
            f"👋 **Bienvenue {full_name}!**\n\n"
            f"╭─ 📊 **INFORMATIONS COMPTE** ─╮\n"
            f"│ 🆔 ID: `{user_id}`\n"
            f"│ {status_emoji} Statut: **{status_text}**\n"
            f"│ {exp_txt.replace(chr(10), chr(10) + '│ ')}\n"
            f"╰─────────────────────────────╯\n\n"
            f"╭─ 📬 **SERVICES DISPONIBLES** ─╮\n"
            f"│ 📮 Boîtes actives: **{nb_box}**\n"
            f"│ 🇫🇷 Fournisseurs français\n"
            f"│ 🌍 Fournisseurs internationaux\n"
            f"│ 🔄 Vérification automatique\n"
            f"╰─────────────────────────────╯\n\n"
            f"🕐 Mis à jour: {now.strftime('%H:%M:%S')}"
        )

        await query.edit_message_text(
            message,
            reply_markup=InlineKeyboardMarkup(btns),
            parse_mode='Markdown'
        )
        await log(context.application, "🔄 Retour au menu principal", user_id)
        return

async def show_profil(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Affichage du profil utilisateur"""
    query = update.callback_query
    user_id = query.from_user.id
    full_name = query.from_user.full_name
    
    if DatabaseHelper.is_banned(user_id):
        await query.answer()
        await query.edit_message_text(
            f"{MessageDesign.header('🚫 ACCÈS SUSPENDU')}\n\n"
            "⛔ Votre compte a été suspendu.\n"
            "📞 Contactez @bluebackpack pour faire appel.",
            parse_mode='Markdown'
        )
        return
    
    license_data = DatabaseHelper.get_license(user_id)
    
    if not license_data:
        await query.edit_message_text(
            f"{MessageDesign.header('❌ LICENCE INTROUVABLE')}\n\n"
            "🔍 Aucune licence active trouvée pour votre compte.\n\n"
            "🔐 **Pour vous connecter:**\n"
            "└─ Utilisez `/login <votre_licence>`\n\n"
            "📞 **Besoin d'aide?** @bluebackpack",
            parse_mode='Markdown'
        )
        return
    
    license, exp = license_data
    exp = datetime.fromisoformat(exp) if isinstance(exp, str) else exp
    
    # Calcul du temps restant
    now = datetime.now()
    time_left = exp - now
    
    if time_left.total_seconds() > 0:
        days_left = time_left.days
        hours_left = time_left.seconds // 3600
        status_emoji, status_text = MessageDesign.status_emoji(days_left)
        
        if days_left > 0:
            time_remaining = f"{days_left} jour{'s' if days_left > 1 else ''} et {hours_left}h"
        else:
            time_remaining = f"{hours_left}h restantes"
    else:
        status_emoji, status_text = "🔴", "LICENCE EXPIRÉE"
        days_expired = (now - exp).days
        time_remaining = f"Expirée depuis {days_expired} jour{'s' if days_expired > 1 else ''}"
    
    # Masquage partiel de la licence pour sécurité
    masked_license = f"{license}"
    
    msg = (
        f"{MessageDesign.header('👤 PROFIL UTILISATEUR', 'Informations personnelles')}\n\n"
        f"╭─ 👤 **INFORMATIONS GÉNÉRALES** ─╮\n"
        f"│ 🆔 Utilisateur: {full_name}\n"
        f"│ 📱 ID Telegram: `{user_id}`\n"
        f"│ 🔐 Licence: `{masked_license}`\n"
        f"╰─────────────────────────────╯\n\n"
        f"╭─ 📊 **STATUT DE LA LICENCE** ─╮\n"
        f"│ {status_emoji} État: **{status_text}**\n"
        f"│ 📅 Expiration: {exp.strftime('%d/%m/%Y à %H:%M')}\n"
        f"│ ⏰ Temps restant: {time_remaining}\n"
        f"╰─────────────────────────────╯\n\n"
        f"🔒 **Sécurité:** Licence partiellement masquée\n"
        f"📞 **Support:** @bluebackpack"
    )
    
    btns = [[InlineKeyboardButton("🔄 Retour au menu", callback_data="retour_menu")]]
    await query.edit_message_text(msg, reply_markup=InlineKeyboardMarkup(btns), parse_mode='Markdown')
    await log(context.application, "👤 Consultation du profil utilisateur", user_id)

async def show_category(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Affichage des webmails par catégorie"""
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id

    # Vérifie bannissement
    if DatabaseHelper.is_banned(user_id):
        return await query.edit_message_text(
            f"{MessageDesign.header('🚫 ACCÈS SUSPENDU')}\n\n"
            "⛔ Votre compte est suspendu.",
            parse_mode='Markdown'
        )

    # Détermination de la catégorie
    if query.data.endswith("fr"):
        cat_db = "France"
        cat_label = "🇫🇷 Fournisseurs français"
        cat_emoji = "🇫🇷"
    else:
        cat_db = "International"
        cat_label = "🌍 Fournisseurs internationaux"
        cat_emoji = "🌍"

    # Récupération des webmails actifs
    rows = DatabaseHelper.get_webmails_by_category(cat_db)

    # Message si aucun webmail
    if not rows:
        return await query.edit_message_text(
            f"{MessageDesign.header('📭 AUCUNE BOÎTE ACTIVE', cat_label)}\n\n"
            f"🔍 Aucun webmail disponible dans cette catégorie.\n\n"
            f"⏳ **Statut:** Maintenance en cours\n"
            f"🔄 **Action:** Réessayez plus tard",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🏠 Retour au menu", callback_data="retour_menu")]
            ]),
            parse_mode='Markdown'
        )

    # Construire les boutons WebApp, 2 par ligne
    webmail_buttons = []
    for email_addr, enc_pwd in rows:
        # Extraire le nom du domaine pour l'affichage
        domain = email_addr.split('@')[1].split('.')[0].capitalize()
        
        # Créer l'URL de la webapp avec les paramètres
        webapp_url = f"{WEBAPP_URL}?user_id={user_id}&email={urllib.parse.quote(email_addr)}&category={urllib.parse.quote(cat_db)}"
        
        webmail_buttons.append(
            InlineKeyboardButton(
                text=f"✉️ {domain}",
                web_app=WebAppInfo(url=webapp_url)
            )
        )

    # Grouper par 2
    buttons = [webmail_buttons[i:i+2] for i in range(0, len(webmail_buttons), 2)]
    # Ajouter les boutons de navigation
    buttons.append([
        InlineKeyboardButton("🔄 Actualiser", callback_data=query.data),
        InlineKeyboardButton("🏠 Menu", callback_data="retour_menu")
    ])

    # Message avec design amélioré
    message = (
        f"{MessageDesign.header('📬 SÉLECTION WEBMAIL', cat_label)}\n\n"
        f"╭─ {cat_emoji} **{cat_label.upper()}** ─╮\n"
        f"│ 📊 Webmails disponibles: **{len(rows)}**\n"
        f"│ 🔄 Dernière vérification: {datetime.now().strftime('%H:%M')}\n"
                f"│ ✅ Tous les accès sont fonctionnels\n"
        f"╰─────────────────────────────╯\n\n"
        f"👆 **Cliquez sur un webmail** pour y accéder\n"
        f"🔒 **Sécurisé** - Connexion chiffrée"
    )

    await query.edit_message_text(
        message,
        reply_markup=InlineKeyboardMarkup(buttons),
        parse_mode='Markdown'
    )

async def show_my_access(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Affichage des accès utilisateur"""
    query = update.callback_query
    user_id = query.from_user.id

    if DatabaseHelper.is_banned(user_id):
        await query.answer()
        await query.edit_message_text(
            f"{MessageDesign.header('🚫 ACCÈS REFUSÉ')}\n\n"
            "⛔ Votre compte a été suspendu.\n"
            "📞 Contactez @bluebackpack pour la réactivation.",
            parse_mode='Markdown'
        )
        return

    c.execute("SELECT category, email, password FROM webmails WHERE active = 1")
    rows = c.fetchall()
    
    if not rows:
        await query.edit_message_text(
            f"{MessageDesign.header('📭 AUCUN ACCÈS')}\n\n"
            "🔍 Aucune boîte mail active disponible pour le moment.\n\n"
            "⏳ **Statut:** Maintenance en cours\n"
            "🔄 **Action:** Réessayez plus tard",
            parse_mode='Markdown'
        )
        return

    # En-tête du message
    text = f"{MessageDesign.header('📥 VOS ACCÈS WEBMAIL', f'{len(rows)} comptes disponibles')}\n\n"
    
    # Groupement par catégorie
    france_emails = []
    international_emails = []
    
    for cat, email_, enc_pwd in rows:
        if cat == "France":
            france_emails.append(email_)
        else:
            international_emails.append(email_)
    
    # Affichage France
    if france_emails:
        text += "╭─ 🇫🇷 **FRANCE** ─╮\n"
        for i, email in enumerate(france_emails, 1):
            text += f"│ {i:2d}. 📧 `{email}`\n"
        text += "╰─────────────────╯\n\n"
    
    # Affichage International
    if international_emails:
        text += "╭─ 🌍 **INTERNATIONAL** ─╮\n"
        for i, email in enumerate(international_emails, 1):
            text += f"│ {i:2d}. 📧 `{email}`\n"
        text += "╰─────────────────────╯\n\n"
    
    # Conseils de sécurité
    text += (
        "╭─ 💡 **CONSEILS DE SÉCURITÉ** ─╮\n"
        "│ • Changez régulièrement vos mots de passe\n"
        "│ • Ne partagez jamais vos identifiants\n"
        "│ • Utilisez la 2FA si disponible\n"
        "│ • Déconnectez-vous après usage\n"
        "╰─────────────────────────────╯"
    )

    await query.edit_message_text(
        text, 
        parse_mode="Markdown", 
        reply_markup=InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🔄 Actualiser", callback_data="mes_acces"),
                InlineKeyboardButton("🏠 Menu", callback_data="retour_menu")
            ]
        ])
    )
    await log(context.application, "📥 Consultation des accès", user_id)

async def admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Panel d'administration"""
    query = update.callback_query
    user_id = query.from_user.id

    if user_id not in ADMIN_IDS:
        await query.answer("❌ Accès refusé")
        return

    # Statistiques
    c.execute("SELECT COUNT(*) FROM licenses")
    total_licenses = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM licenses WHERE expires_at > ?", (datetime.now(),))
    active_licenses = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM webmails WHERE active = 1")
    active_webmails = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM bans")
    banned_users = c.fetchone()[0]

    message = (
        f"{MessageDesign.header('🔧 PANEL ADMINISTRATION', 'Gestion du système')}\n\n"
        f"╭─ 📊 **STATISTIQUES SYSTÈME** ─╮\n"
        f"│ 🎫 Licences totales: **{total_licenses}**\n"
        f"│ ✅ Licences actives: **{active_licenses}**\n"
        f"│ 📬 Webmails actifs: **{active_webmails}**\n"
        f"│ 🚫 Utilisateurs bannis: **{banned_users}**\n"
        f"╰─────────────────────────────╯\n\n"
        f"🕐 **Dernière mise à jour:** {datetime.now().strftime('%H:%M:%S')}"
    )

    buttons = [
        [
            InlineKeyboardButton("📬 Gestion Webmails", callback_data="admin_webmails"),
            InlineKeyboardButton("🎫 Gestion Licences", callback_data="admin_licenses")
        ],
        [
            InlineKeyboardButton("👥 Gestion Utilisateurs", callback_data="admin_users"),
            InlineKeyboardButton("🔄 Scan Webmails", callback_data="force_refresh")
        ],
        [
            InlineKeyboardButton("📊 Statistiques", callback_data="admin_stats"),
            InlineKeyboardButton("🏠 Menu Principal", callback_data="retour_menu")
        ]
    ]

    await query.edit_message_text(
        message,
        reply_markup=InlineKeyboardMarkup(buttons),
        parse_mode='Markdown'
    )

async def force_refresh(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Scan manuel des webmails"""
    query = update.callback_query
    user_id = query.from_user.id

    if user_id not in ADMIN_IDS:
        await query.answer("❌ Accès refusé")
        return

    await query.edit_message_text(
        f"{MessageDesign.header('⏳ SCAN EN COURS', 'Vérification des webmails')}\n\n"
        f"╭─ 🔄 **OPÉRATION EN COURS** ─╮\n"
        f"│ 📡 Connexion aux serveurs IMAP...\n"
        f"│ 🔍 Vérification des identifiants...\n"
        f"│ ⚡ Mise à jour de la base...\n"
        f"╰─────────────────────────────╯\n\n"
        f"⏳ **Veuillez patienter...**"
    )
    
    await check_webmail_validity(context)
    
    # Récupération des nouvelles statistiques
    c.execute("SELECT COUNT(*) FROM webmails WHERE active = 1")
    active_count = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM webmails WHERE active = 0")
    inactive_count = c.fetchone()[0]
    
    await query.edit_message_text(
        f"{MessageDesign.header('✅ SCAN TERMINÉ', 'Résultats de la vérification')}\n\n"
        f"╭─ 📊 **RÉSULTATS** ─╮\n"
        f"│ ✅ Webmails actifs: **{active_count}**\n"
        f"│ ❌ Webmails inactifs: **{inactive_count}**\n"
        f"│ 🕐 Scan effectué: {datetime.now().strftime('%H:%M:%S')}\n"
        f"╰─────────────────────╯\n\n"
        f"🎉 **Mise à jour terminée avec succès!**",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔧 Panel Admin", callback_data="admin_panel")],
            [InlineKeyboardButton("🏠 Menu Principal", callback_data="retour_menu")]
        ]),
        parse_mode='Markdown'
    )
    await log(context.application, "🔄 Scan manuel effectué", user_id)

# ═══════════════════════════════════════════════════════════════════════════════
#                              COMMANDES ADMINISTRATEUR
# ═══════════════════════════════════════════════════════════════════════════════

async def add_license(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Ajout d'une licence"""
    if update.effective_user.id not in ADMIN_IDS:
        return
    
    if len(context.args) != 3:
        await update.message.reply_text(
            f"{MessageDesign.header('📋 AJOUTER LICENCE', 'Format de commande')}\n\n"
            f"📝 **Format requis:**\n"
            f"`/add_license <licence> <user_id> <durée>`\n\n"
            f"💡 **Exemple:**\n"
            f"`/add_license ABC123 987654321 7d`\n\n"
            f"╭─ ⏰ **UNITÉS DE TEMPS** ─╮\n"
            f"│ h = heures (ex: 24h)\n"
            f"│ d = jours (ex: 7d)\n"
            f"│ w = semaines (ex: 2w)\n"
            f"╰─────────────────────╯",
            parse_mode="Markdown"
        )
        return

    license, user_id, durée = context.args
    delta = {'h': 'hours', 'd': 'days', 'w': 'weeks'}
    unit = durée[-1]

    if unit not in delta:
        await update.message.reply_text(
            f"{MessageDesign.header('❌ ERREUR UNITÉ')}\n\n"
            f"⚠️ Unité de temps non valide!\n\n"
            f"✅ **Unités acceptées:** h, d, w\n"
            f"(heures, jours, semaines)",
            parse_mode='Markdown'
        )
        return

    try:
        value = int(durée[:-1])
        expire = datetime.now() + timedelta(**{delta[unit]: value})
        c.execute("INSERT OR REPLACE INTO licenses (license, user_id, expires_at) VALUES (?, ?, ?)", 
                 (license, int(user_id), expire))
        conn.commit()
        
        await update.message.reply_text(
            f"{MessageDesign.header('✅ LICENCE AJOUTÉE', 'Création réussie')}\n\n"
            f"╭─ 🎫 **DÉTAILS LICENCE** ─╮\n"
            f"│ 🔐 Licence: `{license}`\n"
            f"│ 👤 Utilisateur: `{user_id}`\n"
            f"│ ⏰ Durée: {value}{unit}\n"
            f"│ 📅 Expire le: {expire.strftime('%d/%m/%Y à %H:%M')}\n"
            f"╰─────────────────────────╯",
            parse_mode="Markdown"
        )
        await log(context.application, f"➕ Ajout licence {license} pour {user_id}", update.effective_user.id)
    except Exception as e:
        await update.message.reply_text(
            f"{MessageDesign.header('❌ ERREUR')}\n\n"
            f"💥 Impossible d'ajouter la licence\n\n"
            f"🔍 **Vérifiez:**\n"
            f"├─ Format de la commande\n"
            f"├─ ID utilisateur valide\n"
            f"└─ Durée correcte",
            parse_mode='Markdown'
        )

async def renew_license(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Renouvellement d'une licence"""
    if update.effective_user.id not in ADMIN_IDS:
        return
    
    if len(context.args) != 2:
        await update.message.reply_text(
            f"{MessageDesign.header('📋 RENOUVELER LICENCE', 'Format de commande')}\n\n"
            f"📝 **Format requis:**\n"
            f"`/renew <license> <durée>`\n\n"
            f"💡 **Exemples:**\n"
            f"├─ `/renew ABC123 1d` (1 jour)\n"
            f"├─ `/renew DEF456 3h` (3 heures)\n"
            f"└─ `/renew GHI789 2w` (2 semaines)",
            parse_mode="Markdown"
        )
        return
        
    license, durée = context.args
    delta = {'h': 'hours', 'd': 'days', 'w': 'weeks'}
    unit = durée[-1]
    
    if unit not in delta:
        await update.message.reply_text(
            f"{MessageDesign.header('❌ ERREUR UNITÉ')}\n\n"
            f"⚠️ Unité de temps non valide!\n\n"
            f"✅ **Unités acceptées:** h, d, w",
            parse_mode='Markdown'
        )
        return
        
    try:
        value = int(durée[:-1])
        expire = datetime.now() + timedelta(**{delta[unit]: value})
        c.execute("UPDATE licenses SET expires_at = ? WHERE license = ?", (expire, license))
        conn.commit()
        
        await update.message.reply_text(
            f"{MessageDesign.header('✅ LICENCE RENOUVELÉE', 'Mise à jour réussie')}\n\n"
            f"╭─ 🔄 **RENOUVELLEMENT** ─╮\n"
            f"│ 🔐 Licence: `{license}`\n"
            f"│ ⏰ Durée ajoutée: {value}{unit}\n"
            f"│ 📅 Nouvelle expiration:\n"
            f"│    {expire.strftime('%d/%m/%Y à %H:%M')}\n"
            f"╰─────────────────────────╯",
            parse_mode="Markdown"
        )
        await log(context.application, f"🔄 Renouvellement licence {license}", update.effective_user.id)
    except Exception as     e:
        await update.message.reply_text(
            f"{MessageDesign.header('❌ ERREUR')}\n\n"
            f"💥 Impossible de renouveler la licence\n\n"
            f"🔍 Vérifiez que la licence existe",
            parse_mode='Markdown'
        )

async def list_users(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Liste des utilisateurs"""
    if update.effective_user.id not in ADMIN_IDS:
        return

    c.execute("SELECT license, user_id, expires_at FROM licenses ORDER BY expires_at DESC")
    rows = c.fetchall()
    
    if not rows:
        await update.message.reply_text(
            f"{MessageDesign.header('📋 LISTE UTILISATEURS')}\n\n"
            f"🔍 Aucun utilisateur trouvé dans la base",
            parse_mode='Markdown'
        )
        return

    msg = f"{MessageDesign.header('📋 LISTE UTILISATEURS', f'{len(rows)} utilisateurs')}\n\n"
    
    for i, (license, uid, exp) in enumerate(rows[:20], 1):  # Limite à 20 pour éviter les messages trop longs
        exp_dt = datetime.fromisoformat(exp) if isinstance(exp, str) else exp
        status = "✅" if exp_dt > datetime.now() else "❌"
        
        msg += f"╭─ {i:2d}. {status} - **{license}** ─╮\n"
        msg += f"│ 👤 ID: `{uid}`\n"
        msg += f"│ 📅 Expire: {exp_dt.strftime('%d/%m/%Y %H:%M')}\n"
        msg += f"╰─────────────────────╯\n\n"
    
    if len(rows) > 20:
        msg += f"... et {len(rows) - 20} autres utilisateurs"
    
    await update.message.reply_text(msg, parse_mode="Markdown")

async def list_webmails(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Liste des webmails"""
    if update.effective_user.id not in ADMIN_IDS:
        return

    c.execute("SELECT email, category, active, last_check FROM webmails ORDER BY active DESC, category")
    rows = c.fetchall()
    
    if not rows:
        await update.message.reply_text(
            f"{MessageDesign.header('📬 LISTE WEBMAILS')}\n\n"
            f"🔍 Aucun webmail trouvé dans la base",
            parse_mode='Markdown'
        )
        return

    msg = f"{MessageDesign.header('📬 LISTE WEBMAILS', f'{len(rows)} webmails')}\n\n"
    
    for i, (email_, cat, active, check) in enumerate(rows[:15], 1):
        status = "✅ ACTIF" if active else "❌ INACTIF"
        check_str = datetime.fromisoformat(check).strftime("%d/%m %H:%M") if check else "Jamais"
        
        msg += f"╭─ {i:2d}. {status} ─╮\n"
        msg += f"│ 📧 `{email_}`\n"
        msg += f"│ 🏷️ [{cat}] | 📅 {check_str}\n"
        msg += f"╰─────────────────────╯\n\n"
    
    if len(rows) > 15:
        msg += f"... et {len(rows) - 15} autres webmails"
    
    await update.message.reply_text(msg, parse_mode="Markdown")

async def delete_license(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Suppression d'une licence"""
    if update.effective_user.id not in ADMIN_IDS:
        return
    
    if len(context.args) != 1:
        await update.message.reply_text(
            f"{MessageDesign.header('🗑️ SUPPRIMER LICENCE', 'Format de commande')}\n\n"
            f"📝 **Format:** `/del_license <licence>`\n\n"
            f"💡 **Exemple:** `/del_license ABC123`",
            parse_mode="Markdown"
        )
        return

    license = context.args[0]
    c.execute("DELETE FROM licenses WHERE license = ?", (license,))
    conn.commit()
    
    await update.message.reply_text(
        f"{MessageDesign.header('✅ LICENCE SUPPRIMÉE', 'Suppression réussie')}\n\n"
        f"╭─ 🗑️ **SUPPRESSION** ─╮\n"
        f"│ 🔐 Licence: `{license}`\n"
        f"│ ✅ Supprimée avec succès\n"
        f"│ 🕐 Le: {datetime.now().strftime('%d/%m/%Y à %H:%M')}\n"
        f"╰─────────────────────╯",
        parse_mode="Markdown"
    )
    await log(context.application, f"🗑️ Suppression licence {license}", update.effective_user.id)

async def delete_webmail(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Suppression d'un webmail"""
    if update.effective_user.id not in ADMIN_IDS:
        return
    
    if len(context.args) != 1:
        await update.message.reply_text(
            f"{MessageDesign.header('🗑️ SUPPRIMER WEBMAIL', 'Format de commande')}\n\n"
            f"📝 **Format:** `/del_webmail <email>`\n\n"
            f"💡 **Exemple:** `/del_webmail user@example.com`",
            parse_mode="Markdown"
        )
        return

    email_ = context.args[0]
    c.execute("DELETE FROM webmails WHERE email = ?", (email_,))
    conn.commit()
    
    await update.message.reply_text(
        f"{MessageDesign.header('✅ WEBMAIL SUPPRIMÉ', 'Suppression réussie')}\n\n"
        f"╭─ 🗑️ **SUPPRESSION** ─╮\n"
        f"│ 📧 Email: `{email_}`\n"
        f"│ ✅ Supprimé avec succès\n"
        f"│ 🕐 Le: {datetime.now().strftime('%d/%m/%Y à %H:%M')}\n"
        f"╰─────────────────────╯",
        parse_mode="Markdown"
    )
    await log(context.application, f"🗑️ Suppression webmail {email_}", update.effective_user.id)

async def ban_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Bannissement d'un utilisateur"""
    if update.effective_user.id not in ADMIN_IDS:
        return
    
    if len(context.args) != 1:
        await update.message.reply_text(
            f"{MessageDesign.header('🚫 BANNIR UTILISATEUR', 'Format de commande')}\n\n"
            f"📝 **Format:** `/ban <user_id>`\n\n"
            f"💡 **Exemple:** `/ban 123456789`",
            parse_mode="Markdown"
        )
        return
        
    uid = int(context.args[0])
    c.execute("INSERT OR REPLACE INTO bans (user_id) VALUES (?)", (uid,))
    conn.commit()
    
    await update.message.reply_text(
        f"{MessageDesign.header('🚫 UTILISATEUR BANNI', 'Bannissement effectué')}\n\n"
        f"╭─ 🚫 **BANNISSEMENT** ─╮\n"
        f"│ 👤 Utilisateur: `{uid}`\n"
        f"│ ✅ Banni avec succès\n"
        f"│ 🕐 Le: {datetime.now().strftime('%d/%m/%Y à %H:%M')}\n"
        f"│ ⚠️ Ne peut plus utiliser le bot\n"
        f"╰─────────────────────────╯",
        parse_mode="Markdown"
    )
    await log(context.application, f"🚫 Bannissement utilisateur {uid}", update.effective_user.id)

    try:
        ban_notification = (
            f"{MessageDesign.header('🚫 COMPTE SUSPENDU', 'Notification officielle')}\n\n"
            f"⛔ **Votre accès a été suspendu**\n\n"
            f"╭─ 📞 **PROCÉDURE D'APPEL** ─╮\n"
            f"│ Pour contester cette décision:\n"
            f"│ └─ Contactez @bluebackpack\n"
            f"│ └─ Expliquez votre situation\n"
            f"│ └─ Respectez les règles\n"
            f"╰─────────────────────────╯"
        )
        await context.bot.send_message(chat_id=uid, text=ban_notification, parse_mode='Markdown')
    except Exception as e:
        print(f"Erreur envoi notification ban: {e}")

async def unban_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Débannissement d'un utilisateur"""
    if update.effective_user.id not in ADMIN_IDS:
        return
    
    if len(context.args) != 1:
        await update.message.reply_text(
            f"{MessageDesign.header('✅ DÉBANNIR UTILISATEUR', 'Format de commande')}\n\n"
            f"📝 **Format:** `/unban <user_id>`\n\n"
            f"💡 **Exemple:** `/unban 123456789`",
            parse_mode="Markdown"
        )
        return
        
    uid = int(context.args[0])
    c.execute("DELETE FROM bans WHERE user_id = ?", (uid,))
    conn.commit()
    
    await update.message.reply_text(
        f"{MessageDesign.header('✅ UTILISATEUR DÉBANNI', 'Débannissement effectué')}\n\n"
        f"╭─ ✅ **DÉBANNISSEMENT** ─╮\n"
        f"│ 👤 Utilisateur: `{uid}`\n"
        f"│ ✅ Débanni avec succès\n"
        f"│ 🕐 Le: {datetime.now().strftime('%d/%m/%Y à %H:%M')}\n"
        f"│ 🎉 Peut à nouveau utiliser le bot\n"
        f"╰─────────────────────────╯",
        parse_mode="Markdown"
    )
    await log(context.application, f"✅ Débannissement utilisateur {uid}", update.effective_user.id)

    try:
        unban_notification = (
            f"{MessageDesign.header('🎉 COMPTE RÉACTIVÉ', 'Bonne nouvelle!')}\n\n"
            f"✅ **Votre compte a été réactivé!**\n\n"
            f"╭─ 🎯 **PROCHAINES ÉTAPES** ─╮\n"
            f"│ ✓ Vous pouvez utiliser le bot\n"
            f"│ ✓ Respectez les conditions\n"
            f"│ ✓ Utilisez /start pour commencer\n"
            f"╰─────────────────────────╯\n\n"
            f"💡 **Rappel:** Respectez les règles d'utilisation"
        )
        await context.bot.send_message(chat_id=uid, text=unban_notification, parse_mode='Markdown')
    except Exception as e:
        print(f"Erreur envoi notification débannissement: {e}")

# ═══════════════════════════════════════════════════════════════════════════════
#                              GESTIONNAIRE DE CALLBACKS
# ═══════════════════════════════════════════════════════════════════════════════

async def callback_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Routeur principal pour les callbacks"""
    query = update.callback_query
    data = query.data
    
    # Routage des callbacks
    if data.startswith("cat_show_"):
        await show_category(update, context)
    elif data == "show_profil":
        await show_profil(update, context)
    elif data == "mes_acces":
        await show_my_access(update, context)
    elif data == "admin_panel":
        await admin_panel(update, context)
    elif data == "force_refresh":
        await force_refresh(update, context)
    else:
        await handle_callbacks(update, context)

async def security_middleware(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Middleware de sécurité pour bloquer les utilisateurs bannis"""
    user_id = update.effective_user.id
    
    if DatabaseHelper.is_banned(user_id):
        try:
            ban_message = (
                f"{MessageDesign.header('🚫 ACCÈS BLOQUÉ', 'Compte suspendu')}\n\n"
                f"⛔ **Votre compte est suspendu**\n\n"
                f"╭─ 📞 **CONTACT SUPPORT** ─╮\n"
                f"│ Pour faire appel de cette décision:\n"
                f"│ └─ Contactez @bluebackpack\n"
                f"│ └─ Expliquez votre situation\n"
                f"│ └─ Respectez les règles\n"
                f"╰─────────────────────────╯"
            )
            await update.message.reply_text(ban_message, parse_mode='Markdown')
        except:
            pass
        return

# ═══════════════════════════════════════════════════════════════════════════════
#                              CONFIGURATION PRINCIPALE
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    """Fonction principale"""
    print("🚀 Démarrage de Telegra'Mail Bot...")
    print(f"📊 Version: 2.0 - Design amélioré")
    print(f"🔧 Administrateurs: {len(ADMIN_IDS)}")
    print(f"📬 Base de données: {DB_NAME}")
    
    # Construction de l'application
    app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
    
    # Tâche de vérification automatique des webmails (toutes les heures)
    app.job_queue.run_repeating(check_webmail_validity, interval=3600, first=10)
    
    # Gestionnaire de conversation pour l'ajout de webmails
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("add_webmail", add_webmail_command)],
        states={
            CHOOSING_CATEGORY: [CallbackQueryHandler(choose_category)],
            SENDING_CREDENTIALS: [MessageHandler(filters.TEXT | filters.Document.ALL, receive_credentials)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )
    
    # Ajout des handlers
    app.add_handler(conv_handler)
    
    # Commandes principales
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("login", login))
    app.add_handler(CommandHandler("cancel", cancel))
    
    # Commandes administrateur
    app.add_handler(CommandHandler("add_license", add_license))
    app.add_handler(CommandHandler("renew", renew_license))
    app.add_handler(CommandHandler("del_license", delete_license))
    app.add_handler(CommandHandler("del_webmail", delete_webmail))
    app.add_handler(CommandHandler("user", list_users))
    app.add_handler(CommandHandler("webmail", list_webmails))
    app.add_handler(CommandHandler("ban", ban_user))
    app.add_handler(CommandHandler("unban", unban_user))
    
    # Gestionnaire de callbacks
    app.add_handler(CallbackQueryHandler(callback_router))
    
    # Middleware de sécurité (groupe 1 pour priorité)
    app.add_handler(MessageHandler(filters.ALL, security_middleware), group=1)
    
    print("✅ Bot configuré avec succès!")
    print("🔄 Démarrage du polling...")
    
    # Démarrage du bot
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    try:
        # Démarrer le serveur Flask dans un thread séparé
        threading.Thread(target=app_flask.run, kwargs={'host': '0.0.0.0', 'port': 5000}).start()
        main()
    except KeyboardInterrupt:
        print("\n🛑 Arrêt du bot demandé par l'utilisateur")
    except Exception as e:
        print(f"❌ Erreur critique: {e}")
    finally:
        print("👋 Telegra'Mail Bot arrêté")
        if conn:
            conn.close()