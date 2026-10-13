import os
import uuid
from functools import wraps
from io import BytesIO

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, send_from_directory, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from rsa_core import keys
from rsa_core.cipher import decrypt_file, encrypt_file
from rsa_core.errors import FileFormatError, RSAError
from storage import cleanup_expired, connect, contact_pair, expiration, initialize, now

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("RSA_SECRET_KEY", "rsa-file-secure-development-key")
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8 Mo
app.config["DATABASE"] = os.path.join(app.instance_path, "rsa_file_secure.db")
app.config["UPLOAD_FOLDER"] = os.path.join(app.instance_path, "encrypted_uploads")
app.config["AVATAR_FOLDER"] = os.path.join(app.instance_path, "avatars")
KEY_BITS = 2048
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["AVATAR_FOLDER"], exist_ok=True)
initialize(app.config["DATABASE"])

@app.errorhandler(RSAError)
def handle_rsa_error(err):
    return jsonify(error=str(err)), 400

@app.errorhandler(413)
def too_large(_):
    return jsonify(error="Fichier trop volumineux (8 Mo maximum)."), 413

def read_key(kind):
    """Clé depuis un fichier .json importé, sinon depuis les champs saisis."""
    f = request.files.get("key_file")
    if f and f.filename:
        text = f.read().decode("utf-8", "replace")
        return keys.public_from_json(text) if kind == "public" else keys.private_from_json(text)
    n = request.form.get("n", "")
    if kind == "public":
        return keys.public_key(n, request.form.get("e", ""))
    return keys.private_key(n, request.form.get("d", ""))

def read_upload():
    f = request.files.get("file")
    if not f or not f.filename:
        raise FileFormatError("Choisis d'abord un fichier.")
    return os.path.basename(f.filename), f.read()

def read_encrypt_input():
    f = request.files.get("file")
    has_file = bool(f and f.filename)
    text = request.form.get("text", "")
    has_text = text != ""
    if has_file == has_text:
        raise FileFormatError("Choisis un fichier ou saisis un texte à chiffrer, mais pas les deux.")
    if has_file:
        return os.path.basename(f.filename), f.read()
    return "texte.txt", text.encode("utf-8")

def db():
    return connect(app.config["DATABASE"])

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with db() as connection:
        return connection.execute("SELECT id, username, public_key, display_name, bio, avatar_name FROM users WHERE id = ?", (user_id,)).fetchone()

@app.context_processor
def inject_user():
    user = current_user()
    counts = {"messages": 0, "files": 0, "requests": 0, "total": 0}
    if user:
        with db() as connection:
            cleanup_expired(connection, app.config["UPLOAD_FOLDER"])
            counts["messages"] = connection.execute(
                "SELECT COUNT(*) FROM messages WHERE recipient_id = ? AND read_at IS NULL", (user["id"],)
            ).fetchone()[0]
            counts["files"] = connection.execute(
                "SELECT COUNT(*) FROM transfers WHERE recipient_id = ? AND downloaded_at IS NULL AND expired_at IS NULL", (user["id"],)
            ).fetchone()[0]
            counts["requests"] = connection.execute(
                "SELECT COUNT(*) FROM contacts WHERE (user_a = ? OR user_b = ?) AND requested_by != ? AND status = 'pending'", (user["id"], user["id"], user["id"])
            ).fetchone()[0]
            counts["total"] = sum(counts.values())
    return {"current_user": user, "notification_counts": counts}

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Connectez-vous pour accéder à cette page.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

@app.get("/")
def index():
    if current_user():
        return redirect(url_for("inbox"))
    return render_template("index.html", page="home")

@app.route("/register", methods=("GET", "POST"))
def register():
    if current_user():
        return redirect(url_for("inbox"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(username) > 32 or not username.replace("_", "").replace("-", "").isalnum():
            flash("Le nom d'utilisateur doit contenir 3 à 32 lettres, chiffres, tirets ou underscores.", "error")
        elif len(password) < 8:
            flash("Le mot de passe doit contenir au moins 8 caractères.", "error")
        else:
            try:
                with db() as connection:
                    connection.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                                       (username, generate_password_hash(password, method="pbkdf2:sha256"), now().isoformat()))
                    connection.commit()
                flash("Compte créé. Connectez-vous puis ajoutez votre clé publique.", "ok")
                return redirect(url_for("login"))
            except Exception:
                flash("Ce nom d'utilisateur est déjà utilisé.", "error")
    return render_template("register.html", page="account")

@app.route("/login", methods=("GET", "POST"))
def login():
    if current_user():
        return redirect(url_for("inbox"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as connection:
            user = connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("inbox"))
        flash("Nom d'utilisateur ou mot de passe incorrect.", "error")
    return render_template("login.html", page="account")

@app.post("/logout")
def logout():
    session.clear()
    flash("Vous êtes déconnecté.", "ok")
    return redirect(url_for("index"))

@app.route("/profile", methods=("GET", "POST"))
@login_required
def profile():
    user = current_user()
    if request.method == "POST":
        display_name = request.form.get("display_name", "").strip()[:50]
        bio = request.form.get("bio", "").strip()[:280]
        avatar_name = user["avatar_name"]
        avatar = request.files.get("avatar")
        if avatar and avatar.filename:
            extension = os.path.splitext(secure_filename(avatar.filename))[1].lower()
            if extension not in (".jpg", ".jpeg", ".png", ".webp"):
                flash("La photo doit être au format JPG, PNG ou WebP.", "error")
                return redirect(url_for("profile"))
            avatar_name = uuid.uuid4().hex + extension
            avatar.save(os.path.join(app.config["AVATAR_FOLDER"], avatar_name))
        with db() as connection:
            connection.execute("UPDATE users SET display_name = ?, bio = ?, avatar_name = ? WHERE id = ?", (display_name, bio, avatar_name, user["id"]))
            connection.commit()
        flash("Profil mis à jour.", "ok")
        return redirect(url_for("profile"))
    return render_template("profile.html", page="profile", user=user)

@app.get("/avatars/<path:filename>")
def avatar(filename):
    return send_from_directory(app.config["AVATAR_FOLDER"], filename)

@app.route("/contacts", methods=("GET", "POST"))
@login_required
def contacts():
    user = current_user()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        with db() as connection:
            other = connection.execute("SELECT id, username, display_name, avatar_name FROM users WHERE username = ?", (username,)).fetchone()
            if not other:
                flash("Aucun utilisateur ne correspond à ce pseudo.", "error")
            elif other["id"] == user["id"]:
                flash("Vous ne pouvez pas vous ajouter vous-même.", "error")
            else:
                user_a, user_b = contact_pair(user["id"], other["id"])
                relationship = connection.execute("SELECT status FROM contacts WHERE user_a = ? AND user_b = ?", (user_a, user_b)).fetchone()
                if relationship:
                    message = {"pending": "Une demande est déjà en attente.", "accepted": "Cette personne est déjà dans vos contacts.", "blocked": "Cette personne n'est pas disponible.", "rejected": "Cette demande a déjà été refusée."}[relationship["status"]]
                    flash(message, "error")
                else:
                    timestamp = now().isoformat()
                    connection.execute("INSERT INTO contacts (user_a, user_b, requested_by, status, created_at, updated_at) VALUES (?, ?, ?, 'pending', ?, ?)", (user_a, user_b, user["id"], timestamp, timestamp))
                    connection.commit()
                    flash(f"Demande de contact envoyée à {other['username']}.", "ok")
        return redirect(url_for("contacts"))
    with db() as connection:
        relationships = connection.execute("""
            SELECT contacts.*, users.id AS other_id, users.username, users.display_name, users.avatar_name
            FROM contacts JOIN users ON users.id = CASE WHEN contacts.user_a = ? THEN contacts.user_b ELSE contacts.user_a END
            WHERE contacts.user_a = ? OR contacts.user_b = ? ORDER BY contacts.updated_at DESC
        """, (user["id"], user["id"], user["id"])).fetchall()
    received = [row for row in relationships if row["status"] == "pending" and row["requested_by"] != user["id"]]
    sent = [row for row in relationships if row["status"] == "pending" and row["requested_by"] == user["id"]]
    accepted = [row for row in relationships if row["status"] == "accepted"]
    blocked = [row for row in relationships if row["status"] == "blocked"]
    return render_template("contacts.html", page="contacts", contacts=accepted, received=received, sent=sent, blocked=blocked)

@app.post("/contacts/<int:other_id>/<action>")
@login_required
def update_contact(other_id, action):
    user = current_user()
    if action not in ("accept", "refuse", "block", "unblock"):
        abort(404)
    user_a, user_b = contact_pair(user["id"], other_id)
    with db() as connection:
        relationship = connection.execute("SELECT * FROM contacts WHERE user_a = ? AND user_b = ?", (user_a, user_b)).fetchone()
        if not relationship:
            abort(404)
        if action == "accept" and relationship["status"] == "pending" and relationship["requested_by"] != user["id"]:
            status, message = "accepted", "Demande acceptée. Vous pouvez maintenant échanger des fichiers."
        elif action == "refuse" and relationship["status"] == "pending" and relationship["requested_by"] != user["id"]:
            status, message = "rejected", "Demande refusée."
        elif action == "block":
            status, message = "blocked", "Utilisateur bloqué."
        elif action == "unblock" and relationship["status"] == "blocked":
            connection.execute("DELETE FROM contacts WHERE user_a = ? AND user_b = ?", (user_a, user_b))
            connection.commit()
            flash("Utilisateur débloqué. Vous pouvez lui envoyer une nouvelle demande de contact.", "ok")
            return redirect(url_for("contacts"))
        else:
            abort(403)
        connection.execute("UPDATE contacts SET status = ?, updated_at = ? WHERE user_a = ? AND user_b = ?", (status, now().isoformat(), user_a, user_b))
        connection.commit()
    flash(message, "ok")
    return redirect(url_for("contacts"))

@app.route("/profile/key", methods=("GET", "POST"))
@login_required
def public_key_profile():
    user = current_user()
    if request.method == "POST":
        file = request.files.get("public_key")
        if not file or not file.filename:
            flash("Sélectionnez votre fichier de clé publique.", "error")
        else:
            try:
                public = keys.public_from_json(file.read().decode("utf-8", "replace"))
                with db() as connection:
                    connection.execute("UPDATE users SET public_key = ? WHERE id = ?", (public.to_json(), user["id"]))
                    connection.commit()
                flash("Votre clé publique est enregistrée. Les autres utilisateurs peuvent maintenant vous envoyer des fichiers.", "ok")
                return redirect(url_for("public_key_profile"))
            except RSAError as err:
                flash(str(err), "error")
    return render_template("profile_key.html", page="account", has_key=bool(user["public_key"]))

@app.get("/inbox")
@login_required
def inbox():
    user = current_user()
    with db() as connection:
        cleanup_expired(connection, app.config["UPLOAD_FOLDER"])
        received = connection.execute("""
            SELECT transfers.*, users.username AS sender_name FROM transfers
            JOIN users ON users.id = transfers.sender_id
            WHERE recipient_id = ? ORDER BY created_at DESC
        """, (user["id"],)).fetchall()
    return render_template("inbox.html", page="inbox", received=received, has_key=bool(user["public_key"]))

@app.get("/notifications")
@login_required
def notifications():
    user = current_user()
    with db() as connection:
        cleanup_expired(connection, app.config["UPLOAD_FOLDER"])
        contact_requests = connection.execute("""
            SELECT users.id, users.username, users.display_name, users.avatar_name, contacts.created_at
            FROM contacts JOIN users ON users.id = contacts.requested_by
            WHERE (contacts.user_a = ? OR contacts.user_b = ?) AND contacts.requested_by != ? AND contacts.status = 'pending'
            ORDER BY contacts.created_at DESC
        """, (user["id"], user["id"], user["id"])).fetchall()
        messages_received = connection.execute("""
            SELECT messages.id, messages.sender_id, messages.created_at, users.username, users.display_name, users.avatar_name
            FROM messages JOIN users ON users.id = messages.sender_id
            WHERE messages.recipient_id = ? AND messages.read_at IS NULL ORDER BY messages.created_at DESC
        """, (user["id"],)).fetchall()
        files_received = connection.execute("""
            SELECT transfers.id, transfers.original_name, transfers.created_at, users.username, users.display_name, users.avatar_name
            FROM transfers JOIN users ON users.id = transfers.sender_id
            WHERE transfers.recipient_id = ? AND transfers.downloaded_at IS NULL AND transfers.expired_at IS NULL ORDER BY transfers.created_at DESC
        """, (user["id"],)).fetchall()
    return render_template("notifications.html", page="notifications", contact_requests=contact_requests,
                           messages_received=messages_received, files_received=files_received)

@app.route("/send", methods=("GET", "POST"))
@login_required
def send_to_friend():
    sender = current_user()
    with db() as connection:
        cleanup_expired(connection, app.config["UPLOAD_FOLDER"])
        recipients = connection.execute("""
            SELECT users.id, users.username FROM contacts
            JOIN users ON users.id = CASE WHEN contacts.user_a = ? THEN contacts.user_b ELSE contacts.user_a END
            WHERE (contacts.user_a = ? OR contacts.user_b = ?) AND contacts.status = 'accepted' AND users.public_key IS NOT NULL
            ORDER BY users.username
        """, (sender["id"], sender["id"], sender["id"])).fetchall()
    if request.method == "POST":
        recipient_id = request.form.get("recipient", type=int)
        expiry_choice = request.form.get("expiry", "7d")
        with db() as connection:
            recipient = connection.execute("SELECT id, username, public_key FROM users WHERE id = ?", (recipient_id,)).fetchone()
            user_a, user_b = contact_pair(sender["id"], recipient_id or 0)
            relationship = connection.execute("SELECT status FROM contacts WHERE user_a = ? AND user_b = ?", (user_a, user_b)).fetchone()
        if not recipient or not recipient["public_key"] or not relationship or relationship["status"] != "accepted":
            flash("Choisissez un contact accepté qui a publié une clé publique.", "error")
        else:
            try:
                name, data = read_encrypt_input()
                blob = encrypt_file(data, name, keys.public_from_json(recipient["public_key"]))
                stored_name = uuid.uuid4().hex + ".rsa"
                expires_at, expires_on_download = {
                    "24h": (expiration(hours=24), 0),
                    "7d": (expiration(days=7), 0),
                    "first_download": (expiration(days=7), 1),
                }.get(expiry_choice, (expiration(days=7), 0))
                with open(os.path.join(app.config["UPLOAD_FOLDER"], stored_name), "wb") as output:
                    output.write(blob)
                with db() as connection:
                    connection.execute("""INSERT INTO transfers (sender_id, recipient_id, original_name, stored_name, size, created_at, expires_at, expires_on_download)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", (sender["id"], recipient["id"], name, stored_name, len(blob), now().isoformat(), expires_at, expires_on_download))
                    connection.commit()
                lifespan = "après son premier téléchargement" if expires_on_download else ("dans 24 heures" if expiry_choice == "24h" else "dans 7 jours")
                flash(f"Fichier chiffré et envoyé à {recipient['username']}. Il expirera {lifespan}.", "ok")
                return redirect(url_for("inbox"))
            except RSAError as err:
                flash(str(err), "error")
    return render_template("send.html", page="send", recipients=recipients)

@app.get("/history")
@login_required
def history():
    user = current_user()
    with db() as connection:
        cleanup_expired(connection, app.config["UPLOAD_FOLDER"])
        sent = connection.execute("""
            SELECT transfers.*, users.username AS recipient_name FROM transfers
            JOIN users ON users.id = transfers.recipient_id
            WHERE sender_id = ? ORDER BY created_at DESC
        """, (user["id"],)).fetchall()
    return render_template("history.html", page="history", sent=sent)

def accepted_contact(connection, user_id, other_id):
    user_a, user_b = contact_pair(user_id, other_id)
    return connection.execute("""
        SELECT users.id, users.username, users.display_name, users.avatar_name, users.public_key
        FROM contacts JOIN users ON users.id = ?
        WHERE contacts.user_a = ? AND contacts.user_b = ? AND contacts.status = 'accepted'
    """, (other_id, user_a, user_b)).fetchone()

@app.get("/messages")
@login_required
def messages():
    user = current_user()
    with db() as connection:
        contacts = connection.execute("""
            SELECT users.id, users.username, users.display_name, users.avatar_name,
                (SELECT MAX(created_at) FROM messages WHERE (sender_id = ? AND recipient_id = users.id) OR (sender_id = users.id AND recipient_id = ?)) AS last_message_at,
                (SELECT COUNT(*) FROM messages WHERE sender_id = users.id AND recipient_id = ? AND read_at IS NULL) AS unread_count
            FROM contacts JOIN users ON users.id = CASE WHEN contacts.user_a = ? THEN contacts.user_b ELSE contacts.user_a END
            WHERE (contacts.user_a = ? OR contacts.user_b = ?) AND contacts.status = 'accepted'
            ORDER BY last_message_at DESC, users.username
        """, (user["id"], user["id"], user["id"], user["id"], user["id"], user["id"])).fetchall()
    return render_template("messages.html", page="messages", contacts=contacts)

@app.route("/messages/<int:contact_id>", methods=("GET", "POST"))
@login_required
def conversation(contact_id):
    user = current_user()
    with db() as connection:
        contact = accepted_contact(connection, user["id"], contact_id)
        if not contact:
            abort(403)
        if request.method == "POST":
            if request.form.get("intent") == "file":
                uploaded = request.files.get("file")
                expiry_choice = request.form.get("expiry", "7d")
                if not uploaded or not uploaded.filename:
                    flash("Choisissez un fichier avant de l'envoyer.", "error")
                elif not contact["public_key"]:
                    flash("Ce contact n'a pas encore publié de clé publique.", "error")
                else:
                    try:
                        name, data = read_upload()
                        blob = encrypt_file(data, name, keys.public_from_json(contact["public_key"]))
                        stored_name = uuid.uuid4().hex + ".rsa"
                        expires_at, expires_on_download = {
                            "24h": (expiration(hours=24), 0),
                            "7d": (expiration(days=7), 0),
                            "first_download": (expiration(days=7), 1),
                        }.get(expiry_choice, (expiration(days=7), 0))
                        with open(os.path.join(app.config["UPLOAD_FOLDER"], stored_name), "wb") as output:
                            output.write(blob)
                        connection.execute("""INSERT INTO transfers (sender_id, recipient_id, original_name, stored_name, size, created_at, expires_at, expires_on_download)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", (user["id"], contact_id, name, stored_name, len(blob), now().isoformat(), expires_at, expires_on_download))
                        connection.commit()
                        flash(f"Fichier chiffré et envoyé à {contact['username']}.", "ok")
                        return redirect(url_for("conversation", contact_id=contact_id))
                    except RSAError as err:
                        flash(str(err), "error")
            text = request.form.get("text", "").strip()
            if request.form.get("intent") == "file":
                text = ""
            if not text and request.form.get("intent") != "file":
                flash("Écrivez un message avant de l'envoyer.", "error")
            elif text and len(text) > 5000:
                flash("Le message est limité à 5 000 caractères.", "error")
            elif text and not contact["public_key"]:
                flash("Ce contact n'a pas encore publié de clé publique.", "error")
            elif text:
                encrypted = encrypt_file(text.encode("utf-8"), "message.txt", keys.public_from_json(contact["public_key"]))
                connection.execute("INSERT INTO messages (sender_id, recipient_id, encrypted_payload, created_at) VALUES (?, ?, ?, ?)",
                                   (user["id"], contact_id, encrypted, now().isoformat()))
                connection.commit()
                return redirect(url_for("conversation", contact_id=contact_id))
        connection.execute("UPDATE messages SET read_at = ? WHERE sender_id = ? AND recipient_id = ? AND read_at IS NULL", (now().isoformat(), contact_id, user["id"]))
        connection.commit()
        thread = connection.execute("""
            SELECT messages.*, users.username AS sender_name FROM messages
            JOIN users ON users.id = messages.sender_id
            WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
            ORDER BY created_at ASC
        """, (user["id"], contact_id, contact_id, user["id"])).fetchall()
    return render_template("conversation.html", page="messages", contact=contact, thread=thread, user_id=user["id"])

@app.get("/messages/<int:message_id>/download")
@login_required
def download_message(message_id):
    user = current_user()
    with db() as connection:
        message = connection.execute("SELECT * FROM messages WHERE id = ? AND recipient_id = ?", (message_id, user["id"])).fetchone()
        if not message:
            abort(404)
        connection.execute("UPDATE messages SET read_at = COALESCE(read_at, ?) WHERE id = ?", (now().isoformat(), message_id))
        connection.commit()
    return send_file(BytesIO(message["encrypted_payload"]), as_attachment=True, download_name="message.rsa", mimetype="application/octet-stream")

@app.post("/messages/<int:message_id>/decrypt")
@login_required
def decrypt_message(message_id):
    user = current_user()
    with db() as connection:
        message = connection.execute(
            "SELECT encrypted_payload FROM messages WHERE id = ? AND recipient_id = ?",
            (message_id, user["id"]),
        ).fetchone()
    if not message:
        abort(404)
    key_file = request.files.get("key_file")
    if not key_file or not key_file.filename:
        raise FileFormatError("Importez votre fichier de clé privée.")
    private = keys.private_from_json(key_file.read().decode("utf-8", "replace"))
    _, plaintext = decrypt_file(message["encrypted_payload"], private)
    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError as err:
        raise FileFormatError("Le contenu déchiffré n'est pas un message texte UTF-8.") from err
    return jsonify(message=text)

@app.get("/transfers/<int:transfer_id>/download")
@login_required
def download_transfer(transfer_id):
    user = current_user()
    with db() as connection:
        cleanup_expired(connection, app.config["UPLOAD_FOLDER"])
        transfer = connection.execute("SELECT * FROM transfers WHERE id = ? AND recipient_id = ?", (transfer_id, user["id"])).fetchone()
        if not transfer or transfer["expired_at"]:
            abort(404)
        timestamp = now().isoformat()
        connection.execute("UPDATE transfers SET downloaded_at = ? WHERE id = ?", (timestamp, transfer_id))
        connection.commit()
    path = os.path.join(app.config["UPLOAD_FOLDER"], transfer["stored_name"])
    if not os.path.exists(path):
        abort(404)
    if transfer["expires_on_download"]:
        with open(path, "rb") as source:
            content = source.read()
        os.remove(path)
        with db() as connection:
            connection.execute("UPDATE transfers SET expired_at = ? WHERE id = ?", (now().isoformat(), transfer_id))
            connection.commit()
        return send_file(BytesIO(content), as_attachment=True, download_name=transfer["original_name"] + ".rsa", mimetype="application/octet-stream")
    return send_file(path, as_attachment=True, download_name=transfer["original_name"] + ".rsa", mimetype="application/octet-stream")

@app.get("/keys")
@login_required
def keys_page():
    user = current_user()
    return render_template("keys.html", page="keys", has_key=bool(user["public_key"]))

@app.post("/keys/generate")
@login_required
def keys_generate():
    if request.form.get("bits", type=int) != KEY_BITS:
        return jsonify(error="Taille de clé non autorisée."), 400
    pub, priv = keys.generate_keypair(KEY_BITS)
    user = current_user()
    with db() as connection:
        connection.execute("UPDATE users SET public_key = ? WHERE id = ?", (pub.to_json(), user["id"]))
        connection.commit()
    return jsonify(n=str(pub.n), e=str(pub.e),
                   public_json=pub.to_json(), private_json=priv.to_json())

@app.get("/encrypt")
def encrypt_page():
    return render_template("encrypt.html", page="encrypt")

@app.post("/encrypt")
def encrypt_post():
    name, data = read_encrypt_input()
    blob = encrypt_file(data, name, read_key("public"))
    return send_file(BytesIO(blob), as_attachment=True, download_name=name + ".rsa",
                     mimetype="application/octet-stream")

@app.get("/decrypt")
def decrypt_page():
    return render_template("decrypt.html", page="decrypt")

@app.post("/decrypt")
def decrypt_post():
    _, blob = read_upload()
    name, data = decrypt_file(blob, read_key("private"))
    return send_file(BytesIO(data), as_attachment=True, download_name=os.path.basename(name),
                     mimetype="application/octet-stream")

if __name__ == "__main__":
    app.run(debug=True)
