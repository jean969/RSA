import os
from io import BytesIO

from flask import Flask, jsonify, redirect, render_template, request, send_file, url_for

from rsa_core import keys
from rsa_core.cipher import decrypt_file, encrypt_file
from rsa_core.errors import FileFormatError, RSAError

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8 Mo
ALLOWED_BITS = (1024, 2048)

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

@app.get("/")
def index():
    return render_template("index.html", page="home")

@app.get("/keys")
def keys_page():
    return render_template("keys.html", page="keys", bits=ALLOWED_BITS)

@app.post("/keys/generate")
def keys_generate():
    bits = request.form.get("bits", type=int)
    if bits not in ALLOWED_BITS:
        return jsonify(error="Taille de clé non autorisée."), 400
    pub, priv = keys.generate_keypair(bits)  # rien n'est stocké côté serveur
    return jsonify(n=str(pub.n), e=str(pub.e), d=str(priv.d),
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
