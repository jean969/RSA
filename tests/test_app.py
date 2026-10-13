from io import BytesIO
from unittest.mock import patch
import uuid
import pytest
from app import app, db, now
from rsa_core import keys
from rsa_core.cipher import encrypt_file
from storage import contact_pair


@pytest.fixture
def client():
    app.config["TESTING"] = True
    return app.test_client()


def create_account(client):
    username = "test_" + uuid.uuid4().hex[:12]
    client.post("/register", data={"username": username, "password": "test-password"})
    client.post("/login", data={"username": username, "password": "test-password"})
    return username


def test_pages_load(client):
    for url in ("/encrypt", "/decrypt"):
        assert client.get(url).status_code == 200

def test_keys_page_requires_account(client):
    assert client.get("/keys").status_code == 302

def test_generate_encrypt_decrypt_through_http(client):
    pub, priv = keys.generate_keypair(1024)
    payload = b"reclamations\x00\x01" * 300
    enc = client.post("/encrypt", data={"file": (BytesIO(payload), "r.xlsx"), "n": str(pub.n), "e": str(pub.e)})
    assert enc.status_code == 200 and "r.xlsx.rsa" in enc.headers["Content-Disposition"]
    dec = client.post("/decrypt", data={"file": (BytesIO(enc.data), "r.xlsx.rsa"),
                                         "key_file": (BytesIO(priv.to_json().encode()), "cle.json")})
    assert dec.status_code == 200 and dec.data == payload

def test_encrypt_text_through_http(client):
    pub, priv = keys.generate_keypair(1024)
    text = "Bonjour, voici un texte à chiffrer.\nDeuxième ligne."
    enc = client.post("/encrypt", data={"text": text, "n": str(pub.n), "e": str(pub.e)})
    assert enc.status_code == 200 and "texte.txt.rsa" in enc.headers["Content-Disposition"]
    dec = client.post("/decrypt", data={"file": (BytesIO(enc.data), "texte.txt.rsa"),
                                         "n": str(priv.n), "d": str(priv.d)})
    assert dec.status_code == 200 and dec.data == text.encode("utf-8")
    assert "texte.txt" in dec.headers["Content-Disposition"]

def test_encrypt_requires_exactly_one_input(client):
    pub, _ = keys.generate_keypair(1024)
    empty = client.post("/encrypt", data={"text": "", "n": str(pub.n), "e": str(pub.e)})
    both = client.post("/encrypt", data={"file": (BytesIO(b"file"), "a.txt"),
                                          "text": "texte", "n": str(pub.n), "e": str(pub.e)})
    assert empty.status_code == both.status_code == 400
    assert "Choisis un fichier ou saisis un texte" in empty.get_json()["error"]

def test_errors_are_json(client):
    r = client.post("/encrypt", data={"file": (BytesIO(b"x"), "a"), "n": "abc", "e": "65537"})
    assert r.status_code == 400 and "chiffres" in r.get_json()["error"]
    assert client.post("/decrypt", data={"n": "1", "d": "1"}).status_code == 400

def test_generated_public_key_is_saved_to_logged_in_user(client):
    username = create_account(client)
    public, private = keys.make_keypair(61, 53)
    with patch("app.keys.generate_keypair", return_value=(public, private)) as generate:
        response = client.post("/keys/generate", data={"bits": "2048"})

    assert response.status_code == 200
    assert generate.call_args.args == (2048,)
    payload = response.get_json()
    assert payload["public_json"] == public.to_json()
    assert payload["private_json"] == private.to_json()
    assert "d" not in payload
    from app import db
    with db() as connection:
        saved = connection.execute(
            "SELECT public_key FROM users WHERE username = ?", (username,)
        ).fetchone()["public_key"]
    assert saved == public.to_json()

def test_key_generation_requires_login_and_2048_bits(client):
    assert client.post("/keys/generate", data={"bits": "2048"}).status_code == 302
    create_account(client)
    response = client.post("/keys/generate", data={"bits": "1024"})
    assert response.status_code == 400
    assert response.get_json()["error"] == "Taille de clé non autorisée."

def add_received_message(client, public_key, plaintext):
    recipient_name = create_account(client)
    sender_name = "sender_" + uuid.uuid4().hex[:12]
    encrypted = encrypt_file(plaintext.encode("utf-8"), "message.txt", public_key)
    timestamp = now().isoformat()
    with db() as connection:
        recipient_id = connection.execute(
            "SELECT id FROM users WHERE username = ?", (recipient_name,)
        ).fetchone()["id"]
        cursor = connection.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (sender_name, "unused-test-hash", timestamp),
        )
        sender_id = cursor.lastrowid
        user_a, user_b = contact_pair(recipient_id, sender_id)
        connection.execute(
            """INSERT INTO contacts (user_a, user_b, requested_by, status, created_at, updated_at)
               VALUES (?, ?, ?, 'accepted', ?, ?)""",
            (user_a, user_b, sender_id, timestamp, timestamp),
        )
        cursor = connection.execute(
            """INSERT INTO messages (sender_id, recipient_id, encrypted_payload, created_at)
               VALUES (?, ?, ?, ?)""",
            (sender_id, recipient_id, encrypted, timestamp),
        )
        message_id = cursor.lastrowid
    return sender_id, message_id, encrypted

def test_recipient_can_decrypt_message_in_chat_without_persisting_plaintext(client):
    public, private = keys.generate_keypair(1024)
    plaintext = "Bonjour, message déchiffré dans la conversation."
    sender_id, message_id, encrypted = add_received_message(client, public, plaintext)

    page = client.get(f"/messages/{sender_id}")
    assert page.status_code == 200
    assert "Déchiffrer le message".encode("utf-8") in page.data
    assert plaintext.encode("utf-8") not in page.data

    response = client.post(
        f"/messages/{message_id}/decrypt",
        data={"key_file": (BytesIO(private.to_json().encode("utf-8")), "cle_privee.json")},
    )
    assert response.status_code == 200
    assert response.get_json()["message"] == plaintext
    with db() as connection:
        saved = connection.execute(
            "SELECT encrypted_payload FROM messages WHERE id = ?", (message_id,)
        ).fetchone()["encrypted_payload"]
    assert saved == encrypted

def test_message_decryption_rejects_wrong_private_key(client):
    public, _ = keys.generate_keypair(1024)
    _, message_id, _ = add_received_message(client, public, "Message confidentiel.")
    _, wrong_private = keys.generate_keypair(1024)

    response = client.post(
        f"/messages/{message_id}/decrypt",
        data={"key_file": (BytesIO(wrong_private.to_json().encode("utf-8")), "mauvaise_cle.json")},
    )

    assert response.status_code == 400
    assert "error" in response.get_json()
