from io import BytesIO
import pytest
from app import app
from rsa_core import keys

@pytest.fixture
def client():
    app.config["TESTING"] = True
    return app.test_client()

def test_pages_load(client):
    for url in ("/keys", "/encrypt", "/decrypt"):
        assert client.get(url).status_code == 200

def test_generate_encrypt_decrypt_through_http(client):
    k = client.post("/keys/generate", data={"bits": "1024"}).get_json()
    payload = b"reclamations\x00\x01" * 300
    enc = client.post("/encrypt", data={"file": (BytesIO(payload), "r.xlsx"), "n": k["n"], "e": k["e"]})
    assert enc.status_code == 200 and "r.xlsx.rsa" in enc.headers["Content-Disposition"]
    dec = client.post("/decrypt", data={"file": (BytesIO(enc.data), "r.xlsx.rsa"),
                                         "key_file": (BytesIO(k["private_json"].encode()), "cle.json")})
    assert dec.status_code == 200 and dec.data == payload

def test_encrypt_text_through_http(client):
    k = client.post("/keys/generate", data={"bits": "1024"}).get_json()
    text = "Bonjour, voici un texte à chiffrer.\nDeuxième ligne."
    enc = client.post("/encrypt", data={"text": text, "n": k["n"], "e": k["e"]})
    assert enc.status_code == 200 and "texte.txt.rsa" in enc.headers["Content-Disposition"]
    dec = client.post("/decrypt", data={"file": (BytesIO(enc.data), "texte.txt.rsa"),
                                         "n": k["n"], "d": k["d"]})
    assert dec.status_code == 200 and dec.data == text.encode("utf-8")
    assert "texte.txt" in dec.headers["Content-Disposition"]

def test_encrypt_requires_exactly_one_input(client):
    k = client.post("/keys/generate", data={"bits": "1024"}).get_json()
    empty = client.post("/encrypt", data={"text": "", "n": k["n"], "e": k["e"]})
    both = client.post("/encrypt", data={"file": (BytesIO(b"file"), "a.txt"),
                                          "text": "texte", "n": k["n"], "e": k["e"]})
    assert empty.status_code == both.status_code == 400
    assert "Choisis un fichier ou saisis un texte" in empty.get_json()["error"]

def test_errors_are_json(client):
    r = client.post("/encrypt", data={"file": (BytesIO(b"x"), "a"), "n": "abc", "e": "65537"})
    assert r.status_code == 400 and "chiffres" in r.get_json()["error"]
    assert client.post("/decrypt", data={"n": "1", "d": "1"}).status_code == 400
    assert client.post("/keys/generate", data={"bits": "8"}).status_code == 400
