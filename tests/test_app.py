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

def test_errors_are_json(client):
    r = client.post("/encrypt", data={"file": (BytesIO(b"x"), "a"), "n": "abc", "e": "65537"})
    assert r.status_code == 400 and "chiffres" in r.get_json()["error"]
    assert client.post("/decrypt", data={"n": "1", "d": "1"}).status_code == 400
    assert client.post("/keys/generate", data={"bits": "8"}).status_code == 400
