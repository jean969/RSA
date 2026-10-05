import pytest
from rsa_core.cipher import decrypt_int, encrypt_int
from rsa_core.errors import KeyFormatError
from rsa_core.keys import (generate_keypair, make_keypair, parse_int,
                           private_from_json, public_from_json)

def test_textbook_example():
    pub, priv = make_keypair(61, 53, e=17)
    assert (pub.n, priv.d) == (3233, 2753)
    c = encrypt_int(65, pub)
    assert c == 2790 and decrypt_int(c, priv) == 65

def test_generated_keys_roundtrip_with_and_without_crt():
    pub, priv = generate_keypair(256)
    assert pub.n.bit_length() == 256
    slow = type(priv)(priv.n, priv.d)
    for m in (0, 1, 42, pub.n - 1):
        c = encrypt_int(m, pub)
        assert decrypt_int(c, priv) == decrypt_int(c, slow) == m

def test_json_roundtrip():
    pub, priv = generate_keypair(128)
    assert public_from_json(pub.to_json()) == pub
    assert private_from_json(priv.to_json()) == priv

def test_invalid_inputs():
    with pytest.raises(KeyFormatError):
        parse_int("12ab", "module n")
    with pytest.raises(KeyFormatError):
        public_from_json("pas du json")
    with pytest.raises(KeyFormatError):
        public_from_json('{"n": "3233"}')
