import os
import pytest
from rsa_core.cipher import (clear_block_size, cipher_block_size, decrypt_file, encrypt_file)
from rsa_core.errors import DecryptionError, FileFormatError
from rsa_core.keys import generate_keypair

PUB, PRIV = generate_keypair(512)

def test_block_sizes_for_1024_bits():
    n = 1 << 1023
    assert clear_block_size(n) == 127 and cipher_block_size(n) == 128

@pytest.mark.parametrize("data", [b"", b"A", b"\x00\x00\x00", b"\x00" * 200 + b"x", os.urandom(5000)])
def test_roundtrip(data):
    name, out = decrypt_file(encrypt_file(data, "demo é.bin", PUB), PRIV)
    assert (name, out) == ("demo é.bin", data)

def test_wrong_key_is_detected():
    blob = encrypt_file(b"secret" * 100, "a.txt", PUB)
    _, other = generate_keypair(512)
    with pytest.raises(DecryptionError):
        decrypt_file(blob, other)

def test_corrupted_and_foreign_files():
    blob = bytearray(encrypt_file(b"secret" * 100, "a.txt", PUB))
    blob[-5] ^= 0xFF
    with pytest.raises(DecryptionError):
        decrypt_file(bytes(blob), PRIV)
    with pytest.raises(FileFormatError):
        decrypt_file(b"ceci n'est pas un rsa", PRIV)
    with pytest.raises(FileFormatError):
        decrypt_file(b"RS", PRIV)
