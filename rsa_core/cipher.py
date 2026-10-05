import hashlib
from functools import lru_cache

from . import fileformat
from .errors import DecryptionError
from .keys import PrivateKey, PublicKey

def clear_block_size(n):
    """Octets en clair par bloc : 8*k <= bits-1, donc tout bloc est < n."""
    return (n.bit_length() - 1) // 8

def cipher_block_size(n):
    return (n.bit_length() + 7) // 8

def encrypt_int(m, pub):
    if not 0 <= m < pub.n:
        raise ValueError("M doit vérifier 0 <= M < n")
    return pow(m, pub.e, pub.n)

@lru_cache(maxsize=8)
def _crt_params(p, q, d):
    return d % (p - 1), d % (q - 1), pow(q, -1, p)

def decrypt_int(c, priv):
    if not 0 <= c < priv.n:
        raise DecryptionError("Bloc invalide pour cette clé.")
    if priv.p and priv.q:  # théorème des restes chinois : ~3x plus rapide
        p, q = priv.p, priv.q
        dp, dq, qinv = _crt_params(p, q, priv.d)
        m1, m2 = pow(c, dp, p), pow(c, dq, q)
        return m2 + ((qinv * (m1 - m2)) % p) * q
    return pow(c, priv.d, priv.n)

def encrypt_bytes(data, pub):
    k, kc = clear_block_size(pub.n), cipher_block_size(pub.n)
    out = bytearray()
    for i in range(0, len(data), k):
        m = int.from_bytes(data[i:i + k], "big")
        out += encrypt_int(m, pub).to_bytes(kc, "big")
    return bytes(out)

def decrypt_bytes(blob, priv, size):
    k, kc = clear_block_size(priv.n), cipher_block_size(priv.n)
    count = len(blob) // kc
    if len(blob) % kc or count != -(-size // k):
        raise DecryptionError("Fichier corrompu : taille des blocs incohérente.")
    out = bytearray()
    for idx in range(count):
        c = int.from_bytes(blob[idx * kc:(idx + 1) * kc], "big")
        length = k if idx < count - 1 else size - (count - 1) * k
        try:
            out += decrypt_int(c, priv).to_bytes(length, "big")
        except OverflowError:
            raise DecryptionError("Déchiffrement impossible : mauvaise clé ou fichier corrompu.")
    return bytes(out)

def encrypt_file(data, name, pub):
    header = fileformat.Header(name, len(data), clear_block_size(pub.n),
                               cipher_block_size(pub.n), hashlib.sha256(data).digest())
    return fileformat.pack(header, encrypt_bytes(data, pub))

def decrypt_file(blob, priv):
    header, payload = fileformat.unpack(blob)
    if (header.clear_block, header.cipher_block) != (clear_block_size(priv.n), cipher_block_size(priv.n)):
        raise DecryptionError("Cette clé privée ne correspond pas à la clé publique utilisée pour chiffrer.")
    data = decrypt_bytes(payload, priv, header.size)
    if hashlib.sha256(data).digest() != header.digest:
        raise DecryptionError("Déchiffrement impossible : mauvaise clé ou fichier corrompu.")
    return header.name, data
