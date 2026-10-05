import json
from dataclasses import dataclass
from math import gcd
from typing import Optional

from .errors import KeyFormatError
from .primes import generate_prime

DEFAULT_E = 65537
MIN_BITS = 16

@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int

    def to_json(self):
        return json.dumps({"type": "rsa-public", "n": str(self.n), "e": str(self.e)}, indent=2)

@dataclass(frozen=True)
class PrivateKey:
    n: int
    d: int
    p: Optional[int] = None  # facultatifs : accélèrent le déchiffrement (CRT)
    q: Optional[int] = None

    def to_json(self):
        data = {"type": "rsa-private", "n": str(self.n), "d": str(self.d)}
        if self.p and self.q:
            data.update(p=str(self.p), q=str(self.q))
        return json.dumps(data, indent=2)

def parse_int(value, label):
    text = "".join(str(value).split())
    if not text.isdigit():
        raise KeyFormatError(f"Le {label} doit contenir uniquement des chiffres.")
    return int(text)

def _check_n(n):
    if n.bit_length() < MIN_BITS:
        raise KeyFormatError("Le module n est trop petit.")
    return n

def public_key(n, e):
    n, e = parse_int(n, "module n"), parse_int(e, "exposant e")
    return PublicKey(_check_n(n), e)

def private_key(n, d, p=None, q=None):
    n, d = parse_int(n, "module n"), parse_int(d, "exposant d")
    p = parse_int(p, "facteur p") if p else None
    q = parse_int(q, "facteur q") if q else None
    return PrivateKey(_check_n(n), d, p, q)

def _load(text):
    try:
        data = json.loads(text)
        assert isinstance(data, dict)
        return data
    except (ValueError, AssertionError):
        raise KeyFormatError("Fichier de clé illisible (JSON attendu).")

def public_from_json(text):
    data = _load(text)
    try:
        return public_key(data["n"], data["e"])
    except KeyError:
        raise KeyFormatError("Ce fichier n'est pas une clé publique (champs n et e attendus).")

def private_from_json(text):
    data = _load(text)
    try:
        return private_key(data["n"], data["d"], data.get("p"), data.get("q"))
    except KeyError:
        raise KeyFormatError("Ce fichier n'est pas une clé privée (champs n et d attendus).")

def make_keypair(p, q, e=DEFAULT_E):
    """Construit une paire à partir de deux premiers (utile pour les tests)."""
    n, phi = p * q, (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError("e n'est pas premier avec phi(n)")
    d = pow(e, -1, phi)
    return PublicKey(n, e), PrivateKey(n, d, p, q)

def generate_keypair(bits=1024, e=DEFAULT_E):
    """Paire RSA dont le module n fait exactement `bits` bits."""
    if bits < 32 or bits % 2:
        raise ValueError("bits doit être pair et >= 32")
    while True:
        p, q = generate_prime(bits // 2), generate_prime(bits // 2)
        if p != q and gcd(e, (p - 1) * (q - 1)) == 1:
            return make_keypair(p, q, e)
