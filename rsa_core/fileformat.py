"""Format .rsa : MAGIC | version | longueur nom | nom | taille | bloc clair | bloc chiffré | SHA-256 | blocs."""
import struct
from dataclasses import dataclass

from .errors import FileFormatError

MAGIC, VERSION = b"RSAF", 1
_HEAD = struct.Struct(">4sBH")
_META = struct.Struct(">QHH32s")

@dataclass(frozen=True)
class Header:
    name: str
    size: int
    clear_block: int
    cipher_block: int
    digest: bytes

def pack(header, payload):
    name = header.name.encode("utf-8")
    return (_HEAD.pack(MAGIC, VERSION, len(name)) + name +
            _META.pack(header.size, header.clear_block, header.cipher_block, header.digest) + payload)

def unpack(blob):
    try:
        magic, version, name_len = _HEAD.unpack_from(blob, 0)
        if magic != MAGIC or version != VERSION:
            raise FileFormatError("Ce fichier n'est pas un .rsa produit par ce site.")
        pos = _HEAD.size
        name = blob[pos:pos + name_len].decode("utf-8")
        pos += name_len
        size, clear, cipher, digest = _META.unpack_from(blob, pos)
        pos += _META.size
    except (struct.error, UnicodeDecodeError):
        raise FileFormatError("Fichier .rsa incomplet ou corrompu.")
    return Header(name, size, clear, cipher, digest), blob[pos:]
