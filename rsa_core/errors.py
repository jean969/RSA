class RSAError(Exception):
    """Erreur lisible par l'utilisateur."""

class KeyFormatError(RSAError):
    pass

class FileFormatError(RSAError):
    pass

class DecryptionError(RSAError):
    pass
