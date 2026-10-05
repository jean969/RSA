import secrets

def _sieve(limit=200):
    flags = [True] * (limit + 1)
    flags[0:2] = [False, False]
    for i in range(2, int(limit ** 0.5) + 1):
        if flags[i]:
            flags[i * i::i] = [False] * len(flags[i * i::i])
    return [i for i, ok in enumerate(flags) if ok]

SMALL_PRIMES = _sieve()

def is_probable_prime(n, rounds=40):
    """Test de Miller-Rabin (probabiliste, erreur < 4**-rounds)."""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """Premier de exactement `bits` bits (deux bits de tête à 1 : p*q a 2*bits bits)."""
    if bits < 8:
        raise ValueError("bits doit être >= 8")
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if is_probable_prime(c):
            return c
