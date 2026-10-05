from rsa_core.primes import generate_prime, is_probable_prime

def test_small_cases():
    assert [n for n in range(30) if is_probable_prime(n)] == [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]

def test_carmichael_numbers_are_rejected():
    for n in (561, 1105, 1729, 2465, 41041):
        assert not is_probable_prime(n)

def test_known_large_prime():
    assert is_probable_prime(2 ** 127 - 1)
    assert not is_probable_prime(2 ** 127 + 1)

def test_generate_prime_has_requested_size():
    p = generate_prime(128)
    assert p.bit_length() == 128 and is_probable_prime(p)
