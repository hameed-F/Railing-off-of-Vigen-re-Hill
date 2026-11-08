import random, string
from cipher import *

def rnd(n): return "".join(random.choice(string.ascii_uppercase) for _ in range(n))

def good_hill(n):
    while True:
        h = rnd(n * n)
        try: hill_key_checked(h); return h
        except ValueError: pass

def good_vkey(L):
    while True:
        v = rnd(L)
        if vigenere_weakness(v) is None: return v

def test_roundtrip():
    random.seed(1)
    for _ in range(500):
        p = rnd(random.randint(20, 300))
        h = good_hill(random.choice((2, 3)))
        v, r = good_vkey(random.randint(10, 20)), random.randint(2, 15)
        assert decrypt(encrypt(p, h, v, r), h, v, r) == p

def test_cleaning():
    assert decrypt(encrypt("Hello, World 123!", "HILL", "SECURITYKEY", 3), "HILL", "SECURITYKEY", 3) == "HELLOWORLD"

def test_empty_and_short():
    assert encrypt("", "HILL", "SECURITYKEY", 3) == ""
    assert decrypt(encrypt("ABCDEFGHIJK", "HILL", "SECURITYKEY", 3), "HILL", "SECURITYKEY", 3) == "ABCDEFGHIJK"

def _rejects(f):
    try: f()
    except ValueError: return True
    return False

def test_weak_keys_rejected():
    assert _rejects(lambda: encrypt("HELLOWORLDTEST", "BAAB", "NETWORKSECURITY", 3))      # identity Hill
    assert _rejects(lambda: encrypt("HELLOWORLDTEST", "DAAF", "NETWORKSECURITY", 3))      # diagonal Hill
    assert _rejects(lambda: encrypt("HELLOWORLDTEST", "DDDD", "NETWORKSECURITY", 3))      # not invertible
    assert _rejects(lambda: encrypt("HELLOWORLDTEST", "HILL", "AAAAAAAAAA", 3))
    assert _rejects(lambda: encrypt("HELLOWORLDTEST", "HILL", "ABABABABAB", 3))
    assert _rejects(lambda: encrypt("HELLOWORLDTEST", "HILL", "ABCDEABCDE", 3))           # repeated 5-letter word
    assert _rejects(lambda: encrypt("HELLO", "HILL", "NETWORKSECURITY", 5))               # rails >= length
    assert _rejects(lambda: encrypt("HELLOWORLDTEST", "HILL", "SHORTKEY", 3))             # < 10 letters
    assert _rejects(lambda: encrypt("HELLOWORLDTEST", "HILL", "NETWORKSECURITY", 1))      # 1 rail

if __name__ == "__main__":
    test_roundtrip(); test_cleaning(); test_empty_and_short(); test_weak_keys_rejected()
    print("All tests passed")
