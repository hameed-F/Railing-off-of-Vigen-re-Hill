import random, string
from cipher import *

def rnd(n): return "".join(random.choice(string.ascii_uppercase) for _ in range(n))

def test_roundtrip():
    random.seed(1)
    for _ in range(500):
        p = rnd(random.randint(0, 300))
        h = rnd(random.choice((4, 9)))
        while True:
            try: hill_key(h); break
            except ValueError: h = rnd(len(h))
        v, r = rnd(random.randint(10, 20)), random.randint(2, 15)
        assert decrypt(encrypt(p, h, v, r), h, v, r) == p

def test_cleaning():
    assert decrypt(encrypt("Hello, World 123!", "HILL", "SECURITYKEY", 3), "HILL", "SECURITYKEY", 3) == "HELLOWORLD"

if __name__ == "__main__":
    test_roundtrip(); test_cleaning(); print("All tests passed")
