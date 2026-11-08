"""Attack success + computational effort vs CIPHERTEXT LENGTH (assignment deliverable 2)."""
import random, time, string
from cipher import *
from attack import *
random.seed(7)
rnd = lambda n: "".join(random.choice(string.ascii_uppercase) for _ in range(n))
CORPUS = clean(open("sample_text.txt").read())
def text(n):  # English-like text of any length (corpus repeated if needed)
    s = (CORPUS * (n // len(CORPUS) + 2)); o = random.randrange(len(CORPUS)); return s[o:o + n]
def hk():
    while True:
        w = rnd(4)
        try: hill_key_checked(w); return w
        except ValueError: pass
def gv():
    while True:
        v = rnd(random.randint(10, 16))
        if vigenere_weakness(v) is None: return v
T = 30
print(f"{'n':>7} | {'KPA(m=60) ok%':>13} {'time ms':>8} | {'Freq 3-stage ok%':>16} {'time ms':>8} | {'Freq 2-stage ok%':>16}")
for n in [100, 200, 500, 1000, 2000, 5000, 10000]:
    k = f = f2 = 0; tk = tf = 0.0
    for _ in range(T):
        p, vk, r = text(n), gv(), random.randint(2, 12)
        c = encrypt(p, hk(), vk, r)
        t = time.perf_counter(); res = known_plaintext_attack(c, p[:60]); tk += time.perf_counter() - t
        k += bool(res and res[3] == p)
        t = time.perf_counter(); f += frequency_attack(c)[2] == p; tf += time.perf_counter() - t
        if n <= 2000: f2 += frequency_attack(encrypt_2stage(p, vk, r))[2] == p
    print(f"{n:>7} | {100*k/T:>12.0f}% {1000*tk/T:>8.2f} | {100*f/T:>15.0f}% {1000*tf/T:>8.1f} | {('%.0f%%' % (100*f2/T)) if n <= 2000 else 'n/a':>16}")
