"""
Benchmark / analysis functions. Used by gui.py (on the text typed at run time)
and runnable alone:  python3 benchmark.py [textfile]   (default: sample_text.txt)
"""
import random, string, sys, time
from cipher import *
from attack import *


def rnd(n): return "".join(random.choice(string.ascii_uppercase) for _ in range(n))


def rand_hill(n=2):
    """Random invertible n x n Hill key (n*n letters)."""
    while True:
        w = rnd(n * n)
        try: hill_key(w); return w
        except ValueError: pass


def rand_keys(n=2): return rand_hill(n), rnd(random.randint(10, 16)), random.randint(2, 12)


def _time(f, *a):
    """Seconds per call (best of 3, auto-repeated so tiny inputs are measurable)."""
    t0 = time.perf_counter(); f(*a); one = max(time.perf_counter() - t0, 1e-7)
    reps = max(1, min(2000, int(0.05 / one))); best = 1e9
    for _ in range(3):
        t = time.perf_counter()
        for _i in range(reps): f(*a)
        best = min(best, (time.perf_counter() - t) / reps)
    return best


def performance(text, h, v, r):
    """Encrypt/decrypt time vs the Shift cipher; the text is repeated 1x..1000x to show O(n)."""
    p = clean(text); out = ["Letters      | Encrypt      | Decrypt      | Shift enc    | Slower than Shift"]
    for mult in (1, 10, 100, 1000):
        t = p * mult; c = encrypt(t, h, v, r)
        e, d, s = _time(encrypt, t, h, v, r), _time(decrypt, c, h, v, r), _time(shift_encrypt, t, 3)
        out.append(f"{len(t):>12} | {e*1e3:9.3f} ms | {d*1e3:9.3f} ms | {s*1e3:9.3f} ms | {e/s:5.1f}x")
    out.append("· Time grows linearly with length, so encryption and decryption are O(n).")
    return out


def ic_by_stage(text, h, v, r):
    """Index of Coincidence after each stage (English ~0.066, random ~0.038)."""
    p = clean(text); a = hill_encrypt(p, hill_key(h)); b = vigenere_encrypt(a, clean(v)); c = rail_fence_encrypt(b, r)
    out = [f"{n:<24} IC = {index_of_coincidence(t):.4f}" for n, t in
           [("Plaintext", p), ("After Hill", a), ("After Vigenere", b), ("After Rail Fence", c)]]
    out.append("· English ~0.066, random ~0.038. IC near 0.04 means letter counts reveal nothing.")
    if len(p) < 100: out.append("· Text is short, so IC values are noisy.")
    return out


def at_min(n, L): return min_known(n, L)


def kpa_vs_known(text, trials, n=2):
    """Known-plaintext attack: success vs how many plaintext letters the attacker knows."""
    p = clean(text); ms = [m for m in (10, 20, 30, 40, 50, 60, 80, 100, 150, 200, 300) if m <= len(p)]
    if not ms: return ["✗ Text needs at least 10 letters for this test."]
    out = ["Known letters | Success | Avg time"]
    for m in ms:
        ok = tt = 0
        for _i in range(trials):
            h, v, r = rand_keys(n); c = encrypt(p, h, v, r)
            t0 = time.perf_counter(); res = known_plaintext_attack(c, p[:m]); tt += time.perf_counter() - t0
            ok += bool(res and res[3] == p)
        out.append(f"{m:>13} | {100*ok/trials:5.0f}% | {1e3*tt/trials:7.2f} ms")
    out.append(f"· Each row: {trials} random key sets ({n}x{n} Hill, key length 10-16, 2-12 rails) applied to YOUR text.")
    out.append(f"· Letters needed for key length 10-16 (attack.min_known): {at_min(n, 10)}-{at_min(n, 16)}.")
    return out


def attack_vs_length(text, trials, n=2):
    """Both attacks vs ciphertext length (prefixes of your text), random keys each trial."""
    p = clean(text); lens = sorted({max(20, int(len(p) * f)) for f in (.25, .5, .75, 1)}); lens = [L for L in lens if L <= len(p)]
    if not lens: return ["✗ Text needs at least 20 letters for this test."]
    mk = n * (18 + n)          # known letters given to the KPA: enough for any key length up to 16
    out = [f"Ciphertext len | KPA (m={mk}) | KPA time | Freq attack 3-stage | Freq attack 2-stage (no Hill) | Freq time"]
    for L in lens:
        q = p[:L]; m = min(mk, L); k = f3 = f2 = 0; kt = ft = 0.0
        for _i in range(trials):
            h, v, r = rand_keys(n); c = encrypt(q, h, v, r)
            t0 = time.perf_counter(); res = known_plaintext_attack(c, q[:m]); kt += time.perf_counter() - t0
            k += bool(res and res[3] == q)
            t0 = time.perf_counter(); f3 += frequency_attack(c)[2] == q; ft += time.perf_counter() - t0
            f2 += frequency_attack(encrypt_2stage(q, v, r))[2] == q
        out.append(f"{L:>14} | {100*k/trials:8.0f}% | {1e3*kt/trials:6.1f} ms | {100*f3/trials:18.0f}% | {100*f2/trials:28.0f}% | {1e3*ft/trials:6.1f} ms")
    out.append("· Frequency analysis needs a few hundred letters; the Hill stage defeats it at every length.")
    return out


def full_report(text, h, v, r, trials=10):
    p = clean(text)
    n = hill_size(h)
    s = [f"## Results for YOUR text ({len(p)} letters) · Hill {n}x{n} ({h.upper()}) · Vigenere key length {len(clean(v))} · {r} rails"]
    if len(p) < 100: s.append("· Short text: frequency attacks need hundreds of letters, known-plaintext needs roughly 40 (2x2) to 120+ (5x5) letters.")
    s += ["", "## 1. Efficiency (encryption / decryption vs Shift cipher)"] + performance(text, h, v, r)
    s += ["", "## 2. Statistics after each stage"] + ic_by_stage(text, h, v, r)
    s += ["", "## 3. Known-plaintext attack vs amount of known plaintext"] + kpa_vs_known(text, trials, n)
    s += ["", "## 4. Attacks vs ciphertext length"] + attack_vs_length(text, trials, n)
    return "\n".join(s)


if __name__ == "__main__":
    random.seed(486)
    f = sys.argv[1] if len(sys.argv) > 1 else "sample_text.txt"
    print(full_report(open(f).read(), "HILL", "NETWORKSECURITY", 5, trials=20))
