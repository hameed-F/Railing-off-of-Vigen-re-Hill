"""
CT-486 CCP - 3-stage product cipher
  Stage 1  Hill (n x n) : block substitution / diffusion  (key: n*n letters -> n x n matrix, any n >= 2)
  Stage 2  Vigenere     : polyalphabetic substitution       (key: >= 10 letters)
  Stage 3  Rail Fence   : transposition                     (key: number of rails >= 2)
Encrypt: P -> Hill -> Vigenere -> Rail Fence -> C        Decrypt: reverse order.
Only A-Z are processed. If the length is not a multiple of n, the last incomplete block skips Hill (no padding needed).
"""
import re
import argparse
from math import gcd


def clean(text):
    return re.sub(r"[^A-Z]", "", text.upper())


# ---------- Stage 1: Hill (n x n, any n >= 2) ----------
# A key of n*n letters is read row by row as an n x n matrix (A=0 ... Z=25).
# Matrices are stored as flat tuples of n*n ints (row-major).  Nothing here is limited to 2x2 or 3x3:
# encryption costs O(n) per letter, and the only real requirement is det(M) coprime to 26.
from math import isqrt


def _size(m):
    n = isqrt(len(m))
    if n * n != len(m) or n < 2:
        raise ValueError("Matrix must be square (n x n) with n >= 2.")
    return n


def _det_int(rows):
    """Exact integer determinant (Bareiss, fraction-free) - works for any size."""
    a = [list(r) for r in rows]
    n, sign, prev = len(a), 1, 1
    for k in range(n - 1):
        if a[k][k] == 0:
            sw = next((i for i in range(k + 1, n) if a[i][k] != 0), None)
            if sw is None:
                return 0
            a[k], a[sw] = a[sw], a[k]
            sign = -sign
        for i in range(k + 1, n):
            for j in range(k + 1, n):
                a[i][j] = (a[i][j] * a[k][k] - a[i][k] * a[k][j]) // prev
        prev = a[k][k]
    return sign * a[n - 1][n - 1]


def hill_size(word):
    """Matrix size n for a key word of n*n letters, or raise ValueError."""
    k = len(clean(word)); n = isqrt(k)
    if n < 2 or n * n != k:
        raise ValueError(f"Hill key needs a square number of letters (4, 9, 16, 25...); you gave {k}.")
    return n


def hill_det(m):
    n = _size(m)
    return _det_int([m[i * n:(i + 1) * n] for i in range(n)]) % 26


def _inv(m):
    """Inverse of an n x n matrix mod 26 (adjugate method) or None if det shares a factor with 26."""
    n = _size(m)
    rows = [list(m[i * n:(i + 1) * n]) for i in range(n)]
    det = _det_int(rows) % 26
    if gcd(det, 26) != 1:
        return None
    di = pow(det, -1, 26)
    out = [0] * (n * n)
    for i in range(n):
        for j in range(n):
            minor = [r[:j] + r[j + 1:] for k, r in enumerate(rows) if k != i]
            cof = (-1) ** (i + j) * _det_int(minor)
            out[j * n + i] = (di * cof) % 26          # adjugate = transpose of cofactors
    return tuple(out)


def hill_key(word):
    w = clean(word)
    n = isqrt(len(w))
    if n < 2 or n * n != len(w):
        raise ValueError("Hill key must have n\u00d7n letters (4, 9, 16, 25, \u2026 for a 2\u00d72, 3\u00d73, 4\u00d74, 5\u00d75 \u2026 matrix).")
    m = tuple(ord(c) - 65 for c in w)
    if _inv(m) is None:
        raise ValueError("Hill matrix is not invertible mod 26 (determinant shares a factor with 26) - choose another key.")
    return m


def hill_apply(t, m):
    n = _size(m)
    out = []
    full = len(t) - len(t) % n
    for i in range(0, full, n):
        v = [ord(c) - 65 for c in t[i:i + n]]
        for r in range(n):
            out.append(chr(sum(m[r * n + k] * v[k] for k in range(n)) % 26 + 65))
    out.append(t[full:])                              # incomplete last block is left unchanged
    return "".join(out)


def hill_encrypt(t, m): return hill_apply(t, m)
def hill_decrypt(t, m): return hill_apply(t, _inv(m))


# ---------- Stage 2: Vigenere ----------
def vigenere_encrypt(p, key):
    k = len(key)
    return "".join(chr((ord(c) - 65 + ord(key[i % k]) - 65) % 26 + 65) for i, c in enumerate(p))


def vigenere_decrypt(c, key):
    k = len(key)
    return "".join(chr((ord(ch) - ord(key[i % k])) % 26 + 65) for i, ch in enumerate(c))


# ---------- Stage 3: Rail Fence ----------
def rail_order(n, rails):
    rows = [[] for _ in range(rails)]
    r, d = 0, 1
    for i in range(n):
        rows[r].append(i)
        if r == 0:
            d = 1
        elif r == rails - 1:
            d = -1
        r += d
    return [i for row in rows for i in row]


def rail_fence_encrypt(t, rails):
    return "".join(t[i] for i in rail_order(len(t), rails))


def rail_fence_decrypt(c, rails):
    out = [""] * len(c)
    for j, i in enumerate(rail_order(len(c), rails)):
        out[i] = c[j]
    return "".join(out)


# ---------- Full cipher ----------
def _check(vkey, rails):
    vkey = clean(vkey)
    if len(vkey) < 10:
        raise ValueError("Vigenere key must have at least 10 letters.")
    if rails < 2:
        raise ValueError("Need at least 2 rails.")
    return vkey


def encrypt(plaintext, hkey, vkey, rails):
    vkey = _check(vkey, rails)
    t = hill_encrypt(clean(plaintext), hill_key(hkey))
    return rail_fence_encrypt(vigenere_encrypt(t, vkey), rails)


def decrypt(ciphertext, hkey, vkey, rails):
    vkey = _check(vkey, rails)
    t = vigenere_decrypt(rail_fence_decrypt(clean(ciphertext), rails), vkey)
    return hill_decrypt(t, hill_key(hkey))


# ---------- Comparison ciphers ----------
def encrypt_2stage(plaintext, vkey, rails):          # Vigenere + Rail Fence only
    return rail_fence_encrypt(vigenere_encrypt(clean(plaintext), _check(vkey, rails)), rails)


def shift_encrypt(p, k): return "".join(chr((ord(c) - 65 + k) % 26 + 65) for c in p)
def shift_decrypt(c, k): return shift_encrypt(c, -k)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Hill + Vigenere + Rail Fence")
    ap.add_argument("mode", choices=["enc", "dec"])
    ap.add_argument("text")
    ap.add_argument("--hill", default="HILL", help="n*n letters (4 = 2x2, 9 = 3x3, 16 = 4x4 ...)")
    ap.add_argument("--key", required=True, help="Vigenere key, >= 10 letters")
    ap.add_argument("--rails", type=int, required=True)
    a = ap.parse_args()
    print((encrypt if a.mode == "enc" else decrypt)(a.text, a.hill, a.key, a.rails))
