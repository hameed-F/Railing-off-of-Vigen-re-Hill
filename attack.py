"""
Attacks on the 3-stage cipher (Hill -> Vigenere -> Rail Fence)

known_plaintext_attack : attacker knows the first m plaintext letters.
   For every rail count r: undo the transposition -> u = Vig(Hill(P)) in original order.
   For every Hill size n and key length L: the Vigenere key repeats every T = L/gcd(L,n) blocks,
   so  C_b - C_(b+T) = H (P_b - P_(b+T)).  These equations are solved mod 2 and mod 13 for H (any n x n).
   Then K = C - H P must be consistent with a key of period L -> key recovered.

frequency_attack       : ciphertext-only attack designed for Vigenere + Rail Fence
   (brute-force rails, Index of Coincidence for key length, chi-squared for key letters).
   Used to show it SUCCEEDS on the 2-stage cipher and FAILS once the Hill stage is added.
"""
from math import gcd
from cipher import (rail_fence_decrypt, vigenere_decrypt, hill_decrypt, _inv)

ENG = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025,
       2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
       1.974, 0.074]
TRI = {"THE": 1.81, "AND": .73, "ING": .72, "ENT": .42, "ION": .42, "HER": .36, "FOR": .34,
       "THA": .33, "NTH": .33, "INT": .32, "ERE": .31, "TIO": .31, "TER": .30, "EST": .28,
       "ERS": .28, "ATI": .26, "HAT": .26, "ATE": .25, "ALL": .25, "ETH": .24, "HES": .24,
       "VER": .24, "HIS": .24, "OFT": .22, "ITH": .21, "FTH": .21, "STH": .21, "OTH": .21,
       "RES": .21, "ONT": .20}


def index_of_coincidence(s):
    n = len(s)
    if n < 2:
        return 0.0
    cnt = [0] * 26
    for ch in s:
        cnt[ord(ch) - 65] += 1
    return sum(c * (c - 1) for c in cnt) / (n * (n - 1))


def best_shift(col):
    n = len(col)
    cnt = [0] * 26
    for ch in col:
        cnt[ord(ch) - 65] += 1
    return min((sum((cnt[(i + s) % 26] - ENG[i] / 100 * n) ** 2 / (ENG[i] / 100 * n)
                    for i in range(26)), s) for s in range(26))[1]


def fitness(text):
    return sum(TRI.get(text[i:i + 3], 0) for i in range(len(text) - 2)) / max(len(text), 1)


def break_vigenere(ct, max_len=20):
    ics = {L: sum(index_of_coincidence(ct[i::L]) for i in range(L)) / L
           for L in range(1, min(max_len, len(ct)) + 1)}
    top = max(ics.values())
    L = min(l for l, v in ics.items() if v >= top - 0.004)
    key = "".join(chr(best_shift(ct[i::L]) + 65) for i in range(L))
    return key, vigenere_decrypt(ct, key)


def frequency_attack(ct, max_rails=20, max_key_len=20):
    best = None
    for r in range(2, max_rails + 1):
        key, pt = break_vigenere(rail_fence_decrypt(ct, r), max_key_len)
        sc = fitness(pt)
        if best is None or sc > best[0]:
            best = (sc, r, key, pt)
    return best[1], best[2], best[3]


def _solve_mod_p(A, Y, p, n):
    """Solve A X = Y over GF(p) (A: E x n, Y: E x n). Returns X (n x n) or None if rank < n or inconsistent."""
    M = [[a % p for a in ra] + [y % p for y in ry] for ra, ry in zip(A, Y)]
    piv_row = 0
    for col in range(n):
        sel = next((i for i in range(piv_row, len(M)) if M[i][col]), None)
        if sel is None:
            return None                                   # rank deficient
        M[piv_row], M[sel] = M[sel], M[piv_row]
        iv = pow(M[piv_row][col], -1, p)
        M[piv_row] = [(x * iv) % p for x in M[piv_row]]
        for i in range(len(M)):
            if i != piv_row and M[i][col]:
                f = M[i][col]
                M[i] = [(x - f * y) % p for x, y in zip(M[i], M[piv_row])]
        piv_row += 1
    if any(any(row[n:]) for row in M[n:]):
        return None                                       # leftover equations do not hold -> wrong guess
    return [row[n:] for row in M[:n]]


def _recover_hill(dP, dC, n):
    """Find H (n x n, mod 26) with dC_e = H dP_e for every difference pair e, solving mod 2 and mod 13 (CRT)."""
    s2, s13 = _solve_mod_p(dP, dC, 2, n), _solve_mod_p(dP, dC, 13, n)
    if s2 is None or s13 is None:
        return None
    H = [0] * (n * n)
    for k in range(n):                                    # X = H^T, so H[j][k] = X[k][j]
        for j in range(n):
            a, b = s2[k][j], s13[k][j]
            H[j * n + k] = b + 13 * ((a - b) % 2)
    H = tuple(H)
    return H if _inv(H) is not None else None


def known_plaintext_attack(ct, known, max_rails=40, max_key_len=40, sizes=(2, 3, 4, 5, 6)):
    """Returns (rails, vigenere_key, hill_matrix, plaintext) or None.

    The attacker is NOT told the rails, the Vigenere key, the Hill matrix or even its size n.
    For each guess (n, rails r, key length L):
       u = Vigenere(Hill(P)) in original order (after undoing the rail fence),
       the key repeats every T = L / gcd(L, n) Hill blocks, so  u_b - u_(b+T) = H (P_b - P_(b+T))
       -> a linear system for H solved mod 2 and mod 13.  We insist on at least TWO spare equations
       (E >= n + 2) so that a wrong guess cannot fit by luck, then rebuild the key and check every block.
    Needs about n * (T + n + 8) known letters to be reliable (see min_known_letters), e.g. 42 for a 2x2 matrix with an 11-letter key."""
    known = known.upper()
    max_rails = min(max_rails, max(2, len(ct) - 1))
    for n in sizes:
        known_n = known[:n * (max_key_len + n + 12)]      # more letters than this cannot help and only slow the search
        mb = len(known_n) // n
        if mb < n + 3:
            continue
        P = [ord(c) - 65 for c in known_n[:n * mb]]
        Ls = [L for L in range(1, max_key_len + 1) if mb - L // gcd(L, n) >= n + 2]
        if not Ls:
            continue
        # the plaintext side of the equations depends only on (n, T): skip key lengths whose P-differences are singular
        usable = {}
        for L in Ls:
            T = L // gcd(L, n)
            if T not in usable:
                dP = [[(P[n*b + k] - P[n*(b+T) + k]) % 26 for k in range(n)] for b in range(mb - T)]
                usable[T] = dP if (_solve_mod_p(dP, [[0]*n]*len(dP), 2, n) is not None and
                                   _solve_mod_p(dP, [[0]*n]*len(dP), 13, n) is not None) else None
        for r in range(2, max_rails + 1):
            u = rail_fence_decrypt(ct, r)
            C = [ord(c) - 65 for c in u[:n * mb]]
            for L in Ls:
                T = L // gcd(L, n)
                dP = usable[T]
                if dP is None:
                    continue
                dC = [[(C[n*b + k] - C[n*(b+T) + k]) % 26 for k in range(n)] for b in range(mb - T)]
                H = _recover_hill(dP, dC, n)
                if H is None:
                    continue
                key, ok = [None] * L, True
                for b in range(mb):
                    for j in range(n):
                        v = (C[n*b + j] - sum(H[j*n + k] * P[n*b + k] for k in range(n))) % 26
                        i = (n * b + j) % L
                        if key[i] is None:
                            key[i] = v
                        elif key[i] != v:
                            ok = False
                            break
                    if not ok:
                        break
                if ok and None not in key:
                    vk = "".join(chr(k + 65) for k in key)
                    return r, vk, H, hill_decrypt(vigenere_decrypt(u, vk), H)
    return None


def min_known_letters(n, key_len):
    """Known-plaintext length that makes this attack succeed reliably for an n x n Hill matrix and a key
    of key_len letters. Exactly n difference columns are independent mod 2 AND mod 13 only ~30% of the
    time, so 8 spare columns are added (failure then ~0.4%). The attack can occasionally succeed with fewer."""
    return n * (key_len // gcd(key_len, n) + n + 8)


min_known = min_known_letters


if __name__ == "__main__":
    from cipher import encrypt, clean
    text = clean(open("sample_text.txt").read())[:1000]
    ct = encrypt(text, "HILL", "NETWORKSECURITY", 6)
    res = known_plaintext_attack(ct, text[:60])
    print("KPA:", res[:3], "| plaintext recovered:", res[3] == text)
    r, k, pt = frequency_attack(ct)
    print("Frequency attack on 3-stage cipher recovered plaintext:", pt == text)
