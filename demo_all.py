"""Demo script for the report: run `python demo_all.py` and screenshot / copy the whole output."""
from cipher import *
from attack import *

H, V, R = "HILL", "NETWORKSECURITY", 5
MSG = "ATTACKATDAWN"

print("=" * 70); print("PART 1 - WORKED EXAMPLE (stage by stage)"); print("=" * 70)
p = clean(MSG); m = hill_key(H)
a = hill_encrypt(p, m); b = vigenere_encrypt(a, V); c = rail_fence_encrypt(b, R)
print(f"Keys           : Hill={H} (matrix {list(m)}), Vigenere={V}, rails={R}")
print(f"Plaintext      : {p}")
print(f"After Hill     : {a}")
print(f"After Vigenere : {b}")
print(f"After RailFence: {c}   <- ciphertext")
print("\nPART 2 - DECRYPTION (reverse order)")
d1 = rail_fence_decrypt(c, R); d2 = vigenere_decrypt(d1, V); d3 = hill_decrypt(d2, m)
print(f"Undo Rail Fence: {d1}\nUndo Vigenere  : {d2}\nUndo Hill      : {d3}")
print("Round trip OK  :", d3 == p, "| encrypt()/decrypt() agree:", decrypt(encrypt(MSG, H, V, R), H, V, R) == p)

print("\nPART 3 - DIFFERENT MESSAGE LENGTHS")
for t in ["HI", "NETWORKSECURITY", "The quick brown fox jumps over the lazy dog 123!", clean(open("sample_text.txt").read())[:500]]:
    try:
        ct = encrypt(t, H, V, R); ok = decrypt(ct, H, V, R) == clean(t)
        print(f"{len(clean(t)):>4} letters -> round trip {'OK' if ok else 'FAIL'}  ({ct[:30]}...)")
    except ValueError as e:
        print(f"{len(clean(t)):>4} letters -> rejected: {e}")

print("\nPART 4 - WEAK KEYS ARE REJECTED")
for name, args in [("identity Hill BAAB", ("BAAB", V, R)), ("diagonal Hill DAAF", ("DAAF", V, R)),
                   ("non-invertible Hill DDDD", ("DDDD", V, R)), ("Vigenere AAAAAAAAAA", (H, "AAAAAAAAAA", R)),
                   ("Vigenere ABABABABAB", (H, "ABABABABAB", R)), ("Vigenere shorter than 10", (H, "SHORTKEY", R)),
                   ("rails >= message length", (H, V, 50))]:
    try: encrypt(MSG, *args); print(f"{name:28s}: ACCEPTED (unexpected)")
    except ValueError as e: print(f"{name:28s}: rejected - {e}")

text = clean(open("sample_text.txt").read())[:1500]
ct = encrypt(text, H, V, R)
print("\n" + "=" * 70); print("PART 5 - ATTACKS on a 1500-letter ciphertext (keys unknown to attacker)"); print("=" * 70)
print(f"IC plaintext {index_of_coincidence(text):.4f} | IC ciphertext {index_of_coincidence(ct):.4f}  (English ~0.066, random ~0.038)")
res = known_plaintext_attack(ct, text[:50])
print(f"\n[Known-plaintext attack, attacker knows first 50 letters]")
print(f"  recovered rails={res[0]}, Vigenere key={res[1]}, Hill matrix={list(res[2])}")
print(f"  full plaintext recovered: {res[3] == text}")
res2 = known_plaintext_attack(ct, text[300:380], offset=300)
print(f"[Known-plaintext attack, crib of 80 letters at position 300] plaintext recovered: {bool(res2) and res2[3] == text}")
r, k, pt = frequency_attack(ct)
print(f"\n[Frequency attack on 3-stage cipher] plaintext recovered: {pt == text}")
ct2 = encrypt_2stage(text, V, R)
r, k, pt = frequency_attack(ct2)
print(f"[Frequency attack on 2-stage Vigenere+RailFence (no Hill)] rails={r}, key={k}, plaintext recovered: {pt == text}")
full = clean(open("sample_text.txt").read())
for N in (1500, len(full)):
    per, reps = kasiski_period(encrypt(full[:N], H, V, R), R)
    print(f"[Kasiski leak, ciphertext only, correct rails, {N} letters] repeated 6-grams: {reps}, gcd of distances: {per} (true key period: {len(V) * 2 // __import__('math').gcd(len(V), 2)})")
print("  -> with too few repeats the leak is unreliable; it needs several thousand letters of natural English.")
