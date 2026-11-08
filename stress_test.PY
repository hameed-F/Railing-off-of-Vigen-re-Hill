"""
Stress Testing Suite for CT-486 Hybrid Cipher (Hill + Vigenere + Rail Fence)
Run: python3 stress_test.py
"""

import cipher as cp
import attack as at
import benchmark as bm
import random
import string
import time

def print_header(title):
    print("\n" + "="*60)
    print(f" STRESS TEST: {title}")
    print("="*60)

# -------------------------------------------------------------------
# 1. Edge-Case Input Testing
# -------------------------------------------------------------------
def test_edge_cases():
    print_header("1. Edge-Case Inputs & Boundary Testing")
    
    # Using Vigenère keys with length >= 10 to satisfy cipher.py validation rules
    test_cases = [
        ("Single Character", "A", "GYBNQKURP", "SECURITYKEY", 4),
        ("Exact Block Length", "ABC", "GYBNQKURP", "SECURITYKEY", 4),
        ("Rail Count > Message Length", "HELLO", "GYBNQKURP", "SECURITYKEY", 10),
        ("Rail Count = 2", "TESTINGRAILFENCE", "GYBNQKURP", "SECURITYKEY", 2),
        ("Special Chars & Numbers", "Meet me at 12:00 PM! #Secret", "GYBNQKURP", "SECURITYKEY", 4),
        ("Very Long Text (100k chars)", "A" * 100000, "GYBNQKURP", "SECURITYKEY", 5),
    ]

    for name, plain, h_key, v_key, rails in test_cases:
        try:
            clean_p = cp.clean(plain)
            if not clean_p:
                print(f"[PASS] {name}: Correctly handled empty/invalid string.")
                continue
                
            k = cp.hill_key(h_key)
            ct = cp.encrypt(clean_p, h_key, v_key, rails)
            dec = cp.decrypt(ct, h_key, v_key, rails)
            
            assert dec == clean_p, f"Decrypted text does not match!"
            print(f"[PASS] {name} | Input Len: {len(clean_p)} | Cipher Len: {len(ct)}")
        except Exception as e:
            print(f"[FAIL] {name} raised exception: {e}")
# -------------------------------------------------------------------
# 2. Key Validation & Invertibility Stress Test
# -------------------------------------------------------------------
def test_key_space_invertibility():
    print_header("2. Hill Matrix Invertibility Check")
    
    invalid_matrix_keys = [
        "AAAA",       # Zero determinant mod 26
        "ABCD",       # det % 2 == 0 or det % 13 == 0 (non-coprime)
    ]
    
    for key_str in invalid_matrix_keys:
        try:
            k = cp.hill_key(key_str)
            det = cp.hill_det(k)
            inv = cp._inv(k)
            print(f"[FAIL] Key '{key_str}' should be invalid but was accepted (det={det})")
        except ValueError as e:
            print(f"[PASS] Correctly rejected invalid Hill key '{key_str}': {e}")

# -------------------------------------------------------------------
# 3. Avalanche Effect (Confusion & Diffusion)
# -------------------------------------------------------------------
def test_avalanche_effect():
    print_header("3. Avalanche & Diffusion Test")
    
    base_p = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 3
    h_key, v_key, rails = "GYBNQKURP", "SECURITYKEY", 4
    
    ct_base = cp.encrypt(base_p, h_key, v_key, rails)
    
    # Flip 1 character in plaintext
    modified_p = list(base_p)
    modified_p[0] = 'X' if modified_p[0] != 'X' else 'Y'
    modified_p = "".join(modified_p)
    
    ct_mod = cp.encrypt(modified_p, h_key, v_key, rails)
    
    diffs = sum(1 for c1, c2 in zip(ct_base, ct_mod) if c1 != c2)
    percentage = (diffs / len(ct_base)) * 100
    
    print(f"Original Text Length:  {len(base_p)}")
    print(f"1-Char Change Output: {diffs}/{len(ct_base)} characters changed ({percentage:.2f}%)")
    if percentage > 40.0:
        print("[PASS] Strong diffusion detected.")
    else:
        print("[WARN] Weak diffusion: Avalanche effect is low (< 40%).")

# -------------------------------------------------------------------
# 4. KPA & Known-Plaintext Attack Failure Threshold
# -------------------------------------------------------------------
def test_kpa_threshold():
    print_header("4. Known-Plaintext Attack Threshold Sweep")
    
    p = "WEAREDISCOVEREDSAVEYOURSELF" * 10
    h_key, v_key, rails = "GYBNQKURP", "SECURITYKEY", 4
    ct = cp.encrypt(p, h_key, v_key, rails)
    
    print("Testing recovery success vs. length of known plaintext:")
    for m in range(5, 55, 5):
        known_p = p[:m]
        res = at.known_plaintext_attack(ct, known_p)
        if res and res[3] == p:
            print(f"  - Known Length {m:2d}: [SUCCESS] Full message recovered!")
        else:
            print(f"  - Known Length {m:2d}: [FAILED] Insufficient linear equations.")

# -------------------------------------------------------------------
# 5. Performance & Scalability Benchmark
# -------------------------------------------------------------------
def test_performance():
    print_header("5. Execution Time Bottleneck Benchmark")
    
    h_key, v_key, rails = "GYBNQKURP", "SECURITYKEY", 4
    sizes = [1000, 10000, 50000, 100000]
    
    for sz in sizes:
        sample = "".join(random.choices(string.ascii_uppercase, k=sz))
        
        t0 = time.perf_counter()
        ct = cp.encrypt(sample, h_key, v_key, rails)
        t_enc = (time.perf_counter() - t0) * 1000
        
        t0 = time.perf_counter()
        dec = cp.decrypt(ct, h_key, v_key, rails)
        t_dec = (time.perf_counter() - t0) * 1000
        
        print(f"Text Size: {sz:6d} chars | Encrypt: {t_enc:6.2f} ms | Decrypt: {t_dec:6.2f} ms")

if __name__ == "__main__":
    test_edge_cases()
    test_key_space_invertibility()
    test_avalanche_effect()
    test_kpa_threshold()
    test_performance()