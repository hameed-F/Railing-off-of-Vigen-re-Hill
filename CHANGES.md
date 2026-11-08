# Patch notes
cipher.py  : weak-key rejection (identity/diagonal-like Hill matrices, Vigenere keys with <7 distinct letters or a repeating shorter word, rails >= message length). encrypt/decrypt now call these checks.
attack.py  : known_plaintext_attack(..., offset=k) - known text may start anywhere in the message; new kasiski_period() ciphertext-only key-period leak.
test_cipher.py : tests for weak-key rejection, empty/short input.
benchmark*.py  : random key generators now only produce keys the cipher accepts.
