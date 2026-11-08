# CT-486 CCP - Design and Break a Custom Cipher
**Cipher:** Hill (n x n, any n >= 2) -> Vigenere (key >= 10 letters) -> Rail Fence.  **Language:** Python 3 (tkinter for the GUI; no other packages).

## Run the demo (single interface)
    python3 gui.py
Tabs: **Encrypt - Decrypt - Attack - Results**. Type any message and keys at the top; every tab works on what you typed, at run time.
(Linux: `sudo apt install python3-tk` if tkinter is missing. Windows/macOS installers include it.)

## Files
| File | Purpose |
|---|---|
| `gui.py` | Single-window frontend; imports the three modules below |
| `cipher.py` | Encryption/decryption (3 stages), Shift + 2-stage baselines, CLI |
| `attack.py` | Known-plaintext attack (breaks it) and frequency attack (fails on 3-stage) |
| `benchmark.py` | Efficiency, IC per stage, attack success tables for ANY text (used by the GUI) |
| `benchmark_lengths.py` | Stand-alone attack-vs-length experiment used in the report |
| `test_cipher.py` | Round-trip + edge-case tests |
| `index.html` | Optional animated website (open in any browser) |
| `sample_text.txt` | English corpus used ONLY by the stand-alone scripts and the "Load sample text" button |
| `results_*.txt` | Saved outputs of the stand-alone scripts |
| `docs/` | Final report |

## Command line
    python3 test_cipher.py
    python3 cipher.py enc "Attack at dawn" --hill HILL --key NETWORKSECURITY --rails 5
    python3 attack.py
    python3 benchmark.py [yourtext.txt]
    python3 benchmark_lengths.py

## Group members
(add names + roll numbers)

## Hill size
The Hill key is n*n letters (4 = 2x2, 9 = 3x3, 16 = 4x4 ...). No hard limit: cost is O(n) per letter; the key only needs det coprime to 26.
The known-plaintext attack needs about n*(T+n+8) known letters, T = key length / gcd(key length, n), and is not told n, rails or keys.
