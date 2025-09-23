# Cryptography Project — Documentation and Examples

This repository contains educational implementations and demos of several
classical and simplified cryptographic algorithms. Each demo has a `main`
script in the repository root so you can run and explore them individually.

Prerequisites
-------------

- Python 3.8+ (recommended)
- pip

Install dependencies
--------------------

From the project root:

```sh
pip install -r requirements.txt
```

Run commands from the repository root so `src/` is on the import path.

Detailed examples for every demo (all flags/options)
--------------------------------------------------

Notes: replace the sample values with your own. Each section below lists the
available command-line flags and multiple example usages including useful
combinations.

1) Affine cipher (`affineCipherMain.py`)
------------------------------------------------
Flags and behavior:
- `--text TEXT` : input text (if omitted the script prompts interactively)
- `--decrypt` : decrypt mode (default: encrypt)
- `--alpha INT` : coefficient α (default: 19)
- `--beta INT` : coefficient β (default: 11)
- `--CheckAllCombinations` : brute-force all coprime α and β values and save results
- `--savePathAllCombinations PATH` : file path to write the all-combinations CSV

Examples:

- Encrypt (default α/β):

```sh
python affineCipherMain.py --text "hello world"
```

- Decrypt with explicit key:

```sh
python affineCipherMain.py --text "xuo jxuhu" --decrypt --alpha 19 --beta 11
```

- Encrypt with custom α/β:

```sh
python affineCipherMain.py --text "secret msg" --alpha 5 --beta 8
```

- Brute-force all valid α,β and save CSV (useful to recover keys):

```sh
python affineCipherMain.py --text "ciphertext_here" --CheckAllCombinations --savePathAllCombinations results/affineCipher/shifts.csv
```

2) Caesar cipher (`caesarCipherMain.py`)
------------------------------------------------
Flags:
- `--text TEXT` : input text (prompts if omitted)
- `--shift N` : integer shift (default: 3)
- `--decrypt` : decrypt instead of encrypt
- `--saveFrecuencyTable` : saves frequency table CSV for every shift
- `--savePlots` : save per-shift frequency plots (PNG)
- `--savePossibleShifts` : save all shifted outputs to a text file
- `--resultsPath PATH` : directory for output files (default: `../results/caesarCipher`)

Examples:

- Basic encrypt (default shift = 3):

```sh
python caesarCipherMain.py --text "hello world"
```

- Decrypt given shift:

```sh
python caesarCipherMain.py --text "khoor" --shift 3 --decrypt
```

- Save frequency table (CSV) for shifts 1..25 and save to custom path:

```sh
python caesarCipherMain.py --text "sample text" --saveFrecuencyTable --resultsPath results/caesarCipher
```

- Save frequency plots for each shift (PNG files):

```sh
python caesarCipherMain.py --text "sample text" --savePlots --resultsPath results/caesarCipher
```

- Save all shifted outputs to text file (useful for quick manual analysis):

```sh
python caesarCipherMain.py --text "secret" --savePossibleShifts --resultsPath results/caesarCipher
```

- Combine reporting options (table + plots + possible shifts):

```sh
python caesarCipherMain.py --text "example" --saveFrecuencyTable --savePlots --savePossibleShifts --resultsPath results/caesarCipher
```

3) Diffie–Hellman demo (`diffieHellmanMain.py`)
------------------------------------------------
Flags:
- `-p INT` : prime modulus to use (optional; if omitted the script picks one)
- `-g INT` : generator (optional; selected if omitted)
- `--BobKey INT` : Bob's private key (optional; random if omitted)
- `--AliceKey INT` : Alice's private key (optional; random if omitted)
- `--checkAllPosibilites` : brute-force possible private keys that match the published public keys

Examples:

- Run with automatically chosen prime and generator:

```sh
python diffieHellmanMain.py
```

- Run with explicit `p` and `g` (repeatable demo):

```sh
python diffieHellmanMain.py -p 31847 -g 5
```

- Provide explicit private keys for deterministic run:

```sh
python diffieHellmanMain.py --BobKey 1234 --AliceKey 4321
```

- Brute-force private keys that could generate the public keys (only for small p):

```sh
python diffieHellmanMain.py -p 7919 -g 2 --checkAllPosibilites
```

4) Simplified AES / SAES (`saesCipherMain.py`)
------------------------------------------------
Flags:
- `--text TEXT` : input; either a 16-bit binary block or plaintext depending on `--encryptText`
- `--key BITSTRING` : 16-bit key as binary string (default: `0100101011110101`)
- `--encryptText` : treat `--text` as arbitrary UTF-8 plaintext and use CTR-like mode
- `--decrypt` : decrypt mode
- `--verbose` : verbose debug prints
- `--saveFrequencyPlots` : compute and save frequency plots of subkeys (long)
- `--savePathFrequencyPlots PATH` : folder to store SAES plots (default: `results/SAES`)
- `--CheckAllCombinations` : enumerate all 65536 keys and save derived subkeys to CSV
- `--savePathAllCombinations PATH` : CSV path for `--CheckAllCombinations`

Examples (binary-block mode):

```sh
# Encrypt a single 16-bit block
python saesCipherMain.py --text "1010110010101100" --key "0100101011110101"

# Decrypt that block
python saesCipherMain.py --text "<ciphertext_16bits>" --key "0100101011110101" --decrypt
```

Examples (text mode, CTR-like):

```sh
# Encrypt arbitrary UTF-8 text
python saesCipherMain.py --text "Hello world!" --key "0100101011110101" --encryptText

# Decrypt base64 output produced by the previous command
python saesCipherMain.py --text "<BASE64_ENCRYPTED>" --key "0100101011110101" --encryptText --decrypt
```

Long-running analysis:

```sh
# Compute and save frequency plots for all subkeys (expensive; precomputes keysFrequency.json)
python saesCipherMain.py --saveFrequencyPlots --savePathFrequencyPlots results/SAES

# Enumerate all 65536 keys and write subkeys CSV (very slow)
python saesCipherMain.py --CheckAllCombinations --savePathAllCombinations results/saes/keys.csv
```

5) S-PDH-EC (`SPDHECMain.py`)
------------------------------------------------
Flags:
- `--curveIndex INT` : choose a specific elliptic curve entry from `Elliptic Curves.txt` (index starts at 0)
- `--BobKey INT` : explicit Bob private key (optional)
- `--AliceKey INT` : explicit Alice private key (optional)
- `--checkAllPosibilites` : brute-force to recover private key pairs (small ecOrder only)

Examples:

```sh
# Run demo with random curve and keys
python SPDHECMain.py

# Run demo selecting curve index 3 and fixed private keys
python SPDHECMain.py --curveIndex 3 --BobKey 222751 --AliceKey 1944710

# Attempt exhaustive search for private-key pairs (only feasible for very small curves)
python SPDHECMain.py --checkAllPosibilites
```