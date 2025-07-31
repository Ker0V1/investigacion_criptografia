# Cryptography Project

This repository contains implementations of various cryptographic algorithms and protocols. Each algorithm has its own `main` file for independent execution.

## Installing dependencies

Before running any file, install the required dependencies with:

```sh
pip install -r requirements.txt
```

## Running the main scripts

Each main algorithm has its own entry point. You can run them as follows:

### Affine Cipher

**Encrypt a text**

```sh
python affineCipherMain.py --text "hello world"
```

**Decrypt a text**

```sh
python affineCipherMain.py --text "encryptedtext" --decrypt
```

**Specify custom alpha and beta coefficients**

```sh
python affineCipherMain.py --text "hello world" --alpha 5 --beta 8
```

**Check all combinations of alpha and beta and save results**

```sh
python affineCipherMain.py --text "hello world" --CheckAllCombinations --savePathAllCombinations "my_results.csv"
```

#### Note:

- If you omit --text, the script will prompt you to enter the text interactively.

- The default values are alpha=19 and beta=11 if not specified.

- The output file for all combinations will be saved in the affineCipher folder by default if you don't specify `--savePathAllCombinations`.

### Caesar Cipher

**Encrypt a text**
```sh
python caesarCipherMain.py --text "hello world"
```

**Decrypt a text**
```sh
python caesarCipherMain.py --text "encryptedtext" --decrypt
```

**Save the frequency table to a CSV file**
```sh

python caesarCipherMain.py --text "hello world" --saveFrecuencyTable

```

**Save frequency plots for each shift**
```sh
python caesarCipherMain.py --text "hello world" --savePlots
```

**Save all possible shifts to a txt file**
```sh
python caesarCipherMain.py --text "hello world" --savePossibleShifts
```

**Specify a custom results path**
```sh
python caesarCipherMain.py --text "hello world" --resultsPath "./my_results"
```

#### Note:
- You can combine options, for example: 
```sh
python caesarCipherMain.py --text "hello world" --saveFrecuencyTable --savePlots --savePossibleShifts
```

- If you omit --text, the script will prompt you to enter the text interactively.

- The default results path is ../results/caesarCipher if not specified.

### Diffie-Hellman

```sh
python diffieHellmanMain.py
```

### Simplified AES (SAES)
**Encrypt a 16-bit binary text**
```sh
python saesCipherMain.py --text "1010110010101100" --key "0100101011110101"
```

**Decrypt a 16-bit binary text**
```sh
python saesCipherMain.py --text "1010110010101100" --key "0100101011110101" --decrypt
```

**Encrypt a full text (string mode, CTR)**
```sh
python saesCipherMain.py --text "Hello world!" --key "0100101011110101" --encryptText
```

**Decrypt a full text (provide base64-encoded encrypted text)**
```sh
python saesCipherMain.py --text "BASE64_ENCRYPTED_TEXT" --key "0100101011110101" --encryptText --decrypt
```

**Save frequency plots of subkeys**
```sh
python saesCipherMain.py --saveFrequencyPlots
```

**Check all key combinations and save to a CSV**
```sh
python saesCipherMain.py --CheckAllCombinations --savePathAllCombinations "my_keys.csv"
```

#### Notes:
- The key and binary text must be 16 bits long (e.g., "0100101011110101").

- For full text encryption/decryption, use --encryptText.

- If you omit --savePathAllCombinations, the CSV will be saved to keys.csv by default.

### S-PDH-EC (Simplified Password-authenticated Diffie-Hellman on Elliptic Curves)

```sh
python SPDHECMain.py
```

## Notes
- Make sure you have Python installed (preferably version 3.8 or higher).

- Run the commands from the root of the repository.