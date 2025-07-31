import base64
from bitstring import BitArray
import matplotlib.pyplot as plt
from collections import Counter
from src.saesCipher import saesCipher
from src.utils import *
import argparse
import re
import os
import json
import pandas as pd


def getConsoleArguments() -> argparse.Namespace:
    """
    """

    # Configure the arguments for the script
    parser = argparse.ArgumentParser(
        description="Encrypt text using SAES Cipher.")
    parser.add_argument('--text', type=str,
                        help='The text to encrypt and analyze.')
    parser.add_argument('--key', type=str,
                        help='The key to use for encryption.', default="0100101011110101")
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose output for debugging.', default=False)
    parser.add_argument('--decrypt', action='store_true',
                        help='Enable decryption mode.', default=False)
    parser.add_argument('--savePathFrequencyPlots', type=str,
                        help='The folder path to save all the ocurrence frequency plots.', default="results/SAES")
    parser.add_argument('--saveFrequencyPlots', action='store_true',
                        default=False)
    parser.add_argument('--encryptText', action='store_true',
                        default=False)
    parser.add_argument('--CheckAllCombinations', action='store_true', default=False)
    parser.add_argument('--savePathAllCombinations', type=str)
    return parser.parse_args()


def cleanText(text: str) -> str:
    """
    Cleans a string by removing whitespace and any characters that are not '0' or '1'.

    This function is used to ensure that the input text or key consists only of binary digits,
    which is required for the SAES cipher operations.

    Args:
        text (str): The input string to clean.

    Returns:
        str: The cleaned string containing only '0' and '1' characters.
    """

    text = text.strip()
    text = re.sub(r'[^01]', '', text)
    return text

def savePlots(args: argparse.Namespace, cipher: saesCipher):
    checkPath(os.path.join(args.savePathFrequencyPlots))

    if not os.path.exists(os.path.join('keysFrequency.json')):
        # Save the aparition frequency of each subkey
        keysFrequency = {"key0": Counter(), "key1": Counter(),
                         "key2": Counter()}
        for i in range(0x0000, 0x10000):
            config = {'key': i}
            cipher.setConfig(config)
            generatedKeys = cipher._generateKeys()

            for key, value in generatedKeys.items():
                keysFrequency[key].update([value])

        with open(os.path.join('keysFrequency.json'), "w") as f:
            json.dump(keysFrequency, f, indent=4)

    with open(os.path.join('keysFrequency.json'), "r") as archivo:
        keysFrequency = json.load(archivo)

    allKeys = []
    allCounts = Counter()
    for key in keysFrequency.keys():
        keys = [int(k) for k in keysFrequency[key].keys()]
        counts = list(keysFrequency[key].values())

        allKeys += keys
        allCounts.update(keysFrequency[key])

        plt.figure(figsize=(12, 6))
        plt.hist(keys, bins=50, weights=counts,
                 color='blue', alpha=0.7, edgecolor='black')

        plt.xlabel("SAES keys (0 - 65536)")
        plt.ylabel("Frequency of Occurrence")
        plt.title(f"Frequency Distribution of SAES Keys for subkey {key}")

        plt.savefig(os.path.join(
            args.savePathFrequencyPlots, f'frequency_ocurrence_{key}.jpg'))

    plt.figure(figsize=(12, 6))
    plt.hist(set(allKeys), bins=50, weights=list(allCounts.values()),
             color='blue', alpha=0.7, edgecolor='black')

    plt.xlabel("SAES keys (0 - 65536)")
    plt.ylabel("Frequency of Occurrence")
    plt.title(f"Frequency Distribution of SAES Keys for all subkeys")

    plt.savefig(os.path.join(
        args.savePathFrequencyPlots, f'frequency_ocurrence_all_keys.jpg'))

def encryptBinaryText(args: argparse.Namespace, cipher: saesCipher):
    if args.text:
        text = args.text
    else:
        text = input("Enter a text to encrypt: ")

    if not args.key:
        raise ValueError("Key must be provided for encryption/decryption.")
    if not args.text:
        raise ValueError("You need provied the text to encrypt/decrypt.")

    key = cleanText(args.key)
    text = cleanText(text)

    if len(key) != 16:
        raise ValueError("Key must be 16 bits long.")
    if len(text) != 16:
        raise ValueError("text must be 16 bits long.")

    key = int(key, 2)

    config = {
        'key': key,
        'verbose': args.verbose,
    }

    cipher.setConfig(config)

    if not args.decrypt:
        encryptedText = cipher.encrypt(text).bin
        print(f"The encrypted text is: {encryptedText}")
    else:
        decryptedText = cipher.decrypt(text).bin
        print(f"The decrypted text is: {decryptedText}")

def encryptText(args: argparse.Namespace, cipher: saesCipher):
    if args.text:
        text = args.text
    else:
        text = input("Enter a text to encrypt: ")

    if not args.key:
        raise ValueError("Key must be provided for encryption/decryption.")
    if not args.text:
        raise ValueError("You need provied the text to encrypt/decrypt.")

    key = cleanText(args.key)

    if len(key) != 16:
        raise ValueError("Key must be 16 bits long.")

    key = int(key, 2)

    config = {
        'key': key,
        'verbose': args.verbose,
        'mode': 'CTR',
        'IV': BitArray(uint=21611, length=16), # For testing propouse
        'N': BitArray(uint=20011, length=16), # For testing propouse
    }

    cipher.setConfig(config)

    if not args.decrypt:
        encryptedText = cipher.encryptText(text)
        print(f'Original text: {text}')
        print(
            f'Original text in Hexadecimal: 0x{BitArray(bytes=text.encode('utf-8')).hex}')
        print(f'Encryted text in Hexadecimal: 0x{encryptedText.hex}')
        print(
            f'Encryted text in base64 (to copy and decrypt): {base64.b64encode(encryptedText.bytes).decode("utf-8")}')
    else:
        encryptedBytes = base64.b64decode(text)
        decryptedText = cipher.decryptText(BitArray(bytes=encryptedBytes))
        print(f"The decrypted text in hexadecimal is: 0x{decryptedText.hex}")
        print(f"The decrypted text is: {decryptedText.bytes.decode('utf-8')}")

def checkAllCombinations(args, cipher: saesCipher):
    pandasRawData = []
    for i in range(0, 0x10000):
        config = {'key': i}
        cipher.setConfig(config)
        generatedKeys = cipher._generateKeys()
        pandasRawData.append([i, generatedKeys['key0'].uint, generatedKeys['key1'].uint, generatedKeys['key2'].uint])
    
    df = pd.DataFrame(data= pandasRawData, columns=['key', 'key0', 'key1', 'key2'])
    actual_folder = os.path.dirname(__file__)
    if args.savePathAllCombinations:
        filePath = os.path.join(actual_folder, args.savePathAllCombinations)
    else:
        filePath = os.path.join(actual_folder, 'results', 'saes', 'keys.csv')
    df.to_csv(filePath,index=False)

def main():
    from src.saesCipher import saesCipher
    cipher = saesCipher()

    args = getConsoleArguments()
    if args.saveFrequencyPlots:
        savePlots(args, cipher)


    if args.CheckAllCombinations:
        checkAllCombinations(args, cipher)
    
    if not (args.CheckAllCombinations or args.saveFrequencyPlots):
        if args.encryptText:
            encryptText(args, cipher)
            return
        
        # If the user dont want save the plots or encrypt a whole text then we suposse that he
        # want encrypt a binary text
        encryptBinaryText(args, cipher)

if __name__ == "__main__":
    main()
