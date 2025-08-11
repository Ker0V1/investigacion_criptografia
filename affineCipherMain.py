import argparse
import os
import re
import pandas as pd

from src.affineCipher import affineCipher
from src.utils import checkPath


def cleanText(text) -> str:
    """
    Cleans the input text by performing several normalization steps.
    Steps include:
    - Removing leading and trailing whitespace.
    - Converting the text to lowercase.
    - Replacing newline and carriage return characters with spaces.
    - Replacing multiple consecutive spaces with a single space.
    - Removing any characters that are not lowercase letters or spaces.
    Args:
        text (str): The input string to be cleaned.
    Returns:
        str: The cleaned string.
    """

    text = text.strip().lower()
    text = text.replace('\n', ' ').replace('\r', ' ')
    text = re.sub(r'\s{2,}', ' ', text)
    text = re.sub(r'[^a-z\s]', '', text)

    return text


def getConsoleArguments() -> argparse.Namespace:
    """
    Parses and retrieves the command-line arguments provided by the user.

    This function sets up an ArgumentParser to handle the arguments passed
    when running the script from the console. It defines the expected arguments,
    their types, and default values.

    The available command-line arguments are:
        --text (str): The input string to be processed. This is the text
            that will be encrypted or decrypted.
        --decrypt (bool): A flag that, when present, switches the mode of
            operation from encryption to decryption. Defaults to False.
        --alpha (int): The first coefficient (α) used in the affine cipher
            encryption/decryption formula. Defaults to 19.
        --beta (int): The second coefficient (β) used in the affine cipher
            encryption/decryption formula. This value represents the shift.
            Defaults to 11.
        --CheckAllCombinations (bool): A flag that, when present, tells the
            script to check all possible combinations, likely for brute-force
            decryption. Defaults to False.
        --savePathAllCombinations (str): The file path where the output of
            checking all combinations should be saved. This is optional.

    Returns:
        argparse.Namespace: An object containing the parsed command-line
                            arguments as attributes. For example, if the script
                            is run with `--text "Hello"`, the text can be
                            accessed via `args.text`.
    """

    # Configure the arguments for the script
    parser = argparse.ArgumentParser(
        description="Encrypt text using Caesar Cipher and analyze frequencies.")
    parser.add_argument('--text', type=str,
                        help='The text to encrypt and analyze.')
    parser.add_argument('--decrypt', action='store_true',
                        help='Decrypt the text instead of encrypting it.')
    parser.add_argument('--alpha', type=int,
                        help='The first coefficient', default=19)
    parser.add_argument('--beta', type=int,
                        help='The second coefficient', default=11)
    parser.add_argument('--CheckAllCombinations',
                        action='store_true', default=False)
    parser.add_argument('--savePathAllCombinations', type=str)
    return parser.parse_args()


if __name__ == "__main__":

    args = getConsoleArguments()

    cipher = affineCipher()
    alphabet = 'abcdefghijklmnopqrstuvwxyz'

    if args.text:
        text = args.text
    else:
        text = input("Enter a text to encrypt: ")

    text = cleanText(text)

    if args.CheckAllCombinations:
        
        # All the coprimes of 26
        coprimes = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
        shiftsRawData = []
        for alpha in coprimes:
            for beta in range(0, 26):
                cipher.setConfig({'alpha': alpha, 'beta': beta})
                shiftsRawData.append([alpha, beta, cipher.encrypt(text)])

        df = pd.DataFrame(data=shiftsRawData, columns=[
                          'alpha', 'beta', 'result'])
        
        actual_folder = os.path.dirname(__file__)
        if args.savePathAllCombinations:
            filePath = os.path.join(
                actual_folder, args.savePathAllCombinations)
        else:
            filePath = os.path.join(
                actual_folder, 'results', 'affineCipher', 'Shifts.csv')

        checkPath(filePath)
        
        df.to_csv(filePath, index=False)

    else:

        cipher.setConfig({'alpha': args.alpha, 'beta': args.beta})
        if not args.decrypt:
            encryptedText = cipher.encrypt(text)
            print(f"The encrypted text is: {encryptedText}")
        else:
            decryptedText = cipher.decrypt(text)
            print(f"The decrypted text is: {decryptedText}")
