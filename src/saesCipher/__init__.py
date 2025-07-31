import secrets
from src.cipher import cipher
from bitstring import BitArray
import pandas as pd
import re
import os

from src.utils import BinaryBeauty, splitBinaryGroupsInt


class saesCipher(cipher):
    """
    A class that implements the Simplified AES (SAES) cipher, inheriting from the base `cipher` class.

    This class provides methods for encrypting and decrypting binary strings using the SAES algorithm.
    It supports configuration of the cipher key, encryption/decryption mode, and uses S-box and bitwise multiplication tables loaded from CSV files.

    Attributes:
        config (dict): Stores the cipher configuration, including the key, mode (encrypt/decrypt), S-boxes, and multiplication table.
    """

    def __init__(self):
        self.config = {
            'decrypt': False,  # Default mode is encryption
            'mode': 'ECB',
            'blockLength': 16,
            'IV': self._randomBitArray(16),
            'N': self._randomBitArray(16)
        }

        actual_folder = os.path.dirname(__file__)
        self.config['encryptionSbox'] = pd.read_csv(
            os.path.join(actual_folder, 'encryptionSbox.csv'), sep=';')
        self.config['decryptionSbox'] = pd.read_csv(
            os.path.join(actual_folder, 'decryptionSbox.csv'), sep=';')
        self.config['BitwiseMultiplyTable'] = pd.read_csv(
            os.path.join(actual_folder, 'BitwiseMultiplyTable.csv'), sep=';', header=None)

    def setConfig(self, newConf) -> None:
        """
        Sets the configuration for the cipher.

        Args:
            newConf (dict): A dictionary containing the new configuration.
                             Must include 'key' (str) and 'mode' (str).
        Raises:
            ValueError: If 'key' is missing from newConf.
        """
        if 'key' not in newConf and 'key' not in self.config:
            raise ValueError("Configuration must include 'key'.")

        if 'decrypt' in newConf:
            print(
                "Warning: you can't change 'decrypt' configuration manually, please use the method.")

            del newConf['decrypt']

        self.config = self.config | newConf

    def _rota(self, byte: BitArray) -> BitArray:
        """
        Rotates the input byte 4 bits to the left.

        This operation swaps the higher and lower 4 bits of the byte.
        For example, 1011 0001 becomes 0001 1011.

        Args:
            byte (int): An 8-bit integer to be rotated.

        Returns:
            int: The rotated 8-bit integer.
        """
        return byte[4:] + byte[:4]

    def _sub(self, word: BitArray) -> BitArray:
        """
        Applies the S-box substitution to the input word.

        For 4-bit words, it uses the S-box (encryption or decryption, depending on the mode)
        to substitute the value. For longer words, it recursively splits the word and applies
        the substitution to each part, then combines the results.

        Args:
            word (int): The input integer to be substituted.
            length (int): The bit length of the input word.

        Returns:
            int: The substituted integer after applying the S-box.
        """
        length = len(word)

        if length == 4:
            sbox = self.config['encryptionSbox']
            if self.config['decrypt']:
                sbox = self.config['decryptionSbox']

            rowBits = word[0:2]
            colBits = word[2:4]

            row = rowBits.uint
            col = colBits.uint

            substitutedValue = int(sbox.loc[(sbox["row"] == row) & (
                sbox["col"] == col)].loc[:, "value"].values[0])
            # if the program is slowing down, maybe we need use dictionaries instead of pandas DataFrames
            return BitArray(uint=substitutedValue, length=4)
        else:
            mitad = length // 2

            firstWordPart = word[:mitad]
            lastWordPart = word[mitad:]

            subFirstPart = self._sub(firstWordPart)
            subLastWordPart = self._sub(lastWordPart)

            return subFirstPart + subLastWordPart

    def _generateKeys(self) -> dict[str, BitArray]:
        """
        Generates and returns the round keys used in the SAES encryption and decryption process.

        The method derives three 16-bit round keys from the main cipher key using key scheduling,
        S-box substitution, and bitwise operations. The keys are returned in a dictionary.

        Returns:
            dict[str, int]: A dictionary with keys 'key0', 'key1', and 'key2', each containing a 16-bit integer round key.
        """
        if isinstance(self.config['key'], str):
            initialKey = BitArray(bytes=self.config['key'].encode('utf-8'))
        elif isinstance(self.config['key'], int):
            initialKey = BitArray(uint=self.config['key'], length=16)
        elif not isinstance(self.config['key'], BitArray):
            raise Exception(
                f'The plaintext must be a string, a integer or a BinaryArray. Currently plaintext is a {type(self.config['key'])}')
        else:
            initialKey = self.config['key']

        keys = {}
        decryptMode = self.config.get('decrypt', False)
        self.config['decrypt'] = False

        w0 = initialKey[0:8]
        w1 = initialKey[8:16]

        const1 = BitArray(bin='10000000')
        const2 = BitArray(bin='00110000')

        w2 = w0 ^ const1 ^ self._sub(self._rota(w1))
        w3 = w2 ^ w1
        w4 = w2 ^ const2 ^ self._sub(self._rota(w3))
        w5 = w4 ^ w3

        keys = {
            'key0': w0 + w1,
            'key1': w2 + w3,
            'key2': w4 + w5,
        }

        self.config['decrypt'] = decryptMode
        return keys

    def _addRoundKey(self, state: BitArray, key: BitArray) -> BitArray:
        """
        Combines the current state with a round key using the XOR operation.

        This step is used in both encryption and decryption to add (XOR) the round key to the state.

        Args:
            state (int): The current state as an integer.
            key (int): The round key as an integer.

        Returns:
            int: The result of XOR-ing the state with the round key.
        """
        return state ^ key

    def _shiftRows(self, state: BitArray) -> BitArray:
        """
        Performs the ShiftRows operation on the state.

        This operation swaps the second and fourth 4-bit nibbles of the 16-bit state,
        leaving the first and third nibbles unchanged. It is used to provide diffusion in the cipher.

        Args:
            state (int): The current 16-bit state as an integer.

        Returns:
            int: The state after the ShiftRows transformation.

        Example:
        >>> cipher = saesCipher()
        >>> state = 0x1234
        >>> shifted = cipher._shiftRows(state)
        >>> print(hex(shifted))
        0x1432
        """
        nibble1 = state[0:4]
        nibble2 = state[4:8]
        nibble3 = state[8:12]
        nibble4 = state[12:16]

        shiftedBits = nibble1 + nibble4 + nibble3 + nibble2

        return shiftedBits

    def _mixColumnsGetDecimalList(self, state: BitArray) -> list[BitArray]:
        """
        Splits a 16-bit state into a list of four 4-bit integers (nibbles).

        Each element in the returned list represents a column in the state,
        extracted from the 16-bit integer.

        Args:
            state (int): The current 16-bit state as an integer.

        Returns:
            list[int]: A list of four integers, each corresponding to a 4-bit column.

        Example:
            >>> cipher = saesCipher()
            >>> state = 0x1234
            >>> columns = cipher._mixColumnsGetDecimalList(state)
            >>> print(columns)
            [1, 2, 3, 4]
        """

        return list(state.cut(4))

    def _BitwiseMultiply(self, a: BitArray, b: BitArray) -> BitArray:
        """
        Multiplies two 4-bit integers using a precomputed bitwise multiplication table.

        This method looks up the result in the BitwiseMultiplyTable loaded from a CSV file.
        If either input is zero, the result is zero.

        Args:
            a (int): The first 4-bit integer (1-15).
            b (int): The second 4-bit integer (1-15).

        Returns:
            int: The result of the bitwise multiplication.

        Example:
            >>> cipher = saesCipher()
            >>> result = cipher._BitwiseMultiply(3, 4)
            >>> print(result)
            12
        """
        if a.uint == 0 or b.uint == 0:
            return BitArray(uint=0, length=4)
        result = int(
            self.config['BitwiseMultiplyTable'].iloc[a.uint-1, b.uint-1])
        return BitArray(uint=result, length=4)

    def _mixColumns(self, state: BitArray) -> BitArray:
        """
        Applies the MixColumns transformation to the state.

        This operation mixes the columns of the 16-bit state using bitwise multiplication
        and XOR operations, providing diffusion in the cipher. The multiplication factors
        depend on whether the cipher is in encryption or decryption mode.

        Args:
            state (int): The current 16-bit state as an integer.

        Returns:
            int: The state after the MixColumns transformation.
        """
        btm = self._BitwiseMultiply

        nibbles = self._mixColumnsGetDecimalList(state)

        mF = [BitArray(uint=1, length=4), BitArray(uint=4, length=4)]
        if self.config['decrypt']:
            mF = [BitArray(uint=9, length=4), BitArray(uint=2, length=4)]

        result_nibble_0 = btm(nibbles[0], mF[0]) ^ btm(nibbles[1], mF[1])
        result_nibble_1 = btm(nibbles[0], mF[1]) ^ btm(nibbles[1], mF[0])
        result_nibble_2 = btm(nibbles[2], mF[0]) ^ btm(nibbles[3], mF[1])
        result_nibble_3 = btm(nibbles[2], mF[1]) ^ btm(nibbles[3], mF[0])

        return result_nibble_0 + result_nibble_1 + result_nibble_2 + result_nibble_3

    def _electronicCodeBlock(self, blocks: list[BitArray]) -> BitArray:
        result = BitArray()
        for b in blocks:
            if self.config.get('decrypt'):
                result += self.decrypt(b)
            else:
                result += self.encrypt(b)
        return result

    def _cipherBlockChaining(self, blocks: list[BitArray]) -> BitArray:
        if not self.config.get('IV'):
            raise Exception(
                'The cipher need a initializer vector for this operation')

        modificator = self.config['IV']

        result = BitArray()

        if not self.config.get('decrypt'):
            for b in blocks:
                modificator = self.encrypt(modificator ^ b)
                result += modificator
        else:
            for i in range(len(blocks)):
                result += self.decrypt(blocks[i]) ^ modificator
                modificator = blocks[i]

        return result

    def _counter(self, blocks: list[BitArray]) -> BitArray:
        if not self.config.get('N'):
            raise Exception(
                'The cipher need a initial value for the counter')

        if not self.config.get('blockLength'):
            raise Exception(
                'The cipher need a block length for this operation')

        result = BitArray()
        counter = 0
        blockLength = self.config['blockLength']
        for b in blocks:
            result += self.encrypt(BitArray(uint=counter,
                                       length=blockLength)) ^ b
            counter += 1
        return result

    def _addPadding(self, binaryPlainText: BitArray):
        """
        """

        if not binaryPlainText:
            return []

        if not self.config.get('blockLength'):
            raise Exception(
                'The cipher need a block length for this operation')

        blockLength = self.config['blockLength']

        # 1. Split the text into blocks. The last one may be shorter.
        blocks = list(binaryPlainText.cut(blockLength))

        # 2. Isolate the last block.
        lastBlock = blocks[-1]
        lastBlockLength = len(lastBlock)

        # --- Case A: The last block is already complete ---
        if lastBlockLength == blockLength:
            # Create a completely new padding block.
            # Starts with '1' and is filled with zeros.
            paddingBlock = BitArray(bin='1')
            paddingBlock.append(BitArray(length=blockLength - 1))  # Add zeros
            blocks.append(paddingBlock)

        # --- Case B: The last block is incomplete ---
        else:
            # Add the '1' padding bit.
            paddedLastBlock = lastBlock + BitArray(bin='1')

            # Calculate how many zeros are missing to complete the block.
            zerosToAdd = blockLength - len(paddedLastBlock)

            # Add the necessary zeros.
            if zerosToAdd > 0:
                paddedLastBlock += BitArray(length=zerosToAdd)

            # Replace the original last block with its padded version.
            blocks[-1] = paddedLastBlock

        return blocks

    def _removePadding(self, text: BitArray) -> BitArray:
        if not self.config.get('blockLength'):
            raise Exception(
                'The cipher need a block lenght for this operation')

        blocks = list(text.cut(self.config['blockLength']))

        lastBlock = blocks.pop()

        index = len(lastBlock) - 1
        limitFound = False
        while index >= 0:
            if lastBlock[index] == 1:
                limitFound = True
                break

            index -= 1

        if (limitFound):
            if index != 0:
                lastBlock = lastBlock[:index]

                blocks.append(lastBlock)
        else:
            raise Exception("This blocks does not have padding")

        return BitArray().join(blocks)

    def _randomBitArray(self, length: int) -> BitArray:
        numBytes = (length + 7) // 8

        randomBytes = secrets.token_bytes(numBytes)

        randomBits = BitArray(bytes=randomBytes)

        return randomBits[:length]

    def decryptText(self, plaintext: str | BitArray | int):

        self.config['decrypt'] = True

        if not self.config.get('mode'):
            raise Exception(
                'The cipher need a encryptation mode for this operation')
        if not self.config.get('blockLength'):
            raise Exception(
                'The cipher need a block lenght for this operation')

        blockLength = self.config['blockLength']

        binaryPlainText = plaintext

        if isinstance(plaintext, str):
            binaryPlainText = BitArray(bytes=plaintext.encode('utf-8'))
        elif isinstance(plaintext, int):
            binaryPlainText = BitArray(uint=plaintext, length=16)
        elif not isinstance(plaintext, BitArray):
            raise Exception(
                f'The plaintext must be a string, a integer or a BinaryArray. Currently plaintext is a {type(plaintext)}')

        blocks = list(binaryPlainText.cut(blockLength))

        result = BitArray()
        if (self.config['mode'].upper() == 'ECB'):
            result = self._electronicCodeBlock(blocks)
        elif (self.config['mode'].upper() == 'CBC'):
            result = self._cipherBlockChaining(blocks)
        elif (self.config['mode'].upper() == 'CTR'):
            result = self._counter(blocks)
        else:
            result = BitArray().join(blocks)

        return self._removePadding(result)

    def encryptText(self, plaintext: str | BitArray | int):
        if not self.config.get('mode'):
            raise Exception(
                'The cipher need a encryptation mode for this operation')

        binaryPlainText = plaintext

        if isinstance(plaintext, str):
            binaryPlainText = BitArray(bytes=plaintext.encode('utf-8'))
        elif isinstance(plaintext, int):
            binaryPlainText = BitArray(uint=plaintext, length=16)
        elif not isinstance(plaintext, BitArray):
            raise Exception(
                f'The plaintext must be a string, a integer or a BinaryArray. Currently plaintext is a {type(plaintext)}')

        blocks = self._addPadding(binaryPlainText)

        result = BitArray()
        if (self.config['mode'].upper() == 'ECB'):
            result = self._electronicCodeBlock(blocks)
        elif (self.config['mode'].upper() == 'CBC'):
            result = self._cipherBlockChaining(blocks)
        elif (self.config['mode'].upper() == 'CTR'):
            result = self._counter(blocks)
        else:
            result = binaryPlainText

        return result

    def encrypt(self, plaintext: str | BitArray | int) -> BitArray:
        """
        Encrypts a 16-bit binary string using the SAES algorithm.

        This method takes a plaintext binary string (e.g., '1010110010101100'),
        applies the SAES encryption steps (AddRoundKey, SubBytes, ShiftRows, MixColumns),
        and returns the resulting ciphertext as a 16-bit binary string.

        Args:
            plaintext (str): The plaintext to encrypt, as a 16-character binary string (e.g., '1010110010101100').

        Returns:
            str: The encrypted ciphertext as a 16-character binary string.

        """
        self.config['decrypt'] = False  # Ensure we are in encryption mode
        keys = self._generateKeys()

        state = plaintext

        if isinstance(plaintext, str):
            state = BitArray(bin=plaintext)
        elif isinstance(plaintext, int):
            state = BitArray(uint=plaintext, length=16)
        elif not isinstance(plaintext, BitArray):
            raise Exception(
                f'The plaintext must be a string, a integer or a BinaryArray. Currently plaintest is a {type(plaintext)}')

        if self.config['verbose']:
            print("-"*26+"|SAES Cipher - Encrytation|"+"-"*26)
            print(f"Initial state:\n  {BinaryBeauty(state)}")

            print("keys:")
            for k, v in keys.items():
                print(f"  {k}: {BinaryBeauty(v)}")

        # step 1: AddRoundKey
        state = self._addRoundKey(state, keys['key0'])
        if self.config['verbose']:
            print("-"*80)
            print(f"After step 1:\n  {BinaryBeauty(state)}")

        # step 2: SubBytes
        state = self._sub(state)
        if self.config['verbose']:
            print("-"*80)
            print(f"After step 2:\n  {BinaryBeauty(state)}")

        # step 3: ShiftRows
        state = self._shiftRows(state)
        if self.config['verbose']:
            print("-"*80)
            print(f"After step 3:\n  {BinaryBeauty(state)}")

        # step 4: MixColumns
        state = self._mixColumns(state)
        if self.config['verbose']:
            print("-"*80)
            print(f"After step 4:\n  {BinaryBeauty(state)}")

        # step 5: AddRoundKey
        state = self._addRoundKey(state, keys['key1'])
        if self.config['verbose']:
            print("-"*80)
            print(f"After step 5:\n  {BinaryBeauty(state)}")

        # step 6: SubBytes
        state = self._sub(state)
        if self.config['verbose']:
            print("-"*80)
            print(f"After step 6:\n  {BinaryBeauty(state)}")

        # step 7: ShiftRows
        state = self._shiftRows(state)
        if self.config['verbose']:
            print("-"*80)
            print(f"After step 7:\n  {BinaryBeauty(state)}")

        # step 8: AddRoundKey
        state = self._addRoundKey(state, keys['key2'])
        if self.config['verbose']:
            print("-"*80)
            print(f"After step 8:\n  {BinaryBeauty(state)}")

        return state

    def decrypt(self, cipheredtext: str) -> BitArray:
        """
        Decrypts a 16-bit binary string using the SAES algorithm.

        This method takes a ciphertext binary string (e.g., '1010110010101100'),
        applies the SAES decryption steps (inverse AddRoundKey, inverse SubBytes, inverse ShiftRows, inverse MixColumns),
        and returns the resulting plaintext as a 16-bit binary string.

        Args:
            ciphertext (str): The ciphertext to decrypt, as a 16-character binary string (e.g., '1010110010101100').

        Returns:
            str: The decrypted plaintext as a 16-character binary string.

        1111 1110 1010 1000
        """
        self.config['decrypt'] = True
        keys = self._generateKeys()

        state = cipheredtext
        if isinstance(cipheredtext, str):
            state = BitArray(bin=cipheredtext)
        elif isinstance(cipheredtext, int):
            state = BitArray(uint=cipheredtext, length=16)
        elif not isinstance(cipheredtext, BitArray):
            raise Exception(
                f'The cipheredtext must be a string, a integer or a BinaryArray. Currently plaintest is a {type(cipheredtext)}')

        if self.config['verbose']:
            print("-"*27+"|SAES Cipher - Decryption|"+"-"*27)
            print(f"Initial state:\n  {BinaryBeauty(state)}")
            print("keys:")
            for k, v in keys.items():
                print(f"  {k}: {BinaryBeauty(v)}")

        # step 8: AddRoundKey
        state = self._addRoundKey(state, keys['key2'])
        if self.config['verbose']:
            print("-"*80)
            print(f"After step 8:\n  {BinaryBeauty(state)}")

        # step 7: ShiftRows
        state = self._shiftRows(state)
        if self.config['verbose']:
            print("-"*80)
            print(f"After step 7:\n  {BinaryBeauty(state)}")

        # step 6: subBytes
        state = self._sub(state)
        if self.config['verbose']:
            print("-"*80)
            print(f"After step 6:\n  {BinaryBeauty(state)}")

        # step 5: AddRoundKey
        state = self._addRoundKey(state, keys['key1'])
        if self.config['verbose']:
            print("-"*80)
            print(f"After step 5:\n  {BinaryBeauty(state)}")

        # step 4: MixColumns
        state = self._mixColumns(state)
        if self.config['verbose']:
            print("-"*80)
            print(f"After step 4:\n  {BinaryBeauty(state)}")

        # step 3: ShiftRows
        state = self._shiftRows(state)
        if self.config['verbose']:
            print("-"*80)
            print(f"After step 3:\n  {BinaryBeauty(state)}")

        # step 2: subBytes
        state = self._sub(state)
        if self.config['verbose']:
            print("-"*80)
            print(f"After step 2:\n  {BinaryBeauty(state)}")

        # step 1: AddRoundKey
        state = self._addRoundKey(state, keys['key0'])
        if self.config['verbose']:
            print("-"*80)
            print(f"After step 1:\n  {BinaryBeauty(state)}")

        return state
