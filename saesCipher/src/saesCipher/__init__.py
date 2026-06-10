import secrets
from src.cipher import cipher
from bitstring import BitArray
import pandas as pd
import re
import os

from src.utils import BinaryBeauty, splitBinaryGroupsInt


class saesCipher(cipher):
    """
    Implements the Simplified AES (SAES) block cipher algorithm with support for multiple modes of operation.
    This class provides encryption and decryption functionality for 16-bit blocks using the SAES algorithm.
    It supports ECB (Electronic Codebook), CBC (Cipher Block Chaining), and CTR (Counter) modes, and includes
    padding and unpadding mechanisms. The cipher uses configurable S-boxes, bitwise multiplication tables, and
    allows for verbose output for educational or debugging purposes.
    Attributes:
        config (dict): Configuration dictionary containing cipher parameters such as mode, block length,initialization vector (IV), counter value (N), S-boxes, and bitwise multiplication table.
    Methods:
        __init__():
            Initializes the cipher configuration, loads S-boxes and multiplication tables from CSV files.
        setConfig(newConf: dict) -> None:
            Updates the cipher configuration with new parameters.
        _rota(byte: BitArray) -> BitArray:
            Rotates an 8-bit byte 4 bits to the left.
        _sub(word: BitArray) -> BitArray:
            Applies S-box substitution to a word (4 or more bits).
        _generateKeys() -> dict[str, BitArray]:
            Generates round keys for the SAES algorithm.
        _addRoundKey(state: BitArray, key: BitArray) -> BitArray:
            XORs the state with a round key.
        _shiftRows(state: BitArray) -> BitArray:
            Performs the ShiftRows transformation on the state.
        _mixColumnsGetDecimalList(state: BitArray) -> list[BitArray]:
            Splits a 16-bit state into four 4-bit nibbles.
        _BitwiseMultiply(a: BitArray, b: BitArray) -> BitArray:
            Multiplies two 4-bit integers using a precomputed table.
        _mixColumns(state: BitArray) -> BitArray:
        _electronicCodeBlock(blocks: list[BitArray]) -> BitArray:
            Encrypts or decrypts blocks using ECB mode.
        _cipherBlockChaining(blocks: list[BitArray]) -> BitArray:
            Encrypts or decrypts blocks using CBC mode.
        _counter(blocks: list[BitArray]) -> BitArray:
            Encrypts or decrypts blocks using CTR mode.
        _addPadding(binaryPlainText: BitArray) -> list[BitArray]:
            Adds padding to the plaintext to fit block size.
        _removePadding(text: BitArray) -> BitArray:
            Removes padding from the decrypted text.
        _randomBitArray(length: int) -> BitArray:
            Generates a random bit array of the specified length.
        decryptText(plaintext: str | BitArray | int) -> BitArray:
            Decrypts the input text using the configured mode and removes padding.
        encryptText(plaintext: str | BitArray | int) -> BitArray:
            Encrypts the input text using the configured mode and adds padding.
        encrypt(plaintext: str | BitArray | int) -> BitArray:
            Encrypts a single 16-bit block using the SAES algorithm.
        decrypt(cipheredtext: str | BitArray | int) -> BitArray:
            Decrypts a single 16-bit block using the SAES algorithm.
    Note:
        - The class requires external CSV files for S-boxes and multiplication tables.
        - The BitArray type is used for bitwise operations and block representation.
        - Verbose output can be enabled via the 'verbose' config parameter for step-by-step tracing.
    """

    def __init__(self):
        """
        Initializes the cipher configuration with default parameters and loads required tables from CSV files.
        Attributes:
            config (dict): Configuration dictionary containing:
                - 'decrypt' (bool): Indicates if the cipher is in decryption mode (default: False).
                - 'mode' (str): Cipher mode of operation (default: 'ECB').
                - 'blockLength' (int): Length of the cipher block in bytes (default: 16).
                - 'IV' (BitArray): Initialization vector, randomly generated bit array of length 16.
                - 'N' (BitArray): Randomly generated bit array of length 16.
                - 'encryptionSbox' (DataFrame): Substitution box for encryption, loaded from 'encryptionSbox.csv'.
                - 'decryptionSbox' (DataFrame): Substitution box for decryption, loaded from 'decryptionSbox.csv'.
                - 'BitwiseMultiplyTable' (DataFrame): Table for bitwise multiplication, loaded from 'BitwiseMultiplyTable.csv'.
        Notes:
            - The S-boxes and multiplication table are loaded from CSV files located in the same directory as this module.
            - The random bit arrays for 'IV' and 'N' are generated using the `_randomBitArray` method.
        """
        
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
            byte (BitArray): An 8-bit array.

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
            word (BitArray): The input bit array (4 or more bits).

        Returns:
            BitArray: The substituted BitArray after applying the S-box.
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
        Generates round keys for the SAES cipher based on the initial key provided in the configuration.
        The method supports initial keys as strings, integers, or BitArray objects. It performs key expansion
        using bitwise operations and substitution/rotation functions to produce three round keys.
        Returns:
            dict[str, BitArray]: A dictionary containing the generated round keys.
        Raises:
            Exception: If the key in the configuration is not a string, integer, or BitArray.
        Side Effects:
            Temporarily modifies the 'decrypt' flag in the configuration during key generation.
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
        Applies the AddRoundKey step in the SAES cipher by performing a bitwise XOR 
        between the current state and the round key.
        Args:
            state (BitArray): The current state of the cipher as a BitArray.
            key (BitArray): The round key as a BitArray.
        Returns:
            BitArray: The result of XOR-ing the state with the key.
        """
        
        return state ^ key

    def _shiftRows(self, state: BitArray) -> BitArray:
        """
        Performs the ShiftRows operation on a 16-bit state represented as a BitArray.
        The state is divided into four 4-bit nibbles. The operation rearranges the nibbles
        as follows:
            - The first nibble remains in place.
            - The second nibble is shifted to the last position.
            - The third nibble remains in place.
            - The fourth nibble moves to the second position.
        Args:
            state (BitArray): A 16-bit BitArray representing the current state.
        Returns:
            BitArray: A new BitArray with the nibbles rearranged according to the ShiftRows operation.
        """
        
        nibble1 = state[0:4]
        nibble2 = state[4:8]
        nibble3 = state[8:12]
        nibble4 = state[12:16]

        shiftedBits = nibble1 + nibble4 + nibble3 + nibble2

        return shiftedBits

    def _mixColumnsGetDecimalList(self, state: BitArray) -> list[BitArray]:
        """
        Splits the given BitArray `state` into a list of BitArray objects, each containing 4 bits.
        Args:
            state (BitArray): The input BitArray representing the current state.
        Returns:
            list[BitArray]: A list of BitArray objects, each representing a 4-bit segment of the input state.
        """
        

        return list(state.cut(4))

    def _BitwiseMultiply(self, a: BitArray, b: BitArray) -> BitArray:
        """
        Performs bitwise multiplication of two 4-bit values using a lookup table.
        Args:
            a (BitArray): The first 4-bit operand.
            b (BitArray): The second 4-bit operand.
        Returns:
            BitArray: The result of the bitwise multiplication as a 4-bit value.
        Notes:
            - If either operand is zero, the result is zero.
            - The multiplication is performed using a precomputed lookup table
              stored in self.config['BitwiseMultiplyTable'].
        """
        
        if a.uint == 0 or b.uint == 0:
            return BitArray(uint=0, length=4)
        result = int(
            self.config['BitwiseMultiplyTable'].iloc[a.uint-1, b.uint-1])
        return BitArray(uint=result, length=4)

    def _mixColumns(self, state: BitArray) -> BitArray:
        """
        Performs the MixColumns transformation on the given state for the SAES cipher.
        This method applies a matrix multiplication over the finite field GF(2^4) to the input state,
        mixing the nibbles according to the cipher's specification. The multiplication factors depend
        on whether encryption or decryption is being performed.
        Args:
            state (BitArray): The current state of the cipher represented as a BitArray.
        Returns:
            BitArray: The transformed state after the MixColumns operation.
        Note:
            - For encryption, the multiplication factors are [1, 4].
            - For decryption, the multiplication factors are [9, 2].
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
        """
        Processes a list of BitArray blocks using Electronic Codebook (ECB) mode.
        For each block in the input list, encrypts or decrypts the block based on the configuration.
        The processed blocks are concatenated and returned as a single BitArray.
        Args:
            blocks (list[BitArray]): List of BitArray blocks to be processed.
        Returns:
            BitArray: Concatenated result of encrypted or decrypted blocks.
        Note:
            The operation (encryption or decryption) is determined by the 'decrypt' key in self.config.
        """
        
        
        result = BitArray()
        for b in blocks:
            if self.config.get('decrypt'):
                result += self.decrypt(b)
            else:
                result += self.encrypt(b)
        return result

    def _cipherBlockChaining(self, blocks: list[BitArray]) -> BitArray:
        """
        Performs Cipher Block Chaining (CBC) mode encryption or decryption on a list of BitArray blocks.
        Args:
            blocks (list[BitArray]): The list of BitArray blocks to be processed.
        Returns:
            BitArray: The resulting BitArray after CBC encryption or decryption.
        Raises:
            Exception: If the initializer vector (IV) is not provided in the configuration.
        Notes:
            - The method uses the 'IV' value from the configuration as the initial vector.
            - If 'decrypt' is not set in the configuration, encryption is performed; otherwise, decryption is performed.
            - For encryption, each block is XORed with the previous ciphertext (or IV for the first block), then encrypted.
            - For decryption, each block is decrypted, then XORed with the previous ciphertext (or IV for the first block).
        """
        
        
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
        """
        Applies a counter (CTR) mode encryption to a list of BitArray blocks.
        For each block in `blocks`, this method generates a keystream block by encrypting
        the current counter value (starting from zero) with the configured block length.
        The keystream block is then XORed with the input block to produce the output.
        The counter is incremented for each block.
        Raises:
            Exception: If the initial counter value ('N') or block length ('blockLength')
                       is not set in the cipher configuration.
        Args:
            blocks (list[BitArray]): List of BitArray blocks to be encrypted/decrypted.
        Returns:
            BitArray: The result of applying the counter mode operation to the input blocks.
        """
        
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
        Adds padding to the input binary plaintext to ensure all blocks are of equal length.
        The padding scheme works as follows:
        - The input BitArray is split into blocks of size `blockLength` (from self.config).
        - If the last block is already complete (its length equals `blockLength`), a new padding block is appended.
          This padding block starts with a '1' bit followed by zeros to fill the block.
        - If the last block is incomplete, a '1' bit is appended to it, followed by enough zeros to reach `blockLength`.
        - Returns a list of BitArray blocks, each of length `blockLength`.
        Args:
            binaryPlainText (BitArray): The plaintext to be padded, represented as a BitArray.
        Returns:
            List[BitArray]: The padded blocks as a list of BitArray objects.
        Raises:
            Exception: If the cipher configuration does not specify a block length.
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
        """
        Removes padding from the given BitArray text according to the block length specified in the cipher configuration.
        The method splits the input BitArray into blocks of the configured block length, then inspects the last block to find the padding delimiter (a bit set to 1).
        If the delimiter is found, the padding is removed from the last block and the blocks are rejoined.
        Raises an exception if the block length is not configured or if the padding delimiter is not found.
        Args:
            text (BitArray): The input BitArray from which padding should be removed.
        Returns:
            BitArray: The BitArray with padding removed.
        Raises:
            Exception: If block length is not configured or if padding delimiter is not found in the last block.
        """
        
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
        """
        Generates a random BitArray of the specified length.
        Args:
            length (int): The number of bits to generate.
        Returns:
            BitArray: A BitArray containing 'length' random bits.
        Notes:
            - Uses cryptographically secure random bytes from the 'secrets' module.
            - The resulting BitArray is sliced to ensure it matches the requested bit length.
        """
        
        numBytes = (length + 7) // 8

        randomBytes = secrets.token_bytes(numBytes)

        randomBits = BitArray(bytes=randomBytes)

        return randomBits[:length]

    def decryptText(self, plaintext: str | BitArray | int):
        """
        Decrypts the given plaintext using the configured cipher mode and block length.
        Args:
            plaintext (str | BitArray | int): The input data to decrypt. Can be a string, BitArray, or integer.
        Raises:
            Exception: If the cipher mode or block length is not configured.
            Exception: If the plaintext is not of a supported type.
        Returns:
            BitArray: The decrypted data with padding removed.
        """

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
        """
        Encrypts the given plaintext using the configured encryption mode.
        Args:
            plaintext (str | BitArray | int): The plaintext to encrypt. Can be a string, BitArray, or integer.
        Raises:
            Exception: If the encryption mode is not set in the configuration.
            Exception: If the plaintext is not a string, integer, or BitArray.
        Returns:
            BitArray: The encrypted ciphertext as a BitArray.
        Notes:
            - Supported encryption modes are 'ECB', 'CBC', and 'CTR'.
            - The plaintext is converted to a BitArray before encryption.
            - Padding is added to the plaintext as needed.
        """
        
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
