from src.cipher import cipher


class caesarCipher(cipher):
    """
    Implements the Caesar cipher encryption and decryption.

    This class inherits from a base `cipher` class.
    It supports configuring the shift value and the alphabet used for encryption/decryption.
    """

    def __init__(self):
        self._conf = {'shift': 1, 'alphabet': 'abcdefghijklmnopqrstuvwxyz'}

    def setConfig(self, newConf) -> None:
        """
        Sets the configuration for the cipher.
        Validates the new configuration to ensure it contains 'shift' and 'alphabet'
        keys and that the 'shift' value is a positive integer.
        Args:
            newConf (dict): A dictionary containing the new configuration.
                            Must include 'shift' (int > 0) and 'alphabet' (str).
        Raises:
            ValueError: If 'shift' or 'alphabet' are missing from newConf,
                        or if 'shift' is not a number greater than 0.
        """

        if 'shift' not in newConf or 'alphabet' not in newConf:
            raise ValueError(
                "Configuration must include 'shift' and 'alphabet'.")

        if newConf['shift'] <= 0:
            raise ValueError("Shift must be a number greater than 0.")

        self._conf = newConf

    def encrypt(self, text) -> str:
        """Encrypts the input text using the Caesar cipher.
        The text is cleaned by converting it to lowercase and removing leading/trailing spaces.
        Each character in the cleaned text is shifted according to the configured shift value
        within the defined alphabet. Spaces are preserved. Characters not in the alphabet
        (except spaces) will raise a ValueError.
        Args:
            text: The string to encrypt.
        Returns:
            The encrypted string.
        Raises:
            ValueError: If a character in the input text is not found in the configured alphabet
                        and is not a space.
        """

        alphabetSize = len(self._conf['alphabet'])
        result = ''

        text = text.lower().strip()

        for char in text:
            if char in self._conf['alphabet']:
                index = self._conf['alphabet'].index(char)
                newIndex = (index + self._conf['shift']) % alphabetSize
                result += self._conf['alphabet'][newIndex]
            elif char == ' ':
                result += char
            else:
                raise ValueError(f"Character '{char}' not in alphabet.")

        return result

    def decrypt(self, ciphertext) -> str:
        """
        Decrypts a ciphertext using the Caesar cipher with the configured shift and alphabet.
        Args:
            ciphertext: The string to decrypt.
        Returns:
            The decrypted plaintext string.
        Raises:
            ValueError: If a character in the ciphertext is not in the configured alphabet and is not a space.
        """

        alphabetSize = len(self._conf['alphabet'])
        result = ''

        ciphertext = ciphertext.lower().strip()

        for char in ciphertext:
            if char in self._conf['alphabet']:
                index = self._conf['alphabet'].index(char)
                newIndex = (index - self._conf['shift']) % alphabetSize
                result += self._conf['alphabet'][newIndex]
            elif char == ' ':
                result += char
            else:
                raise ValueError(f"Character '{char}' not in alphabet.")

        return result
