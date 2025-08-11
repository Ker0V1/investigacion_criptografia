from src.cipher import cipher
from math import gcd


class affineCipher(cipher):
    """
    Implements the affine cipher for encrypting and decrypting text.

    The affine cipher is a type of monoalphabetic substitution cipher where each
    letter in an alphabet is mapped to its numeric equivalent, encrypted using a
    simple mathematical function, and then converted back to a letter. The
    encryption function is `E(x) = (αx + β) mod n`, where `α` (alpha) and `β`
    (beta) are the keys of the cipher.

    This class requires that the coefficient `α` be coprime with the length
    of the alphabet (`n`).

    Attributes:
        _config (dict): A dictionary holding the cipher's configuration,
                        including 'alpha', 'beta', and the 'alphabet'.
    """

    def __init__(self):
        """
        Initializes the affineCipher object.

        Sets up the initial configuration with default values for the coefficients
        (alpha and beta) and the alphabet.
        """
        
        self._config = {
            'alpha': 1,
            'beta': 1,
            'alphabet': "abcdefghijklmnopqrstuvwxyz"
        }

    def setConfig(self, newConf):
        """
        Sets a new configuration for the cipher after validation.

        This method validates the provided configuration, specifically ensuring
        that the 'alpha' and 'beta' coefficients are valid for the affine
        cipher with the current alphabet. After successful validation, it
        calls the parent class's `setConfig` method to apply the configuration.

        Args:
            newConf (dict): A dictionary containing the new configuration
                            settings to be applied (e.g., {'alpha': 5, 'beta': 8}).

        Returns:
            The return value of the parent class's `setConfig` method.

        Raises:
            Exception: If the 'alpha' or 'beta' coefficients are invalid.
                    This is raised by the `_checkCoef` method.
        """
        self._checkCoef(self._config| newConf)
        return super().setConfig(newConf)

    def _checkCoef(self, config: dict):
        """
        Validates the coefficients for the affine cipher.

        This internal method checks if the provided 'alpha' and 'beta'
        coefficients are valid for an affine cipher given the alphabet size (`n`).
        It performs the following checks:
        1.  Ensures 'beta' is within the valid range [0, n-1].
        2.  Ensures 'alpha' is within the valid range [0, n-1].
        3.  Ensures 'alpha' is coprime with the length of the alphabet (`n`),
            which is a necessary condition for the ciphertext to be decryptable.

        Args:
            config (dict): The configuration dictionary to validate. It is
                        expected to contain 'alpha', 'beta', and 'alphabet' keys.

        Raises:
            Exception: If any of the validation checks fail, an exception is
                    raised with a descriptive error message.
        """
    
        n = len(config['alphabet'])

        if (config['beta'] < 0) or (config['beta'] >= n):
            raise Exception(
                f'The coefficiente "beta" must be in the range [0, {n - 1}].'
            )

        if (config['alpha'] < 0) or (config['alpha'] >= n):
            raise Exception(
                f'The coefficiente "alpha" must be in the range [0, {n - 1}].'
            )

        if gcd(config['alpha'], n) != 1:
            raise Exception(
                f'The coefficient "alpha" must be coprime with the alphabet size ({n}).')

    def encrypt(self, plainText):
        """
        Encrypts a given plaintext string using the affine cipher.

        The method processes the input string character by character. It converts
        each character to lowercase, finds its index in the configured alphabet,
        and applies the affine cipher encryption formula: E(x) = (αx + β) mod n.
        Characters not present in the alphabet will raise an error, while spaces
        are preserved.

        Args:
            plainText (str): The string to be encrypted.

        Returns:
            str: The resulting encrypted string (ciphertext).

        Raises:
            ValueError: If a character in `plainText` (other than a space) is not
                        found in the configured alphabet.
        """
        result = ""
        n = len(self._config['alphabet'])

        plainText = plainText.lower().strip()

        for char in plainText:
            if char in self._config['alphabet']:
                index = self._config['alphabet'].index(char)

                newIndex = (self._config['alpha'] *
                            index + self._config['beta']) % n

                result += self._config['alphabet'][newIndex]

            elif char == ' ':
                result += char

            else:
                raise ValueError(f"Character '{char}' not in alphabet.")

        return result

    def decrypt(self, ciphertext):
        """
        Decrypts a given ciphertext string that was encrypted with the affine cipher.

        The method processes the input string character by character. It finds each
        character's index in the alphabet and applies the affine cipher decryption
        formula: D(y) = α⁻¹(y - β) mod n, where α⁻¹ is the modular multiplicative
        inverse of α modulo n. Characters not in the alphabet will raise an error,
        and spaces are preserved.

        Args:
            ciphertext (str): The string to be decrypted.

        Returns:
            str: The resulting decrypted string (plaintext).

        Raises:
            ValueError: If a character in `ciphertext` (other than a space) is not
                        found in the configured alphabet.
        """
        
        result = ""
        n = len(self._config['alphabet'])

        ciphertext = ciphertext.lower().strip()

        for char in ciphertext:
            if char in self._config['alphabet']:
                index = self._config['alphabet'].index(char)

                newIndex = (
                    index - self._config['beta'])*pow(self._config['alpha'], -1, n) % n

                result += self._config['alphabet'][newIndex]

            elif char == ' ':
                result += char

            else:
                raise ValueError(f"Character '{char}' not in alphabet.")

        return result
