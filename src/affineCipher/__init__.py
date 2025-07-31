from src.cipher import cipher
from math import gcd


class affineCipher(cipher):
    """
    """

    def __init__(self):
        """
        """
        self._config = {
            'alpha': 1,
            'beta': 1,
            'alphabet': "abcdefghijklmnopqrstuvwxyz"
        }

    def setConfig(self, newConf):
        self._checkCoef(self._config| newConf)
        return super().setConfig(newConf)

    def _checkCoef(self, config: dict):
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
