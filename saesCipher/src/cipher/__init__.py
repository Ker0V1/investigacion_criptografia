from abc import ABC, abstractmethod
from typing import Any

class cipher(ABC):
    """
    Abstract base class for ciphers.
    """

    @abstractmethod
    def encrypt(self, plaintext: str) -> Any:
        """
        Encrypts the given plaintext.
        Args:
            plaintext: The string to encrypt.
        Returns:
            The encrypted data. The type depends on the specific cipher implementation.
        """

        pass

    @abstractmethod
    def decrypt(self, ciphertext: str) -> Any:
        """
        Decrypts the given ciphertext.

        Args:
            ciphertext: The string to decrypt.

        Returns:
            The decrypted plaintext string.
        """

        pass

    @abstractmethod
    def setConfig(self, newConf:dict) -> None:
        """
        Sets the configuration for the cipher. In this method, the cipher should be initialized with the corrects parameters, for example, the key, mode of operation, etc.

        Args:
            config (dict): A dictionary containing all the configuration parameters for the cipher.
        """
        self._config = self._config | newConf
    