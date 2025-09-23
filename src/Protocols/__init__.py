import os
import random

from .SPDHEC import *

class DiffieHellman:
    """
    Implements the Diffie-Hellman key exchange protocol for secure key generation and sharing.

    Attributes:
        _p (int | None): The prime number used for the key exchange.
        _g (int | None): The generator used for the key exchange.
        config (dict): Configuration dictionary containing the prime file path.
    """

    _p = None
    _g = None

    def __init__(self, p: int | None = None, g: int | None = None):
        """
        Initializes the DiffieHellman instance with optional prime and generator values.
        If not provided, primes are loaded from a file.

        Args:
            p (int | None): Optional prime number.
            g (int | None): Optional generator.
        """

        self.config = {
            "primeFile": "primes.txt",
        }

        if p is not None and g is not None:
            self._p = p
            self._g = g
        else:
            self._p = None
            self._g = None
            self.setPrimes()

    def setPrimes(self):
        """
        Loads prime and generator values from a file if they are not already set.
        Selects random values for the prime and generator from the file.
        """

        if self._p is not None and self._g is not None:
            return

        actualFolder = os.path.dirname(__file__)
        with open(os.path.join(actualFolder, self.config["primeFile"]), "r") as f:
            lines = f.readlines()

            primes = lines[0].strip().split(" ")

            pIndex = random.choice(range(1, len(primes)))

            # the generator must be less than the prime, and also need to be a coprime to the prime
            gIndex = random.choice(range(pIndex))

            self._p = int(primes[pIndex])
            self._g = int(primes[gIndex])

    def getPrime(self) -> int | None:
        
        """
        Returns the current prime number used for the key exchange.

        Returns:
            int | None: The prime number, or None if not set.
        """
        return self._p

    def getGenerator(self) -> int | None:
        """
        Returns the current generator used for the key exchange.

        Returns:
            int | None: The generator, or None if not set.
        """
        return self._g

    def getPublicKey(self, privateKey: int) -> int | None:
        """
        Computes the public key from a given private key using the Diffie-Hellman algorithm.

        Args:
            privateKey (int): The private key.

        Returns:
            int | None: The computed public key, or None if prime or generator is not set.
        """
        if (self._p is None) or (self._g is None):
            return None

        return pow(self._g, privateKey, self._p)

    def getSharedKey(self, publicKey: int, privateKey: int) -> int | None:
        """
        Computes the shared secret key using a public key and a private key.

        Args:
            publicKey (int): The public key received from the other party.
            privateKey (int): The private key of the current party.

        Returns:
            int | None: The computed shared key, or None if prime or generator is not set.
        """
        
        if (self._p is None) or (self._g is None):
            return None

        return pow(publicKey, privateKey, self._p)
