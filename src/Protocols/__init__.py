import os
import random


class DiffieHellman:
    _p = None
    _g = None

    def __init__(self, p: int | None = None, g: int | None = None):
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
        return self._p

    def getGenerator(self) -> int | None:
        return self._g

    def getPublicKey(self, privateKey: int) -> int | None:
        if (self._p is None) or (self._g is None):
            return None

        return pow(self._g, privateKey, self._p)

    def getSharedKey(self, publicKey: int, privateKey: int) -> int | None:
        if (self._p is None) or (self._g is None):
            return None

        return pow(publicKey, privateKey, self._p)
