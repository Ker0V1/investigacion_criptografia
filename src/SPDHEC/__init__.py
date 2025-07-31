from math import sqrt
from src.SPDHEC.ModularAritmetic import *
from bitstring import BitArray
import random
import os


class ECPoint:

    def __init__(self, x=None, y=None, p=None) -> None:
        if p != None:
            self.x = p.x
            self.y = p.y
        elif x != None and y != None:
            self.x = x
            self.y = y
        else:
            self.x = -1
            self.y = -1


class ECC:

    def __init__(self, a=None, b=None, safePrime=None) -> None:
        if (a == None or b == None or safePrime == None):
            self.A = -1
            self.B = -1
            self.p = -1
            self.ecOrder = -1
            self.ecStatus = False
        else:
            if (not self.isECNonSingular(a, b, safePrime)):
                self.ecStatus = False
                print(
                    "ERROR: The object canonot be created because the Elliptic is Singular")
                return

            self.ecOrder = self.ECOrder(a, b, safePrime)
            if not self.isPrime(self.ecOrder):
                self.ecStatus = False
                print(
                    "ERROR: The object canonot be created because the Elliptic is Singular")
                return

            self.ecStatus = True
            self.A = a
            self.B = b
            self.p = safePrime

    def setECParameters(self, a, b, safePrime, primeOrder):
        self.ecStatus = True
        self.A = a
        self.B = b
        self.p = safePrime
        self.ecOrder = primeOrder

    def generateRandomEC(self):
        primesArray = []
        primes = ""

        try:
            actualFolder = os.path.dirname(__file__)

            with open(os.path.join(actualFolder, "ecc_safe_primes.txt"), "r") as readfile:
                primes = readfile.readline()
        except (IOError, FileNotFoundError):
            print("Error: Could not find or read the file 'ecc_safe_primes.txt'.")
            return

        primesArray = primes.split()

        if not primesArray:
            print("Error: The primes file is empty or has an incorrect format.")
            return

        while True:
            pos = random.randint(0, len(primesArray) - 1)
            p = int(primesArray[pos])

            MAXVAL = 9000000

            while True:
                a = random.randint(0, MAXVAL)
                if a != 0:
                    break

            while True:
                b = random.randint(0, MAXVAL)
                if b != 0:
                    break

            if not self.isECNonSingular(a, b, p):
                continue

            self.ecOrder = self.ECOrder(a, b, p)

            if not self.isPrime(self.ecOrder):
                continue

            self.ecStatus = True
            self.A = a
            self.B = b
            self.p = p
            break

        print(f"A = {self.A}")
        print(f"B = {self.B}")
        print(f"p = {self.p}")
        print(f"Order = {self.ecOrder}")

    def isECNonSingular(self, a, b, p):
        result = 0
        exp = fastExponentation

        result = ((4 * exp(a, 3, p) % p) + (27 * exp(b, 2, p) % p)) % p

        return result != 0

    def ECPointAddition(self, P1, P2):
        P3 = ECPoint(-1, -1)

        if self.isAdditiveInverse(P1, P2):
            return P3

        elif self.isEqual(P1, P2):
            if P1.y == 0:
                return P3

            inv = MultiplicativeInverse((2 * P1.y) % self.p, self.p) % self.p
            m = (((((3 * fastExponentation(P1.x, 2, self.p)) %
                 self.p) + self.A) % self.p) * inv) % self.p
        else:
            inv = MultiplicativeInverse(Mod(P2.x - P1.x, self.p), self.p)
            m = (Mod(P2.y - P1.y, self.p) * inv) % self.p

        P3.x = Mod(fastExponentation(m, 2, self.p) - P1.x - P2.x, self.p)
        P3.y = Mod(((m * Mod(P1.x - P3.x, self.p)) % self.p) - P1.y, self.p)

        return P3

    def ECPointDoubling(self, P):
        R = ECPoint(-1, -1)
        if P.y == 0:
            return R

        Q = ECPoint(p=P)

        inv = MultiplicativeInverse((2 * P.y) % self.p, self.p) % self.p
        m = (((((3 * fastExponentation(P.x, 2, self.p)) %
             self.p) + self.A) % self.p) * inv) % self.p

        R.x = Mod(fastExponentation(
            m, 2, self.p) - ((2 * P.x) % self.p), self.p)
        R.y = Mod(((m * Mod(P.x - R.x, self.p)) %
                   self.p) - P.y, self.p)

        return R

    def ECDoubleAndAdd(self, P, n):
        Q = ECPoint(p=P)
        x = bin(n)[2:] 
        for i in range(1, len(x)):
            Q = self.ECPointDoubling(Q)
            if x[i] == '1':
                Q = self.ECPointAddition(Q, P)

        return Q

    def isEqual(self, P1, P2):
        return P1.x == P2.x and P1.y == P2.y

    def isAdditiveInverse(self, P1, P2):
        return P1.x == P2.x and P1.y == (self.p - P2.y)

    def generateAllECPoints(self):
        x = 0
        count = 0
        while x < self.p:
            w = (fastExponentation(x, 3, self.p) +
                 ((self.A * x) % self.p) + self.B) % self.p
            if w == 0:
                print(f"({x}, {w})")
                count += 1
                x += 1
                continue

            if isQuadraticResidue(w, self.p):
                sqrt = ModularSquareRoot(w, self.p)
                print(f"({x}, {sqrt})\t({x}, {-1 * sqrt + self.p})")
                count += 2

            x += 1

        print(
            f"Total Points on Elliptic Curve (without the point at infinity) = {count}")

    def generateRandomECPoint(self):
        P = ECPoint(0, 0)
        Q = ECPoint(0, 0)

        while True:
            x = random.randint(0, self.p - 1)
            w = (fastExponentation(x, 3, self.p) +
                 ((self.A * x) % self.p) + self.B) % self.p

            if w == 0:
                P.x = x
                P.y = 0
                return P

            if isQuadraticResidue(w, self.p):
                sqrt = ModularSquareRoot(w, self.p)
                P.x = x
                P.y = sqrt
                Q.x = x
                Q.y = -1 * sqrt + self.p
                break

        choice = random.choice([P, Q])
        return choice

    def ECOrder(self, a, b, p):
        order = p + 1
        x = 0
        while (x < p):
            w = (fastExponentation(x, 3, p) + ((a * x) % p) + b) % p

            if (w == 0):
                x += 1
                continue

            if isQuadraticResidue(w, p):
                order += 1
            else:
                order -= 1

            x += 1

        return order

    def ECOrderOfElement(self, P):
        return self.ecOrder

    def isPrime(self, n):
        if n > 100000:
            primesArray = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
                           37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]

            for prime in primesArray:
                if n % prime == 0:
                    return False

            d = 101

            sqrtN = sqrt(n)

            while d <= sqrtN:
                if n % d == 0:
                    return False
                d += 2

            return True
        else:
            if n in [2, 3, 5, 7]:
                return True

            if n % 2 == 0 or n % 3 == 0:
                return False

            d = 3
            sqrtN = sqrt(n)

            while d <= n:
                if n % d == 0:
                    return False
                d += 2

            return True
