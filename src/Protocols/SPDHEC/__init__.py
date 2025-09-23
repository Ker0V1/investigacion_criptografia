from math import sqrt
from .ModularAritmetic import *
import random
import os


class ECPoint:
    """
    Represents a point on an elliptic curve.
    Attributes:
        x (int): The x-coordinate of the point.
        y (int): The y-coordinate of the point.
    Args:
        x (int, optional): The x-coordinate of the point. Defaults to None.
        y (int, optional): The y-coordinate of the point. Defaults to None.
        p (ECPoint, optional): Another ECPoint instance to copy coordinates from. Defaults to None.
    If `p` is provided, the point is initialized as a copy of `p`.
    If `x` and `y` are provided, the point is initialized with those coordinates.
    If neither is provided, the point is initialized with coordinates (-1, -1).
    """
    

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
        """
        Initializes the elliptic curve object with given parameters.
        Parameters:
            a (int, optional): The coefficient 'a' of the elliptic curve equation. Defaults to None.
            b (int, optional): The coefficient 'b' of the elliptic curve equation. Defaults to None.
            safePrime (int, optional): The prime modulus 'p' for the elliptic curve. Defaults to None.
        Behavior:
            - If any parameter is None, sets the curve parameters and status to invalid values.
            - Checks if the curve defined by (a, b, safePrime) is non-singular.
            - Computes the order of the elliptic curve and checks if it is prime.
            - Sets the curve parameters and status accordingly.
            - Prints error messages if the curve is singular or has non-prime order.
        """
        
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
        """
        Sets the parameters for the elliptic curve.
        Args:
            a (int): The coefficient 'a' of the elliptic curve equation.
            b (int): The coefficient 'b' of the elliptic curve equation.
            safePrime (int): The prime number defining the finite field (the modulus).
            primeOrder (int): The order of the elliptic curve group.
        Sets:
            self.ecStatus (bool): Flag indicating that elliptic curve parameters are set.
            self.A (int): Stores the coefficient 'a'.
            self.B (int): Stores the coefficient 'b'.
            self.p (int): Stores the prime modulus.
            self.ecOrder (int): Stores the order of the elliptic curve group.
        """
        
        self.ecStatus = True
        self.A = a
        self.B = b
        self.p = safePrime
        self.ecOrder = primeOrder

    def generateRandomEC(self):
        """
        Generates random parameters for an elliptic curve over a finite field defined by a safe prime.
        This method selects a random safe prime from a file, then randomly generates coefficients 'a' and 'b'
        for the elliptic curve equation y^2 = x^3 + ax + b (mod p). It ensures the curve is non-singular and
        that the order of the curve is prime. The generated parameters are stored in the instance attributes:
        self.A, self.B, self.p, and self.ecOrder. If the process fails at any step, an error message is printed.
        Raises:
            Prints error messages if the safe primes file cannot be read or is empty/incorrectly formatted.
        """
        
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
        """
        Determines if the elliptic curve defined by the equation y^2 = x^3 + ax + b over the finite field F_p is non-singular.

        An elliptic curve is non-singular if the discriminant (4a^3 + 27b^2) mod p is not zero.

        Args:
            a (int): The coefficient 'a' in the elliptic curve equation.
            b (int): The coefficient 'b' in the elliptic curve equation.
            p (int): The prime modulus defining the finite field F_p.

        Returns:
            bool: True if the curve is non-singular, False otherwise.
        """
        result = 0
        exp = fastExponentation

        result = ((4 * exp(a, 3, p) % p) + (27 * exp(b, 2, p) % p)) % p

        return result != 0

    def ECPointAddition(self, P1, P2):
        """
        Adds two elliptic curve points P1 and P2 over a finite field.
        This method implements the group law for elliptic curves, handling the following cases:
            - If P1 and P2 are additive inverses, returns the point at infinity.
            - If P1 and P2 are equal (point doubling), uses the tangent method.
            - Otherwise, uses the chord method for distinct points.
        Args:
            P1 (ECPoint): The first elliptic curve point.
            P2 (ECPoint): The second elliptic curve point.
        Returns:
            ECPoint: The resulting point from the addition of P1 and P2.
        """
        
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
        """
        Performs point doubling on an elliptic curve over a finite field.
        Given a point P on the elliptic curve, computes and returns the result of 2P
        according to the curve's group law.
        Args:
            P (ECPoint): The point to be doubled on the elliptic curve.
        Returns:
            ECPoint: The resulting point after doubling P. If P.y == 0, returns the point at infinity.
        """
        
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
        """
        Performs scalar multiplication of an elliptic curve point using the double-and-add algorithm.
        Args:
            P (ECPoint): The elliptic curve point to be multiplied.
            n (int): The scalar multiplier.
        Returns:
            ECPoint: The resulting elliptic curve point after multiplication.
        """
        
        Q = ECPoint(p=P)
        x = bin(n)[2:] 
        for i in range(1, len(x)):
            Q = self.ECPointDoubling(Q)
            if x[i] == '1':
                Q = self.ECPointAddition(Q, P)

        return Q

    def isEqual(self, P1, P2):
        """
        Checks whether two points P1 and P2 are equal by comparing their x and y coordinates.
        Args:
            P1: The first point, expected to have 'x' and 'y' attributes.
            P2: The second point, expected to have 'x' and 'y' attributes.
        Returns:
            bool: True if both points have the same x and y coordinates, False otherwise.
        """
        
        return P1.x == P2.x and P1.y == P2.y

    def isAdditiveInverse(self, P1, P2):
        """
        Checks if two points P1 and P2 are additive inverses on the elliptic curve.
        Args:
            P1: An object representing a point on the elliptic curve, with attributes 'x' and 'y'.
            P2: An object representing another point on the elliptic curve, with attributes 'x' and 'y'.
        Returns:
            bool: True if P2 is the additive inverse of P1 (i.e., they have the same x-coordinate and their y-coordinates sum to 0 modulo the curve's prime p), False otherwise.
        """
        
        return P1.x == P2.x and P1.y == (self.p - P2.y)

    def generateAllECPoints(self):
        """
        Generates and prints all points (x, y) on the elliptic curve defined by the equation:
            y^2 ≡ x^3 + A*x + B (mod p)
        for all x in the range [0, p-1], where A, B, and p are attributes of the class instance.
        For each x in the field:
            - Computes w = x^3 + A*x + B mod p.
            - If w == 0, prints the point (x, 0).
            - If w is a quadratic residue modulo p, computes the modular square root(s) of w,
              and prints both corresponding points (x, sqrt) and (x, p - sqrt).
        Prints the total number of points found (excluding the point at infinity).
        """
        
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
        """
        Generates a random point on the elliptic curve defined by the parameters of the current instance.
        The method randomly selects an x-coordinate and computes the corresponding y-coordinate(s) 
        such that the point (x, y) lies on the elliptic curve: y^2 ≡ x^3 + Ax + B (mod p).
        If the computed value is a quadratic residue modulo p, two possible y-coordinates exist.
        One of these points is randomly chosen and returned.
        Returns:
            ECPoint: A randomly generated point on the elliptic curve.
        """
        
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
        """
        Calculates the order of an elliptic curve defined over a finite field of prime order p.
        The elliptic curve is defined by the equation: y^2 = x^3 + a*x + b (mod p).
        The function iterates over all possible x values in the field, computes the corresponding
        right-hand side value, and determines if it is a quadratic residue modulo p to count the
        number of points on the curve.
        Args:
            a (int): The coefficient 'a' in the elliptic curve equation.
            b (int): The coefficient 'b' in the elliptic curve equation.
            p (int): The prime order of the finite field.
        Returns:
            int: The order (number of points) of the elliptic curve over the finite field.
        """
        
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
        """
        Determines whether a given integer n is a prime number.
        For n > 100,000, the function first checks divisibility by a list of small prime numbers.
        If n is not divisible by any of these, it checks for divisibility by odd numbers starting from 101 up to sqrt(n).
        For n <= 100,000, it handles small primes directly, checks divisibility by 2 and 3,
        and then tests odd divisors up to n.
        Args:
            n (int): The integer to test for primality.
        Returns:
            bool: True if n is prime, False otherwise.
        """
        
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
