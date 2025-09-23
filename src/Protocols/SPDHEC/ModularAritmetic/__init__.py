from bitstring import BitArray
from ..ExtendedEuclideanAlgorithm import ExtendedEuclideanAlgorithm
import secrets


def Mod(a, p):
    mod = a % p
    if (mod >= 0):
        return mod
    else:
        return mod + p


def fastExponentation(a, b, p):
    _a = a
    x = bin(int(b))[2:]
    result = 1
    for i in range(len(x) - 1, -1, -1):
        if x[i] == '1':
            result = (result * _a) % p
            # print(f"\t result: {result}")
        _a = (_a * _a) % p
    return result


def MultiplicativeInverse(a, n):
    gcd = ExtendedEuclideanAlgorithm(a, n)
    d = gcd.d
    S = gcd.S
    if (d == 1):
        S = Mod(S, n)
        return S
    else:
        return -1


def isQuadraticResidue(x, p):
    b = fastExponentation(x, (p - 1) / 2, p)
    if (b == 1):
        return True
    else:
        return False


def RandomQuadraticResidue(p):
    while True:
        x = secrets.randbelow(p - 1)
        if isQuadraticResidue(x, p):
            return x


def RandomQuadraticNonResidue(p):
    while True:
        x = secrets.randbelow(p - 1)
        if not isQuadraticResidue(x, p):
            return x


def ModularSquareRoot(a, p):
    return fastExponentation(a, (p+1)/4, p)
