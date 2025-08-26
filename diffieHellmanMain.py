from src.Protocols import DiffieHellman
from random import randint
import argparse
import sys

def checkPosiblePrivateKey(p, g, publicKey):
    """
    Finds all possible private keys that could generate the given public key in a Diffie-Hellman key exchange.
    Args:
        p (int): The prime modulus used in the Diffie-Hellman algorithm.
        g (int): The generator value used in the Diffie-Hellman algorithm.
        publicKey (int): The public key whose possible private keys are to be determined.
    Returns:
        list: A list of integers representing all possible private keys (exponents) such that pow(g, privateKey, p) == publicKey.
    Note:
        This function performs a brute-force search over all possible private keys in the range [1, p-1].
        For large values of p, this operation can be computationally expensive.
    """
    possiblePrivateKeys = []
    for i in range(1,p):
        if pow(g,i,p) == publicKey:
            possiblePrivateKeys.append(i)
    return possiblePrivateKeys

def getConsoleArguments() -> argparse.Namespace:
    """
    Parses command-line arguments for the Diffie-Hellman key exchange script.

    Returns:
        argparse.Namespace: Parsed arguments including prime modulus, generator, private keys, and options.
    """
    parser = argparse.ArgumentParser(
        description="Simulates the Diffie-Hellman key exchange and allows customization of parameters."
    )
    parser.add_argument(
        '-g',
        type=int,
        help='Generator value (g) for the Diffie-Hellman algorithm. If not specified, it will be generated automatically.'
    )
    parser.add_argument(
        '-p',
        type=int,
        help='Prime modulus (p) for the Diffie-Hellman algorithm. If not specified, it will be generated automatically.'
    )
    parser.add_argument(
        '--BobKey',
        type=int,
        help='Bob\'s private key. If not specified, a random value in the range [1, p-1] will be chosen.'
    )
    parser.add_argument(
        '--AliceKey',
        type=int,
        help='Alice\'s private key. If not specified, a random value in the range [1, p-1] will be chosen.'
    )
    parser.add_argument(
        '--checkAllPosibilites',
        action='store_true',
        help='Checks all possible private keys that can generate the public keys of Alice and Bob.'
    )
    return parser.parse_args()

def randomTest():
    dh = DiffieHellman()
    p = dh.getPrime()
    g = dh.getGenerator()

    print("------- Diffie-Hellman Key Exchange -------")
    print(f"Prime (p): {p}")
    print(f"Generator (g): {g}")
    print('================== Bob ====================')
    privateKeyBob = randint(1, p-1)# Arregla esto para que este en el rango [1,p-1]
    publicKeyBob = dh.getPublicKey(privateKeyBob)
    
    print(f"Private Key Bob: {privateKeyBob}")
    print(f"Public Key Bob: {publicKeyBob}")
    
    print('================= Alice ===================')
    privateKeyAlice = randint(1, p-1)
    publicKeyAlice = dh.getPublicKey(privateKeyAlice)
    
    print(f"Private Key Alice: {privateKeyAlice}")
    print(f"Public Key Alice: {publicKeyAlice}")
    
    print('============== Shared Keys ================')
    
    if publicKeyBob is None or publicKeyAlice is None:
        raise ValueError("Public keys must not be None.")
    
    sharedKeyAlice = dh.getSharedKey(publicKeyBob, privateKeyAlice)
    sharedKeyBob = dh.getSharedKey(publicKeyAlice, privateKeyBob)
    
    print(f"Shared Key Alice: {sharedKeyAlice}")
    print(f"Shared Key Bob: {sharedKeyBob}")

if __name__ == "__main__":
    args = getConsoleArguments()

    # If p and g are not provided, generate them automatically
    if not (args.p and args.g):
        dh = DiffieHellman()
        p = dh.getPrime()
        g = dh.getGenerator()
    else:
        p = args.p
        g = args.g
        dh = DiffieHellman(p=p, g=g)

    print("------- Diffie-Hellman Key Exchange -------")
    print(f"Prime (p): {p}")
    print(f"Generator (g): {g}")

    print('================== Bob ====================')
    privateKeyBob = args.BobKey if args.BobKey else randint(1, p - 1)
    publicKeyBob = dh.getPublicKey(privateKeyBob)
    print(f"Private Key Bob: {privateKeyBob}")
    print(f"Public Key Bob: {publicKeyBob}")

    print('================= Alice ===================')
    privateKeyAlice = args.AliceKey if args.AliceKey else randint(1, p - 1)
    publicKeyAlice = dh.getPublicKey(privateKeyAlice)
    print(f"Private Key Alice: {privateKeyAlice}")
    print(f"Public Key Alice: {publicKeyAlice}")

    print('============== Shared Keys ================')
    sharedKeyAlice = dh.getSharedKey(publicKeyBob, privateKeyAlice)
    sharedKeyBob = dh.getSharedKey(publicKeyAlice, privateKeyBob)
    print(f"Shared Key Alice: {sharedKeyAlice}")
    print(f"Shared Key Bob: {sharedKeyBob}")

    if args.checkAllPosibilites:
        print('========= Checking All Possible Private Keys =========')
        possibleBobKeys = checkPosiblePrivateKey(p, g, publicKeyBob)
        possibleAliceKeys = checkPosiblePrivateKey(p, g, publicKeyAlice)
        print(f"Possible Bob Private Keys: {possibleBobKeys}")
        print(f"Possible Alice Private Keys: {possibleAliceKeys}")

