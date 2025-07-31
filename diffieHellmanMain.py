from random import randint
from src.Protocols import DiffieHellman


if __name__ == "__main__":
    dh = DiffieHellman()
    p = dh.getPrime()
    g = dh.getGenerator()

    print("------- Diffie-Hellman Key Exchange -------")
    print(f"Prime (p): {p}")
    print(f"Generator (g): {g}")
    print('================== Bob ====================')
    privateKeyBob = randint(0, 10000)# Arregla esto para que este en el rango [1,p-1]
    publicKeyBob = dh.getPublicKey(privateKeyBob)
    
    print(f"Private Key Bob: {privateKeyBob}")
    print(f"Public Key Bob: {publicKeyBob}")
    
    print('================= Alice ===================')
    privateKeyAlice = randint(1, 10000)
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


