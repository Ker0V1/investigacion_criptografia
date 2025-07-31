from src.SPDHEC import *

set_pos = 10
set_generator = ECPoint(2621579, 1711625)
set_alice_private_key = 1944710
set_bob_private_key = 222751

class SPDHEC:

    def __init__(self):
        self.A = -1
        self.B = -1
        self.p = -1
        self.ecOrder = -1

        self.Total_Elliptic_Curves = 15
        self.all_elliptic_curves = [[]
                                    for _ in range(self.Total_Elliptic_Curves)]

        self.privateKeyAlice = -1
        self.privateKeyBob = -1
        self.publicKeyAlice = None
        self.publicKeyBob = None
        self.G = None
        self.key = None
        self.SPDHEC_Key = -1
        self.ec = ECC()

        self.getECFromFile()

    def getECFromFile(self):
        try:
            actualFolder = os.path.dirname(__file__)

            with open(os.path.join(actualFolder, "Elliptic Curves.txt"), "r") as readfile:
                i = 0
                for line in readfile:
                    if i < self.Total_Elliptic_Curves:
                        self.all_elliptic_curves[i] = line.split()
                        i += 1
        except (IOError, FileNotFoundError):
            pass

    def getRandomEC(self):
        pos = random.randint(0, self.Total_Elliptic_Curves - 1)
        pos = set_pos  # TODO: BORRAR
        self.A = int(self.all_elliptic_curves[pos][0])
        self.B = int(self.all_elliptic_curves[pos][1])
        self.p = int(self.all_elliptic_curves[pos][2])
        self.ecOrder = int(self.all_elliptic_curves[pos][3])

        print(f"Elliptic Curve: x^3 + {self.A}x + {self.B} mod {self.p}")
        print(f"Prime order of Elliptic Curve = {self.ecOrder}")

    def getRandomGenerator(self):
        generator = self.ec.generateRandomECPoint()
        generator = set_generator #TODO: BORRAR
        return generator

    def getPrivateKey(self):
        randVal = -1
        MAXVAL = self.ec.ecOrder

        while True:
            randVal = random.randint(0, MAXVAL - 1)
            if randVal != 0:
                break
        return randVal

    def getPublicKey(self, generator, privateKey):
        publicKey = self.ec.ECDoubleAndAdd(generator, privateKey)
        return publicKey

    def getPDHECSecretKey(self):
        self.getRandomEC()
        self.ec.setECParameters(self.A, self.B, self.p, self.ecOrder)

        self.G = self.getRandomGenerator()
        print(f"Generator G = ({self.G.x}, {self.G.y})")

        self.privateKeyAlice = self.getPrivateKey()
        self.privateKeyAlice = set_alice_private_key
        print(f"Alice - Private Key = {self.privateKeyAlice}")

        self.privateKeyBob = self.getPrivateKey()
        self.privateKeyBob = set_bob_private_key
        print(f"Bob - Private Key = {self.privateKeyBob}")

        self.publicKeyAlice = self.getPublicKey(self.G, self.privateKeyAlice)
        print(
            f"Alice - Public Key = ({self.publicKeyAlice.x}, {self.publicKeyAlice.y})")

        self.publicKeyBob = self.getPublicKey(self.G, self.privateKeyBob)
        print(
            f"Bob - Public Key = ({self.publicKeyBob.x}, {self.publicKeyBob.y})")

        K_Alice = self.ec.ECDoubleAndAdd(
            self.publicKeyBob, self.privateKeyAlice)

        K_Bob = self.ec.ECDoubleAndAdd(self.publicKeyAlice, self.privateKeyBob)

        self.key = K_Alice

        print(f"Alice - S-PDH-EC - Key Point = ({K_Alice.x}, {K_Alice.y})")
        print(f"Bob - S-PDH-EC - Key Point = ({K_Bob.x}, {K_Bob.y})")

        self.SPDHEC_Key = self.key.y
        print(f"S-PDH-EC Secret Key = {self.SPDHEC_Key}") # resultado esperado = 3

        return self.SPDHEC_Key


if __name__ == "__main__":
    ecdh = SPDHEC()
    key = ecdh.getPDHECSecretKey()
