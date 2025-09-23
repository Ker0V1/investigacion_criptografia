from src.Protocols.SPDHEC import *
import argparse

set_pos = 10
set_generator = ECPoint(2621579, 1711625)
set_alice_private_key = 1944710
set_bob_private_key = 222751

def getConsoleArguments() -> argparse.Namespace:
    """
    Parses command-line arguments for the SPDHEC main script.
    Allows the user to define Bob's and Alice's private keys and select the index of the elliptic curve coefficients.
    Returns:
        argparse.Namespace: Parsed arguments including Bob's and Alice's private keys and the curve index.
    """
    parser = argparse.ArgumentParser(
        description="Simulates the SPDHEC key exchange and allows customization of parameters."
    )
    parser.add_argument(
        '--BobKey',
        type=int,
        help="Bob's private key. If not specified, a random value in the allowed range will be chosen."
    )
    parser.add_argument(
        '--AliceKey',
        type=int,
        help="Alice's private key. If not specified, a random value in the allowed range will be chosen."
    )
    parser.add_argument(
        '--curveIndex',
        type=int,
        help="Index of the elliptic curve coefficients in the list parsed from the file."
    )
    parser.add_argument(
        '--checkAllPosibilites',
        action='store_true',
        help='Checks all possible private keys that can generate the public keys of Alice and Bob.'
    )
    return parser.parse_args()

class SPDHEC:

    def __init__(self, args):
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
        
        if args is None:
            raise Exception("Args should be provided")    
        
        self.args = args

        self.getECFromFile()
        
        self.getRandomEC()
        self.ec.setECParameters(self.A, self.B, self.p, self.ecOrder)

        self.G = self.getRandomGenerator()
        print(f"Generator G = ({self.G.x}, {self.G.y})")

    def getECFromFile(self):
        """
        Reads elliptic curve data from the "Elliptic Curves.txt" file located in the same directory as this script.
        Populates the `self.all_elliptic_curves` list with the data, up to `self.Total_Elliptic_Curves` entries.
        Each line in the file is split into components and stored as a list in `self.all_elliptic_curves`.
        If the file cannot be opened or found, the method silently ignores the error.
        Exceptions:
            IOError, FileNotFoundError: If the file cannot be accessed, the exception is caught and ignored.
        """
        
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
        """
        Selects a random elliptic curve from the list of available curves or uses the curve specified by the user.
        If a curve index is provided in the arguments (`self.args.curveIndex`), selects the curve at that index.
        Otherwise, randomly selects an elliptic curve from the available list.
        Sets the curve parameters (`self.A`, `self.B`, `self.p`, `self.ecOrder`) based on the selected curve.
        Prints the equation of the selected elliptic curve and its prime order.
        Returns:
            None
        """
        

        if self.args.curveIndex is not None:
            pos = self.args.curveIndex
        else:
            pos = random.randint(0, self.Total_Elliptic_Curves - 1)

        self.A = int(self.all_elliptic_curves[pos][0])
        self.B = int(self.all_elliptic_curves[pos][1])
        self.p = int(self.all_elliptic_curves[pos][2])
        self.ecOrder = int(self.all_elliptic_curves[pos][3])

        print(f"Elliptic Curve: x^3 + {self.A}x + {self.B} mod {self.p}")
        print(f"Prime order of Elliptic Curve = {self.ecOrder}")

    def getRandomGenerator(self):
        """
        Generates and returns a random elliptic curve (EC) point to be used as a generator.
        Returns:
            ECPoint: A randomly generated elliptic curve point.
        Note:
            The method relies on the `generateRandomECPoint` function of the `ec` attribute,
            which should provide a valid random point on the elliptic curve.
        """
        
        generator = self.ec.generateRandomECPoint()
        return generator

    def getPrivateKey(self):
        """
        Generates a random private key for elliptic curve cryptography.
        The private key is a random integer in the range [1, ecOrder - 1], where
        ecOrder is the order of the elliptic curve group. The value 0 is excluded
        to ensure the key is valid.
        Returns:
            int: A randomly generated private key.
        """
        
        randVal = -1
        MAXVAL = self.ec.ecOrder

        while True:
            randVal = random.randint(0, MAXVAL - 1)
            if randVal != 0:
                break
        return randVal

    def getPublicKey(self, generator, privateKey):
        """
        Computes the public key corresponding to a given private key using the provided generator point.
        Args:
            generator: The generator point on the elliptic curve.
            privateKey: The private key (integer) to be used for public key generation.
        Returns:
            The public key point resulting from scalar multiplication of the generator by the private key.
        """
        
        publicKey = self.ec.ECDoubleAndAdd(generator, privateKey)
        return publicKey

    def getPDHECSecretKey(self):
        """
        Generates and returns the S-PDH-EC (Simplified Password-authenticated Diffie-Hellman over Elliptic Curves) secret key and the public keys for Alice and Bob.
        This method performs the following steps:
        1. Retrieves or generates private keys for Alice and Bob, either from provided arguments or by generating new ones.
        2. Computes the corresponding public keys for Alice and Bob using elliptic curve point multiplication.
        3. Computes the shared secret key point for both Alice and Bob using the ECDoubleAndAdd method.
        4. Sets the S-PDH-EC secret key as the y-coordinate of the shared key point.
        5. Prints the private keys, public keys, shared key points, and the final secret key for debugging purposes.
        Returns:
            tuple: A tuple containing:
                - SPDHEC_Key (int): The S-PDH-EC secret key (y-coordinate of the shared key point).
                - publicKeyAlice (ECPoint): Alice's public key point.
                - publicKeyBob (ECPoint): Bob's public key point.
        """
        
        if self.args.AliceKey is not None:
            self.privateKeyAlice = self.args.AliceKey
        else:
            self.privateKeyAlice = self.getPrivateKey()
        
        print(f"Alice - Private Key = {self.privateKeyAlice}")

        if self.args.BobKey is not None:
            self.privateKeyBob = self.args.BobKey
        else:
            self.privateKeyBob = self.getPrivateKey()
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
        print(f"S-PDH-EC Secret Key = {self.SPDHEC_Key}")

        return (self.SPDHEC_Key, self.publicKeyAlice, self.publicKeyBob)
    
    def find_all_private_keys(self, publicKeyAlice, publicKeyBob, final_key):
        """
        Attempts to find all pairs of private keys for Alice and Bob that correspond to the given public keys and shared secret.
        This function iterates over all possible private key values within the elliptic curve order, computes the corresponding public keys,
        and checks if they match the provided public keys for Alice and Bob. If a match is found, it computes the shared secret using both
        private keys and verifies if the resulting shared secret's y-coordinate matches the provided final_key. All valid pairs of private keys
        are collected and returned.
        Args:
            publicKeyAlice: The public key of Alice (expected to have 'x' and 'y' attributes).
            publicKeyBob: The public key of Bob (expected to have 'x' and 'y' attributes).
            final_key: The expected y-coordinate of the shared secret point.
        Returns:
            list: A list of dictionaries, each containing a valid pair of private keys:
                [
                    {
                        'AlicePrivateKey': <int>,
                        'BobPrivateKey': <int>
                    },
                    ...
                ]
        """
        
        results = []
        for alice_priv in range(1, self.ec.ecOrder):
            for bob_priv in range(1, self.ec.ecOrder):
                
                test_pub_alice = self.getPublicKey(self.G, alice_priv)
                test_pub_bob = self.getPublicKey(self.G, bob_priv)
                if (test_pub_alice.x == publicKeyAlice.x and test_pub_alice.y == publicKeyAlice.y   
                    and
                    test_pub_bob.x == publicKeyBob.x and test_pub_bob.y == publicKeyBob.y):
                    K_Alice = self.ec.ECDoubleAndAdd(publicKeyBob, alice_priv)
                    K_Bob = self.ec.ECDoubleAndAdd(publicKeyAlice, bob_priv)
                    if K_Alice.y == final_key and K_Bob.y == final_key:
                        results.append({
                            'AlicePrivateKey': alice_priv,
                            'BobPrivateKey': bob_priv
                        })
        return results


if __name__ == "__main__":
    args = getConsoleArguments()
    ecdh = SPDHEC(args)
    key, publicKeyAlice, publicKeyBob = ecdh.getPDHECSecretKey()
    
    if args.checkAllPosibilites:
        all_possibilities = ecdh.find_all_private_keys(publicKeyAlice, publicKeyBob, key)
        print(f"Total possibilities found: {len(all_possibilities)}")
        for possibility in all_possibilities:
            print(f"Alice Private Key: {possibility['AlicePrivateKey']}, Bob Private Key: {possibility['BobPrivateKey']}")
    
