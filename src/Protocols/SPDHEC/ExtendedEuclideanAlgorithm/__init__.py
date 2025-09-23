class ExtendedEuclideanAlgorithm:
    """
    Implements the Extended Euclidean Algorithm for two integers.
    Attributes:
        a (int): The first integer.
        b (int): The second integer.
        S (int): The coefficient for 'a' in the equation d = S*a + T*b, where d is the GCD.
        T (int): The coefficient for 'b' in the equation d = S*a + T*b, where d is the GCD.
        d (int): The greatest common divisor (GCD) of 'a' and 'b'.
    """
    

    def __init__(self, temp_a, temp_b):
        self.a = temp_a
        self.b = temp_b
        self.S = 0
        self.T = 0
        self.d = -1
        self.GCD(self.a, self.b)

    def GCD(self, a, b):
        r1 = a
        r2 = b
        s1 = 1
        s2 = 0
        t1 = 0
        t2 = 1
        while r2 > 0:
            q = r1 // r2
            # updating r's
            r = r1 - q * r2
            r1 = r2
            r2 = r
            # updating s's
            S = s1 - q * s2
            s1 = s2
            s2 = S
            # updating t's
            T = t1 - q * t2
            t1 = t2
            t2 = T
        self.d = r1
        self.S = s1
        self.T = t1
