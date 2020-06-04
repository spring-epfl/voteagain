"""
Pedersen commitment
"""

from petlib.ec import EcGroup
import numpy as np


class PublicKey:
    """Simple public key for Pedersen's commitment scheme"""

    def __init__(self, group, n):
        """Create a public key for the Pedersen commitment scheme.

        Create a public key for a Pedersen commitment scheme in group `group` for n
        elements. We set the bases by hashing integers to points on the curve.

        Example:
            >>> G = EcGroup()
            >>> pk = PublicKey(G, 2)
        """

        self.group = group
        self.order = self.group.order()
        self.n = n
        self.generators = [
            self.group.hash_to_point(str(i).encode()) for i in range(n + 1)
        ]
        self.generators = np.array(self.generators)

    def commit(self, values, randomizer=None):
        """Commit to a list of values

        Returns two values: the Commitment and the randomizer used to create
        it. The randomizer can also be passed in as the optional parameter.

        Example:
            >>> G = EcGroup()
            >>> pk = PublicKey(G, 2)
            >>> com, rand = pk.commit([10, 20])
        """

        if len(values) != self.n:
            raise RuntimeError(
                "Incorrect length of input {0} expected {1}".format(len(values), self.n)
            )

        if randomizer is None:
            randomizer = self.group.order().random()

        powers = np.array(values + [randomizer])
        commitment = Commitment(np.sum(powers * self.generators))
        return commitment, randomizer

    def commit_reduced(self, values, reduced_n, randomizer=None):
        """Commit to a list of values with a reduced number of generators

        Returns two values as in the method above 'commit'
        """

        generators = self.generators[: reduced_n + 1]

        if len(values) != reduced_n:
            raise RuntimeError(
                "Incorrect length of input {} expected {}".format(
                    len(values), reduced_n
                )
            )

        if randomizer is None:
            randomizer = self.group.order().random()

        powers = np.array(values + [randomizer])
        commitment = Commitment(np.sum(powers * generators))
        return commitment, randomizer

    def export(self):
        # TODO: fix export to be robust
        export = bytes([0x00, 0xFF])
        for gen in self.generators:
            export += gen.export()
        return export


class Commitment:
    """A Pedersen commitment"""

    def __init__(self, commitment):
        self.commitment = commitment

    def __mul__(self, other):
        """Multiply two Pedersen commitments

        The commitment scheme is additively homomorphic. Multiplying two
        commitments gives a commitment to the pointwise sum of the original
        values.

        Example:
            >>> G = EcGroup()
            >>> pk = PublicKey(G, 2)
            >>> com1, rand1 = pk.commit([10, 20])
            >>> com2, rand2 = pk.commit([13, 19])
            >>> comsum = com1 * com2
            >>> com, rand = pk.commit([23, 39], randomizer=rand1 + rand2)
            >>> com == comsum
            True
        """

        return Commitment(self.commitment + other.commitment)

    def __pow__(self, exponent):
        """Raise Pedersen commitment to the power of a constant

        The commitment scheme is additively homomorphic. Raising a commitment
        to a constant power multiplies the committed vector by that constant.

        Example:
            >>> G = EcGroup()
            >>> pk = PublicKey(G, 2)
            >>> com1, rand1 = pk.commit([10, 20])
            >>> commul = com1 ** 10
            >>> com, rand = pk.commit([100, 200], randomizer=10 * rand1)
            >>> com == commul
            True
        """
        return Commitment(exponent * self.commitment)

    def __eq__(self, other):
        return self.commitment == other.commitment

    def export(self):
        return self.commitment.export()


if __name__ == "__main__":
    import doctest

    doctest.testmod()
