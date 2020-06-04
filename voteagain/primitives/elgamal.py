"""
El Gamal encryption
"""

from petlib.ec import EcGroup

from .ballot_structure import ValuesVector, BallotBundle


class KeyPair:
    """ElGamal key pair"""

    def __init__(self, group):
        self.group = group
        self.sk = self.group.order().random()
        self.pk = PublicKey(self.group, self.sk * self.group.generator())


class PublicKey:
    """ElGamal Public Key"""

    def __init__(self, group, pk):
        self.group = group
        self.infinity = self.group.infinite()
        self.order = self.group.order()
        self.pk = pk
        self.generator = self.group.generator()
        """Generate a random point R"""
        self.pointR = self.order.random() * self.generator

    def get_randomizer(self):
        """Return a random value from the publickey randomizer's space"""
        return self.group.order().random()

    def encrypt(self, msg, ephemeral_key=None):
        """Encrypt a message
        :param msg: Message to encrypt
        :param ephemeral_key: Randomizer of encryption. This should be empty except if we need the randomizer to
        generate a proof of knowledge which requires the randomizer
        :return: Encryption of msg.
        """
        generator = self.group.generator()

        if type(ephemeral_key) is ValuesVector:
            return BallotBundle(
                Ciphertext(
                    ephemeral_key.vid * generator, ephemeral_key.vid * self.pk + msg
                ),
                Ciphertext(
                    ephemeral_key.index * generator, ephemeral_key.index * self.pk + msg
                ),
                Ciphertext(
                    ephemeral_key.tag * generator, ephemeral_key.tag * self.pk + msg
                ),
                Ciphertext(
                    ephemeral_key.vote * generator, ephemeral_key.vote * self.pk + msg
                )
                # TODO: Should the previous line not use ephemeral_key.vote?
                # TODO: And why is msg not used here?
            )
        elif ephemeral_key is None:
            ephemeral_key = self.group.order().random()
            return Ciphertext(ephemeral_key * generator, ephemeral_key * self.pk + msg)
        else:
            return Ciphertext(ephemeral_key * generator, ephemeral_key * self.pk + msg)

    def reencrypt(self, ctxt, ephemeral_key=None):
        """Reencrypt a ciphertext
        :param ctxt:
        :param ephemeral_key: randomness of reencryption.
        :return: Reencryption of ctxt
        """
        if ephemeral_key is None:
            ephemeral_key = self.order.random()
        zero_encryption = self.encrypt(self.infinity, ephemeral_key=ephemeral_key)

        return ctxt * zero_encryption


class Ciphertext:
    """ElGamal ciphertext """

    def __init__(self, c1, c2):
        self.c1 = c1
        self.c2 = c2
        self.group = self.c1.group

    def __mul__(self, other):
        """Multiply two ElGamal ciphertexts

        ElGamal ciphertexts are homomorphic. You can multiply two ciphertexts to add
        corresponding plaintexts.

        Example:
            >>> G = EcGroup()
            >>> kp = KeyPair(G)
            >>> ctxt1 = kp.pk.encrypt(10 * G.generator())
            >>> ctxt2 = kp.pk.encrypt(1014 * G.generator())
            >>> ctxt = ctxt1 * ctxt2
            >>> msg = ctxt.decrypt(kp.sk)
            >>> msg == 1024 * G.generator()
            True
        """
        return Ciphertext(self.c1 + other.c1, self.c2 + other.c2)

    def __pow__(self, exponent):
        """Raise ElGamal ciphertexts to a constant exponent

        ElGamal ciphertexts are homomorphic. You can raise a ciphertexts to a known
        exponent to multiply the corresponding plaintext by this exponent.

        Example:
            >>> G = EcGroup()
            >>> kp = KeyPair(G)
            >>> ctxt = kp.pk.encrypt(10 * G.generator()) ** 100
            >>> msg = ctxt.decrypt(kp.sk)
            >>> msg == 1000 * G.generator()
            True
        """
        return Ciphertext(exponent * self.c1, exponent * self.c2)

    def __eq__(self, other):
        return self.c1 == other.c1 and self.c2 == other.c2

    def decrypt(self, sk):
        """Decrypt ElGamal ciphertext

        Example:
            >>> G = EcGroup()
            >>> kp = KeyPair(G)
            >>> msg = 20 * G.generator()
            >>> ctxt = kp.pk.encrypt(msg)
            >>> msg_recovered = ctxt.decrypt(kp.sk)
            >>> msg == msg_recovered
            True
        """
        return self.c2 - sk * self.c1

    def tolist(self):
        """ Create a list out of the ciphertexts
        """
        return [self.c1, self.c2]

    def export(self):
        return


if __name__ == "__main__":
    import doctest

    doctest.testmod()
