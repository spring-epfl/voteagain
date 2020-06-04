"""
Correct decryption
"""

from petlib.ec import EcGroup

import voteagain.primitives.elgamal as elgamal
from voteagain.primitives.hash_function import compute_challenge


class CorrectDecryption:
    """Proof of correct decryption"""

    def __init__(self, ciphertext, plaintext, kp):
        self.group = kp.group
        self.infinity = self.group.infinite()
        self.order = self.group.order()
        self.pk = kp.pk
        self.generator = self.group.generator()

        random_announcement = self.order.random()
        self.announcement = random_announcement * ciphertext.c1

        challenge = compute_challenge(
            ciphertext.tolist() + [plaintext] + [self.announcement] + [self.order],
            self.order,
        )

        self.response = random_announcement + challenge * kp.sk

    def verify(self, ciphertext, plaintext):
        """Verify proof
        Example:
            >>> G = EcGroup()
            >>> kp = elgamal.KeyPair(G)
            >>> msg = 20 * G.generator()
            >>> ctxt = kp.pk.encrypt(msg)
            >>> msg_recovered = ctxt.decrypt(kp.sk)
            >>> proof = CorrectDecryption(ctxt, msg_recovered, kp)
            >>> proof.verify(ctxt, msg_recovered)
            True
        """
        challenge = compute_challenge(
            ciphertext.tolist() + [plaintext] + [self.announcement] + [self.order],
            self.order,
        )

        return (
            challenge * plaintext - self.announcement
            == challenge * ciphertext.c2 - self.response * ciphertext.c1
        )


if __name__ == "__main__":

    import doctest

    doctest.testmod()
