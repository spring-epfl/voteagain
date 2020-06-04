"""
Shuffle argument
"""

# numpy only for random permutation
import numpy as np
from petlib.ec import EcGroup

import voteagain.primitives.pedersen_commitment as com
import voteagain.primitives.elgamal as elgamal

from voteagain.primitives.hash_function import compute_challenge
from voteagain.primitives.ballot_structure import BallotBundle, VoteVector
from voteagain.proofs.efficient_shuffle.multi_exponantiation_argument import (
    MultiExponantiation,
)
from voteagain.proofs.efficient_shuffle.product_argument import ProductArgument


class ShuffleArgument:
    """
    Proof that a shuffle was performed correctly. Following Bayer and Groth in 'Efficient Zero-Knowledge Argument for
    correctness of a shuffle'.
    For sake simplicity in python notation, and without loss of generality, we work with rows instead of working
    with columns, as opposed to the original paper.
    Attention to the change of notation where the permutation in the paper permutes numbers [1, n], whereas our code
    works with a permutation of numbers [0, n-1]
    """

    def __init__(
        self, com_pk, pk, ciphertexts, shuffled_ciphertexts, permutation, randomizers
    ):
        self.order = com_pk.group.order()
        self.m = len(ciphertexts)
        try:
            self.n = len(ciphertexts[0])
        except TypeError:
            raise ValueError(
                "Must reshape ciphertext list to shape m*n. Use functions prepare_ctxts and reshape_m_n."
            )

        if self.n != com_pk.n:
            raise RuntimeError(
                "Incorrect length of commitment key length. Input {} expected {}".format(
                    com_pk.n, self.n
                )
            )

        if (
            self.m != len(shuffled_ciphertexts)
            or self.m != len(permutation)
            or self.m != len(randomizers)
            or self.n != len(shuffled_ciphertexts[0])
            or self.n != len(permutation[0])
            or self.n != len(randomizers[0])
        ):
            raise ValueError(
                "Shape of ciphertexts, shuffled_ciphertexts, permutation and randomizers must be equal."
            )

        # Prepare announcement
        randomizers_permutation_comm = [self.order.random() for _ in range(self.m)]

        self.permutation_comm = [
            com_pk.commit(permutation[i], randomizers_permutation_comm[i])[0]
            for i in range(self.m)
        ]

        # Compute challenge
        self.challenge1 = compute_challenge(self.permutation_comm, self.order)

        # Prepare response
        randomizers_exp_permutation_comm = [self.order.random() for _ in range(self.m)]
        exp_challenge_pem = [
            [
                self.challenge1.mod_pow(permutation[i][j], self.order)
                for j in range(self.n)
            ]
            for i in range(self.m)
        ]

        self.exp_permutation_comm = [
            com_pk.commit(exp_challenge_pem[i], randomizers_exp_permutation_comm[i])[0]
            for i in range(self.m)
        ]

        # Compute challenges
        self.challenge2 = compute_challenge(
            self.permutation_comm + self.exp_permutation_comm, self.order
        )
        self.challenge3 = compute_challenge(
            [self.challenge1, self.challenge2], self.order
        )

        # Final response
        commitment_neg_challenge3 = [
            com_pk.commit([-self.challenge3] * self.n, 0)[0] for _ in range(self.m)
        ]

        commitment_D = [
            (self.permutation_comm[i] ** self.challenge2) * self.exp_permutation_comm[i]
            for i in range(self.m)
        ]

        openings_commitment_D = [
            [
                (self.challenge2 * permutation[i][j] + exp_challenge_pem[i][j]).mod(
                    self.order
                )
                for j in range(self.n)
            ]
            for i in range(self.m)
        ]

        randomizers_commitment_D = [
            (
                self.challenge2 * randomizers_permutation_comm[i]
                + randomizers_exp_permutation_comm[i]
            ).mod(self.order)
            for i in range(self.m)
        ]
        product = (
            self.challenge2 * 0
            + self.challenge1.mod_pow(0, self.order)
            - self.challenge3
        )
        for i in range(1, self.m * self.n):
            product = (
                product * self.challenge2 * i
                + self.challenge1.mod_pow(i, self.order)
                - self.challenge3
            ).mod(self.order)

        # Now we start by engaging in the product argument.
        # We define the matrix A to prove the product argument

        matrix_A = [
            [
                (openings_commitment_D[i][j] - self.challenge3).mod(self.order)
                for j in range(self.n)
            ]
            for i in range(self.m)
        ]
        commitment_A = [
            commitment_D[i] * commitment_neg_challenge3[i] for i in range(self.m)
        ]

        self.product_argument_proof = ProductArgument(
            com_pk, commitment_A, product, matrix_A, randomizers_commitment_D
        )

        # Prepare the statements and witnesses of multiexponantiation argument.
        reencryption_randomizers = sum(
            [
                (-randomizers[i][j] * exp_challenge_pem[i][j]).mod(self.order)
                for i in range(self.m)
                for j in range(self.n)
            ]
        ).mod(self.order)
        challenge_powers = [
            self.challenge1.mod_pow(i, self.order)
            for i in range(1, self.m * self.n + 1)
        ]
        ciphertexts_exponantiated = MultiExponantiation.ctxt_weighted_sum(
            sum(ciphertexts, []), challenge_powers
        )

        self.multi_exponantiation_argument = MultiExponantiation(
            com_pk,
            pk,
            shuffled_ciphertexts,
            ciphertexts_exponantiated,
            self.exp_permutation_comm,
            exp_challenge_pem,
            randomizers_exp_permutation_comm,
            reencryption_randomizers,
        )

    def verify(self, com_pk, pk, ciphertexts, shuffled_ciphertexts):
        """
        Verify shuffle argument
        todo: for some reason this doctest gives error.

        Example:
            >>> G = EcGroup()
            >>> key_pair = elgamal.KeyPair(G)
            >>> pk = key_pair.pk
            >>> m = 3
            >>> ctxts = [BallotBundle(pk.encrypt((i) * G.generator()), pk.encrypt((i) * G.generator()), pk.encrypt((i) * G.generator()), VoteVector([pk.encrypt((i) * G.generator())])) for i in range(10)]
            >>> ctxts, n = ShuffleArgument.prepare_ctxts(ctxts, m, pk)
            >>> com_pk = com.PublicKey(G, n)
            >>> mn = len(ctxts)
            >>> randomizers = [G.order().random() for _ in range(mn)]
            >>> permutation = np.random.permutation(mn).tolist()
            >>> shuffled_ctxts = [pk.reencrypt(ctxts[permuted_index], ephemeral_key=randomizers[index]) for index,permuted_index in enumerate(permutation)]
            >>> ctxts = ShuffleArgument.reshape_m_n(ctxts, m)
            >>> randomizers = ShuffleArgument.reshape_m_n(randomizers, m)
            >>> shuffled_ctxts = ShuffleArgument.reshape_m_n(shuffled_ctxts, m)
            >>> permutation = ShuffleArgument.reshape_m_n(permutation, m)
            >>> proof = ShuffleArgument(com_pk, pk, ctxts, shuffled_ctxts, permutation, randomizers)
            >>> proof.verify(com_pk, pk, ctxts, shuffled_ctxts)
            True

            >>> G = EcGroup()
            >>> key_pair = elgamal.KeyPair(G)
            >>> pk = key_pair.pk
            >>> m = 3
            >>> ctxts = [BallotBundle(pk.encrypt(i * G.generator()), pk.encrypt(i * G.generator()), pk.encrypt(i * G.generator()), VoteVector([pk.encrypt(i * G.generator())])) for i in range(10)]
            >>> ctxts, n = ShuffleArgument.prepare_ctxts(ctxts, m, pk)
            >>> com_pk = com.PublicKey(G, n)
            >>> mn = len(ctxts)
            >>> randomizers = [G.order().random() for _ in range(mn)]
            >>> permutation = np.random.permutation(mn).tolist()
            >>> shuffled_ctxts = [pk.reencrypt(ctxts[permuted_index], ephemeral_key=randomizers[index]) for index, permuted_index in enumerate(permutation)]
            >>> ctxts = ShuffleArgument.reshape_m_n(ctxts, m)
            >>> randomizers = ShuffleArgument.reshape_m_n(randomizers, m)
            >>> shuffled_ctxts = ShuffleArgument.reshape_m_n(shuffled_ctxts, m)
            >>> permutation = ShuffleArgument.reshape_m_n(permutation, m)
            >>> proof = ShuffleArgument(com_pk, pk, ctxts, shuffled_ctxts, permutation, randomizers)
            >>> proof.verify(com_pk, pk, ctxts, shuffled_ctxts)
            True

            >>> ctxts_fake = [BallotBundle(pk.encrypt((i+1) * G.generator()), pk.encrypt((i+1) * G.generator()), pk.encrypt((i+1) * G.generator()), VoteVector([pk.encrypt((i+1) * G.generator())])) for i in range(10)]
            >>> ctxts_fake, n = ShuffleArgument.prepare_ctxts(ctxts_fake, m, pk)
            >>> ctxts = ShuffleArgument.reshape_m_n(ctxts_fake, m)
            >>> proof = ShuffleArgument(com_pk, pk, ctxts, shuffled_ctxts, permutation, randomizers)
            >>> proof.verify(com_pk, pk, ctxts, shuffled_ctxts)
            False

            # We verify that the shuffle also works for single ciphertexts
            >>> G = EcGroup()
            >>> key_pair = elgamal.KeyPair(G)
            >>> pk = key_pair.pk
            >>> m = 3
            >>> ctxts = [pk.encrypt((i) * G.generator()) for i in range(10)]
            >>> ctxts, n = ShuffleArgument.prepare_ctxts(ctxts, m, pk)
            >>> com_pk = com.PublicKey(G, n)
            >>> mn = len(ctxts)
            >>> randomizers = [G.order().random() for _ in range(mn)]
            >>> permutation = np.random.permutation(mn).tolist()
            >>> shuffled_ctxts = [pk.reencrypt(ctxts[permuted_index], ephemeral_key=randomizers[index]) for index,permuted_index in enumerate(permutation)]
            >>> ctxts = ShuffleArgument.reshape_m_n(ctxts, m)
            >>> randomizers = ShuffleArgument.reshape_m_n(randomizers, m)
            >>> shuffled_ctxts = ShuffleArgument.reshape_m_n(shuffled_ctxts, m)
            >>> permutation = ShuffleArgument.reshape_m_n(permutation, m)
            >>> proof = ShuffleArgument(com_pk, pk, ctxts, shuffled_ctxts, permutation, randomizers)
            >>> proof.verify(com_pk, pk, ctxts, shuffled_ctxts)
            True

        """
        check1 = all(
            [
                com_pk.group.check_point(self.permutation_comm[i].commitment)
                for i in range(self.m)
            ]
        )

        check2 = all(
            [
                com_pk.group.check_point(self.exp_permutation_comm[i].commitment)
                for i in range(self.m)
            ]
        )

        # check product argument
        commitment_neg_challenge3 = [
            com_pk.commit([-self.challenge3] * self.n, 0)[0] for _ in range(self.m)
        ]

        commitment_D = [
            (self.permutation_comm[i] ** self.challenge2) * self.exp_permutation_comm[i]
            for i in range(self.m)
        ]
        product = (
            self.challenge2 * 0
            + self.challenge1.mod_pow(0, self.order)
            - self.challenge3
        )
        for i in range(1, self.m * self.n):
            product = (
                product
                * (
                    self.challenge2 * i
                    + self.challenge1.mod_pow(i, self.order)
                    - self.challenge3
                )
            ).mod(self.order)

        commitment_A = [
            commitment_D[i] * commitment_neg_challenge3[i] for i in range(self.m)
        ]

        check3 = self.product_argument_proof.verify(com_pk, commitment_A, product)

        # Check multi-exponantiation argument
        challenge_powers = [
            self.challenge1.mod_pow(i, self.order) for i in range(self.m * self.n)
        ]
        ciphertexts_exponantiated = MultiExponantiation.ctxt_weighted_sum(
            sum(ciphertexts, []), challenge_powers
        )
        check4 = self.multi_exponantiation_argument.verify(
            com_pk,
            pk,
            shuffled_ciphertexts,
            ciphertexts_exponantiated,
            self.exp_permutation_comm,
        )

        return all([check1, check2, check3, check4])

    @staticmethod
    def prepare_ctxts(ctxts, m, election_key):
        """
        Prepares the ctxts list to a compatible ctxts list for the format m * n for the given m, i.e. we append encrypted
        zeros (with randomization 0) till we reach a length of m * (ceil(len(ctxts) / m)
        """
        import math

        if len(ctxts) < m:
            raise ValueError("Lengths of ciphertexts expected greater than value m.")
        n = math.ceil(len(ctxts) / m)

        if type(ctxts[0]) == elgamal.Ciphertext:
            group = ctxts[0].group
            zeros = [elgamal.Ciphertext(group.infinite(), group.infinite())] * (
                m * n - len(ctxts)
            )

        elif type(ctxts[0]) == BallotBundle:
            # todo: attention, we are assuming all values in the BallotBundle come from the same group.
            nr_candidates = ctxts[0].vote.length
            group = ctxts[0].vid.group
            vid = group.order().random()
            counter = group.order().random()
            encrypted_vid = election_key.encrypt(vid * group.generator())
            encrypted_counter = election_key.encrypt(counter * group.generator())
            encrypted_tag = election_key.encrypt(1 * group.generator())
            zeros = [
                BallotBundle(
                    encrypted_vid,
                    encrypted_counter,
                    encrypted_tag,
                    VoteVector(
                        [
                            elgamal.Ciphertext(group.infinite(), group.infinite())
                            for _ in range(nr_candidates)
                        ]
                    ),
                )
            ] * (m * n - len(ctxts))
        else:
            raise ValueError(
                "Unexpected type of ciphertexts. Expecting Ciphertext or BallotBundle, got {0}",
                type(ctxts[0]),
            )

        ctxts.extend(zeros)
        return ctxts, n

    @staticmethod
    def reshape_m_n(list, m):
        """
        Reshapes a list of length len(list) to a 2D array of length m * (len(ctxts) / m)
        """
        n = len(list) // m
        if len(list) % m > 0:
            raise ValueError(
                "Length of list must be divisible by m. Run function prepare_ctxts first."
            )

        return [list[i * n : (i + 1) * n] for i in range(m)]


if __name__ == "__main__":
    import doctest

    doctest.testmod()
