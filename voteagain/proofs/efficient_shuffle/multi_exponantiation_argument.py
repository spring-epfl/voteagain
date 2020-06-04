"""
Multi exponentiation
"""

from petlib.ec import EcGroup, Bn

import voteagain.primitives.elgamal as elgamal
import voteagain.primitives.pedersen_commitment as com

from voteagain.primitives.hash_function import compute_challenge
from voteagain.primitives.ballot_structure import BallotBundle, VoteVector


class MultiExponantiation:
    """
    We implement the multi exponantiation argument in Bayer and Groth in 'Efficient Zero-Knowledge Argument for
    correctness of a shuffle. However we, for the moment, do not implement the optimization for the multi
    exponantiation computation.
    """

    def __init__(
        self,
        com_pk,
        pk,
        ciphertexts,
        exponantiated_reencrypted_product,
        exponents_commitment,
        exponents,
        commitment_randomizer,
        reencrypted_randomizer,
    ):
        """Shuffle works for both ciphertext of type Ciphertext, or ciphertexts of type BallotBundle"""
        self.order = com_pk.group.order()
        self.infinity = pk.group.infinite()
        self.m = len(ciphertexts)
        self.n = len(ciphertexts[0])
        self.G = pk.generator
        self.type = type(ciphertexts[0][0])
        # If entry is a ballot bundle, then calculate the number of ciphertexts
        if self.type == BallotBundle:
            self.nr_candidates = ciphertexts[0][0].vote.length
        else:
            self.nr_candidates = None

        # Prepare announcement
        announcementA_values = [self.order.random() for _ in range(self.n)]
        announcementA_randomiser = self.order.random()

        exponents.insert(0, announcementA_values)
        commitment_randomizer.insert(0, announcementA_randomiser)

        announcementB_values = [self.order.random() for _ in range(2 * self.m)]
        announcementB_randomisers = [self.order.random() for _ in range(2 * self.m)]
        announcement_reencryption_randomisers = [
            self.order.random() for _ in range(2 * self.m)
        ]

        announcementB_values[self.m] = 0
        announcementB_randomisers[self.m] = 0
        announcement_reencryption_randomisers[self.m] = reencrypted_randomizer

        self.announcementA = com_pk.commit(
            announcementA_values, announcementA_randomiser
        )[0]
        self.announcementB = [
            com_pk.commit_reduced(
                [announcementB_values[i]], 1, announcementB_randomisers[i]
            )[0]
            for i in range(2 * self.m)
        ]

        diagonals = []
        for k in range(2 * self.m):
            # Initiate diagonal as the zero BallotBundle
            diagonal = (
                BallotBundle(
                    elgamal.Ciphertext(self.infinity, self.infinity),
                    elgamal.Ciphertext(self.infinity, self.infinity),
                    elgamal.Ciphertext(self.infinity, self.infinity),
                    VoteVector(
                        [
                            elgamal.Ciphertext(self.infinity, self.infinity)
                            for _ in range(self.nr_candidates)
                        ]
                    ),
                )
                if self.type != elgamal.Ciphertext
                else elgamal.Ciphertext(self.infinity, self.infinity)
            )
            for i in range(self.m):
                j = k - self.m + i + 1
                if j < 0:
                    continue
                if j > self.m:
                    break

                diagonal *= self.ctxt_weighted_sum(ciphertexts[i], exponents[j])
            diagonals.append(diagonal)

        # We begin with additive notation for the public keys
        if self.type == elgamal.Ciphertext:
            self.announcement_reencryption = [
                pk.encrypt(
                    announcementB_values[i] * self.G,
                    announcement_reencryption_randomisers[i],
                )
                * diagonals[i]
                for i in range(2 * self.m)
            ]

        elif self.type == BallotBundle:
            self.announcement_reencryption = [
                BallotBundle(
                    pk.encrypt(
                        announcementB_values[i] * self.G,
                        announcement_reencryption_randomisers[i],
                    ),
                    pk.encrypt(
                        announcementB_values[i] * self.G,
                        announcement_reencryption_randomisers[i],
                    ),
                    pk.encrypt(
                        announcementB_values[i] * self.G,
                        announcement_reencryption_randomisers[i],
                    ),
                    VoteVector(
                        [
                            pk.encrypt(
                                announcementB_values[i] * self.G,
                                announcement_reencryption_randomisers[i],
                            )
                            for _ in range(self.nr_candidates)
                        ]
                    ),
                )
                * diagonals[i]
                for i in range(2 * self.m)
            ]
        else:
            raise ValueError(
                "Unexpected type of ciphertexts. Expecting Ciphertext or BallotBundle, got {0}",
                type(self.type),
            )

        # Compute challenge
        # todo: change challenge
        self.challenge = compute_challenge(
            self.announcementB + [self.announcementA], self.order
        )

        # Prepare response
        challenge_powers = [
            self.challenge.mod_pow(i, self.order) for i in range(self.m + 1)
        ]
        self.responseA = [
            sum([exponents[j][i] * challenge_powers[j] for j in range(self.m + 1)])
            for i in range(self.n)
        ]
        self.responseA_randomizers = sum(
            [commitment_randomizer[i] * challenge_powers[i] for i in range(self.m + 1)]
        )

        self.responseB = sum(
            [
                announcementB_values[i] * (self.challenge.mod_pow(i, self.order))
                for i in range(self.m * 2)
            ]
        )
        self.responseB_randomizers = sum(
            [
                announcementB_randomisers[i] * (self.challenge.mod_pow(i, self.order))
                for i in range(self.m * 2)
            ]
        )
        self.response_reencryption_randomisers = sum(
            [
                announcement_reencryption_randomisers[i]
                * (self.challenge.mod_pow(i, self.order))
                for i in range(self.m * 2)
            ]
        )

    def verify(
        self,
        com_pk,
        pk,
        ciphertexts,
        exponantiated_reencrypted_product,
        exponents_commitment,
    ):
        """
        Verify multi-exponantiation argument.
        Example:

            >>> G = EcGroup()
            >>> com_pk = com.PublicKey(G, 3)
            >>> key_pair = elgamal.KeyPair(G)
            >>> pk = key_pair.pk
            >>> ctxts = [pk.encrypt((i) * G.generator()) for i in range(9)]
            >>> ctxts = [ctxts[i*3:(i+1)*3] for i in range(3)]
            >>> exponents = [2, 0, 1, 3, 5, 8, 6, 7, 4]
            >>> exponents_Bn = [Bn.from_num(i) for i in exponents]
            >>> exponents = [exponents_Bn[i * 3:(i + 1) * 3] for i in range(3)]
            >>> randomizers = [G.order().random() for _ in range(3)]
            >>>
            >>> reencryption_randomization = G.order().random()
            >>> product_ctxts = prod([MultiExponantiation.ctxt_weighted_sum(ctxts[i], exponents[i]) for i in range(3)])
            >>>
            >>> exponantiated_reencrypted_product = pk.encrypt(G.infinite(), reencryption_randomization) * product_ctxts
            >>>
            >>> commitment_permutation = [com_pk.commit(exponents[i], randomizers[i])[0] for i in range(3)]
            >>> proof = MultiExponantiation(com_pk, pk, ctxts, exponantiated_reencrypted_product, commitment_permutation, exponents, randomizers, reencryption_randomization)
            >>> proof.verify(com_pk, pk, ctxts, exponantiated_reencrypted_product, commitment_permutation)
            True

            >>> ctxts_fake = [pk.encrypt((i + 1) * G.generator()) for i in range(9)]
            >>> ctxts_fake = [ctxts_fake[i*3:(i+1)*3] for i in range(3)]
            >>> exponents = [2, 0, 1, 3, 5, 8, 6, 7, 4]
            >>> exponents_Bn = [Bn.from_num(i) for i in exponents]
            >>> exponents = [exponents_Bn[i * 3:(i + 1) * 3] for i in range(3)]
            >>> randomizers = [G.order().random() for _ in range(3)]
            >>>
            >>> reencryption_randomization = G.order().random()
            >>> product_ctxts = prod([MultiExponantiation.ctxt_weighted_sum(ctxts[i], exponents[i]) for i in range(3)])
            >>>
            >>> exponantiated_reencrypted_product = pk.encrypt(G.infinite(), reencryption_randomization) * product_ctxts
            >>>
            >>> commitment_permutation = [com_pk.commit(exponents[i], randomizers[i])[0] for i in range(3)]
            >>> proof = MultiExponantiation(com_pk, pk, ctxts_fake, exponantiated_reencrypted_product, commitment_permutation, exponents, randomizers, reencryption_randomization)
            >>> proof.verify(com_pk, pk, ctxts_fake, exponantiated_reencrypted_product, commitment_permutation)
            False


        """

        check1 = com_pk.group.check_point(self.announcementA.commitment)
        check2 = all(
            [
                com_pk.group.check_point(self.announcementB[i].commitment)
                for i in range(self.m)
            ]
        )
        if self.type == elgamal.Ciphertext:
            check3 = all(
                [
                    pk.group.check_point(self.announcement_reencryption[i].c1)
                    and pk.group.check_point(self.announcement_reencryption[i].c2)
                    for i in range(self.m * 2)
                ]
            )
        elif self.type == BallotBundle:
            check3 = all(
                [
                    pk.group.check_point(self.announcement_reencryption[i].vid.c1)
                    and pk.group.check_point(self.announcement_reencryption[i].vid.c2)
                    and pk.group.check_point(self.announcement_reencryption[i].index.c1)
                    and pk.group.check_point(self.announcement_reencryption[i].index.c2)
                    and pk.group.check_point(self.announcement_reencryption[i].tag.c1)
                    and pk.group.check_point(self.announcement_reencryption[i].tag.c2)
                    and all(
                        [
                            pk.group.check_point(c1s[0])
                            for c1s in self.announcement_reencryption[i].vote.c1()
                        ]
                    )
                    and all(
                        [
                            pk.group.check_point(c2s[0])
                            for c2s in self.announcement_reencryption[i].vote.c2()
                        ]
                    )
                    for i in range(self.m * 2)
                ]
            )
        else:
            raise ValueError(
                "Unexpected ciphertext type. Expected either 'Ciphertext' or 'BallotBundle'. Got {0})",
                self.type,
            )

        check4 = self.announcementB[self.m] == com_pk.commit_reduced([0], 1, 0)[0]
        check5 = (
            self.announcement_reencryption[self.m] == exponantiated_reencrypted_product
        )

        exponents_product_A = [
            self.challenge.mod_pow(i, self.order) for i in range(1, self.m + 1)
        ]
        product_A = self.announcementA * self.comm_weighted_sum(
            exponents_commitment, exponents_product_A
        )
        check6 = (
            product_A == com_pk.commit(self.responseA, self.responseA_randomizers)[0]
        )

        exponents_product_B = [
            self.challenge.mod_pow(i, self.order) for i in range(self.m * 2)
        ]
        product_B = self.comm_weighted_sum(self.announcementB, exponents_product_B)
        check7 = (
            product_B
            == com_pk.commit_reduced([self.responseB], 1, self.responseB_randomizers)[0]
        )

        exponents_product_E = [
            self.challenge.mod_pow(i, self.order) for i in range(self.m * 2)
        ]
        product_E = self.ctxt_weighted_sum(
            self.announcement_reencryption, exponents_product_E
        )

        encryption_responseB = pk.encrypt(
            self.responseB * self.G, self.response_reencryption_randomisers
        )
        reencryption_value = (
            BallotBundle(
                encryption_responseB,
                encryption_responseB,
                encryption_responseB,
                VoteVector([encryption_responseB for _ in range(self.nr_candidates)]),
            )
            if self.type != elgamal.Ciphertext
            else encryption_responseB
        )

        verification_product_E = reencryption_value * prod(
            [
                self.ctxt_weighted_sum(
                    ciphertexts[i],
                    [
                        (self.challenge.mod_pow(self.m - (i + 1), self.order))
                        * self.responseA[j]
                        for j in range(self.n)
                    ],
                )
                for i in range(self.m)
            ]
        )

        check8 = product_E == verification_product_E

        return all([check1, check2, check3, check4, check5, check6, check7, check8])

    @staticmethod
    def ctxt_weighted_sum(list_ctxts, weights):
        """
        Function wsum applied to our object of ciphertexts
        Example:
            >>> G = EcGroup()
            >>> key_pair = elgamal.KeyPair(G)
            >>> pk = key_pair.pk
            >>> ctxts = [pk.encrypt((i) * G.generator()) for i in range(9)]
            >>> weights = [Bn.from_num(i) for i in range(9)]
            >>> function_sum = MultiExponantiation.ctxt_weighted_sum(ctxts, weights)
            >>> weighted_sum = prod([ctxts[i] ** weights[i] for i in range(9)])
            >>> function_sum == weighted_sum
            True

        """
        ctxt_type = type(list_ctxts[0])
        if ctxt_type == elgamal.Ciphertext:
            group = list_ctxts[0].group
            c1s = [ctxts.c1 for ctxts in list_ctxts]
            c2s = [ctxts.c2 for ctxts in list_ctxts]

            return elgamal.Ciphertext(
                group.wsum(weights, c1s), group.wsum(weights, c2s)
            )

        elif ctxt_type == BallotBundle:
            # todo: again, we are assuming that all elements of BallotBundle come from the same group.
            group = list_ctxts[0].vid.group
            nr_candidates = list_ctxts[0].vote.length
            c1s_vid = []
            c2s_vid = []
            c1s_index = []
            c2s_index = []
            c1s_tag = []
            c2s_tag = []
            c1s_vote = [[] for _ in range(nr_candidates)]
            c2s_vote = [[] for _ in range(nr_candidates)]
            for ctxts in list_ctxts:
                c1s_vid.append(ctxts.vid.c1)
                c2s_vid.append(ctxts.vid.c2)

                c1s_index.append(ctxts.index.c1)
                c2s_index.append(ctxts.index.c2)

                c1s_tag.append(ctxts.tag.c1)
                c2s_tag.append(ctxts.tag.c2)

                candidates_c1 = ctxts.vote.c1()
                for a, b in zip(c1s_vote, candidates_c1):
                    a.extend(b)
                candidates_c2 = ctxts.vote.c2()
                for a, b in zip(c2s_vote, candidates_c2):
                    a.extend(b)

            return BallotBundle(
                elgamal.Ciphertext(
                    group.wsum(weights, c1s_vid), group.wsum(weights, c2s_vid)
                ),
                elgamal.Ciphertext(
                    group.wsum(weights, c1s_index), group.wsum(weights, c2s_index)
                ),
                elgamal.Ciphertext(
                    group.wsum(weights, c1s_tag), group.wsum(weights, c2s_tag)
                ),
                VoteVector(
                    [
                        elgamal.Ciphertext(
                            group.wsum(weights, c1s_votes),
                            group.wsum(weights, c2s_votes),
                        )
                        for c1s_votes, c2s_votes in zip(c1s_vote, c2s_vote)
                    ]
                ),
            )
        else:
            raise ValueError(
                "Unexpected type of ciphertexts. Expecting Ciphertext or BallotBundle, got {0}",
                type(ctxt_type),
            )

    @staticmethod
    def comm_weighted_sum(list_comms, weights):
        """
        Function wsum applied to our object of commitments
        Example:
             >>> G = EcGroup()
             >>> com_pk = com.PublicKey(G, 3)
             >>> comms = [com_pk.commit_reduced([i], 1)[0] for i in range(9)]
             >>> weights = [Bn.from_num(i) for i in range(9)]
             >>> function_sum = MultiExponantiation.comm_weighted_sum(comms, weights)
             >>> weighted_sum = prod([comms[i] ** weights[i] for i in range(9)])
             >>> function_sum == weighted_sum
             True
        """
        group = list_comms[0].commitment.group
        commitments = [comms.commitment for comms in list_comms]
        return com.Commitment(group.wsum(weights, commitments))


def prod(factors):
    """
    Computes the product of values in a list
    :param factors: list of values to multiply
    :return: product
    """
    product = factors[0]
    if len(factors) > 1:
        for i in factors[1:]:
            product *= i
    return product


if __name__ == "__main__":
    # import doctest
    #
    # doctest.testmod()
    G = EcGroup()
    com_pk = com.PublicKey(G, 3)
    key_pair = elgamal.KeyPair(G)
    pk = key_pair.pk
    ctxts = [pk.encrypt((i) * G.generator()) for i in range(9)]
    ctxts = [ctxts[i * 3 : (i + 1) * 3] for i in range(3)]
    exponents = [2, 0, 1, 3, 5, 8, 6, 7, 4]
    exponents_Bn = [Bn.from_num(i) for i in exponents]
    exponents = [exponents_Bn[i * 3 : (i + 1) * 3] for i in range(3)]
    randomizers = [G.order().random() for _ in range(3)]

    reencryption_randomization = G.order().random()
    product_ctxts = prod(
        [
            MultiExponantiation.ctxt_weighted_sum(ctxts[i], exponents[i])
            for i in range(3)
        ]
    )

    exponantiated_reencrypted_product = (
        pk.encrypt(G.infinite(), reencryption_randomization) * product_ctxts
    )

    commitment_permutation = [
        com_pk.commit(exponents[i], randomizers[i])[0] for i in range(3)
    ]
    proof = MultiExponantiation(
        com_pk,
        pk,
        ctxts,
        exponantiated_reencrypted_product,
        commitment_permutation,
        exponents,
        randomizers,
        reencryption_randomization,
    )
    print(
        proof.verify(
            com_pk, pk, ctxts, exponantiated_reencrypted_product, commitment_permutation
        )
    )
