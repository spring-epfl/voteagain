"""
Product argument
"""

from petlib.ec import EcGroup, Bn

from voteagain.primitives.hash_function import compute_challenge

import voteagain.primitives.pedersen_commitment as com
import voteagain.proofs.efficient_shuffle.multi_exponantiation_argument as mult_exp


class ProductArgument:
    """
        Argument to prove that a set of committed values have a particular product. Following Bayer and Groth
        in 'Efficient Zero-Knowledge Argument for correctness of a shuffle.
        For sake simplicity in python notation, and without loss of generality, we work with rows instead of working
        with columns, as opposed to the original paper.
    """

    def __init__(self, com_pk, commitment, product, A, randomizers):
        self.order = com_pk.group.order()
        self.m = len(A)
        self.n = len(A[0])

        # Maybe here we have a calculation which slows down the running time
        product_rows_A = [
            modular_prod([Bn.from_num(a[i]) for a in A], self.order)
            for i in range(self.n)
        ]
        self.commitment_products, randomizer_commitment_products = com_pk.commit(
            product_rows_A
        )

        self.hadamard = HadamardProductArgument(
            com_pk,
            commitment,
            self.commitment_products,
            A,
            randomizers,
            randomizer_commitment_products,
        )

        self.single_value = SingleValueProdArg(
            com_pk,
            self.commitment_products,
            product,
            product_rows_A,
            randomizer_commitment_products,
        )

    def verify(self, com_pk, commitment, product):
        """
            Verify product argument proof.
            Example:
                 >>> G = EcGroup()
                 >>> com_pk = com.PublicKey(G, 3)
                 >>> order = G.order()
                 >>> A = [[Bn.from_num(10), Bn.from_num(20), Bn.from_num(30)],[Bn.from_num(40), Bn.from_num(20), Bn.from_num(30)], [Bn.from_num(60), Bn.from_num(20), Bn.from_num(40)]]
                 >>> commits_rands_A = [com_pk.commit(a) for a in A]
                 >>> comm_A = [a[0] for a in commits_rands_A]
                 >>> random_comm_A = [a[1] for a in commits_rands_A]
                 >>> b = modular_prod([modular_prod([Bn.from_num(A[i][j]) for i in range(3)], order) for j in range(3)], order)
                 >>> proof = ProductArgument(com_pk, comm_A, b, A, random_comm_A)
                 >>> proof.verify(com_pk, comm_A, b)
                 True
        """

        check1 = com_pk.group.check_point(self.commitment_products.commitment)
        check2 = self.hadamard.verify(com_pk, commitment, self.commitment_products)
        check3 = self.single_value.verify(com_pk, self.commitment_products, product)

        return all([check3, check2, check1])


class SingleValueProdArg:
    """
        3-move argument of knowledge of committed single values having a particular product. Following Bayer and Groth
        in 'Efficient Zero-Knowledge Argument for correctness of a shuffle'.
    """

    def __init__(self, com_pk, commitment, product, committed_values, randomizer):
        self.n = len(committed_values)
        self.order = com_pk.group.order()

        self.sec_param_l_e = 160
        self.sec_param_l_s = 80
        self.bn_two = Bn.from_num(2)

        # Prepare announcement
        products = [committed_values[0]]
        for i in range(1, self.n):
            products.append((products[i - 1] * committed_values[i]).mod(self.order))

        commitment_rand_one = self.order.random()
        commitment_rand_two = self.order.random()
        commitment_rand_three = self.order.random()

        d_randoms = [self.order.random() for _ in range(self.n)]

        delta_randoms = [self.order.random() for _ in range(self.n)]
        delta_randoms[0] = d_randoms[0]
        delta_randoms[-1] = 0

        value_to_commit_two = [
            -delta_randoms[i] * d_randoms[i + 1] for i in range(self.n - 1)
        ]
        value_to_commit_three = [
            delta_randoms[i + 1]
            - committed_values[i + 1] * delta_randoms[i]
            - products[i] * d_randoms[i + 1]
            for i in range(self.n - 1)
        ]

        self.announcement_one, _ = com_pk.commit(d_randoms, commitment_rand_one)
        self.announcement_two, _ = com_pk.commit_reduced(
            value_to_commit_two, self.n - 1, commitment_rand_two
        )
        self.announcement_three, _ = com_pk.commit_reduced(
            value_to_commit_three, self.n - 1, commitment_rand_three
        )

        # Compute challenge [Verify validity of this]
        self.challenge = compute_challenge(
            [
                commitment,
                product,
                self.announcement_one,
                self.announcement_two,
                self.announcement_three,
            ],
            self.order,
        )

        # Compute response
        self.response_committed_values = [
            (self.challenge * committed_values[i] + d_randoms[i]).mod(self.order)
            for i in range(self.n)
        ]
        self.response_product = [
            (self.challenge * products[i] + delta_randoms[i]).mod(self.order)
            for i in range(self.n)
        ]

        self.response_randomizer = (
            self.challenge * randomizer + commitment_rand_one
        ).mod(self.order)
        self.response_randomizer_commitments = (
            self.challenge * commitment_rand_three + commitment_rand_two
        ).mod(self.order)

    def verify(self, com_pk, commitment, product):
        """
        Verify the correctness of the proof.

        Example:
            >>> G = EcGroup()
            >>> order = G.order()
            >>> com_pk = com.PublicKey(G, 3)
            >>> msgs = [Bn.from_num(10), Bn.from_num(20), Bn.from_num(30)]
            >>> product = modular_prod(msgs, order)
            >>> commit, rand = com_pk.commit(msgs)
            >>> proof = SingleValueProdArg(com_pk, commit, product, msgs, rand)
            >>> proof.verify(com_pk, commit, product)
            True

            >>> msgs = [Bn.from_num(11), Bn.from_num(12), Bn.from_num(13)]
            >>> proof = SingleValueProdArg(com_pk, commit, product, msgs, rand)
            >>> proof.verify(com_pk, commit, product)
            False

        """
        # First verify that values are in the group
        check1 = com_pk.group.check_point(self.announcement_one.commitment)
        check2 = com_pk.group.check_point(self.announcement_two.commitment)
        check3 = com_pk.group.check_point(self.announcement_three.commitment)

        check4 = (
            commitment ** self.challenge * self.announcement_one
            == com_pk.commit(self.response_committed_values, self.response_randomizer)[
                0
            ]
        )
        value_to_commit_check5 = [
            (
                self.challenge * self.response_product[i + 1]
                - self.response_product[i] * self.response_committed_values[i + 1]
            ).mod(self.order)
            for i in range(self.n - 1)
        ]
        check5 = (
            self.announcement_three ** self.challenge * self.announcement_two
            == com_pk.commit_reduced(
                value_to_commit_check5, self.n - 1, self.response_randomizer_commitments
            )[0]
        )

        check6 = self.response_committed_values[0] == self.response_product[0]
        check7 = (self.challenge * product).mod(self.order) == self.response_product[
            -1
        ].mod(self.order)

        return all([check1, check2, check3, check4, check5, check6, check7])


class ZeroArgument:
    """
        Given commitments to a_1, b_0, ..., a_m, b_m-1 (where each is a vector of value), the prover wants to show that
        0 = sum(a_i * b_i-1) for i in {1,...,m} where * is the dot product. Following Bayer and Groth
        in 'Efficient Zero-Knowledge Argument for correctness of a shuffle.
        For sake simplicity in python notation, and without loss of generality, we work with rows instead of working
        with columns, as opposed to the original paper.
    """

    def __init__(
        self,
        com_pk,
        A,
        B,
        random_comm_A,
        random_comm_B,
        bilinear_const=Bn.from_decimal("1"),
    ):
        """
        :param com_pk: Commitment key
        :param commitment_A: Commitment of A
        :param commitment_B: Commitment of B
        :param A: Matrix formed by rows a_i
        :param B: Matrix formed by rows b_i
        :param random_comm_A vector of random values used for commitment_A
        :param random_comm_B: vector of random values used for commitment_B
        """
        self.order = com_pk.group.order()
        self.m = len(A)
        self.n = len(A[0])
        self.bilinear_const = bilinear_const

        # Prepare announcement
        A.insert(0, [self.order.random() for _ in range(self.n)])
        B.append([self.order.random() for _ in range(self.n)])
        random_comm_A.insert(0, self.order.random())
        random_comm_B.append(self.order.random())

        self.announcement_a0, _ = com_pk.commit_reduced(A[0], self.n, random_comm_A[0])
        self.announcement_bm, _ = com_pk.commit_reduced(
            B[-1], self.n, random_comm_B[-1]
        )

        diagonals = []
        for k in range(2 * self.m + 1):
            diagonal = 0
            for i in range(self.m + 1):
                j = self.m - k + i
                if j < 0:
                    continue
                if j > self.m:
                    break
                diagonal += (
                    self.bilinear_map(A[i], B[j], self.bilinear_const, self.order)
                ).mod(self.order)
            diagonals.append(diagonal)

        commitment_rand_diagonals = [self.order.random() for _ in range(2 * self.m + 1)]
        commitment_rand_diagonals[self.m + 1] = 0

        self.announcement_diagonals = [
            com_pk.commit_reduced([diagonals[i]], 1, commitment_rand_diagonals[i])[0]
            for i in range(self.m * 2 + 1)
        ]
        # Prepare challenge (for the moment we only put two announcements, as I yet need to determine how to deal with
        # the matrices. Maybe I form a class, maybe not. Once decided, I'll add them here (same for announcement of
        # diagonals).
        self.challenge = compute_challenge(
            [self.announcement_a0, self.announcement_bm], self.order
        )
        # Compute the response
        A_modified = [
            [
                (A[j][i] * (self.challenge.mod_pow(j, self.order))).mod(self.order)
                for i in range(self.n)
            ]
            for j in range(self.m + 1)
        ]
        self.response_as = [
            modular_sum(x, self.order) for x in zip(*A_modified[: self.m + 1])
        ]

        self.response_randomizer_A = modular_sum(
            [
                (self.challenge.mod_pow(i, self.order) * random_comm_A[i]).mod(
                    self.order
                )
                for i in range(self.m + 1)
            ],
            self.order,
        )

        B_modified = [
            [
                B[j][i] * (self.challenge.mod_pow(self.m - j, self.order))
                for i in range(self.n)
            ]
            for j in range(self.m + 1)
        ]
        self.response_bs = [
            modular_sum(x, self.order) for x in zip(*B_modified[: self.m + 1])
        ]
        self.response_randomizer_B = modular_sum(
            [
                (self.challenge.mod_pow(self.m - i, self.order) * random_comm_B[i]).mod(
                    self.order
                )
                for i in range(self.m + 1)
            ],
            self.order,
        )

        self.response_randomizer_diagonals = modular_sum(
            [
                (
                    self.challenge.mod_pow(i, self.order) * commitment_rand_diagonals[i]
                ).mod(self.order)
                for i in range(self.m * 2 + 1)
            ],
            self.order,
        )

    def verify(self, com_pk, commitment_A, commitment_B):
        """
        Verify ZeroArgument proof
        Example:
            >>> G = EcGroup()
            >>> com_pk = com.PublicKey(G, 3)
            >>> order = G.order()
            >>> A = [[Bn.from_num(10), Bn.from_num(20), Bn.from_num(30)], [Bn.from_num(40), Bn.from_num(20), Bn.from_num(30)], [Bn.from_num(60), Bn.from_num(20), Bn.from_num(40)]]
            >>> B = [[Bn.from_num(1), Bn.from_num(1), order - 1], [Bn.from_num(1), Bn.from_num(1), order - 2], [order - 1, Bn.from_num(1), Bn.from_num(1)]]
            >>> commits_rand_A = [com_pk.commit_reduced(A[i], 3) for i in range(3)]
            >>> comm_A = [a[0] for a in commits_rand_A]
            >>> random_comm_A = [a[1] for a in commits_rand_A]
            >>> commits_rand_B = [com_pk.commit_reduced(B[i], 3) for i in range(3)]
            >>> comm_B = [b[0] for b in commits_rand_B]
            >>> random_comm_B = [b[1] for b in commits_rand_B]
            >>> proof_Zero = ZeroArgument(com_pk, A, B, random_comm_A, random_comm_B)
            >>> proof_Zero.verify(com_pk, comm_A, comm_B)
            True

            >>> G = EcGroup()
            >>> com_pk = com.PublicKey(G, 3)
            >>> order = G.order()
            >>> A = [[Bn.from_num(10), Bn.from_num(20), Bn.from_num(30)], [Bn.from_num(40), Bn.from_num(20), Bn.from_num(30)], [Bn.from_num(60), Bn.from_num(20), Bn.from_num(40)]]
            >>> B = [[Bn.from_num(2), Bn.from_num(1), order - 1], [Bn.from_num(1), Bn.from_num(1), order - 2], [order - 1, Bn.from_num(1), Bn.from_num(1)]]
            >>> commits_rand_A = [com_pk.commit_reduced(A[i], 3) for i in range(3)]
            >>> comm_A = [a[0] for a in commits_rand_A]
            >>> random_comm_A = [a[1] for a in commits_rand_A]
            >>> commits_rand_B = [com_pk.commit_reduced(B[i], 3) for i in range(3)]
            >>> comm_B = [b[0] for b in commits_rand_B]
            >>> random_comm_B = [b[1] for b in commits_rand_B]
            >>> proof_Zero = ZeroArgument(com_pk, A, B, random_comm_A, random_comm_B)
            >>> proof_Zero.verify(com_pk, comm_A, comm_B)
            False


        """
        check1 = com_pk.group.check_point(self.announcement_a0.commitment)
        check2 = com_pk.group.check_point(self.announcement_bm.commitment)

        commitment_A.insert(0, self.announcement_a0)
        commitment_B.append(self.announcement_bm)

        check3 = all(
            [
                com_pk.group.check_point(self.announcement_diagonals[i].commitment)
                for i in range(self.m * 2 + 1)
            ]
        )

        check4 = (
            self.announcement_diagonals[self.m + 1]
            == com_pk.commit_reduced([0], 1, 0)[0]
        )

        exponents_5 = [self.challenge.mod_pow(i, self.order) for i in range(self.m + 1)]
        check5 = (
            mult_exp.MultiExponantiation.comm_weighted_sum(commitment_A, exponents_5)
            == com_pk.commit_reduced(
                self.response_as, self.n, self.response_randomizer_A
            )[0]
        )

        exponents_6 = [
            self.challenge.mod_pow(self.m - i, self.order) for i in range(self.m + 1)
        ]
        check6 = (
            mult_exp.MultiExponantiation.comm_weighted_sum(commitment_B, exponents_6)
            == com_pk.commit_reduced(
                self.response_bs, self.n, self.response_randomizer_B
            )[0]
        )

        exponents_7 = [
            self.challenge.mod_pow(i, self.order) for i in range(self.m * 2 + 1)
        ]
        check7 = (
            mult_exp.MultiExponantiation.comm_weighted_sum(
                self.announcement_diagonals, exponents_7
            )
            == com_pk.commit_reduced(
                [
                    self.bilinear_map(
                        self.response_as,
                        self.response_bs,
                        self.bilinear_const,
                        self.order,
                    )
                ],
                1,
                self.response_randomizer_diagonals,
            )[0]
        )

        return all([check1, check2, check3, check4, check5, check6, check7])

    @staticmethod
    def bilinear_map(a, b, bilinear_const, order):
        """
        Example:
             >>> bilinear_const = Bn.from_num(3)
             >>> order = Bn.from_num(1000000)
             >>> aa = [32, 53, 54]
             >>> aa3 = [a * 3 for a in aa]
             >>> bb = [61, 11, 10]
             >>> cc = [43, 52, 33]
             >>> sum_aabb = [sum([la, lb]) for la, lb in zip(aa, bb)]
             >>> ZeroArgument.bilinear_map(sum_aabb, cc, bilinear_const, order) == (ZeroArgument.bilinear_map(aa, cc, bilinear_const, order) + ZeroArgument.bilinear_map(bb, cc, bilinear_const, order))
             True
             >>> ZeroArgument.bilinear_map(cc, sum_aabb, bilinear_const, order) == (ZeroArgument.bilinear_map(cc, aa, bilinear_const, order) + ZeroArgument.bilinear_map(cc, bb, bilinear_const, order))
             True
             >>> ZeroArgument.bilinear_map(aa3, cc, bilinear_const, order) == (ZeroArgument.bilinear_map(aa, cc, bilinear_const, order) * 3)
             True

        """
        if len(a) != len(b):
            raise ValueError(
                "Values must be same length. Got %d and %d" % (len(a), len(b))
            )

        return modular_sum(
            [
                (a[i] * b[i] * (bilinear_const.mod_pow(i, order))).mod(order)
                for i in range(len(a))
            ],
            order,
        )


class HadamardProductArgument:
    """
        We give an argument for committed values [a_1], [a_2], ..., [a_n] and b_1, b_2, ..., b_n such that
        b_i equals the product of each element of [a_i], where [·] denotes a vector.
        Following Bayer and Groth in 'Efficient Zero-Knowledge Argument for correctness of a shuffle.
        For sake simplicity in python notation, and without loss of generality, we work with rows instead of working
        with columns, as opposed to the original paper.
    """

    def __init__(
        self, com_pk, commitment_A, commitment_b, A, random_comm_A, random_comm_b
    ):
        self.order = com_pk.group.order()
        self.m = len(A)
        self.n = len(A[0])

        # Prepare announcement
        vectors_b = [A[0]]
        for i in range(1, self.m):
            vectors_b.append(
                [
                    (first * second).mod(self.order)
                    for first, second in zip(vectors_b[i - 1], A[i])
                ]
            )

        random_comm_announcement = [self.order.random() for _ in range(self.m)]
        self.announcement_b = [
            com_pk.commit(vectors_b[i], random_comm_announcement[i])[0]
            for i in range(self.m)
        ]
        random_comm_announcement[0] = random_comm_A[0]
        random_comm_announcement[self.m - 1] = random_comm_b
        self.announcement_b[0] = commitment_A[0]
        self.announcement_b[self.m - 1] = commitment_b

        # Compute challenges. One challenge is used for the constant of the bilinear map.
        # todo: attention to the transcript. Change it
        self.challenge = compute_challenge(self.announcement_b, self.order)
        transcript_bilinear = self.announcement_b
        transcript_bilinear.append(self.challenge)
        self.challenge_bilinear = compute_challenge(transcript_bilinear, self.order)

        # Engage in the Zero argument proof
        opening_vectors_commitments_D = [
            [
                (self.challenge.mod_pow(i, self.order) * vectors_b[i][j]).mod(
                    self.order
                )
                for j in range(self.n)
            ]
            for i in range(self.m - 1)
        ]
        random_vectors_commitments_D = [
            (self.challenge.mod_pow(i, self.order) * random_comm_announcement[i]).mod(
                self.order
            )
            for i in range(self.m - 1)
        ]

        modified_vectors_b = [
            [
                (self.challenge.mod_pow(i, self.order) * vectors_b[i + 1][j]).mod(
                    self.order
                )
                for j in range(self.n)
            ]
            for i in range(self.m - 1)
        ]
        opening_value_commitment_D = [
            modular_sum(x, self.order) for x in zip(*modified_vectors_b[: self.m - 1])
        ]
        random_value_commitment_D = modular_sum(
            [
                (
                    self.challenge.mod_pow(i, self.order)
                    * random_comm_announcement[i + 1]
                ).mod(self.order)
                for i in range(self.m - 1)
            ],
            self.order,
        )

        zero_argument_A = A[1:]
        zero_argument_A.append([-1] * self.n)
        zero_argument_B = opening_vectors_commitments_D
        zero_argument_B.append(opening_value_commitment_D)
        zero_argument_random_A = random_comm_A[1:]
        zero_argument_random_A.append(0)
        zero_argument_random_B = random_vectors_commitments_D
        zero_argument_random_B.append(random_value_commitment_D)

        self.zero_argument_proof = ZeroArgument(
            com_pk,
            zero_argument_A,
            zero_argument_B,
            zero_argument_random_A,
            zero_argument_random_B,
            self.challenge_bilinear,
        )

    def verify(self, com_pk, commitment_A, commitment_b):
        """
        Verify Hadamard Product Argument
        Example:
            >>> G = EcGroup()
            >>> order = G.order()
            >>> com_pk = com.PublicKey(G, 3)
            >>> A = [[Bn.from_num(10), Bn.from_num(20), Bn.from_num(30)], [Bn.from_num(40), Bn.from_num(20), Bn.from_num(30)], [Bn.from_num(60), Bn.from_num(20), Bn.from_num(40)]]
            >>> commits_rands_A = [com_pk.commit(a) for a in A]
            >>> comm_A = [a[0] for a in commits_rands_A]
            >>> random_comm_A = [a[1] for a in commits_rands_A]
            >>> b = [modular_prod([Bn.from_num(a[i]) for a in A], order) for i in range(3)]
            >>> comm_b, random_comm_b = com_pk.commit(b)
            >>> proof = HadamardProductArgument(com_pk, comm_A, comm_b, A, random_comm_A, random_comm_b)
            >>> proof.verify(com_pk, comm_A, comm_b)
            True
        """
        check1 = self.announcement_b[0] == commitment_A[0]
        check2 = self.announcement_b[self.m - 1] == commitment_b
        check3 = all(
            [
                com_pk.group.check_point(self.announcement_b[i].commitment)
                for i in range(1, self.m - 1)
            ]
        )

        vectors_commitments_D = [
            self.announcement_b[i] ** (self.challenge.mod_pow(i, self.order))
            for i in range(self.m - 1)
        ]
        exponents = [self.challenge.mod_pow(i, self.order) for i in range(self.m - 1)]
        value_commitment_D = mult_exp.MultiExponantiation.comm_weighted_sum(
            self.announcement_b[1 : self.m], exponents
        )

        commitment_minus1 = com_pk.commit([-1] * self.n, 0)

        zero_argument_A = commitment_A[1:]
        zero_argument_A.append(commitment_minus1[0])
        zero_argument_B = vectors_commitments_D
        zero_argument_B.append(value_commitment_D)
        check4 = self.zero_argument_proof.verify(
            com_pk, zero_argument_A, zero_argument_B
        )

        return all([check1, check2, check3, check4])


def modular_prod(factors, modulo):
    """
    Computes the product of values in a list modulo modulo.
    :param factors: list of values to multiply
    :return: product 
    """
    product = factors[0]
    if len(factors) > 1:
        for i in factors[1:]:
            product = (product * i).mod(modulo)
    return product


def modular_sum(values, modulo):
    """
    Computes de modular sum of the list of values modulo modulo
    :param values:
    :param modulo:
    :return:
    """
    values_sum = values[0]
    if len(values) > 1:
        for i in values[1:]:
            values_sum = (values_sum + i).mod(modulo)
    return values_sum


if __name__ == "__main__":
    # import doctest
    #
    # doctest.testmod()
    G = EcGroup()
    com_pk = com.PublicKey(G, 3)
    order = com_pk.group.order()
    A = [
        [Bn.from_num(10), Bn.from_num(20), Bn.from_num(30)],
        [Bn.from_num(40), Bn.from_num(20), Bn.from_num(30)],
        [Bn.from_num(60), Bn.from_num(20), Bn.from_num(40)],
    ]
    for _ in range(10):
        A.extend(A)
        length_A = len(A)
        commits_rands_A = [com_pk.commit(a) for a in A]
        comm_A = [a[0] for a in commits_rands_A]
        random_comm_A = [a[1] for a in commits_rands_A]
        b = modular_prod(
            [
                modular_prod([Bn.from_num(A[i][j]) for i in range(length_A)], order)
                for j in range(3)
            ],
            order,
        )
        print("Start proof.")
        proof = ProductArgument(com_pk, comm_A, b, A, random_comm_A)
        print("Start verification.")
        print(proof.verify(com_pk, comm_A, b))
