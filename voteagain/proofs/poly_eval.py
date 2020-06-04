"""
Polynomial proof
"""

import math

from functools import reduce
from petlib.ec import EcGroup, Bn

from voteagain.primitives.hash_function import (
    compute_challenge_poly as compute_challenge,
)
from voteagain.primitives.pedersen_commitment import PublicKey
from voteagain.primitives.polynomial import Polynomial


class PolynomialProof:
    def __init__(
        self,
        com_pk,
        polynomial_list,
        commitment_to_eval,
        commitment_eval,
        value_to_eval,
        value_eval,
        random_to_eval,
        random_eval,
    ):
        """
        Generate proof of correct polynomial evaluation. We follow the construction by Bayer and Groth in
        'Zero-knowledge Argument for Polynomial Evaluation with Application to Blacklists'. The first step is to
        transform the polynomial to binary representation. See paper for a further explanation. Note that here we are
        working with cyclic groups over elliptic curves. This code should be changed if we want to use it over finite
        fields.

        :param polynomial_list: Polynomial to evaluate
        :param commitment_to_eval: Commitment of the value where we evaluate the polynomial
        :param commitment_eval: Commitment of the result of evaluating polynomial
        :param value_to_eval: Value where we evaluate the polynomial
        :param value_eval: Result of evaluating the polynomial
        :param random_to_eval: Random used for the commitment of value_to_eval
        :param random_eval: Random used for the commitment of value_eval
        """

        self.group = com_pk.group
        self.order = com_pk.order

        self.degree = int(math.pow(2, math.ceil(math.log(len(polynomial_list) - 1, 2))))
        self.bit_length = int(math.log(self.degree, 2))

        # Pad with zeros the polynomial to size a power of two
        padded_zeros = [0] * (self.degree - len(polynomial_list))
        polynomial_list.extend(padded_zeros)
        self.polynomial = polynomial_list

        random_commitments = [self.order.random() for _ in range(self.bit_length)]
        self.commitments = [
            com_pk.commit(
                [value_to_eval.mod_pow(int(math.pow(2, i + 1)), self.order)],
                random_commitments[i],
            )[0]
            for i in range(self.bit_length)
        ]

        random_commitments.insert(0, random_to_eval)
        self.commitments.insert(0, commitment_to_eval)

        random_commitments_hidden = [
            self.order.random() for _ in range(self.bit_length + 1)
        ]
        random_hidden = [self.order.random() for _ in range(self.bit_length + 1)]
        self.commitments_hidden = [
            com_pk.commit([a], b)[0]
            for a, b in zip(random_hidden, random_commitments_hidden)
        ]

        deltas = self.hidden_polynomial_computation(value_to_eval, random_hidden)
        random_commitments_deltas = [
            self.order.random() for _ in range(self.bit_length + 1)
        ]
        self.commitments_deltas = [
            com_pk.commit([a], b)[0] for a, b in zip(deltas, random_commitments_deltas)
        ]

        random_commitments_exponantiations = [
            self.order.random() for _ in range(self.bit_length)
        ]
        self.commitments_exponantiations = [
            com_pk.commit(
                [random_hidden[i] * (value_to_eval ** (2 ** i))],
                random_commitments_exponantiations[i],
            )[0]
            for i in range(self.bit_length)
        ]

        # Compute challenge
        self.challenge = compute_challenge(
            self.commitments
            + self.commitments_deltas
            + self.commitments_exponantiations
            + self.commitments_hidden,
            self.order,
        )

        # Response
        self.response_random_hidden = [
            self.challenge * value_to_eval ** (2 ** i) + random_hidden[i]
            for i in range(self.bit_length + 1)
        ]
        self.response_random_commitments = [
            self.challenge * random_commitments[i] + random_commitments_hidden[i]
            for i in range(self.bit_length + 1)
        ]

        self.response_random_deltas = self.challenge.mod_pow(
            self.bit_length + 1, self.order
        ) * random_eval + sum(
            [
                random_commitments_deltas[i] * self.challenge.mod_pow(i, self.order)
                for i in range(self.bit_length + 1)
            ]
        )

        self.response_random_exponantiations = [
            self.challenge * random_commitments[i + 1]
            - self.response_random_hidden[i] * random_commitments[i]
            + random_commitments_exponantiations[i]
            for i in range(self.bit_length)
        ]

    def verify(self, com_pk, polynomial_list, commitment_to_eval, commitment_eval):
        """
        Verify proof

        Example:
            >>> G = EcGroup()
            >>> com_pk = PublicKey(G, 1)
            >>> order = com_pk.order
            >>> polynomial_list = [51, 115, 3, 0, 93]
            >>> value_to_eval = Bn.from_num(5)
            >>> random_to_eval = order.random()
            >>> commitment_to_eval = com_pk.commit([value_to_eval], random_to_eval)[0]

            >>> value_eval = Bn.from_num(58826)
            >>> random_eval = order.random()
            >>> commitment_eval = com_pk.commit([value_eval], random_eval)[0]

            >>> proof = PolynomialProof(com_pk, polynomial_list, commitment_to_eval, commitment_eval, value_to_eval, value_eval, random_to_eval, random_eval)
            >>> proof.verify(com_pk, polynomial_list, commitment_to_eval, commitment_eval)
            True

            Now, it should not validate as value_eval is not P(value_to_eval)
            >>> value_eval = Bn.from_num(3333)
            >>> random_eval = order.random()
            >>> commitment_eval = com_pk.commit([value_eval], random_eval)[0]

            >>> proof = PolynomialProof(com_pk, polynomial_list, commitment_to_eval, commitment_eval, value_to_eval, value_eval, random_to_eval, random_eval)
            >>> proof.verify(com_pk, polynomial_list, commitment_to_eval, commitment_eval)
            False

            Again, should not validate because random for commitment_to_eval is not used in the proof
            >>> G = EcGroup()
            >>> com_pk = PublicKey(G, 1)
            >>> order = com_pk.order
            >>> polynomial_list = [51, 115, 3, 0, 93]
            >>> value_to_eval = Bn.from_num(5)
            >>> random_to_eval = order.random()
            >>> commitment_to_eval = com_pk.commit([value_to_eval])[0]

            >>> value_eval = Bn.from_num(58826)
            >>> random_eval = order.random()
            >>> commitment_eval = com_pk.commit([value_eval], random_eval)[0]

            >>> proof = PolynomialProof(com_pk, polynomial_list, commitment_to_eval, commitment_eval, value_to_eval, value_eval, random_to_eval, random_eval)
            >>> proof.verify(com_pk, polynomial_list, commitment_to_eval, commitment_eval)
            False

        """
        # Pad with zeros the polynomial to size a power of two
        padded_zeros = [0] * (self.degree - len(polynomial_list))
        polynomial_list.extend(padded_zeros)

        check1 = [
            (self.commitments[i] ** self.challenge) * self.commitments_hidden[i]
            == com_pk.commit(
                [self.response_random_hidden[i]], self.response_random_commitments[i]
            )[0]
            for i in range(self.bit_length + 1)
        ]

        check2 = [
            (self.commitments[i + 1] ** self.challenge)
            * (self.commitments[i] ** (-self.response_random_hidden[i]))
            * self.commitments_exponantiations[i]
            == com_pk.commit([0], self.response_random_exponantiations[i])[0]
            for i in range(self.bit_length)
        ]

        product_lhs = reduce(
            lambda a, b: a * b,
            [
                self.commitments_deltas[i] ** (self.challenge.mod_pow(i, self.order))
                for i in range(self.bit_length + 1)
            ],
        )
        product_rhs = self.product_rhs_calculation(polynomial_list)
        check3 = (
            commitment_eval ** (self.challenge.mod_pow(self.bit_length + 1, self.order))
            * product_lhs
            == com_pk.commit([product_rhs], self.response_random_deltas)[0]
        )

        return all(check1) and all(check2) and check3

    def hidden_polynomial_computation(self, value_to_eval, random_hidden):
        """
        Evaluate polynomial of step 3 in the algorithm description
        """
        final_poly = Polynomial([0], modulo=self.order)
        for i in range(len(self.polynomial)):
            bin_repr_i = PolynomialProof.binary_repr_int(i, self.bit_length + 1)
            temp_poly = []
            for j in range(self.bit_length + 1):
                temp_poly.append(
                    (
                        Polynomial(
                            [
                                random_hidden[j],
                                value_to_eval.mod_pow(int(math.pow(2, j)), self.order),
                            ],
                            modulo=self.order,
                        )
                        ** bin_repr_i[j]
                    )
                    * Polynomial(
                        [bin_repr_i[j], (1 - bin_repr_i[j])], modulo=self.order
                    )
                )

            final_poly += reduce(lambda a, b: a * b, temp_poly) * self.polynomial[i]

        coeff = final_poly.coefficients

        if len(coeff) < self.bit_length + 2:
            return final_poly.coefficients
        else:
            return final_poly.coefficients[:-1]

        return final_poly.coefficients[:-1]

    def product_rhs_calculation(self, polynomial_list):
        final_poly = 0
        for i in range(len(polynomial_list)):
            bin_repr_i = PolynomialProof.binary_repr_int(i, self.bit_length + 1)
            temp_poly = [
                self.response_random_hidden[j] ** bin_repr_i[j]
                * self.challenge ** (1 - bin_repr_i[j])
                for j in range(self.bit_length + 1)
            ]

            final_poly += (
                reduce(lambda a, b: (a * b).mod(self.order), temp_poly)
                * polynomial_list[i]
            )

        return final_poly

    @staticmethod
    def binary_repr_int(a, length):
        """
        Get the binary representation of a number
        :param a: Value to converto to binary
        :param length: desired length of the binary string (padded with zeros)

        Order is with lsb in position 0
        Example:
            >>> PolynomialProof.binary_repr_int(3, 4)
            [1, 1, 0, 0]
        """
        bin_number = [int(x) for x in bin(a)[2:]]
        to_extend = [0] * (length - len(bin_number))
        to_extend.extend(bin_number)
        return to_extend[::-1]


if __name__ == "__main__":
    import doctest

    doctest.testmod()
