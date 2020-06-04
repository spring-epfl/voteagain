import sys
import time


from petlib.ec import EcGroup, Bn
from numpy import mean

from voteagain.primitives.pedersen_commitment import PublicKey
from voteagain.primitives.polynomial import Polynomial
from voteagain.proofs.poly_eval import PolynomialProof


class VoteEncryption:
    """
    We compute the time it takes to prove correct encryption
    """

    def __init__(self, polynomial_list, chosen_candidate, G, com_pk):
        self.group = G
        self.com_pk = com_pk
        self.order = com_pk.order

        time_start_proof = time.process_time()
        chosen_candidate = Bn.from_num(chosen_candidate)
        random_to_eval = self.order.random()
        self.commitment_to_eval = com_pk.commit([chosen_candidate], random_to_eval)[0]

        value_eval = Bn.from_num(0)
        random_eval = Bn.from_num(0)
        commitment_eval = self.com_pk.commit([value_eval], random_eval)[0]

        self.proof = PolynomialProof(
            com_pk,
            polynomial_list,
            self.commitment_to_eval,
            commitment_eval,
            chosen_candidate,
            value_eval,
            random_to_eval,
            random_eval,
        )

        time_end_proof = time.process_time()

        self.time_proof = time_end_proof - time_start_proof

    def verify(self, polynomial_list):

        value_eval = Bn.from_num(0)
        random_eval = Bn.from_num(0)
        commitment_eval = self.com_pk.commit([value_eval], random_eval)[0]

        time_start_verify = time.process_time()
        self.proof.verify(
            self.com_pk, polynomial_list, self.commitment_to_eval, commitment_eval
        )
        time_end_verify = time.process_time()

        self.time_verify = time_end_verify - time_start_verify


if __name__ == "__main__":
    G = EcGroup()
    com_pk = PublicKey(G, 1)
    order = com_pk.order
    nr_candidates = 1000
    REPS = 2

    time_poly_start = time.process_time()
    polynomial_list = Polynomial.from_roots_opt(
        list(range(nr_candidates)), order
    ).coefficients
    print(time.process_time() - time_poly_start)
    proof_time = []
    verification_time = []
    for _ in range(REPS):
        proof = VoteEncryption(polynomial_list, 3, G, com_pk)
        proof.verify(polynomial_list)
        proof_time.append(proof.time_proof)
        verification_time.append(proof.time_verify)

    print("Proof time: ", mean(proof_time))
    print("Verification time: ", mean(verification_time))
