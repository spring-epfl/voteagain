"""
Mixnet
"""

import time

from petlib.ec import EcGroup
import numpy as np
from numpy import mean

import voteagain.primitives.elgamal as elgamal
import voteagain.primitives.pedersen_commitment as commitment
from voteagain.proofs.correct_decryption import CorrectDecryption
from voteagain.proofs.efficient_shuffle.shuffle_argument import ShuffleArgument


class MixNetPerTeller:
    """
    We compute the time that it will take 'per teller' to perform the mixnet, decrypt and tally
    procedure. This codes evaluates the running time of a single shuffle and prove, and then
    decrypting (each vote individually) and proving correctness.
    """

    def __init__(self, kp, voting_key, list_ctxts, m):
        """
        Perform and generate proof of shuffle
        """
        self.pk = kp.pk
        self.election_key = voting_key
        self.group = kp.group
        self.generator = self.group.generator()
        self.order = self.group.order()

        self.m = m
        self.total_votes = list_ctxts
        self.length_total = len(self.total_votes)

        shuffle_start = time.process_time()
        (
            self.ctxts,
            randomizers,
            self.shuffled_ctxts,
            permutation,
            n,
        ) = self.perform_shuffle()
        self.com_pk = commitment.PublicKey(self.group, n)
        self.proof_of_shuffle = ShuffleArgument(
            self.com_pk,
            self.pk,
            self.ctxts,
            self.shuffled_ctxts,
            permutation,
            randomizers,
        )

        # Now we return to 'normal shape' of shuffled ciphertexts, i.e. one list of size length total
        self.reshaped_shuffled_ctxts = [
            b for sublist in self.shuffled_ctxts for b in sublist
        ]
        self.permutation = [p for sublist in permutation for p in sublist]

        shuffle_end = time.process_time()

        self.decrypted_candidates, self.proof = self.decrypt_and_proof(kp)
        decrypt_and_prove_time = time.process_time()

        self.time_mixing = shuffle_end - shuffle_start
        self.time_decrypting = decrypt_and_prove_time - shuffle_end

    def decrypt_and_proof(self, kp):
        """
        The function decrypts and proofs correct decryption. It publishes (makes a class variable) an array with
        all votes together with a proof of correct decryption.
        """
        decrypted_candidates = []
        proof_decryption = []
        for ciphertext in self.reshaped_shuffled_ctxts:
            plaintext = ciphertext.decrypt(kp.sk)
            decrypted_candidates.append(plaintext)
            proof_decryption.append(CorrectDecryption(ciphertext, plaintext, kp))

        return decrypted_candidates, proof_decryption

    def perform_shuffle(self):
        """
        Re-shape and shuffle to be accepted in proof format
        TODO: lots of duplication here ;) also in filter.py
        TODO: extract to shuffle
        """
        ctxts, n, = self.prepare_ctxts(self.total_votes, self.m, self.election_key)
        randomizers = [self.order.random() for _ in range(self.length_total)]
        permutation = np.random.permutation(self.length_total).tolist()
        shuffled_ctxts = [
            self.pk.reencrypt(ctxts[permuted_index], ephemeral_key=randomizers[index])
            for index, permuted_index in enumerate(permutation)
        ]

        ctxts = ShuffleArgument.reshape_m_n(ctxts, self.m)
        randomizers = ShuffleArgument.reshape_m_n(randomizers, self.m)
        shuffled_ctxts = ShuffleArgument.reshape_m_n(shuffled_ctxts, self.m)
        permutation = ShuffleArgument.reshape_m_n(permutation, self.m)

        return ctxts, randomizers, shuffled_ctxts, permutation, n

    def prepare_ctxts(self, ctxts, m, election_key):
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

        else:
            raise ValueError(
                "Unexpected type of ciphertexts. Expecting Ciphertext, got {0}".format(
                    type(ctxts[0])
                )
            )

        ctxts.extend(zeros)
        return ctxts, n


if __name__ == "__main__":
    G = EcGroup()
    key_pair = elgamal.KeyPair(G)
    pk = key_pair.pk
    m = 4
    nr_candidates = 1
    several_number_voters = [100, 1000, 3000]
    security_param = 128
    REPS = 2

    proof_times = []

    # TODO: THESE ARE A LIE TOO
    verification_times = []

    for number_voters in several_number_voters:
        ctxts = [pk.encrypt(i * G.generator()) for i in range(number_voters)]
        tmp_proof_times = []
        tmp_verification_times = []
        for _ in range(REPS):
            mixnetperserver = MixNetPerTeller(key_pair, pk, ctxts, m)
            tmp_proof_times.append(mixnetperserver.time_mixing)
            tmp_verification_times.append(mixnetperserver.time_decrypting)

        proof_times.append(mean(tmp_proof_times))
        verification_times.append(mean(tmp_proof_times))

        print("Times for {} total of votes:".format(number_voters))
        print("=================================")
        print("Mixnet per teller", mean(tmp_proof_times))
        print("Verification of mixnet teller", mean(tmp_proof_times))
