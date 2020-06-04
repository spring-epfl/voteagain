"""
Experiment on minimal shuffle
"""

# Pythn standard library
import csv
import time

# Libraries
import numpy as np
from petlib.ec import EcGroup
from numpy import mean
from objsize import get_deep_size

# Local files
from .common import ensures_csv_exists, ensures_dir_exists, parse_arg_list_int
from .logging import LOGGER
from .primitives import pedersen_commitment
from .primitives import elgamal
from .procedures.election_data import (
    generate_ciphertexts,
    generate_shuffled_reencryptions,
)
from .proofs.efficient_shuffle.shuffle_argument import ShuffleArgument


MEASURE_PERFORMANCES_MINIMAL_SHUFFLE_TITLE = (
    "NumberCiphertexts",
    "ProofGenTime",
    "ProofVerTime",
    "Size",
)


def measure_performances_minimal_shuffle(namespace):
    """Measure performances of filtering."""

    output_dir = namespace.out
    num_ciphertexts_l = parse_arg_list_int(namespace.num_ciphertexts)
    repetitions = namespace.repetitions
    num_candidates = namespace.num_candidates
    m_value = namespace.m

    ensures_dir_exists(output_dir)

    measurements = shuffle_minimal_times(
        num_ciphertexts_l, num_candidates, m_value=m_value, n_repetitions=repetitions
    )

    filepath = output_dir / "shuffle_minimal_{0}.csv".format(m_value)

    ensures_csv_exists(filepath, MEASURE_PERFORMANCES_MINIMAL_SHUFFLE_TITLE)

    with filepath.open(mode="a+", newline="") as shuffle_fd:
        filewriter = csv.writer(
            shuffle_fd, delimiter=",", quotechar="|", quoting=csv.QUOTE_MINIMAL
        )

        for measurement in measurements:
            filewriter.writerow(measurement)

        shuffle_fd.flush()


def shuffle_minimal_times(
    num_ciphertexts_l, number_candidates, m_value=8, curve_nid=415, n_repetitions=1
):
    """
    Only minimal shuffles times. Attention because this shuffle uses the same
    reencryption randomizers for the ciphertexts in BallotBundle.
    """

    group = EcGroup(curve_nid)
    key_pair = elgamal.KeyPair(group)
    pub_key = key_pair.pk

    measurements = list()

    for num_ciphertexts in num_ciphertexts_l:
        ctxts = generate_ciphertexts(num_ciphertexts, group, pub_key)
        ctxts, n = ShuffleArgument.prepare_ctxts(ctxts, m_value, pub_key)
        com_pub = pedersen_commitment.PublicKey(group, n)
        mn = m_value * n

        permutation = np.random.permutation(mn).tolist()
        randomizers, shuffled_ctxts = generate_shuffled_reencryptions(
            ctxts, permutation, group, pub_key, values_vector=False
        )

        # Reshape to shape m*n
        ctxts = ShuffleArgument.reshape_m_n(ctxts, m_value)
        randomizers = ShuffleArgument.reshape_m_n(randomizers, m_value)
        shuffled_ctxts = ShuffleArgument.reshape_m_n(shuffled_ctxts, m_value)
        permutation = ShuffleArgument.reshape_m_n(permutation, m_value)

        for _ in range(n_repetitions):
            shuffle_proof_gen = time.process_time()
            proof = ShuffleArgument(
                com_pub, pub_key, ctxts, shuffled_ctxts, permutation, randomizers
            )
            size = get_deep_size(proof)
            shuffle_proof_verif = time.process_time()
            proof.verify(com_pub, pub_key, ctxts[:num_ciphertexts], shuffled_ctxts)

            rt_verify = time.process_time() - shuffle_proof_verif
            rt_gen = shuffle_proof_verif - shuffle_proof_gen

            measures_vector = (num_ciphertexts, rt_gen, rt_verify, size)
            measurements.append(measures_vector)

    return measurements
