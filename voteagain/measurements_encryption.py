"""
Measurements for encryption proof and verification.
"""

# Pythn standard library
import csv
import json
import time

# Libraries
from petlib.ec import EcGroup

# Local files
from .common import ensures_csv_exists, ensures_dir_exists
from .logging import LOGGER
from .primitives import pedersen_commitment
from .primitives.polynomial import Polynomial
from .procedures.vote_encryption import VoteEncryption


MEASURE_PERFORMANCES_ENCRYPTION_TITLES = (
    "NumberCandidates",
    "ProofGenTime",
    "ProofVerTime",
)


def measure_performances_encryption(namespace):
    """Measure performances of encryption proof and validation."""

    output_dir = namespace.out
    num_candidates = namespace.num_candidates
    repetitions = namespace.repetitions

    ensures_dir_exists(output_dir)

    measurements = gen_encryption_proof(num_candidates, n_repetitions=repetitions)

    filepath = output_dir / "correct_encryption.csv"

    ensures_csv_exists(filepath, MEASURE_PERFORMANCES_ENCRYPTION_TITLES)

    with filepath.open(mode="a+", newline="") as encryption_fd:
        filewriter = csv.writer(
            encryption_fd, delimiter=",", quotechar="|", quoting=csv.QUOTE_MINIMAL
        )
        for measurement in measurements:
            filewriter.writerow(measurement)


def gen_encryption_proof(num_candidates, curve_nid=415, n_repetitions=1):
    group = EcGroup(curve_nid)
    com_pub = pedersen_commitment.PublicKey(group, 1)
    order = com_pub.order

    polynomial_list = Polynomial.from_roots_opt(
        list(range(num_candidates)), order
    ).coefficients
    measurements = list()
    for _ in range(n_repetitions):
        proof = VoteEncryption(polynomial_list, 3, group, com_pub)
        proof.verify(polynomial_list)
        proof_time = proof.time_proof
        verification_time = proof.time_verify
        measurement = (num_candidates, proof_time, verification_time)
        measurements.append(measurement)

    return measurements
