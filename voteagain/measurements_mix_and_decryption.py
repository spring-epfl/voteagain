"""
Experiment concerning mixing and decryption.
"""

# Pythn standard library
import csv

# Libraries
from petlib.ec import EcGroup

# Local files
from .common import ensures_csv_exists, ensures_dir_exists, parse_arg_list_int
from .primitives import elgamal
from .procedures.mixnet import MixNetPerTeller
from .logging import LOGGER


MEASURE_MIX_AND_DECRYPT_KEYS = (
    "NumberCiphertexts",
    "ShuffleAndProofTime",
    "DecryptAndProofTime",
)


def measure_performances_mix_and_decrypt(namespace):
    """Measure performances of mixing and decryption."""

    output_dir = namespace.out
    num_ciphertexts = parse_arg_list_int(namespace.num_ciphertexts)
    repetitions = namespace.repetitions

    ensures_dir_exists(output_dir)

    filepath = output_dir / "mix_and_decrypt.csv"

    mix_and_decrypt_l = measure_mix_and_decrypt_execution_times(
        num_ciphertexts, n_repetitions=repetitions
    )

    ensures_csv_exists(filepath, MEASURE_MIX_AND_DECRYPT_KEYS)

    with filepath.open(mode="a+", newline="") as mix_and_decrypt_fd:
        filewriter = csv.writer(
            mix_and_decrypt_fd, delimiter=",", quotechar="|", quoting=csv.QUOTE_MINIMAL
        )

        for mix_and_decrypt in mix_and_decrypt_l:
            filewriter.writerow(mix_and_decrypt)

        mix_and_decrypt_fd.flush()


def measure_mix_and_decrypt_execution_times(
    num_ciphertexts_l, m_value=4, curve_nid=415, n_repetitions=1
):
    """Measure the execution time for mix and decrypt operations."""

    group = EcGroup(curve_nid)
    key_pair = elgamal.KeyPair(group)
    pk = key_pair.pk

    measures = list()

    for num_ciphertexts in num_ciphertexts_l:

        LOGGER.info("Running mix and decrypt with %d ctxts.", num_ciphertexts)
        ctxts = [pk.encrypt(i * group.generator()) for i in range(num_ciphertexts)]
        for _ in range(n_repetitions):
            mixnet_per_server = MixNetPerTeller(key_pair, pk, ctxts, m_value)
            proof_time = mixnet_per_server.time_mixing
            decryption_time = mixnet_per_server.time_decrypting

            measures.append([num_ciphertexts, proof_time, decryption_time])

    return measures
