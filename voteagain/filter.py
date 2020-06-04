"""
"""

# Python standard library
import gc
import time


# Libraries
from petlib.ec import EcGroup


# Local files
from .primitives import elgamal
from .procedures.filter import Filter
from .procedures.election_data import election_setup, generate_ballots
from .logging import LOGGER


MEASURE_FILTER_EXECUTION_GEN_KEYS = (
    "Nr_Voters",
    "Total_Revotes",
    "Extra_Padding",
    "Dummies",
    "Shuffle",
    "Decrypt",
    "Reencrypt",
    "FinalShuffle",
    "FinalOpen",
    "FullFilter",
)

MEASURE_FILTER_EXECUTION_VER_KEYS = (
    "Nr_Voters",
    "Total_Revotes",
    "Extra_Padding",
    "Shuffle",
    "Decrypt",
    "Reencrypt",
    "FinalShuffle",
    "FinalOpen",
    "FullFilter",
)


def measure_filter_execution_times(
    revote_percent,
    number_voters,
    m=4,
    curve_nid=415,
    security_param=128,
    n_repetitions=1,
):
    """
    Measure performances of filtering.
    """

    LOGGER.info("Considering percentage of revotes per voter %f", revote_percent)
    revotes_fraction = revote_percent * 0.01

    group = EcGroup(curve_nid)
    key_pair = elgamal.KeyPair(group)
    pk = key_pair.pk

    # Setup the vids, counters and the lookup table of the counters.
    vids, counters = election_setup(group, number_voters, security_param)

    gen_times = list()
    ver_times = list()

    ctxts, counter_lookup_table, nr_revotes = generate_ballots(
        pk, vids, counters, single_vote=False, revotes_fraction=revotes_fraction
    )
    for rep in range(n_repetitions):
        LOGGER.info("... running repetition %d", rep)

        gc.disable()
        gc.collect()

        filter_Start = time.process_time()
        filter_proof = Filter(key_pair, key_pair.pk, ctxts, m, counter_lookup_table)
        filter_end = time.process_time()

        gc.collect()

        filter_verif_start = time.process_time()
        filter_proof.verify()
        filter_verif_end = time.process_time()

        gc.collect()
        gc.enable()

        gen_times_entry = (
            number_voters,
            nr_revotes,
            filter_proof.overhead,
            round(filter_proof.time_dummy_gen, 5),
            round(filter_proof.time_shuffle, 5),
            round(filter_proof.time_decrypt, 5),
            round(filter_proof.time_reencrypt, 5),
            round(filter_proof.time_final_shuffle, 5),
            round(filter_proof.time_final_open, 8),
            round(filter_end - filter_Start, 5),
        )
        gen_times.append(gen_times_entry)

        ver_times_entry = (
            number_voters,
            nr_revotes,
            filter_proof.overhead,
            round(filter_proof.shufle_time_ver, 5),
            round(filter_proof.dec_time_ver, 5),
            round(filter_proof.reenc_time_ver, 5),
            round(filter_proof.final_shuffle_time_ver, 5),
            round(filter_proof.final_open_time_ver, 8),
            round(filter_verif_end - filter_verif_start, 5),
        )
        ver_times.append(ver_times_entry)

    return gen_times, ver_times
