"""
Measurements of ballot distribution.
"""

# Pythn standard library
import csv

# Local files
from .common import (
    ensures_csv_exists,
    ensures_dir_exists,
    parse_arg_list_int,
    parse_arg_list_float,
)
from .filter import (
    measure_filter_execution_times,
    MEASURE_FILTER_EXECUTION_GEN_KEYS,
    MEASURE_FILTER_EXECUTION_VER_KEYS,
)
from .logging import LOGGER


def measure_performances_filter(namespace):
    """Measure performances of ballot filtering."""

    output_dir = namespace.out
    num_voters_l = parse_arg_list_int(namespace.num_voters)
    revote_percent_l = parse_arg_list_float(namespace.revote_percentage)
    repetitions = namespace.repetitions

    if len(num_voters_l) != len(revote_percent_l):
        if len(revote_percent_l) == 1:
            revote_percent_l = revote_percent_l * len(num_voters_l)
        else:
            # In this case, there is likely an error in the arguments passed to the program.
            raise AttributeError()

    ensures_dir_exists(output_dir)

    gen_filename = output_dir / "full_filter.csv"
    ver_filename = output_dir / "full_filter_ver.csv"

    ensures_csv_exists(gen_filename, MEASURE_FILTER_EXECUTION_GEN_KEYS)
    ensures_csv_exists(ver_filename, MEASURE_FILTER_EXECUTION_VER_KEYS)

    for num_voters, revote_percent in zip(num_voters_l, revote_percent_l):
        LOGGER.info(
            "Run filter experiment with %d voters and %d percent revoting.",
            num_voters,
            revote_percent,
        )
        gen_times, ver_times = measure_filter_execution_times(
            revote_percent, num_voters, n_repetitions=repetitions
        )

        # Data written after each experiment.
        with open(gen_filename, "a+", newline="") as gen_fd:
            filewriter = csv.writer(
                gen_fd, delimiter=",", quotechar="|", quoting=csv.QUOTE_MINIMAL
            )
            for gen_time in gen_times:
                filewriter.writerow(gen_time)

            gen_fd.flush()

        with open(ver_filename, "a+", newline="") as ver_fd:
            filewriter = csv.writer(
                ver_fd, delimiter=",", quotechar="|", quoting=csv.QUOTE_MINIMAL
            )
            for ver_time in ver_times:
                filewriter.writerow(ver_time)

            ver_fd.flush()
