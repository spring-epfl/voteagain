"""
Padding overhead
"""

# Python standard library
import csv
import gc
from math import ceil

# Libraries
import numpy as np

# Local files
from .common import ensures_csv_exists, ensures_dir_exists, parse_arg_list_float
from .dummies.dummies import cover_size, compute_cover


def padding_overhead(nr_voters, nr_ballots, **kwargs):
    """Compute the padding overhead."""
    return cover_size(compute_cover(nr_voters, nr_ballots, **kwargs)) / nr_ballots


def measure_padding_normal_overhead(namespace):
    """Measure the normal overhead."""

    output_dir = namespace.out
    vote_factors_l = parse_arg_list_float(namespace.vote_factors)
    voters_min = namespace.voters_min_log
    voters_max = namespace.voters_max_log

    ensures_dir_exists(output_dir)

    overhead_titles = ["NrVoters"]
    for vote_factor in vote_factors_l:
        extra_percent = 100 * (vote_factor - 1)
        title = "{:.0f} % revote".format(extra_percent)
        overhead_titles.append(title)

    num_voters_ls = np.logspace(voters_min, voters_max, dtype=np.int64)

    overheads = list()

    for num_voters in num_voters_ls:
        overhead = [num_voters]

        for factor in vote_factors_l:
            pad_oh = padding_overhead(num_voters, int(num_voters * factor))
            overhead.append(pad_oh)

        overheads.append(overhead)

    filepath = output_dir / "normal_overhead.csv"

    ensures_csv_exists(filepath, overhead_titles)

    with filepath.open(mode="a+", newline="") as overhead_fd:
        filewriter = csv.writer(
            overhead_fd, delimiter=",", quotechar="|", quoting=csv.QUOTE_MINIMAL
        )

        for overhead in overheads:
            filewriter.writerow(overhead)

        overhead_fd.flush()


def measure_padding_max_votes_limit(namespace):
    """Measure the padding overead for max votes limit."""

    output_dir = namespace.out
    voters_min = namespace.voters_min_log
    voters_max = namespace.voters_max_log
    vote_factor_fixed = namespace.vote_factor_fixed
    votes_per_min_l = parse_arg_list_float(namespace.votes_per_min)

    overhead_titles = ["NrVoters"]
    for votes_per_min in votes_per_min_l:
        title = "{} votes/min".format(votes_per_min)
        overhead_titles.append(title)

    num_voters_ls = np.logspace(voters_min, voters_max, dtype=np.int64)

    overheads = list()

    for num_voters in num_voters_ls:
        overhead = [num_voters]
        for votes_per_min in votes_per_min_l:
            # There are 1440 minutes in one day.
            votes_per_day = votes_per_min * 1440
            num_ballots = int(num_voters * vote_factor_fixed)
            max_ballots = {num_voters: votes_per_day}
            pad_oh = padding_overhead(
                num_voters, num_ballots, max_ballots_dict=max_ballots
            )
            overhead.append(pad_oh)

        overheads.append(overhead)

    filepath = output_dir / "max_votes_limit.csv"

    ensures_csv_exists(filepath, overhead_titles)

    with filepath.open(mode="a+", newline="") as overhead_fd:
        filewriter = csv.writer(
            overhead_fd, delimiter=",", quotechar="|", quoting=csv.QUOTE_MINIMAL
        )

        for overhead in overheads:
            filewriter.writerow(overhead)

        overhead_fd.flush()


def measure_padding_max_votes_voters_limit(namespace):
    """Measure padding for max voters limit."""

    output_dir = namespace.out
    voters_min = namespace.voters_min_log
    voters_max = namespace.voters_max_log
    vote_factor_fixed = namespace.vote_factor_fixed
    votes_per_min_fixed = namespace.votes_per_min_fixed
    crasy_factors_l = parse_arg_list_float(namespace.crazy_factors)

    votes_per_day_fixed = votes_per_min_fixed * 1440

    overhead_titles = ["NrVoters"]

    for crasy_factor in crasy_factors_l:
        title = "{} %".format(crasy_factor)
        overhead_titles.append(title)

    num_voters_ls = np.logspace(voters_min, voters_max, dtype=np.int64)

    overheads = list()

    for num_voters in num_voters_ls:
        overhead = [num_voters]
        for crasy_factor in crasy_factors_l:
            num_ballots = int(num_voters * vote_factor_fixed)
            num_crazy = int(ceil(crasy_factor * num_voters))
            num_normal = num_voters - num_crazy
            max_ballots = {num_normal: 1, num_crazy: votes_per_day_fixed}
            pad_oh = padding_overhead(
                num_voters, num_ballots, max_ballots_dict=max_ballots
            )
            overhead.append(pad_oh)

        overheads.append(overhead)

    filepath = output_dir / "max_votes_voter_limit.csv"

    ensures_csv_exists(filepath, overhead_titles)

    with filepath.open(mode="a+", newline="") as overhead_fd:
        filewriter = csv.writer(
            overhead_fd, delimiter=",", quotechar="|", quoting=csv.QUOTE_MINIMAL
        )

        for overhead in overheads:
            filewriter.writerow(overhead)

        overhead_fd.flush()
