"""
Entrypoint of the program
"""

# Python standard library
import argparse
from pathlib import Path
import sys

# Local files
from .measurements_filter import measure_performances_filter
from .measurements_mix_and_decryption import measure_performances_mix_and_decrypt
from .measurements_encryption import measure_performances_encryption
from .measurements_padding_overhead import (
    measure_padding_normal_overhead,
    measure_padding_max_votes_limit,
    measure_padding_max_votes_voters_limit,
)
from .measurements_minimal_shuffle import measure_performances_minimal_shuffle


def main(args):
    """Parse the arguments passed to the program."""

    # A common parser with arguments common to all subparsers
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-r", "--repetitions", help="Number of repetitions.", type=int, default=1
    )

    # Common options for output directory
    common_out_args = ["-o", "--out"]
    common_out_kwargs = {"help": "Result directory", "type": Path}
    base_path = Path.cwd() / "data"

    parser = argparse.ArgumentParser(
        prog="python -m voteagain",
        description="Module to reproduce VoteAgain performance measurements. See each of the sub-experiments for more details.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    subparsers = parser.add_subparsers(help="Command")

    # Parse arguments for the filter experiment.
    parser_filter = subparsers.add_parser(
        "filter",
        help="Measure the performances of filter",
        description="Measures the performance of the Filter and VerifyFilter steps performed by the Tally Server in VoteAgain.",
        parents=[common],
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser_filter.add_argument(
        "-n", "--num-voters", help="Number of voters.", type=str, default="4"
    )
    parser_filter.add_argument(
        "-p",
        "--revote-percentage",
        help="Percentage of voters revoting.",
        type=str,
        default="0",
    )
    parser_filter.add_argument(
        *common_out_args, default=(base_path / "filter"), **common_out_kwargs
    )
    parser_filter.set_defaults(callback=measure_performances_filter)

    # Parse arguments for the mixing and decryption experiment.
    parser_mix_decrypt = subparsers.add_parser(
        "mix-and-decrypt",
        help="Measure the performances of mixing and decryption.",
        parents=[common],
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser_mix_decrypt.add_argument(
        "-n", "--num-ciphertexts", help="Number of ciphertexts.", type=str, default="1"
    )
    parser_mix_decrypt.add_argument(
        *common_out_args, default=(base_path / "mix"), **common_out_kwargs
    )
    parser_mix_decrypt.set_defaults(callback=measure_performances_mix_and_decrypt)

    # Parse arguments for the encryption experiment.
    parser_encryption = subparsers.add_parser(
        "encryption",
        help="Measure performance of encrypting candidate",
        parents=[common],
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser_encryption.add_argument(
        "-c", "--num-candidates", help="Number of voters.", type=int, default=1
    )
    parser_encryption.add_argument(
        *common_out_args, default=(base_path / "encrypt"), **common_out_kwargs
    )
    parser_encryption.set_defaults(callback=measure_performances_encryption)

    # Parse arguments for the overhead experiment.
    parser_padding = subparsers.add_parser(
        "padding",
        help="Compute the padding overhead",
        parents=[common],
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser_padding.add_argument(
        "--vote-factors", help="Average nr of ballots per voter", type=str, default="1"
    )

    parser_padding.add_argument(
        "--voters-min-log",
        help="Minimum nr. of voters (as base-10 log)",
        type=float,
        default=3.0,
    )
    parser_padding.add_argument(
        "--voters-max-log",
        help="Maximum nr. of voters (as base-10 log)",
        type=float,
        default=8.0,
    )
    parser_padding.add_argument(
        *common_out_args, default=(base_path / "padding"), **common_out_kwargs
    )
    parser_padding.set_defaults(callback=measure_padding_normal_overhead)

    # Parse arguments for the overhead experiment.
    parser_padding_max_votes = subparsers.add_parser(
        "padding-max-votes",
        help="Compute the padding overhead",
        parents=[common],
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser_padding_max_votes.add_argument(
        "--votes-per-min", help="Maximum nr of votes per minute", type=str, default="1"
    )
    parser_padding_max_votes.add_argument(
        "--vote-factor-fixed",
        help="Average nr of ballots per voter for rate-limit experiment",
        type=float,
        default=1.5,
    )
    parser_padding_max_votes.add_argument(
        "--voters-min-log",
        help="Minimum nr. of voters (as base-10 log)",
        type=float,
        default=3.0,
    )
    parser_padding_max_votes.add_argument(
        "--voters-max-log",
        help="Maximum nr. of voters (as base-10 log)",
        type=float,
        default=8.0,
    )
    parser_padding_max_votes.add_argument(
        *common_out_args, default=(base_path / "padding"), **common_out_kwargs
    )
    parser_padding_max_votes.set_defaults(callback=measure_padding_max_votes_limit)

    # Parse arguments for the overhead experiment.
    parser_padding_max_voters_vote = subparsers.add_parser(
        "padding-max-vote-per-voters",
        help="Compute the padding overhead",
        parents=[common],
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser_padding_max_voters_vote.add_argument(
        "--crazy-factors",
        help="Fraction of voters casting more than 1 ballot.",
        type=str,
        default="0",
    )
    parser_padding_max_voters_vote.add_argument(
        "--vote-factor-fixed",
        help="Average nr of ballots per voter for rate-limit experiment",
        type=float,
        default=1.5,
    )
    parser_padding_max_voters_vote.add_argument(
        "--votes-per-min-fixed",
        help="Max voting rate for rate-limit and revoting-limit experiment",
        type=float,
        default=6.0,
    )
    parser_padding_max_voters_vote.add_argument(
        "--voters-min-log",
        help="Minimum nr. of voters (as base-10 log)",
        type=float,
        default=3.0,
    )
    parser_padding_max_voters_vote.add_argument(
        "--voters-max-log",
        help="Maximum nr. of voters (as base-10 log)",
        type=float,
        default=8.0,
    )
    parser_padding_max_voters_vote.add_argument(
        *common_out_args, default=(base_path / "padding"), **common_out_kwargs
    )
    parser_padding_max_voters_vote.set_defaults(
        callback=measure_padding_max_votes_voters_limit
    )

    # Parse arguments for the minimal shuffle experiment.
    parser_shuffle = subparsers.add_parser(
        "min-shuffle",
        help="Measure performance of verifiable shuffle.",
        parents=[common],
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser_shuffle.add_argument("-m", help="M value.", type=int, default=8)
    parser_shuffle.add_argument(
        "-n",
        "--num-ciphertexts",
        help="Number of ciphertexts.",
        type=str,
        default="1000",
    )
    parser_shuffle.add_argument(
        *common_out_args, default=(base_path / "shuffle"), **common_out_kwargs
    )
    parser_shuffle.set_defaults(callback=measure_performances_minimal_shuffle)

    namespace = parser.parse_args(args)

    if "callback" in namespace:
        namespace.callback(namespace)

    else:
        parser.print_help()


if __name__ == "__main__":
    main(sys.argv[1:])
